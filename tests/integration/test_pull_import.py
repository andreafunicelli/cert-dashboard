"""Task 16: worker-side host:port pull import (real Postgres, real HTTP stack, local TLS listener)."""

import re
import socket
import time
from datetime import timedelta
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import func, select, update

from app.crypto.parse import parse_certificates
from app.jobs.handlers import import_pull as pull_handler
from app.jobs.queue import JobFailure
from app.jobs.worker import JobContext
from app.models import AuditLog, Certificate, Endpoint, Job, ScanResult
from app.models.enums import EndpointSource, JobStatus, JobType
from app.services.scans import PulledChain, pull_chain

PULL = "/certificates/import/pull"


@pytest.fixture(autouse=True)
def _no_leftover_jobs(web_factory):
    """The web database is shared by the module: never let one test's queued job run in another."""
    yield
    with web_factory.begin() as db:
        db.execute(update(Job).where(Job.status == JobStatus.QUEUED).values(status=JobStatus.CANCELLED))


def _post(client, host, port, *, sni="", headers=None, **fields):
    data = {"host": host, "port": str(port), "sni": sni, "csrf_token": client.fixture_csrf, **fields}
    return client.post(PULL, data=data, headers=headers, follow_redirects=False)


def _job_id(response):
    assert response.status_code == 303, response.text[:500]
    match = re.fullmatch(r"/imports/([0-9a-f-]{36})", response.headers["location"])
    assert match, response.headers["location"]
    return match.group(1)


def _job(factory, job_id):
    with factory() as db:
        return db.get(Job, job_id)


def _count(factory, model):
    with factory() as db:
        return db.scalar(select(func.count()).select_from(model))


def _imported(factory, fingerprint):
    with factory() as db:
        return db.scalar(select(Certificate).where(Certificate.sha256_fingerprint == fingerprint))


def _endpoints(factory, host, port):
    with factory() as db:
        return list(db.scalars(select(Endpoint).where(Endpoint.host == host, Endpoint.port == port)))


def _fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def _self_signed(now):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "selfsigned.example.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("selfsigned.example.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _closed_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --- the plan's flow ---------------------------------------------------------------------------


def test_pull_import_creates_expectation(worker_harness, signed_in, tls_server, web_factory, pull_certs):
    response = _post(signed_in, tls_server.host, tls_server.port, sni="www.example.internal")
    job_id = _job_id(response)
    worker_harness.run_queued()
    cert = _imported(web_factory, _fingerprint(pull_certs.leaf))
    with web_factory() as db:
        endpoint = db.scalar(select(Endpoint).where(Endpoint.port == tls_server.port))
    assert cert.imported_from == "pull_endpoint"
    assert cert.key_id is None and endpoint.expected_certificate_id == cert.id
    assert len(parse_certificates(cert.chain_pem.encode())) == 2
    assert (endpoint.host, endpoint.sni, endpoint.source, endpoint.is_active) == (
        tls_server.host,
        "www.example.internal",
        EndpointSource.MANUAL,
        True,
    )
    job = _job(web_factory, job_id)
    assert job.status == JobStatus.SUCCEEDED
    assert job.result["certificate_id"] == cert.id and job.result["created"] is True
    assert tls_server.seen_server_names == ["www.example.internal"]
    assert _count(web_factory, ScanResult) == 0  # endpoint assessment belongs to Plan 2


def test_web_post_only_enqueues_and_the_worker_connects(worker_harness, signed_in, tls_server, web_factory):
    response = _post(signed_in, tls_server.host, tls_server.port, owner_name="Ada", team="Edge", notes="n")
    job_id = _job_id(response)
    assert tls_server.connections == 0
    time.sleep(0.3)
    assert tls_server.connections == 0
    job = _job(web_factory, job_id)
    assert (job.type, job.status, job.priority, job.max_attempts, job.scheduled_reason) == (
        JobType.SCAN,
        JobStatus.QUEUED,
        200,
        3,
        "manual",
    )
    assert job.requested_by is not None
    assert job.payload == {
        "action": "import_pull",
        "host": tls_server.host,
        "port": tls_server.port,
        "sni": None,
        "metadata": {"owner_name": "Ada", "owner_email": None, "team": "Edge", "notes": "n"},
    }
    with web_factory() as db:
        enqueue = db.scalar(
            select(AuditLog).where(AuditLog.action == "job.enqueue", AuditLog.target_id == job_id)
        )
    assert enqueue is not None and enqueue.details["action"] == "import_pull"
    worker_harness.run_queued()
    assert tls_server.connections == 1


def test_metadata_and_actor_are_recovered_from_the_job(worker_harness, signed_in, tls_server, web_factory, web_user, pull_certs):
    job_id = _job_id(_post(signed_in, tls_server.host, tls_server.port, owner_name="Ada", notes="edge"))
    worker_harness.run_queued()
    cert = _imported(web_factory, _fingerprint(pull_certs.leaf))
    assert (cert.owner_name, cert.notes, cert.created_by) == ("Ada", "edge", web_user.id)
    with web_factory() as db:
        audits = {
            row.action: row
            for row in db.scalars(
                select(AuditLog).where(AuditLog.action.in_(["certificate.import", "endpoint.upsert"]))
            )
        }
    assert audits["certificate.import"].actor_label == web_user.username
    upsert = audits["endpoint.upsert"]
    assert upsert.actor_user_id == web_user.id
    assert upsert.details["expected_certificate_id"] == cert.id and upsert.details["port"] == tls_server.port
    assert _job(web_factory, job_id).status == JobStatus.SUCCEEDED


def test_ip_host_without_sni_sends_no_server_name(worker_harness, signed_in, tls_server, web_factory):
    _post(signed_in, tls_server.host, tls_server.port)
    worker_harness.run_queued()
    assert tls_server.connections == 1
    assert tls_server.seen_server_names == []


def test_dns_host_without_sni_sends_the_host_as_server_name(worker_harness, signed_in, tls_server, web_factory):
    _post(signed_in, "localhost", tls_server.port)
    worker_harness.run_queued()
    assert tls_server.seen_server_names == ["localhost"]
    assert [e.sni for e in _endpoints(web_factory, "localhost", tls_server.port)] == [None]


# --- served certificates are never trust-checked -------------------------------------------------


def test_self_signed_served_certificate_imports_with_warnings(worker_harness, signed_in, tls_servers, web_factory, now):
    cert, key = _self_signed(now)
    server = tls_servers(cert, key)
    job_id = _job_id(_post(signed_in, server.host, server.port))
    worker_harness.run_queued()
    job = _job(web_factory, job_id)
    assert job.status == JobStatus.SUCCEEDED, job.error_message
    assert job.result["created"] is True and job.result["warnings"]
    stored = _imported(web_factory, _fingerprint(cert))
    assert stored.imported_from == "pull_endpoint"
    assert _endpoints(web_factory, server.host, server.port)[0].expected_certificate_id == stored.id


def test_expired_served_certificate_imports_with_expiry_warning(
    worker_harness, signed_in, tls_servers, web_factory, pull_certs
):
    server = tls_servers(pull_certs.expired, pull_certs.leaf_key, pull_certs.intermediates)
    job_id = _job_id(_post(signed_in, server.host, server.port))
    worker_harness.run_queued()
    job = _job(web_factory, job_id)
    assert job.status == JobStatus.SUCCEEDED, job.error_message
    assert "expired" in job.result["warnings"]
    assert _imported(web_factory, _fingerprint(pull_certs.expired)) is not None


# --- failures are classified and sanitized ---------------------------------------------------------


def test_silent_server_times_out_as_retryable_network_failure(tls_servers, pull_certs):
    server = tls_servers(pull_certs.leaf, pull_certs.leaf_key, mode="silent")
    started = time.monotonic()
    with pytest.raises(JobFailure) as caught:
        pull_chain(server.host, server.port, None, timeout_seconds=1)
    assert time.monotonic() - started < 4
    assert caught.value.error_class == "transient_network"
    assert caught.value.message == f"{server.host}:{server.port} unreachable: timeout"
    assert caught.value.retryable is True


def test_dns_failure_is_a_retryable_network_failure():
    with pytest.raises(JobFailure) as caught:
        pull_chain("no-such-host.invalid", 443, None, timeout_seconds=10)
    assert caught.value.error_class == "transient_network"
    assert caught.value.message == "no-such-host.invalid:443 unreachable: dns"
    assert caught.value.retryable is True


def test_refused_connection_is_a_retryable_network_failure():
    port = _closed_port()
    with pytest.raises(JobFailure) as caught:
        pull_chain("127.0.0.1", port, None, timeout_seconds=5)
    assert (caught.value.error_class, caught.value.retryable) == ("transient_network", True)
    assert caught.value.message == f"127.0.0.1:{port} unreachable: refused"


def test_non_tls_peer_fails_the_handshake_without_retry(tls_servers, pull_certs):
    server = tls_servers(pull_certs.leaf, pull_certs.leaf_key, mode="garbage")
    with pytest.raises(JobFailure) as caught:
        pull_chain(server.host, server.port, None, timeout_seconds=5)
    assert caught.value.error_class == "config_invalid"
    assert caught.value.message == f"{server.host}:{server.port}: TLS handshake failed"
    assert caught.value.retryable is False


def test_pull_chain_returns_the_served_chain_and_tls_version(tls_server, pull_certs):
    pulled = pull_chain(tls_server.host, tls_server.port, "www.example.internal", timeout_seconds=5)
    assert isinstance(pulled, PulledChain)
    expected = (pull_certs.leaf, *pull_certs.intermediates)
    assert [bytes(der) for der in pulled.der_chain] == [c.public_bytes(_der()) for c in expected]
    assert pulled.tls_version.startswith("TLSv1")


def _der():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def test_pull_chain_caps_certificate_count(tls_servers, pull_certs):
    extras = [pull_certs.intermediate1] * 12
    server = tls_servers(pull_certs.leaf, pull_certs.leaf_key, extras)
    pulled = pull_chain(server.host, server.port, None, timeout_seconds=5)
    assert len(pulled.der_chain) == 10


def test_job_failures_are_sanitized_and_classified(worker_harness, signed_in, tls_servers, web_factory, monkeypatch, pull_certs):
    monkeypatch.setattr(pull_handler, "PULL_TIMEOUT_SECONDS", 1)
    silent = tls_servers(pull_certs.leaf, pull_certs.leaf_key, mode="silent")
    garbage = tls_servers(pull_certs.leaf, pull_certs.leaf_key, mode="garbage")
    refused_port = _closed_port()
    ids = {
        "timeout": _job_id(_post(signed_in, silent.host, silent.port)),
        "handshake": _job_id(_post(signed_in, garbage.host, garbage.port)),
        "refused": _job_id(_post(signed_in, "127.0.0.1", refused_port)),
        "dns": _job_id(_post(signed_in, "no-such-host.invalid", 8443)),
    }
    worker_harness.run_queued()
    outcomes = {name: _job(web_factory, job_id) for name, job_id in ids.items()}
    assert {n: (j.status, j.error_class) for n, j in outcomes.items()} == {
        "timeout": (JobStatus.FAILED, "transient_network"),
        "handshake": (JobStatus.FAILED, "config_invalid"),
        "refused": (JobStatus.FAILED, "transient_network"),
        "dns": (JobStatus.FAILED, "transient_network"),
    }
    assert outcomes["timeout"].error_message == f"127.0.0.1:{silent.port} unreachable: timeout"
    assert outcomes["handshake"].error_message == f"127.0.0.1:{garbage.port}: TLS handshake failed"
    assert outcomes["refused"].error_message == f"127.0.0.1:{refused_port} unreachable: refused"
    assert outcomes["dns"].error_message == "no-such-host.invalid:8443 unreachable: dns"
    assert outcomes["handshake"].result == {"retryable": False}
    assert not _endpoints(web_factory, "127.0.0.1", refused_port)


def test_unparseable_served_certificate_fails_without_retry(
    worker_harness, signed_in, tls_server, web_factory, monkeypatch
):
    monkeypatch.setattr(
        pull_handler, "pull_chain", lambda *args, **kwargs: PulledChain((b"not a certificate",), "TLSv1.3")
    )
    job_id = _job_id(_post(signed_in, tls_server.host, tls_server.port))
    worker_harness.run_queued()
    job = _job(web_factory, job_id)
    assert (job.status, job.error_class) == (JobStatus.FAILED, "config_invalid")
    assert job.error_message == f"{tls_server.host}:{tls_server.port}: served certificate could not be parsed"
    assert not _endpoints(web_factory, tls_server.host, tls_server.port)


def test_empty_served_chain_fails_without_retry(worker_harness, signed_in, tls_server, web_factory, monkeypatch):
    monkeypatch.setattr(pull_handler, "pull_chain", lambda *args, **kwargs: PulledChain((), "TLSv1.3"))
    job_id = _job_id(_post(signed_in, tls_server.host, tls_server.port))
    worker_harness.run_queued()
    job = _job(web_factory, job_id)
    assert (job.status, job.error_class) == (JobStatus.FAILED, "config_invalid")


# --- idempotence -------------------------------------------------------------------------------------


def test_rerunning_the_job_yields_the_same_certificate_and_endpoint(
    worker_harness, signed_in, tls_server, web_factory, pull_certs, clock
):
    job_id = _job_id(_post(signed_in, tls_server.host, tls_server.port, sni="www.example.internal"))
    worker_harness.run_queued()
    first = _job(web_factory, job_id)
    certificates = _count(web_factory, Certificate)
    endpoints = _count(web_factory, Endpoint)
    context = JobContext(first.id, "retry-worker", web_factory, worker_harness.settings, clock=clock)
    again = pull_handler.import_pull(context, first.payload)
    assert again["certificate_id"] == first.result["certificate_id"] and again["created"] is False
    assert "duplicate" in again["warnings"]
    assert (_count(web_factory, Certificate), _count(web_factory, Endpoint)) == (certificates, endpoints)
    assert len(_endpoints(web_factory, tls_server.host, tls_server.port)) == 1


def test_existing_endpoint_gets_the_new_expectation_and_keeps_its_source(
    worker_harness, signed_in, tls_server, web_factory, pull_certs
):
    # coalesce(sni, host): an endpoint stored with sni == host is the same identity as sni NULL.
    with web_factory.begin() as db:
        db.add(Endpoint(host="localhost", port=tls_server.port, sni="localhost", source=EndpointSource.DISCOVERY))
    _post(signed_in, "localhost", tls_server.port)
    worker_harness.run_queued()
    rows = _endpoints(web_factory, "localhost", tls_server.port)
    cert = _imported(web_factory, _fingerprint(pull_certs.leaf))
    assert len(rows) == 1
    assert (rows[0].expected_certificate_id, rows[0].source) == (cert.id, EndpointSource.DISCOVERY)


def test_a_different_sni_is_a_different_endpoint(worker_harness, signed_in, tls_server, web_factory):
    _post(signed_in, tls_server.host, tls_server.port, sni="a.example.internal")
    _post(signed_in, tls_server.host, tls_server.port, sni="b.example.internal")
    worker_harness.run_queued()
    assert {e.sni for e in _endpoints(web_factory, tls_server.host, tls_server.port)} == {
        "a.example.internal",
        "b.example.internal",
    }


# --- web validation -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "port", "sni", "field"),
    [
        ("example.internal", "0", "", "port"),
        ("example.internal", "65536", "", "port"),
        ("example.internal", "abc", "", "port"),
        ("example.internal", "44 3", "", "port"),
        ("https://example.internal", "443", "", "host"),
        ("example.internal/path", "443", "", "host"),
        ("example.internal:8443", "443", "", "host"),
        ("10.0.0.0/24", "443", "", "host"),
        ("admin@example.internal", "443", "", "host"),
        ("exa mple.internal", "443", "", "host"),
        ("", "443", "", "host"),
        ("example.internal", "443", "192.0.2.1", "sni"),
        ("example.internal", "443", "*.example.internal", "sni"),
        (" example.internal", "443", "", "host"),
        ("example.internal ", "443", "", "host"),
        ("example.internal\t", "443", "", "host"),
        ("example.internal", "443", " sni.example.internal", "sni"),
        ("example.internal", "443", "sni.example.internal ", "sni"),
        ("example.internal", "443", "   ", "sni"),
        ("a" * 254, "443", "", "host"),
        (("a" * 60 + ".") * 5 + "internal", "443", "", "host"),
        ("example.internal", "443", ("a" * 60 + ".") * 5 + "internal", "sni"),
        ("a" * 5000, "443", "", "host"),
        ("example.internal", "443", "a" * 5000, "sni"),
    ],
)
def test_invalid_input_is_a_422_and_enqueues_nothing(signed_in, web_factory, host, port, sni, field):
    before = (_count(web_factory, Job), _count(web_factory, AuditLog))
    response = _post(signed_in, host, port, sni=sni)
    assert response.status_code == 422
    assert f'data-field="pull_{field}"' in response.text
    assert (_count(web_factory, Job), _count(web_factory, AuditLog)) == before


def test_invalid_metadata_is_a_422_and_keeps_the_entered_values(signed_in, web_factory):
    before = _count(web_factory, Job)
    response = _post(signed_in, "example.internal", 443, owner_email="not-an-email", team="Edge")
    assert response.status_code == 422
    assert 'data-field="pull_metadata"' in response.text
    assert 'value="example.internal"' in response.text and 'value="Edge"' in response.text
    assert _count(web_factory, Job) == before


def test_secret_like_notes_are_rejected_instead_of_enqueued(signed_in, web_factory):
    before = _count(web_factory, Job)
    response = _post(signed_in, "example.internal", 443, notes="password=hunter2hunter2")
    assert response.status_code == 422
    assert _count(web_factory, Job) == before


def test_blank_port_defaults_to_443(signed_in, web_factory):
    job_id = _job_id(_post(signed_in, "example.internal", ""))
    assert _job(web_factory, job_id).payload["port"] == 443


def test_htmx_success_redirects_with_a_header(signed_in):
    response = _post(signed_in, "example.internal", 443, headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert re.fullmatch(r"/imports/[0-9a-f-]{36}", response.headers["HX-Redirect"])


def test_htmx_failure_returns_only_the_pull_panel(signed_in):
    response = _post(signed_in, "https://example.internal", 443, headers={"HX-Request": "true"})
    assert response.status_code == 422
    assert "<html" not in response.text and 'id="pull-panel"' in response.text
    assert 'id="import-panel"' not in response.text


def test_pull_requires_csrf_and_sign_in(signed_in, client, web_factory):
    before = _count(web_factory, Job)
    missing = signed_in.post(PULL, data={"host": "example.internal", "port": "443"}, follow_redirects=False)
    assert missing.status_code == 403
    client.cookies.clear()
    anonymous = client.post(PULL, data={"host": "example.internal", "port": "443"}, follow_redirects=False)
    assert anonymous.status_code in (303, 401, 403)
    assert _count(web_factory, Job) == before


def test_import_page_offers_the_pull_form(signed_in):
    page = signed_in.get("/certificates/import")
    assert page.status_code == 200
    assert 'action="/certificates/import/pull"' in page.text
    assert "Pull from server" in page.text
    assert re.search(r'name="port"[^>]*value="443"', page.text)
    assert f'value="{signed_in.fixture_csrf}"' in page.text
    assert page.text.count('id="owner_name"') == 1  # element ids stay unique across both forms


# --- progress page ------------------------------------------------------------------------------------


def test_progress_page_polls_while_pending_and_links_the_certificate_when_done(
    worker_harness, signed_in, tls_server, web_factory
):
    job_id = _job_id(_post(signed_in, tls_server.host, tls_server.port))
    page = signed_in.get(f"/imports/{job_id}")
    assert page.status_code == 200
    assert f'hx-get="/imports/{job_id}/progress"' in page.text
    assert 'hx-trigger="every 2s"' in page.text
    assert f'href="/imports/{job_id}"' in page.text and "Refresh" in page.text
    assert "queued" in page.text.lower()
    assert f"{tls_server.host}:{tls_server.port}" in page.text

    worker_harness.run_queued()
    fragment = signed_in.get(f"/imports/{job_id}/progress")
    certificate_id = _job(web_factory, job_id).result["certificate_id"]
    assert fragment.status_code == 200 and "<html" not in fragment.text
    assert f'href="/certificates/{certificate_id}"' in fragment.text
    assert "imported" in fragment.text.lower() and "already in inventory" not in fragment.text.lower()
    assert "hx-trigger" not in fragment.text  # polling stops on a terminal state
    full = signed_in.get(f"/imports/{job_id}")
    assert "hx-trigger" not in full.text and f'href="/certificates/{certificate_id}"' in full.text


def test_progress_page_says_already_in_inventory_for_a_duplicate(worker_harness, signed_in, tls_server, web_factory):
    _post(signed_in, tls_server.host, tls_server.port)
    second = _job_id(_post(signed_in, tls_server.host, tls_server.port, sni="other.example.internal"))
    worker_harness.run_queued()
    assert _job(web_factory, second).status == JobStatus.SUCCEEDED
    page = signed_in.get(f"/imports/{second}")
    assert "already in inventory" in page.text.lower()


def test_progress_page_shows_the_sanitized_failure_and_stops_polling(
    worker_harness, signed_in, web_factory, tls_servers, pull_certs
):
    server = tls_servers(pull_certs.leaf, pull_certs.leaf_key, mode="garbage")
    job_id = _job_id(_post(signed_in, server.host, server.port))
    worker_harness.run_queued()
    page = signed_in.get(f"/imports/{job_id}")
    assert f"{server.host}:{server.port}: TLS handshake failed" in page.text
    assert "hx-trigger" not in page.text
    assert "Refresh" in page.text


def test_progress_page_keeps_polling_while_a_retry_is_pending(signed_in, web_factory, tls_server):
    job_id = _job_id(_post(signed_in, tls_server.host, tls_server.port))
    with web_factory.begin() as db:
        db.execute(
            update(Job)
            .where(Job.id == job_id)
            .values(
                status=JobStatus.FAILED,
                attempt=1,
                error_class="transient_network",
                error_message="x:1 unreachable: refused",
                finished_at=func.now(),
            )
        )
    page = signed_in.get(f"/imports/{job_id}")
    assert 'hx-trigger="every 2s"' in page.text
    assert "retry" in page.text.lower()


@pytest.mark.parametrize("bad", ["not-a-uuid", "1234", "00000000-0000-0000-0000-000000000000"])
def test_unknown_or_malformed_job_ids_are_404(signed_in, bad):
    assert signed_in.get(f"/imports/{bad}").status_code == 404
    assert signed_in.get(f"/imports/{bad}/progress").status_code == 404


def test_only_pull_import_jobs_are_viewable(signed_in, web_factory, now):
    other = {}
    with web_factory.begin() as db:
        for name, job_type, payload in (
            ("cleanup", JobType.CLEANUP, {}),
            ("scan", JobType.SCAN, {"action": "default"}),
        ):
            job = Job(type=job_type, priority=100, payload=payload, run_after=now, status=JobStatus.CANCELLED)
            db.add(job)
            db.flush()
            other[name] = job.id
    for job_id in other.values():
        assert signed_in.get(f"/imports/{job_id}").status_code == 404
        assert signed_in.get(f"/imports/{job_id}/progress").status_code == 404
    assert signed_in.get(f"/imports/{uuid4()}").status_code == 404


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "import_pull", "host": "bad.example", "port": "not-a-port"},
        {"action": "import_pull", "host": "bad.example", "port": None},
        {"action": "import_pull", "host": "bad.example", "port": [1]},
        {"action": "import_pull", "host": 5, "port": 1.5},
        {"action": "import_pull"},
    ],
)
def test_progress_page_survives_a_poison_job_with_a_malformed_payload(signed_in, web_factory, now, payload):
    with web_factory.begin() as db:
        job = Job(
            type=JobType.SCAN,
            priority=200,
            payload=payload,
            run_after=now,
            status=JobStatus.FAILED,
            attempt=1,
            max_attempts=3,
            error_class="validation",
            error_message="The pull request is invalid.",
            finished_at=now,
        )
        db.add(job)
        db.flush()
        job_id = job.id
    page = signed_in.get(f"/imports/{job_id}")
    fragment = signed_in.get(f"/imports/{job_id}/progress")
    for response in (page, fragment):
        assert response.status_code == 200
        assert "The pull request is invalid." in response.text
        assert "hx-trigger" not in response.text


def test_progress_pages_require_sign_in(client, signed_in, tls_server):
    job_id = _job_id(_post(signed_in, tls_server.host, tls_server.port))
    client.cookies.clear()
    response = client.get(f"/imports/{job_id}", follow_redirects=False)
    assert response.status_code in (303, 401)
    assert tls_server.host not in response.text
