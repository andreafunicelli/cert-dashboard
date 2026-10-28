"""scan/default end to end: worker retries, schedule, concurrency bounds and the "Scan now" route."""

import time
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy import delete, func, select

from app.crypto.parse import parse_certificates
from app.jobs.queue import SYSTEM_ACTOR, enqueue
from app.models import AuditLog, Certificate, Endpoint, Job, ScanResult
from app.models.enums import ChainStatus, EndpointSource, JobStatus, JobType, ScanStatus
from app.services.audit import Actor
from tests.integration.conftest import closed_port, disable_schedules, set_setting


@pytest.fixture(autouse=True)
def isolated(web_factory):
    """The web database is shared by the module: start each test with no endpoints, results or jobs."""
    disable_schedules(web_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup", "discovery")
    set_setting(web_factory, "scan.timeout_seconds", 10)
    with web_factory.begin() as db:
        db.execute(delete(ScanResult))
        db.execute(delete(Endpoint))
        db.execute(delete(Job))


def add_certificate(factory, cert):
    parsed = parse_certificates(cert.public_bytes(Encoding.DER))[0]
    with factory.begin() as db:
        row = Certificate(
            common_name=parsed.common_name,
            subject_dn=parsed.subject_dn,
            sans=list(parsed.sans),
            issuer_dn=parsed.issuer_dn,
            issuer_cn=parsed.issuer_cn,
            serial=parsed.serial,
            not_before=parsed.not_before,
            not_after=parsed.not_after,
            sha256_fingerprint=parsed.sha256_fingerprint,
            pem=parsed.pem,
            chain_status=ChainStatus.UNCHECKED,
            imported_from="upload_pem",
        )
        db.add(row)
        db.flush()
        return row.id


def add_endpoint(factory, host, port, *, expected=None, active=True, sni="www.example.internal"):
    with factory.begin() as db:
        endpoint = Endpoint(
            host=host,
            port=port,
            sni=sni,
            source=EndpointSource.MANUAL,
            expected_certificate_id=expected,
            is_active=active,
        )
        db.add(endpoint)
        db.flush()
        return endpoint.id


def enqueue_scan(factory, payload, now, actor=SYSTEM_ACTOR, max_attempts=3):
    with factory.begin() as db:
        return enqueue(
            db,
            JobType.SCAN,
            payload,
            actor,
            priority=100,
            run_after=now - timedelta(minutes=1),
            max_attempts=max_attempts,
        ).id


def job_state(factory, job_id):
    with factory() as db:
        job = db.get(Job, job_id)
        return job.status, job.error_class


def job_result(factory, job_id):
    with factory() as db:
        return db.get(Job, job_id).result


def result_count(factory, endpoint_id):
    with factory() as db:
        return db.scalar(select(func.count()).select_from(ScanResult).where(ScanResult.endpoint_id == endpoint_id))


def results_of(factory, endpoint_id):
    with factory() as db:
        return list(db.scalars(select(ScanResult).where(ScanResult.endpoint_id == endpoint_id).order_by(ScanResult.id)))


def scan_audits(factory, job_id):
    with factory() as db:
        rows = db.scalars(
            select(AuditLog).where(AuditLog.action == "scan.run", AuditLog.target_id == str(job_id)).order_by(AuditLog.created_at)
        )
        return [(row.actor_user_id, row.actor_label, row.target_type, row.details) for row in rows]


def serve(tls_servers, certs, mode="tls"):
    return tls_servers(certs.leaf, certs.leaf_key, certs.intermediates, mode=mode)


def retry_to_the_end(worker_harness, clock):
    for delay in (31, 121):
        clock.advance(seconds=delay)
        worker_harness.tick()
        worker_harness.run_queued()


def test_unreachable_endpoints_are_retried_alone_until_the_last_attempt(
    worker_harness, web_factory, tls_servers, pull_certs, clock
):
    live = tls_servers(pull_certs.leaf, pull_certs.leaf_key, pull_certs.intermediates)
    up = add_endpoint(web_factory, live.host, live.port)
    down = add_endpoint(web_factory, "127.0.0.1", closed_port())
    job_id = enqueue_scan(web_factory, {"endpoint_ids": [up, down]}, clock())
    worker_harness.run_queued()
    assert job_state(web_factory, job_id) == ("failed", "transient_network")
    retry_to_the_end(worker_harness, clock)
    assert job_state(web_factory, job_id) == ("succeeded", None)
    assert (result_count(web_factory, up), result_count(web_factory, down)) == (1, 3)
    assert live.connections == 1  # the healthy endpoint is never rescanned by a retry
    audits = scan_audits(web_factory, job_id)
    assert [(a[3]["attempt"], a[3]["scanned"], a[3]["unreachable"]) for a in audits] == [(1, 2, 1), (2, 1, 1), (3, 1, 1)]
    assert {a[3]["source"] for a in audits} == {"scheduled"}


def test_scan_job_failure_message_counts_the_unreachable_endpoints(
    worker_harness, web_factory, tls_servers, pull_certs, clock
):
    live = serve(tls_servers, pull_certs)
    ids = [
        add_endpoint(web_factory, live.host, live.port),
        add_endpoint(web_factory, "127.0.0.1", closed_port(), sni="a.example.internal"),
        add_endpoint(web_factory, "127.0.0.1", closed_port(), sni="b.example.internal"),
    ]
    job_id = enqueue_scan(web_factory, {"endpoint_ids": ids}, clock())
    worker_harness.run_queued()
    with web_factory() as db:
        assert db.get(Job, job_id).error_message == "2 of 3 endpoints unreachable; retrying them"


def test_scan_job_records_one_result_per_active_endpoint(
    worker_harness, web_factory, tls_servers, pull_certs, ca, clock, now
):
    leaf = pull_certs.leaf
    expected = add_certificate(web_factory, leaf)
    other = add_certificate(web_factory, pull_certs.wildcard)
    live = serve(tls_servers, pull_certs)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = ca.issue(
        public_key=key.public_key(),
        common_name="expired.example.internal",
        sans=["expired.example.internal"],
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1),
    )
    old = tls_servers(parse_certificates(pem)[0].cert, key, [ca.intermediate])
    garbage = serve(tls_servers, pull_certs, mode="garbage")
    parked = serve(tls_servers, pull_certs)
    ids = {
        "ok": add_endpoint(web_factory, live.host, live.port, expected=expected, sni="ok.example.internal"),
        "mismatch": add_endpoint(web_factory, live.host, live.port, expected=other, sni="mismatch.example.internal"),
        "expired": add_endpoint(web_factory, old.host, old.port),
        "unreachable": add_endpoint(web_factory, "127.0.0.1", closed_port()),
        "error": add_endpoint(web_factory, garbage.host, garbage.port),
        "inactive": add_endpoint(web_factory, parked.host, parked.port, active=False),
    }
    job_id = enqueue_scan(web_factory, {"endpoint_ids": sorted(ids.values())}, clock(), max_attempts=1)
    worker_harness.run_queued()
    assert job_state(web_factory, job_id) == ("succeeded", None)
    expected_counts = {
        "scanned": 5,
        "ok": 1,
        "mismatch": 1,
        "expired": 1,
        "unreachable": 1,
        "error": 1,
        "skipped_inactive": 1,
    }
    assert job_result(web_factory, job_id) == expected_counts
    for name, status in (
        ("ok", ScanStatus.OK),
        ("mismatch", ScanStatus.MISMATCH),
        ("expired", ScanStatus.EXPIRED),
        ("unreachable", ScanStatus.UNREACHABLE),
        ("error", ScanStatus.ERROR),
    ):
        (row,) = results_of(web_factory, ids[name])
        assert row.status is status, name
    assert result_count(web_factory, ids["inactive"]) == 0 and parked.connections == 0
    (audit,) = scan_audits(web_factory, job_id)
    assert audit[:3] == (None, "system", "job")
    assert audit[3] == {"source": "scheduled", "attempt": 1, **expected_counts}
    with web_factory() as db:
        assert db.get(Endpoint, ids["ok"]).last_scan_status is ScanStatus.OK


def test_scheduled_scan_runs_daily_with_system_source(worker_harness, web_factory, tls_servers, pull_certs, clock):
    live = serve(tls_servers, pull_certs)
    endpoint = add_endpoint(web_factory, live.host, live.port)
    set_setting(web_factory, "scan.enabled", True)
    clock.value = datetime(2026, 10, 19, 2, 0, 30, tzinfo=UTC)
    worker_harness.tick()
    clock.advance(seconds=30)
    worker_harness.tick()  # the same occurrence is never enqueued twice
    with web_factory() as db:
        jobs = list(db.scalars(select(Job).where(Job.type == JobType.SCAN)))
    # The 02:00 tick also enqueues scan/trust_recheck (shares scan.daily_at); pick scan/default by payload.
    (job,) = [candidate for candidate in jobs if "action" not in candidate.payload]
    assert (job.status, job.priority, job.scheduled_reason, job.payload) == (JobStatus.QUEUED, 100, "daily", {})
    assert job.requested_by is None and job.max_attempts == 3
    worker_harness.run_queued()
    assert job_state(web_factory, job.id) == ("succeeded", None)
    (row,) = results_of(web_factory, endpoint)
    assert row.source == "scheduled"


def test_manual_scan_keeps_manual_source_across_retries(worker_harness, web_factory, web_user, clock):
    down = add_endpoint(web_factory, "127.0.0.1", closed_port())
    actor = Actor(web_user.id, web_user.username)
    job_id = enqueue_scan(web_factory, {"endpoint_ids": [down]}, clock(), actor)
    worker_harness.run_queued()
    retry_to_the_end(worker_harness, clock)
    assert job_state(web_factory, job_id) == ("succeeded", None)
    assert [row.source for row in results_of(web_factory, down)] == ["manual"] * 3
    audits = scan_audits(web_factory, job_id)
    assert [(a[0], a[3]["source"]) for a in audits] == [(web_user.id, "manual")] * 3


def test_certificate_scope_scans_only_endpoints_expecting_it(
    worker_harness, web_factory, tls_servers, pull_certs, clock
):
    wanted = add_certificate(web_factory, pull_certs.leaf)
    unrelated = add_certificate(web_factory, pull_certs.wildcard)
    hit, miss, bare, parked = (serve(tls_servers, pull_certs) for _ in range(4))
    scanned = add_endpoint(web_factory, hit.host, hit.port, expected=wanted)
    others = [
        add_endpoint(web_factory, miss.host, miss.port, expected=unrelated),
        add_endpoint(web_factory, bare.host, bare.port),
    ]
    inactive = add_endpoint(web_factory, parked.host, parked.port, expected=wanted, active=False)
    job_id = enqueue_scan(web_factory, {"certificate_id": wanted}, clock())
    worker_harness.run_queued()
    assert job_result(web_factory, job_id)["scanned"] == 1
    assert job_result(web_factory, job_id)["skipped_inactive"] == 1
    assert (hit.connections, miss.connections, bare.connections, parked.connections) == (1, 0, 0, 0)
    assert result_count(web_factory, scanned) == 1
    assert [result_count(web_factory, item) for item in (*others, inactive)] == [0, 0, 0]
    (row,) = results_of(web_factory, scanned)
    assert row.status is ScanStatus.OK


def test_an_empty_scope_succeeds_with_zero_counts(worker_harness, web_factory, clock):
    job_id = enqueue_scan(web_factory, {}, clock())
    worker_harness.run_queued()
    assert job_state(web_factory, job_id) == ("succeeded", None)
    assert job_result(web_factory, job_id) == {
        "scanned": 0,
        "ok": 0,
        "mismatch": 0,
        "expired": 0,
        "unreachable": 0,
        "error": 0,
        "skipped_inactive": 0,
    }


def test_scan_honours_scan_timeout_setting(worker_harness, web_factory, tls_servers, pull_certs, clock):
    silent = serve(tls_servers, pull_certs, mode="silent")
    endpoint = add_endpoint(web_factory, silent.host, silent.port)
    set_setting(web_factory, "scan.timeout_seconds", 1)
    job_id = enqueue_scan(web_factory, {"endpoint_ids": [endpoint]}, clock(), max_attempts=1)
    started = time.monotonic()
    worker_harness.run_queued()
    assert time.monotonic() - started < 5
    assert silent.connections == 1
    assert job_result(web_factory, job_id)["unreachable"] == 1
    (row,) = results_of(web_factory, endpoint)
    assert row.status is ScanStatus.UNREACHABLE and row.elapsed_ms < 4000


def wait_until(predicate, timeout=10.0, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError("condition not met in time")


def test_a_third_scan_job_stays_queued_while_two_scans_run(
    worker_harness, web_factory, tls_servers, pull_certs, clock
):
    set_setting(web_factory, "scan.timeout_seconds", 3)
    servers = [serve(tls_servers, pull_certs, mode="silent") for _ in range(3)]
    endpoints = [add_endpoint(web_factory, s.host, s.port, sni=f"h{index}.example.internal") for index, s in enumerate(servers)]
    scans = [enqueue_scan(web_factory, {"endpoint_ids": [endpoint]}, clock(), max_attempts=1) for endpoint in endpoints]
    with web_factory.begin() as db:
        cleanup_id = enqueue(
            db, JobType.CLEANUP, {"reason": "scheduled"}, SYSTEM_ACTOR, priority=10, run_after=clock(), max_attempts=1
        ).id
    assert worker_harness.poll() == 3  # two scans plus the cleanup job in the free slot
    states = [job_state(web_factory, job_id)[0] for job_id in scans]
    assert sorted(states) == [JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.RUNNING]
    assert worker_harness.poll() == 0  # still no discovery/scan capacity
    worker_harness.run_queued()
    assert [job_state(web_factory, job_id)[0] for job_id in (*scans, cleanup_id)] == [JobStatus.SUCCEEDED] * 4


def test_bounded_concurrency_never_exceeds_twenty_connections(
    worker_harness, web_factory, tls_servers, pull_certs, clock
):
    set_setting(web_factory, "scan.timeout_seconds", 2)
    servers = [serve(tls_servers, pull_certs, mode="silent") for _ in range(25)]
    ids = [add_endpoint(web_factory, s.host, s.port, sni="h.example.internal") for s in servers]
    job_id = enqueue_scan(web_factory, {"endpoint_ids": ids}, clock(), max_attempts=1)

    def accepted():
        return sum(1 for server in servers if server.connections)

    assert worker_harness.poll() == 1
    wait_until(lambda: accepted() >= 20, timeout=1.5)
    time.sleep(0.5)  # well inside the 2 s timeout: the other five wait for a free worker thread
    assert accepted() == 20
    assert worker_harness.wait_idle(30)
    assert accepted() == 25
    assert job_state(web_factory, job_id) == ("succeeded", None)
    assert job_result(web_factory, job_id)["unreachable"] == 25


# --- "Scan now" on the certificate detail page ---------------------------------------------------


def scan_jobs(factory):
    with factory() as db:
        return list(db.scalars(select(Job).where(Job.type == JobType.SCAN).order_by(Job.created_at)))


def test_cert_detail_scan_now_enqueues_on_demand_scan(
    signed_in, worker_harness, web_factory, web_user, tls_servers, pull_certs, clock
):
    certificate_id = add_certificate(web_factory, pull_certs.leaf)
    live = serve(tls_servers, pull_certs)
    endpoint = add_endpoint(web_factory, live.host, live.port, expected=certificate_id)
    path = f"/certificates/{certificate_id}/scan"

    assert signed_in.post(path, follow_redirects=False).status_code == 403  # no CSRF token
    assert scan_jobs(web_factory) == []

    response = signed_in.post(path, data={"csrf_token": signed_in.fixture_csrf}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/certificates/{certificate_id}#endpoints-panel"
    (job,) = scan_jobs(web_factory)
    assert (job.status, job.priority, job.payload) == (JobStatus.QUEUED, 200, {"certificate_id": certificate_id})
    assert (job.requested_by, job.max_attempts, job.scheduled_reason) == (web_user.id, 3, "manual")
    assert live.connections == 0  # the web process only enqueues
    worker_harness.run_queued()
    assert live.connections == 1
    (row,) = results_of(web_factory, endpoint)
    assert (row.status, row.source) == (ScanStatus.OK, "manual")
    page = signed_in.get(f"/certificates/{certificate_id}")
    assert f'action="/certificates/{certificate_id}/scan"' in page.text


def test_cert_detail_scan_now_without_an_active_endpoint_is_a_422(
    signed_in, web_factory, pull_certs, tls_servers, clock
):
    certificate_id = add_certificate(web_factory, pull_certs.leaf)
    path = f"/certificates/{certificate_id}/scan"
    data = {"csrf_token": signed_in.fixture_csrf}
    assert signed_in.post(path, data=data, follow_redirects=False).status_code == 422  # no endpoint at all
    parked = serve(tls_servers, pull_certs)
    add_endpoint(web_factory, parked.host, parked.port, expected=certificate_id, active=False)
    response = signed_in.post(path, data=data, follow_redirects=False)
    assert response.status_code == 422 and "No active endpoint expects this certificate" in response.text
    assert scan_jobs(web_factory) == [] and parked.connections == 0
    assert signed_in.post("/certificates/999999/scan", data=data, follow_redirects=False).status_code == 404
