"""Plan 2 Task 17 (spec §10.2 scenarios 10 and 11): real nginx/Apache TLS servers and a compose SMTP capture.

The targets come from ``docker-compose.test.yml`` (profile ``targets``); nothing here reaches the internet.
"""

import hashlib
from dataclasses import dataclass
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy import select

from app.crypto.parse import parse_certificates
from app.jobs.queue import SYSTEM_ACTOR, enqueue
from app.models import Certificate, Endpoint, Job, ScanResult
from app.models.enums import ChainStatus, JobStatus, JobType
from tests.integration.conftest import add_endpoint, configure_smtp, disable_schedules, set_setting


@dataclass(frozen=True)
class TargetCertificate:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey
    chain: list[x509.Certificate]


def issue_target_pair(ca, now):
    """Two distinct leaves for the same name, so a reload from the first to the second is a mismatch."""
    pair = []
    for _ in range(2):
        key = ec.generate_private_key(ec.SECP256R1())
        pem = ca.issue(
            public_key=key.public_key(),
            common_name="target.example.internal",
            sans=["target.example.internal"],
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=90),
        )
        pair.append(TargetCertificate(x509.load_pem_x509_certificate(pem), key, [ca.intermediate]))
    return tuple(pair)


def fingerprint_of(target: TargetCertificate) -> str:
    return hashlib.sha256(target.cert.public_bytes(Encoding.DER)).hexdigest()


def endpoint_expecting(factory, host, port, expected: TargetCertificate) -> int:
    """Commit the expected certificate and an active endpoint that expects it."""
    parsed = parse_certificates(expected.cert.public_bytes(Encoding.DER))[0]
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
        return add_endpoint(db, host, port, sni="target.example.internal", expected_certificate_id=row.id)


def run_scan(factory, worker, payload, now) -> None:
    """Queue one single-attempt scan job (an unreachable endpoint is then a result, not a retry) and run it."""
    with factory.begin() as db:
        enqueue(db, JobType.SCAN, payload, SYSTEM_ACTOR, priority=100, run_after=now - timedelta(minutes=1), max_attempts=1)
    assert worker.run_queued() == 1


def latest_status(factory, endpoint_id) -> str:
    with factory() as db:
        return db.get(Endpoint, endpoint_id).last_scan_status.value


def latest_observed_fingerprint(factory, endpoint_id) -> str | None:
    with factory() as db:
        return db.scalars(
            select(ScanResult.observed_fingerprint).where(ScanResult.endpoint_id == endpoint_id).order_by(ScanResult.id.desc())
        ).first()


@pytest.mark.parametrize("service", ["tls-nginx", "tls-apache"])
def test_real_webserver_scan_reports_ok_then_mismatch_then_unreachable(
    service, compose_targets, queue_factory, make_worker, ca, clock
):
    set_setting(queue_factory, "scan.timeout_seconds", 10)
    host, port = compose_targets.address(service)
    first, second = issue_target_pair(ca, clock())
    compose_targets.serve(service, first.cert, first.key, first.chain)
    endpoint_id = endpoint_expecting(queue_factory, host, port, first)
    worker = make_worker(queue_factory)
    statuses, observed = [], []
    for change in (
        None,
        lambda: compose_targets.serve(service, second.cert, second.key, second.chain),
        lambda: compose_targets.stop(service),
    ):
        if change:
            change()
        run_scan(queue_factory, worker, {"endpoint_ids": [endpoint_id]}, clock())
        statuses.append(latest_status(queue_factory, endpoint_id))
        observed.append(latest_observed_fingerprint(queue_factory, endpoint_id))
    # The scanner must have seen exactly the leaf the target was made to serve (a stale server generation
    # answering the scan shows up here as the wrong fingerprint, not as a bare status difference).
    assert observed == [fingerprint_of(first), fingerprint_of(second), None], f"{service}: served leaves {observed}"
    assert statuses == ["ok", "mismatch", "unreachable"]


def test_compose_smtp_target_receives_the_test_email(
    signed_in, worker_harness, web_factory, web_user, compose_targets
):
    disable_schedules(web_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup", "discovery")
    with web_factory.begin() as db:
        db.query(Job).delete()
    _, port = compose_targets.address("smtp")
    assert not compose_targets.messages()
    configure_smtp(web_factory, type("Relay", (), {"port": port})())
    response = signed_in.post("/settings/smtp/test", data={"csrf_token": signed_in.fixture_csrf}, follow_redirects=False)
    assert response.status_code == 303
    worker_harness.run_queued()
    with web_factory() as db:
        [job] = db.scalars(select(Job).where(Job.type == JobType.ALERT_EXPIRY))
    assert job.status == JobStatus.SUCCEEDED, job.error_message
    [message] = compose_targets.messages()
    assert message["To"] == web_user.email and message["Subject"] == "Cert Dashboard test email"
