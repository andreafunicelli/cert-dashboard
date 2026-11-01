"""Overview queue counts (spec §8.2): the numbers the landing page's work queue needs.

Every test runs in one rolled-back transaction, so the first test really starts from an empty database.
Each count is asserted against the filtered list it links to, so a count can never drift from the rows the
operator sees. Boundary rule: ``lt7`` is ``now <= not_after < now + 7 days`` — a certificate that expires at
exactly ``now + 7 days`` is *not* "expiring within 7 days" (it is in the ``lt30`` bucket), the same rule the
``/certificates?expiry=lt7`` filter uses.
"""

import secrets
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto.parse import parse_certificates
from app.models import Certificate, Job, JobHost, PrivateKey, Renewal
from app.models.enums import (
    CertificateStatus,
    ChainStatus,
    JobHostStatus,
    JobStatus,
    JobType,
    PrivateKeyType,
    RenewalState,
    ScanStatus,
)
from app.services.certificates import CertificateFilters, list_certificates
from app.services.deploy_views import JobFilters, list_jobs
from app.services.endpoints import EndpointFilters, list_endpoints
from app.services.overview import QueueCounts, queue_counts, status_strip
from app.services.renewals import RenewalFilters, list_renewals
from tests.integration.conftest import add_endpoint, add_results, add_server

BASE = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def _certificate(db, ca, days: int, *, status: CertificateStatus = CertificateStatus.ACTIVE) -> Certificate:
    """An active certificate expiring ``days`` after the fixture ``now`` (negative: already expired)."""
    name = f"queue-{secrets.token_hex(4)}.example.test"
    not_after = BASE + timedelta(days=days)
    pem = ca.issue(
        public_key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        common_name=name,
        sans=[name],
        not_before=not_after - timedelta(days=365),
        not_after=not_after,
    )
    parsed = parse_certificates(pem)[0]
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
        status=status,
    )
    db.add(row)
    db.flush()
    return row


def _key(db) -> int:
    key = PrivateKey(
        key_type=PrivateKeyType.ECDSA,
        key_size=256,
        curve="P-256",
        ciphertext=b"x",
        nonce=b"n" * 12,
        aad="fixture",
        master_key_version=1,
        public_key_sha256=secrets.token_hex(32),
        public_key_pem="fixture",
        origin="generated",
    )
    db.add(key)
    db.flush()
    return key.id


def _renewal(db, now, state: RenewalState, *, age_days: int = 0, name: str | None = None) -> Renewal:
    keyless = state in (RenewalState.DRAFT, RenewalState.CANCELLED)
    common_name = name or f"renew-{secrets.token_hex(4)}.example.test"
    row = Renewal(
        common_name=common_name,
        sans=[common_name],
        state=state,
        state_changed_at=now - timedelta(days=age_days),
        key_id=None if keyless else _key(db),
    )
    db.add(row)
    db.flush()
    return row


def _job(db, kind: JobType, status: JobStatus, payload: dict, *, finished=None) -> Job:
    job = Job(
        type=kind,
        status=status,
        priority=100,
        payload=payload,
        run_after=finished or BASE,
        finished_at=finished,
        started_at=finished,
    )
    db.add(job)
    db.flush()
    return job


def _host(db, job: Job, server_id: int, status: JobHostStatus, *, rolled_back: bool = False) -> JobHost:
    row = JobHost(job_id=job.id, server_id=server_id, status=status, rolled_back=rolled_back, finished_at=BASE)
    db.add(row)
    db.flush()
    return row


def _zero() -> QueueCounts:
    return QueueCounts(
        certificates_expired=0,
        certificates_expiring_7d=0,
        endpoints_mismatch=0,
        deploy_jobs_failed=0,
        deploy_jobs_rolled_back=0,
        renewals_awaiting_certificate=0,
        scans_running=0,
        deploys_running=0,
    )


def test_queue_counts_are_zero_on_an_empty_database(db, now):
    assert queue_counts(db, now) == _zero()


def test_queue_counts_read_every_queue_from_its_own_rows(db, ca, now):
    rollback_host, plain_host = (
        add_server(db, f"queue-a-{secrets.token_hex(3)}.example.test").id,
        add_server(db, f"queue-b-{secrets.token_hex(3)}.example.test").id,
    )

    # Certificates: an active expired one, an active < 7 days one, and a superseded expired one (ignored).
    _certificate(db, ca, -400)
    _certificate(db, ca, 3)
    _certificate(db, ca, -2, status=CertificateStatus.SUPERSEDED)

    # Endpoints: the newest result of one endpoint mismatches, one is healthy, one inactive mismatches.
    mismatch = add_endpoint(db, f"mismatch-{secrets.token_hex(3)}.example.test")
    add_results(db, mismatch, [(now - timedelta(hours=2), "ok"), (now, "mismatch")])
    add_results(db, add_endpoint(db, f"ok-{secrets.token_hex(3)}.example.test"), [(now, "ok")])
    add_results(
        db,
        add_endpoint(db, f"off-{secrets.token_hex(3)}.example.test", is_active=False),
        [(now, "mismatch")],
    )

    # Jobs: one plain failure, one rollout that rolled back a host, one running each, one queued deploy.
    failed = _job(db, JobType.DEPLOY, JobStatus.FAILED, {"certificate_id": 1}, finished=now)
    _host(db, failed, rollback_host, JobHostStatus.FAILED)
    rolled_back = _job(db, JobType.DEPLOY, JobStatus.FAILED, {"certificate_id": 1}, finished=now)
    _host(db, rolled_back, rollback_host, JobHostStatus.SUCCEEDED)
    _host(db, rolled_back, plain_host, JobHostStatus.ROLLED_BACK, rolled_back=True)
    _job(db, JobType.DEPLOY, JobStatus.RUNNING, {"certificate_id": 1})
    _job(db, JobType.SCAN, JobStatus.RUNNING, {"endpoint_ids": [1]})
    _job(db, JobType.DEPLOY, JobStatus.QUEUED, {"certificate_id": 1})
    _job(db, JobType.DEPLOY, JobStatus.SUCCEEDED, {"certificate_id": 1}, finished=now)

    # Renewals: three wait for the CA, an issued and a done one do not.
    for state in (RenewalState.DRAFT, RenewalState.CSR_GENERATED, RenewalState.SUBMITTED):
        _renewal(db, now, state)
    _renewal(db, now, RenewalState.ISSUED)
    _renewal(db, now, RenewalState.DONE)

    counts = queue_counts(db, now)
    assert counts == QueueCounts(
        certificates_expired=1,
        certificates_expiring_7d=1,
        endpoints_mismatch=1,
        deploy_jobs_failed=1,
        deploy_jobs_rolled_back=1,
        renewals_awaiting_certificate=3,
        scans_running=1,
        deploys_running=1,
    )


def test_expiring_within_seven_days_stops_exactly_at_seven_days(db, ca, now):
    _certificate(db, ca, -1)  # expired, not expiring
    _certificate(db, ca, 0)  # expires now: still < 7 days
    _certificate(db, ca, 6)  # 6 days: < 7 days
    boundary = _certificate(db, ca, 7)  # exactly 7 days: the next bucket, never this one
    _certificate(db, ca, 8)

    counts = queue_counts(db, now)
    assert (counts.certificates_expired, counts.certificates_expiring_7d) == (1, 2)
    with_now = list_certificates(db, CertificateFilters(status=CertificateStatus.ACTIVE, expiry="lt7"), now=now)
    assert counts.certificates_expiring_7d == with_now.total
    assert boundary.id not in {row.id for row in with_now.items}


def test_each_queue_count_equals_the_filtered_list_it_links_to(db, ca, now):
    """The anti-drift assertion: the queue number and the list rows are the same predicate, not two."""
    server = add_server(db, f"queue-{secrets.token_hex(3)}.example.test")
    _certificate(db, ca, -10)
    _certificate(db, ca, -1)
    _certificate(db, ca, 2)
    _certificate(db, ca, 5)
    _certificate(db, ca, 30)
    _certificate(db, ca, -5, status=CertificateStatus.SUPERSEDED)
    mismatch = add_endpoint(db, f"mismatch-{secrets.token_hex(3)}.example.test")
    add_results(db, mismatch, [(now, "mismatch")])
    add_results(db, add_endpoint(db, f"ok-{secrets.token_hex(3)}.example.test"), [(now, "ok")])
    for status, host_status in (
        (JobStatus.FAILED, JobHostStatus.FAILED),
        (JobStatus.FAILED, JobHostStatus.ROLLED_BACK),
        (JobStatus.RUNNING, JobHostStatus.RUNNING),
        (JobStatus.SUCCEEDED, JobHostStatus.SUCCEEDED),
        (JobStatus.QUEUED, JobHostStatus.PENDING),
    ):
        finished = now if status in (JobStatus.FAILED, JobStatus.SUCCEEDED, JobStatus.CANCELLED) else None
        job = _job(db, JobType.DEPLOY, status, {"certificate_id": 1}, finished=finished)
        _host(db, job, server.id, host_status, rolled_back=host_status is JobHostStatus.ROLLED_BACK)
    _job(db, JobType.SCAN, JobStatus.RUNNING, {"endpoint_ids": [1]})
    _job(db, JobType.SCAN, JobStatus.QUEUED, {"endpoint_ids": [1]})
    for state in (RenewalState.DRAFT, RenewalState.SUBMITTED, RenewalState.ISSUED, RenewalState.DONE):
        _renewal(db, now, state)

    counts = queue_counts(db, now)
    certificates = CertificateFilters(status=CertificateStatus.ACTIVE)
    assert counts.certificates_expired == list_certificates(
        db, CertificateFilters(status=CertificateStatus.ACTIVE, expiry="expired"), now=now
    ).total == 2
    assert counts.certificates_expiring_7d == list_certificates(
        db, CertificateFilters(status=CertificateStatus.ACTIVE, expiry="lt7"), now=now
    ).total == 2
    assert counts.endpoints_mismatch == list_endpoints(db, EndpointFilters(status=ScanStatus.MISMATCH)).total == 1
    assert counts.deploy_jobs_failed == list_jobs(
        db, JobFilters(outcome="failed", type=JobType.DEPLOY)
    ).total == 1
    assert counts.deploy_jobs_rolled_back == list_jobs(
        db, JobFilters(outcome="rolled_back", type=JobType.DEPLOY)
    ).total == 1
    assert counts.deploys_running == list_jobs(
        db, JobFilters(outcome="running", type=JobType.DEPLOY)
    ).total == 1
    assert counts.scans_running == list_jobs(db, JobFilters(outcome="running", type=JobType.SCAN)).total == 1
    assert counts.renewals_awaiting_certificate == list_renewals(
        db, RenewalFilters(state="awaiting_certificate"), now=now
    ).total == 2
    # The expiry buckets are still the overview's own disjoint ranges, unchanged by this card.
    assert list_certificates(db, certificates, now=now).total == 5


def test_status_strip_reports_the_last_successful_discovery(db, now):
    assert status_strip(db, now).last_discovery_at is None

    failed = _job(db, JobType.DISCOVER, JobStatus.FAILED, {}, finished=now - timedelta(minutes=5))
    assert failed.id is not None
    assert status_strip(db, now).last_discovery_at is None

    _job(db, JobType.DISCOVER, JobStatus.SUCCEEDED, {}, finished=now - timedelta(hours=2))
    newest = _job(db, JobType.DISCOVER, JobStatus.SUCCEEDED, {}, finished=now - timedelta(hours=1))
    # A later failure (or a queued run) is not a discovery: only a successful run moves the strip.
    _job(db, JobType.DISCOVER, JobStatus.FAILED, {}, finished=now)
    assert status_strip(db, now).last_discovery_at == newest.finished_at
