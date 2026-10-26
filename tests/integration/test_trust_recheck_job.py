"""scan/trust_recheck: the background trust recheck, its schedule and the "Recheck now" button."""

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import func, select

from app.crypto.chain import order_chain
from app.crypto.parse import parse_certificates
from app.jobs.queue import SYSTEM_ACTOR, enqueue
from app.models import AuditLog, Certificate, Endpoint, Job, ScanResult
from app.models.enums import EndpointSource, JobStatus, JobType
from app.services.audit import Actor
from app.services.certificates import CertificateMetadata, save_certificate
from app.services.scans import ScanObservation, record_scan
from app.services.trust_anchors import add_anchor
from tests.integration.conftest import set_setting

RECHECK = {"action": "trust_recheck"}
RECHECK_PATH = "/settings/trust-anchors/recheck"


def save_with_root_anchor(factory, leaf, chain, root, *, validation_time):
    actor = Actor(None, "fixture")
    with factory.begin() as db:
        add_anchor(db, root.public_bytes(Encoding.PEM), None, actor, validation_time)
        parsed = parse_certificates(leaf.public_bytes(Encoding.PEM))[0]
        saved = save_certificate(
            db,
            parsed,
            order_chain(leaf, list(chain)),
            CertificateMetadata(),
            actor,
            source="upload_pem",
            validation_time=validation_time,
        )
        return saved.certificate.id


def chain_status(factory, certificate_id):
    with factory() as db:
        return db.get(Certificate, certificate_id).chain_status.value


def chain_audits(factory, certificate_id):
    with factory() as db:
        return list(
            db.scalars(
                select(AuditLog)
                .where(AuditLog.action == "certificate.chain_check", AuditLog.target_id == str(certificate_id))
                .order_by(AuditLog.created_at)
            )
        )


def enqueue_recheck(factory, now):
    with factory.begin() as db:
        return enqueue(
            db, JobType.SCAN, RECHECK, SYSTEM_ACTOR, priority=100, run_after=now - timedelta(minutes=1)
        ).id


def scan_jobs(factory):
    with factory() as db:
        return list(db.scalars(select(Job).where(Job.type == JobType.SCAN).order_by(Job.created_at)))


def issue(cn, key, parent, parent_key, *, ca, before, after):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent.subject if parent else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca and parent else None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key((parent_key or key).public_key()), critical=False
        )
    )
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(parent_key or key, hashes.SHA256())


def expired_intermediate_certificate(queue_factory, clock):
    """Store a leaf whose intermediate has since expired, trusted as of the time it was still valid.

    The shared ``certs`` fixture cannot do this: its leaf is only valid after its intermediate expired.
    """
    now = clock()
    root_key, ca_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = issue("Recheck Root", root_key, None, None, ca=True, before=now - timedelta(days=400), after=now + timedelta(days=365))
    intermediate = issue(
        "Recheck Intermediate", ca_key, root, root_key, ca=True, before=now - timedelta(days=90), after=now - timedelta(days=30)
    )
    leaf = issue(
        "recheck.example.test", leaf_key, intermediate, ca_key, ca=False, before=now - timedelta(days=60), after=now + timedelta(days=300)
    )
    valid_at = max(leaf.not_valid_before_utc, intermediate.not_valid_before_utc) + timedelta(seconds=1)
    assert valid_at < intermediate.not_valid_after_utc < now
    return save_with_root_anchor(queue_factory, leaf, (intermediate,), root, validation_time=valid_at)


def test_background_recheck_notices_an_intermediate_that_expired(queue_factory, make_worker, clock):
    certificate_id = expired_intermediate_certificate(queue_factory, clock)
    assert chain_status(queue_factory, certificate_id) == "trusted"
    job_id = enqueue_recheck(queue_factory, clock())
    make_worker(queue_factory).run_queued()
    assert chain_status(queue_factory, certificate_id) == "incomplete"
    last = chain_audits(queue_factory, certificate_id)[-1]
    assert (last.details["status"], last.details["validation_time"]) == ("incomplete", clock().isoformat())
    assert last.actor_user_id is None and last.actor_label == "system"
    with queue_factory() as db:
        job = db.get(Job, job_id)
    assert job.status == JobStatus.SUCCEEDED
    assert job.result["incomplete"] == 1 and job.result["validation_time"] == clock().isoformat()
    assert set(job.result) == {"incomplete", "validation_time"}  # counts and the time only

    audits = len(chain_audits(queue_factory, certificate_id))
    enqueue_recheck(queue_factory, clock())
    make_worker(queue_factory).run_queued()
    assert len(chain_audits(queue_factory, certificate_id)) == audits  # unchanged statuses are not audited


def test_trust_recheck_is_scheduled_with_the_scan_time_and_flag(queue_factory, make_worker, clock):
    runtime = make_worker(queue_factory)
    clock.value = datetime(2026, 10, 19, 2, 0, 30, tzinfo=UTC)
    runtime.tick()
    jobs = scan_jobs(queue_factory)
    assert sorted((job.payload for job in jobs), key=len) == [{}, RECHECK]
    assert {(job.priority, job.scheduled_reason, job.requested_by) for job in jobs} == {(100, "daily", None)}
    runtime.tick()  # the same occurrence is never enqueued twice
    assert len(scan_jobs(queue_factory)) == 2

    set_setting(queue_factory, "scan.enabled", False)
    clock.value += timedelta(days=1)
    runtime.tick()
    assert len(scan_jobs(queue_factory)) == 2  # one flag switches off the scan and the recheck


def test_recheck_now_button_requires_csrf_and_enqueues(signed_in, web_factory, web_user, worker_harness, clock):
    page = signed_in.get("/settings?tab=trust")
    assert page.status_code == 200
    assert '<button type="submit">Recheck now</button>' in page.text  # enabled: the handler is registered
    assert signed_in.post(RECHECK_PATH, follow_redirects=False).status_code == 403  # no CSRF token
    assert scan_jobs(web_factory) == []

    response = signed_in.post(RECHECK_PATH, data={"csrf_token": signed_in.fixture_csrf}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/settings?tab=trust"
    (job,) = scan_jobs(web_factory)
    assert (job.status, job.priority, job.payload) == (JobStatus.QUEUED, 200, RECHECK)
    assert (job.requested_by, job.scheduled_reason) == (web_user.id, "manual")
    worker_harness.run_queued()  # the worker, not the web process, does the work
    with web_factory() as db:
        assert db.get(Job, job.id).status == JobStatus.SUCCEEDED


def test_trust_recheck_never_touches_endpoints_or_scan_results(queue_factory, make_worker, clock):
    certificate_id = expired_intermediate_certificate(queue_factory, clock)
    with queue_factory.begin() as db:
        endpoint = Endpoint(
            host="198.51.100.7", port=443, sni="www.example.internal", source=EndpointSource.MANUAL,
            expected_certificate_id=certificate_id,
        )
        db.add(endpoint)
        db.flush()
        observation = ScanObservation(None, None, None, None, None, None, "unreachable", "198.51.100.7:443 unreachable", 3)
        record_scan(db, endpoint.id, observation, "manual", clock())

    def snapshot():
        with queue_factory() as db:
            rows = db.execute(select(Endpoint.id, Endpoint.last_scan_at, Endpoint.last_scan_status, Endpoint.expected_certificate_id))
            results = db.execute(select(ScanResult.id, ScanResult.status, ScanResult.checked_at, ScanResult.observed_chain_length))
            return list(rows), list(results), db.scalar(select(func.count()).select_from(ScanResult))

    before = snapshot()
    assert before[2] == 1
    enqueue_recheck(queue_factory, clock())
    make_worker(queue_factory).run_queued()
    assert chain_status(queue_factory, certificate_id) == "incomplete"  # the job really ran
    assert snapshot() == before
