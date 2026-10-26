"""Plan 2 Task 16: Overview TLS health, recent jobs, renewals in flight and status strip (real Postgres)."""

import re
import secrets
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import delete

from app.models import (
    Binding,
    Certificate,
    Endpoint,
    Job,
    NotificationLog,
    PrivateKey,
    Renewal,
    ScanResult,
    Server,
    User,
    WorkerHeartbeat,
)
from app.models.enums import (
    EndpointSource,
    JobStatus,
    JobType,
    NotificationStatus,
    PrivateKeyType,
    RenewalState,
    ScanStatus,
)
from app.services.certificates import expiry_counts
from app.services.overview import (
    RecentJob,
    TLSHealth,
    job_summary,
    overview_snapshot,
    recent_jobs,
    renewals_in_flight,
    status_strip,
    tls_health,
)
from tests.integration.conftest import add_binding, add_server, expiring

MINUTE = timedelta(minutes=1)
UNKNOWN_FINGERPRINT = "a" * 64


def _key(db) -> int:
    key = PrivateKey(
        key_type=PrivateKeyType.ECDSA, key_size=256, curve="P-256", ciphertext=b"x", nonce=b"n" * 12,
        aad="fixture", master_key_version=1, public_key_sha256=secrets.token_hex(32),
        public_key_pem="fixture", origin="generated",
    )
    db.add(key)
    db.flush()
    return key.id


def _renewal(db, now, state, days, name):
    keyless = state in (RenewalState.DRAFT, RenewalState.CANCELLED)
    renewal = Renewal(
        common_name=name, sans=[name], state=state, state_changed_at=now - timedelta(days=days),
        key_id=None if keyless else _key(db),
    )
    db.add(renewal)
    db.flush()
    return renewal


def _job(db, kind, status, payload, *, finished=None, started=None, created=None, user=None, result=None):
    columns = {"created_at": created} if created else {}  # otherwise the server default applies
    job = Job(
        type=kind, status=status, priority=100, payload=payload, run_after=created or finished,
        requested_by=user.id if user else None, finished_at=finished, started_at=started, result=result, **columns,
    )
    db.add(job)
    db.flush()
    return job


def _build_world(db, now):
    """TLS: ok 2, mismatch 1, expired 1, unreachable 1, never 1 (inactive rows ignored). 12 jobs, 2 open renewals."""
    token = secrets.token_hex(3)
    user = User(username=f"ops-{token}", email=f"ops-{token}@example.test")
    db.add(user)
    db.flush()
    states = [("ok", True), ("ok", True), ("mismatch", True), ("expired", True), ("unreachable", True), (None, True),
              ("error", False), ("ok", False)]
    for number, (status, active) in enumerate(states):
        db.add(Endpoint(
            host=f"ep{number}-{token}.example.test", source=EndpointSource.MANUAL, is_active=active,
            last_scan_status=ScanStatus(status) if status else None,
        ))
    server = add_server(db, f"srv-{token}.example.test")
    for vhost, state, fingerprint in (
        ("u1", "unknown", UNKNOWN_FINGERPRINT), ("u2", "unknown", UNKNOWN_FINGERPRINT),  # one certificate, two vhosts
        ("k1", "key_mismatch", "b" * 64), ("m1", "matched", "c" * 64), ("gone", "unknown", "d" * 64),
    ):
        binding = add_binding(db, server, f"{vhost}-{token}.example.test", match_state=state, fingerprint=fingerprint, at=now)
        binding.is_active = vhost != "gone"
    failed = _job(db, JobType.SCAN, JobStatus.FAILED, {"endpoint_ids": [1, 2]}, user=user,
                  started=now - 3 * MINUTE, finished=now - MINUTE)
    pull = _job(db, JobType.SCAN, JobStatus.SUCCEEDED, {"action": "import_pull", "host": "pull.example.test", "port": 443},
                started=now - 2 * MINUTE, finished=now - 2 * MINUTE)
    queued = _job(db, JobType.DIGEST, JobStatus.QUEUED, {}, created=now - 5 * MINUTE)  # ordered by created_at
    cleanups = [
        _job(db, JobType.CLEANUP, JobStatus.SUCCEEDED, {"reason": "scheduled", "notes": "SECRET-NOTE"},
             finished=now - (10 + number) * MINUTE)
        for number in range(9)
    ]
    db.add(WorkerHeartbeat(worker_id=f"w-{token}", started_at=now - timedelta(hours=1), last_seen_at=now - timedelta(seconds=30)))
    for sent_at, status, key in ((now - timedelta(hours=26), NotificationStatus.SENT, "old"),
                                 (now - timedelta(hours=2), NotificationStatus.SENT, "new"),
                                 (None, NotificationStatus.FAILED, "failed")):
        db.add(NotificationLog(kind="digest", recipients=["ops@example.test"], status=status, sent_at=sent_at,
                               dedupe_key=f"digest:{token}:{key}"))
    stalled = _renewal(db, now, RenewalState.SUBMITTED, 10, f"stalled-{token}.example.test")
    fresh = _renewal(db, now, RenewalState.CSR_GENERATED, 2, f"fresh-{token}.example.test")
    _renewal(db, now, RenewalState.DONE, 30, f"done-{token}.example.test")
    _renewal(db, now, RenewalState.CANCELLED, 40, f"cancelled-{token}.example.test")
    db.flush()
    return SimpleNamespace(
        user=user, failed=str(failed.id), pull=str(pull.id), queued=str(queued.id), stalled=str(stalled.id),
        fresh=str(fresh.id), oldest_cleanups={str(job.id) for job in cleanups[-2:]},
    )


@pytest.fixture
def overview_world(db, now):
    return _build_world(db, now)


@pytest.fixture
def web_world(web_factory, now):
    with web_factory.begin() as session:
        return _build_world(session, now)


@pytest.fixture(autouse=True)
def _clean_web_database(web_factory):
    """The web database is shared by the whole module: every test starts empty."""
    with web_factory.begin() as session:
        for model in (WorkerHeartbeat, NotificationLog, Renewal, PrivateKey, Job, ScanResult, Endpoint, Binding, Server, Certificate):
            session.execute(delete(model))
    yield


def test_overview_snapshot_counts_tls_health_and_recent_work(db, overview_world, now):
    snapshot = overview_snapshot(db, now)
    assert snapshot.tls == TLSHealth(ok=2, mismatch=1, expired=1, unreachable=1, error=0,
                                     never_scanned=1, unknown_certificates=1, key_mismatch_bindings=1)
    assert [job.status for job in snapshot.recent_jobs][:2] == ["failed", "succeeded"]
    assert len(snapshot.recent_jobs) == 10 and snapshot.recent_jobs[0].href.startswith("/audit?")
    assert [renewal.state for renewal in snapshot.renewals] == ["submitted", "csr_generated"]
    ids = [job.id for job in snapshot.recent_jobs]
    assert ids[:3] == [overview_world.failed, overview_world.pull, overview_world.queued]
    assert not overview_world.oldest_cleanups & set(ids)
    failed, pull, queued = snapshot.recent_jobs[:3]
    assert (failed.summary, failed.actor, failed.duration_seconds, failed.finished_at) == ("2 endpoints", overview_world.user.username, 120, now - MINUTE)
    assert (pull.summary, pull.actor, pull.href) == ("pull pull.example.test:443", "system", f"/imports/{pull.id}")
    assert (queued.type, queued.duration_seconds, queued.finished_at) == ("digest", None, None)
    assert [(item.id, item.age_days) for item in snapshot.renewals] == [(overview_world.stalled, 10), (overview_world.fresh, 2)]
    assert snapshot.status.worker == "ok" and snapshot.status.last_heartbeat_at == now - timedelta(seconds=30)
    assert snapshot.status.last_digest_at == now - timedelta(hours=2)  # newest *sent* row
    assert (snapshot.status.inventory_rev, snapshot.status.inventory_rev_age_hours) == (None, None)
    assert isinstance(failed, RecentJob) and "SECRET-NOTE" not in repr(snapshot)


def test_job_summaries_never_echo_raw_payloads():
    assert job_summary(JobType.SCAN, {"endpoint_ids": [1, 2, 3]}) == "3 endpoints"
    assert job_summary(JobType.SCAN, {"action": "import_pull", "host": "h", "port": 443, "metadata": {"notes": "x"}}) == "pull h:443"
    assert "notes" not in job_summary(JobType.CLEANUP, {"reason": "manual_prune", "notes": "x"})
    assert job_summary(JobType.SCAN, {"endpoint_ids": [1]}) == "1 endpoint"
    assert job_summary(JobType.SCAN, {"certificate_id": 7}) == "certificate 7"
    assert job_summary(JobType.DEPLOY, {"certificate_id": 7, "mode": "dry_run", "notes": "x"}) == "certificate 7 (dry_run)"
    assert job_summary(JobType.SCAN, {}) == "all endpoints"
    assert job_summary(JobType.CLEANUP, {"reason": "<script>alert(1)</script> password=hunter2"}) == ""
    assert job_summary(JobType.SCAN, {"endpoint_ids": "not-a-list", "certificate_id": "7; drop"}) == "all endpoints"
    assert job_summary(JobType.SCAN, {"action": "import_pull", "host": ["h"], "port": "x"}) == "pull"
    assert job_summary(JobType.DIGEST, {"notes": "x"}) == ""
    assert job_summary(JobType.CLEANUP, {"reason": "scheduled", "notes": "x"}) == "scheduled"
    assert job_summary(JobType.ALERT_EXPIRY, {"mode": "retry_failed"}) == "retry failed"


CANARY = "CANARY123"


@pytest.mark.parametrize("job_type", list(JobType))
@pytest.mark.parametrize("field", ["reason", "mode", "action", "notes", "host", "metadata"])
def test_job_summaries_ignore_values_outside_the_per_type_allowlist(job_type, field):
    """A valid-looking canary word under any key never renders, whatever the job type."""
    assert CANARY not in job_summary(job_type, {field: CANARY, "certificate_id": 7, "endpoint_ids": [1]})
    assert CANARY not in job_summary(job_type, {field: CANARY})


@pytest.mark.parametrize(
    ("job_type", "payload", "expected"),
    [
        (JobType.DIGEST, {"reason": CANARY, "mode": CANARY, "certificate_id": 7}, ""),
        (JobType.DISCOVER, {"reason": CANARY, "mode": CANARY, "certificate_id": 7}, ""),
        (JobType.SCAN, {"reason": CANARY, "mode": CANARY}, "all endpoints"),
        (JobType.CLEANUP, {"reason": CANARY, "mode": "dry_run", "certificate_id": 7}, ""),
        (JobType.ALERT_EXPIRY, {"reason": CANARY, "mode": CANARY, "certificate_id": 7}, ""),
        (JobType.DEPLOY, {"reason": "scheduled", "mode": CANARY}, ""),
    ],
)
def test_job_summaries_render_only_the_fields_each_type_allows(job_type, payload, expected):
    assert job_summary(job_type, payload) == expected


def test_inventory_revision_comes_from_the_newest_succeeded_discover_or_deploy_job(db, now):
    stamp = (now - timedelta(hours=5)).isoformat()
    _job(db, JobType.DISCOVER, JobStatus.SUCCEEDED, {}, finished=now - timedelta(hours=9),
         result={"inventory_rev": "old1234", "inventory_rev_date": (now - timedelta(hours=20)).isoformat()})
    _job(db, JobType.DEPLOY, JobStatus.SUCCEEDED, {}, finished=now - timedelta(hours=4),
         result={"inventory_rev": "abc1234", "inventory_rev_date": stamp})
    _job(db, JobType.DISCOVER, JobStatus.FAILED, {}, finished=now - MINUTE, result={"inventory_rev": "failed99"})
    status = overview_snapshot(db, now).status
    assert (status.inventory_rev, status.inventory_rev_age_hours) == ("abc1234", 5)


def test_renewals_in_flight_cover_every_open_state_oldest_first(db, now):
    for age, state in enumerate(RenewalState, start=1):
        _renewal(db, now, state, age, f"{state.value}.example.test")
    shown = overview_snapshot(db, now).renewals
    assert [item.state for item in shown] == ["deployed", "issued", "submitted", "csr_generated", "draft"]
    assert [item.age_days for item in shown] == [5, 4, 3, 2, 1]


def _row(html, attribute, value):
    match = re.search(rf"<(tr|li|a|section)[^>]*{attribute}=\"{re.escape(value)}\"[^>]*>.*?</\1>", html, re.DOTALL)
    assert match, (attribute, value)
    return match.group(0)


def test_overview_page_fills_every_slot_and_links_filters(signed_in, web_world):
    page = signed_in.get("/")
    assert page.status_code == 200
    links = {
        "ok": ("/scans?status=ok", 2), "mismatch": ("/scans?status=mismatch", 1), "expired": ("/scans?status=expired", 1),
        "unreachable": ("/scans?status=unreachable", 1), "error": ("/scans?status=error", 0), "never_scanned": ("/scans", 1),
        "unknown_certificates": ("/bindings?match_state=unknown", 1), "key_mismatch_bindings": ("/bindings?match_state=key_mismatch", 1),
    }
    for name, (href, count) in links.items():
        counter = _row(page.text, "data-tls", name)
        assert f'href="{href}"' in counter and f"<strong>{count}</strong>" in counter, name
    failed, pull = _row(page.text, "data-job-id", web_world.failed), _row(page.text, "data-job-id", web_world.pull)
    assert "job-failed" in failed and "job-failed" not in pull
    assert f'href="/audit?target_type=job&amp;target_id={web_world.failed}"' in failed
    assert "2 endpoints" in failed and web_world.user.username in failed and "2m" in failed
    assert f'href="/imports/{web_world.pull}"' in pull and "pull pull.example.test:443" in pull and "system" in pull
    assert page.text.count("data-job-id=") == 10 and "SECRET-NOTE" not in page.text
    stalled = _row(page.text, "data-renewal-id", web_world.stalled)
    assert f'href="/renewals/{web_world.stalled}"' in stalled and "submitted" in stalled and "10 days" in stalled
    assert "2 days" in _row(page.text, "data-renewal-id", web_world.fresh) and page.text.count("data-renewal-id=") == 2
    strip = _row(page.text, "data-status-strip", "true")
    assert "no inventory revision recorded yet" in strip and "2026-10-19" in strip and "ok" in strip
    assert "10:00" in strip  # last digest 2 h before the 12:00 fixture clock (UTC display)


def test_overview_page_without_data_says_so(signed_in):
    page = signed_in.get("/")
    assert page.status_code == 200 and "No jobs have run yet" in page.text and "No renewals in flight" in page.text
    assert "never" in _row(page.text, "data-status-strip", "true")


def test_expiry_counters_are_unchanged(signed_in, web_world, web_factory, now):
    for days in (-1, 3, 20, 45, 200):
        expiring(web_factory, days)
    page = signed_in.get("/")
    with web_factory() as session:
        assert expiry_counts(session, now) == {"expired": 1, "lt7": 1, "lt30": 1, "lt60": 1, "total_active": 5}
    for name, count in {"expired": 1, "lt7": 1, "lt30": 1, "lt60": 1, "total_active": 5}.items():
        counter = _row(page.text, "data-counter", name)
        assert f"<strong>{count}</strong>" in counter


def test_overview_query_count_is_constant(signed_in, web_world, count_statements, web_factory, now):
    assert signed_in.get("/").status_code == 200  # warm the per-app worker-liveness cache
    with count_statements() as small:
        signed_in.get("/")
    with web_factory.begin() as db:
        server = add_server(db, f"bulk-{secrets.token_hex(3)}.example.test")
        for number in range(30):
            _job(db, JobType.CLEANUP, JobStatus.FAILED, {"reason": "scheduled"}, finished=now - number * MINUTE)
            _renewal(db, now, RenewalState.SUBMITTED, number, f"bulk{number}.example.test")
            db.add(Endpoint(host=f"bulk{number}.example.test", source=EndpointSource.MANUAL, last_scan_status=ScanStatus.OK))
            add_binding(db, server, f"bulk{number}.example.test", match_state="unknown", fingerprint=f"{number:064x}", at=now)
    with count_statements() as large:
        page = signed_in.get("/")
    assert small.count == large.count and page.text.count("data-job-id=") == 10
    assert page.text.count("data-renewal-id=") == 32


def test_each_overview_slot_costs_a_fixed_number_of_statements(db, overview_world, now, engine, count_statements):
    """Task 16: one aggregate per slot; the status strip adds only the shared worker_liveness helper."""
    overview_snapshot(db, now)  # warm: savepoint and type caches
    slots = {
        "tls": (lambda: tls_health(db), 1),
        "jobs": (lambda: recent_jobs(db), 1),
        "renewals": (lambda: renewals_in_flight(db, now), 1),
        "status": (lambda: status_strip(db, now), 2),
        "snapshot": (lambda: overview_snapshot(db, now), 5),
    }
    for name, (run, expected) in slots.items():
        with count_statements(engine) as counter:
            run()
        assert counter.count == expected, name
