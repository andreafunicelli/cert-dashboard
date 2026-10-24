from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.jobs.queue import StaleJobError, claim, enqueue, finish, reap, retry_due
from app.models import AuditLog, Job, JobHost, Server, User
from app.models.enums import JobHostStatus, JobStatus, JobType
from app.services.audit import Actor


def add_job(factory, now, **overrides):
    """Commit one job row directly (bypassing enqueue) and return its id."""
    values = {
        "type": JobType.SCAN,
        "priority": 100,
        "payload": {},
        "run_after": now - timedelta(minutes=1),
        "max_attempts": 3,
    }
    values.update(overrides)
    with factory.begin() as db:
        job = Job(**values)
        db.add(job)
        db.flush()
        return job.id


def load(factory, job_id) -> Job:
    with factory() as db:
        return db.get(Job, job_id)


def audits(factory, action=None):
    with factory() as db:
        query = select(AuditLog).order_by(AuditLog.created_at, AuditLog.id)
        if action:
            query = query.where(AuditLog.action == action)
        return list(db.scalars(query))


def take(factory, worker, now, **kwargs):
    with factory.begin() as db:
        job = claim(db, worker, now, lambda db, job: 300, **kwargs)
        return job.id if job else None


def run_to_failure(factory, now, job_id, error_class, *, result=None, worker="w1"):
    """Claim ``job_id`` (the only claimable row) and fail it at ``now``."""
    assert take(factory, worker, now) == job_id
    with factory.begin() as db:
        finish(db, job_id, worker, "failed", now, result=result, error_class=error_class, error_message="x")


@pytest.fixture
def queue_actor(queue_factory):
    with queue_factory.begin() as db:
        user = User(username="queue-admin", email="queue@example.test")
        db.add(user)
        db.flush()
        return Actor(user.id, user.username, "192.0.2.10", "fixture-browser")


def test_claims_are_exclusive(queue_factory, seeded_jobs, now):
    def take(worker):
        with queue_factory.begin() as db:
            job = claim(db, worker, now, lambda db, job: 300)
            return job.id if job else None

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(take, [str(i) for i in range(8)]))
    assert len([i for i in ids if i]) == len({i for i in ids if i}) == 8
    assert set(ids) == set(seeded_jobs)


def test_more_workers_than_jobs_each_job_is_claimed_once(queue_factory, seeded_jobs, now):
    with ThreadPoolExecutor(max_workers=12) as pool:
        ids = list(pool.map(lambda i: take(queue_factory, str(i), now), range(12)))
    claimed = [i for i in ids if i]
    assert len(claimed) == len(set(claimed)) == 8
    assert ids.count(None) == 4


def test_claim_order_is_priority_then_run_after_then_created_at(queue_factory, now):
    early = now - timedelta(days=1)
    low_old = add_job(queue_factory, now, priority=100, run_after=now - timedelta(minutes=20))
    high = add_job(queue_factory, now, priority=200, run_after=now - timedelta(minutes=1))
    tie_late = add_job(
        queue_factory, now, run_after=now - timedelta(minutes=10), created_at=early + timedelta(hours=2)
    )
    tie_early = add_job(queue_factory, now, run_after=now - timedelta(minutes=10), created_at=early)
    cleanup = add_job(queue_factory, now, type=JobType.CLEANUP, priority=10, max_attempts=2)

    order = [take(queue_factory, "w", now) for _ in range(6)]

    assert order == [high, low_old, tie_early, tie_late, cleanup, None]


def test_equal_priority_run_after_and_created_at_fall_back_to_id(queue_factory, now):
    stamp = now - timedelta(hours=1)
    ids = [add_job(queue_factory, now, run_after=stamp, created_at=stamp) for _ in range(3)]
    order = [take(queue_factory, "w", now) for _ in range(3)]
    assert order == sorted(ids)


def test_locked_head_row_is_skipped(queue_factory, now):
    head = add_job(queue_factory, now, priority=200)
    second = add_job(queue_factory, now, priority=100)
    holder = queue_factory()
    try:
        holder.execute(select(Job.id).where(Job.id == head).with_for_update())
        assert take(queue_factory, "w", now) == second
        assert take(queue_factory, "w", now) is None
    finally:
        holder.rollback()
        holder.close()
    assert take(queue_factory, "w", now) == head


def test_future_run_after_is_excluded_until_due(queue_factory, now):
    job_id = add_job(queue_factory, now, run_after=now + timedelta(seconds=1))
    assert take(queue_factory, "w", now) is None
    assert take(queue_factory, "w", now + timedelta(seconds=1)) == job_id


def test_claim_sets_ownership_attempt_and_timeout_from_the_callback(queue_factory, now):
    job_id = add_job(queue_factory, now, type=JobType.DIGEST)
    seen = []

    def timeout_seconds(db, job):
        seen.append((job.id, job.type, job.status, job.attempt))
        return 123

    with queue_factory.begin() as db:
        job = claim(db, "worker-a", now, timeout_seconds)

    assert seen == [(job_id, JobType.DIGEST, JobStatus.RUNNING, 1)]
    row = load(queue_factory, job_id)
    assert job.id == job_id and job.attempt == row.attempt == 1
    assert (row.status, row.locked_by) == (JobStatus.RUNNING, "worker-a")
    assert row.locked_at == row.started_at == now
    assert row.timeout_at == now + timedelta(seconds=123)


def test_failed_timeout_callback_leaves_the_job_queued(queue_factory, now):
    job_id = add_job(queue_factory, now)

    def broken(db, job):
        raise RuntimeError("no timeout available")

    with pytest.raises(RuntimeError), queue_factory.begin() as db:
        claim(db, "w", now, broken)
    row = load(queue_factory, job_id)
    assert (row.status, row.attempt, row.locked_by, row.timeout_at) == (JobStatus.QUEUED, 0, None, None)


def test_attempt_increments_on_every_claim(queue_factory, now):
    job_id = add_job(queue_factory, now)
    assert take(queue_factory, "w", now) == job_id
    with queue_factory.begin() as db:
        job = db.get(Job, job_id)
        job.status, job.locked_by = JobStatus.QUEUED, None
    assert take(queue_factory, "w", now) == job_id
    assert load(queue_factory, job_id).attempt == 2


def test_eligible_types_filter(queue_factory, now):
    scan = add_job(queue_factory, now, type=JobType.SCAN, priority=100)
    deploy = add_job(queue_factory, now, type=JobType.DEPLOY, priority=300, max_attempts=1)
    assert take(queue_factory, "w", now, eligible_types=frozenset()) is None
    assert take(queue_factory, "w", now, eligible_types=frozenset({JobType.DIGEST})) is None
    assert take(queue_factory, "w", now, eligible_types=frozenset({JobType.SCAN, JobType.DIGEST})) == scan
    assert take(queue_factory, "w", now, eligible_types=frozenset({JobType.SCAN})) is None
    assert take(queue_factory, "w", now, eligible_types=None) == deploy


def test_only_queued_jobs_are_claimable(queue_factory, now):
    for status in (
        JobStatus.PAUSED,
        JobStatus.RUNNING,
        JobStatus.SUCCEEDED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    ):
        add_job(queue_factory, now, status=status)
    assert take(queue_factory, "w", now) is None


def test_job_exhausted_at_three_attempts_is_never_claimed_a_fourth_time(queue_factory, now):
    job_id = add_job(queue_factory, now, attempt=3, max_attempts=3)
    assert take(queue_factory, "w", now) is None
    assert load(queue_factory, job_id).attempt == 3


def test_finish_succeeded_clears_claim_metadata_and_audits(queue_factory, now):
    job_id = add_job(queue_factory, now, type=JobType.DIGEST)
    take(queue_factory, "worker-a", now)
    done = now + timedelta(seconds=5)
    with queue_factory.begin() as db:
        finish(db, job_id, "worker-a", "succeeded", done, result={"sent": 2})
    row = load(queue_factory, job_id)
    assert row.status == JobStatus.SUCCEEDED and row.finished_at == done and row.result == {"sent": 2}
    assert (row.locked_by, row.locked_at, row.timeout_at) == (None, None, None)
    (audit,) = audits(queue_factory, "job.succeeded")
    assert (audit.actor_label, audit.actor_user_id) == ("worker:worker-a", None)
    assert (audit.target_type, audit.target_id) == ("job", str(job_id))
    assert audit.details == {"type": "digest", "attempt": 1, "error_class": None}


def test_finish_failed_stores_redacted_truncated_message(queue_factory, now):
    job_id = add_job(queue_factory, now)
    take(queue_factory, "w1", now)
    message = "connect failed password=fixture-secret " + "x" * 5000
    with queue_factory.begin() as db:
        finish(db, job_id, "w1", "failed", now, error_class="transient_network", error_message=message)
    row = load(queue_factory, job_id)
    assert row.status == JobStatus.FAILED and row.error_class == "transient_network"
    assert "fixture-secret" not in row.error_message
    assert len(row.error_message) <= 2000 and row.error_message.startswith("connect failed")
    (audit,) = audits(queue_factory, "job.failed")
    assert audit.details == {"type": "scan", "attempt": 1, "error_class": "transient_network"}
    assert "fixture-secret" not in str(audit.details)


@pytest.mark.parametrize(
    "bad_class",
    ["password=fixture-class-secret", "Bearer fixture-class-token", "has space", "x" * 200, ""],
)
def test_finish_never_persists_unsafe_error_class(queue_factory, now, bad_class):
    job_id = add_job(queue_factory, now)
    take(queue_factory, "w1", now)
    with queue_factory.begin() as db:
        finish(db, job_id, "w1", "failed", now, error_class=bad_class, error_message="failure")
    row = load(queue_factory, job_id)
    assert row.status == JobStatus.FAILED and row.error_class == "internal"
    (audit,) = audits(queue_factory, "job.failed")
    assert audit.details["error_class"] == "internal"
    for value in ("fixture-class-secret", "fixture-class-token"):
        assert value not in str(
            (row.error_class, row.error_message, row.result, audit.details, audit.actor_label)
        )
    with queue_factory.begin() as db:
        assert retry_due(db, now + timedelta(days=1)) == 0


def test_finish_cancelled(queue_factory, now):
    job_id = add_job(queue_factory, now)
    take(queue_factory, "w1", now)
    with queue_factory.begin() as db:
        finish(db, job_id, "w1", "cancelled", now)
    assert load(queue_factory, job_id).status == JobStatus.CANCELLED
    assert len(audits(queue_factory, "job.cancelled")) == 1


def test_finish_rejects_secret_bearing_result(queue_factory, now):
    job_id = add_job(queue_factory, now)
    take(queue_factory, "w1", now)
    with pytest.raises(ValueError, match="secret"), queue_factory.begin() as db:
        finish(db, job_id, "w1", "succeeded", now, result={"api_token": "fixture"})
    assert load(queue_factory, job_id).status == JobStatus.RUNNING


def test_wrong_owner_finish_is_rejected_and_changes_nothing(queue_factory, now):
    job_id = add_job(queue_factory, now)
    take(queue_factory, "owner", now)
    before = load(queue_factory, job_id)
    with pytest.raises(StaleJobError), queue_factory.begin() as db:
        finish(db, job_id, "intruder", "succeeded", now + timedelta(seconds=1))
    after = load(queue_factory, job_id)
    assert (after.status, after.locked_by, after.finished_at, after.timeout_at) == (
        before.status,
        before.locked_by,
        before.finished_at,
        before.timeout_at,
    )
    assert after.status == JobStatus.RUNNING and audits(queue_factory, "job.succeeded") == []


def test_finish_of_unknown_or_queued_job_is_stale(queue_factory, now):
    import uuid

    queued = add_job(queue_factory, now)
    for job_id in (uuid.uuid4(), queued):
        with pytest.raises(StaleJobError), queue_factory.begin() as db:
            finish(db, job_id, "w", "succeeded", now)
    assert load(queue_factory, queued).status == JobStatus.QUEUED


def test_late_finish_after_reap_is_rejected(queue_factory, now):
    job_id = add_job(queue_factory, now)
    take(queue_factory, "w1", now)  # timeout_at = now + 300
    later = now + timedelta(seconds=301)
    with queue_factory.begin() as db:
        assert reap(db, later) == 1
    reaped = load(queue_factory, job_id)
    with pytest.raises(StaleJobError), queue_factory.begin() as db:
        finish(db, job_id, "w1", "succeeded", later + timedelta(seconds=1), result={"late": True})
    after = load(queue_factory, job_id)
    assert after.status == JobStatus.FAILED and after.error_class == "timeout"
    assert (after.result, after.finished_at) == (reaped.result, reaped.finished_at)
    assert audits(queue_factory, "job.succeeded") == []


def test_late_finish_after_reap_and_reclaim_by_another_worker_is_rejected(queue_factory, now):
    job_id = add_job(queue_factory, now)
    take(queue_factory, "w1", now)
    with queue_factory.begin() as db:
        job = db.get(Job, job_id)
        job.locked_by = "w2"  # requeued and re-claimed elsewhere
    with pytest.raises(StaleJobError), queue_factory.begin() as db:
        finish(db, job_id, "w1", "succeeded", now)


def test_reaper_fails_timed_out_jobs_and_their_running_hosts(queue_factory, now):
    stale = add_job(
        queue_factory, now, type=JobType.DEPLOY, max_attempts=1, run_after=now - timedelta(days=1)
    )
    take(queue_factory, "w1", now - timedelta(seconds=400))  # timeout_at = now - 100
    fresh = add_job(queue_factory, now, priority=50)
    with queue_factory.begin() as db:
        servers = [Server(hostname=f"queue-host-{i}", inventory_source="fixture") for i in range(4)]
        db.add_all(servers)
        db.flush()
        statuses = [
            JobHostStatus.RUNNING,
            JobHostStatus.PENDING,
            JobHostStatus.SUCCEEDED,
            JobHostStatus.RUNNING,
        ]
        db.add_all(
            JobHost(job_id=stale, server_id=server.id, status=status)
            for server, status in zip(servers, statuses, strict=True)
        )
    take(queue_factory, "w2", now)  # fresh, timeout_at = now + 300

    with queue_factory.begin() as db:
        assert reap(db, now) == 1

    row = load(queue_factory, stale)
    assert row.status == JobStatus.FAILED and row.error_class == "timeout"
    assert row.error_message and "password" not in row.error_message.lower()
    assert row.finished_at == now
    assert (row.locked_by, row.locked_at, row.timeout_at) == (None, None, None)
    assert load(queue_factory, fresh).status == JobStatus.RUNNING
    with queue_factory() as db:
        hosts = list(db.scalars(select(JobHost).where(JobHost.job_id == stale).order_by(JobHost.server_id)))
    assert [host.status for host in hosts] == [
        JobHostStatus.FAILED,
        JobHostStatus.PENDING,
        JobHostStatus.SUCCEEDED,
        JobHostStatus.FAILED,
    ]
    assert [(h.error_message, h.finished_at) for h in (hosts[0], hosts[3])] == [("worker_lost", now)] * 2
    assert hosts[1].error_message is None and hosts[2].finished_at is None
    (audit,) = audits(queue_factory, "job.timeout")
    assert (audit.actor_label, audit.actor_user_id) == ("system", None)
    assert (audit.target_type, audit.target_id) == ("job", str(stale))
    assert audit.details == {"type": "deploy", "attempt": 1, "error_class": "timeout"}


def test_reaper_boundary_and_paused_jobs(queue_factory, now):
    exact = add_job(queue_factory, now, run_after=now - timedelta(days=1))
    take(queue_factory, "w", now - timedelta(seconds=300))  # timeout_at == now exactly
    paused = add_job(
        queue_factory,
        now,
        type=JobType.DEPLOY,
        max_attempts=1,
        status=JobStatus.PAUSED,
        paused_at=now - timedelta(hours=1),
        timeout_at=now - timedelta(hours=1),
    )
    with queue_factory.begin() as db:
        assert reap(db, now) == 0
        assert reap(db, now + timedelta(seconds=1)) == 1
    assert load(queue_factory, exact).status == JobStatus.FAILED
    assert load(queue_factory, paused).status == JobStatus.PAUSED
    assert audits(queue_factory, "job.timeout")[0].target_id == str(exact)


def test_reaped_timeouts_are_never_retried(queue_factory, now):
    job_id = add_job(queue_factory, now)
    take(queue_factory, "w", now)
    with queue_factory.begin() as db:
        reap(db, now + timedelta(days=1))
        assert retry_due(db, now + timedelta(days=2)) == 0
    assert load(queue_factory, job_id).status == JobStatus.FAILED


def test_transient_retry_waits_30_then_120_seconds_then_stops(queue_factory, now):
    job_id = add_job(queue_factory, now)
    run_to_failure(queue_factory, now, job_id, "transient_network")

    with queue_factory.begin() as db:
        assert retry_due(db, now + timedelta(seconds=29)) == 0
    assert load(queue_factory, job_id).status == JobStatus.FAILED
    retry_at = now + timedelta(seconds=30)
    with queue_factory.begin() as db:
        assert retry_due(db, retry_at) == 1
        assert retry_due(db, retry_at) == 0
    row = load(queue_factory, job_id)
    assert row.status == JobStatus.QUEUED and row.run_after == retry_at
    assert row.scheduled_reason == "retry" and row.finished_at is None
    assert (row.error_class, row.error_message) == ("transient_network", "x")  # kept for display
    assert (row.locked_by, row.timeout_at) == (None, None) and row.attempt == 1
    (audit,) = audits(queue_factory, "job.retry")
    assert (audit.actor_label, audit.actor_user_id) == ("system", None)
    assert audit.details == {"type": "scan", "attempt": 1, "error_class": "transient_network"}

    second_failure = retry_at + timedelta(seconds=5)
    run_to_failure(queue_factory, second_failure, job_id, "transient_network")
    assert load(queue_factory, job_id).attempt == 2
    with queue_factory.begin() as db:
        assert retry_due(db, second_failure + timedelta(seconds=119)) == 0
        assert retry_due(db, second_failure + timedelta(seconds=120)) == 1

    third_failure = second_failure + timedelta(seconds=130)
    run_to_failure(queue_factory, third_failure, job_id, "transient_network")
    assert load(queue_factory, job_id).attempt == 3
    with queue_factory.begin() as db:
        assert retry_due(db, third_failure + timedelta(days=1)) == 0
    assert take(queue_factory, "w", third_failure + timedelta(days=1)) is None
    assert load(queue_factory, job_id).status == JobStatus.FAILED
    assert len(audits(queue_factory, "job.retry")) == 2


def test_deploy_is_never_retried(queue_factory, now):
    job_id = add_job(queue_factory, now, type=JobType.DEPLOY, priority=300, max_attempts=1)
    run_to_failure(queue_factory, now, job_id, "transient_network")
    with queue_factory.begin() as db:
        assert retry_due(db, now + timedelta(days=1)) == 0
    assert load(queue_factory, job_id).status == JobStatus.FAILED


@pytest.mark.parametrize(
    "error_class", ["auth", "validation", "config_invalid", "key_unwrap", "internal", "timeout"]
)
def test_non_retryable_classes_are_never_requeued(queue_factory, now, error_class):
    job_id = add_job(queue_factory, now)
    run_to_failure(queue_factory, now, job_id, error_class)
    with queue_factory.begin() as db:
        assert retry_due(db, now + timedelta(days=1)) == 0
    assert load(queue_factory, job_id).status == JobStatus.FAILED


def test_unknown_error_class_is_not_retried(queue_factory, now):
    job_id = add_job(queue_factory, now)
    run_to_failure(queue_factory, now, job_id, "surprising")
    with queue_factory.begin() as db:
        assert retry_due(db, now + timedelta(days=1)) == 0
    assert load(queue_factory, job_id).status == JobStatus.FAILED


def test_handler_declared_non_retryable_failure_is_skipped(queue_factory, now):
    job_id = add_job(queue_factory, now)
    run_to_failure(queue_factory, now, job_id, "transient_network", result={"retryable": False})
    assert load(queue_factory, job_id).result == {"retryable": False}
    with queue_factory.begin() as db:
        assert retry_due(db, now + timedelta(days=1)) == 0


def test_handler_cannot_widen_the_policy(queue_factory, now):
    deploy = add_job(queue_factory, now, type=JobType.DEPLOY, priority=300, max_attempts=1)
    run_to_failure(queue_factory, now, deploy, "transient_network", result={"retryable": True})
    auth = add_job(queue_factory, now)
    run_to_failure(queue_factory, now, auth, "auth", result={"retryable": True})
    with queue_factory.begin() as db:
        assert retry_due(db, now + timedelta(days=1)) == 0


@pytest.mark.parametrize(
    ("job_type", "error_class", "expected"),
    [
        (JobType.ALERT_EXPIRY, "smtp_transient", 1),
        (JobType.DIGEST, "smtp_transient", 1),
        (JobType.ALERT_EXPIRY, "transient_network", 0),
        (JobType.SCAN, "smtp_transient", 0),
        (JobType.DISCOVER, "transient_network", 1),
        (JobType.CLEANUP, "operational", 1),
        (JobType.CLEANUP, "transient_network", 1),
        (JobType.CLEANUP, "smtp_transient", 0),
    ],
)
def test_retryable_classes_follow_the_per_type_policy(queue_factory, now, job_type, error_class, expected):
    max_attempts = 2 if job_type == JobType.CLEANUP else 3
    job_id = add_job(queue_factory, now, type=job_type, max_attempts=max_attempts)
    run_to_failure(queue_factory, now, job_id, error_class)
    with queue_factory.begin() as db:
        assert retry_due(db, now + timedelta(days=1)) == expected


def test_cleanup_stops_after_two_attempts(queue_factory, now):
    job_id = add_job(queue_factory, now, type=JobType.CLEANUP, priority=10, max_attempts=2)
    run_to_failure(queue_factory, now, job_id, "operational")
    with queue_factory.begin() as db:
        assert retry_due(db, now + timedelta(seconds=30)) == 1
    later = now + timedelta(minutes=5)
    run_to_failure(queue_factory, later, job_id, "operational")
    with queue_factory.begin() as db:
        assert retry_due(db, later + timedelta(days=1)) == 0
    assert take(queue_factory, "w", later + timedelta(days=1)) is None


def test_retry_due_skips_rows_locked_by_another_connection(queue_factory, now):
    job_id = add_job(queue_factory, now)
    run_to_failure(queue_factory, now, job_id, "transient_network")
    holder = queue_factory()
    try:
        holder.execute(select(Job.id).where(Job.id == job_id).with_for_update())
        with queue_factory.begin() as db:
            assert retry_due(db, now + timedelta(days=1)) == 0
    finally:
        holder.rollback()
        holder.close()
    with queue_factory.begin() as db:
        assert retry_due(db, now + timedelta(days=1)) == 1


def test_enqueue_persists_job_and_audit_atomically(queue_factory, queue_actor, now):
    with queue_factory.begin() as db:
        job = enqueue(
            db,
            JobType.SCAN,
            {"action": "default", "endpoint_ids": [1, 2]},
            queue_actor,
            priority=200,
            run_after=now,
        )
        job_id = job.id
    row = load(queue_factory, job_id)
    assert (row.type, row.status, row.priority, row.attempt, row.max_attempts) == (
        JobType.SCAN,
        JobStatus.QUEUED,
        200,
        0,
        3,
    )
    assert row.payload == {"action": "default", "endpoint_ids": [1, 2]}
    assert (row.requested_by, row.scheduled_reason, row.run_after) == (queue_actor.user_id, "manual", now)
    (audit,) = audits(queue_factory, "job.enqueue")
    assert (audit.actor_user_id, audit.actor_label) == (queue_actor.user_id, "queue-admin")
    assert (audit.target_type, audit.target_id) == ("job", str(job_id))
    assert audit.details == {"type": "scan", "action": "default", "priority": 200}


def test_enqueue_action_defaults_and_system_actor_has_no_reason(queue_factory, now):
    with queue_factory.begin() as db:
        job = enqueue(
            db, JobType.CLEANUP, {}, Actor(None, "system"), priority=10, run_after=now, max_attempts=2
        )
        job_id = job.id
    row = load(queue_factory, job_id)
    assert (row.requested_by, row.scheduled_reason, row.max_attempts) == (None, None, 2)
    assert audits(queue_factory, "job.enqueue")[0].details["action"] == "default"


def test_enqueue_scheduled_reason_extension(queue_factory, now):
    with queue_factory.begin() as db:
        job = enqueue(
            db,
            JobType.DISCOVER,
            {"action": "nightly"},
            Actor(None, "scheduler"),
            priority=100,
            run_after=now,
            scheduled_reason="nightly",
        )
        job_id = job.id
    assert load(queue_factory, job_id).scheduled_reason == "nightly"


def test_enqueue_deploy_with_single_attempt(queue_factory, queue_actor, now):
    with queue_factory.begin() as db:
        job = enqueue(db, JobType.DEPLOY, {}, queue_actor, priority=300, run_after=now, max_attempts=1)
        assert job.max_attempts == 1


def test_rolled_back_enqueue_leaves_no_job_and_no_audit(queue_factory, queue_actor, now):
    with pytest.raises(RuntimeError), queue_factory.begin() as db:
        enqueue(db, JobType.SCAN, {}, queue_actor, priority=100, run_after=now)
        raise RuntimeError("caller failed after enqueue")
    with queue_factory() as db:
        assert db.scalar(select(func.count()).select_from(Job)) == 0
    assert audits(queue_factory, "job.enqueue") == []


def test_rolled_back_finish_leaves_the_job_running_and_no_audit(queue_factory, now):
    job_id = add_job(queue_factory, now)
    take(queue_factory, "w1", now)
    with pytest.raises(RuntimeError), queue_factory.begin() as db:
        finish(db, job_id, "w1", "succeeded", now)
        raise RuntimeError("caller failed after finish")
    row = load(queue_factory, job_id)
    assert row.status == JobStatus.RUNNING and row.locked_by == "w1" and row.finished_at is None
    assert audits(queue_factory, "job.succeeded") == []


def test_rolled_back_reap_and_retry_leave_state_and_audit_untouched(queue_factory, now):
    stale = add_job(queue_factory, now)
    take(queue_factory, "w1", now)
    with pytest.raises(RuntimeError), queue_factory.begin() as db:
        reap(db, now + timedelta(days=1))
        raise RuntimeError("rollback")
    assert load(queue_factory, stale).status == JobStatus.RUNNING
    assert audits(queue_factory, "job.timeout") == []

    failed = add_job(queue_factory, now, priority=50)
    run_to_failure_at = now + timedelta(hours=1)
    with queue_factory.begin() as db:
        db.get(Job, stale).status = JobStatus.CANCELLED
    run_to_failure(queue_factory, run_to_failure_at, failed, "transient_network")
    with pytest.raises(RuntimeError), queue_factory.begin() as db:
        assert retry_due(db, run_to_failure_at + timedelta(days=1)) == 1
        raise RuntimeError("rollback")
    assert load(queue_factory, failed).status == JobStatus.FAILED
    assert audits(queue_factory, "job.retry") == []
