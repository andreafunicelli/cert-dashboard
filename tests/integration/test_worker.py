"""Job registry dispatch, scheduler tick and cleanup handler against a real PostgreSQL."""

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select, update

from app.config import Settings
from app.crypto.keyring import Keyring
from app.jobs import worker
from app.jobs.handlers import build_registry
from app.jobs.handlers.cleanup import cleanup
from app.jobs.queue import JobFailure, claim, enqueue, finish, retry_due
from app.jobs.worker import JobContext, scheduler_tick
from app.models import (
    AppSetting,
    AuditLog,
    Endpoint,
    Job,
    JobHost,
    LoginRateLimit,
    ScanResult,
    SchedulerState,
    Server,
    User,
    UserSession,
)
from app.models.enums import (
    EndpointSource,
    JobHostStatus,
    JobStatus,
    JobType,
    ScanStatus,
)
from app.services.audit import Actor

DAY = timedelta(days=1)
FOUR_AM = datetime(2026, 10, 19, 4, 0, tzinfo=UTC)


def worker_settings(**overrides):
    values = {
        "profile": "worker",
        "db_password": b"fixture-not-used",
        "keyring": Keyring(1, {1: bytes(range(32))}),
        "keyring_sha256": "0" * 64,
    }
    return Settings(**(values | overrides))


def jobs_of(factory, job_type=JobType.CLEANUP):
    with factory() as db:
        return list(db.scalars(select(Job).where(Job.type == job_type).order_by(Job.created_at)))


def set_setting(factory, key, value):
    with factory.begin() as db:
        row = db.get(AppSetting, key)
        if row is None:
            db.add(AppSetting(key=key, value=value))
        else:
            row.value = value


def last_run(factory, key="cleanup"):
    with factory() as db:
        return db.scalar(select(SchedulerState.last_run_at).where(SchedulerState.key == key))


# --- registry against the queue -------------------------------------------------------------


def test_registry_capabilities_for_the_web_and_worker_processes():
    registry = build_registry()
    assert registry.supports(JobType.CLEANUP)
    assert not registry.supports(JobType.DEPLOY)
    assert not registry.supports(JobType.SCAN)


def test_poison_payload_fails_validation_and_is_never_retried(queue_factory, now):
    settings = worker_settings()
    with queue_factory.begin() as db:
        job = enqueue(
            db,
            JobType.CLEANUP,
            {"path": "/etc"},
            Actor(None, "system"),
            priority=10,
            run_after=now,
            max_attempts=2,
        )
        job_id = job.id
    with queue_factory.begin() as db:
        claimed = claim(db, "w1", now, worker.timeout_for)
        assert claimed.id == job_id
    context = JobContext(job_id, "w1", queue_factory, settings, clock=lambda: now)
    with queue_factory() as db, pytest.raises(JobFailure) as caught:
        build_registry().dispatch(context, db.get(Job, job_id))
    failure = caught.value
    assert failure.error_class == "validation"
    with queue_factory.begin() as db:
        finish(
            db,
            job_id,
            "w1",
            "failed",
            now,
            result=failure.result(),
            error_class=failure.error_class,
            error_message=failure.message,
        )
    with queue_factory.begin() as db:
        assert retry_due(db, now + timedelta(hours=1)) == 0
    with queue_factory() as db:
        job = db.get(Job, job_id)
        assert (job.status, job.error_class, job.attempt) == (JobStatus.FAILED, "validation", 1)


def test_timeout_is_stored_on_claim_for_each_type(queue_factory, now):
    with queue_factory.begin() as db:
        job = enqueue(
            db, JobType.CLEANUP, {}, Actor(None, "system"), priority=10, run_after=now, max_attempts=2
        )
        job_id = job.id
        claim(db, "w1", now, worker.timeout_for)
    with queue_factory() as db:
        assert db.get(Job, job_id).timeout_at == now + timedelta(seconds=600)


# --- scheduler ------------------------------------------------------------------------------


def test_scheduler_enqueues_the_daily_cleanup_once_with_system_actor(queue_factory):
    scheduler_tick(queue_factory, build_registry(), FOUR_AM)
    (job,) = jobs_of(queue_factory)
    assert (job.priority, job.payload, job.scheduled_reason) == (10, {"reason": "scheduled"}, "daily")
    assert job.requested_by is None and job.status == JobStatus.QUEUED
    assert last_run(queue_factory) == FOUR_AM
    with queue_factory() as db:
        enqueue_audit = db.scalar(select(AuditLog).where(AuditLog.action == "job.enqueue"))
        assert enqueue_audit.actor_label == "system" and enqueue_audit.actor_user_id is None


def test_two_schedulers_ticking_simultaneously_enqueue_one_cleanup(queue_factory):
    registry = build_registry()
    barrier = Barrier(6)

    def tick(_):
        barrier.wait()
        scheduler_tick(queue_factory, registry, FOUR_AM)

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(tick, range(6)))
    assert len(jobs_of(queue_factory)) == 1
    with queue_factory() as db:
        assert db.scalar(select(func.count()).select_from(SchedulerState)) == 1


def test_a_scheduler_waits_on_the_state_row_lock_and_then_sees_the_winners_run(queue_factory):
    """With the state row already present, only the row lock serializes the two schedulers."""
    registry = build_registry()
    scheduler_tick(queue_factory, registry, FOUR_AM)
    next_day = FOUR_AM + DAY
    with queue_factory() as winner:  # the "other scheduler", paused between lock and commit
        winner.execute(select(SchedulerState).where(SchedulerState.key == "cleanup").with_for_update())
        with ThreadPoolExecutor(max_workers=1) as pool:
            loser = pool.submit(scheduler_tick, queue_factory, registry, next_day)
            with pytest.raises(FuturesTimeout):
                loser.result(timeout=1.5)  # blocked on the row lock, not racing ahead
            enqueue(
                winner,
                JobType.CLEANUP,
                {"reason": "scheduled"},
                Actor(None, "system"),
                priority=10,
                run_after=next_day,
                max_attempts=2,
                scheduled_reason="daily",
            )
            winner.execute(
                update(SchedulerState).where(SchedulerState.key == "cleanup").values(last_run_at=next_day)
            )
            winner.commit()
            loser.result(timeout=30)
    assert len(jobs_of(queue_factory)) == 2  # day one + the winner's day two; the loser added none
    assert last_run(queue_factory) == next_day


def test_a_second_tick_for_the_same_occurrence_enqueues_nothing(queue_factory):
    registry = build_registry()
    scheduler_tick(queue_factory, registry, FOUR_AM)
    scheduler_tick(queue_factory, registry, FOUR_AM + timedelta(minutes=10))
    scheduler_tick(queue_factory, registry, FOUR_AM + timedelta(hours=11, minutes=59))
    assert len(jobs_of(queue_factory)) == 1


def test_tick_before_the_first_occurrence_of_a_new_day_uses_yesterdays_slot(queue_factory):
    registry = build_registry()
    scheduler_tick(queue_factory, registry, FOUR_AM)
    scheduler_tick(queue_factory, registry, FOUR_AM + DAY - timedelta(minutes=1))
    assert len(jobs_of(queue_factory)) == 1
    scheduler_tick(queue_factory, registry, FOUR_AM + DAY)
    assert len(jobs_of(queue_factory)) == 2
    assert last_run(queue_factory) == FOUR_AM + DAY


@pytest.mark.parametrize("late", [timedelta(minutes=31), timedelta(hours=11)])
def test_a_missed_run_catches_up_exactly_once(queue_factory, late):
    registry = build_registry()
    scheduler_tick(queue_factory, registry, FOUR_AM + late)
    scheduler_tick(queue_factory, registry, FOUR_AM + late + timedelta(minutes=1))
    assert len(jobs_of(queue_factory)) == 1
    assert last_run(queue_factory) == FOUR_AM


def test_a_run_missed_by_twelve_hours_is_skipped_and_logged(queue_factory, caplog):
    registry = build_registry()
    with caplog.at_level(logging.WARNING, logger="app.jobs.worker"):
        scheduler_tick(queue_factory, registry, FOUR_AM + timedelta(hours=12))
    assert jobs_of(queue_factory) == []
    record = next(r for r in caplog.records if getattr(r, "event", None) == "schedule_missed")
    assert (record.schedule, record.lateness_seconds) == ("cleanup", 12 * 3600)
    assert last_run(queue_factory) == FOUR_AM  # the skipped occurrence does not fire later
    scheduler_tick(queue_factory, registry, FOUR_AM + timedelta(hours=13))
    assert jobs_of(queue_factory) == []
    scheduler_tick(queue_factory, registry, FOUR_AM + DAY)  # next occurrence runs normally
    assert len(jobs_of(queue_factory)) == 1


def test_no_unregistered_schedule_is_enqueued(queue_factory, monkeypatch):
    monkeypatch.setattr(worker, "SCHEDULES", dict(worker.SCHEDULES))
    worker.register_schedule("scan", JobType.SCAN)
    worker.register_schedule("expiry_check", JobType.ALERT_EXPIRY)
    worker.register_schedule("discovery", JobType.DISCOVER)
    scheduler_tick(queue_factory, build_registry(), datetime(2026, 10, 19, 12, 0, tzinfo=UTC))
    with queue_factory() as db:
        types = set(db.scalars(select(Job.type)))
        states = set(db.scalars(select(SchedulerState.key)))
    assert types == {JobType.CLEANUP}
    assert states == {"cleanup"}


def test_registered_non_default_action_schedule_uses_its_settings_and_payload(queue_factory, monkeypatch):
    monkeypatch.setattr(worker, "SCHEDULES", {})
    worker.register_schedule("discovery", JobType.DISCOVER, "nightly_scan")
    registry = worker.JobRegistry()
    registry.register(JobType.DISCOVER, lambda c, p: {}, action="nightly_scan", validator=dict)
    scheduler_tick(queue_factory, registry, datetime(2026, 10, 19, 3, 5, tzinfo=UTC))
    (job,) = jobs_of(queue_factory, JobType.DISCOVER)
    assert (job.priority, job.payload, job.scheduled_reason) == (100, {"action": "nightly_scan"}, "nightly")
    assert job.max_attempts == 3


def test_digest_schedule_has_priority_50_and_follows_its_enabled_setting(queue_factory, monkeypatch):
    monkeypatch.setattr(worker, "SCHEDULES", {})
    worker.register_schedule("digest", JobType.DIGEST)
    registry = worker.JobRegistry()
    registry.register(JobType.DIGEST, lambda c, p: {}, validator=dict)
    set_setting(queue_factory, "alert.digest_enabled", False)
    scheduler_tick(queue_factory, registry, datetime(2026, 10, 19, 8, 0, tzinfo=UTC))
    assert jobs_of(queue_factory, JobType.DIGEST) == []
    set_setting(queue_factory, "alert.digest_enabled", True)
    scheduler_tick(queue_factory, registry, datetime(2026, 10, 19, 8, 0, tzinfo=UTC))
    (job,) = jobs_of(queue_factory, JobType.DIGEST)
    assert job.priority == 50


def test_disabled_missing_flag_and_changed_time_settings(queue_factory):
    registry = build_registry()
    set_setting(queue_factory, "cleanup.enabled", False)
    scheduler_tick(queue_factory, registry, FOUR_AM)
    assert jobs_of(queue_factory) == []
    with queue_factory.begin() as db:  # a missing flag means enabled
        db.delete(db.get(AppSetting, "cleanup.enabled"))
    set_setting(queue_factory, "cleanup.daily_at", "05:30")
    scheduler_tick(queue_factory, registry, FOUR_AM + timedelta(minutes=89))
    assert jobs_of(queue_factory) == []
    scheduler_tick(queue_factory, registry, FOUR_AM + timedelta(minutes=90))
    assert len(jobs_of(queue_factory)) == 1


@pytest.mark.parametrize("bad", ["4am", "25:00", "", None, 4])
def test_an_invalid_time_setting_skips_the_schedule(queue_factory, bad):
    set_setting(queue_factory, "cleanup.daily_at", bad)
    scheduler_tick(queue_factory, build_registry(), FOUR_AM)
    assert jobs_of(queue_factory) == []


def test_tick_rejects_a_naive_clock(queue_factory):
    with pytest.raises(ValueError):
        scheduler_tick(queue_factory, build_registry(), datetime(2026, 10, 19, 4, 0))


def test_tick_reaps_timed_out_jobs_and_requeues_retryable_failures(queue_factory, now):
    with queue_factory.begin() as db:
        hung = enqueue(db, JobType.SCAN, {}, Actor(None, "system"), priority=100, run_after=now)
        flaky = enqueue(db, JobType.SCAN, {}, Actor(None, "system"), priority=100, run_after=now)
        hung_id, flaky_id = hung.id, flaky.id
    with queue_factory.begin() as db:
        for _ in range(2):
            assert claim(db, "w1", now, lambda db, job: 60) is not None
    with queue_factory.begin() as db:
        finish(
            db, flaky_id, "w1", "failed", now, error_class="transient_network", error_message="down"
        )
    later = now + timedelta(minutes=10)
    scheduler_tick(queue_factory, build_registry(), later)
    with queue_factory() as db:
        hung_row, flaky_row = db.get(Job, hung_id), db.get(Job, flaky_id)
        assert (hung_row.status, hung_row.error_class) == (JobStatus.FAILED, "timeout")
        assert (flaky_row.status, flaky_row.scheduled_reason) == (JobStatus.QUEUED, "retry")


def test_a_failing_step_does_not_stop_the_other_steps(queue_factory, now, monkeypatch, caplog):
    def explode(db, when):
        raise RuntimeError("password=fixture-tick-secret")

    monkeypatch.setattr(worker, "reap", explode)
    with caplog.at_level(logging.ERROR, logger="app.jobs.worker"):
        scheduler_tick(queue_factory, build_registry(), FOUR_AM)
    assert len(jobs_of(queue_factory)) == 1
    assert "RuntimeError" in caplog.text and "fixture-tick-secret" not in caplog.text


# --- cleanup --------------------------------------------------------------------------------


@pytest.fixture
def artifacts_root(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    return root


@pytest.fixture
def cleanup_context(queue_factory, artifacts_root, now):
    settings = worker_settings(artifacts_root=artifacts_root)
    return JobContext(uuid4(), "w1", queue_factory, settings, clock=lambda: now)


def add_job(db, status, *, finished_days_ago=None, now, job_type=JobType.SCAN):
    finished = None if finished_days_ago is None else now - timedelta(days=finished_days_ago)
    job = Job(
        type=job_type,
        status=status,
        priority=100,
        payload={},
        run_after=now - timedelta(days=200),
        finished_at=finished,
    )
    db.add(job)
    db.flush()
    return job


def add_host_row(db, job, server):
    db.add(JobHost(job_id=job.id, server_id=server.id, status=JobHostStatus.SUCCEEDED))
    db.flush()


def test_cleanup_prunes_finished_jobs_past_retention_and_their_hosts(queue_factory, cleanup_context, now):
    with queue_factory.begin() as db:
        server = Server(hostname="cleanup-host", inventory_source="fixture")
        db.add(server)
        db.flush()
        old = [
            add_job(db, status, finished_days_ago=91, now=now)
            for status in (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED)
        ]
        for job in old:
            add_host_row(db, job, server)
        recent = add_job(db, JobStatus.SUCCEEDED, finished_days_ago=89, now=now)
        add_host_row(db, recent, server)
        boundary = add_job(db, JobStatus.FAILED, finished_days_ago=90, now=now)
        queued = add_job(db, JobStatus.QUEUED, now=now)
        running = add_job(db, JobStatus.RUNNING, now=now)
        paused = add_job(db, JobStatus.PAUSED, now=now)
        add_host_row(db, paused, server)
        keep = {recent.id, boundary.id, queued.id, running.id, paused.id}
        gone = {job.id for job in old}
        audits_before = db.scalar(select(func.count()).select_from(AuditLog))
        db.add(AuditLog(actor_label="system", action="job.enqueue", target_type="job", target_id=str(old[0].id)))
    result = cleanup(cleanup_context, {"reason": "scheduled"})
    assert result["jobs"] == 3 and result["job_hosts"] == 3
    with queue_factory() as db:
        remaining = set(db.scalars(select(Job.id)))
        assert remaining == keep and not gone & remaining
        assert db.scalar(select(func.count()).select_from(JobHost)) == 2  # recent + paused
        assert db.scalar(select(func.count()).select_from(AuditLog)) == audits_before + 1


def test_cleanup_honours_the_retention_days_setting(queue_factory, cleanup_context, now):
    set_setting(queue_factory, "retention.days", 30)
    with queue_factory.begin() as db:
        old = add_job(db, JobStatus.SUCCEEDED, finished_days_ago=31, now=now).id
        recent = add_job(db, JobStatus.SUCCEEDED, finished_days_ago=29, now=now).id
    assert cleanup(cleanup_context, {})["jobs"] == 1
    with queue_factory() as db:
        assert db.get(Job, old) is None and db.get(Job, recent) is not None


@pytest.mark.parametrize("bad", [0, -5, "ninety", None, True, 2.5])
def test_cleanup_falls_back_to_90_days_for_an_unusable_retention_setting(
    queue_factory, cleanup_context, now, bad
):
    set_setting(queue_factory, "retention.days", bad)
    with queue_factory.begin() as db:
        old = add_job(db, JobStatus.SUCCEEDED, finished_days_ago=91, now=now).id
        recent = add_job(db, JobStatus.SUCCEEDED, finished_days_ago=89, now=now).id
    cleanup(cleanup_context, {})
    with queue_factory() as db:
        assert db.get(Job, old) is None and db.get(Job, recent) is not None


def test_cleanup_prunes_scan_results_older_than_90_days(queue_factory, cleanup_context, now):
    with queue_factory.begin() as db:
        endpoint = Endpoint(host="cleanup.example.test", source=EndpointSource.MANUAL)
        db.add(endpoint)
        db.flush()
        for days in (91, 89):
            db.add(
                ScanResult(
                    endpoint_id=endpoint.id,
                    status=ScanStatus.OK,
                    source="scheduled",
                    checked_at=now - timedelta(days=days),
                )
            )
    assert cleanup(cleanup_context, {})["scan_results"] == 1
    with queue_factory() as db:
        (kept,) = db.scalars(select(ScanResult.checked_at))
        assert kept == now - timedelta(days=89)


def test_cleanup_removes_expired_and_revoked_sessions_only(queue_factory, cleanup_context, now):
    with queue_factory.begin() as db:
        user = User(username="cleanup-user", email="cleanup@example.test")
        db.add(user)
        db.flush()

        def session(name, expires, revoked=None):
            db.add(
                UserSession(
                    id=name * 64,
                    user_id=user.id,
                    csrf_token="c" * 64,
                    last_seen_at=now,
                    expires_at=expires,
                    revoked_at=revoked,
                )
            )

        session("a", now - timedelta(seconds=1))  # expired
        session("b", now + timedelta(hours=8), revoked=now - timedelta(hours=1))  # revoked
        session("c", now + timedelta(hours=8))  # live
    assert cleanup(cleanup_context, {})["sessions"] == 2
    with queue_factory() as db:
        assert set(db.scalars(select(UserSession.id))) == {"c" * 64}


def test_cleanup_prunes_stale_login_counters_but_keeps_active_buckets(queue_factory, cleanup_context, now):
    stale = now - timedelta(days=1, minutes=1)
    keep = {
        ("203.0.113.9", now.replace(second=0)),  # current IPv4 minute bucket
        ("2001:db8::9", now - timedelta(minutes=1)),  # current IPv6 bucket
        ("203.0.113.10", now - timedelta(hours=23)),  # recent
        ("2001:db8::10", now - timedelta(days=1)),  # exactly one day old: not older than 1 day
    }
    with queue_factory.begin() as db:
        rows = keep | {("203.0.113.1", stale), ("2001:db8::1", stale - timedelta(days=30))}
        db.execute(
            insert(LoginRateLimit),
            [{"ip": ip, "window_start": window, "attempts": 4} for ip, window in rows],
        )
    assert cleanup(cleanup_context, {})["login_counters"] == 2
    with queue_factory() as db:
        rows = {(str(ip), window) for ip, window in db.execute(select(LoginRateLimit.ip, LoginRateLimit.window_start))}
        assert rows == keep
        assert set(db.scalars(select(LoginRateLimit.attempts))) == {4}


def age(path, days, now):
    stamp = (now - timedelta(days=days)).timestamp()
    os.utime(path, (stamp, stamp), follow_symlinks=False)


def test_cleanup_removes_old_artifacts_and_leaves_symlinks_and_outside_files(
    queue_factory, cleanup_context, artifacts_root, tmp_path, now
):
    old = artifacts_root / "job-old" / "stdout.log"
    old.parent.mkdir()
    old.write_text("old")
    age(old, 31, now)
    age(old.parent, 31, now)
    fresh = artifacts_root / "job-new" / "stdout.log"
    fresh.parent.mkdir()
    fresh.write_text("new")
    age(fresh, 1, now)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim"
    victim.write_text("keep")
    age(victim, 400, now)
    age(outside, 400, now)
    (artifacts_root / "escape").symlink_to(outside, target_is_directory=True)
    (artifacts_root / "file-link").symlink_to(victim)
    age(artifacts_root / "escape", 400, now)
    result = cleanup(cleanup_context, {})
    assert result["artifacts"] == 2  # stdout.log + job-old/
    assert not old.parent.exists() and fresh.exists()
    assert victim.exists() and outside.is_dir()
    assert (artifacts_root / "escape").is_symlink() and (artifacts_root / "file-link").is_symlink()
    assert artifacts_root.is_dir()


def test_cleanup_with_a_missing_artifacts_root_still_prunes_the_database(
    queue_factory, cleanup_context, artifacts_root, now
):
    artifacts_root.rmdir()
    with queue_factory.begin() as db:
        add_job(db, JobStatus.SUCCEEDED, finished_days_ago=100, now=now)
    result = cleanup(cleanup_context, {})
    assert result["jobs"] == 1 and result["artifacts"] == 0


def test_cleanup_result_is_json_ints_for_every_category(cleanup_context):
    result = cleanup(cleanup_context, {"reason": "manual_prune"})
    assert result == {
        "jobs": 0,
        "job_hosts": 0,
        "scan_results": 0,
        "sessions": 0,
        "login_counters": 0,
        "artifacts": 0,
    }
    assert all(type(value) is int for value in result.values())


def test_cleanup_is_idempotent(queue_factory, cleanup_context, now):
    with queue_factory.begin() as db:
        add_job(db, JobStatus.SUCCEEDED, finished_days_ago=100, now=now)
    assert cleanup(cleanup_context, {})["jobs"] == 1
    assert cleanup(cleanup_context, {})["jobs"] == 0


def test_cleanup_runs_end_to_end_through_dispatch_and_the_claimed_job_row(
    queue_factory, cleanup_context, now
):
    with queue_factory.begin() as db:
        add_job(db, JobStatus.SUCCEEDED, finished_days_ago=100, now=now)
    scheduler_tick(queue_factory, build_registry(), FOUR_AM)
    with queue_factory.begin() as db:
        job = claim(db, "w1", now, worker.timeout_for)
        job_id = job.id
    context = JobContext(
        job_id, "w1", queue_factory, cleanup_context.settings, clock=lambda: FOUR_AM + timedelta(hours=1)
    )
    with queue_factory() as db:
        result = build_registry().dispatch(context, db.get(Job, job_id))
    assert result["jobs"] == 1
    with queue_factory.begin() as db:
        finish(db, job_id, "w1", "succeeded", now, result=result)
    with queue_factory() as db:
        assert db.get(Job, job_id).result["jobs"] == 1
        # The finished cleanup job and its audit trail survive; the job row is in retention.
        assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "job.succeeded")) == 1


def test_cleanup_never_updates_unrelated_job_columns(queue_factory, cleanup_context, now):
    with queue_factory.begin() as db:
        queued = add_job(db, JobStatus.QUEUED, now=now)
        db.execute(update(Job).where(Job.id == queued.id).values(finished_at=now - timedelta(days=500)))
        queued_id = queued.id
    cleanup(cleanup_context, {})
    with queue_factory() as db:
        assert db.get(Job, queued_id).status == JobStatus.QUEUED
