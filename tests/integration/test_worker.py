"""Job registry dispatch, scheduler tick and cleanup handler against a real PostgreSQL."""

import logging
import os
import re
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, func, insert, select, text, update
from sqlalchemy.orm import sessionmaker

from app.config import Settings
from app.crypto.keyring import Keyring
from app.jobs import worker
from app.jobs.handlers import build_registry
from app.jobs.handlers.cleanup import cleanup, validate_cleanup_payload
from app.jobs.queue import RETRY_POLICY, JobFailure, claim, enqueue, finish, retry_due
from app.jobs.worker import (
    JobContext,
    KeyStagingError,
    run_worker,
    scheduler_tick,
    wipe_key_staging,
    worker_liveness,
)
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
    WorkerHeartbeat,
)
from app.models.enums import (
    EndpointSource,
    JobHostStatus,
    JobStatus,
    JobType,
    ScanStatus,
)
from app.services.audit import Actor
from tests.integration.conftest import disable_schedules, set_setting

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


def last_run(factory, key="cleanup"):
    with factory() as db:
        return db.scalar(select(SchedulerState.last_run_at).where(SchedulerState.key == key))


# --- registry against the queue -------------------------------------------------------------


def test_registry_capabilities_for_the_web_and_worker_processes():
    registry = build_registry()
    assert registry.supports(JobType.CLEANUP)
    assert not registry.supports(JobType.DEPLOY)
    assert registry.supports(JobType.SCAN)  # scan/default (Plan 2 Task 2)


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
    assert len(jobs_of(queue_factory, JobType.SCAN)) == 2  # the daily scan and trust recheck, each deduplicated
    with queue_factory() as db:
        assert set(db.scalars(select(SchedulerState.key))) == {"cleanup", "scan", "trust_recheck"}  # one row each


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
    worker.register_schedule("expiry_check", JobType.ALERT_EXPIRY)
    worker.register_schedule("discovery", JobType.DISCOVER)
    scheduler_tick(queue_factory, build_registry(), datetime(2026, 10, 19, 12, 0, tzinfo=UTC))
    with queue_factory() as db:
        types = set(db.scalars(select(Job.type)))
        states = set(db.scalars(select(SchedulerState.key)))
    assert types == {JobType.CLEANUP, JobType.SCAN}  # scan/default is registered; the other two are not
    assert states == {"cleanup", "scan", "trust_recheck"}


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


def test_cleanup_prunes_sessions_idle_for_eight_hours_but_keeps_just_inside_the_boundary(
    queue_factory, cleanup_context, now
):
    with queue_factory.begin() as db:
        user = User(username="idle-user", email="idle@example.test")
        db.add(user)
        db.flush()

        def session(name, last_seen):
            db.add(
                UserSession(
                    id=name * 64,
                    user_id=user.id,
                    csrf_token="c" * 64,
                    last_seen_at=last_seen,
                    expires_at=now + timedelta(hours=15),  # absolute expiry still in the future
                )
            )

        session("a", now - timedelta(hours=9))  # idle-expired for the app: must go
        session("b", now - timedelta(hours=8))  # boundary: resolve_session rejects at exactly 8 h
        session("c", now - timedelta(hours=8) + timedelta(seconds=1))  # still live
        session("d", now - timedelta(hours=1))  # live control
    assert cleanup(cleanup_context, {})["sessions"] == 2
    with queue_factory() as db:
        assert set(db.scalars(select(UserSession.id))) == {"c" * 64, "d" * 64}


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
    disable_schedules(queue_factory, "scan")  # the claim below must pick the cleanup job
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


# --- worker runtime (plan Task 13, part B) --------------------------------------------------


def wait_until(predicate, timeout=10.0, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("condition not met in time")


def payload_validator(payload):
    return dict(payload)


def queue_job(factory, job_type, now, payload=None, priority=100):
    with factory.begin() as db:
        job = enqueue(
            db,
            job_type,
            payload or {},
            Actor(None, "system"),
            priority=priority,
            run_after=now - timedelta(minutes=1),
            max_attempts=RETRY_POLICY[job_type].max_attempts,
        )
        return job.id


def job_state(factory, job_id):
    with factory() as db:
        job = db.get(Job, job_id)
        return job.status, job.error_class, job.error_message, job.result


def statuses(factory, job_ids):
    return [job_state(factory, job_id)[0] for job_id in job_ids]


def advisory_locks(factory):
    with factory() as db:
        return db.scalar(
            text(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted "
                "AND database = (SELECT oid FROM pg_database WHERE datname = current_database())"
            )
        )


class Gate:
    """A test job handler that blocks until released, recording which jobs started."""

    def __init__(self):
        self.release = threading.Event()
        self.started = []
        self._lock = threading.Lock()

    def __call__(self, context, payload):
        with self._lock:
            self.started.append(context.job_id)
        if not self.release.wait(20):
            raise RuntimeError("gate never released")
        return {"gated": True}


@pytest.fixture
def gate():
    gate = Gate()
    yield gate
    gate.release.set()


def registry_with(*pairs):
    """Cleanup plus the given default-action test handlers (never the real scan/discovery ones)."""
    registry = worker.JobRegistry()
    registry.register(JobType.CLEANUP, cleanup, validator=validate_cleanup_payload)
    for job_type, handler in pairs:
        registry.register(job_type, handler, validator=payload_validator)
    return registry


def quick_registry(*job_types):
    return registry_with(*((job_type, lambda context, payload: {"ran": True}) for job_type in job_types))


# --- liveness -------------------------------------------------------------------------------


def test_heartbeat_and_cleanup(worker_harness, client, clock):
    worker_harness.tick()
    assert client.get("/healthz").json() == {"web": "ok", "worker": "ok", "db": "ok"}
    clock.advance(minutes=5, seconds=1)
    assert client.get("/healthz").json()["worker"] == "stale"
    assert worker_harness.registry.supports(JobType.CLEANUP)
    assert not worker_harness.registry.supports(JobType.DEPLOY)


def test_worker_liveness_uses_the_newest_heartbeat_within_five_minutes(db, now):
    assert worker_liveness(db, now) == "stale"  # no rows at all
    for name, age in (("old", timedelta(hours=2)), ("edge", timedelta(minutes=5))):
        db.add(WorkerHeartbeat(worker_id=name, started_at=now - DAY, last_seen_at=now - age))
    db.flush()
    assert worker_liveness(db, now) == "ok"  # five minutes exactly still counts
    assert worker_liveness(db, now + timedelta(seconds=1)) == "stale"
    db.add(WorkerHeartbeat(worker_id="fresh", started_at=now - DAY, last_seen_at=now - timedelta(seconds=3)))
    db.flush()
    assert worker_liveness(db, now + timedelta(seconds=1)) == "ok"


def test_the_worker_id_is_hostname_pid_and_a_boot_uuid(queue_factory, make_worker):
    first, second = make_worker(queue_factory), make_worker(queue_factory)
    pattern = re.compile(rf"^[^:]+:{os.getpid()}:[0-9a-f]{{8}}-[0-9a-f]{{4}}-4[0-9a-f]{{3}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$")
    assert pattern.match(first.worker_id) and pattern.match(second.worker_id)
    assert first.worker_id != second.worker_id


def test_a_tick_upserts_a_single_heartbeat_row_and_advances_last_seen(queue_factory, make_worker, clock):
    runtime = make_worker(queue_factory)
    runtime.tick()
    clock.advance(seconds=30)
    runtime.tick()
    with queue_factory() as db:
        rows = list(db.scalars(select(WorkerHeartbeat)))
    assert [row.worker_id for row in rows] == [runtime.worker_id]
    assert rows[0].started_at == clock.value - timedelta(seconds=30)
    assert rows[0].last_seen_at == clock.value
    assert rows[0].current_job_id is None


def test_the_heartbeat_names_one_running_job_as_representative(queue_factory, make_worker, clock, gate):
    runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, gate)))
    job_id = queue_job(queue_factory, JobType.SCAN, clock())
    runtime.poll()
    wait_until(lambda: gate.started)
    runtime.tick()
    with queue_factory() as db:
        assert db.scalar(select(WorkerHeartbeat.current_job_id)) == job_id
    gate.release.set()
    runtime.wait_idle(10)
    runtime.tick()
    with queue_factory() as db:
        assert db.scalar(select(WorkerHeartbeat.current_job_id)) is None


# --- capacity and claims --------------------------------------------------------------------


def test_a_third_scan_stays_queued_while_cleanup_is_still_claimed(queue_factory, make_worker, clock, gate):
    runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, gate)))
    scans = [queue_job(queue_factory, JobType.SCAN, clock()) for _ in range(3)]
    cleanup_id = queue_job(queue_factory, JobType.CLEANUP, clock(), {"reason": "scheduled"}, priority=10)

    assert runtime.poll() == 3  # two scans and the cleanup; never the third scan
    wait_until(lambda: len(gate.started) == 2)
    wait_until(lambda: job_state(queue_factory, cleanup_id)[0] == JobStatus.SUCCEEDED)
    assert statuses(queue_factory, scans).count(JobStatus.RUNNING) == 2
    assert statuses(queue_factory, scans).count(JobStatus.QUEUED) == 1
    assert runtime.poll() == 0  # still no discovery/scan capacity

    gate.release.set()
    runtime.wait_idle(10)
    assert runtime.poll() == 1  # capacity returned: the third scan runs now
    runtime.wait_idle(10)
    assert statuses(queue_factory, scans) == [JobStatus.SUCCEEDED] * 3


def test_the_discovery_scan_cap_counts_both_types_together(queue_factory, make_worker, clock, gate):
    runtime = make_worker(
        queue_factory,
        registry=registry_with((JobType.SCAN, gate), (JobType.DISCOVER, gate)),
        ansible_ssh_key=b"fixture-not-a-key",
    )
    jobs = [
        queue_job(queue_factory, JobType.SCAN, clock()),
        queue_job(queue_factory, JobType.DISCOVER, clock()),
        queue_job(queue_factory, JobType.DISCOVER, clock()),
    ]
    assert runtime.poll() == 2
    wait_until(lambda: len(gate.started) == 2)
    states = statuses(queue_factory, jobs)
    assert states.count(JobStatus.RUNNING) == 2 and states.count(JobStatus.QUEUED) == 1


def test_at_most_worker_concurrency_jobs_run_at_once(queue_factory, make_worker, clock, gate):
    runtime = make_worker(queue_factory, registry=registry_with((JobType.ALERT_EXPIRY, gate)))
    jobs = [queue_job(queue_factory, JobType.ALERT_EXPIRY, clock()) for _ in range(5)]
    assert runtime.poll() == 4
    wait_until(lambda: len(gate.started) == 4)
    assert statuses(queue_factory, jobs).count(JobStatus.QUEUED) == 1
    assert runtime.poll() == 0
    gate.release.set()
    runtime.wait_idle(10)
    assert runtime.run_queued() == 1
    assert statuses(queue_factory, jobs) == [JobStatus.SUCCEEDED] * 5


def test_types_without_a_registered_handler_are_never_claimed(queue_factory, make_worker, clock):
    runtime = make_worker(queue_factory)  # cleanup and scan only; deploy/digest have no handler
    ignored = [queue_job(queue_factory, JobType.DEPLOY, clock()), queue_job(queue_factory, JobType.DIGEST, clock())]
    wanted = queue_job(queue_factory, JobType.CLEANUP, clock(), {"reason": "scheduled"}, priority=10)
    assert runtime.run_queued() == 1
    assert statuses(queue_factory, ignored) == [JobStatus.QUEUED] * 2
    assert job_state(queue_factory, wanted)[0] == JobStatus.SUCCEEDED


def test_without_ssh_credentials_scans_run_but_discover_and_deploy_stay_queued(
    queue_factory, make_worker, clock
):
    registry = quick_registry(JobType.SCAN, JobType.DISCOVER, JobType.DEPLOY)
    runtime = make_worker(queue_factory, registry=registry)
    assert not runtime.settings.ssh_available
    scan = queue_job(queue_factory, JobType.SCAN, clock())
    ineligible = [queue_job(queue_factory, JobType.DISCOVER, clock()), queue_job(queue_factory, JobType.DEPLOY, clock())]
    assert runtime.run_queued() == 1
    assert job_state(queue_factory, scan)[0] == JobStatus.SUCCEEDED
    assert statuses(queue_factory, ineligible) == [JobStatus.QUEUED] * 2


def test_with_ssh_credentials_discover_and_deploy_are_eligible(queue_factory, make_worker, clock):
    registry = quick_registry(JobType.SCAN, JobType.DISCOVER, JobType.DEPLOY)
    runtime = make_worker(queue_factory, registry=registry, ansible_ssh_key=b"fixture-not-a-key")
    jobs = [queue_job(queue_factory, kind, clock()) for kind in (JobType.SCAN, JobType.DISCOVER, JobType.DEPLOY)]
    assert runtime.run_queued() == 3
    assert statuses(queue_factory, jobs) == [JobStatus.SUCCEEDED] * 3


def test_a_stopped_worker_claims_nothing(queue_factory, make_worker, clock):
    runtime = make_worker(queue_factory)
    job_id = queue_job(queue_factory, JobType.CLEANUP, clock(), {"reason": "scheduled"}, priority=10)
    runtime.stop()
    assert runtime.poll() == 0
    assert job_state(queue_factory, job_id)[0] == JobStatus.QUEUED


# --- job outcomes ---------------------------------------------------------------------------


def test_a_handler_result_is_stored_with_the_job(queue_factory, make_worker, clock):
    runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, lambda c, p: {"seen": 3})))
    job_id = queue_job(queue_factory, JobType.SCAN, clock())
    runtime.run_queued()
    status, error_class, _, result = job_state(queue_factory, job_id)
    assert (status, error_class, result) == (JobStatus.SUCCEEDED, None, {"seen": 3})


def test_a_retryable_failure_is_requeued_and_a_non_retryable_one_is_not(queue_factory, make_worker, clock):
    def transient(context, payload):
        raise JobFailure("transient_network", "host unreachable", retryable=True)

    def denied(context, payload):
        raise JobFailure("auth", "credentials rejected")

    runtime = make_worker(
        queue_factory,
        registry=registry_with((JobType.SCAN, transient), (JobType.DISCOVER, denied)),
        ansible_ssh_key=b"fixture-not-a-key",
    )
    retryable = queue_job(queue_factory, JobType.SCAN, clock())
    final = queue_job(queue_factory, JobType.DISCOVER, clock())
    runtime.run_queued()
    status, error_class, message, result = job_state(queue_factory, retryable)
    assert (status, error_class, message, result) == (
        JobStatus.FAILED,
        "transient_network",
        "host unreachable",
        None,
    )
    assert job_state(queue_factory, final) == (
        JobStatus.FAILED,
        "auth",
        "credentials rejected",
        {"retryable": False},
    )
    with queue_factory.begin() as db:
        assert retry_due(db, clock() + timedelta(minutes=5)) == 1  # only the retryable one
    assert job_state(queue_factory, retryable)[0] == JobStatus.QUEUED
    assert job_state(queue_factory, final)[0] == JobStatus.FAILED


def test_an_unexpected_exception_fails_the_job_as_internal_without_leaking_its_text(
    queue_factory, make_worker, clock, caplog
):
    def explode(context, payload):
        raise RuntimeError("password=hunter2-should-never-be-stored")

    runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, explode)))
    job_id = queue_job(queue_factory, JobType.SCAN, clock())
    with caplog.at_level(logging.DEBUG):
        runtime.run_queued()
    status, error_class, message, _ = job_state(queue_factory, job_id)
    assert (status, error_class, message) == (JobStatus.FAILED, "internal", "internal error")
    assert "hunter2" not in caplog.text


def test_a_result_that_cannot_be_stored_fails_the_job_instead_of_wedging_it(queue_factory, make_worker, clock):
    runtime = make_worker(
        queue_factory, registry=registry_with((JobType.SCAN, lambda c, p: {"password": "hunter2-leaked"}))
    )
    job_id = queue_job(queue_factory, JobType.SCAN, clock())
    runtime.run_queued()
    status, error_class, _, result = job_state(queue_factory, job_id)
    assert (status, error_class, result) == (JobStatus.FAILED, "internal", {"retryable": False})


def test_an_unknown_action_fails_validation_without_retry(queue_factory, make_worker, clock):
    runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, lambda c, p: {})))
    job_id = queue_job(queue_factory, JobType.SCAN, clock(), {"action": "nope"})
    runtime.run_queued()
    status, error_class, _, result = job_state(queue_factory, job_id)
    assert (status, error_class, result) == (JobStatus.FAILED, "validation", {"retryable": False})


def test_a_reaped_jobs_late_completion_is_never_written(queue_factory, make_worker, clock, gate, caplog):
    runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, gate)))
    job_id = queue_job(queue_factory, JobType.SCAN, clock())
    runtime.poll()
    wait_until(lambda: gate.started)
    clock.advance(seconds=1801)  # past the 1800 s scan timeout
    runtime.tick()  # the scheduler holder reaps it
    assert job_state(queue_factory, job_id)[:2] == (JobStatus.FAILED, "timeout")
    with caplog.at_level(logging.INFO):
        gate.release.set()
        runtime.wait_idle(10)
    status, error_class, _, result = job_state(queue_factory, job_id)
    assert (status, error_class, result) == (JobStatus.FAILED, "timeout", None)
    with queue_factory() as db:
        succeeded = db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "job.succeeded"))
    assert succeeded == 0
    assert "stale" in caplog.text.lower()


# --- scheduler lock -------------------------------------------------------------------------


def test_only_one_worker_holds_the_scheduler_lock_and_another_takes_over(
    queue_factory, make_worker, monkeypatch
):
    ticks = []
    monkeypatch.setattr(worker, "scheduler_tick", lambda factory, registry, now: ticks.append(now))
    first, second = make_worker(queue_factory), make_worker(queue_factory)
    first.tick()
    second.tick()
    assert (first.holds_scheduler_lock, second.holds_scheduler_lock) == (True, False)
    assert len(ticks) == 1 and advisory_locks(queue_factory) == 1
    first.tick()  # re-attempts never stack or double-tick
    second.tick()
    assert len(ticks) == 2 and advisory_locks(queue_factory) == 1

    first.close(grace_seconds=0)
    wait_until(lambda: advisory_locks(queue_factory) == 0)  # connection closed -> lock released
    second.tick()
    assert second.holds_scheduler_lock and len(ticks) == 3
    assert advisory_locks(queue_factory) == 1
    with queue_factory() as db:
        assert db.scalar(select(func.count()).select_from(WorkerHeartbeat)) == 2


def test_closing_a_worker_is_idempotent_and_releases_the_lock(queue_factory, make_worker):
    runtime = make_worker(queue_factory)
    runtime.tick()
    assert advisory_locks(queue_factory) == 1
    runtime.close(grace_seconds=0)
    runtime.close(grace_seconds=0)
    wait_until(lambda: advisory_locks(queue_factory) == 0)
    assert not runtime.holds_scheduler_lock


def test_a_lost_lock_connection_is_replaced_by_a_new_acquisition(queue_factory, make_worker, monkeypatch):
    ticks = []
    monkeypatch.setattr(worker, "scheduler_tick", lambda factory, registry, now: ticks.append(now))
    runtime = make_worker(queue_factory)
    runtime.tick()
    with queue_factory.begin() as db:
        db.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": runtime.scheduler_lock_pid})
    wait_until(lambda: advisory_locks(queue_factory) == 0)
    runtime.tick()
    assert runtime.holds_scheduler_lock and len(ticks) == 2
    assert advisory_locks(queue_factory) == 1


def test_the_scheduler_enqueues_cleanup_through_the_worker_tick(queue_factory, make_worker, clock):
    runtime = make_worker(queue_factory)
    clock.value = FOUR_AM + timedelta(minutes=1)
    runtime.tick()
    assert len(jobs_of(queue_factory)) == 1


# --- run loop and shutdown ------------------------------------------------------------------


def test_the_run_loop_executes_jobs_and_stops_cleanly(queue_factory, make_worker, clock):
    runtime = make_worker(queue_factory)
    thread = threading.Thread(target=runtime.run, daemon=True)
    thread.start()
    wait_until(lambda: advisory_locks(queue_factory) == 1)
    job_id = queue_job(queue_factory, JobType.CLEANUP, clock(), {"reason": "scheduled"}, priority=10)
    wait_until(lambda: job_state(queue_factory, job_id)[0] == JobStatus.SUCCEEDED)
    runtime.stop()
    thread.join(10)
    assert not thread.is_alive()
    wait_until(lambda: advisory_locks(queue_factory) == 0)


def test_shutdown_waits_for_a_running_job_within_the_grace_period(queue_factory, make_worker, clock, gate):
    runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, gate)))
    job_id = queue_job(queue_factory, JobType.SCAN, clock())
    thread = threading.Thread(target=runtime.run, daemon=True)
    thread.start()
    wait_until(lambda: gate.started)
    runtime.stop()
    time.sleep(0.3)
    assert thread.is_alive()  # still draining the running job
    gate.release.set()
    thread.join(10)
    assert not thread.is_alive()
    assert job_state(queue_factory, job_id)[0] == JobStatus.SUCCEEDED


def test_shutdown_gives_up_after_the_grace_period_and_leaves_the_job_to_the_reaper(
    queue_factory, make_worker, clock, gate
):
    runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, gate)))
    runtime.grace_seconds = 0.3
    job_id = queue_job(queue_factory, JobType.SCAN, clock())
    thread = threading.Thread(target=runtime.run, daemon=True)
    thread.start()
    wait_until(lambda: gate.started)
    runtime.stop()
    thread.join(10)
    assert not thread.is_alive()
    wait_until(lambda: advisory_locks(queue_factory) == 0)
    assert job_state(queue_factory, job_id)[0] == JobStatus.RUNNING  # reaped after its timeout


def test_the_grace_period_is_capped_at_25_seconds(queue_factory, make_worker):
    runtime = make_worker(queue_factory)
    runtime.grace_seconds = 600
    assert runtime.effective_grace_seconds + worker.COMMIT_SETTLE_SECONDS == 25


def process_settings(queue_factory, tmp_path):
    url = queue_factory.kw["bind"].url
    return Settings(
        profile="worker",
        db_password=url.password.encode(),
        db_host=url.host,
        db_port=url.port,
        db_user=url.username,
        db_name=url.database,
        keyring=Keyring(1, {1: bytes(range(32))}),
        keyring_sha256="0" * 64,
        artifacts_root=tmp_path / "artifacts",
        key_staging_dir=tmp_path / "missing-keys",
    )


def test_run_worker_drains_running_slots_once_within_the_grace_bound(queue_factory, tmp_path, monkeypatch):
    waits = []

    def never_idle(self, timeout):
        waits.append(timeout)
        return False  # a slot is still running when the grace expires

    monkeypatch.setattr(worker.Worker, "wait_idle", never_idle)
    settings = process_settings(queue_factory, tmp_path)
    timer = threading.Timer(1.0, os.kill, (os.getpid(), signal.SIGTERM))
    timer.start()
    try:
        run_worker(settings, build_registry())
    finally:
        timer.cancel()
    assert len(waits) == 1  # run() and run_worker() must not each wait for the full grace
    assert waits[0] + worker.COMMIT_SETTLE_SECONDS <= 25  # drain plus commit settle stay in the bound


def test_an_explicit_close_grace_is_capped_at_25_seconds(queue_factory, make_worker, monkeypatch):
    waits = []
    runtime = make_worker(queue_factory)
    monkeypatch.setattr(runtime, "wait_idle", lambda timeout: waits.append(timeout) or True)
    runtime.close(grace_seconds=600)
    runtime.close(grace_seconds=600)  # repeated closes never drain again
    assert waits == [25 - worker.COMMIT_SETTLE_SECONDS]


def test_a_completion_inside_the_grace_period_is_written(queue_factory, make_worker, clock, gate):
    runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, gate)))
    job_id = queue_job(queue_factory, JobType.SCAN, clock())
    runtime.poll()
    wait_until(lambda: gate.started)
    threading.Timer(0.3, gate.release.set).start()
    runtime.close(grace_seconds=10)
    assert job_state(queue_factory, job_id)[0] == JobStatus.SUCCEEDED


def test_a_completion_after_the_grace_expired_is_fenced_out_and_the_job_stays_for_the_reaper(
    queue_factory, make_worker, clock, gate, caplog
):
    runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, gate)))
    job_id = queue_job(queue_factory, JobType.SCAN, clock())
    runtime.poll()
    wait_until(lambda: gate.started)
    runtime.close(grace_seconds=0)  # grace expires with the job still running
    with caplog.at_level(logging.INFO):
        gate.release.set()  # the handler finishes long before the 1800 s queue timeout
        assert runtime.wait_idle(10)
    status, error_class, _, result = job_state(queue_factory, job_id)
    assert (status, error_class, result) == (JobStatus.RUNNING, None, None)
    with queue_factory() as db:
        written = db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "job.succeeded"))
    assert written == 0
    assert "abandoned" in caplog.text.lower()
    clock.advance(seconds=1801)
    reaper = make_worker(queue_factory)
    reaper.tick()
    assert job_state(queue_factory, job_id)[:2] == (JobStatus.FAILED, "timeout")


@pytest.mark.parametrize("pause_after_write", [False, True], ids=["before-write", "inside-open-transaction"])
def test_an_in_flight_finish_is_fenced_when_the_grace_expires(
    queue_factory, make_worker, clock, gate, monkeypatch, pause_after_write
):
    """A completion already inside ``finish`` when shutdown abandons its slot must not commit."""
    entered, proceed = threading.Event(), threading.Event()
    real_finish = worker.finish

    def paused_finish(*args, **kwargs):
        if not pause_after_write:
            entered.set()
            assert proceed.wait(20)
        outcome = real_finish(*args, **kwargs)  # the UPDATE is now pending in the open transaction
        if pause_after_write:
            entered.set()
            assert proceed.wait(20)
        return outcome

    monkeypatch.setattr(worker, "finish", paused_finish)
    runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, gate)))
    job_id = queue_job(queue_factory, JobType.SCAN, clock())
    runtime.poll()
    wait_until(lambda: gate.started)
    gate.release.set()
    assert entered.wait(10)  # the slot is inside finish(), not yet committed
    runtime.close(grace_seconds=0)  # shutdown abandons the still-running slot
    proceed.set()
    assert runtime.wait_idle(10)
    status, error_class, _, result = job_state(queue_factory, job_id)
    assert (status, error_class, result) == (JobStatus.RUNNING, None, None)
    with queue_factory() as db:
        written = db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "job.succeeded"))
    assert written == 0
    clock.advance(seconds=1801)
    reaper = make_worker(queue_factory)
    reaper.tick()
    assert job_state(queue_factory, job_id)[:2] == (JobStatus.FAILED, "timeout")


def test_shutdown_lets_a_commit_already_underway_complete_before_returning(queue_factory, make_worker, clock, gate):
    """Past the last fence check the commit is atomic: close() waits for it instead of racing it."""
    in_commit, proceed = threading.Event(), threading.Event()
    engine = queue_factory.kw["bind"]

    @event.listens_for(engine, "commit")
    def pause_commit(connection):
        if threading.current_thread().name.startswith("job-"):
            in_commit.set()
            assert proceed.wait(20)

    try:
        runtime = make_worker(queue_factory, registry=registry_with((JobType.SCAN, gate)))
        job_id = queue_job(queue_factory, JobType.SCAN, clock())
        runtime.poll()
        wait_until(lambda: gate.started)
        gate.release.set()
        assert in_commit.wait(10)
        threading.Timer(0.3, proceed.set).start()
        runtime.close(grace_seconds=0)
        assert job_state(queue_factory, job_id)[0] == JobStatus.SUCCEEDED  # committed, not torn
    finally:
        proceed.set()
        event.remove(engine, "commit", pause_commit)


def test_run_worker_stops_on_sigterm_and_releases_everything(queue_factory, tmp_path):
    settings = process_settings(queue_factory, tmp_path)
    previous = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
    timer = threading.Timer(2.0, os.kill, (os.getpid(), signal.SIGTERM))
    timer.start()
    try:
        run_worker(settings, build_registry())
    finally:
        timer.cancel()
    assert (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)) == previous
    with queue_factory() as db:
        assert db.scalar(select(func.count()).select_from(WorkerHeartbeat)) == 1
    wait_until(lambda: advisory_locks(queue_factory) == 0)


# --- key staging wipe -----------------------------------------------------------------------


def test_wipe_removes_files_and_directories_but_keeps_the_staging_directory(tmp_path):
    staging = tmp_path / "keys"
    (staging / "nested" / "deeper").mkdir(parents=True)
    (staging / "a.pem").write_bytes(b"fixture")
    (staging / ".hidden").write_bytes(b"fixture")
    (staging / "nested" / "deeper" / "b.key").write_bytes(b"fixture")
    assert wipe_key_staging(staging) is True
    assert staging.is_dir() and list(staging.iterdir()) == []


def test_wipe_unlinks_symlinks_without_touching_their_targets(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_bytes(b"precious")
    staging = tmp_path / "keys"
    (staging / "real").mkdir(parents=True)
    (staging / "link-to-dir").symlink_to(outside, target_is_directory=True)
    (staging / "link-to-file").symlink_to(outside / "keep.txt")
    (staging / "dangling").symlink_to(tmp_path / "does-not-exist")
    (staging / "real" / "inner-link").symlink_to(outside, target_is_directory=True)
    wipe_key_staging(staging)
    assert list(staging.iterdir()) == []
    assert (outside / "keep.txt").read_bytes() == b"precious"


def test_wipe_refuses_a_symlinked_staging_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_bytes(b"precious")
    staging = tmp_path / "keys"
    staging.symlink_to(outside, target_is_directory=True)
    with pytest.raises(KeyStagingError):
        wipe_key_staging(staging)
    assert (outside / "keep.txt").read_bytes() == b"precious"
    assert staging.is_symlink()


def test_wipe_refuses_a_staging_path_that_is_not_a_directory(tmp_path):
    staging = tmp_path / "keys"
    staging.write_bytes(b"fixture")
    with pytest.raises(KeyStagingError):
        wipe_key_staging(staging)
    assert staging.read_bytes() == b"fixture"


def test_wipe_of_a_missing_directory_warns_and_continues(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        assert wipe_key_staging(tmp_path / "absent") is False
    assert "does not exist" in caplog.text


def test_wipe_fails_loudly_when_a_child_cannot_be_removed(tmp_path, monkeypatch):
    staging = tmp_path / "keys"
    staging.mkdir()
    (staging / "a.pem").write_bytes(b"fixture")

    def refuse(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(os, "unlink", refuse)
    with pytest.raises(KeyStagingError):
        wipe_key_staging(staging)


def test_run_worker_refuses_to_start_on_an_unsafe_staging_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    staging = tmp_path / "keys"
    staging.symlink_to(outside, target_is_directory=True)
    # The wipe runs before any database access: these settings point nowhere.
    settings = worker_settings(key_staging_dir=staging)
    with pytest.raises(KeyStagingError):
        run_worker(settings, build_registry())


def test_main_exits_non_zero_when_the_staging_directory_is_unsafe(tmp_path, monkeypatch, caplog):
    staging = tmp_path / "keys"
    staging.symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setattr(worker, "load_settings", lambda *args, **kwargs: worker_settings(key_staging_dir=staging))
    assert worker.main() == 1


def test_main_exits_non_zero_on_a_configuration_error(monkeypatch):
    def broken(*args, **kwargs):
        raise worker.ConfigurationError("master_key: required secret missing")

    monkeypatch.setattr(worker, "load_settings", broken)
    assert worker.main() == 2


# --- web: healthz and the stale-worker banner -----------------------------------------------

STALE_TEXT = "Worker is not running (last heartbeat > 5 minutes)"
KEY_TEXT = "key material cannot be decrypted"


def test_healthz_reports_a_stale_worker_when_no_heartbeat_exists(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"web": "ok", "worker": "stale", "db": "ok"}


def test_healthz_is_503_when_the_database_is_unavailable(client, web_app):
    dead = create_engine("postgresql+psycopg://nobody:none@127.0.0.1:1/none", connect_args={"connect_timeout": 1})
    web_app.state.factory = sessionmaker(dead)
    response = client.get("/healthz")
    assert response.status_code == 503
    assert response.json() == {"web": "ok", "worker": "unknown", "db": "unavailable"}
    assert client.get("/health/live").status_code == 200  # liveness never needs the database


def test_the_other_health_endpoints_are_unchanged(client):
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {"status": "ok"}


def test_the_banner_is_shown_when_the_worker_is_stale_and_absent_when_it_is_fresh(
    signed_in, worker_harness, clock
):
    worker_harness.tick()
    assert STALE_TEXT not in signed_in.get("/_test/page").text
    clock.advance(minutes=5, seconds=1)
    page = signed_in.get("/_test/page")
    assert page.status_code == 200 and STALE_TEXT in page.text


def test_the_stale_banner_is_shown_on_error_pages_too(signed_in):
    response = signed_in.get("/_test/error/403", headers={"Accept": "text/html"})
    assert response.status_code == 403 and STALE_TEXT in response.text


def test_the_worker_banner_combines_with_the_key_material_banner(signed_in, web_app):
    web_app.state.status_banner = "key material cannot be decrypted with the configured master key"
    # The fixture page passes its own empty status_banner; the real renderer passes the app's.
    response = signed_in.get("/_test/error/403", headers={"Accept": "text/html"})
    assert KEY_TEXT in response.text and STALE_TEXT in response.text


def test_the_worker_state_is_cached_for_thirty_seconds(signed_in, worker_harness, web_factory, clock):
    worker_harness.tick()
    assert STALE_TEXT not in signed_in.get("/_test/page").text
    with web_factory.begin() as db:
        db.execute(update(WorkerHeartbeat).values(last_seen_at=clock() - timedelta(hours=1)))
    clock.advance(seconds=29)
    assert STALE_TEXT not in signed_in.get("/_test/page").text  # served from the cache
    clock.advance(seconds=2)
    assert STALE_TEXT in signed_in.get("/_test/page").text  # cache expired


def test_pages_still_render_without_a_worker_banner_when_the_liveness_query_fails(signed_in, monkeypatch):
    from sqlalchemy.exc import OperationalError

    def broken(db, now):
        raise OperationalError("fixture-query", {}, Exception("fixture: database down"))

    monkeypatch.setattr("app.main.worker_liveness", broken)
    page = signed_in.get("/_test/page")
    assert page.status_code == 200 and STALE_TEXT not in page.text
