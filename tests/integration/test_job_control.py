"""Pause, requeue and cancel outcomes, success hooks and worker capabilities (Plan 3 Task 1)."""

import dataclasses
import json
import logging
import os
import signal
import threading
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import select

from app.jobs import worker as worker_module
from app.jobs.queue import (
    SYSTEM_ACTOR,
    InvalidJobState,
    JobCancelled,
    JobFailure,
    JobPaused,
    JobRequeued,
    StaleJobError,
    cancel_idle,
    claim,
    finish,
    reap,
    release_claim,
)
from app.jobs.worker import (
    JobRegistry,
    WorkerCapabilities,
    record_worker_start,
    run_worker,
    worker_capabilities,
)
from app.models import AuditLog, Job, WorkerHeartbeat
from app.models.enums import JobStatus, JobType
from app.services.audit import Actor, record
from tests.integration.conftest import audit_actions, enqueue_one, fetch
from tests.integration.test_worker import process_settings

SSH_KEY = b"fixture-ssh-key"
UNKNOWN_JOB = UUID(int=0)


def deploy_worker(make_worker, factory, handler, *, on_success=None):
    registry = JobRegistry()
    registry.register(JobType.DEPLOY, handler, validator=dict, on_success=on_success)
    return make_worker(factory, registry=registry, ansible_ssh_key=SSH_KEY)


def claimed(factory, now, worker_id="w1"):
    """Commit a due deploy job and claim it as ``worker_id`` (the job is then ``running``)."""
    job_id = enqueue_one(factory, JobType.DEPLOY, {"certificate_id": 1}, priority=300, max_attempts=1)
    with factory.begin() as db:
        job = claim(db, worker_id, now, lambda db, job: 900)
        assert job is not None and job.id == job_id
    return job_id


# --- pause ------------------------------------------------------------------------------------


def test_paused_deploy_holds_no_claim_and_resumes_without_consuming_its_attempt(queue_factory, make_worker, clock):
    calls = []

    def canary_then_finish(context, payload):
        calls.append(payload)
        if len(calls) == 1:
            raise JobPaused(resume_from_batch=1, result={"phase": "paused"})
        return {"phase": "done"}

    registry = JobRegistry()
    registry.register(JobType.DEPLOY, canary_then_finish, validator=dict)
    worker = make_worker(queue_factory, registry=registry, ansible_ssh_key=b"fixture-ssh-key")
    job_id = enqueue_one(queue_factory, JobType.DEPLOY, {"certificate_id": 1}, priority=300, max_attempts=1)
    worker.run_queued()
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.attempt, job.resume_from_batch, job.result) == ("paused", 0, 1, {"phase": "paused"})
    assert (job.locked_by, job.timeout_at, job.paused_at) == (None, None, clock())
    clock.advance(hours=2)
    worker.tick()
    assert worker.run_queued() == 0 and fetch(queue_factory, Job, job_id).status == "paused"  # never claimed or reaped
    with queue_factory.begin() as db:
        db.get(Job, job_id).status = JobStatus.QUEUED  # what Continue does (Task 17)
    worker.run_queued()
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.attempt, job.result) == ("succeeded", 1, {"phase": "done"})
    assert audit_actions(queue_factory, str(job_id)) == ["job.enqueue", "job.paused", "job.succeeded"]


def test_release_to_paused_clears_every_claim_field_and_audits_the_worker(queue_factory, now):
    job_id = claimed(queue_factory, now)
    with queue_factory() as db:
        before = db.get(Job, job_id)
        assert (before.attempt, before.locked_by, before.timeout_at) == (1, "w1", now + timedelta(seconds=900))
    later = now + timedelta(minutes=5)
    with queue_factory.begin() as db:
        job = release_claim(
            db, job_id, "w1", later, to="paused", resume_from_batch=2, result={"phase": "paused"}
        )
        assert job.status == JobStatus.PAUSED
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.attempt, job.resume_from_batch, job.result) == ("paused", 0, 2, {"phase": "paused"})
    assert (job.locked_by, job.locked_at, job.timeout_at, job.paused_at) == (None, None, None, later)
    assert job.started_at == now and job.finished_at is None
    with queue_factory() as db:
        row = db.scalars(select(AuditLog).where(AuditLog.action == "job.paused")).one()
    assert (row.target_id, row.actor_label) == (str(job_id), "worker:w1")
    assert row.details == {"type": "deploy", "attempt": 0, "error_class": None}


# --- requeue ----------------------------------------------------------------------------------


def test_requeued_job_waits_and_writes_no_audit(queue_factory, make_worker, clock, caplog):
    calls = []

    def lock_wait_then_finish(context, payload):
        calls.append(payload)
        if len(calls) == 1:
            raise JobRequeued(clock() + timedelta(seconds=30))
        return {"phase": "done"}

    worker = deploy_worker(make_worker, queue_factory, lock_wait_then_finish)
    job_id = enqueue_one(queue_factory, JobType.DEPLOY, {"certificate_id": 1}, priority=300, max_attempts=1)
    with caplog.at_level(logging.INFO):
        worker.run_queued()
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.attempt, job.run_after) == ("queued", 0, clock() + timedelta(seconds=30))
    assert (job.locked_by, job.locked_at, job.timeout_at, job.paused_at) == (None, None, None, None)
    assert audit_actions(queue_factory, str(job_id)) == ["job.enqueue"]  # like the claim it undoes
    assert any("requeued" in record_.getMessage() for record_ in caplog.records)
    clock.advance(seconds=29)
    assert worker.run_queued() == 0  # not claimable before run_after
    clock.advance(seconds=1)
    assert worker.run_queued() == 1
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.attempt) == ("succeeded", 1)
    assert audit_actions(queue_factory, str(job_id)) == ["job.enqueue", "job.succeeded"]


def test_release_to_queued_requires_a_timezone_aware_run_after(queue_factory, now):
    job_id = claimed(queue_factory, now)
    for bad in (None, datetime(2026, 10, 19, 12, 1)):
        with pytest.raises(ValueError, match="run_after"), queue_factory.begin() as db:
            release_claim(db, job_id, "w1", now, to="queued", run_after=bad)
    assert fetch(queue_factory, Job, job_id).status == JobStatus.RUNNING


def test_release_rejects_an_unknown_target_and_secret_like_results(queue_factory, now):
    job_id = claimed(queue_factory, now)
    with pytest.raises(ValueError, match="to"), queue_factory.begin() as db:
        release_claim(db, job_id, "w1", now, to="failed")
    with pytest.raises(ValueError, match="result"), queue_factory.begin() as db:
        release_claim(db, job_id, "w1", now, to="paused", resume_from_batch=1, result={"password": "hunter2-fixture"})
    assert fetch(queue_factory, Job, job_id).status == JobStatus.RUNNING


# --- cancel -----------------------------------------------------------------------------------


def test_cancelled_outcome_finishes_cancelled(queue_factory, make_worker, clock):
    def stop(context, payload):
        raise JobCancelled("cancelled by an operator", {"phase": "cancelled", "done": 1})

    worker = deploy_worker(make_worker, queue_factory, stop)
    job_id = enqueue_one(queue_factory, JobType.DEPLOY, {"certificate_id": 1}, priority=300, max_attempts=1)
    worker.run_queued()
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.attempt, job.result) == ("cancelled", 1, {"phase": "cancelled", "done": 1})
    assert (job.locked_by, job.timeout_at, job.finished_at) == (None, None, clock())
    assert job.error_message == "cancelled by an operator"
    assert audit_actions(queue_factory, str(job_id)) == ["job.enqueue", "job.cancelled"]


def test_cancel_idle_only_for_queued_or_paused(queue_factory, now):
    actor = Actor(None, "operator-fixture")
    later = datetime(2030, 1, 1, tzinfo=UTC)  # not claimable: the helper below must claim the other job
    queued = enqueue_one(
        queue_factory, JobType.DEPLOY, {"certificate_id": 1}, priority=300, max_attempts=1, run_after=later
    )
    paused = claimed(queue_factory, now)
    with queue_factory.begin() as db:
        release_claim(db, paused, "w1", now, to="paused", resume_from_batch=1)
    for job_id in (queued, paused):
        with queue_factory.begin() as db:
            job = cancel_idle(db, job_id, actor, now)
            assert job.status == JobStatus.CANCELLED
        row = fetch(queue_factory, Job, job_id)
        assert (row.status, row.finished_at, row.locked_by, row.timeout_at) == ("cancelled", now, None, None)
        with queue_factory() as db:
            audit = db.scalars(
                select(AuditLog).where(AuditLog.action == "job.cancelled", AuditLog.target_id == str(job_id))
            ).one()
        assert audit.actor_label == "operator-fixture"
    # running, succeeded, failed and cancelled jobs are refused and untouched
    running = claimed(queue_factory, now, "w2")
    done = claimed(queue_factory, now, "w3")
    with queue_factory.begin() as db:
        finish(db, done, "w3", "succeeded", now)
    failed = claimed(queue_factory, now, "w4")
    with queue_factory.begin() as db:
        finish(db, failed, "w4", "failed", now, error_class="internal", error_message="x")
    for job_id, status in ((running, "running"), (done, "succeeded"), (failed, "failed"), (paused, "cancelled")):
        with pytest.raises(InvalidJobState), queue_factory.begin() as db:
            cancel_idle(db, job_id, actor, now)
        assert fetch(queue_factory, Job, job_id).status == status
    with pytest.raises(InvalidJobState), queue_factory.begin() as db:
        cancel_idle(db, UNKNOWN_JOB, actor, now)





# --- fencing ----------------------------------------------------------------------------------


def test_release_is_fenced_to_the_owning_worker(queue_factory, now):
    job_id = claimed(queue_factory, now, "w1")
    with pytest.raises(StaleJobError), queue_factory.begin() as db:
        release_claim(db, job_id, "w2", now, to="paused", resume_from_batch=1)  # not the owner
    with queue_factory.begin() as db:
        reap(db, now + timedelta(hours=1))  # w1 timed out
    with pytest.raises(StaleJobError), queue_factory.begin() as db:
        release_claim(db, job_id, "w1", now, to="paused", resume_from_batch=1)  # late release from the stale owner
    with pytest.raises(StaleJobError), queue_factory.begin() as db:
        release_claim(db, UNKNOWN_JOB, "w1", now, to="queued", run_after=now)
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_class, job.attempt, job.resume_from_batch) == ("failed", "timeout", 1, 0)
    assert audit_actions(queue_factory, str(job_id)) == ["job.enqueue", "job.timeout"]


def test_a_stale_worker_control_outcome_writes_nothing(queue_factory, make_worker, clock):
    def paused_after_being_reaped(context, payload):
        clock.advance(hours=1)
        with queue_factory.begin() as db:
            assert reap(db, clock()) == 1
        raise JobPaused(resume_from_batch=1, result={"phase": "paused"})

    worker = deploy_worker(make_worker, queue_factory, paused_after_being_reaped)
    job_id = enqueue_one(queue_factory, JobType.DEPLOY, {"certificate_id": 1}, priority=300, max_attempts=1)
    worker.run_queued()
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_class, job.resume_from_batch, job.paused_at) == ("failed", "timeout", 0, None)
    assert audit_actions(queue_factory, str(job_id)) == ["job.enqueue", "job.timeout"]


# --- success hook -----------------------------------------------------------------------------


def test_success_hook_runs_in_the_finish_transaction(queue_factory, make_worker, clock):
    seen = []

    def hook(db, job, now):
        seen.append((job.status, job.attempt, now, db.in_transaction()))
        record(db, SYSTEM_ACTOR, "test.hook", "job", str(job.id), {"saw": str(job.status)})

    worker = deploy_worker(make_worker, queue_factory, lambda context, payload: {"phase": "done"}, on_success=hook)
    job_id = enqueue_one(queue_factory, JobType.DEPLOY, {"certificate_id": 1}, priority=300, max_attempts=1)
    worker.run_queued()
    assert seen == [(JobStatus.SUCCEEDED, 1, clock(), True)]  # after finish(): mark_deployed needs ``succeeded``
    assert sorted(audit_actions(queue_factory, str(job_id))) == ["job.enqueue", "job.succeeded", "test.hook"]
    with queue_factory() as db:
        hook_row = db.scalars(select(AuditLog).where(AuditLog.action == "test.hook")).one()
        done_row = db.scalars(select(AuditLog).where(AuditLog.action == "job.succeeded")).one()
    assert hook_row.created_at == done_row.created_at  # one transaction, one commit


def test_a_raising_success_hook_leaves_the_job_succeeded_without_the_hooks_writes(queue_factory, make_worker, caplog):
    def hook(db, job, now):
        record(db, SYSTEM_ACTOR, "test.hook", "job", str(job.id), {})
        db.flush()
        raise RuntimeError("hook-secret-fixture")

    worker = deploy_worker(make_worker, queue_factory, lambda context, payload: {"phase": "done"}, on_success=hook)
    job_id = enqueue_one(queue_factory, JobType.DEPLOY, {"certificate_id": 1}, priority=300, max_attempts=1)
    with caplog.at_level(logging.ERROR):
        worker.run_queued()
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.result, job.error_class) == ("succeeded", {"phase": "done"}, None)
    assert audit_actions(queue_factory, str(job_id)) == ["job.enqueue", "job.succeeded"]
    assert "RuntimeError" in caplog.text and "hook-secret-fixture" not in caplog.text  # class name only


@pytest.mark.parametrize(
    ("outcome", "status"),
    [
        (JobFailure("config_invalid", "stop"), "failed"),
        (JobPaused(resume_from_batch=1, result={}), "paused"),
        (JobCancelled("stop", {}), "cancelled"),
        (JobRequeued(datetime(2030, 1, 1, tzinfo=UTC)), "queued"),
    ],
)
def test_success_hook_never_runs_unless_the_job_succeeds(queue_factory, make_worker, outcome, status):
    ran = []

    def handler(context, payload):
        raise outcome

    worker = deploy_worker(make_worker, queue_factory, handler, on_success=lambda db, job, now: ran.append(job.id))
    job_id = enqueue_one(queue_factory, JobType.DEPLOY, {"certificate_id": 1}, priority=300, max_attempts=1)
    worker.run_queued()
    assert fetch(queue_factory, Job, job_id).status == status
    assert ran == []


# --- worker capabilities ----------------------------------------------------------------------


def test_worker_start_records_capabilities_without_values(queue_factory, make_worker, clock, tmp_path):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("[127.0.0.1]:2222 ssh-ed25519 AAAAfixture\n")
    worker = make_worker(
        queue_factory,
        ansible_ssh_key=b"ssh-key-secret-fixture",
        inventory_git_token=b"git-token-secret-fixture",
        known_hosts_file=known_hosts,
    )
    record_worker_start(queue_factory, worker.settings, worker.worker_id, clock())
    with queue_factory() as db:
        row = db.scalars(select(AuditLog).where(AuditLog.action == "worker.start")).one()
    assert (row.target_type, row.target_id, row.actor_label) == ("worker", worker.worker_id, f"worker:{worker.worker_id}")
    assert row.details == {
        "worker_id": worker.worker_id,
        "ssh_key_present": True,
        "known_hosts_present": True,
        "vault_password_present": False,
        "inventory_token_present": True,
    }
    assert "secret-fixture" not in json.dumps(row.details)


def test_worker_start_reports_a_missing_known_hosts_file(queue_factory, make_worker, clock, tmp_path):
    worker = make_worker(queue_factory, known_hosts_file=tmp_path / "absent", ansible_vault_password=b"vault-fixture")
    record_worker_start(queue_factory, worker.settings, worker.worker_id, clock())
    worker.tick()
    with queue_factory() as db:
        assert worker_capabilities(db, clock()) == WorkerCapabilities(worker.worker_id, False, False, True, False)


def test_worker_capabilities_ignore_workers_without_a_fresh_heartbeat(queue_factory, make_worker, clock, tmp_path):
    with queue_factory() as db:
        assert worker_capabilities(db, clock()) is None  # nothing recorded yet
    alive = make_worker(queue_factory, ansible_ssh_key=SSH_KEY, known_hosts_file=tmp_path / "absent")
    silent = make_worker(queue_factory, known_hosts_file=tmp_path / "absent")  # newer start row, never heartbeats
    record_worker_start(queue_factory, alive.settings, alive.worker_id, clock())
    alive.tick()
    clock.advance(seconds=1)
    record_worker_start(queue_factory, silent.settings, silent.worker_id, clock())
    with queue_factory() as db:
        assert worker_capabilities(db, clock()) == WorkerCapabilities(alive.worker_id, True, False, False, False)
    clock.advance(minutes=10)  # the heartbeat of the only recorded worker is now stale
    with queue_factory() as db:
        assert worker_capabilities(db, clock()) is None


def test_run_worker_records_capabilities_once_the_database_is_ready(queue_factory, tmp_path, monkeypatch):
    settings = dataclasses.replace(
        process_settings(queue_factory, tmp_path), ansible_ssh_key=SSH_KEY, known_hosts_file=tmp_path / "absent"
    )
    order = []
    original_ready = worker_module.assert_database_ready
    original_record = worker_module.record_worker_start

    def ready(engine, *args, **kwargs):
        order.append("ready")
        return original_ready(engine, *args, **kwargs)

    def recorded(factory, settings, worker_id, now):
        order.append("record")
        return original_record(factory, settings, worker_id, now)

    monkeypatch.setattr(worker_module, "assert_database_ready", ready)
    monkeypatch.setattr(worker_module, "record_worker_start", recorded)
    previous = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
    timer = threading.Timer(1.5, os.kill, (os.getpid(), signal.SIGTERM))
    timer.start()
    try:
        run_worker(settings, JobRegistry())
    finally:
        timer.cancel()
        signal.signal(signal.SIGTERM, previous[0])
        signal.signal(signal.SIGINT, previous[1])
    assert order == ["ready", "record"]
    with queue_factory() as db:
        start = db.scalars(select(AuditLog).where(AuditLog.action == "worker.start")).one()
        heartbeat = db.scalars(select(WorkerHeartbeat)).one()
    assert start.target_id == heartbeat.worker_id
    assert start.details["ssh_key_present"] is True and start.details["known_hosts_present"] is False
