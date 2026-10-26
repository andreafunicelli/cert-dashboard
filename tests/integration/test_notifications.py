"""Notification ledger (§4.15) and the scheduler's generic tick steps, against real PostgreSQL."""

import logging
from datetime import timedelta

import pytest
from sqlalchemy import select, update

from app.jobs import worker
from app.jobs.worker import JobRegistry, scheduler_tick
from app.models import Job, NotificationLog
from app.models.enums import JobStatus, JobType
from app.services.notifications import (
    MAX_NOTIFICATION_ATTEMPTS,
    due_retries,
    enqueue_notification_retry,
    open_notification,
    record_attempt,
)
from app.services.smtp import SendOutcome

TRANSIENT = SendOutcome(False, "smtp_transient", "451 at rcpt", True)
SENT = SendOutcome(True, "sent", "250 accepted", False)
RECIPIENTS = ["a@example.test"]


def opener(db, now, key="expiry:1:30:2026-10-19", **overrides):
    values = {
        "kind": "expiry",
        "dedupe_key": key,
        "certificate_id": None,
        "threshold_days": 30,
        "recipients": RECIPIENTS,
        "now": now,
    }
    return open_notification(db, **{**values, **overrides})


def test_failed_attempts_back_off_then_stop_at_three(db, previous_certificate, now):
    def attempt(when):
        return open_notification(
            db,
            kind="expiry",
            dedupe_key=f"expiry:{previous_certificate.id}:30:2026-10-19",
            certificate_id=previous_certificate.id,
            threshold_days=30,
            recipients=["a@example.test"],
            now=when,
        )

    transient = SendOutcome(False, "smtp_transient", "451 at rcpt", True)
    row = record_attempt(db, attempt(now), transient, now)
    assert (row.status, row.attempts, row.sent_at, row.last_attempt_at) == ("failed", 1, None, now)
    assert row.next_attempt_at == now + timedelta(seconds=30)
    assert attempt(now + timedelta(seconds=29)) is None
    second = now + timedelta(seconds=30)
    row = record_attempt(db, attempt(second), transient, second)
    assert row.next_attempt_at == second + timedelta(seconds=120)
    third = second + timedelta(seconds=120)
    row = record_attempt(db, attempt(third), transient, third)
    assert (row.attempts, row.next_attempt_at, row.sent_at) == (3, None, None)
    assert attempt(third + timedelta(days=1)) is None


def test_a_new_row_starts_failed_with_no_attempts_and_empty_timestamps(db, now):
    row = opener(db, now)
    assert (row.status, row.attempts, row.kind, row.threshold_days, row.recipients) == (
        "failed",
        0,
        "expiry",
        30,
        RECIPIENTS,
    )
    assert (row.sent_at, row.next_attempt_at, row.last_attempt_at, row.error) == (None, None, None, None)


def test_success_sets_sent_at_with_last_attempt_at(db, now):
    row = record_attempt(db, opener(db, now), TRANSIENT, now)
    later = now + timedelta(seconds=30)
    row = record_attempt(db, opener(db, later), SENT, later)
    assert (row.status, row.attempts, row.sent_at, row.last_attempt_at) == ("sent", 2, later, later)
    assert (row.error, row.next_attempt_at) == (None, None)


def test_permanent_failure_is_not_rescheduled(db, now):
    rejected = SendOutcome(False, "smtp_rejected", "550 at rcpt", False)
    row = record_attempt(db, opener(db, now), rejected, now)
    assert (row.status, row.attempts, row.next_attempt_at, row.sent_at) == ("failed", 1, None, None)
    assert row.error == "smtp_rejected: 550 at rcpt"
    assert due_retries(db, "expiry", now + timedelta(hours=1)) == []


def test_sent_row_is_never_reopened(db, now):
    record_attempt(db, opener(db, now), SENT, now)
    assert opener(db, now + timedelta(days=2)) is None


def test_error_text_is_redacted_and_bounded(db, now):
    leaky = SendOutcome(False, "smtp_rejected", "password=hunter2-fixture " + "x" * 900, False)
    row = record_attempt(db, opener(db, now), leaky, now)
    assert row.error.startswith("smtp_rejected: ")
    assert len(row.error) <= 500
    assert "hunter2-fixture" not in row.error
    long = SendOutcome(False, "smtp_rejected", "word " * 180, False)
    row = record_attempt(db, opener(db, now, key="expiry:2:30:2026-10-19"), long, now)
    assert len(row.error) == 500 and row.error.startswith("smtp_rejected: word word")


def test_concurrent_open_returns_the_row_to_one_session_only(queue_factory, now):
    with queue_factory.begin() as setup:
        opener(setup, now)  # committed, attemptable
    first, second = queue_factory(), queue_factory()
    try:
        assert opener(first, now) is not None  # holds the row lock
        assert opener(second, now) is None  # SKIP LOCKED: nothing to attempt, no waiting
    finally:
        first.rollback()
        second.rollback()
        first.close()
        second.close()


def test_ledger_functions_never_commit(queue_factory, now):
    with queue_factory() as db:
        record_attempt(db, opener(db, now), TRANSIENT, now)
        due_retries(db, "expiry", now + timedelta(minutes=1))
        db.rollback()
    with queue_factory() as db:
        assert db.scalar(select(NotificationLog.id)) is None


def test_due_retries_selects_todays_failed_rows_in_id_order(db, now):
    for index in range(3):
        record_attempt(db, opener(db, now, key=f"expiry:{index}:30:2026-10-19"), TRANSIENT, now)
    record_attempt(db, opener(db, now, key="digest:2026-10-19", kind="digest"), TRANSIENT, now)
    assert due_retries(db, "expiry", now + timedelta(seconds=29)) == []
    rows = due_retries(db, "expiry", now + timedelta(seconds=30))
    assert [row.dedupe_key for row in rows] == [f"expiry:{index}:30:2026-10-19" for index in range(3)]
    assert [row.dedupe_key for row in due_retries(db, "digest", now + timedelta(seconds=30))] == [
        "digest:2026-10-19"
    ]


# --- tick steps -------------------------------------------------------------------------------


def stub_registry():
    registry = JobRegistry()
    registry.register(JobType.ALERT_EXPIRY, lambda context, payload: {}, validator=dict)
    return registry


def seed_due_row(factory, now, key, *, created_at=None):
    with factory.begin() as db:
        row = record_attempt(db, opener(db, now, key=key), TRANSIENT, now)
        if created_at is not None:
            db.execute(update(NotificationLog).where(NotificationLog.id == row.id).values(created_at=created_at))


def expiry_jobs(factory):
    with factory() as db:
        return list(db.scalars(select(Job).where(Job.type == JobType.ALERT_EXPIRY).order_by(Job.created_at)))


@pytest.fixture
def only_notification_retry(monkeypatch):
    steps = {"notification_retry": worker.TICK_STEPS["notification_retry"]}
    monkeypatch.setattr(worker, "TICK_STEPS", steps)
    monkeypatch.setattr(worker, "SCHEDULES", {})
    return steps


def test_tick_step_enqueues_one_retry_job_for_due_expiry_rows(queue_factory, now, only_notification_retry):
    seed_due_row(queue_factory, now, "expiry:1:30:2026-10-19")
    later = now + timedelta(seconds=31)
    scheduler_tick(queue_factory, stub_registry(), later)
    (job,) = expiry_jobs(queue_factory)
    assert (job.payload, job.priority, job.scheduled_reason, job.max_attempts, job.status) == (
        {"mode": "retry_failed"},
        100,
        "retry",
        1,
        JobStatus.QUEUED,
    )
    scheduler_tick(queue_factory, stub_registry(), later + timedelta(seconds=30))
    assert len(expiry_jobs(queue_factory)) == 1  # one is already queued
    with queue_factory.begin() as db:
        db.execute(update(Job).where(Job.id == job.id).values(status=JobStatus.RUNNING))
    scheduler_tick(queue_factory, stub_registry(), later + timedelta(seconds=60))
    assert len(expiry_jobs(queue_factory)) == 1  # nor while it is running


def test_a_due_row_created_yesterday_enqueues_nothing(queue_factory, now, only_notification_retry):
    seed_due_row(queue_factory, now, "expiry:1:30:2026-10-18", created_at=now - timedelta(days=1))
    scheduler_tick(queue_factory, stub_registry(), now + timedelta(seconds=31))
    assert expiry_jobs(queue_factory) == []


def test_enqueue_notification_retry_returns_the_number_of_jobs(queue_factory, now):
    seed_due_row(queue_factory, now, "expiry:1:30:2026-10-19")
    with queue_factory.begin() as db:
        assert enqueue_notification_retry(db, now) == 0  # not due yet
        assert enqueue_notification_retry(db, now + timedelta(seconds=30)) == 1
        assert enqueue_notification_retry(db, now + timedelta(seconds=30)) == 0


def test_tick_steps_are_skipped_without_their_handler(queue_factory, now, only_notification_retry):
    seed_due_row(queue_factory, now, "expiry:1:30:2026-10-19")
    scheduler_tick(queue_factory, JobRegistry(), now + timedelta(seconds=31))
    assert expiry_jobs(queue_factory) == []


def test_failing_tick_step_does_not_stop_other_steps(queue_factory, now, monkeypatch, caplog):
    calls = []

    def explode(db, when):
        raise RuntimeError("password=fixture-tick-secret")

    monkeypatch.setattr(worker, "SCHEDULES", {})
    monkeypatch.setattr(worker, "TICK_STEPS", {})
    key = (JobType.ALERT_EXPIRY, "default")
    worker.register_tick_step("exploding", explode, requires=key)
    worker.register_tick_step("counting", lambda db, when: calls.append(when) or 1, requires=key)
    with caplog.at_level(logging.ERROR, logger="app.jobs.worker"):
        scheduler_tick(queue_factory, stub_registry(), now)
    assert calls == [now]
    assert "RuntimeError" in caplog.text and "fixture-tick-secret" not in caplog.text


def test_a_tick_step_name_can_only_be_registered_once(monkeypatch):
    monkeypatch.setattr(worker, "TICK_STEPS", {})
    worker.register_tick_step("once", lambda db, when: 0, requires=(JobType.ALERT_EXPIRY, "default"))
    with pytest.raises(ValueError, match="once"):
        worker.register_tick_step("once", lambda db, when: 0, requires=(JobType.ALERT_EXPIRY, "default"))


def test_the_notification_retry_step_is_registered_but_production_has_no_stub_handler():
    from app.jobs.handlers import build_registry

    step = worker.TICK_STEPS["notification_retry"]
    assert step.requires == (JobType.ALERT_EXPIRY, "default")
    assert MAX_NOTIFICATION_ATTEMPTS == 3
    assert not build_registry().supports(JobType.ALERT_EXPIRY, "default")  # inert until Task 8
