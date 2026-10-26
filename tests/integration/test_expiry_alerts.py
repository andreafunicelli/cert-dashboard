"""alert_expiry/default end to end (spec §10.2 scenario 11): idempotent delivery, retries, outcomes."""

import json
import logging
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.jobs.handlers import build_registry
from app.jobs.handlers.expiry import validate_expiry_payload
from app.jobs.queue import SYSTEM_ACTOR, enqueue
from app.jobs.worker import scheduler_tick
from app.models import AuditLog, Certificate, Job, NotificationLog
from app.models.enums import JobStatus, JobType
from tests.integration.conftest import closed_port, configure_smtp, disable_schedules, expiring, set_setting
from tests.integration.test_smtp_test_send import logged, quiet_capture_server

PASSWORD = "fixture-smtp-password-123"
CANARY = "PEER-TEXT-CANARY"
RETRY = {"mode": "retry_failed"}


@pytest.fixture(autouse=True)
def isolated(queue_factory):
    """Only the sweep (a tick step) and the jobs a test queues itself may run."""
    disable_schedules(queue_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup")


def run_expiry(factory, worker, now, payload=None):
    with factory.begin() as db:
        job_id = enqueue(db, JobType.ALERT_EXPIRY, payload or {}, SYSTEM_ACTOR, priority=100, run_after=now).id
    worker.run_queued()
    return job_id


def job_of(factory, job_id):
    with factory() as db:
        return db.get(Job, job_id)


def notifications(factory, certificate_id):
    with factory() as db:
        return list(
            db.scalars(
                select(NotificationLog).where(NotificationLog.certificate_id == certificate_id).order_by(NotificationLog.id)
            )
        )


def only_notification(factory, certificate_id):
    [row] = notifications(factory, certificate_id)
    return row


def expiry_jobs(factory):
    with factory() as db:
        return list(db.scalars(select(Job).where(Job.type == JobType.ALERT_EXPIRY).order_by(Job.created_at, Job.id)))


def sweep(factory, worker, clock, *delays):
    """Advance by each delay, tick, run what the tick queued; return the jobs run per tick."""
    ran = []
    for delay in delays:
        clock.advance(seconds=delay)
        worker.tick()
        ran.append(worker.run_queued())
    return ran


def everything(factory) -> str:
    """Every persisted place a leak could land: ledger rows, job rows (result/error) and audit details."""
    with factory() as db:
        rows = [
            {column.name: getattr(row, column.name) for column in row.__table__.columns}
            for model in (NotificationLog, Job, AuditLog)
            for row in db.scalars(select(model))
        ]
    return json.dumps(rows, default=str)


@pytest.mark.parametrize(
    ("payload", "valid"),
    [({}, True), (RETRY, True), ({"mode": "other"}, False), ({"mode": "retry_failed", "x": 1}, False), ({"x": 1}, False)],
)
def test_payload_is_empty_or_the_retry_mode(payload, valid):
    if valid:
        assert validate_expiry_payload(payload) == payload
    else:
        with pytest.raises(ValueError):
            validate_expiry_payload(payload)


def test_29_days_out_sends_the_30_day_alert_exactly_once(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture, recipients=["team@example.test"])
    certificate = expiring(queue_factory, days=29, owner_email="owner@example.test")
    worker = make_worker(queue_factory)
    for advance in ({}, {"hours": 1}, {"days": 1}):
        clock.advance(**advance)
        run_expiry(queue_factory, worker, clock())
    [message] = capture.messages
    assert message["To"] == "owner@example.test, team@example.test"
    assert "expires in 29 days" in message.get_body(("plain",)).get_content()
    row = only_notification(queue_factory, certificate.id)
    assert (row.status, row.threshold_days, row.attempts, row.error) == ("sent", 30, 1, None)
    assert row.sent_at == row.last_attempt_at


def test_several_crossed_thresholds_send_one_mail_at_the_smallest(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture)
    certificate = expiring(queue_factory, days=5, owner_email="owner@example.test")
    worker = make_worker(queue_factory)
    job_id = run_expiry(queue_factory, worker, clock())
    run_expiry(queue_factory, worker, clock())
    assert len(capture.messages) == 1
    row = only_notification(queue_factory, certificate.id)
    assert (row.status, row.threshold_days) == ("sent", 7)
    assert job_of(queue_factory, job_id).result == {
        "evaluated": 1, "sent": 1, "failed": 0, "no_recipients": 0, "skipped": 0,
    }  # fmt: skip


def test_expired_certificate_gets_the_zero_day_alert_once(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture)
    certificate = expiring(queue_factory, days=-3, owner_email="owner@example.test")
    worker = make_worker(queue_factory)
    for _ in range(2):
        run_expiry(queue_factory, worker, clock())
        clock.advance(days=1)
    [message] = capture.messages
    assert "has expired" in message["Subject"]
    assert only_notification(queue_factory, certificate.id).threshold_days == 0


def test_no_recipients_is_recorded_without_sending(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture)
    certificate = expiring(queue_factory, days=29)
    worker = make_worker(queue_factory)
    job_id = run_expiry(queue_factory, worker, clock())
    row = only_notification(queue_factory, certificate.id)
    assert (row.status, row.attempts, row.error, row.sent_at) == ("failed", 1, "no_recipients: no recipients", None)
    assert capture.connections == 0
    job = job_of(queue_factory, job_id)
    assert job.status == JobStatus.SUCCEEDED
    assert job.result == {"evaluated": 1, "sent": 0, "failed": 0, "no_recipients": 1, "skipped": 0}


def test_unconfigured_smtp_records_failures_and_fails_the_job_config_invalid(queue_factory, make_worker, clock):
    set_setting(queue_factory, "alert.recipients", ["team@example.test"])
    certificate = expiring(queue_factory, days=29, owner_email="owner@example.test")
    worker = make_worker(queue_factory)
    job_id = run_expiry(queue_factory, worker, clock())
    row = only_notification(queue_factory, certificate.id)
    assert (row.status, row.attempts, row.next_attempt_at) == ("failed", 1, None)
    assert row.error.startswith("smtp_not_configured: ")
    job = job_of(queue_factory, job_id)
    assert (job.status, job.error_class, job.attempt) == (JobStatus.FAILED, "config_invalid", 1)
    assert sweep(queue_factory, worker, clock, 31, 121) == [0, 0]  # a configuration error is not retried
    assert len(expiry_jobs(queue_factory)) == 1


def test_partial_failure_succeeds_the_job_and_the_sweep_retries_the_row(
    queue_factory, make_worker, smtp_server, clock
):
    capture = smtp_server()
    configure_smtp(queue_factory, capture)
    flaky = expiring(queue_factory, days=29, owner_email="tempfail@example.test")
    healthy = expiring(queue_factory, days=29, owner_email="owner@example.test")
    worker = make_worker(queue_factory)
    job_id = run_expiry(queue_factory, worker, clock())
    job = job_of(queue_factory, job_id)
    assert job.status == JobStatus.SUCCEEDED
    assert job.result == {"evaluated": 2, "sent": 1, "failed": 1, "no_recipients": 0, "skipped": 0}
    assert only_notification(queue_factory, healthy.id).status == "sent"

    assert sweep(queue_factory, worker, clock, 31, 121) == [1, 1]
    retries = expiry_jobs(queue_factory)[1:]
    assert [(j.payload, j.priority, j.max_attempts, j.scheduled_reason, j.status) for j in retries] == [
        (RETRY, 100, 1, "retry", JobStatus.SUCCEEDED)
    ] * 2
    row = only_notification(queue_factory, flaky.id)
    assert (row.status, row.attempts, row.sent_at, row.next_attempt_at) == ("failed", 3, None, None)
    assert row.error == "smtp_transient: 451 at rcpt"

    assert sweep(queue_factory, worker, clock, 600, 600) == [0, 0]  # never attempted again
    assert only_notification(queue_factory, flaky.id).attempts == 3
    assert len(capture.messages) == 1 and capture.connections == 3  # the first job and the two retries


def test_retry_sweep_uses_the_stored_row_not_a_fresh_evaluation(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture)  # no team: a refused owner must not be masked by other recipients
    flaky = expiring(queue_factory, days=29, owner_email="tempfail@example.test")
    healthy = expiring(queue_factory, days=29, owner_email="owner@example.test")
    worker = make_worker(queue_factory)
    run_expiry(queue_factory, worker, clock())
    before = only_notification(queue_factory, flaky.id)
    assert (before.status, before.threshold_days, before.attempts) == ("failed", 30, 1)
    assert before.recipients == ["tempfail@example.test"]
    assert len(capture.messages) == 1  # the healthy certificate only

    # Everything a fresh evaluation reads changes: owner, team list and thresholds (29 days now crosses 29).
    with queue_factory.begin() as db:
        db.get(Certificate, flaky.id).owner_email = "new-owner@example.test"
    set_setting(queue_factory, "alert.recipients", ["new-team@example.test"])
    set_setting(queue_factory, "alert.thresholds_days", [45, 29])

    assert sweep(queue_factory, worker, clock, 31) == [1]
    [retry] = expiry_jobs(queue_factory)[1:]
    assert (retry.payload, retry.status) == (RETRY, JobStatus.SUCCEEDED)
    assert retry.result == {"evaluated": 1, "sent": 0, "failed": 1, "no_recipients": 0, "skipped": 0}
    # The same row was attempted again with its stored recipients: the tempfail owner still fails the RCPT
    # step, whereas a freshly resolved recipient list would have been delivered.
    after = only_notification(queue_factory, flaky.id)
    assert (after.id, after.dedupe_key, after.threshold_days) == (before.id, before.dedupe_key, 30)
    assert (after.status, after.attempts, after.recipients) == ("failed", 2, before.recipients)
    assert after.error == "smtp_transient: 451 at rcpt"
    # No newly evaluated candidate was created or mailed: not for the new threshold, not for the sent certificate.
    assert [row.threshold_days for row in notifications(queue_factory, healthy.id)] == [30]
    assert len(capture.messages) == 1
    stored = everything(queue_factory)
    assert "new-owner@example.test" not in stored and "new-team@example.test" not in stored


def test_total_transient_failure_fails_the_job_for_queue_retry(queue_factory, make_worker, smtp_server, clock):
    port = closed_port()
    configure_smtp(queue_factory, SimpleNamespace(port=port))
    certificate = expiring(queue_factory, days=29, owner_email="owner@example.test")
    worker = make_worker(queue_factory)
    job_id = run_expiry(queue_factory, worker, clock())
    job = job_of(queue_factory, job_id)
    assert (job.status, job.error_class, job.attempt) == (JobStatus.FAILED, "smtp_transient", 1)
    row = only_notification(queue_factory, certificate.id)
    assert (row.status, row.attempts) == ("failed", 1) and row.error.startswith("smtp_transient: connection failed")

    capture = smtp_server(port=port)  # the relay comes back
    assert sweep(queue_factory, worker, clock, 31) == [1]
    job = job_of(queue_factory, job_id)
    assert (job.status, job.attempt) == (JobStatus.SUCCEEDED, 2)
    row = only_notification(queue_factory, certificate.id)
    assert (row.status, row.attempts, row.error) == ("sent", 2, None)
    assert len(capture.messages) == 1 and len(expiry_jobs(queue_factory)) == 1  # the queue retried, the sweep did not


def test_next_days_key_takes_over_after_three_failures(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture)
    flaky = expiring(queue_factory, days=29, owner_email="tempfail@example.test")
    expiring(queue_factory, days=29, owner_email="owner@example.test")  # keeps the first job successful
    worker = make_worker(queue_factory)
    run_expiry(queue_factory, worker, clock())
    sweep(queue_factory, worker, clock, 31, 121)
    clock.advance(days=1)
    run_expiry(queue_factory, worker, clock())
    first, second = notifications(queue_factory, flaky.id)
    assert (first.status, first.attempts) == ("failed", 3)
    assert (second.status, second.attempts) == ("failed", 1)
    assert first.dedupe_key.endswith(":2026-10-19") and second.dedupe_key.endswith(":2026-10-20")


def test_notification_errors_hold_reply_codes_not_peer_text(
    queue_factory, make_worker, smtp_server, clock, caplog, monkeypatch
):
    caplog.set_level(logging.DEBUG, logger="app")
    capture = smtp_server(replies={"RCPT": f"451 4.3.0 {CANARY} {PASSWORD}"})
    quiet_capture_server(monkeypatch)
    configure_smtp(queue_factory, capture)
    certificate = expiring(queue_factory, days=29, owner_email="owner@example.test")
    worker = make_worker(queue_factory, smtp_password=PASSWORD.encode())
    job_id = run_expiry(queue_factory, worker, clock())
    sweep(queue_factory, worker, clock, 31)
    assert only_notification(queue_factory, certificate.id).error == "smtp_transient: 451 at rcpt"
    assert job_of(queue_factory, job_id).error_class == "smtp_transient"
    stored = everything(queue_factory)
    for secret in (CANARY, PASSWORD):
        assert secret not in stored and secret not in logged(caplog)


def test_scheduled_expiry_check_runs_at_its_daily_time(queue_factory):
    set_setting(queue_factory, "expiry_check.enabled", True)
    registry = build_registry()
    scheduler_tick(queue_factory, registry, datetime(2026, 10, 19, 7, 0, 30, tzinfo=UTC))
    [job] = expiry_jobs(queue_factory)
    assert (job.priority, job.scheduled_reason, job.payload, job.max_attempts) == (100, "daily", {}, 3)
    set_setting(queue_factory, "expiry_check.enabled", False)
    scheduler_tick(queue_factory, registry, datetime(2026, 10, 20, 7, 0, 30, tzinfo=UTC))
    assert len(expiry_jobs(queue_factory)) == 1
