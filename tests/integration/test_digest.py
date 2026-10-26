"""digest/default end to end (spec §7.5, §10.2): one heartbeat mail per UTC day through the ledger."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.jobs.handlers import build_registry
from app.jobs.handlers.digest import validate_digest_payload
from app.jobs.queue import SYSTEM_ACTOR, enqueue
from app.jobs.worker import scheduler_tick
from app.models import Job, NotificationLog
from app.models.enums import JobStatus, JobType
from tests.integration.conftest import (
    add_binding,
    add_endpoint,
    add_results,
    add_server,
    closed_port,
    configure_smtp,
    disable_schedules,
    reconcile,
    set_setting,
)

COUNT_KEYS = {
    "delivered", "expiring", "expired", "new_mismatches", "mismatches", "unknown_certificates",
    "stale_servers", "failed_jobs", "rolled_back_hosts", "failed_notifications",
}  # fmt: skip


@pytest.fixture(autouse=True)
def isolated(queue_factory):
    disable_schedules(queue_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup")


def run_digest(factory, worker, now):
    with factory.begin() as db:
        job_id = enqueue(db, JobType.DIGEST, {}, SYSTEM_ACTOR, priority=50, run_after=now).id
    worker.run_queued()
    return job_id


def digest_jobs(factory):
    with factory() as db:
        return list(db.scalars(select(Job).where(Job.type == JobType.DIGEST).order_by(Job.created_at, Job.id)))


def job_results(factory, job_type):
    with factory() as db:
        jobs = db.scalars(select(Job).where(Job.type == job_type).order_by(Job.created_at, Job.id))
        return [job.result for job in jobs]


def digest_rows(factory):
    with factory() as db:
        return list(db.scalars(select(NotificationLog).where(NotificationLog.kind == "digest")))


def body(message):
    return message.get_body(("plain",)).get_content()


def test_payload_is_empty_only():
    assert validate_digest_payload({}) == {}
    with pytest.raises(ValueError):
        validate_digest_payload({"x": 1})


def test_empty_digest_is_still_a_daily_heartbeat(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture, recipients=["team@example.test"])
    worker = make_worker(queue_factory)
    run_digest(queue_factory, worker, clock())
    clock.advance(hours=2)  # still the same UTC day
    run_digest(queue_factory, worker, clock())
    [message] = capture.messages
    assert message["Subject"].startswith("Cert Dashboard daily digest")
    text = message.get_body(("plain",)).get_content()
    assert "Nothing to report" in text and "Inventory revision: none recorded" in text
    assert job_results(queue_factory, JobType.DIGEST)[0] == {
        "delivered": True, "expiring": 0, "expired": 0, "new_mismatches": 0, "mismatches": 0,
        "unknown_certificates": 0, "stale_servers": 0, "failed_jobs": 0, "rolled_back_hosts": 0,
        "failed_notifications": 0,
    }  # fmt: skip
    second = job_results(queue_factory, JobType.DIGEST)[1]
    assert set(second) == COUNT_KEYS and second["delivered"] is False  # same UTC day: nothing sent


def seed_transitions(factory, since, tag):
    """One new and one repeat TLS mismatch, one new and one repeat unknown certificate."""
    before, after = since - timedelta(hours=1), since + timedelta(hours=1)
    with factory.begin() as db:
        new = add_endpoint(db, f"new-{tag}.example.internal")
        repeat = add_endpoint(db, f"repeat-{tag}.example.internal")
        add_results(db, new, [(before, "ok"), (after, "mismatch")])
        add_results(db, repeat, [(before, "mismatch"), (after, "mismatch")])
        server = add_server(db, f"web-{tag}.example.internal")
        old = since - timedelta(days=10)
        flipped = add_binding(db, server, f"flip-{tag}.example.internal", match_state="matched", fingerprint="a" * 64, at=old)
        add_binding(db, server, f"stay-{tag}.example.internal", match_state="unknown", fingerprint="b" * 64, at=old)
        reconcile(db, flipped, match_state="unknown", fingerprint="c" * 64, at=after)


def test_digest_mail_lists_the_new_and_repeat_signals(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture, recipients=["team@example.test"])
    seed_transitions(queue_factory, clock() - timedelta(hours=24), "a")
    run_digest(queue_factory, make_worker(queue_factory), clock())
    [message] = capture.messages
    text = body(message)
    assert "New TLS mismatches" in text and "new-a.example.internal" in text
    assert "Unknown certificates found by discovery" in text and "flip-a.example.internal" in text
    assert "Current mismatches: 2" in text
    assert "repeat-a.example.internal" not in text and "stay-a.example.internal" not in text
    [result] = job_results(queue_factory, JobType.DIGEST)
    assert (result["new_mismatches"], result["mismatches"], result["unknown_certificates"]) == (1, 2, 1)


def test_second_digest_uses_the_first_digests_sent_at(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture, recipients=["team@example.test"])
    worker = make_worker(queue_factory)
    seed_transitions(queue_factory, clock() - timedelta(hours=24), "a")
    run_digest(queue_factory, worker, clock())
    first_sent = clock()
    clock.advance(days=1)
    seed_transitions(queue_factory, first_sent, "b")
    run_digest(queue_factory, worker, clock())
    first, second = (body(message) for message in capture.messages)
    assert "new-a.example.internal" in first and "new-a.example.internal" not in second
    assert "new-b.example.internal" in second and "flip-b.example.internal" in second
    assert "repeat-b.example.internal" not in second


def test_transient_failure_retries_the_job_and_reuses_the_days_row(queue_factory, make_worker, smtp_server, clock):
    port = closed_port()
    configure_smtp(queue_factory, SimpleNamespace(port=port), recipients=["team@example.test"])
    worker = make_worker(queue_factory)
    job_id = run_digest(queue_factory, worker, clock())
    [job] = digest_jobs(queue_factory)
    assert (job.status, job.error_class, job.attempt) == (JobStatus.FAILED, "smtp_transient", 1)
    [row] = digest_rows(queue_factory)
    assert (row.status, row.attempts, row.dedupe_key) == ("failed", 1, "digest:2026-10-19")
    assert row.error.startswith("smtp_transient: connection failed")

    capture = smtp_server(port=port)  # the relay comes back
    clock.advance(seconds=31)
    worker.tick()
    worker.run_queued()
    with queue_factory() as db:
        job = db.get(Job, job_id)
    assert (job.status, job.attempt) == (JobStatus.SUCCEEDED, 2)
    [row] = digest_rows(queue_factory)
    assert (row.status, row.attempts, row.error) == ("sent", 2, None)
    assert len(capture.messages) == 1


def test_empty_team_list_records_no_recipients(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture)
    run_digest(queue_factory, make_worker(queue_factory), clock())
    [row] = digest_rows(queue_factory)
    assert (row.status, row.attempts, row.error) == ("failed", 1, "no_recipients: no recipients")
    assert capture.connections == 0
    [job] = digest_jobs(queue_factory)
    assert job.status == JobStatus.SUCCEEDED and job.result["delivered"] is False


def test_unconfigured_smtp_is_recorded_without_contacting_anyone(queue_factory, make_worker, clock):
    set_setting(queue_factory, "alert.recipients", ["team@example.test"])
    run_digest(queue_factory, make_worker(queue_factory), clock())
    [row] = digest_rows(queue_factory)
    assert row.error.startswith("smtp_not_configured: ") and row.attempts == 1
    [job] = digest_jobs(queue_factory)
    assert (job.status, job.error_class) == (JobStatus.FAILED, "config_invalid")


def test_disabled_digest_schedule_enqueues_nothing(queue_factory):
    scheduler_tick(queue_factory, build_registry(), datetime(2026, 10, 19, 7, 30, 30, tzinfo=UTC))
    assert digest_jobs(queue_factory) == []


def test_scheduled_digest_has_priority_50(queue_factory):
    set_setting(queue_factory, "alert.digest_enabled", True)
    scheduler_tick(queue_factory, build_registry(), datetime(2026, 10, 19, 7, 30, 30, tzinfo=UTC))
    [job] = digest_jobs(queue_factory)
    assert (job.priority, job.scheduled_reason, job.payload, job.max_attempts) == (50, "daily", {}, 3)
