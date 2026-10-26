"""Settings → Alerts failures list and Status SMTP health (Plan 2 Task 11): read-only signals."""

import html
import json
from datetime import timedelta

import pytest

from app.models import AppSetting, Job, NotificationLog
from app.models.enums import JobStatus, JobType, NotificationStatus
from app.services.settings import notification_failures, smtp_health, status_snapshot
from tests.integration.conftest import expiring

TRANSIENT = "smtp_transient: 451 try again later"


@pytest.fixture
def web_factory(queue_factory):
    """A private, migrated database per test (these tests commit ledger and settings rows)."""
    return queue_factory


def seed_notifications(factory, now, statuses, *, certificate_id=None, kind="expiry", error=TRANSIENT):
    """Commit one ledger row per entry, oldest first: ``sent``, ``failed`` or ``no_recipients``."""
    ids = []
    with factory.begin() as db:
        for index, state in enumerate(statuses):
            at = now - timedelta(minutes=len(statuses) - index)
            row = NotificationLog(
                certificate_id=certificate_id,
                kind=kind,
                threshold_days=7 if certificate_id else None,
                recipients=["ops@example.test", "owner@example.test"],
                status=NotificationStatus.SENT if state == "sent" else NotificationStatus.FAILED,
                error=None
                if state == "sent"
                else error
                if state == "failed"
                else "no_recipients: no recipients",
                sent_at=at if state == "sent" else None,
                dedupe_key=f"fixture-{index}-{at.isoformat()}",
                attempts=1,
                last_attempt_at=at,
                next_attempt_at=at + timedelta(minutes=5) if state == "failed" else None,
            )
            db.add(row)
            db.flush()
            ids.append(row.id)
    return ids


def seed_smtp_test(factory, now, status, *, minutes_ago, action="smtp_test", result=None, error_class=None):
    with factory.begin() as db:
        db.add(
            Job(
                type=JobType.ALERT_EXPIRY,
                status=status,
                priority=200,
                payload={"action": action},
                run_after=now - timedelta(minutes=minutes_ago),
                created_at=now - timedelta(minutes=minutes_ago),
                finished_at=now - timedelta(minutes=minutes_ago - 1),
                result=result,
                error_class=error_class,
                error_message="smtp_transient: 451 try later" if error_class else None,
            )
        )


def health(factory):
    with factory() as db:
        return smtp_health(db)


def flat(text):
    return " ".join(html.unescape(text).split())


def test_status_shows_consecutive_failures_and_the_last_error(signed_in, web_factory, now):
    seed_notifications(web_factory, now, ["sent", "failed", "failed"])
    page = signed_in.get("/settings?tab=status").text
    assert "2 consecutive delivery failures" in page and "smtp_transient: 451" in page
    assert "Send a test email" in page


def test_alerts_tab_lists_recent_failures_with_attempts(signed_in, web_factory, now):
    seed_notifications(web_factory, now, ["failed"])
    page = signed_in.get("/settings?tab=alerts").text
    assert "attempt 1 of 3" in page and "next attempt" in page


def test_consecutive_failures_reset_at_the_newest_sent_row(web_factory, now):
    seed_notifications(web_factory, now, ["failed", "sent", "failed", "failed", "failed"])
    assert health(web_factory)["consecutive_failures"] == 3
    seed_notifications(web_factory, now + timedelta(hours=1), ["sent"])
    assert health(web_factory)["consecutive_failures"] == 0
    assert health(web_factory)["last_error"] is None


def test_equal_attempt_times_are_ordered_by_id(web_factory, now):
    with web_factory.begin() as db:
        for key, state in (("a", NotificationStatus.SENT), ("b", NotificationStatus.FAILED)):
            db.add(
                NotificationLog(
                    kind="digest",
                    recipients=["ops@example.test"],
                    status=state,
                    error=None if state == NotificationStatus.SENT else TRANSIENT,
                    dedupe_key=key,
                    attempts=1,
                    last_attempt_at=now,
                )
            )
    assert health(web_factory)["consecutive_failures"] == 1


def test_no_recipients_rows_count_as_failures_but_smtp_test_jobs_do_not(web_factory, now):
    seed_notifications(web_factory, now, ["sent", "no_recipients"])
    seed_smtp_test(web_factory, now, JobStatus.FAILED, minutes_ago=30, error_class="smtp_transient")
    state = health(web_factory)
    assert state["consecutive_failures"] == 1
    assert state["last_error"] == "no_recipients: no recipients"
    assert state["last_success_at"] == (now - timedelta(minutes=2)).isoformat()


def test_a_row_that_was_never_attempted_is_not_a_failure(web_factory, now):
    with web_factory.begin() as db:
        db.add(
            NotificationLog(kind="digest", recipients=[], status=NotificationStatus.FAILED, dedupe_key="open")
        )
    assert health(web_factory)["consecutive_failures"] == 0


def test_last_test_is_the_newest_smtp_test_job_only(web_factory, now):
    assert health(web_factory)["last_test"] is None
    seed_smtp_test(web_factory, now, JobStatus.FAILED, minutes_ago=60, error_class="smtp_transient")
    seed_smtp_test(
        web_factory, now, JobStatus.SUCCEEDED, minutes_ago=20, result={"recipient": "me@example.test"}
    )
    seed_smtp_test(web_factory, now, JobStatus.FAILED, minutes_ago=5, action="mode_other")  # not a test send
    last = health(web_factory)["last_test"]
    assert last["status"] == "succeeded" and last["recipient"] == "me@example.test"


def test_failures_list_links_the_certificate_and_escapes_the_error(signed_in, web_factory, now):
    certificate = expiring(web_factory, days=7)
    seed_notifications(
        web_factory, now, ["failed"], certificate_id=certificate.id, error="<script>alert(1)</script>"
    )
    raw = signed_in.get("/settings?tab=alerts").text
    assert "<script>alert(1)</script>" not in raw and "&lt;script&gt;alert(1)&lt;/script&gt;" in raw
    assert f'href="/certificates/{certificate.id}"' in raw
    assert "ops@example.test" in raw and "7 days" in flat(raw)


def test_failures_list_is_newest_first_bounded_and_excludes_delivered_rows(web_factory, now):
    seed_notifications(web_factory, now, ["failed", "sent", "failed", "failed"], kind="digest")
    with web_factory() as db:
        rows = notification_failures(db)
        assert [row.last_attempt_at for row in rows] == sorted(
            (row.last_attempt_at for row in rows), reverse=True
        )
        assert len(rows) == 3 and {row.kind for row in rows} == {"digest"}
        assert rows[0].recipients == ("ops@example.test", "owner@example.test") and rows[0].attempts == 1
        assert len(notification_failures(db, limit=2)) == 2


def test_digest_failures_have_no_certificate_link(signed_in, web_factory, now):
    seed_notifications(web_factory, now, ["failed"], kind="digest")
    raw = signed_in.get("/settings?tab=alerts").text
    assert "digest" in raw and "/certificates/" not in raw


def test_alerts_tab_without_failures_says_so(signed_in):
    assert "No delivery failures" in flat(signed_in.get("/settings?tab=alerts").text)


def test_status_warnings_follow_failures_and_tls_verification(signed_in, web_factory, now):
    clean = signed_in.get("/settings?tab=status").text
    assert 'data-warning="smtp_failing"' not in clean and 'data-warning="smtp_tls_unverified"' not in clean
    assert "No delivery failures" in flat(clean)
    seed_notifications(web_factory, now, ["failed"])
    with web_factory.begin() as db:
        db.add(AppSetting(key="smtp.tls_verify", value=False))
    page = signed_in.get("/settings?tab=status").text
    assert 'data-warning="smtp_failing"' in page and 'data-warning="smtp_tls_unverified"' in page
    assert "Recent alert or digest mail could not be delivered." in page
    assert "SMTP TLS certificate verification is disabled (unsafe)." in page


def test_snapshot_is_json_native_with_the_smtp_block(web_factory, keyring, now):
    seed_notifications(web_factory, now, ["sent", "failed"])
    seed_smtp_test(
        web_factory, now, JobStatus.SUCCEEDED, minutes_ago=10, result={"recipient": "me@example.test"}
    )
    with web_factory() as db:
        snapshot = status_snapshot(db, keyring, now)
    assert json.loads(json.dumps(snapshot)) == snapshot
    assert set(snapshot["smtp"]) == {"consecutive_failures", "last_error", "last_success_at", "last_test"}
    assert snapshot["smtp"]["consecutive_failures"] == 1 and "smtp_failing" in snapshot["warnings"]
