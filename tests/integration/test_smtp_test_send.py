"""Settings → SMTP "Send test email": a worker job whose outcome is fixed step names and reply codes."""

import json
import logging

import pytest
from sqlalchemy import select, update

from app.jobs.handlers import build_registry
from app.jobs.handlers.smtp_test import SMTP_TEST_ACTION, validate_smtp_test_payload
from app.models import AuditLog, Job, NotificationLog, User
from app.models.enums import JobStatus, JobType
from tests.integration.conftest import configure_smtp, disable_schedules, set_setting

PATH = "/settings/smtp/test"
PASSWORD = "fixture-smtp-password-123"
CANARY = "PEER-TEXT-CANARY"
ECHO = {"AUTH": f"535 5.7.8 {CANARY} incorrect credential {{password}}"}


@pytest.fixture(autouse=True)
def isolated(web_factory):
    """The web database is shared by the module: no jobs, and no schedule can enqueue one."""
    disable_schedules(web_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup")
    with web_factory.begin() as db:
        db.query(Job).delete()


def post(signed_in):
    return signed_in.post(PATH, data={"csrf_token": signed_in.fixture_csrf}, follow_redirects=False)


def smtp_test_jobs(factory):
    with factory() as db:
        return list(db.scalars(select(Job).where(Job.payload["action"].as_string() == "smtp_test")))


def logged(caplog) -> str:
    """Every captured log record, unfiltered."""
    return "\n".join(f"{record.name} {record.getMessage()} {record.exc_text or ''}" for record in caplog.records)


def quiet_capture_server(monkeypatch) -> None:
    """Drop the fixture relay's own DEBUG echo of its server replies (``mail.log``); application loggers stay as they are."""
    monkeypatch.setattr(logging.getLogger("mail.log"), "level", logging.INFO)


def everything(factory) -> str:
    """Every persisted place a leak could land: job payload/result/error and any audit details."""
    with factory() as db:
        jobs = [(j.payload, j.result, j.error_class, j.error_message) for j in db.scalars(select(Job))]
        audits = [(a.action, a.details) for a in db.scalars(select(AuditLog))]
    return json.dumps([jobs, audits], default=str)


def test_test_email_is_sent_by_the_worker_to_the_signed_in_user(
    signed_in, worker_harness, web_factory, web_user, smtp_server
):
    capture = smtp_server()
    configure_smtp(web_factory, capture)
    response = post(signed_in)
    assert response.status_code == 303 and capture.connections == 0
    worker_harness.run_queued()
    [message] = capture.messages
    assert message["To"] == web_user.email and message["Subject"] == "Cert Dashboard test email"
    page = signed_in.get(response.headers["location"]).text
    assert "Delivered" in page and "250" in page
    [job] = smtp_test_jobs(web_factory)
    assert (job.status, job.priority, job.max_attempts, job.payload) == (JobStatus.SUCCEEDED, 200, 1, {"action": "smtp_test"})
    assert job.requested_by == web_user.id and job.type == JobType.ALERT_EXPIRY
    assert job.result["delivered"] is True and job.result["recipient"] == web_user.email
    with web_factory() as db:
        assert db.scalar(select(NotificationLog.id).limit(1)) is None  # a test send is not a notification


def test_recipient_is_the_requesters_e_mail_read_when_the_worker_runs(
    signed_in, worker_harness, web_factory, web_user, smtp_server
):
    capture = smtp_server()
    configure_smtp(web_factory, capture)
    post(signed_in)
    [queued] = smtp_test_jobs(web_factory)
    assert queued.payload == {"action": "smtp_test"} and queued.requested_by == web_user.id
    with web_factory.begin() as db:
        db.execute(update(User).where(User.id == web_user.id).values(email="changed-after-queue@example.test"))
    worker_harness.run_queued()
    [message] = capture.messages
    assert message["To"] == "changed-after-queue@example.test"
    [job] = smtp_test_jobs(web_factory)
    assert job.payload == {"action": "smtp_test"} and job.result["recipient"] == "changed-after-queue@example.test"


def test_failed_test_email_reports_the_real_reply_and_is_never_retried(
    signed_in, worker_harness, web_factory, web_user, smtp_server, clock
):
    capture = smtp_server()
    configure_smtp(web_factory, capture)
    with web_factory.begin() as db:
        db.execute(update(User).where(User.id == web_user.id).values(email="tempfail@example.test"))
    response = post(signed_in)
    worker_harness.run_queued()
    [job] = smtp_test_jobs(web_factory)
    assert (job.status, job.error_class, job.max_attempts) == (JobStatus.FAILED, "smtp_transient", 1)
    assert job.error_message.startswith("451 at rcpt; connect 220, ehlo 250, mail 250, rcpt 451")
    clock.advance(seconds=600)
    worker_harness.tick()
    assert worker_harness.run_queued() == 0 and capture.connections == 1
    assert smtp_test_jobs(web_factory)[0].status == JobStatus.FAILED
    page = signed_in.get(response.headers["location"]).text
    assert "Failed" in page and "451 at rcpt" in page


def test_relay_echoing_the_password_never_leaks_through_the_test_send(
    signed_in, make_worker, web_factory, smtp_server, tls_material, caplog, monkeypatch
):
    caplog.set_level(logging.DEBUG, logger="app")
    capture = smtp_server(tls=tls_material, password="another-password", replies=ECHO)
    quiet_capture_server(monkeypatch)
    configure_smtp(web_factory, capture, security="starttls", username="mailer", tls_verify=False)
    worker = make_worker(web_factory, smtp_password=PASSWORD.encode())
    response = post(signed_in)
    worker.run_queued()
    [job] = smtp_test_jobs(web_factory)
    assert (job.status, job.error_class) == (JobStatus.FAILED, "auth")
    assert job.error_message.startswith("535 at auth; connect 220") and job.error_message.endswith("auth 535")
    pages = [
        signed_in.get(response.headers["location"]).text,
        signed_in.get("/settings?tab=status").text,
        signed_in.get(f"/settings/smtp/test/{job.id}").text,
    ]
    assert "535 at auth" in pages[0] and "535 at auth" in pages[2]
    assert any(record.name.startswith("app") for record in caplog.records)  # application logging was not suppressed
    for haystack in (everything(web_factory), logged(caplog), *pages):
        assert PASSWORD not in haystack and CANARY not in haystack


def test_smtp_password_never_reaches_payload_result_audit_logs_or_page(
    signed_in, make_worker, web_factory, smtp_server, tls_material, caplog, monkeypatch
):
    caplog.set_level(logging.DEBUG, logger="app")
    capture = smtp_server(tls=tls_material, password=PASSWORD)
    quiet_capture_server(monkeypatch)
    configure_smtp(web_factory, capture, security="starttls", username="mailer", tls_verify=False)
    worker = make_worker(web_factory, smtp_password=PASSWORD.encode())
    response = post(signed_in)
    worker.run_queued()
    [job] = smtp_test_jobs(web_factory)
    assert job.status == JobStatus.SUCCEEDED and len(capture.messages) == 1
    assert [step["step"] for step in job.result["steps"]][:5] == ["connect", "ehlo", "starttls", "ehlo", "auth"]
    assert all(set(step) == {"step", "code"} for step in job.result["steps"])
    assert {"step": "auth", "code": 235} in job.result["steps"]
    pages = [signed_in.get(response.headers["location"]).text, signed_in.get("/settings?tab=status").text]
    for haystack in (everything(web_factory), logged(caplog), *pages):
        assert PASSWORD not in haystack and CANARY not in haystack


def test_unsafe_tls_warning_is_visible_when_verification_is_off(signed_in, web_factory, smtp_server):
    configure_smtp(web_factory, smtp_server(), tls_verify=True)
    assert "unsafe: TLS certificate verification disabled" not in signed_in.get("/settings?tab=smtp").text
    set_setting(web_factory, "smtp.tls_verify", False)
    page = signed_in.get("/settings?tab=smtp").text
    assert "unsafe: TLS certificate verification disabled" in page


def test_test_send_requires_csrf_and_sign_in(client, signed_in, web_factory):
    assert signed_in.post(PATH, follow_redirects=False).status_code == 403
    assert smtp_test_jobs(web_factory) == []
    signed_in.cookies.clear()
    assert signed_in.post(PATH, data={"csrf_token": "x"}, follow_redirects=False).status_code in (303, 403)
    assert smtp_test_jobs(web_factory) == []
    assert client.get("/settings/smtp/test/00000000-0000-0000-0000-000000000000", follow_redirects=False).status_code == 303


def test_unconfigured_smtp_fails_with_config_invalid_and_says_why(signed_in, worker_harness, web_factory):
    set_setting(web_factory, "smtp.host", "")
    response = post(signed_in)
    worker_harness.run_queued()
    [job] = smtp_test_jobs(web_factory)
    assert (job.status, job.error_class) == (JobStatus.FAILED, "config_invalid")
    assert job.error_message == "smtp.host, smtp.from or smtp.security is not set"
    assert "smtp.host, smtp.from or smtp.security is not set" in signed_in.get(response.headers["location"]).text


def test_a_job_without_a_requester_is_a_validation_failure(worker_harness, web_factory, smtp_server, clock):
    from app.jobs.queue import SYSTEM_ACTOR, enqueue

    configure_smtp(web_factory, smtp_server())
    with web_factory.begin() as db:
        enqueue(db, JobType.ALERT_EXPIRY, {"action": "smtp_test"}, SYSTEM_ACTOR, priority=200, run_after=clock(), max_attempts=1)
    worker_harness.run_queued()
    [job] = smtp_test_jobs(web_factory)
    assert (job.status, job.error_class) == (JobStatus.FAILED, "validation")


def test_the_payload_is_exactly_the_action():
    assert build_registry().supports(JobType.ALERT_EXPIRY, SMTP_TEST_ACTION)
    assert validate_smtp_test_payload({"action": "smtp_test"}) == {"action": "smtp_test"}
    for bad in ({}, {"action": "smtp_test", "to": "x@example.test"}, {"action": "other"}):
        with pytest.raises(ValueError):
            validate_smtp_test_payload(bad)


def test_fragment_polls_every_two_seconds_only_while_the_job_is_pending(
    signed_in, worker_harness, web_factory, smtp_server
):
    configure_smtp(web_factory, smtp_server())
    post(signed_in)
    [job] = smtp_test_jobs(web_factory)
    pending = signed_in.get(f"/settings/smtp/test/{job.id}")
    assert pending.status_code == 200 and 'hx-trigger="every 2s"' in pending.text and "Queued" in pending.text
    worker_harness.run_queued()
    done = signed_in.get(f"/settings/smtp/test/{job.id}").text
    assert "hx-trigger" not in done and "Delivered" in done
    assert signed_in.get("/settings/smtp/test/00000000-0000-0000-0000-000000000000").status_code == 404


def test_tab_shows_the_newest_test_job_with_its_own_finish_time(
    signed_in, worker_harness, web_factory, web_user, smtp_server, clock
):
    configure_smtp(web_factory, smtp_server())
    post(signed_in)
    worker_harness.run_queued()
    [first] = smtp_test_jobs(web_factory)
    first_stamp = f'datetime="{first.finished_at:%Y-%m-%dT%H:%M:%SZ}"'
    tab = signed_in.get("/settings?tab=smtp").text
    assert "Delivered" in tab and first_stamp in tab
    clock.advance(seconds=300)
    with web_factory.begin() as db:
        db.execute(update(User).where(User.id == web_user.id).values(email="tempfail@example.test"))
    post(signed_in)
    [second] = [job for job in smtp_test_jobs(web_factory) if job.id != first.id]
    queued = signed_in.get("/settings?tab=smtp").text  # the newest job is still queued: not the earlier delivery
    assert 'data-test-status="queued"' in queued and f"/settings/smtp/test/{second.id}" in queued
    assert 'hx-trigger="every 2s"' in queued and "Delivered" not in queued and first_stamp not in queued
    worker_harness.run_queued()
    with web_factory() as db:
        second = db.get(Job, second.id)
    second_stamp = f'datetime="{second.finished_at:%Y-%m-%dT%H:%M:%SZ}"'
    assert second_stamp != first_stamp
    done = signed_in.get("/settings?tab=smtp").text
    assert 'data-test-status="failed"' in done and "451 at rcpt" in done and second_stamp in done
    assert "Delivered" not in done and first_stamp not in done and "hx-trigger" not in done
