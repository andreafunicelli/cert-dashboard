"""Worker handler for ``alert_expiry/smtp_test``: the "Send test email" button of Settings → SMTP.

The web process never holds ``smtp_password`` or opens SMTP, so it only enqueues this job. The
recipient is the requesting user's e-mail, read from ``job.requested_by`` at run time (the payload
carries nothing but the action). Persisted outcomes are fixed step names, reply codes and the fixed
texts of ``app.services.smtp`` (Plan 2 Contract decisions 13 and 20); nothing the peer said.
"""

from collections.abc import Mapping

from app.jobs.queue import JobFailure
from app.jobs.worker import JobContext
from app.models import Job, JSONValue, User
from app.services.smtp import (
    job_error_class,
    load_smtp_config,
    open_smtp,
    outcome_message,
    smtp_tls_context,
    test_message,
    transcript_summary,
)

__all__ = ["SMTP_TEST_ACTION", "smtp_test", "validate_smtp_test_payload"]

SMTP_TEST_ACTION = "smtp_test"


def validate_smtp_test_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Accept exactly ``{"action": "smtp_test"}``; anything else raises ``ValueError``."""
    if not isinstance(payload, Mapping) or dict(payload) != {"action": SMTP_TEST_ACTION}:
        raise ValueError("an SMTP test payload is exactly its action")
    return {"action": SMTP_TEST_ACTION}


def smtp_test(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
    with context.factory() as db:
        job = db.get(Job, context.job_id)
        user = db.get(User, job.requested_by) if job is not None and job.requested_by is not None else None
        recipient = user.email if user is not None else ""
        config = load_smtp_config(db)
    if not recipient:
        raise JobFailure("validation", "the test e-mail has no requesting user to send to")
    if config is None:
        raise JobFailure("config_invalid", outcome_message("not_configured"))
    # The session is closed before any socket opens: no connection or lock is held during SMTP I/O.
    with open_smtp(
        config, context.settings.smtp_password, context=smtp_tls_context(config.tls_verify)
    ) as session:
        outcome = session.send(test_message(config, recipient, context.clock()))
    if not outcome.delivered:
        raise JobFailure(
            job_error_class(outcome.code), f"{outcome.message}; {transcript_summary(outcome.steps)}"
        )
    return {
        "delivered": True,
        "recipient": recipient,
        "steps": [{"step": step.step, "code": step.code} for step in outcome.steps],
    }
