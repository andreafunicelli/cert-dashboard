"""Worker handler for ``digest/default``: the daily digest, sent once per UTC day through the ledger.

The data is collected in a short transaction; the day's ``notification_log`` row (``digest:<UTC date>``)
is then locked, the mail sent and the attempt recorded in one transaction (Plan 2 Contract decisions
7, 8 and 11). A transient SMTP failure fails the job after the attempt is committed, so the queue
retry reuses the same row. Results and failure messages are counts and the fixed texts of
``app.services.smtp`` only — never the dedupe key, which the redactor would refuse.
"""

from collections.abc import Mapping

from app.jobs.queue import JobFailure
from app.jobs.worker import JobContext
from app.models import JSONValue
from app.services.alerts import resolve_recipients
from app.services.digest import collect_digest, digest_counts, digest_dedupe_key, render_digest
from app.services.notifications import open_notification, record_attempt
from app.services.settings import get_setting
from app.services.smtp import (
    SendOutcome,
    build_message,
    job_error_class,
    load_smtp_config,
    open_smtp,
    outcome_message,
    smtp_tls_context,
)

__all__ = ["send_digest", "validate_digest_payload"]


def validate_digest_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Accept ``{}`` only; anything else raises ``ValueError``."""
    if not isinstance(payload, Mapping) or dict(payload):
        raise ValueError("a digest payload is empty")
    return {}


def send_digest(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
    now = context.clock()
    with context.factory.begin() as db:
        data = collect_digest(db, now)
        zone = get_setting(db, "ui.timezone")
    mail = render_digest(data, zone if isinstance(zone, str) else "UTC", context.settings.dashboard_url)
    counts = digest_counts(data)

    with context.factory() as db:
        team = get_setting(db, "alert.recipients")
        addresses = [item for item in team if isinstance(item, str)] if isinstance(team, list) else []
        recipients = resolve_recipients(None, addresses)
        config = load_smtp_config(db)
        row = open_notification(
            db,
            kind="digest",
            dedupe_key=digest_dedupe_key(now),
            certificate_id=None,
            threshold_days=None,
            recipients=recipients,
            now=now,
        )
        if row is None:  # already sent today, attempts exhausted, backing off or locked elsewhere
            return {"delivered": False, **counts}
        if not recipients:
            outcome = SendOutcome(False, "no_recipients", outcome_message("no_recipients"), False)
        elif config is None:
            outcome = SendOutcome(False, "smtp_not_configured", outcome_message("not_configured"), False)
        else:
            # The password is passed on as bytes and only ever decoded inside ``login`` (app.services.smtp).
            with open_smtp(
                config, context.settings.smtp_password, context=smtp_tls_context(config.tls_verify)
            ) as session:
                outcome = session.send(build_message(config, recipients, mail.subject, mail.text, mail.html, now))
        record_attempt(db, row, outcome, now)
        db.commit()

    if outcome.delivered or outcome.code == "no_recipients":
        # An empty team list is a recorded configuration state (like the expiry job's ``no_recipients``
        # count), not a job failure: the ledger row and the result's ``delivered: False`` carry it.
        return {"delivered": outcome.delivered, **counts}
    raise JobFailure(job_error_class(outcome.code), outcome.message, retryable=outcome.retryable)
