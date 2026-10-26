"""Worker handler for ``alert_expiry/default``: idempotent expiry mail through the delivery ledger.

Two modes (Plan 2 Contract decisions 6-10). The default mode evaluates every due certificate and
sends one mail per candidate; ``{"mode": "retry_failed"}`` (queued by the ``notification_retry`` tick
step) only re-attempts ledger rows that are due for a retry and never fails for SMTP reasons, because
the sweep itself is the retry. One SMTP session serves the whole job; every candidate gets its own
transaction, which holds the ledger row lock across the send and commits it with the attempt.
Results and failure messages are counts and the fixed texts of ``app.services.smtp`` only.
"""

from collections.abc import Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime

from app.jobs.queue import JobFailure
from app.jobs.worker import JobContext
from app.models import JSONValue
from app.services.alerts import ExpiryCandidate, due_expiry_alerts, render_expiry
from app.services.notifications import due_retries, open_notification, record_attempt
from app.services.smtp import (
    SendOutcome,
    SmtpConfig,
    SmtpSession,
    build_message,
    job_error_class,
    load_smtp_config,
    open_smtp,
    outcome_message,
    smtp_tls_context,
)

__all__ = ["RETRY_MODE", "expiry_check", "validate_expiry_payload"]

RETRY_MODE = "retry_failed"


def validate_expiry_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Accept ``{}`` or exactly ``{"mode": "retry_failed"}``; anything else raises ``ValueError``."""
    if not isinstance(payload, Mapping) or dict(payload) not in ({}, {"mode": RETRY_MODE}):
        raise ValueError("an expiry payload is empty or the retry_failed mode")
    return dict(payload)


@dataclass
class _Tally:
    evaluated: int = 0
    sent: int = 0
    failed: int = 0
    no_recipients: int = 0
    skipped: int = 0
    first_failure: SendOutcome | None = None
    transient: SendOutcome | None = None

    def counts(self) -> dict[str, JSONValue]:
        return {
            "evaluated": self.evaluated,
            "sent": self.sent,
            "failed": self.failed,
            "no_recipients": self.no_recipients,
            "skipped": self.skipped,
        }


def expiry_check(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
    now = context.clock()
    retry_mode = payload.get("mode") == RETRY_MODE
    with context.factory.begin() as db:
        config = load_smtp_config(db)
        if retry_mode:
            candidates = [
                ExpiryCandidate(row.certificate_id, row.threshold_days, 0, row.dedupe_key, tuple(row.recipients))
                for row in due_retries(db, "expiry", now)
                if row.certificate_id is not None and row.threshold_days is not None
            ]
        else:
            candidates = due_expiry_alerts(db, now)

    tally = _Tally(evaluated=len(candidates))
    with ExitStack() as stack:
        # The password is passed on as bytes and only ever decoded inside ``login`` (app.services.smtp).
        session = (
            stack.enter_context(
                open_smtp(config, context.settings.smtp_password, context=smtp_tls_context(config.tls_verify))
            )
            if config is not None
            else None
        )
        for candidate in candidates:
            _deliver(context, candidate, config, session, now, tally)

    attempted = tally.sent + tally.failed
    if retry_mode or tally.first_failure is None or tally.sent or not attempted:
        return tally.counts()
    # Contract decision 9: nothing was delivered although at least one send was attempted.
    worst = tally.transient or tally.first_failure
    raise JobFailure(
        job_error_class(worst.code),
        f"{attempted} expiry alert(s) not delivered: {worst.message}",
        retryable=tally.transient is not None,
    )


def _deliver(
    context: JobContext,
    candidate: ExpiryCandidate,
    config: SmtpConfig | None,
    session: SmtpSession | None,
    now: datetime,
    tally: _Tally,
) -> None:
    """One candidate, one transaction: lock the ledger row, send (if possible), record, commit."""
    with context.factory() as db:
        row = open_notification(
            db,
            kind="expiry",
            dedupe_key=candidate.dedupe_key,
            certificate_id=candidate.certificate_id,
            threshold_days=candidate.threshold_days,
            recipients=candidate.recipients,
            now=now,
        )
        if row is None:
            tally.skipped += 1
            return
        if not candidate.recipients:
            outcome = SendOutcome(False, "no_recipients", outcome_message("no_recipients"), False)
        elif config is None or session is None:
            outcome = SendOutcome(False, "smtp_not_configured", outcome_message("not_configured"), False)
        else:
            try:
                mail = render_expiry(db, candidate, now, context.settings.dashboard_url)
            except LookupError:  # the certificate vanished since evaluation; nothing is recorded
                db.rollback()
                tally.skipped += 1
                return
            outcome = session.send(build_message(config, candidate.recipients, mail.subject, mail.text, mail.html, now))
        record_attempt(db, row, outcome, now)
        db.commit()
    if outcome.code == "no_recipients":
        tally.no_recipients += 1
    elif outcome.delivered:
        tally.sent += 1
    else:
        tally.failed += 1
        tally.first_failure = tally.first_failure or outcome
        if outcome.retryable:
            tally.transient = tally.transient or outcome
