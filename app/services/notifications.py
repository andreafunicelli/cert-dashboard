"""Delivery ledger (§4.15): one ``notification_log`` row per dedupe key, bounded attempts.

Nothing here commits; the caller owns the transaction. The send happens while the row lock taken
by ``open_notification`` is held and is committed together with ``record_attempt``. A worker crash
between SMTP acceptance and that commit can therefore resend once (at-least-once delivery).
"""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.jobs.queue import SYSTEM_ACTOR, enqueue, retry_delay_seconds
from app.models import Job, NotificationLog
from app.models.enums import JobStatus, JobType, NotificationStatus
from app.services.audit import redact

if TYPE_CHECKING:  # smtp -> settings -> worker -> this module: a runtime import would be circular
    from app.services.smtp import SendOutcome

MAX_NOTIFICATION_ATTEMPTS = 3
ERROR_LIMIT = 500
RETRY_PRIORITY = 100

type NotificationKind = Literal["expiry", "digest"]


def next_attempt_after(attempts: int, now: datetime, retryable: bool) -> datetime | None:
    """When the next attempt may run after ``attempts`` failed ones; ``None`` = stop for today."""
    if not retryable or attempts >= MAX_NOTIFICATION_ATTEMPTS:
        return None
    return now + timedelta(seconds=retry_delay_seconds(attempts))


def open_notification(
    db: Session,
    *,
    kind: NotificationKind,
    dedupe_key: str,
    certificate_id: int | None,
    threshold_days: int | None,
    recipients: Sequence[str],
    now: datetime,
) -> NotificationLog | None:
    """Create-or-lock the ledger row; return it only while a send attempt is allowed.

    ``None`` means: already sent, attempts exhausted, backoff not elapsed, or another session
    holds the row (``SKIP LOCKED``). ``created_at`` takes the injected clock so the "created
    today" rule of ``due_retries`` follows the same time source as the caller.
    """
    db.execute(
        pg_insert(NotificationLog)
        .values(
            certificate_id=certificate_id,
            kind=kind,
            threshold_days=threshold_days,
            recipients=list(recipients),
            status=NotificationStatus.FAILED,
            dedupe_key=dedupe_key,
            attempts=0,
            created_at=now,
        )
        .on_conflict_do_nothing(index_elements=[NotificationLog.dedupe_key])
    )
    row = db.scalar(
        select(NotificationLog)
        .where(NotificationLog.dedupe_key == dedupe_key)
        .with_for_update(skip_locked=True)
        .execution_options(populate_existing=True)
    )
    if row is None:
        return None
    if row.status == NotificationStatus.SENT or row.attempts >= MAX_NOTIFICATION_ATTEMPTS:
        return None
    if row.next_attempt_at is not None and row.next_attempt_at > now:
        return None
    return row


def record_attempt(db: Session, row: NotificationLog, outcome: "SendOutcome", now: datetime) -> NotificationLog:
    """Count the attempt; ``sent_at`` is set only when the message was delivered."""
    row.attempts += 1
    row.last_attempt_at = now
    if outcome.delivered:
        row.status = NotificationStatus.SENT
        row.sent_at = now
        row.error = None
        row.next_attempt_at = None
    else:
        row.status = NotificationStatus.FAILED
        # The code is a fixed literal; only the message goes through the redactor.
        row.error = f"{outcome.code}: {redact(outcome.message)}"[:ERROR_LIMIT]
        row.next_attempt_at = next_attempt_after(row.attempts, now, outcome.retryable)
    db.flush()
    return row


def due_retries(db: Session, kind: NotificationKind, now: datetime) -> list[NotificationLog]:
    """Failed rows created today (UTC) whose backoff elapsed, oldest first, locked."""
    midnight = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    return list(
        db.scalars(
            select(NotificationLog)
            .where(
                NotificationLog.kind == kind,
                NotificationLog.status == NotificationStatus.FAILED,
                NotificationLog.attempts.between(1, MAX_NOTIFICATION_ATTEMPTS - 1),
                NotificationLog.next_attempt_at <= now,
                NotificationLog.created_at >= midnight,
            )
            .order_by(NotificationLog.id)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
    )


def enqueue_notification_retry(db: Session, now: datetime) -> int:
    """Tick step: one ``retry_failed`` expiry job while due rows exist and none is in flight."""
    if not due_retries(db, "expiry", now):
        return 0
    in_flight = db.scalar(
        select(Job.id)
        .where(Job.type == JobType.ALERT_EXPIRY, Job.status.in_((JobStatus.QUEUED, JobStatus.RUNNING)))
        .limit(1)
    )
    if in_flight is not None:
        return 0
    enqueue(
        db,
        JobType.ALERT_EXPIRY,
        {"mode": "retry_failed"},
        SYSTEM_ACTOR,
        priority=RETRY_PRIORITY,
        run_after=now,
        max_attempts=1,
        scheduled_reason="retry",
    )
    return 1
