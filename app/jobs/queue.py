"""Background job queue: PostgreSQL ``SKIP LOCKED`` claims, fenced completion, reaper, retries.

Every function runs inside the caller's transaction and never commits; audit rows are staged
with the state change they describe, so a rollback removes both. ``now`` is always passed in.
"""

import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import Job, JobHost, JSONValue
from app.models.enums import JobHostStatus, JobStatus, JobType
from app.services.audit import Actor, record, redact

ERROR_MESSAGE_LIMIT = 2_000
_ERROR_CLASS_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")
TIMEOUT_MESSAGE = "Job exceeded its time limit or its worker stopped responding."
WORKER_LOST = "worker_lost"
SYSTEM_ACTOR = Actor(None, "system")
ScheduledReason = Literal["manual", "nightly", "daily", "retry"]
_SCHEDULED_REASONS = frozenset(("manual", "nightly", "daily", "retry"))

NON_RETRYABLE_CLASSES = frozenset(
    {"auth", "validation", "config_invalid", "key_unwrap", "internal", "timeout"}
)


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int
    retryable: frozenset[str]


# Single source of truth for attempts and automatic retries (spec 7.2, 9.4); reused by the worker.
RETRY_POLICY: dict[JobType, RetryPolicy] = {
    JobType.DISCOVER: RetryPolicy(3, frozenset({"transient_network"})),
    JobType.SCAN: RetryPolicy(3, frozenset({"transient_network"})),
    JobType.ALERT_EXPIRY: RetryPolicy(3, frozenset({"smtp_transient"})),
    JobType.DIGEST: RetryPolicy(3, frozenset({"smtp_transient"})),
    JobType.CLEANUP: RetryPolicy(2, frozenset({"transient_network", "operational"})),
    JobType.DEPLOY: RetryPolicy(1, frozenset()),
}
# Delay after the Nth failed attempt. Attempts are capped at 3 in total, so 300 s is never used.
_RETRY_DELAYS = {1: 30, 2: 120, 3: 300}


class StaleJobError(Exception):
    """The job is not running under this worker any more (reaped, re-claimed or never claimed)."""


def safe_error_class(value: str | None) -> str:
    """Return ``value`` only if it is a plain classification token the redaction leaves alone.

    Anything else (free text, ``key=value`` pairs, tokens, empty) collapses to ``internal`` so a
    caller-supplied class can never smuggle a secret into ``job.error_class`` or the audit log.
    """
    if isinstance(value, str) and _ERROR_CLASS_PATTERN.fullmatch(value) and redact(value) == value:
        return value
    return "internal"


def safe_error_message(value: str | None) -> str | None:
    """Redact and truncate a failure message before it is persisted."""
    if value is None:
        return None
    return str(redact(value))[:ERROR_MESSAGE_LIMIT]


class JobFailure(Exception):
    """Raised by a handler to fail its job with a classified, already-sanitized message.

    ``error_class`` is normalized to a safe classification token and ``message`` is redacted
    and truncated here, so nothing a handler passes can carry a secret into the job row.
    ``retryable=False`` is persisted as ``result={"retryable": False}`` so the retry sweep skips
    the job. ``retryable=True`` can never widen the per-type policy.
    """

    def __init__(self, error_class: str, message: str, retryable: bool = False) -> None:
        self.error_class = safe_error_class(error_class)
        self.message = safe_error_message(message) or ""
        self.retryable = retryable
        super().__init__(f"{self.error_class}: {self.message}")

    def result(self) -> dict[str, JSONValue] | None:
        return None if self.retryable else {"retryable": False}


def is_retryable(job_type: JobType, error_class: str | None) -> bool:
    if error_class is None or error_class in NON_RETRYABLE_CLASSES:
        return False
    return error_class in RETRY_POLICY[JobType(job_type)].retryable


def retry_delay_seconds(attempt: int) -> int:
    try:
        return _RETRY_DELAYS[attempt]
    except KeyError:
        raise ValueError(f"no retry delay for attempt {attempt}") from None


def _require_aware(name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _require_json(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")  # noqa: TRY004 - contract: ValueError
            _require_json(item)
    elif isinstance(value, list):
        for item in value:
            _require_json(item)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
    elif value is not None and not isinstance(value, (str, int, bool)):
        raise ValueError(f"value of type {type(value).__name__} is not JSON-native")


def _clean_json(name: str, value: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Accept only JSON-native data that the audit redaction would leave unchanged."""
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object (dict)")  # noqa: TRY004 - contract: ValueError
    _require_json(value)
    if redact(value) != value:
        raise ValueError(f"{name} must not contain secret-like keys or values")
    return value


def _audit(db: Session, actor: Actor, action: str, job: Job, error_class: str | None) -> None:
    job_type = JobType(job.type).value
    details: dict[str, JSONValue] = {"type": job_type, "attempt": job.attempt, "error_class": error_class}
    row = record(db, actor, action, "job", str(job.id), details)
    # The redaction scanner mistakes the enum value "digest" for a Digest auth scheme; the type
    # is a closed enum, never user text, so restore it after the (still applied) redaction.
    row.details = {**row.details, "type": job_type}


def enqueue(
    db: Session,
    job_type: JobType,
    payload: Mapping[str, JSONValue],
    actor: Actor,
    *,
    priority: int,
    run_after: datetime,
    max_attempts: int = 3,
    scheduled_reason: ScheduledReason | None = None,
) -> Job:
    """Stage a queued job plus its ``job.enqueue`` audit row (caller commits)."""
    job_type = JobType(job_type)
    ceiling = RETRY_POLICY[job_type].max_attempts
    if not 1 <= max_attempts <= ceiling:
        raise ValueError(f"max_attempts must be between 1 and {ceiling} for {job_type.value} jobs")
    _require_aware("run_after", run_after)
    if scheduled_reason is not None and scheduled_reason not in _SCHEDULED_REASONS:
        raise ValueError(f"scheduled_reason must be one of {sorted(_SCHEDULED_REASONS)}")
    clean_payload = _clean_json("payload", payload)
    if scheduled_reason is None and actor.user_id is not None:
        scheduled_reason = "manual"
    job = Job(
        type=job_type,
        priority=priority,
        payload=clean_payload,
        requested_by=actor.user_id,
        scheduled_reason=scheduled_reason,
        max_attempts=max_attempts,
        run_after=run_after,
    )
    db.add(job)
    db.flush()
    action = clean_payload.get("action", "default")
    row = record(
        db,
        actor,
        "job.enqueue",
        "job",
        str(job.id),
        {"type": job_type.value, "action": action, "priority": priority},
    )
    row.details = {**row.details, "type": job_type.value}  # closed enum value; see _audit
    db.flush()
    return job


def claim(
    db: Session,
    worker_id: str,
    now: datetime,
    timeout_seconds: Callable[[Session, Job], int],
    *,
    eligible_types: frozenset[JobType] | None = None,
) -> Job | None:
    """Atomically take the best due job: one UPDATE over a ``FOR UPDATE SKIP LOCKED`` pick.

    ``timeout_seconds`` runs in the same transaction on the already-claimed row; if it fails the
    claim is rolled back (savepoint) and the job stays queued.
    """
    _require_aware("now", now)
    if eligible_types is not None and not eligible_types:
        return None
    pick = select(Job.id).where(
        Job.status == JobStatus.QUEUED, Job.run_after <= now, Job.attempt < Job.max_attempts
    )
    if eligible_types is not None:
        pick = pick.where(Job.type.in_([JobType(item) for item in eligible_types]))
    pick = (
        pick.order_by(Job.priority.desc(), Job.run_after.asc(), Job.created_at.asc(), Job.id.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    statement = (
        update(Job)
        .where(Job.id == pick.scalar_subquery())
        .values(
            status=JobStatus.RUNNING,
            locked_by=worker_id,
            locked_at=now,
            started_at=now,
            attempt=Job.attempt + 1,
        )
        .returning(Job)
        .execution_options(synchronize_session=False, populate_existing=True)
    )
    with db.begin_nested():
        job = db.execute(statement).scalars().one_or_none()
        if job is None:
            return None
        seconds = timeout_seconds(db, job)
        if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds <= 0:
            raise ValueError("timeout_seconds must return a positive number of seconds")
        job.timeout_at = now + timedelta(seconds=seconds)
        db.flush()
    return job


def finish(
    db: Session,
    job_id: UUID,
    worker_id: str,
    status: Literal["succeeded", "failed", "cancelled"],
    now: datetime,
    *,
    result: Mapping[str, JSONValue] | None = None,
    error_class: str | None = None,
    error_message: str | None = None,
) -> None:
    """Complete a running job, only for the worker that still owns it (else ``StaleJobError``)."""
    _require_aware("now", now)
    if status not in ("succeeded", "failed", "cancelled"):
        raise ValueError("status must be succeeded, failed or cancelled")
    clean_result = _clean_json("result", result) if result is not None else None
    job = db.execute(
        select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if job is None or job.status != JobStatus.RUNNING or job.locked_by != worker_id:
        raise StaleJobError(f"job {job_id} is not running under worker {worker_id}")
    job.status = JobStatus(status)
    job.finished_at = now
    job.locked_by = job.locked_at = job.timeout_at = None
    if clean_result is not None:
        job.result = clean_result
    if status == "failed":
        job.error_class = safe_error_class(error_class)
        error_class = job.error_class
        job.error_message = safe_error_message(error_message)
    elif status == "succeeded":
        error_class = job.error_class = job.error_message = None
    else:
        error_class = job.error_class
    _audit(db, Actor(None, f"worker:{worker_id}"), f"job.{status}", job, error_class)
    db.flush()


def reap(db: Session, now: datetime) -> int:
    """Fail ``running`` jobs past ``timeout_at`` and their ``running`` hosts; return the count.

    Paused jobs are untouched and timeouts are never retried automatically. Advisory locks
    belong to worker connections and vanish with them; nothing here pretends to release them.
    """
    _require_aware("now", now)
    jobs = list(
        db.scalars(
            select(Job)
            .where(Job.status == JobStatus.RUNNING, Job.timeout_at < now)
            .order_by(Job.timeout_at, Job.id)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
    )
    if not jobs:
        return 0
    for job in jobs:
        job.status = JobStatus.FAILED
        job.error_class = "timeout"
        job.error_message = TIMEOUT_MESSAGE
        job.finished_at = now
        job.locked_by = job.locked_at = job.timeout_at = None
        _audit(db, SYSTEM_ACTOR, "job.timeout", job, "timeout")
    db.flush()
    db.execute(
        update(JobHost)
        .where(JobHost.job_id.in_([job.id for job in jobs]), JobHost.status == JobHostStatus.RUNNING)
        .values(status=JobHostStatus.FAILED, error_message=WORKER_LOST, finished_at=now)
        .execution_options(synchronize_session=False)
    )
    return len(jobs)


def retry_due(db: Session, now: datetime) -> int:
    """Requeue failed jobs whose class is retryable for their type and whose backoff elapsed."""
    _require_aware("now", now)
    retryable_classes = {name for policy in RETRY_POLICY.values() for name in policy.retryable}
    candidates = db.scalars(
        select(Job)
        .where(
            Job.status == JobStatus.FAILED,
            Job.finished_at.is_not(None),
            Job.attempt < Job.max_attempts,
            Job.error_class.in_(retryable_classes),
        )
        .order_by(Job.finished_at, Job.id)
        .with_for_update(skip_locked=True)
        .execution_options(populate_existing=True)
    )
    count = 0
    for job in candidates:
        policy = RETRY_POLICY[JobType(job.type)]
        if not is_retryable(job.type, job.error_class) or job.attempt >= policy.max_attempts:
            continue
        if isinstance(job.result, dict) and job.result.get("retryable") is False:
            continue
        if job.finished_at + timedelta(seconds=retry_delay_seconds(job.attempt)) > now:
            continue
        job.status = JobStatus.QUEUED
        job.run_after = now
        job.scheduled_reason = "retry"
        job.finished_at = None
        _audit(db, SYSTEM_ACTOR, "job.retry", job, job.error_class)
        count += 1
    db.flush()
    return count
