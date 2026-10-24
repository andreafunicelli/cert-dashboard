"""Job registry, schedule table, scheduler tick and per-type timeouts.

This module is side-effect free on import. The process loop, slots, heartbeat and liveness
endpoint belong to the worker runtime (plan Task 13, part B) and are deliberately absent here.
"""

import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.crypto.keyring import KeyUnwrapError
from app.jobs.queue import RETRY_POLICY, SYSTEM_ACTOR, JobFailure, enqueue, reap, retry_due
from app.models import AppSetting, Job, JSONValue, SchedulerState
from app.models.enums import JobType

_LOG = logging.getLogger(__name__)

# A scheduled occurrence missed by this much or more is skipped (and logged), never run late.
MISSED_RUN_LIMIT = timedelta(hours=12)

# Fixed, already-sanitized failure texts: nothing a validator or handler raised is ever echoed.
_INVALID_PAYLOAD = "invalid job payload"
_UNKNOWN_HANDLER = "no handler registered for this job"
_KEY_UNWRAP = "master key unavailable for this record"
_INTERNAL = "internal error"


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class JobContext:
    job_id: UUID
    worker_id: str
    factory: sessionmaker[Session]
    settings: Settings
    clock: Callable[[], datetime] = field(default=_utc_now)


type JobHandler = Callable[[JobContext, Mapping[str, JSONValue]], Mapping[str, JSONValue]]
type PayloadValidator = Callable[[Mapping[str, JSONValue]], dict[str, JSONValue]]


class JobRegistry:
    """Capability map ``(JobType, action) -> (validator, handler)``; the web app only reads it."""

    def __init__(self) -> None:
        self._entries: dict[tuple[JobType, str], tuple[PayloadValidator, JobHandler]] = {}

    def register(
        self,
        job_type: JobType,
        handler: JobHandler,
        *,
        action: str = "default",
        validator: PayloadValidator,
    ) -> None:
        key = (JobType(job_type), action)
        if key in self._entries:
            raise ValueError(f"handler already registered for {key[0].value}/{action}")
        self._entries[key] = (validator, handler)

    def supports(self, job_type: JobType, action: str = "default") -> bool:
        return (JobType(job_type), action) in self._entries

    def dispatch(self, context: JobContext, job: Job) -> Mapping[str, JSONValue]:
        """Validate the payload, then run the handler; failures are classified, never raw."""
        payload = job.payload
        if not isinstance(payload, dict):
            raise JobFailure("validation", _INVALID_PAYLOAD)
        action = payload.get("action", "default")
        if not isinstance(action, str):
            raise JobFailure("validation", _INVALID_PAYLOAD)
        entry = self._entries.get((JobType(job.type), action))
        if entry is None:
            raise JobFailure("validation", _UNKNOWN_HANDLER)
        validator, handler = entry
        try:
            clean = validator(payload)
        except Exception:  # noqa: BLE001 - any validator error is a sanitized validation failure
            raise JobFailure("validation", _INVALID_PAYLOAD) from None
        if not isinstance(clean, dict):
            raise JobFailure("validation", _INVALID_PAYLOAD)
        try:
            return handler(context, clean)
        except JobFailure:
            raise
        except KeyUnwrapError:
            raise JobFailure("key_unwrap", _KEY_UNWRAP) from None
        except Exception as exc:  # noqa: BLE001 - classified as internal below
            # Only the class name is logged: exception text and tracebacks may carry secrets.
            _LOG.error("job handler failed: %s", type(exc).__name__)
            raise JobFailure("internal", _INTERNAL) from None


# --- timeouts -----------------------------------------------------------------------------------

_FIXED_TIMEOUTS: dict[JobType, int] = {
    JobType.DISCOVER: 1800,
    JobType.SCAN: 1800,
    JobType.ALERT_EXPIRY: 300,
    JobType.DIGEST: 300,
    JobType.CLEANUP: 600,
}
DEFAULT_DEPLOY_TIMEOUT = 900
_TIMEOUT_CALLBACKS: dict[JobType, Callable[[Session, Job], int]] = {}


def register_timeout(job_type: JobType, callback: Callable[[Session, Job], int]) -> None:
    """Let Plan 3 compute the deploy timeout from the remaining hosts; nothing else is overridable."""
    if JobType(job_type) is not JobType.DEPLOY:
        raise ValueError("only deploy timeouts are computed by a callback")
    if JobType.DEPLOY in _TIMEOUT_CALLBACKS:
        raise ValueError("deploy timeout callback already registered")
    _TIMEOUT_CALLBACKS[JobType.DEPLOY] = callback


def timeout_for(db: Session, job: Job) -> int:
    job_type = JobType(job.type)
    callback = _TIMEOUT_CALLBACKS.get(job_type)
    if callback is not None:
        return callback(db, job)
    return _FIXED_TIMEOUTS.get(job_type, DEFAULT_DEPLOY_TIMEOUT)


# --- schedules ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Schedule:
    key: str
    job_type: JobType
    action: str = "default"


SCHEDULES: dict[str, Schedule] = {}
# Settings keys that do not follow the ``<key>.daily_at`` / ``<key>.enabled`` pattern.
_TIME_SETTING = {"discovery": "discovery.nightly_at"}
_ENABLED_SETTING = {"digest": "alert.digest_enabled"}
_DAILY_TIME = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")


def register_schedule(key: str, job_type: JobType, action: str = "default") -> None:
    if key in SCHEDULES:
        raise ValueError(f"schedule {key!r} already registered")
    SCHEDULES[key] = Schedule(key, JobType(job_type), action)


register_schedule("cleanup", JobType.CLEANUP)


def parse_daily_time(value: object) -> tuple[int, int] | None:
    """Parse a UTC ``HH:MM`` setting; anything else is ``None`` (the schedule is then skipped)."""
    if not isinstance(value, str):
        return None
    match = _DAILY_TIME.fullmatch(value)
    return (int(match.group(1)), int(match.group(2))) if match else None


def latest_occurrence(now: datetime, daily_at: tuple[int, int]) -> datetime:
    """Most recent ``HH:MM`` UTC instant that is not after ``now``."""
    now = now.astimezone(UTC)
    candidate = now.replace(hour=daily_at[0], minute=daily_at[1], second=0, microsecond=0)
    return candidate - timedelta(days=1) if candidate > now else candidate


def _priority(job_type: JobType) -> int:
    if job_type is JobType.CLEANUP:
        return 10
    if job_type is JobType.DIGEST:
        return 50
    return 100


def _run_schedule(db: Session, schedule: Schedule, now: datetime) -> bool:
    time_key = _TIME_SETTING.get(schedule.key, f"{schedule.key}.daily_at")
    enabled_key = _ENABLED_SETTING.get(schedule.key, f"{schedule.key}.enabled")
    values = {
        row.key: row.value
        for row in db.execute(select(AppSetting.key, AppSetting.value).where(AppSetting.key.in_([time_key, enabled_key])))
    }
    if values.get(enabled_key) is False:
        return False
    daily_at = parse_daily_time(values.get(time_key))
    if daily_at is None:
        _LOG.warning("schedule %s skipped: setting %s is not a valid HH:MM", schedule.key, time_key)
        return False
    occurrence = latest_occurrence(now, daily_at)

    # The row lock serializes concurrent schedulers: the loser re-reads the winner's last_run_at.
    db.execute(pg_insert(SchedulerState).values(key=schedule.key).on_conflict_do_nothing())
    state = db.execute(
        select(SchedulerState)
        .where(SchedulerState.key == schedule.key)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    if state.last_run_at is not None and state.last_run_at >= occurrence:
        return False
    state.last_run_at = occurrence  # at most once per occurrence, whether it runs or is skipped
    lateness = now - occurrence
    if lateness >= MISSED_RUN_LIMIT:
        _LOG.warning(
            "schedule %s skipped: occurrence %s missed by %d seconds",
            schedule.key,
            occurrence.isoformat(),
            int(lateness.total_seconds()),
            extra={
                "event": "schedule_missed",
                "schedule": schedule.key,
                "occurrence": occurrence.isoformat(),
                "lateness_seconds": int(lateness.total_seconds()),
            },
        )
        db.flush()
        return False
    payload: dict[str, JSONValue] = {}
    if schedule.action != "default":
        payload = {"action": schedule.action}
    elif schedule.job_type is JobType.CLEANUP:
        payload = {"reason": "scheduled"}
    enqueue(
        db,
        schedule.job_type,
        payload,
        SYSTEM_ACTOR,
        priority=_priority(schedule.job_type),
        run_after=now,
        max_attempts=RETRY_POLICY[schedule.job_type].max_attempts,
        scheduled_reason="nightly" if schedule.key == "discovery" else "daily",
    )
    return True


def scheduler_tick(factory: sessionmaker[Session], registry: JobRegistry, now: datetime) -> None:
    """Enqueue due scheduled jobs, then reap timed-out jobs and requeue retryable failures.

    Each step has its own transaction; a failing step is logged by class name and never stops
    the others. Correctness across concurrent schedulers rests on the per-schedule row lock, not
    on the advisory lock the worker additionally holds.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    for schedule in list(SCHEDULES.values()):
        if not registry.supports(schedule.job_type, schedule.action):
            continue
        try:
            with factory.begin() as db:
                _run_schedule(db, schedule, now)
        except Exception as exc:  # noqa: BLE001 - one failing step must not stop the others
            _LOG.error("schedule %s failed: %s", schedule.key, type(exc).__name__)
    for name, step in (("reap", reap), ("retry", retry_due)):
        try:
            with factory.begin() as db:
                step(db, now)
        except Exception as exc:  # noqa: BLE001 - one failing step must not stop the others
            _LOG.error("scheduler %s failed: %s", name, type(exc).__name__)
