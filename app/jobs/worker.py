"""Worker runtime: job registry, schedules, scheduler tick, slots, heartbeat and liveness.

Importing this module has no side effects (no I/O, no threads, no signal handlers), so the web
app can import ``worker_liveness`` and the registry types. The process only starts in
``main()`` / ``run_worker()``.
"""

import json
import logging
import os
import re
import shutil
import signal
import socket
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import ConfigurationError, Settings, load_settings
from app.crypto.keyring import KeyUnwrapError
from app.db import assert_database_ready, create_session_factory
from app.jobs.queue import (
    RETRY_POLICY,
    SYSTEM_ACTOR,
    JobCancelled,
    JobControl,
    JobFailure,
    JobPaused,
    JobRequeued,
    StaleJobError,
    claim,
    enqueue,
    finish,
    reap,
    release_claim,
    retry_due,
)
from app.models import AppSetting, AuditLog, Job, JSONValue, SchedulerState, WorkerHeartbeat
from app.models.enums import JobType
from app.services.audit import Actor, SecretRedactionFilter, record
from app.services.notifications import enqueue_notification_retry

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
# Runs inside the transaction that marks the job ``succeeded`` (so ``job.status`` is already final).
SuccessHook = Callable[[Session, Job, datetime], None]


class JobRegistry:
    """Capability map ``(JobType, action) -> (validator, handler)``; the web app only reads it."""

    def __init__(self) -> None:
        self._entries: dict[tuple[JobType, str], tuple[PayloadValidator, JobHandler, SuccessHook | None]] = {}

    def register(
        self,
        job_type: JobType,
        handler: JobHandler,
        *,
        action: str = "default",
        validator: PayloadValidator,
        on_success: SuccessHook | None = None,
    ) -> None:
        key = (JobType(job_type), action)
        if key in self._entries:
            raise ValueError(f"handler already registered for {key[0].value}/{action}")
        if on_success is not None and not callable(on_success):
            raise TypeError("on_success must be callable")
        self._entries[key] = (validator, handler, on_success)

    def success_hook(self, job_type: JobType, action: str = "default") -> SuccessHook | None:
        """The hook registered for ``(job_type, action)``, if any."""
        entry = self._entries.get((JobType(job_type), action))
        return entry[2] if entry is not None else None

    def supports(self, job_type: JobType, action: str = "default") -> bool:
        return (JobType(job_type), action) in self._entries

    def job_types(self) -> frozenset[JobType]:
        """Every job type with at least one registered handler (any action)."""
        return frozenset(job_type for job_type, _ in self._entries)

    def dispatch(self, context: JobContext, job: Job) -> Mapping[str, JSONValue]:
        """Validate the payload, then run the handler; failures are classified, never raw."""
        payload = job.payload
        if not isinstance(payload, dict):
            raise JobFailure("validation", _INVALID_PAYLOAD)
        action = payload.get("action", "default")
        if not isinstance(action, str):
            raise JobFailure("validation", _INVALID_PAYLOAD)
        try:
            job_type = JobType(job.type)
        except ValueError:
            raise JobFailure("validation", _UNKNOWN_HANDLER) from None
        entry = self._entries.get((job_type, action))
        if entry is None:
            raise JobFailure("validation", _UNKNOWN_HANDLER)
        validator, handler, _ = entry
        try:
            clean = validator(payload)
        except Exception:  # noqa: BLE001 - any validator error is a sanitized validation failure
            raise JobFailure("validation", _INVALID_PAYLOAD) from None
        if not isinstance(clean, dict):
            raise JobFailure("validation", _INVALID_PAYLOAD)
        try:
            return handler(context, clean)
        except (JobFailure, JobControl):
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
_TIME_SETTING = {"discovery": "discovery.nightly_at", "trust_recheck": "scan.daily_at"}
_ENABLED_SETTING = {"digest": "alert.digest_enabled", "trust_recheck": "scan.enabled"}
_DAILY_TIME = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")


def register_schedule(key: str, job_type: JobType, action: str = "default") -> None:
    if key in SCHEDULES:
        raise ValueError(f"schedule {key!r} already registered")
    SCHEDULES[key] = Schedule(key, JobType(job_type), action)


register_schedule("cleanup", JobType.CLEANUP)
register_schedule("scan", JobType.SCAN)
register_schedule("trust_recheck", JobType.SCAN, "trust_recheck")  # shares scan.daily_at / scan.enabled
register_schedule("expiry_check", JobType.ALERT_EXPIRY)
register_schedule("digest", JobType.DIGEST)  # digest.daily_at / alert.digest_enabled, priority 50
register_schedule("discovery", JobType.DISCOVER)  # discovery.nightly_at / discovery.enabled, priority 100


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


# --- tick steps ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class TickStep:
    """A sweep run on every scheduler tick, only while its handler is registered."""

    name: str
    step: Callable[[Session, datetime], int]
    requires: tuple[JobType, str]


TICK_STEPS: dict[str, TickStep] = {}


def register_tick_step(name: str, step: Callable[[Session, datetime], int], *, requires: tuple[JobType, str]) -> None:
    if name in TICK_STEPS:
        raise ValueError(f"tick step {name!r} already registered")
    TICK_STEPS[name] = TickStep(name, step, (JobType(requires[0]), requires[1]))


# Inert until the expiry handler (``alert_expiry/default``) is registered.
register_tick_step("notification_retry", enqueue_notification_retry, requires=(JobType.ALERT_EXPIRY, "default"))


def scheduler_tick(factory: sessionmaker[Session], registry: JobRegistry, now: datetime) -> None:
    """Enqueue due scheduled jobs, reap timed-out jobs, requeue retryable failures, run tick steps.

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
    for tick_step in list(TICK_STEPS.values()):
        if not registry.supports(*tick_step.requires):
            continue
        try:
            with factory.begin() as db:
                tick_step.step(db, now)
        except Exception as exc:  # noqa: BLE001 - one failing step must not stop the others
            _LOG.error("tick step %s failed: %s", tick_step.name, type(exc).__name__)


# --- liveness -----------------------------------------------------------------------------------

LIVENESS_WINDOW = timedelta(minutes=5)


def worker_liveness(db: Session, now: datetime) -> Literal["ok", "stale"]:
    """``ok`` when the newest heartbeat is at most five minutes old; no heartbeat at all is stale.

    Shared by ``/healthz`` and the web banner so both always agree.
    """
    newest = db.scalar(select(func.max(WorkerHeartbeat.last_seen_at)))
    if newest is None or newest < now - LIVENESS_WINDOW:
        return "stale"
    return "ok"


# --- worker capabilities (spec 9.2) --------------------------------------------------------------


@dataclass(frozen=True)
class WorkerCapabilities:
    """What the newest live worker holds, as the web process (which cannot see secrets) may know it."""

    worker_id: str
    ssh_key_present: bool
    known_hosts_present: bool
    vault_password_present: bool
    inventory_token_present: bool


def record_worker_start(factory: sessionmaker[Session], settings: Settings, worker_id: str, now: datetime) -> None:
    """Write one ``worker.start`` audit row: the worker id and four presence booleans, never a value."""
    details: dict[str, JSONValue] = {
        "worker_id": worker_id,
        "ssh_key_present": settings.ansible_ssh_key is not None,
        "known_hosts_present": settings.known_hosts_file.is_file(),
        "vault_password_present": settings.ansible_vault_password is not None,
        "inventory_token_present": settings.inventory_git_token is not None,
    }
    with factory.begin() as db:
        row = record(db, Actor(None, f"worker:{worker_id}"), "worker.start", "worker", worker_id, details)
        row.created_at = now  # the injected clock, like the heartbeat it is matched against


def worker_capabilities(db: Session, now: datetime) -> WorkerCapabilities | None:
    """Capabilities from the newest ``worker.start`` row whose worker has a fresh heartbeat."""
    row = db.execute(
        select(AuditLog.details)
        .join(WorkerHeartbeat, WorkerHeartbeat.worker_id == AuditLog.target_id)
        .where(AuditLog.action == "worker.start", WorkerHeartbeat.last_seen_at >= now - LIVENESS_WINDOW)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None
    return WorkerCapabilities(
        worker_id=str(row["worker_id"]),
        ssh_key_present=row.get("ssh_key_present") is True,
        known_hosts_present=row.get("known_hosts_present") is True,
        vault_password_present=row.get("vault_password_present") is True,
        inventory_token_present=row.get("inventory_token_present") is True,
    )


# --- key staging wipe ---------------------------------------------------------------------------


class KeyStagingError(Exception):
    """The key staging directory is unsafe to use (symlink, not a directory) or cannot be emptied."""


def wipe_key_staging(path: Path) -> bool:
    """Remove every direct child of ``path`` without ever leaving it; return False if it is absent.

    The directory is opened with ``O_NOFOLLOW | O_DIRECTORY`` and children are addressed relative
    to that descriptor, so a symlinked staging directory is refused and a symlinked child is
    unlinked (never followed). Anything that cannot be removed refuses startup: leftover key
    material must not survive a restart.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        _LOG.warning("key staging directory %s does not exist; nothing to wipe", path)
        return False
    except OSError:
        raise KeyStagingError(f"key staging directory {path} is a symlink or not a directory") from None
    try:
        with os.scandir(fd) as entries:
            children = [(entry.name, entry.is_dir(follow_symlinks=False)) for entry in entries]
        for name, is_directory in children:
            try:
                if is_directory:
                    shutil.rmtree(name, dir_fd=fd)
                else:
                    os.unlink(name, dir_fd=fd)
            except OSError:
                raise KeyStagingError(f"cannot remove an entry of the key staging directory {path}") from None
    finally:
        os.close(fd)
    return True


# --- runtime ------------------------------------------------------------------------------------

CLAIM_POLL_SECONDS = 0.5
TICK_INTERVAL_SECONDS = 30.0
MAX_GRACE_SECONDS = 25.0
# A commit already underway when the grace expires is atomic and cannot be recalled: close() waits
# for it, but only this long (a hung database must not stall shutdown).
COMMIT_SETTLE_SECONDS = 2.0
# Running jobs get what is left of the shutdown bound once the commit settle time is reserved.
MAX_DRAIN_SECONDS = MAX_GRACE_SECONDS - COMMIT_SETTLE_SECONDS
# Discovery and scans share one concurrency budget (``max_parallel_jobs``).
_CAPPED_TYPES = frozenset({JobType.DISCOVER, JobType.SCAN})
# These need the SSH key; without it they are never claimed (scans and cleanup are unaffected).
_SSH_TYPES = frozenset({JobType.DISCOVER, JobType.DEPLOY})
_SCHEDULER_LOCK = "SELECT pg_try_advisory_lock(hashtext('scheduler'))"


class Worker:
    """Four-slot job runner with heartbeat and a single advisory-lock scheduler.

    ``tick()`` (heartbeat + scheduler) and ``poll()`` (claim into free slots) are the two
    single-iteration steps; ``run()`` merely loops them, so tests drive them directly with an
    injected ``clock``. Jobs run on daemon threads, one per claimed job, bounded by the slot
    count that ``poll()`` reserves *before* claiming.
    """

    def __init__(
        self,
        settings: Settings,
        registry: JobRegistry,
        factory: sessionmaker[Session],
        *,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], object] | None = None,
        worker_id: str | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.factory = factory
        self.clock = clock
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid4()}"
        self.started_at = clock()
        self.grace_seconds = MAX_GRACE_SECONDS
        self._engine: Engine = factory.kw["bind"]
        self._wake = threading.Event()
        self._sleep = sleep or self._wake.wait
        self._stop_requested = False
        self._closed = False  # the drain happens once, however many times close() is called
        self._abandoned = False  # grace expired with slots still running: their results are fenced
        self._slots = threading.Condition()
        self._running: dict[UUID, JobType] = {}
        self._committing: set[UUID] = set()  # past the last fence check: their COMMIT is in flight
        self._lock_connection: Connection | None = None
        self._lock_pid: int | None = None

    # -- state ---------------------------------------------------------------------------------

    @property
    def holds_scheduler_lock(self) -> bool:
        return self._lock_connection is not None

    @property
    def scheduler_lock_pid(self) -> int | None:
        return self._lock_pid

    @property
    def effective_grace_seconds(self) -> float:
        return min(max(self.grace_seconds, 0.0), MAX_DRAIN_SECONDS)

    def eligible_types(self) -> frozenset[JobType]:
        """Job types that may be claimed *right now*: capacity is reserved before every claim."""
        with self._slots:
            running = list(self._running.values())
        if len(running) >= self.settings.worker_concurrency:
            return frozenset()
        types = set(self.registry.job_types())
        if not self.settings.ssh_available:
            types -= _SSH_TYPES
        if sum(1 for job_type in running if job_type in _CAPPED_TYPES) >= self.settings.max_parallel_jobs:
            types -= _CAPPED_TYPES
        return frozenset(types)

    # -- one iteration of each loop ------------------------------------------------------------

    def tick(self) -> None:
        """Heartbeat, then (only as the advisory-lock holder) enqueue schedules and reap/retry."""
        now = self.clock()
        self._heartbeat(now)
        if self._ensure_scheduler_lock():
            try:
                scheduler_tick(self.factory, self.registry, now)
            except Exception as exc:  # noqa: BLE001 - the loop must survive a failing tick
                _LOG.error("scheduler tick failed: %s", type(exc).__name__)

    def poll(self) -> int:
        """Claim jobs into every free slot; return how many were started (never blocks on a job)."""
        started = 0
        while not self._stop_requested:
            eligible = self.eligible_types()
            if not eligible:
                break
            try:
                with self.factory.begin() as db:
                    job = claim(db, self.worker_id, self.clock(), timeout_for, eligible_types=eligible)
                    claimed = (job.id, JobType(job.type)) if job is not None else None
            except Exception as exc:  # noqa: BLE001 - a database blip must not kill the worker
                _LOG.error("job claim failed: %s", type(exc).__name__)
                break
            if claimed is None:
                break
            self._start(*claimed)
            started += 1
        return started

    def run_queued(self, timeout: float = 30.0) -> int:
        """Run claimable jobs to completion (test/inline helper); return how many were run."""
        deadline = time.monotonic() + timeout
        total = 0
        while True:
            started = self.poll()
            total += started
            with self._slots:
                if started == 0 and not self._running:
                    return total
                if started == 0:
                    self._slots.wait(0.05)
            if time.monotonic() > deadline:
                raise TimeoutError("run_queued: jobs still running after the deadline")

    def wait_idle(self, timeout: float) -> bool:
        """Block until no slot is busy (True) or ``timeout`` seconds pass (False)."""
        with self._slots:
            return self._slots.wait_for(lambda: not self._running, timeout)

    # -- process loop and shutdown -------------------------------------------------------------

    def request_stop(self) -> None:
        """Signal-handler safe: only flips a flag (no locks); the loop notices within one poll."""
        self._stop_requested = True

    def stop(self) -> None:
        self._stop_requested = True
        self._wake.set()

    def run(self) -> None:
        _LOG.info("worker started", extra={"worker_id": self.worker_id})
        next_tick = 0.0
        try:
            while not self._stop_requested:
                if time.monotonic() >= next_tick:
                    self.tick()
                    next_tick = time.monotonic() + TICK_INTERVAL_SECONDS
                if not self.poll() and not self._stop_requested:
                    self._sleep(CLAIM_POLL_SECONDS)
        finally:
            self.close()

    def close(self, grace_seconds: float | None = None) -> None:
        """Stop claiming, give running jobs one bounded grace, then drop the scheduler lock.

        The drain runs only on the first call (``run()`` and ``run_worker()`` both close, which
        must not double the grace) and ``grace_seconds`` is capped at ``MAX_DRAIN_SECONDS``, so drain plus
        commit settle never exceed ``MAX_GRACE_SECONDS``. Jobs
        still running when the grace expires are abandoned: ``_finish`` refuses to write their
        late result, and a finish already inside its transaction rolls back at its pre-commit
        check, so they stay ``running`` until the reaper times them out. Safe to repeat.
        """
        self.stop()
        with self._slots:
            first, self._closed = not self._closed, True
        if first:
            grace = self.grace_seconds if grace_seconds is None else grace_seconds
            grace = min(max(grace, 0.0), MAX_DRAIN_SECONDS)
            if not self.wait_idle(grace):
                with self._slots:
                    # Same lock as _finish's pre-commit check: a finish either sees the fence and
                    # rolls back, or has already entered its (atomic) commit and is waited for.
                    self._abandoned = bool(self._running)
                    running = len(self._running)
                    self._slots.wait_for(lambda: not self._committing, COMMIT_SETTLE_SECONDS)
                if running:
                    _LOG.warning(
                        "shutdown grace expired with jobs still running",
                        extra={"worker_id": self.worker_id, "running": running},
                    )
        self._drop_scheduler_lock()
        if first:
            _LOG.info("worker stopped", extra={"worker_id": self.worker_id})

    # -- heartbeat and scheduler lock ----------------------------------------------------------

    def _heartbeat(self, now: datetime) -> None:
        with self._slots:
            current = next(iter(self._running), None)  # representative only, never the truth
        statement = pg_insert(WorkerHeartbeat).values(
            worker_id=self.worker_id, started_at=self.started_at, last_seen_at=now, current_job_id=current
        )
        statement = statement.on_conflict_do_update(
            index_elements=[WorkerHeartbeat.worker_id],
            set_={
                "last_seen_at": statement.excluded.last_seen_at,
                "current_job_id": statement.excluded.current_job_id,
                "updated_at": func.now(),
            },
        )
        try:
            with self.factory.begin() as db:
                db.execute(statement)
        except Exception as exc:  # noqa: BLE001 - keep working; the next tick retries
            _LOG.error("heartbeat failed: %s", type(exc).__name__)

    def _ensure_scheduler_lock(self) -> bool:
        """True when this worker holds the scheduler lock; (re)attempt it if it does not."""
        if self._lock_connection is not None:
            try:
                self._lock_connection.execute(text("SELECT 1"))
                return True  # the session, and therefore its advisory lock, is alive
            except Exception as exc:  # noqa: BLE001 - connection lost: the lock went with it
                _LOG.warning("scheduler lock connection lost: %s", type(exc).__name__)
                self._drop_scheduler_lock()
        connection: Connection | None = None
        try:
            connection = self._engine.connect().execution_options(isolation_level="AUTOCOMMIT")
            if connection.execute(text(_SCHEDULER_LOCK)).scalar():
                self._lock_pid = connection.execute(text("SELECT pg_backend_pid()")).scalar()
                self._lock_connection = connection
                return True
        except Exception as exc:  # noqa: BLE001 - not holding the lock is a safe outcome
            _LOG.warning("scheduler lock attempt failed: %s", type(exc).__name__)
        if connection is not None:
            _discard(connection)
        return False

    def _drop_scheduler_lock(self) -> None:
        """Close the dedicated connection; the server releases its session-level advisory lock."""
        connection, self._lock_connection, self._lock_pid = self._lock_connection, None, None
        if connection is not None:
            _discard(connection)

    # -- slots ---------------------------------------------------------------------------------

    def _start(self, job_id: UUID, job_type: JobType) -> None:
        with self._slots:
            self._running[job_id] = job_type  # reserved before the thread exists
        threading.Thread(target=self._slot, args=(job_id, job_type), name=f"job-{job_id}", daemon=True).start()

    def _slot(self, job_id: UUID, job_type: JobType) -> None:
        fields = {"worker_id": self.worker_id, "job_id": str(job_id), "job_type": job_type.value}
        started = time.monotonic()
        try:
            _LOG.info("job started", extra=fields)
            status = self._execute(job_id)
            _LOG.info(
                "job finished",
                extra={**fields, "status": status, "duration_ms": int((time.monotonic() - started) * 1000)},
            )
        except Exception as exc:  # noqa: BLE001 - never let a slot die silently; the reaper cleans up
            _LOG.error("job slot failed: %s", type(exc).__name__, extra=fields)
        finally:
            with self._slots:
                self._running.pop(job_id, None)
                self._slots.notify_all()

    def _execute(self, job_id: UUID) -> str:
        context = JobContext(job_id, self.worker_id, self.factory, self.settings, clock=self.clock)
        failure: JobFailure | None = None
        result: Mapping[str, JSONValue] = {}
        try:
            with self.factory() as db:
                job = db.get(Job, job_id)
                if job is None:
                    raise StaleJobError(f"job {job_id} no longer exists")
                db.expunge(job)
            result = self.registry.dispatch(context, job)
        except JobControl as control:
            try:
                return self._settle_control(job_id, control)
            except ValueError:
                # The outcome's result is not JSON-native or looks secret; fail the job instead.
                failure = JobFailure("internal", _INTERNAL)
        except JobFailure as exc:
            failure = exc
        except Exception as exc:  # noqa: BLE001 - classified as internal; text may carry secrets
            _LOG.error("job could not run: %s", type(exc).__name__)
            failure = JobFailure("internal", _INTERNAL)
        if failure is None:
            try:
                return self._finish(job_id, "succeeded", result=result)
            except ValueError:
                # finish() refuses results that are not JSON-native or look secret; fail the job.
                failure = JobFailure("internal", _INTERNAL)
        return self._finish(
            job_id,
            "failed",
            result=failure.result(),
            error_class=failure.error_class,
            error_message=failure.message,
        )

    def _settle_control(self, job_id: UUID, control: JobControl) -> str:
        """Map a handler's control outcome behind the same ownership fence as ``_finish``."""
        if isinstance(control, JobCancelled):
            return self._finish(job_id, "cancelled", result=control.result, error_message=control.message)
        if isinstance(control, JobPaused):

            def release(db: Session, now: datetime) -> None:
                release_claim(
                    db,
                    job_id,
                    self.worker_id,
                    now,
                    to="paused",
                    resume_from_batch=control.resume_from_batch,
                    result=control.result,
                )

            return self._commit_outcome(job_id, "paused", release)
        if isinstance(control, JobRequeued):

            def requeue(db: Session, now: datetime) -> None:
                release_claim(db, job_id, self.worker_id, now, to="queued", run_after=control.run_after)

            return self._commit_outcome(job_id, "queued", requeue)
        _LOG.error("unknown job control outcome: %s", type(control).__name__)
        return self._finish(job_id, "failed", error_class="internal", error_message=_INTERNAL)

    def _finish(self, job_id: UUID, status: Literal["succeeded", "failed", "cancelled"], **details) -> str:
        def apply(db: Session, now: datetime) -> None:
            finish(db, job_id, self.worker_id, status, now, **details)
            if status == "succeeded":
                self._run_success_hook(db, job_id, now)

        return self._commit_outcome(job_id, status, apply)

    def _run_success_hook(self, db: Session, job_id: UUID, now: datetime) -> None:
        """Run the registration's hook in a savepoint: a failing hook never undoes the success."""
        job = db.get(Job, job_id)
        if job is None or not isinstance(job.payload, dict):
            return
        action = job.payload.get("action", "default")
        hook = self.registry.success_hook(JobType(job.type), action) if isinstance(action, str) else None
        if hook is None:
            return
        try:
            with db.begin_nested():
                hook(db, job, now)
        except Exception as exc:  # noqa: BLE001 - only the class name is logged: the text may carry secrets
            _LOG.error(
                "success hook failed: %s",
                type(exc).__name__,
                extra={"worker_id": self.worker_id, "job_id": str(job_id)},
            )

    def _commit_outcome(self, job_id: UUID, outcome: str, apply: Callable[[Session, datetime], None]) -> str:
        """Run ``apply`` in one transaction, between the two shutdown-fence checks."""
        db = self.factory()
        try:
            with db.begin():
                self._check_fence(job_id)  # cheap early exit: nothing written yet
                apply(db, self.clock())
                # The fence is re-checked with the transaction still open and the job marked as
                # committing under the same lock close() uses to abandon: shutdown either wins
                # (rollback here) or waits for the commit that follows.
                self._check_fence(job_id, committing=True)
        except _Abandoned:
            _LOG.warning(
                "job result discarded: shutdown abandoned the job; the reaper will time it out",
                extra={"worker_id": self.worker_id, "job_id": str(job_id)},
            )
            return "abandoned"
        except StaleJobError:
            _LOG.warning(
                "job result discarded: the job is no longer owned by this worker (stale)",
                extra={"worker_id": self.worker_id, "job_id": str(job_id)},
            )
            return "stale"
        finally:
            with self._slots:
                self._committing.discard(job_id)
                self._slots.notify_all()
            db.close()
        return outcome

    def _check_fence(self, job_id: UUID, *, committing: bool = False) -> None:
        with self._slots:
            if self._abandoned:
                raise _Abandoned
            if committing:
                self._committing.add(job_id)


class _Abandoned(Exception):
    """Shutdown gave up on this job: its result must not be written."""


def _discard(connection: Connection) -> None:
    """Really close a connection (never return it to the pool: it may carry an advisory lock)."""
    for step in (connection.invalidate, connection.close):
        try:
            step()
        except Exception:  # noqa: BLE001, S110 - best effort; the server drops dead sessions
            pass


# --- process entry point ------------------------------------------------------------------------


class _JSONFormatter(logging.Formatter):
    _FIELDS = ("worker_id", "job_id", "job_type", "status", "running", "duration_ms", "error_class")

    def format(self, record: logging.LogRecord) -> str:
        fields: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for name in self._FIELDS:
            if hasattr(record, name):
                fields[name] = getattr(record, name)
        return json.dumps(fields)


def _configure_logging() -> None:
    logger = logging.getLogger("app")
    if not any(getattr(handler, "_cert_dashboard_worker", False) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler._cert_dashboard_worker = True  # type: ignore[attr-defined]
        handler.addFilter(SecretRedactionFilter())
        handler.setFormatter(_JSONFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    # SQL echo can include row data; only warnings and worse leave the process.
    logging.getLogger("sqlalchemy.engine.Engine").setLevel(logging.WARNING)


def run_worker(settings: Settings, registry: JobRegistry) -> None:
    """Wipe the key staging directory, then run until SIGTERM/SIGINT and shut down gracefully."""
    wipe_key_staging(settings.key_staging_dir)  # before any other work: refuse unsafe state early
    factory = create_session_factory(settings)
    engine: Engine = factory.kw["bind"]
    engine.hide_parameters = True
    runtime = Worker(settings, registry, factory)
    previous: dict[int, object] = {}
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, lambda _signum, _frame: runtime.request_stop())
    try:
        assert_database_ready(engine)
        record_worker_start(factory, settings, runtime.worker_id, runtime.clock())
        runtime.run()
    finally:
        runtime.close()
        engine.dispose()
        for signum, handler in previous.items():
            signal.signal(signum, handler)  # type: ignore[arg-type]


def main() -> int:
    """Process exit code: 0 clean stop, 1 unsafe key staging directory, 2 configuration error."""
    _configure_logging()
    from app.jobs.handlers import build_registry  # late: handlers import this module

    try:
        settings = load_settings("worker", os.environ, Path("/run/secrets"))
        run_worker(settings, build_registry())
    except ConfigurationError as exc:
        _LOG.error("worker refused to start: %s", exc)
        return 2
    except KeyStagingError as exc:
        _LOG.error("worker refused to start: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    # ``python -m`` runs this file as ``__main__``; hand over to the canonical module so that the
    # registry, schedule table and timeout callbacks are the single copy handlers also import.
    from app.jobs.worker import main as _main

    raise SystemExit(_main())
