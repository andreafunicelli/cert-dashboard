"""Retention cleanup: finished jobs, scan results, dead sessions, login counters, old artifacts.

Never touches ``audit_log``, queued/running/paused jobs, key material, target-host backups or the
key staging directory. Deleting finished jobs is retention's explicit exception to "jobs are
never deleted".
"""

import os
import stat
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, or_, select

from app.jobs.worker import JobContext
from app.models import AppSetting, Job, JobHost, JSONValue, LoginRateLimit, ScanResult, UserSession
from app.models.enums import JobStatus

DEFAULT_RETENTION_DAYS = 90
SCAN_RESULT_RETENTION = timedelta(days=90)
LOGIN_COUNTER_RETENTION = timedelta(days=1)
ARTIFACT_RETENTION = timedelta(days=30)
_REASONS = frozenset({"scheduled", "manual_prune"})
_FINISHED = (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED)


def validate_cleanup_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Accept ``{}`` or ``{"reason": "scheduled" | "manual_prune"}``; nothing else."""
    if not set(payload) <= {"reason"}:
        raise ValueError("unexpected cleanup payload keys")
    if "reason" in payload and (not isinstance(payload["reason"], str) or payload["reason"] not in _REASONS):
        raise ValueError("invalid cleanup reason")
    return dict(payload)


def prune_artifacts(root: Path, cutoff: datetime) -> int:
    """Remove entries under ``root`` last modified before ``cutoff``; return how many were removed.

    The root is resolved once and opened with ``O_NOFOLLOW``; every deeper step is relative to an
    open directory descriptor, so symlinks are neither followed nor removed and nothing outside
    the root can be reached. A directory goes only when it is old *and* ended up empty; the root
    itself is never removed. Entries that cannot be inspected or removed are left in place.
    """
    try:
        fd = os.open(root.resolve(strict=True), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return 0
    try:
        return _prune_dir(fd, cutoff.timestamp())[0]
    finally:
        os.close(fd)


def _prune_dir(dir_fd: int, cutoff: float) -> tuple[int, bool]:
    """Prune the directory open as ``dir_fd``; return (removed count, directory is now empty)."""
    removed = 0
    empty = True
    for name in os.listdir(dir_fd):
        try:
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
                try:
                    count, child_empty = _prune_dir(child_fd, cutoff)
                finally:
                    os.close(child_fd)
                removed += count
                # ``info`` predates the pruning: removing children bumps the directory's mtime.
                if child_empty and info.st_mtime < cutoff:
                    os.rmdir(name, dir_fd=dir_fd)
                    removed += 1
                    continue
            elif stat.S_ISREG(info.st_mode) and info.st_mtime < cutoff:
                os.unlink(name, dir_fd=dir_fd)
                removed += 1
                continue
        except OSError:
            pass
        empty = False
    return removed, empty


def _retention_days(db) -> int:
    value = db.scalar(select(AppSetting.value).where(AppSetting.key == "retention.days"))
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return DEFAULT_RETENTION_DAYS
    return value


def cleanup(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
    now = context.clock()
    with context.factory.begin() as db:
        job_cutoff = now - timedelta(days=_retention_days(db))
        old_jobs = select(Job.id).where(Job.status.in_(_FINISHED), Job.finished_at < job_cutoff)
        job_hosts = db.execute(delete(JobHost).where(JobHost.job_id.in_(old_jobs))).rowcount
        jobs = db.execute(
            delete(Job).where(Job.status.in_(_FINISHED), Job.finished_at < job_cutoff)
        ).rowcount
        scan_results = db.execute(
            delete(ScanResult).where(ScanResult.checked_at < now - SCAN_RESULT_RETENTION)
        ).rowcount
        sessions = db.execute(
            delete(UserSession).where(
                or_(UserSession.expires_at < now, UserSession.revoked_at.is_not(None))
            )
        ).rowcount
        login_counters = db.execute(
            delete(LoginRateLimit).where(LoginRateLimit.window_start < now - LOGIN_COUNTER_RETENTION)
        ).rowcount
    artifacts = prune_artifacts(context.settings.artifacts_root, now - ARTIFACT_RETENTION)
    return {
        "jobs": jobs,
        "job_hosts": job_hosts,
        "scan_results": scan_results,
        "sessions": sessions,
        "login_counters": login_counters,
        "artifacts": artifacts,
    }
