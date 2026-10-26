"""Worker handler for ``scan/default``: observe active endpoints and persist one result each.

Endpoint outcomes are observations, not job failures. Targets are resolved into plain values and
the session is closed *before* any network I/O; every observation is then committed in its own
short transaction so partial work survives a crash. Only if some endpoint is still unreachable
and attempts remain does the job fail (retryable), so the queue's backoff rescans just those.
"""

from collections import Counter
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.jobs.queue import SYSTEM_ACTOR, JobFailure
from app.jobs.worker import JobContext
from app.models import Job, JSONValue, User
from app.models.enums import ScanStatus
from app.services.audit import Actor, record
from app.services.scans import (
    ScanTarget,
    observe_endpoint,
    record_scan,
    scan_targets,
    validate_scan_payload,
)
from app.services.settings import get_setting

__all__ = ["SCAN_CONCURRENCY", "scan_endpoints", "validate_scan_payload"]

SCAN_CONCURRENCY = 20
_DEFAULT_TIMEOUT_SECONDS = 10


def _timeout_seconds(value: JSONValue) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 60:
        return _DEFAULT_TIMEOUT_SECONDS
    return value


def scan_endpoints(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
    with context.factory.begin() as db:
        job = db.get(Job, context.job_id)
        if job is None:  # pragma: no cover - the worker claimed this row
            raise JobFailure("internal", "job not found")
        attempt, max_attempts = job.attempt, job.max_attempts
        source = "scheduled" if job.requested_by is None else "manual"
        timeout = _timeout_seconds(get_setting(db, "scan.timeout_seconds"))
        targets, skipped_inactive = scan_targets(db, payload, only_unreachable=attempt > 1)
    # The session is closed: nothing below holds a connection or a lock while sockets are open.

    counts: Counter[ScanStatus] = Counter()

    def observe(target: ScanTarget):
        return observe_endpoint(target.host, target.port, target.sni, timeout)

    if targets:
        with ThreadPoolExecutor(max_workers=min(SCAN_CONCURRENCY, len(targets))) as pool:
            futures = {pool.submit(observe, target): target for target in targets}
            for future in as_completed(futures):
                observation = future.result()
                with context.factory.begin() as db:
                    result = record_scan(db, futures[future].endpoint_id, observation, source, context.clock())
                    counts[result.status] += 1

    result_counts: dict[str, JSONValue] = {
        "scanned": len(targets),
        "ok": counts[ScanStatus.OK],
        "mismatch": counts[ScanStatus.MISMATCH],
        "expired": counts[ScanStatus.EXPIRED],
        "unreachable": counts[ScanStatus.UNREACHABLE],
        "error": counts[ScanStatus.ERROR],
        "skipped_inactive": skipped_inactive,
    }
    with context.factory.begin() as db:
        job = db.get(Job, context.job_id)
        user = db.get(User, job.requested_by) if job is not None and job.requested_by is not None else None
        actor = Actor(user.id, user.username) if user is not None else SYSTEM_ACTOR
        record(
            db,
            actor,
            "scan.run",
            "job",
            str(context.job_id),
            {"source": source, "attempt": attempt, **result_counts},
        )
    unreachable = counts[ScanStatus.UNREACHABLE]
    if unreachable and attempt < max_attempts:
        raise JobFailure(
            "transient_network",
            f"{unreachable} of {len(targets)} endpoints unreachable; retrying them",
            retryable=True,
        )
    return result_counts
