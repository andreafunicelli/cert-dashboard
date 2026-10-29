"""Overview read models (spec §8.2): TLS health, recent jobs, renewals in flight and the status strip.

Every slot is one aggregate or one bounded query, so the page costs the same statements for any row count.
Job payloads are caller-supplied JSON: only a closed allowlist of keys is ever summarised, and each value
must match a strict pattern, so raw payload text (``notes`` and the like) can never reach the page.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlencode

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.jobs.worker import worker_liveness
from app.models import Binding, Endpoint, Job, JSONValue, NotificationLog, Renewal, User, WorkerHeartbeat
from app.models.enums import JobType, NotificationStatus, RenewalState, ScanStatus
from app.services.digest import (  # same Plan 3 result keys as the digest
    inventory_revision_result,
    parse_inventory_revision,
)
from app.services.scans import format_hostport

RECENT_JOBS = 10
IN_FLIGHT = (
    RenewalState.DRAFT,
    RenewalState.CSR_GENERATED,
    RenewalState.SUBMITTED,
    RenewalState.ISSUED,
    RenewalState.DEPLOYED,
)
_SCAN_COUNTED = (ScanStatus.OK, ScanStatus.MISMATCH, ScanStatus.EXPIRED, ScanStatus.UNREACHABLE, ScanStatus.ERROR)
_CLEANUP_REASONS = frozenset({"scheduled", "manual_prune"})  # validate_cleanup_payload
_EXPIRY_MODES = frozenset({"retry_failed"})  # validate_expiry_payload
_DEPLOY_MODES = frozenset({"dry_run", "canary", "full"})
_HOST = re.compile(r"[A-Za-z0-9._:-]{1,255}")


@dataclass(frozen=True)
class TLSHealth:
    ok: int
    mismatch: int
    expired: int
    unreachable: int
    error: int
    never_scanned: int
    unknown_certificates: int
    key_mismatch_bindings: int


@dataclass(frozen=True)
class RecentJob:
    id: str
    type: str
    summary: str
    status: str
    duration_seconds: int | None
    actor: str
    finished_at: datetime | None
    href: str


@dataclass(frozen=True)
class RenewalInFlight:
    id: str
    common_name: str
    state: str
    age_days: int


@dataclass(frozen=True)
class StatusStrip:
    worker: str
    last_heartbeat_at: datetime | None
    inventory_rev: str | None
    inventory_rev_age_hours: int | None
    last_digest_at: datetime | None


@dataclass(frozen=True)
class OverviewSnapshot:
    tls: TLSHealth
    recent_jobs: list[RecentJob]
    renewals: list[RenewalInFlight]
    status: StatusStrip


def _positive_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _member(value: object, allowed: frozenset[str]) -> str | None:
    """The value itself when it is one of the fixed ``allowed`` strings, else ``None`` (never arbitrary text)."""
    return value if isinstance(value, str) and value in allowed else None


def job_summary(job_type: JobType, payload: Mapping[str, JSONValue]) -> str:
    """One short line from a closed per-job-type allowlist; anything else in the payload contributes nothing."""
    action = payload.get("action", "default")
    if job_type is JobType.SCAN:
        if action == "import_pull":
            host, port = payload.get("host"), _positive_int(payload.get("port"))
            if not isinstance(host, str) or not _HOST.fullmatch(host):
                return "pull"
            return f"pull {format_hostport(host, port)}" if port else f"pull {host}"
        if action != "default":
            return ""
        ids = payload.get("endpoint_ids")
        if isinstance(ids, list) and ids:
            return f"{len(ids)} endpoint{'' if len(ids) == 1 else 's'}"
        certificate_id = _positive_int(payload.get("certificate_id"))
        return f"certificate {certificate_id}" if certificate_id else "all endpoints"
    if job_type is JobType.DEPLOY:  # mode names are fixed here for Plan 3 to extend; unknown ones render nothing
        parts = [f"certificate {cid}"] if (cid := _positive_int(payload.get("certificate_id"))) else []
        if mode := _member(payload.get("mode"), _DEPLOY_MODES):
            parts.append(f"({mode})")
        return " ".join(parts)
    if job_type is JobType.CLEANUP:
        return _member(payload.get("reason"), _CLEANUP_REASONS) or ""
    if job_type is JobType.ALERT_EXPIRY:
        if _member(payload.get("mode"), _EXPIRY_MODES):
            return "retry failed"
        return "SMTP test" if action == "smtp_test" else ""
    return ""  # discover and digest carry no summarisable fields


def tls_health(db: Session) -> TLSHealth:
    """One statement: two single-row aggregates (endpoint scan states, binding states) side by side."""
    scans = select(
        *(func.count().filter(Endpoint.last_scan_status == status).label(status.value) for status in _SCAN_COUNTED),
        func.count().filter(Endpoint.last_scan_status.is_(None)).label("never_scanned"),
    ).where(Endpoint.is_active).subquery()
    bindings = select(
        func.count(func.distinct(Binding.on_disk_fingerprint)).filter(Binding.match_state == "unknown").label("unknown_certificates"),
        func.count().filter(Binding.match_state == "key_mismatch").label("key_mismatch_bindings"),
    ).where(Binding.is_active).subquery()
    return TLSHealth(**db.execute(select(scans, bindings)).one()._asdict())


def recent_jobs(db: Session) -> list[RecentJob]:
    moment = func.coalesce(Job.finished_at, Job.started_at, Job.created_at)
    rows = db.execute(
        select(Job.id, Job.type, Job.status, Job.payload, Job.started_at, Job.finished_at, User.username)
        .outerjoin(User, User.id == Job.requested_by)
        .order_by(moment.desc(), Job.created_at.desc())
        .limit(RECENT_JOBS)
    )
    jobs = []
    for row in rows:
        payload = row.payload if isinstance(row.payload, dict) else {}
        job_id = str(row.id)
        pulled = row.type is JobType.SCAN and payload.get("action") == "import_pull"
        if row.type is JobType.DEPLOY:
            # The deploy job screen is the operator's view of a rollout; the audit entry stays one click away.
            href = f"/deploy/{job_id}"
        elif pulled:
            href = f"/imports/{job_id}"
        else:
            href = "/audit?" + urlencode({"target_type": "job", "target_id": job_id})
        duration = int((row.finished_at - row.started_at).total_seconds()) if row.finished_at and row.started_at else None
        jobs.append(
            RecentJob(
                id=job_id, type=row.type.value, summary=job_summary(row.type, payload), status=row.status.value,
                duration_seconds=duration, actor=row.username or "system", finished_at=row.finished_at,
                href=href,
            )
        )
    return jobs


def renewals_in_flight(db: Session, now: datetime) -> list[RenewalInFlight]:
    rows = db.execute(
        select(Renewal.id, Renewal.common_name, Renewal.state, Renewal.state_changed_at)
        .where(Renewal.state.in_(IN_FLIGHT))
        .order_by(Renewal.state_changed_at, Renewal.created_at)
    )
    return [
        RenewalInFlight(str(row.id), row.common_name, row.state.value, max((now - row.state_changed_at).days, 0))
        for row in rows
    ]


def status_strip(db: Session, now: datetime) -> StatusStrip:
    """Two statements: the shared ``worker_liveness`` helper, then one SELECT of heartbeat, digest and revision."""
    heartbeat, digest, result = db.execute(
        select(
            select(func.max(WorkerHeartbeat.last_seen_at)).scalar_subquery(),
            select(func.max(NotificationLog.sent_at))
            .where(NotificationLog.kind == "digest", NotificationLog.status == NotificationStatus.SENT)
            .scalar_subquery(),
            inventory_revision_result().scalar_subquery(),
        )
    ).one()
    revision, revision_date = parse_inventory_revision(result)
    age = max(int((now - revision_date).total_seconds() // 3600), 0) if revision_date else None
    return StatusStrip(
        worker=worker_liveness(db, now), last_heartbeat_at=heartbeat, inventory_rev=revision,
        inventory_rev_age_hours=age, last_digest_at=digest,
    )


def overview_snapshot(db: Session, now: datetime) -> OverviewSnapshot:
    return OverviewSnapshot(tls_health(db), recent_jobs(db), renewals_in_flight(db, now), status_strip(db, now))
