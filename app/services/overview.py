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
from app.models.enums import JobType, NotificationStatus, RenewalState
from app.services.digest import _inventory_revision  # same Plan 3 result keys as the digest
from app.services.scans import format_hostport

RECENT_JOBS = 10
IN_FLIGHT = (
    RenewalState.DRAFT,
    RenewalState.CSR_GENERATED,
    RenewalState.SUBMITTED,
    RenewalState.ISSUED,
    RenewalState.DEPLOYED,
)
_WORD = re.compile(r"[A-Za-z0-9_.-]{1,40}")
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


def _word(value: object) -> str | None:
    return value if isinstance(value, str) and _WORD.fullmatch(value) else None


def job_summary(job_type: JobType, payload: Mapping[str, JSONValue]) -> str:
    """One short line built only from allowlisted payload keys (never raw payload text)."""
    action = payload.get("action", "default")
    if job_type is JobType.SCAN and action == "import_pull":
        host, port = payload.get("host"), _positive_int(payload.get("port"))
        if not isinstance(host, str) or not _HOST.fullmatch(host):
            return "pull"
        return f"pull {format_hostport(host, port)}" if port else f"pull {host}"
    if job_type is JobType.SCAN and action == "default":
        ids = payload.get("endpoint_ids")
        if isinstance(ids, list) and ids:
            return f"{len(ids)} endpoint{'' if len(ids) == 1 else 's'}"
    parts = []
    if certificate_id := _positive_int(payload.get("certificate_id")):
        parts.append(f"certificate {certificate_id}")
    if mode := _word(payload.get("mode")):
        parts.append(f"({mode})")
    if reason := _word(payload.get("reason")):
        parts.append(reason)
    if not parts and job_type is JobType.SCAN and action == "default":
        return "all endpoints"
    return " ".join(parts)


def _tls_health(db: Session) -> TLSHealth:
    by_status = {
        status: count
        for status, count in db.execute(
            select(Endpoint.last_scan_status, func.count()).where(Endpoint.is_active).group_by(Endpoint.last_scan_status)
        )
    }
    unknown, key_mismatch = db.execute(
        select(
            func.count(func.distinct(Binding.on_disk_fingerprint)).filter(Binding.match_state == "unknown"),
            func.count().filter(Binding.match_state == "key_mismatch"),
        ).where(Binding.is_active)
    ).one()
    return TLSHealth(  # keys are ScanStatus members (equal to their values) or None for never scanned
        ok=by_status.get("ok", 0), mismatch=by_status.get("mismatch", 0), expired=by_status.get("expired", 0),
        unreachable=by_status.get("unreachable", 0), error=by_status.get("error", 0), never_scanned=by_status.get(None, 0),
        unknown_certificates=unknown, key_mismatch_bindings=key_mismatch,
    )


def _recent_jobs(db: Session) -> list[RecentJob]:
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
        duration = int((row.finished_at - row.started_at).total_seconds()) if row.finished_at and row.started_at else None
        jobs.append(
            RecentJob(
                id=job_id, type=row.type.value, summary=job_summary(row.type, payload), status=row.status.value,
                duration_seconds=duration, actor=row.username or "system", finished_at=row.finished_at,
                href=f"/imports/{job_id}" if pulled else "/audit?" + urlencode({"target_type": "job", "target_id": job_id}),
            )
        )
    return jobs


def _renewals(db: Session, now: datetime) -> list[RenewalInFlight]:
    rows = db.execute(
        select(Renewal.id, Renewal.common_name, Renewal.state, Renewal.state_changed_at)
        .where(Renewal.state.in_(IN_FLIGHT))
        .order_by(Renewal.state_changed_at, Renewal.created_at)
    )
    return [
        RenewalInFlight(str(row.id), row.common_name, row.state.value, max((now - row.state_changed_at).days, 0))
        for row in rows
    ]


def _status(db: Session, now: datetime) -> StatusStrip:
    revision, revision_date = _inventory_revision(db)
    age = max(int((now - revision_date).total_seconds() // 3600), 0) if revision_date else None
    return StatusStrip(
        worker=worker_liveness(db, now),
        last_heartbeat_at=db.scalar(select(func.max(WorkerHeartbeat.last_seen_at))),
        inventory_rev=revision,
        inventory_rev_age_hours=age,
        last_digest_at=db.scalar(
            select(func.max(NotificationLog.sent_at)).where(
                NotificationLog.kind == "digest", NotificationLog.status == NotificationStatus.SENT
            )
        ),
    )


def overview_snapshot(db: Session, now: datetime) -> OverviewSnapshot:
    return OverviewSnapshot(_tls_health(db), _recent_jobs(db), _renewals(db, now), _status(db, now))
