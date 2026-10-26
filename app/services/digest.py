"""Daily digest collection (§7.5): every section is decided against the state at the last digest.

Each list section is one bounded query (``LIMIT`` plus a window ``count(*)`` for the uncapped total).
"New" TLS mismatches and unknown certificates are transitions across the cutoff, so a repeat that
already existed at the last digest is never reported again (Plan 2 Contract decisions 11, 21, 22).
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import Select, and_, func, or_, select, text
from sqlalchemy.orm import Session

from app.models import Certificate, Endpoint, Job, JobHost, JSONValue, NotificationLog, Server
from app.models.enums import CertificateStatus, JobStatus, JobType, NotificationStatus
from app.services.alerts import RenderedMail, email_environment
from app.services.bindings import BINDING_STATE_ACTION

__all__ = [
    "DIGEST_LIST_LIMIT",
    "DigestBinding",
    "DigestCertificate",
    "DigestData",
    "DigestEndpoint",
    "DigestHost",
    "DigestJob",
    "DigestNotification",
    "DigestServer",
    "collect_digest",
    "digest_counts",
    "digest_dedupe_key",
    "digest_since",
    "new_mismatches",
    "new_unknown_bindings",
    "render_digest",
]

DIGEST_LIST_LIMIT = 50
EXPIRING_DAYS = 7
STALE_DISCOVERY = timedelta(hours=48)
RECENT = timedelta(hours=24)
_DAY = timedelta(days=1)


@dataclass(frozen=True)
class DigestCertificate:
    id: int
    common_name: str
    not_after: datetime
    days_remaining: int
    owner: str | None


@dataclass(frozen=True)
class DigestEndpoint:
    id: int
    host: str
    port: int
    sni: str | None
    expected_common_name: str | None
    observed_common_name: str | None
    observed_fingerprint: str | None
    previous_status: str | None
    current_status: str | None
    checked_at: datetime


@dataclass(frozen=True)
class DigestBinding:
    binding_id: int
    server: str
    vhost_name: str
    port: int
    cert_path: str
    on_disk_fingerprint: str | None
    previous_state: str | None
    found_at: datetime


@dataclass(frozen=True)
class DigestServer:
    hostname: str
    last_discovery_status: str | None
    last_discovery_at: datetime | None


@dataclass(frozen=True)
class DigestJob:
    id: str
    type: str
    error_class: str | None
    finished_at: datetime


@dataclass(frozen=True)
class DigestHost:
    job_id: str
    hostname: str
    rolled_back: bool
    rollback_error: str | None
    finished_at: datetime | None


@dataclass(frozen=True)
class DigestNotification:
    kind: str
    certificate_id: int | None
    threshold_days: int | None
    attempts: int
    error: str | None
    last_attempt_at: datetime | None


@dataclass(frozen=True)
class DigestData:
    generated_at: datetime
    since: datetime
    expiring: list[DigestCertificate]
    expired: list[DigestCertificate]
    new_mismatches: list[DigestEndpoint]
    mismatch_count: int
    unknown_certificates: list[DigestBinding]
    stale_servers: list[DigestServer]
    failed_jobs: list[DigestJob]
    rolled_back_hosts: list[DigestHost]
    failed_notifications: list[DigestNotification]
    inventory_rev: str | None
    inventory_rev_date: datetime | None
    totals: dict[str, int]  # uncapped count per list section


def digest_since(db: Session, now: datetime) -> datetime:
    """``sent_at`` of the newest sent digest row, else 24 hours before ``now``."""
    last_sent = db.scalar(
        select(func.max(NotificationLog.sent_at)).where(
            NotificationLog.kind == "digest", NotificationLog.status == NotificationStatus.SENT
        )
    )
    return last_sent if last_sent is not None else now - RECENT


def digest_dedupe_key(now: datetime) -> str:
    return f"digest:{now.astimezone(UTC).date().isoformat()}"


# Latest mismatch per endpoint whose predecessor (full retained history, not only rows after ``since``)
# was not itself a mismatch; filtering before DISTINCT ON keeps the transition row of a run of mismatches.
_NEW_MISMATCHES = text(
    """
    SELECT t.*, count(*) OVER () AS total FROM (
      SELECT DISTINCT ON (r.endpoint_id)
             e.id, e.host, e.port, e.sni, c.common_name AS expected_common_name,
             r.observed_common_name, r.observed_fingerprint, prev.status::text AS previous_status,
             e.last_scan_status::text AS current_status, r.checked_at
        FROM scan_result r
        JOIN endpoint e ON e.id = r.endpoint_id AND e.is_active
        LEFT JOIN certificate c ON c.id = r.expected_certificate_id
        LEFT JOIN LATERAL (
          SELECT p.status FROM scan_result p
           WHERE p.endpoint_id = r.endpoint_id AND p.status IN ('ok', 'mismatch', 'expired')
             AND (p.checked_at, p.id) < (r.checked_at, r.id)
           ORDER BY p.checked_at DESC, p.id DESC LIMIT 1
        ) prev ON true
       WHERE r.status = 'mismatch' AND r.checked_at > :since AND prev.status IS DISTINCT FROM 'mismatch'
       ORDER BY r.endpoint_id, r.checked_at DESC, r.id DESC
    ) t ORDER BY t.checked_at DESC, t.id LIMIT :limit
    """
)

# One group per binding audited after ``since``. Each audit row records its predecessor, so the first
# row's ``from_*`` is the state at the cutoff. The join casts the binding id, never the audit text.
_NEW_UNKNOWN = text(
    """
    SELECT b.id AS binding_id, s.hostname AS server, b.vhost_name, b.port, b.cert_path,
           b.on_disk_fingerprint,
           (array_agg(a.details ORDER BY a.created_at, a.id))[1]->>'from_state' AS previous_state,
           max(a.created_at) FILTER (
             WHERE a.details->>'to_state' = 'unknown'
               AND a.details->>'on_disk_fingerprint' IS NOT DISTINCT FROM b.on_disk_fingerprint::text
           ) AS found_at,
           count(*) OVER () AS total
      FROM audit_log a
      JOIN binding b ON b.id::text = a.target_id
      JOIN server s ON s.id = b.server_id
     WHERE a.action = :action AND a.target_type = 'binding' AND a.created_at > :since
       AND b.is_active AND b.match_state = 'unknown'
     GROUP BY b.id, s.id
    HAVING bool_or(a.details->>'to_state' = 'unknown'
                   AND a.details->>'on_disk_fingerprint' IS NOT DISTINCT FROM b.on_disk_fingerprint::text)
       AND NOT (
         (array_agg(a.details ORDER BY a.created_at, a.id))[1]->>'from_state' IS NOT DISTINCT FROM 'unknown'
         AND (array_agg(a.details ORDER BY a.created_at, a.id))[1]->>'from_fingerprint'
             IS NOT DISTINCT FROM b.on_disk_fingerprint::text
         AND coalesce(((array_agg(a.details ORDER BY a.created_at, a.id))[1]->>'was_active')::boolean, false)
       )
     ORDER BY found_at DESC, b.id LIMIT :limit
    """
)


def new_mismatches(
    db: Session, since: datetime, limit: int = DIGEST_LIST_LIMIT
) -> tuple[list[DigestEndpoint], int]:
    rows = db.execute(_NEW_MISMATCHES, {"since": since, "limit": limit}).mappings().all()
    fields = DigestEndpoint.__dataclass_fields__
    items = [DigestEndpoint(**{name: row[name] for name in fields}) for row in rows]
    return items, rows[0]["total"] if rows else 0


def new_unknown_bindings(
    db: Session, since: datetime, limit: int = DIGEST_LIST_LIMIT
) -> tuple[list[DigestBinding], int]:
    params = {"action": BINDING_STATE_ACTION, "since": since, "limit": limit}
    rows = db.execute(_NEW_UNKNOWN, params).mappings().all()
    fields = DigestBinding.__dataclass_fields__
    items = [DigestBinding(**{name: row[name] for name in fields}) for row in rows]
    return items, rows[0]["total"] if rows else 0


def _page(db: Session, statement: Select, limit: int) -> tuple[list, int]:
    """Run ``statement`` capped at ``limit`` with the uncapped total from one window count."""
    rows = db.execute(statement.add_columns(func.count().over().label("total")).limit(limit)).all()
    return rows, rows[0].total if rows else 0


def _certificates(db: Session, now: datetime, where: list, order: list, limit: int):
    statement = (
        select(
            Certificate.id,
            Certificate.common_name,
            Certificate.not_after,
            func.coalesce(Certificate.owner_name, Certificate.owner_email).label("owner"),
        )
        .where(Certificate.status == CertificateStatus.ACTIVE, *where)
        .order_by(*order, Certificate.id)
    )
    rows, total = _page(db, statement, limit)
    items = [
        DigestCertificate(row.id, row.common_name, row.not_after, (row.not_after - now) // _DAY, row.owner)
        for row in rows
    ]
    return items, total


def _inventory_revision(db: Session) -> tuple[str | None, datetime | None]:
    """Result keys written by Plan 3 on the newest succeeded discover/deploy job (``None`` until then)."""
    result = db.scalar(
        select(Job.result)
        .where(
            Job.status == JobStatus.SUCCEEDED,
            Job.type.in_([JobType.DISCOVER, JobType.DEPLOY]),
            Job.result.has_key("inventory_rev"),
        )
        .order_by(Job.finished_at.desc().nulls_last(), Job.created_at.desc())
        .limit(1)
    )
    if not isinstance(result, dict):
        return None, None
    revision = result.get("inventory_rev")
    stamp = result.get("inventory_rev_date")
    try:
        revision_date = datetime.fromisoformat(stamp) if isinstance(stamp, str) else None
    except ValueError:
        revision_date = None
    if revision_date is not None and revision_date.tzinfo is None:
        revision_date = revision_date.replace(tzinfo=UTC)
    return revision if isinstance(revision, str) else None, revision_date


def collect_digest(db: Session, now: datetime) -> DigestData:
    since = digest_since(db, now)
    recent = now - RECENT
    limit = DIGEST_LIST_LIMIT
    expiring, expiring_total = _certificates(
        db,
        now,
        [Certificate.not_after >= now, Certificate.not_after <= now + timedelta(days=EXPIRING_DAYS)],
        [Certificate.not_after],
        limit,
    )
    expired, expired_total = _certificates(db, now, [Certificate.not_after < now], [Certificate.not_after.desc()], limit)
    mismatches, mismatches_total = new_mismatches(db, since, limit)
    unknown, unknown_total = new_unknown_bindings(db, since, limit)
    mismatch_count = db.scalar(
        select(func.count()).select_from(Endpoint).where(Endpoint.is_active, Endpoint.last_scan_status == "mismatch")
    )

    stale_rows, stale_total = _page(
        db,
        select(Server.hostname, Server.last_discovery_status, Server.last_discovery_at)
        .where(
            Server.is_active,
            or_(
                Server.last_discovery_status.in_(["failed", "unreachable"]),
                Server.last_discovery_at.is_(None),
                Server.last_discovery_at < now - STALE_DISCOVERY,
            ),
        )
        .order_by(Server.hostname),
        limit,
    )
    job_rows, jobs_total = _page(
        db,
        select(Job.id, Job.type, Job.error_class, Job.finished_at)
        .where(Job.status == JobStatus.FAILED, Job.finished_at > recent)
        .order_by(Job.finished_at.desc(), Job.id),
        limit,
    )
    host_rows, hosts_total = _page(
        db,
        select(JobHost.job_id, Server.hostname, JobHost.rolled_back, JobHost.rollback_error, JobHost.finished_at)
        .join(Server, Server.id == JobHost.server_id)
        .where(or_(JobHost.rolled_back, JobHost.rollback_error.is_not(None)), JobHost.finished_at > recent)
        .order_by(JobHost.finished_at.desc(), Server.hostname),
        limit,
    )
    notification_rows, notifications_total = _page(
        db,
        select(
            NotificationLog.kind,
            NotificationLog.certificate_id,
            NotificationLog.threshold_days,
            NotificationLog.attempts,
            NotificationLog.error,
            NotificationLog.last_attempt_at,
        )
        .where(and_(NotificationLog.status == NotificationStatus.FAILED, NotificationLog.last_attempt_at > recent))
        .order_by(NotificationLog.last_attempt_at.desc(), NotificationLog.id),
        limit,
    )
    inventory_rev, inventory_rev_date = _inventory_revision(db)
    return DigestData(
        generated_at=now,
        since=since,
        expiring=expiring,
        expired=expired,
        new_mismatches=mismatches,
        mismatch_count=mismatch_count or 0,
        unknown_certificates=unknown,
        stale_servers=[DigestServer(*row[:3]) for row in stale_rows],
        failed_jobs=[DigestJob(str(row.id), str(row.type), row.error_class, row.finished_at) for row in job_rows],
        rolled_back_hosts=[
            DigestHost(str(row.job_id), row.hostname, row.rolled_back, row.rollback_error, row.finished_at)
            for row in host_rows
        ],
        failed_notifications=[DigestNotification(*row[:6]) for row in notification_rows],
        inventory_rev=inventory_rev,
        inventory_rev_date=inventory_rev_date,
        totals={
            "expiring": expiring_total,
            "expired": expired_total,
            "new_mismatches": mismatches_total,
            "unknown_certificates": unknown_total,
            "stale_servers": stale_total,
            "failed_jobs": jobs_total,
            "rolled_back_hosts": hosts_total,
            "failed_notifications": notifications_total,
        },
    )


def digest_counts(data: DigestData) -> dict[str, JSONValue]:
    """The job result: counts only, never the dedupe key (``digest:`` trips the redactor, Contract decision 11)."""
    totals = data.totals
    return {
        "expiring": totals["expiring"],
        "expired": totals["expired"],
        "new_mismatches": totals["new_mismatches"],
        "mismatches": data.mismatch_count,
        "unknown_certificates": totals["unknown_certificates"],
        "stale_servers": totals["stale_servers"],
        "failed_jobs": totals["failed_jobs"],
        "rolled_back_hosts": totals["rolled_back_hosts"],
        "failed_notifications": totals["failed_notifications"],
    }


def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (KeyError, ValueError, OSError):
        return ZoneInfo("UTC")


def render_digest(data: DigestData, timezone_name: str, base_url: str | None) -> RenderedMail:
    """Text and minimal HTML for the daily digest; only non-empty sections get a heading."""
    zone = _zone(timezone_name)
    prefix = (base_url or "").rstrip("/")

    def when(value: datetime | None) -> str:
        if value is None:
            return "never"
        local = value.astimezone(zone)
        text = local.strftime("%Y-%m-%d %H:%M %Z")
        return text if local.tzname() == "UTC" else f"{text} ({value.astimezone(UTC):%Y-%m-%d %H:%M} UTC)"

    def cert_row(item: DigestCertificate, verb: str) -> dict[str, str | None]:
        owner = f", owner {item.owner}" if item.owner else ""
        link = f"{prefix}/certificates/{item.id}" if prefix else None
        return {"text": f"{item.common_name} - {verb} {when(item.not_after)}{owner}", "url": link}

    def section(title: str, key: str, rows: list, intro: str | None = None) -> dict[str, object]:
        total = data.totals[key]
        return {
            "title": title,
            "intro": intro,
            "rows": [row if isinstance(row, dict) else {"text": row, "url": None} for row in rows],
            "shown": f"showing {len(rows)} of {total}" if total > len(rows) else None,
        }

    sections = []
    if data.expiring:
        rows = [cert_row(item, "expires") for item in data.expiring]
        sections.append(section("Expiring within 7 days", "expiring", rows))
    if data.expired:
        rows = [cert_row(item, "expired") for item in data.expired]
        sections.append(section("Already expired", "expired", rows))
    if data.new_mismatches or data.mismatch_count:
        rows = [
            f"{item.host}:{item.port}{f' (SNI {item.sni})' if item.sni else ''} - expected "
            f"{item.expected_common_name or 'any certificate'}, observed {item.observed_common_name or 'none'}; "
            f"{item.previous_status or 'not scanned'} -> {item.current_status or 'unknown'} at {when(item.checked_at)}"
            for item in data.new_mismatches
        ]
        intro = f"Current mismatches: {data.mismatch_count}"
        sections.append(section("New TLS mismatches", "new_mismatches", rows, intro))
    if data.unknown_certificates:
        rows = [
            f"{item.server} {item.vhost_name}:{item.port} {item.cert_path} "
            f"(was {item.previous_state or 'not bound'}) found {when(item.found_at)}"
            for item in data.unknown_certificates
        ]
        sections.append(section("Unknown certificates found by discovery", "unknown_certificates", rows))
    if data.stale_servers:
        rows = [
            f"{item.hostname} - last discovery {item.last_discovery_status or 'never run'}, "
            f"last attempt {when(item.last_discovery_at)}"
            for item in data.stale_servers
        ]
        sections.append(section("Servers with failed or stale discovery", "stale_servers", rows))
    if data.failed_jobs:
        rows = [
            f"{item.type} job {item.id} failed ({item.error_class or 'unknown error'}) at {when(item.finished_at)}"
            for item in data.failed_jobs
        ]
        sections.append(section("Failed jobs in the last 24 hours", "failed_jobs", rows))
    if data.rolled_back_hosts:
        rows = [
            f"{item.hostname} (job {item.job_id}) - "
            + ("rollback failed, needs manual attention" if item.rollback_error is not None else "rolled back")
            for item in data.rolled_back_hosts
        ]
        sections.append(section("Rolled-back hosts in the last 24 hours", "rolled_back_hosts", rows))
    if data.failed_notifications:
        rows = [
            f"{item.kind} e-mail{f' for certificate {item.certificate_id}' if item.certificate_id else ''}"
            f"{f', {item.threshold_days}-day threshold' if item.threshold_days is not None else ''} - "
            f"{item.attempts} attempt(s): {item.error or 'no error recorded'}"
            for item in data.failed_notifications
        ]
        sections.append(section("Failed notifications in the last 24 hours", "failed_notifications", rows))

    if data.inventory_rev is None:
        revision = "Inventory revision: none recorded"  # until Plan 3 writes ``inventory_rev``
    else:
        age = ""
        if data.inventory_rev_date is not None:
            days = (data.generated_at - data.inventory_rev_date) // timedelta(days=1)
            age = f" ({days} days old)" if days >= 1 else " (less than 1 day old)"
        revision = f"Inventory revision: {data.inventory_rev}{age}"

    context = {
        "since": when(data.since),
        "generated": when(data.generated_at),
        "sections": sections,
        "revision": revision,
        "dashboard_url": prefix or None,
    }
    env = email_environment()
    date = data.generated_at.astimezone(UTC).date().isoformat()
    return RenderedMail(
        subject=f"Cert Dashboard daily digest - {date}",
        text=env.get_template("digest.txt.j2").render(context),
        html=env.get_template("digest.html.j2").render(context),
    )
