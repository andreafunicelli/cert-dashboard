"""Expiry alert evaluation and message rendering (§7.4); sending and the ledger live elsewhere.

``due_expiry_alerts`` is a read-only evaluation: one query for the active certificates inside the
window ``|not_after − now| ≤ max(thresholds)`` days, anti-joined (``NOT EXISTS``) with the ``sent``
expiry rows for ``(certificate_id, selected T)`` of any day, so the cost depends neither on the
number of certificates nor on unrelated ledger history. Rendering is the only
per-candidate work and runs a handful of small queries for one certificate.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path
from zoneinfo import ZoneInfo

import jinja2
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models import Binding, Certificate, NotificationLog, Renewal, Server
from app.models.enums import CertificateStatus, NotificationStatus, RenewalState
from app.services.settings import get_setting

__all__ = [
    "ExpiryCandidate",
    "RenderedMail",
    "crossed_threshold",
    "due_expiry_alerts",
    "email_environment",
    "expiry_dedupe_key",
    "render_expiry",
    "resolve_recipients",
]

BINDING_LIMIT = 50
SUBJECT_CN_LIMIT = 120
NOTES_LIMIT = 500
_DAY = timedelta(days=1)
_TEMPLATES = Path(__file__).resolve().parents[1] / "templates" / "email"


@dataclass(frozen=True)
class ExpiryCandidate:
    certificate_id: int
    threshold_days: int
    days_remaining: int
    dedupe_key: str
    recipients: tuple[str, ...]


@dataclass(frozen=True)
class RenderedMail:
    subject: str
    text: str
    html: str


def crossed_threshold(not_after: datetime, now: datetime, thresholds: Sequence[int]) -> int | None:
    """The smallest ``T`` with ``not_after − now ≤ T`` days, or ``None`` when none is crossed."""
    remaining = not_after - now
    return min((value for value in thresholds if remaining <= timedelta(days=value)), default=None)


def expiry_dedupe_key(certificate_id: int, threshold_days: int, now: datetime) -> str:
    return f"expiry:{certificate_id}:{threshold_days}:{now.astimezone(UTC).date().isoformat()}"


def resolve_recipients(owner_email: str | None, team: Sequence[str]) -> tuple[str, ...]:
    """Owner first, then the team list; case-insensitively deduplicated, blanks dropped."""
    seen: set[str] = set()
    result: list[str] = []
    for address in (owner_email or "", *team):
        address = address.strip()
        if address and address.lower() not in seen:
            seen.add(address.lower())
            result.append(address)
    return tuple(result)


def _days_remaining(not_after: datetime, now: datetime) -> int:
    return (not_after - now) // _DAY


def _int_list(value: object) -> list[int]:
    items = value if isinstance(value, list) else []
    return [item for item in items if isinstance(item, int) and not isinstance(item, bool)]


def due_expiry_alerts(db: Session, now: datetime) -> list[ExpiryCandidate]:
    thresholds = _int_list(get_setting(db, "alert.thresholds_days"))
    if not thresholds:
        return []
    team = _list_of_text(get_setting(db, "alert.recipients"))
    window = timedelta(days=max(thresholds))
    # Smallest crossed threshold per certificate, decided in SQL so the sent-row anti-join can
    # match the selected ``T`` (``not_after − now ≤ T`` days; ascending order = smallest wins).
    selected = case(
        *[(Certificate.not_after <= now + timedelta(days=value), value) for value in sorted(set(thresholds))]
    )
    already_sent = (
        select(1)
        .where(
            NotificationLog.certificate_id == Certificate.id,
            NotificationLog.kind == "expiry",
            NotificationLog.status == NotificationStatus.SENT,
            NotificationLog.threshold_days == selected,
        )
        .exists()
    )
    due = db.execute(
        select(
            Certificate.id, Certificate.not_after, Certificate.owner_email, selected.label("threshold_days")
        )
        .where(
            Certificate.status == CertificateStatus.ACTIVE,
            Certificate.not_after >= now - window,
            Certificate.not_after <= now + window,
            ~already_sent,
        )
        .order_by(Certificate.not_after, Certificate.id)
    ).all()
    return [
        ExpiryCandidate(
            certificate_id=row.id,
            threshold_days=row.threshold_days,
            days_remaining=_days_remaining(row.not_after, now),
            dedupe_key=expiry_dedupe_key(row.id, row.threshold_days, now),
            recipients=resolve_recipients(row.owner_email, team),
        )
        for row in due
    ]


def _list_of_text(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


@cache
def email_environment() -> jinja2.Environment:
    """Dedicated e-mail environment: ``*.html.j2`` is autoescaped, ``*.txt.j2`` is not."""
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(_TEMPLATES)),
        autoescape=jinja2.select_autoescape(enabled_extensions=("html.j2",), default=False),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
    )


def _display_zone(db: Session) -> ZoneInfo:
    """``ui.timezone`` when it names a known zone, else UTC (same rule as the web display)."""
    value = get_setting(db, "ui.timezone")
    if isinstance(value, str) and value:
        try:
            return ZoneInfo(value)
        except (KeyError, ValueError, OSError):
            pass
    return ZoneInfo("UTC")


def _expiry_phrase(days: int) -> str:
    if days < 0:
        return "has expired"
    if days == 0:
        return "expires in less than 1 day"
    return f"expires in {days} day{'s' if days != 1 else ''}"


def _plain(value: str, limit: int) -> str:
    return " ".join(value.split())[:limit]


def render_expiry(db: Session, candidate: ExpiryCandidate, now: datetime, base_url: str | None) -> RenderedMail:
    cert = db.get(Certificate, candidate.certificate_id)
    if cert is None:
        raise LookupError("certificate no longer exists")
    zone = _display_zone(db)
    local = cert.not_after.astimezone(zone)
    utc = cert.not_after.astimezone(UTC)
    days = _days_remaining(cert.not_after, now)
    phrase = _expiry_phrase(days)

    where = (Binding.certificate_id == cert.id, Binding.is_active.is_(True))
    total_bindings = db.scalar(select(func.count()).select_from(Binding).where(*where)) or 0
    bindings = [
        f"{host} {vhost}:{port}"
        for host, vhost, port in db.execute(
            select(Server.hostname, Binding.vhost_name, Binding.port)
            .join(Server, Server.id == Binding.server_id)
            .where(*where)
            .order_by(Server.hostname, Binding.vhost_name, Binding.port)
            .limit(BINDING_LIMIT)
        ).tuples()
    ]
    renewal = db.execute(
        select(Renewal.id, Renewal.state)
        .where(Renewal.previous_certificate_id == cert.id, Renewal.state != RenewalState.CANCELLED)
        .order_by(Renewal.created_at.desc(), Renewal.state_changed_at.desc())
        .limit(1)
    ).first()

    prefix = (base_url or "").rstrip("/")
    context = {
        "common_name": cert.common_name,
        "san_count": len(cert.sans),
        "issuer": cert.issuer_cn,
        "serial": cert.serial,
        "not_after_local": local.strftime("%Y-%m-%d %H:%M %Z"),
        "not_after_utc": utc.strftime("%Y-%m-%d %H:%M UTC"),
        "same_zone": local.tzname() == "UTC",
        "phrase": phrase,
        "bindings": bindings,
        "more_bindings": max(total_bindings - len(bindings), 0),
        "renewal_state": renewal.state.value if renewal else None,
        "renewal_url": f"{prefix}/renewals/{renewal.id}" if renewal else None,
        "certificate_url": f"{prefix}/certificates/{cert.id}",
        "notes": (cert.notes or "")[:NOTES_LIMIT] or None,
    }
    env = email_environment()
    subject = f"Certificate {_plain(cert.common_name, SUBJECT_CN_LIMIT)} {phrase}"
    return RenderedMail(
        subject=subject,
        text=env.get_template("expiry.txt.j2").render(context),
        html=env.get_template("expiry.html.j2").render(context),
    )
