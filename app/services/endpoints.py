"""Read models for the Scan results screen (spec 4.9, 8.8): latest result per endpoint, history, export.

Every query joins what it shows (server, expected certificate, latest scan result) so the row count
never changes the statement count; nothing here writes.
"""

from dataclasses import dataclass, fields
from datetime import UTC, datetime

from sqlalchemy import Text, any_, case, func, literal, select, true
from sqlalchemy.orm import Session

from app.models import Certificate, Endpoint, JSONValue, ScanResult, Server
from app.models.enums import ScanStatus

EXPORT_LIMIT = 5000

# The newest result per endpoint: one index-ordered probe of ix_scan_result_endpoint_checked per row.
_latest = (
    select(
        ScanResult.status,
        ScanResult.checked_at,
        ScanResult.observed_fingerprint,
        ScanResult.observed_common_name,
        ScanResult.observed_issuer_cn,
        ScanResult.observed_not_after,
        ScanResult.observed_chain_length,
        ScanResult.tls_version,
        ScanResult.error,
    )
    .where(ScanResult.endpoint_id == Endpoint.id)
    .order_by(ScanResult.checked_at.desc(), ScanResult.id.desc())
    .limit(1)
    .lateral("latest")
)
_columns = (
    Endpoint.id,
    Endpoint.host,
    Endpoint.port,
    Endpoint.sni,
    Endpoint.source,
    Endpoint.is_active,
    Server.hostname.label("server"),
    Endpoint.expected_certificate_id,
    Certificate.common_name.label("expected_common_name"),
    Certificate.sha256_fingerprint.label("expected_fingerprint"),
    _latest.c.status,
    _latest.c.checked_at,
    _latest.c.observed_fingerprint,
    _latest.c.observed_common_name,
    _latest.c.observed_issuer_cn,
    _latest.c.observed_not_after,
    _latest.c.observed_chain_length,
    _latest.c.tls_version,
    _latest.c.error,
)
# §7.3: expired outranks mismatch; failures next; never scanned (no result) before healthy rows.
_attention = case(
    (_latest.c.status == ScanStatus.EXPIRED, 0),
    (_latest.c.status == ScanStatus.MISMATCH, 1),
    (_latest.c.status == ScanStatus.UNREACHABLE, 2),
    (_latest.c.status == ScanStatus.ERROR, 3),
    (_latest.c.status == ScanStatus.OK, 5),
    else_=4,
)
SORTS = {
    "status": (_attention, Endpoint.host, Endpoint.port),
    "host": (Endpoint.host, Endpoint.port),
    "-host": (Endpoint.host.desc(), Endpoint.port.desc()),
    "port": (Endpoint.port, Endpoint.host),
    "server": (Server.hostname.asc().nulls_last(), Endpoint.host),
    "expected": (Certificate.common_name.asc().nulls_last(), Endpoint.host),
    "checked_at": (_latest.c.checked_at.asc().nulls_first(), Endpoint.host),
    "-checked_at": (_latest.c.checked_at.desc().nulls_last(), Endpoint.host),
}


class EndpointNotFound(LookupError):
    """No endpoint has this id."""


@dataclass(frozen=True)
class EndpointFilters:
    status: ScanStatus | None = None
    server_id: int | None = None
    certificate_id: int | None = None
    group: str | None = None
    search: str | None = None
    active: bool | None = True  # None: active and inactive endpoints


@dataclass(frozen=True)
class EndpointRow:
    id: int
    host: str
    port: int
    sni: str | None
    source: str
    is_active: bool
    server: str | None
    expected_certificate_id: int | None
    expected_common_name: str | None
    expected_fingerprint: str | None
    status: str | None
    checked_at: datetime | None
    observed_fingerprint: str | None
    observed_common_name: str | None
    observed_issuer_cn: str | None
    observed_not_after: datetime | None
    observed_chain_length: int | None
    tls_version: str | None
    error: str | None


ENDPOINT_EXPORT_FIELDS = tuple(field.name for field in fields(EndpointRow))


@dataclass(frozen=True)
class EndpointPage:
    items: list[EndpointRow]
    total: int
    page: int
    page_size: int


@dataclass(frozen=True)
class EndpointDetail:
    row: EndpointRow
    history: list[ScanResult]
    observed_certificate_id: int | None  # the inventory certificate whose fingerprint was served, if any


def _query(filters: EndpointFilters):
    query = (
        select(*_columns)
        .select_from(Endpoint)
        .outerjoin(Server, Server.id == Endpoint.server_id)
        .outerjoin(Certificate, Certificate.id == Endpoint.expected_certificate_id)
        .outerjoin(_latest, true())
    )
    if filters.status is not None:
        query = query.where(_latest.c.status == filters.status)
    if filters.server_id is not None:
        query = query.where(Endpoint.server_id == filters.server_id)
    if filters.certificate_id is not None:
        query = query.where(Endpoint.expected_certificate_id == filters.certificate_id)
    if filters.group:
        query = query.where(literal(filters.group, Text) == any_(Server.ansible_groups))
    if filters.search:
        query = query.where(
            Endpoint.host.icontains(filters.search, autoescape=True)
            | Endpoint.sni.icontains(filters.search, autoescape=True)
        )
    if filters.active is not None:
        query = query.where(Endpoint.is_active.is_(filters.active))
    return query


def _row(mapping) -> EndpointRow:
    values = dict(mapping)
    values["source"] = values["source"].value
    values["status"] = values["status"].value if values["status"] is not None else None
    return EndpointRow(**values)


def _ordered(filters: EndpointFilters, sort: str):
    if sort not in SORTS:
        raise ValueError("unsupported sort")
    return _query(filters).order_by(*SORTS[sort], Endpoint.id)


def list_endpoints(
    db: Session, filters: EndpointFilters, page: int = 1, page_size: int = 50, sort: str = "status"
) -> EndpointPage:
    """One page of endpoints with their latest result; two statements whatever the page holds."""
    if page < 1 or page_size < 1:
        raise ValueError("page and page_size must be positive")
    total = db.scalar(select(func.count()).select_from(_query(filters).subquery())) or 0
    rows = db.execute(_ordered(filters, sort).limit(page_size).offset((page - 1) * page_size)).mappings()
    return EndpointPage([_row(row) for row in rows], total, page, page_size)


def endpoint_detail(db: Session, endpoint_id: int, history_limit: int = 20) -> EndpointDetail:
    found = db.execute(_query(EndpointFilters(active=None)).where(Endpoint.id == endpoint_id)).mappings().first()
    if found is None:
        raise EndpointNotFound(endpoint_id)
    row = _row(found)
    history = list(
        db.scalars(
            select(ScanResult)
            .where(ScanResult.endpoint_id == endpoint_id)
            .order_by(ScanResult.checked_at.desc(), ScanResult.id.desc())
            .limit(history_limit)
        )
    )
    observed = None
    if row.observed_fingerprint is not None:
        observed = db.scalar(
            select(Certificate.id).where(Certificate.sha256_fingerprint == row.observed_fingerprint.lower())
        )
    return EndpointDetail(row, history, observed)


def _json(value: object) -> JSONValue:
    if isinstance(value, datetime):
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value  # type: ignore[return-value]  # the remaining row fields are already JSON scalars


def export_endpoints(db: Session, filters: EndpointFilters, limit: int = EXPORT_LIMIT) -> list[dict[str, JSONValue]]:
    """The allowlisted fields (``ENDPOINT_EXPORT_FIELDS``) of at most ``limit`` endpoints in default order."""
    rows = db.execute(_ordered(filters, "status").limit(limit)).mappings()
    return [{name: _json(getattr(item, name)) for name in ENDPOINT_EXPORT_FIELDS} for item in map(_row, rows)]


def server_choices(db: Session, limit: int = 500) -> list[tuple[int, str]]:
    """``(id, hostname)`` pairs for the list's server filter."""
    return [(row.id, row.hostname) for row in db.execute(select(Server.id, Server.hostname).order_by(Server.hostname).limit(limit))]
