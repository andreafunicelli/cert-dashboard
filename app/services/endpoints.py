"""Read models for the Scan results screen (spec 4.9, 8.8): latest result per endpoint, history, export.

Every query joins what it shows (server, expected certificate, latest scan result) so the row count
never changes the statement count; nothing here writes.
"""

from dataclasses import dataclass, fields
from datetime import UTC, datetime

from sqlalchemy import Text, any_, case, func, literal, select, true
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Binding, Certificate, Endpoint, JSONValue, ScanResult, Server
from app.models.enums import CertificateStatus, EndpointSource, ScanStatus
from app.services.audit import Actor, record
from app.services.bindings import verify_sni
from app.services.scans import EndpointInputError, validate_endpoint_target

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
    observed_certificate_active: bool = False  # ... and whether it can be expected (status active)


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
        observed = db.execute(
            select(Certificate.id, Certificate.status).where(Certificate.sha256_fingerprint == row.observed_fingerprint.lower())
        ).first()
    if observed is None:
        return EndpointDetail(row, history, None)
    return EndpointDetail(row, history, observed.id, observed.status == CertificateStatus.ACTIVE)


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


def certificate_choices(db: Session, limit: int = 500) -> list[tuple[int, str, datetime]]:
    """``(id, common name, expiry)`` of the active certificates an endpoint may expect."""
    rows = db.execute(
        select(Certificate.id, Certificate.common_name, Certificate.not_after)
        .where(Certificate.status == CertificateStatus.ACTIVE)
        .order_by(Certificate.common_name, Certificate.id)
        .limit(limit)
    )
    return [(row.id, row.common_name, row.not_after) for row in rows]


# --- management (spec 4.9 manual source, 4.16 audit; Plan 2 Contract decision 16) -----------------
# Every function stages the change and its audit row on the caller's session; the caller commits.
# Nothing here touches ``scan_result``: past expected-certificate snapshots stay as they were.

NOT_ACTIVE = "Choose an active certificate from the inventory."


class DuplicateEndpoint(EndpointInputError):
    """The host, port and (coalesced) SNI already identify ``existing_id``."""

    def __init__(self, existing_id: int | None) -> None:
        super().__init__({"host": "An endpoint with this host, port and SNI already exists."})
        self.existing_id = existing_id


class ObservedNotInInventory(EndpointInputError):
    """The served fingerprint matches no inventory row, so importing it is the only remedy."""


def _active_certificate(db: Session, certificate_id: int | None, field: str = "certificate_id") -> Certificate:
    certificate = db.get(Certificate, certificate_id) if certificate_id is not None else None
    if certificate is None or certificate.status != CertificateStatus.ACTIVE:
        raise EndpointInputError({field: NOT_ACTIVE})
    return certificate


def _locked(db: Session, endpoint_id: int) -> Endpoint:
    endpoint = db.get(Endpoint, endpoint_id, with_for_update=True)
    if endpoint is None:
        raise EndpointNotFound(endpoint_id)
    return endpoint


def _change(db: Session, endpoint: Endpoint, field: str, value: int | bool, actor: Actor) -> None:
    previous = getattr(endpoint, field)
    if previous == value:
        return  # nothing changes, nothing to audit
    setattr(endpoint, field, value)
    record(db, actor, "endpoint.update", "endpoint", str(endpoint.id), {"field": field, "from": previous, "to": value})


def create_endpoint(
    db: Session, host: str, port: int, sni: str | None, expected_certificate_id: int | None, actor: Actor
) -> Endpoint:
    """Add a manual, active endpoint; the unique identity index decides duplicates, even under concurrency."""
    host, port, sni = validate_endpoint_target(host, port, sni)
    if expected_certificate_id is not None:
        _active_certificate(db, expected_certificate_id, "expected_certificate_id")
    endpoint = Endpoint(
        host=host,
        port=port,
        sni=sni,
        source=EndpointSource.MANUAL,
        expected_certificate_id=expected_certificate_id,
        is_active=True,
    )
    try:
        with db.begin_nested():
            db.add(endpoint)
            db.flush()
    except IntegrityError:
        existing = db.scalar(
            select(Endpoint.id).where(
                Endpoint.host == host, Endpoint.port == port, func.coalesce(Endpoint.sni, Endpoint.host) == (sni or host)
            )
        )
        if existing is None:
            raise
        raise DuplicateEndpoint(existing) from None
    created: dict[str, JSONValue] = {"host": host, "port": port, "sni": sni, "expected_certificate_id": expected_certificate_id}
    record(db, actor, "endpoint.create", "endpoint", str(endpoint.id), {"field": "endpoint", "from": None, "to": created})
    return endpoint


def set_expectation(db: Session, endpoint_id: int, certificate_id: int, actor: Actor) -> Endpoint:
    """Expect an active inventory certificate from now on (``scan_result`` snapshots are untouched)."""
    endpoint = _locked(db, endpoint_id)
    _change(db, endpoint, "expected_certificate_id", _active_certificate(db, certificate_id).id, actor)
    return endpoint


def expect_observed(db: Session, endpoint_id: int, actor: Actor) -> Endpoint:
    """Expect the certificate the newest scan served, when its fingerprint is an active inventory row.

    Never creates a certificate: an unknown fingerprint has to be imported first (observed is not trusted).
    """
    endpoint = _locked(db, endpoint_id)
    fingerprint = db.scalar(
        select(ScanResult.observed_fingerprint)
        .where(ScanResult.endpoint_id == endpoint_id)
        .order_by(ScanResult.checked_at.desc(), ScanResult.id.desc())
        .limit(1)
    )
    if fingerprint is None:
        raise EndpointInputError({"certificate_id": "No certificate has been observed for this endpoint yet; scan it first."})
    certificate = db.scalar(select(Certificate).where(Certificate.sha256_fingerprint == fingerprint.lower()))
    if certificate is None:
        raise ObservedNotInInventory({"certificate_id": "The observed certificate is not in the inventory; import it first."})
    if certificate.status != CertificateStatus.ACTIVE:
        raise EndpointInputError(
            {"certificate_id": "The observed certificate is in the inventory but is not active (revoked or superseded)."}
        )
    _change(db, endpoint, "expected_certificate_id", certificate.id, actor)
    return endpoint


def set_endpoint_active(db: Session, endpoint_id: int, active: bool, actor: Actor) -> Endpoint:
    """Switch scheduled scanning on or off; endpoints and their history are never deleted."""
    endpoint = _locked(db, endpoint_id)
    _change(db, endpoint, "is_active", active, actor)
    return endpoint


# --- binding-derived endpoints (spec 4.9, Plan 3 Contract decision 11) -----------------------------
# Called by discovery reconciliation inside its per-server transaction: stage and audit, never commit.


def _derived_identity(server: Server, binding: Binding) -> tuple[str, int, str | None]:
    """Canonical ``(host, port, sni)`` of the endpoint a binding derives: the address the worker reaches."""
    host = server.connection_address or server.hostname
    sni = verify_sni(binding.vhost_name, binding.vhost_names)
    try:
        return validate_endpoint_target(host, binding.port, sni)
    except EndpointInputError as error:
        if sni is not None and set(error.errors) == {"sni"}:
            return validate_endpoint_target(host, binding.port, None)  # a name the SNI rules refuse: probe by host
        raise


def _by_identity(db: Session, host: str, port: int, sni: str | None) -> Endpoint | None:
    return db.scalar(
        select(Endpoint)
        .where(Endpoint.host == host, Endpoint.port == port, func.coalesce(Endpoint.sni, Endpoint.host) == (sni or host))
        .with_for_update()
    )


def _discovery_change(
    db: Session, endpoint: Endpoint, field: str, previous: int | bool | None, value: int | bool, actor: Actor
) -> None:
    details: dict[str, JSONValue] = {"field": field, "from": previous, "to": value, "source": "discovery"}
    record(db, actor, "endpoint.update", "endpoint", str(endpoint.id), details)


def _link(db: Session, endpoint: Endpoint, binding: Binding, actor: Actor) -> None:
    previous = endpoint.binding_id
    endpoint.binding_id = binding.id
    endpoint.server_id = binding.server_id
    _discovery_change(db, endpoint, "binding_id", previous, binding.id, actor)


def ensure_binding_endpoint(db: Session, binding: Binding, server: Server, actor: Actor) -> tuple[Endpoint, bool]:
    """The endpoint of a binding's ``vhost_name:port`` and whether this call created it.

    Bindings resolving to one identity share one endpoint, linked to the lowest active binding id. An existing
    unlinked (manual) endpoint is adopted with its source kept; a link to an inactive or higher-id binding moves.
    A new endpoint expects the binding's certificate when it is ``matched``. Raises ``EndpointInputError`` when
    the host or port cannot be an endpoint.
    """
    host, port, sni = _derived_identity(server, binding)
    existing = _by_identity(db, host, port, sni)
    if existing is not None:
        owner = db.get(Binding, existing.binding_id) if existing.binding_id is not None else None
        if owner is None or (owner.id != binding.id and (not owner.is_active or owner.id > binding.id)):
            _link(db, existing, binding, actor)
        return existing, False
    endpoint = Endpoint(
        host=host,
        port=port,
        sni=sni,
        source=EndpointSource.DISCOVERY,
        server_id=server.id,
        binding_id=binding.id,
        expected_certificate_id=binding.certificate_id if binding.match_state == "matched" else None,
        is_active=True,
    )
    try:
        with db.begin_nested():
            db.add(endpoint)
            db.flush()
    except IntegrityError:
        racer = _by_identity(db, host, port, sni)
        if racer is None:
            raise
        return racer, False
    created: dict[str, JSONValue] = {
        "host": host,
        "port": port,
        "sni": sni,
        "expected_certificate_id": endpoint.expected_certificate_id,
    }
    details: dict[str, JSONValue] = {
        "field": "endpoint",
        "from": None,
        "to": created,
        "source": "discovery",
        "binding_id": binding.id,
    }
    record(db, actor, "endpoint.create", "endpoint", str(endpoint.id), details)
    return endpoint, True


def expect_for_binding(db: Session, binding_id: int, certificate_id: int, actor: Actor) -> int:
    """Make the endpoints owned by a binding expect its certificate; the number of endpoints changed."""
    owned = db.scalars(
        select(Endpoint)
        .where(Endpoint.binding_id == binding_id, Endpoint.expected_certificate_id.is_distinct_from(certificate_id))
        .order_by(Endpoint.id)
        .with_for_update()
    ).all()
    for endpoint in owned:
        _discovery_change(db, endpoint, "expected_certificate_id", endpoint.expected_certificate_id, certificate_id, actor)
        endpoint.expected_certificate_id = certificate_id
    return len(owned)


def reactivate_binding_endpoints(db: Session, binding_id: int, actor: Actor) -> int:
    """Scan again the endpoints a re-appearing binding owns (an operator's pause on a live binding is kept)."""
    stopped = db.scalars(
        select(Endpoint).where(Endpoint.binding_id == binding_id, Endpoint.is_active.is_(False)).order_by(Endpoint.id).with_for_update()
    ).all()
    for endpoint in stopped:
        endpoint.is_active = True
        _discovery_change(db, endpoint, "is_active", False, True, actor)
    return len(stopped)


def _derives(server: Server, binding: Binding, endpoint: Endpoint) -> bool:
    try:
        host, port, sni = _derived_identity(server, binding)
    except EndpointInputError:
        return False
    return (host, port, sni or host) == (endpoint.host, endpoint.port, endpoint.sni or endpoint.host)


def deactivate_binding_endpoints(db: Session, binding_id: int, actor: Actor) -> int:
    """Deactivate the active endpoints a binding owns, except those another active binding still derives.

    A shared endpoint moves to the lowest such binding instead. Returns the number deactivated; nothing is deleted.
    """
    binding = db.get(Binding, binding_id)
    if binding is None:
        return 0
    owned = db.scalars(
        select(Endpoint)
        .where(Endpoint.binding_id == binding_id, Endpoint.is_active.is_(True))
        .order_by(Endpoint.id)
        .with_for_update()
    ).all()
    if not owned:
        return 0
    server = db.get(Server, binding.server_id)
    siblings = db.scalars(
        select(Binding)
        .where(Binding.server_id == binding.server_id, Binding.is_active.is_(True), Binding.id != binding_id)
        .order_by(Binding.id)
    ).all()
    deactivated = 0
    for endpoint in owned:
        heir = next((item for item in siblings if server is not None and _derives(server, item, endpoint)), None)
        if heir is not None:
            _link(db, endpoint, heir, actor)
            continue
        endpoint.is_active = False
        _discovery_change(db, endpoint, "is_active", True, False, actor)
        deactivated += 1
    return deactivated
