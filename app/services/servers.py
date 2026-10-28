"""Read models for the Servers screens (spec 4.6, 4.7, 8.6): list, export, detail, discovery history.

Counts come from grouped aggregate subqueries joined once, so the statement count does not depend on the
number of rows. Binding counts cover active bindings; "attention" is an active binding whose match state is
``key_mismatch`` or ``missing_file`` (the states that carry the persistent warning badge); the mismatch count is
Plan 2 Contract decision 17 (active endpoints of the server whose latest scan status is ``mismatch``).
Nothing here writes.
"""

from dataclasses import dataclass, fields
from datetime import datetime
from typing import Literal

from sqlalchemy import ARRAY, Text, func, literal, select
from sqlalchemy.orm import Session

from app.models import Binding, Certificate, Endpoint, Job, JobHost, JSONValue, Server
from app.models.enums import JobType, ScanStatus, WebserverType
from app.services.audit import redact

EXPORT_LIMIT = 5000
HISTORY_LIMIT = 20
ATTENTION_STATES = ("key_mismatch", "missing_file")
_ERROR_CHARS = 300
_NOTE_CHARS = 500
_SUMMARY_FILES = 200
_SUMMARY_TEXT_CHARS = 500
UNKNOWN_LIMIT = 10

_bindings = (
    select(
        Binding.server_id,
        func.count().label("total"),
        func.count().filter(Binding.match_state.in_(ATTENTION_STATES)).label("attention"),
    )
    .where(Binding.is_active)
    .group_by(Binding.server_id)
    .subquery("binding_counts")
)
_mismatches = (
    select(Endpoint.server_id, func.count().label("total"))
    .where(Endpoint.is_active, Endpoint.last_scan_status == ScanStatus.MISMATCH)
    .group_by(Endpoint.server_id)
    .subquery("mismatch_counts")
)
_binding_count = func.coalesce(_bindings.c.total, 0)
_mismatch_count = func.coalesce(_mismatches.c.total, 0)
SORTS = {
    "hostname": (Server.hostname,),
    "-hostname": (Server.hostname.desc(),),
    "last_discovery_at": (Server.last_discovery_at.asc().nulls_first(), Server.hostname),
    "-last_discovery_at": (Server.last_discovery_at.desc().nulls_last(), Server.hostname),
    "mismatch_count": (_mismatch_count, Server.hostname),
    "-mismatch_count": (_mismatch_count.desc(), Server.hostname),
    "binding_count": (_binding_count, Server.hostname),
    "-binding_count": (_binding_count.desc(), Server.hostname),
}


class ServerNotFound(LookupError):
    """No server has this id."""


@dataclass(frozen=True)
class ServerFilters:
    search: str | None = None
    group: str | None = None
    active: bool | None = True  # None: active and inactive servers


@dataclass(frozen=True)
class ServerRow:
    id: int
    hostname: str
    display_name: str | None
    groups: tuple[str, ...]
    webserver: str | None
    binding_count: int
    attention_count: int
    last_discovery_at: datetime | None
    last_discovery_status: str | None
    mismatch_count: int
    is_active: bool


SERVER_EXPORT_FIELDS = tuple(field.name for field in fields(ServerRow))


@dataclass(frozen=True)
class ServerPage:
    items: list[ServerRow]
    total: int
    page: int
    page_size: int


@dataclass(frozen=True)
class BindingRow:
    id: int
    server_id: int
    server: str
    webserver: str
    vhost_name: str
    vhost_names: tuple[str, ...]
    port: int
    config_file: str
    cert_path: str
    chain_path: str | None
    key_path: str
    cert_owner: str | None
    cert_group: str | None
    cert_mode: str | None
    key_owner: str | None
    key_group: str | None
    key_mode: str | None
    on_disk_fingerprint: str | None
    on_disk_key_public_sha256: str | None
    certificate_id: int | None
    certificate_common_name: str | None
    match_state: str
    last_seen_at: datetime
    is_active: bool
    notes: str | None = None  # fixed discovery texts (chain diagnostics, missing files); never in the export
    stale: bool = False  # derived (spec 6.3): active, and its server's last discovery did not end ``ok``


# Public metadata only: no free-text notes, no key material (only the key's public hash is stored).
BINDING_EXPORT_FIELDS = (
    "id", "server", "webserver", "vhost_name", "vhost_names", "port", "config_file", "cert_path", "chain_path",
    "key_path", "cert_owner", "cert_group", "cert_mode", "key_owner", "key_group", "key_mode",
    "on_disk_fingerprint", "on_disk_key_public_sha256", "certificate_id", "match_state", "last_seen_at", "is_active",
)
BINDING_SORTS = {
    "server": (Server.hostname, Binding.vhost_name, Binding.port),
    "-server": (Server.hostname.desc(), Binding.vhost_name, Binding.port),
    "vhost": (Binding.vhost_name, Server.hostname, Binding.port),
    "-vhost": (Binding.vhost_name.desc(), Server.hostname.desc(), Binding.port.desc()),
    "match_state": (Binding.match_state, Server.hostname, Binding.vhost_name),
    "-match_state": (Binding.match_state.desc(), Server.hostname, Binding.vhost_name),
    "last_seen_at": (Binding.last_seen_at, Server.hostname, Binding.vhost_name),
    "-last_seen_at": (Binding.last_seen_at.desc(), Server.hostname, Binding.vhost_name),
}


@dataclass(frozen=True)
class BindingFilters:
    certificate_id: int | None = None
    server_id: int | None = None
    group: str | None = None
    webserver: WebserverType | None = None
    match_state: Literal["matched", "unknown", "key_mismatch", "missing_file"] | None = None
    vhost: str | None = None  # substring of the primary name or of any served name
    active: bool | None = True  # None: active and retired bindings


@dataclass(frozen=True)
class BindingPage:
    items: list[BindingRow]
    total: int
    page: int
    page_size: int


@dataclass(frozen=True)
class DiscoveryRun:
    job_id: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: int | None
    inventory_rev: str | None
    error_message: str | None


@dataclass(frozen=True)
class DumpSummary:
    """The facts a discovery recorded about one raw dump (spec 6.2); never the dump text itself."""

    job_id: str
    collected_at: datetime | None
    webserver: str | None
    config_files: tuple[str, ...]
    bindings: int
    warnings: tuple[str, ...]
    parse_suspected: bool
    dump_bytes: int | None
    dump_sha256: str | None


@dataclass(frozen=True)
class ServerDetail:
    server: ServerRow
    connection_address: str | None
    inventory_source: str
    notes: str | None
    bindings: list[BindingRow]
    discovery_history: list[DiscoveryRun]
    endpoint_count: int
    dump_summary: DumpSummary | None = None


def _query(filters: ServerFilters):
    query = (
        select(
            Server.id,
            Server.hostname,
            Server.display_name,
            Server.ansible_groups,
            Server.webserver,
            _binding_count.label("binding_count"),
            func.coalesce(_bindings.c.attention, 0).label("attention_count"),
            Server.last_discovery_at,
            Server.last_discovery_status,
            _mismatch_count.label("mismatch_count"),
            Server.is_active,
            Server.connection_address,
            Server.inventory_source,
            Server.notes,
        )
        .select_from(Server)
        .outerjoin(_bindings, _bindings.c.server_id == Server.id)
        .outerjoin(_mismatches, _mismatches.c.server_id == Server.id)
    )
    if filters.search:
        query = query.where(
            Server.hostname.icontains(filters.search, autoescape=True)
            | Server.display_name.icontains(filters.search, autoescape=True)
        )
    if filters.group:
        query = query.where(Server.ansible_groups.op("@>")(literal([filters.group], ARRAY(Text))))
    if filters.active is not None:
        query = query.where(Server.is_active.is_(filters.active))
    return query


def _row(mapping) -> ServerRow:
    values = {name: mapping[name] for name in SERVER_EXPORT_FIELDS if name != "groups"}
    webserver = values["webserver"]
    values["webserver"] = webserver.value if webserver is not None else None
    return ServerRow(groups=tuple(mapping["ansible_groups"]), **values)


def list_servers(
    db: Session, filters: ServerFilters, page: int = 1, page_size: int = 50, sort: str = "hostname"
) -> ServerPage:
    """One page of servers with their counts; two statements whatever the page holds."""
    if page < 1 or page_size < 1:
        raise ValueError("page and page_size must be positive")
    if sort not in SORTS:
        raise ValueError("unsupported sort")
    base = _query(filters)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = db.execute(
        base.order_by(*SORTS[sort], Server.id).limit(page_size).offset((page - 1) * page_size)
    ).mappings()
    return ServerPage([_row(row) for row in rows], total, page, page_size)


def _octal(mode: int | None) -> str | None:
    return f"{mode:04o}" if mode is not None else None


def binding_query():
    """Bindings with their server name and matched certificate; shared by the cross-server view."""
    return (
        select(Binding, Server.hostname, Certificate.common_name, Server.last_discovery_status)
        .join(Server, Server.id == Binding.server_id)
        .outerjoin(Certificate, Certificate.id == Binding.certificate_id)
    )


def binding_row(
    binding: Binding, server: str, certificate_common_name: str | None, discovery_status: str | None = "ok"
) -> BindingRow:
    return BindingRow(
        id=binding.id,
        server_id=binding.server_id,
        server=server,
        webserver=binding.webserver.value,
        vhost_name=binding.vhost_name,
        vhost_names=tuple(binding.vhost_names),
        port=binding.port,
        config_file=binding.config_file,
        cert_path=binding.cert_path,
        chain_path=binding.chain_path,
        key_path=binding.key_path,
        cert_owner=binding.cert_owner,
        cert_group=binding.cert_group,
        cert_mode=_octal(binding.cert_mode),
        key_owner=binding.key_owner,
        key_group=binding.key_group,
        key_mode=_octal(binding.key_mode),
        on_disk_fingerprint=binding.on_disk_fingerprint,
        on_disk_key_public_sha256=binding.on_disk_key_public_sha256,
        certificate_id=binding.certificate_id,
        certificate_common_name=certificate_common_name,
        match_state=binding.match_state,
        last_seen_at=binding.last_seen_at,
        is_active=bool(binding.is_active),
        notes=str(redact(binding.notes))[:_NOTE_CHARS] if binding.notes else None,
        stale=bool(binding.is_active) and discovery_status != "ok",
    )


def _filtered_bindings(filters: BindingFilters):
    query = binding_query()
    if filters.certificate_id is not None:
        query = query.where(Binding.certificate_id == filters.certificate_id)
    if filters.server_id is not None:
        query = query.where(Binding.server_id == filters.server_id)
    if filters.group:
        query = query.where(Server.ansible_groups.op("@>")(literal([filters.group], ARRAY(Text))))
    if filters.webserver is not None:
        query = query.where(Binding.webserver == filters.webserver)
    if filters.match_state is not None:
        query = query.where(Binding.match_state == filters.match_state)
    if filters.vhost:
        names = func.array_to_string(Binding.vhost_names, " ")
        query = query.where(
            Binding.vhost_name.icontains(filters.vhost, autoescape=True)
            | names.icontains(filters.vhost, autoescape=True)
        )
    if filters.active is not None:
        query = query.where(Binding.is_active.is_(filters.active))
    return query


def list_bindings(
    db: Session, filters: BindingFilters, page: int = 1, page_size: int = 50, sort: str = "server"
) -> BindingPage:
    """One page of bindings across servers; two statements (count, page) whatever the page holds."""
    if page < 1 or page_size < 1:
        raise ValueError("page and page_size must be positive")
    if sort not in BINDING_SORTS:
        raise ValueError("unsupported sort")
    base = _filtered_bindings(filters)
    total = db.scalar(select(func.count()).select_from(base.with_only_columns(Binding.id).subquery())) or 0
    rows = db.execute(
        base.order_by(*BINDING_SORTS[sort], Binding.id).limit(page_size).offset((page - 1) * page_size)
    )
    return BindingPage([binding_row(*row) for row in rows], total, page, page_size)


def export_bindings(
    db: Session, filters: BindingFilters, limit: int = EXPORT_LIMIT
) -> list[dict[str, JSONValue]]:
    """Allowlisted fields only (``BINDING_EXPORT_FIELDS``): never notes."""
    rows = db.execute(_filtered_bindings(filters).order_by(*BINDING_SORTS["server"], Binding.id).limit(limit))
    exported: list[dict[str, JSONValue]] = []
    for row in rows:
        binding = binding_row(*row)
        item = {name: getattr(binding, name) for name in BINDING_EXPORT_FIELDS}
        item["vhost_names"] = list(binding.vhost_names)
        item["last_seen_at"] = binding.last_seen_at.isoformat()
        exported.append(item)  # type: ignore[arg-type]
    return exported


def _history(db: Session, server_id: int) -> list[DiscoveryRun]:
    started = func.coalesce(JobHost.started_at, Job.started_at)
    finished = func.coalesce(JobHost.finished_at, Job.finished_at)
    rows = db.execute(
        select(
            JobHost.job_id,
            JobHost.status,
            started.label("started_at"),
            finished.label("finished_at"),
            Job.result["inventory_rev"].astext.label("inventory_rev"),
            JobHost.error_message,
        )
        .join(Job, Job.id == JobHost.job_id)
        .where(JobHost.server_id == server_id, JobHost.binding_id.is_(None), Job.type == JobType.DISCOVER)
        .order_by(func.coalesce(started, Job.created_at).desc(), JobHost.created_at.desc(), JobHost.id)
        .limit(HISTORY_LIMIT)
    ).mappings()
    return [
        DiscoveryRun(
            job_id=str(row["job_id"]),
            status=row["status"].value,
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            duration_seconds=max(0, int((row["finished_at"] - row["started_at"]).total_seconds()))
            if row["started_at"] and row["finished_at"]
            else None,
            inventory_rev=row["inventory_rev"],
            error_message=str(redact(row["error_message"]))[:_ERROR_CHARS] if row["error_message"] else None,
        )
        for row in rows
    ]


def _text_items(value: object, limit: int) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(redact(item))[:_SUMMARY_TEXT_CHARS] for item in value[:limit] if isinstance(item, str))


def _int_or_none(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def last_dump_summary(db: Session, server_id: int) -> DumpSummary | None:
    """The newest discover ``job_host.precheck`` of the server that recorded a captured dump, as a summary.

    The raw dump lives under the worker's artifact directory, which the web process never mounts or reads;
    ``precheck`` holds only the facts about it (files, counts, size, SHA-256).
    """
    row = db.execute(
        select(JobHost.job_id, JobHost.precheck, func.coalesce(JobHost.finished_at, JobHost.started_at))
        .join(Job, Job.id == JobHost.job_id)
        .where(
            JobHost.server_id == server_id,
            JobHost.binding_id.is_(None),
            Job.type == JobType.DISCOVER,
            JobHost.precheck["dump_sha256"].astext.is_not(None),
        )
        .order_by(func.coalesce(JobHost.finished_at, JobHost.started_at, JobHost.created_at).desc(), JobHost.id.desc())
        .limit(1)
    ).first()
    if row is None:
        return None
    job_id, precheck, collected_at = row
    sha = precheck.get("dump_sha256")
    webserver = precheck.get("webserver")
    return DumpSummary(
        job_id=str(job_id),
        collected_at=collected_at,
        webserver=str(redact(webserver))[:_SUMMARY_TEXT_CHARS] if isinstance(webserver, str) else None,
        config_files=_text_items(precheck.get("config_files"), _SUMMARY_FILES),
        bindings=_int_or_none(precheck.get("bindings")) or 0,
        warnings=_text_items(precheck.get("warnings"), _SUMMARY_FILES),
        parse_suspected=precheck.get("parse_suspected") is True,
        dump_bytes=_int_or_none(precheck.get("dump_bytes")),
        dump_sha256=sha[:64] if isinstance(sha, str) else None,
    )


def unknown_bindings(db: Session, limit: int = UNKNOWN_LIMIT) -> list[BindingRow]:
    """The newest active bindings whose on-disk certificate is not in the inventory (one statement)."""
    rows = db.execute(
        binding_query()
        .where(Binding.is_active, Server.is_active, Binding.match_state == "unknown")
        .order_by(Binding.last_seen_at.desc(), Binding.id.desc())
        .limit(limit)
    )
    return [binding_row(*row) for row in rows]


def server_detail(db: Session, server_id: int) -> ServerDetail:
    found = db.execute(_query(ServerFilters(active=None)).where(Server.id == server_id)).mappings().first()
    if found is None:
        raise ServerNotFound(server_id)
    bindings = db.execute(
        binding_query()
        .where(Binding.server_id == server_id)
        .order_by(Binding.is_active.desc(), Binding.vhost_name, Binding.port, Binding.id)
    )
    endpoints = db.scalar(
        select(func.count()).select_from(Endpoint).where(Endpoint.server_id == server_id, Endpoint.is_active)
    )
    return ServerDetail(
        server=_row(found),
        connection_address=found["connection_address"],
        inventory_source=found["inventory_source"],
        notes=found["notes"],
        bindings=[binding_row(*row) for row in bindings],
        discovery_history=_history(db, server_id),
        endpoint_count=endpoints or 0,
        dump_summary=last_dump_summary(db, server_id),
    )


def export_servers(
    db: Session, filters: ServerFilters, limit: int = EXPORT_LIMIT
) -> list[dict[str, JSONValue]]:
    """Allowlisted fields only (``SERVER_EXPORT_FIELDS``): never notes, connection address or inventory source."""
    rows = db.execute(_query(filters).order_by(*SORTS["hostname"], Server.id).limit(limit)).mappings()
    exported: list[dict[str, JSONValue]] = []
    for mapping in rows:
        row = _row(mapping)
        item = {name: getattr(row, name) for name in SERVER_EXPORT_FIELDS}
        item["groups"] = list(item["groups"])  # type: ignore[arg-type]
        if item["last_discovery_at"] is not None:
            item["last_discovery_at"] = item["last_discovery_at"].isoformat()  # type: ignore[union-attr]
        exported.append(item)  # type: ignore[arg-type]
    return exported
