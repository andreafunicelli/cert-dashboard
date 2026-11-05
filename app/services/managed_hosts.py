"""Manual inventory hosts for Slice B (contract §3.1, §4, decisions D1/D5/D6).

Two sources share the ``server`` table: manual rows (``inventory_source = 'manual'``, created here) and
repository rows (the Git inventory revision marker). This module owns validation, the list read model and
the manual-host mutations; the routes in ``app.web.inventory`` only translate HTTP. Git is optional: every
function here works with no repository configured.

Rules (contract §3.1): hostname syntax and uniqueness across all rows, blank-to-``NULL`` display name,
connection address without user or port, Ansible group names, bounded notes. A manual host keeps its
hostname and may be deleted only while it has no discovery/deploy history (D5); repository rows expose
only ``display_name`` and ``notes`` because the next discovery would overwrite the rest.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal

from sqlalchemy import ARRAY, Text, func, literal, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Binding, Endpoint, JobHost, JSONValue, Server
from app.models.enums import WebserverType
from app.services.audit import Actor, record
from app.services.inventory_sources import MANUAL_SOURCE, is_manual

HOSTNAME_MAX = 253
LABEL_MAX = 63
DISPLAY_NAME_MAX = 200
NOTES_MAX = 2000
GROUPS_MAX = 64
SEARCH_MAX = 200

HOSTNAME_EMPTY = "Enter a hostname."
HOSTNAME_SYNTAX = (
    "Use letters, digits, dots, hyphens or underscores (or an IP address); "
    "a label cannot start or end with a hyphen."
)
HOSTNAME_IMMUTABLE = "A hostname cannot be changed once the host has discovery or deploy history."
CONNECTION_SYNTAX = "Enter a hostname or IP address without a user or port."
DISPLAY_NAME_RULE = "Display name must be at most 200 characters and fit on one line."
NOTES_RULE = "Notes must be at most 2000 characters."
GROUPS_SYNTAX = "Group names use letters, digits and underscores and cannot start with a digit."
GROUPS_RESERVED = '"all" and "ungrouped" are reserved by Ansible.'
GROUPS_MAX_MESSAGE = "At most 64 groups."
WEBSERVER_CHOICE = "Choose auto-detect, nginx or apache."
SSH_USER_RULE = "Use a POSIX user name (lower-case letters, digits, _ . -)."
SSH_PORT_RULE = "Enter a port between 1 and 65535."

REPOSITORY_ROW = "Repository hosts are managed in Git."
CONFIRMATION_REQUIRED = "Confirm the action to continue."
SSH_USER_KEY = "inventory.manual_ssh_user"
SSH_PORT_KEY = "inventory.manual_ssh_port"
DEFAULT_SSH_PORT = 22

_HOST_CHARS = re.compile(r"[A-Za-z0-9_-]+")
_GROUP_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_POSIX_USER = re.compile(r"[a-z_][a-z0-9_.-]{0,31}")
_RESERVED_GROUPS = frozenset({"all", "ungrouped"})
_SOURCE_FILTERS = ("manual", "repository")
_WEBSERVER_FILTERS = ("nginx", "apache", "auto")
_STATES = ("active", "inactive", "all")

State = Literal["active", "inactive", "all"]
SourceFilter = Literal["manual", "repository"]


class HostError(Exception):
    """A refused change: ``field`` is the form field (or ``action``) and ``message`` is user-facing."""

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        self.message = message
        super().__init__(message)


class HostNotFound(LookupError):
    """No server has this id."""


# --- validation ------------------------------------------------------------------------------------


def _host_token(value: str) -> str:
    """Lower-cased hostname or IP literal; raises ``ValueError`` for anything else."""
    if len(value) > HOSTNAME_MAX:
        raise ValueError("too long")
    if "%" in value:
        # Contract §3.1 allows an IP literal, not a scoped literal: ``ip_address`` accepts
        # ``fe80::1%<scope>`` and the scope id is free text (spaces, newlines, shell syntax).
        raise ValueError("scoped literal")
    try:
        return str(ip_address(value))
    except ValueError:
        pass
    if value.endswith("."):
        raise ValueError("empty trailing label")
    labels = value.split(".")
    for label in labels:
        if not 1 <= len(label) <= LABEL_MAX or _HOST_CHARS.fullmatch(label) is None:
            raise ValueError("bad label")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("hyphen at a label edge")
    return value.lower()


def normalize_hostname(raw: object) -> str:
    value = raw.strip() if isinstance(raw, str) else ""
    if not value:
        raise HostError("hostname", HOSTNAME_EMPTY)
    try:
        return _host_token(value)
    except ValueError:
        raise HostError("hostname", HOSTNAME_SYNTAX) from None


def normalize_connection_address(raw: object, hostname: str) -> str | None:
    value = raw.strip() if isinstance(raw, str) else ""
    if not value:
        return None
    if "@" in value or "/" in value or " " in value:
        raise HostError("connection_address", CONNECTION_SYNTAX)
    try:
        normalized = _host_token(value)
    except ValueError:
        raise HostError("connection_address", CONNECTION_SYNTAX) from None
    return None if normalized == hostname else normalized


def normalize_display_name(raw: object) -> str | None:
    value = raw.strip() if isinstance(raw, str) else ""
    if not value:
        return None
    if len(value) > DISPLAY_NAME_MAX or "\n" in value or "\r" in value:
        raise HostError("display_name", DISPLAY_NAME_RULE)
    return value


def normalize_notes(raw: object) -> str | None:
    value = raw.strip() if isinstance(raw, str) else ""
    if not value:
        return None
    if len(value) > NOTES_MAX:
        raise HostError("notes", NOTES_RULE)
    return value


def normalize_groups(raw: object) -> tuple[str, ...]:
    text = raw if isinstance(raw, str) else ""
    names: list[str] = []
    for token in re.split(r"[,\s]+", text.strip()):
        if token and token not in names:
            names.append(token)
    if len(names) > GROUPS_MAX:
        raise HostError("groups", GROUPS_MAX_MESSAGE)
    for name in names:
        if name in _RESERVED_GROUPS:
            raise HostError("groups", GROUPS_RESERVED)
        if _GROUP_NAME.fullmatch(name) is None:
            raise HostError("groups", GROUPS_SYNTAX)
    return tuple(names)


def normalize_webserver(raw: object) -> WebserverType | None:
    value = raw.strip().lower() if isinstance(raw, str) else ""
    if not value:
        return None
    try:
        return WebserverType(value)
    except ValueError:
        raise HostError("webserver", WEBSERVER_CHOICE) from None


@dataclass(frozen=True)
class HostFields:
    hostname: str
    display_name: str | None
    connection_address: str | None
    webserver: WebserverType | None
    groups: tuple[str, ...]
    notes: str | None


@dataclass(frozen=True)
class RepositoryFields:
    """The only two fields discovery never writes, so they stay editable on a repository row (D5)."""

    display_name: str | None
    notes: str | None


def _field(form: Mapping[str, Any], name: str) -> str:
    value = form.get(name)
    return value if isinstance(value, str) else ""


def _collect(errors: dict[str, list[str]], field: str, parse, *args):
    try:
        return parse(*args)
    except HostError as exc:
        errors.setdefault(exc.field, []).append(exc.message)
        return None


def parse_host_form(form: Mapping[str, Any]) -> tuple[HostFields | None, dict[str, list[str]]]:
    """Every field of the create/edit form; all failures are reported together, nothing is normalized then."""
    errors: dict[str, list[str]] = {}
    hostname = _collect(errors, "hostname", normalize_hostname, _field(form, "hostname"))
    display_name = _collect(errors, "display_name", normalize_display_name, _field(form, "display_name"))
    connection_address = _collect(
        errors, "connection_address", normalize_connection_address, _field(form, "connection_address"), hostname or ""
    )
    webserver = _collect(errors, "webserver", normalize_webserver, _field(form, "webserver"))
    groups = _collect(errors, "groups", normalize_groups, _field(form, "groups"))
    notes = _collect(errors, "notes", normalize_notes, _field(form, "notes"))
    if errors:
        return None, errors
    return (
        HostFields(
            hostname=hostname,
            display_name=display_name,
            connection_address=connection_address,
            webserver=webserver,
            groups=groups or (),
            notes=notes,
        ),
        {},
    )


def parse_repository_form(form: Mapping[str, Any]) -> tuple[RepositoryFields | None, dict[str, list[str]]]:
    errors: dict[str, list[str]] = {}
    display_name = _collect(errors, "display_name", normalize_display_name, _field(form, "display_name"))
    notes = _collect(errors, "notes", normalize_notes, _field(form, "notes"))
    if errors:
        return None, errors
    return RepositoryFields(display_name=display_name, notes=notes), {}


def parse_connection_form(form: Mapping[str, Any]) -> tuple[dict[str, JSONValue] | None, dict[str, list[str]]]:
    """The D6 connection defaults: an empty user means the Ansible default, the port is 1–65535."""
    errors: dict[str, list[str]] = {}
    user = _field(form, "ssh_user").strip()
    if user and _POSIX_USER.fullmatch(user) is None:
        errors["ssh_user"] = [SSH_USER_RULE]
    raw_port = _field(form, "ssh_port").strip()
    port = DEFAULT_SSH_PORT
    if raw_port:
        if not raw_port.isdigit() or len(raw_port) > 5 or not 1 <= int(raw_port) <= 65535:
            errors["ssh_port"] = [SSH_PORT_RULE]
        else:
            port = int(raw_port)
    if errors:
        return None, errors
    return {SSH_USER_KEY: user, SSH_PORT_KEY: port}, {}


# --- filters ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class HostFilters:
    q: str | None = None
    group: str | None = None
    source: str | None = None
    webserver: str | None = None
    state: str = "active"


def _filter_value(params: Mapping[str, Any], name: str) -> str | None:
    value = params.get(name)
    if not isinstance(value, str):
        return None
    return value.strip()[:SEARCH_MAX] or None


def parse_filters(params: Mapping[str, Any]) -> HostFilters:
    """Bookmarkable query state; an invalid value falls back to the default instead of refusing the page."""
    source = _filter_value(params, "source")
    webserver = _filter_value(params, "webserver")
    state = _filter_value(params, "state") or "active"
    return HostFilters(
        q=_filter_value(params, "q"),
        group=_filter_value(params, "group"),
        source=source if source in _SOURCE_FILTERS else None,
        webserver=webserver if webserver in _WEBSERVER_FILTERS else None,
        state=state if state in _STATES else "active",
    )


def filter_params(filters: HostFilters) -> dict[str, str]:
    params = {
        name: value
        for name in ("q", "group", "source", "webserver")
        if (value := getattr(filters, name))
    }
    if filters.state != "active":
        params["state"] = filters.state
    return params


# --- read model ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class HostRow:
    id: int
    hostname: str
    display_name: str | None
    connection_address: str | None
    groups: tuple[str, ...]
    webserver: str | None
    source: str
    is_active: bool
    last_discovery_at: datetime | None
    last_discovery_status: str | None
    binding_count: int
    notes: str | None = None

    @property
    def manual(self) -> bool:
        return is_manual(self.source)

    def form_values(self) -> dict[str, str]:
        """The row's stored values, used to prefill its inline edit form."""
        return {
            "hostname": self.hostname,
            "display_name": self.display_name or "",
            "connection_address": self.connection_address or "",
            "webserver": self.webserver or "",
            "groups": " ".join(self.groups),
            "notes": self.notes or "",
        }


@dataclass(frozen=True)
class HostPage:
    items: list[HostRow]
    total: int
    page: int
    page_size: int


_bindings = (
    select(Binding.server_id, func.count().label("total"))
    .where(Binding.is_active)
    .group_by(Binding.server_id)
    .subquery("inventory_binding_counts")
)


def _row(mapping) -> HostRow:
    webserver = mapping["webserver"]
    return HostRow(
        id=mapping["id"],
        hostname=mapping["hostname"],
        display_name=mapping["display_name"],
        connection_address=mapping["connection_address"],
        groups=tuple(mapping["ansible_groups"] or ()),
        webserver=webserver.value if webserver is not None else None,
        source=mapping["inventory_source"],
        is_active=bool(mapping["is_active"]),
        last_discovery_at=mapping["last_discovery_at"],
        last_discovery_status=mapping["last_discovery_status"],
        binding_count=mapping["binding_count"],
        notes=mapping["notes"],
    )


_host_columns = (
    Server.id,
    Server.hostname,
    Server.display_name,
    Server.connection_address,
    Server.ansible_groups,
    Server.webserver,
    Server.inventory_source,
    Server.is_active,
    Server.last_discovery_at,
    Server.last_discovery_status,
    func.coalesce(_bindings.c.total, 0).label("binding_count"),
    Server.notes,
)


def _aggregate():
    return select(*_host_columns).select_from(Server).outerjoin(_bindings, _bindings.c.server_id == Server.id)


def _filtered(filters: HostFilters):
    query = _aggregate()
    if filters.q:
        query = query.where(
            Server.hostname.icontains(filters.q, autoescape=True)
            | Server.display_name.icontains(filters.q, autoescape=True)
            | Server.connection_address.icontains(filters.q, autoescape=True)
        )
    if filters.group:
        query = query.where(Server.ansible_groups.op("@>")(literal([filters.group], ARRAY(Text))))
    if filters.source == "manual":
        query = query.where(Server.inventory_source == MANUAL_SOURCE)
    elif filters.source == "repository":
        query = query.where(Server.inventory_source != MANUAL_SOURCE)
    if filters.webserver == "auto":
        query = query.where(Server.webserver.is_(None))
    elif filters.webserver:
        query = query.where(Server.webserver == WebserverType(filters.webserver))
    if filters.state == "active":
        query = query.where(Server.is_active.is_(True))
    elif filters.state == "inactive":
        query = query.where(Server.is_active.is_(False))
    return query


def list_hosts(db: Session, filters: HostFilters, page: int = 1, page_size: int = 50) -> HostPage:
    """One page of hosts, hostname order; two statements whatever the page holds."""
    if page < 1 or page_size < 1:
        raise ValueError("page and page_size must be positive")
    base = _filtered(filters)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = db.execute(
        base.order_by(Server.hostname, Server.id).limit(page_size).offset((page - 1) * page_size)
    ).mappings()
    return HostPage([_row(row) for row in rows], total, page, page_size)


def get_host_row(db: Session, server_id: int) -> HostRow | None:
    """One row regardless of filters, so a refusal can show the row it is about (contract §4)."""
    if server_id >= 2**63 or server_id < 1:
        return None
    found = db.execute(_aggregate().where(Server.id == server_id)).mappings().first()
    return None if found is None else _row(found)


def count_hosts(db: Session) -> int:
    """Every host, whatever the filters: tells "nothing yet" apart from "no match"."""
    return db.scalar(select(func.count()).select_from(Server)) or 0


def count_manual_hosts(db: Session) -> int:
    """Manual rows only: the D6 warning applies when one exists and no SSH user is set."""
    return db.scalar(
        select(func.count()).select_from(Server).where(Server.inventory_source == MANUAL_SOURCE)
    ) or 0


def groups_in_use(db: Session) -> list[str]:
    name = func.unnest(Server.ansible_groups).label("name")
    return list(db.scalars(select(name).distinct().order_by("name")))


def has_history(db: Session, server_id: int) -> bool:
    """True when any row still depends on the server: bindings, endpoints or job hosts (D5)."""
    for model in (Binding, Endpoint, JobHost):
        found = db.scalar(select(model.id).where(model.server_id == server_id).limit(1))
        if found is not None:
            return True
    return False


# --- mutations -------------------------------------------------------------------------------------


def _get(db: Session, server_id: int) -> Server:
    server = db.get(Server, server_id) if 0 < server_id < 2**63 else None
    if server is None:
        raise HostNotFound(server_id)
    return server


def _require_manual(server: Server) -> None:
    if not is_manual(server.inventory_source):
        raise HostError("action", REPOSITORY_ROW)


def duplicate_message(existing: Server, hostname: str) -> str:
    kind = "Manual" if is_manual(existing.inventory_source) else "Repository"
    state = "active" if existing.is_active else "inactive"
    return f"A host named {hostname} already exists ({kind}, {state})."


def _refuse_duplicate(db: Session, hostname: str, server_id: int | None = None) -> None:
    query = select(Server).where(Server.hostname == hostname)
    if server_id is not None:
        query = query.where(Server.id != server_id)
    existing = db.scalars(query).first()
    if existing is not None:
        raise HostError("hostname", duplicate_message(existing, hostname))


def _flush(db: Session, hostname: str) -> None:
    """The unique index is the concurrency backstop behind the pre-check."""
    try:
        with db.begin_nested():
            db.flush()
    except IntegrityError:
        existing = db.scalars(select(Server).where(Server.hostname == hostname)).first()
        raise HostError("hostname", duplicate_message(existing, hostname) if existing else HOSTNAME_SYNTAX) from None


def create_host(db: Session, fields: HostFields, actor: Actor, now: datetime) -> Server:
    _refuse_duplicate(db, fields.hostname)
    server = Server(
        hostname=fields.hostname,
        display_name=fields.display_name,
        connection_address=fields.connection_address,
        webserver=fields.webserver,
        ansible_groups=list(fields.groups),
        notes=fields.notes,
        inventory_source=MANUAL_SOURCE,
        is_active=True,
    )
    db.add(server)
    _flush(db, fields.hostname)
    record(
        db,
        actor,
        "server.create",
        "server",
        str(server.id),
        {"hostname": server.hostname, "source": MANUAL_SOURCE},
    )
    return server


def _changes(server: Server, fields: HostFields) -> dict[str, dict[str, JSONValue]]:
    """Before/after of the fields that really change; the audit keeps only these."""
    changes: dict[str, dict[str, JSONValue]] = {}
    pairs: list[tuple[str, Any, Any]] = [
        ("hostname", server.hostname, fields.hostname),
        ("display_name", server.display_name, fields.display_name),
        ("connection_address", server.connection_address, fields.connection_address),
        ("groups", list(server.ansible_groups or []), list(fields.groups)),
        ("webserver", server.webserver.value if server.webserver is not None else None,
         fields.webserver.value if fields.webserver is not None else None),
        ("notes", server.notes, fields.notes),
    ]
    for name, before, after in pairs:
        if before != after:
            changes[name] = {"before": before, "after": after}
    return changes


def update_manual_host(db: Session, server_id: int, fields: HostFields, actor: Actor, now: datetime) -> Server:
    server = _get(db, server_id)
    _require_manual(server)
    if fields.hostname != server.hostname:
        if has_history(db, server_id):
            raise HostError("hostname", HOSTNAME_IMMUTABLE)
        _refuse_duplicate(db, fields.hostname, server_id)
    changes = _changes(server, fields)
    if not changes:
        return server
    server.hostname = fields.hostname
    server.display_name = fields.display_name
    server.connection_address = fields.connection_address
    server.webserver = fields.webserver
    server.ansible_groups = list(fields.groups)
    server.notes = fields.notes
    _flush(db, fields.hostname)
    record(
        db,
        actor,
        "server.update",
        "server",
        str(server.id),
        {"hostname": server.hostname, "source": MANUAL_SOURCE, "changes": changes},
    )
    return server


def update_repository_host(
    db: Session, server_id: int, fields: RepositoryFields, actor: Actor, now: datetime
) -> Server:
    server = _get(db, server_id)
    if is_manual(server.inventory_source):
        raise HostError("action", REPOSITORY_ROW)
    changes: dict[str, dict[str, JSONValue]] = {}
    if server.display_name != fields.display_name:
        changes["display_name"] = {"before": server.display_name, "after": fields.display_name}
        server.display_name = fields.display_name
    if server.notes != fields.notes:
        changes["notes"] = {"before": server.notes, "after": fields.notes}
        server.notes = fields.notes
    if changes:
        record(
            db,
            actor,
            "server.update",
            "server",
            str(server.id),
            {"hostname": server.hostname, "source": "repository", "changes": changes},
        )
    return server


def set_active(db: Session, server_id: int, active: bool, actor: Actor, now: datetime) -> Server:
    server = _get(db, server_id)
    _require_manual(server)
    if bool(server.is_active) == active:
        raise HostError("action", "This host is already active." if active else "This host is already inactive.")
    server.is_active = active
    record(
        db,
        actor,
        "server.activate" if active else "server.deactivate",
        "server",
        str(server.id),
        {"hostname": server.hostname, "source": MANUAL_SOURCE},
    )
    return server


def delete_host(db: Session, server_id: int, actor: Actor, now: datetime) -> str:
    server = _get(db, server_id)
    _require_manual(server)
    if has_history(db, server_id):
        raise HostError(
            "action", f"{server.hostname} has discovery or deploy history; deactivate it instead."
        )
    hostname = server.hostname
    record(
        db,
        actor,
        "server.delete",
        "server",
        str(server.id),
        {"hostname": hostname, "source": MANUAL_SOURCE},
    )
    db.delete(server)
    return hostname
