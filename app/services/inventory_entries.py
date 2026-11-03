"""Manual inventory entries: hosts an operator adds without a repository (spec 4.7, 6.1, 8.6).

The spec's inventory source is the git checkout the worker pulls, and discovery owns those rows. This
module adds the other source the dashboard needs: a host typed in by an administrator, marked with
:data:`MANUAL_SOURCE` in ``server.inventory_source`` so :func:`is_manual` can tell the two apart without a
new column. The rules follow from that marker:

* reconciliation never deactivates a manual host (``services.discovery``) — it was never expected in the
  checkout, so its absence is not a removal;
* a manual host whose name *does* appear in the checkout is adopted by the repository on the next
  discovery (the row keeps its id, bindings and history; its source becomes the revision);
* editing and deleting are for manual rows only: a repository row would be overwritten or recreated by
  the next discovery, so the screen refuses instead of pretending the change would last;
* a manual row with discovery history is deactivated rather than deleted, because bindings, endpoints and
  job rows point at it and the audit trail must stay readable (spec 6.3).

Validation is pure (:func:`parse_entry`) so the rules are testable without a database; the mutations here
are audited and run inside the caller's transaction.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import ARRAY, Select, Text, func, literal, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Binding, Endpoint, JobHost, Server
from app.models.enums import WebserverType
from app.services.audit import Actor, record

__all__ = [
    "MANUAL_SOURCE",
    "EntryFields",
    "InventoryEntryError",
    "InventoryEntryNotFound",
    "InventoryFilters",
    "InventoryPage",
    "InventoryRow",
    "create_entry",
    "delete_entry",
    "is_manual",
    "list_entries",
    "parse_entry",
    "set_entry_active",
    "update_entry",
]

MANUAL_SOURCE = "manual"
MAX_HOSTNAME = 253
MAX_DISPLAY_NAME = 200
MAX_NOTES = 2000
MAX_GROUPS = 64
# ``all`` and ``ungrouped`` are Ansible's pseudo-groups (``services.discovery`` drops them); a real
# inventory variable cannot use them, so accepting one here would silently lose the group.
RESERVED_GROUPS = frozenset({"all", "ungrouped"})

_LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\Z")
_GROUP = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
_FORBIDDEN = frozenset("/\\?#&=@%")


class InventoryEntryError(ValueError):
    """A refused edit. ``field`` names the input; ``message`` is user-facing and never echoes a secret."""

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        self.message = message
        super().__init__(message)


class InventoryEntryNotFound(LookupError):
    """No inventory host has this id."""


@dataclass(frozen=True)
class EntryFields:
    """The validated, normalized form of one inventory entry."""

    hostname: str
    display_name: str | None = None
    connection_address: str | None = None
    webserver: WebserverType | None = None
    ansible_groups: tuple[str, ...] = ()
    notes: str | None = None


@dataclass(frozen=True)
class InventoryFilters:
    search: str | None = None
    group: str | None = None
    source: str | None = None  # "manual" | "repository"; None keeps both
    webserver: WebserverType | None = None
    active: bool | None = True  # None keeps active and inactive hosts


@dataclass(frozen=True)
class InventoryRow:
    """One managed host as the list needs it; always a plain tuple of public fields."""

    id: int
    hostname: str
    display_name: str | None
    connection_address: str | None
    groups: tuple[str, ...]
    webserver: str | None
    source: str
    manual: bool
    notes: str | None
    is_active: bool
    binding_count: int
    last_discovery_at: datetime | None
    last_discovery_status: str | None


@dataclass(frozen=True)
class InventoryPage:
    items: list[InventoryRow]
    total: int
    page: int
    page_size: int


# --- pure validation -------------------------------------------------------------------------------


def _text(form: Mapping[str, object], name: str) -> str:
    """The submitted value of one field, trimmed; anything that is not text counts as absent."""
    value = form.get(name, "")
    return value.strip() if isinstance(value, str) else ""


def _single_line(value: str, field: str, label: str, limit: int) -> str | None:
    if not value:
        return None
    if len(value) > limit:
        raise InventoryEntryError(field, f"{label} must be at most {limit} characters.")
    if any(character < " " or character == "\x7f" for character in value):
        raise InventoryEntryError(field, f"{label} must stay on one line.")
    return value


def _notes(value: str) -> str | None:
    if not value:
        return None
    if len(value) > MAX_NOTES:
        raise InventoryEntryError("notes", f"Notes must be at most {MAX_NOTES} characters.")
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    if any((character < " " and character not in "\n\t") or character == "\x7f" for character in normalized):
        raise InventoryEntryError("notes", "Notes cannot contain control characters.")
    return normalized


def _host(value: str, field: str, label: str) -> str | None:
    """A DNS name (underscores allowed: Ansible inventories use them) or an IP literal."""
    if not value:
        return None
    if len(value) > MAX_HOSTNAME:
        raise InventoryEntryError(field, f"{label} must be at most {MAX_HOSTNAME} characters.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return value
    if any(character.isspace() or character in _FORBIDDEN for character in value):
        raise InventoryEntryError(
            field,
            f"{label} must be a hostname or IP address: letters, digits, dots, hyphens and underscores.",
        )
    if not all(_LABEL.fullmatch(part) for part in value.split(".")):
        raise InventoryEntryError(
            field,
            f"{label} must be a hostname or IP address: each dot-separated part starts and ends with a "
            "letter, digit or underscore (at most 63 characters).",
        )
    return value


def _webserver(value: str) -> WebserverType | None:
    if not value:
        return None
    try:
        return WebserverType(value.lower())
    except ValueError:
        raise InventoryEntryError(
            "webserver", "Choose nginx, Apache, or leave it empty so discovery detects the web server."
        ) from None


def _groups(value: str) -> tuple[str, ...]:
    tokens = [token for token in re.split(r"[,\s]+", value) if token]
    groups: list[str] = []
    for token in tokens:
        if token in RESERVED_GROUPS:
            raise InventoryEntryError(
                "ansible_groups", "“all” and “ungrouped” are reserved group names: omit them."
            )
        if not _GROUP.fullmatch(token):
            raise InventoryEntryError(
                "ansible_groups",
                "Each group name must be 1–64 characters: letters, digits, dots, colons, hyphens and underscores.",
            )
        if token not in groups:
            groups.append(token)
    if len(groups) > MAX_GROUPS:
        raise InventoryEntryError("ansible_groups", f"A host can belong to at most {MAX_GROUPS} groups.")
    return tuple(groups)


def parse_entry(form: Mapping[str, object]) -> EntryFields:
    """Validate and normalize one submitted host; raise the first :class:`InventoryEntryError`."""
    hostname = _host(_text(form, "hostname"), "hostname", "Hostname")
    if hostname is None:
        raise InventoryEntryError("hostname", "Enter the hostname or IP address Ansible connects to.")
    return EntryFields(
        hostname=hostname,
        display_name=_single_line(_text(form, "display_name"), "display_name", "Display name", MAX_DISPLAY_NAME),
        connection_address=_host(_text(form, "connection_address"), "connection_address", "Connection address"),
        webserver=_webserver(_text(form, "webserver")),
        ansible_groups=_groups(_text(form, "ansible_groups")),
        notes=_notes(_text(form, "notes")),
    )


def is_manual(server: Server) -> bool:
    """True for a row an operator added here (never for a row a repository revision produced)."""
    return server.inventory_source == MANUAL_SOURCE


# --- reads -----------------------------------------------------------------------------------------

_SORTS = {
    "hostname": (Server.hostname.asc(),),
    "-hostname": (Server.hostname.desc(),),
    "last_discovery_at": (Server.last_discovery_at.asc().nulls_first(), Server.hostname),
    "-last_discovery_at": (Server.last_discovery_at.desc().nulls_last(), Server.hostname),
}
SORTS = tuple(_SORTS)

_binding_counts = (
    select(Binding.server_id, func.count().label("total"))
    .where(Binding.is_active)
    .group_by(Binding.server_id)
    .subquery("inventory_binding_counts")
)
_binding_count = func.coalesce(_binding_counts.c.total, 0)


def _filtered(filters: InventoryFilters) -> Select:
    query = select(Server.id)
    if filters.source == MANUAL_SOURCE:
        query = query.where(Server.inventory_source == MANUAL_SOURCE)
    elif filters.source == "repository":
        query = query.where(Server.inventory_source != MANUAL_SOURCE)
    if filters.search:
        pattern = f"%{filters.search}%"
        query = query.where(
            Server.hostname.ilike(pattern)
            | Server.display_name.ilike(pattern)
            | Server.connection_address.ilike(pattern)
            | Server.notes.ilike(pattern)
            | func.array_to_string(Server.ansible_groups, ",").ilike(pattern)
        )
    if filters.group:
        query = query.where(Server.ansible_groups.op("@")(literal([filters.group], ARRAY(Text))))
    if filters.webserver is not None:
        query = query.where(Server.webserver == filters.webserver)
    if filters.active is not None:
        query = query.where(Server.is_active.is_(filters.active))
    return query


def list_entries(
    db: Session,
    filters: InventoryFilters,
    page: int,
    page_size: int,
    sort: str = "hostname",
) -> InventoryPage:
    """One page of inventory rows with their source marker and active binding count."""
    if sort not in _SORTS:
        raise ValueError(f"unsupported sort: {sort!r}")
    matching = _filtered(filters).subquery("matching_servers")
    total = db.scalar(select(func.count()).select_from(matching)) or 0
    rows = db.execute(
        select(
            Server.id,
            Server.hostname,
            Server.display_name,
            Server.connection_address,
            Server.ansible_groups,
            Server.webserver,
            Server.inventory_source,
            Server.notes,
            Server.is_active,
            Server.last_discovery_at,
            Server.last_discovery_status,
            _binding_count.label("binding_count"),
        )
        .join(matching, matching.c.id == Server.id)
        .outerjoin(_binding_counts, _binding_counts.c.server_id == Server.id)
        .order_by(*_SORTS[sort], Server.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    items = [
        InventoryRow(
            id=row.id,
            hostname=row.hostname,
            display_name=row.display_name,
            connection_address=row.connection_address,
            groups=tuple(row.ansible_groups or ()),
            webserver=row.webserver,
            source=row.inventory_source,
            manual=row.inventory_source == MANUAL_SOURCE,
            notes=row.notes,
            is_active=row.is_active,
            binding_count=row.binding_count,
            last_discovery_at=row.last_discovery_at,
            last_discovery_status=row.last_discovery_status,
        )
        for row in rows
    ]
    return InventoryPage(items, total, page, page_size)


def group_names(db: Session) -> list[str]:
    """Every group currently carried by a host, for the filter select."""
    name = func.unnest(Server.ansible_groups).label("name")
    return list(db.scalars(select(name).distinct().order_by(name)))


# --- mutations -------------------------------------------------------------------------------------


def _entry(db: Session, server_id: int) -> Server:
    server = db.get(Server, server_id)
    if server is None:
        raise InventoryEntryNotFound(server_id)
    return server


def _require_manual(server: Server) -> None:
    if not is_manual(server):
        raise InventoryEntryError(
            "form",
            f"“{server.hostname}” comes from the inventory repository ({server.inventory_source}): change it "
            "there, or discovery will overwrite the edit.",
        )


def _claim_hostname(db: Session, hostname: str, server_id: int | None) -> None:
    """Refuse a case-insensitive duplicate. PostgreSQL's unique index is exact, so check here too."""
    query = select(Server).where(func.lower(Server.hostname) == hostname.lower())
    if server_id is not None:
        query = query.where(Server.id != server_id)
    existing = db.scalars(query.limit(1)).first()
    if existing is None:
        return
    origin = "added here" if is_manual(existing) else f"from the repository ({existing.inventory_source})"
    raise InventoryEntryError(
        "hostname", f"“{existing.hostname}” is already in the inventory, {origin}. Use a different hostname."
    )


def create_entry(db: Session, fields: EntryFields, actor: Actor) -> Server:
    """Insert one manual host and audit it; the caller commits."""
    _claim_hostname(db, fields.hostname, None)
    server = Server(
        hostname=fields.hostname,
        display_name=fields.display_name,
        ansible_groups=list(fields.ansible_groups),
        webserver=fields.webserver,
        connection_address=fields.connection_address,
        inventory_source=MANUAL_SOURCE,
        is_active=True,
        notes=fields.notes,
    )
    db.add(server)
    try:
        db.flush()
    except IntegrityError:
        # Two administrators submitted the same host at once: the unique index wins, the message stays clear.
        raise InventoryEntryError(
            "hostname", f"“{fields.hostname}” is already in the inventory. Use a different hostname."
        ) from None
    record(
        db,
        actor,
        "server.create",
        "server",
        str(server.id),
        {"hostname": server.hostname, "source": MANUAL_SOURCE, "groups": list(fields.ansible_groups)},
    )
    return server


def update_entry(db: Session, server_id: int, fields: EntryFields, actor: Actor) -> Server:
    """Replace the editable fields of one manual host, auditing the before/after of what changed."""
    server = _entry(db, server_id)
    _require_manual(server)
    _claim_hostname(db, fields.hostname, server.id)
    before = {
        "hostname": server.hostname,
        "display_name": server.display_name,
        "connection_address": server.connection_address,
        "webserver": str(server.webserver) if server.webserver else None,
        "ansible_groups": list(server.ansible_groups or ()),
        "notes": server.notes,
    }
    after = {
        "hostname": fields.hostname,
        "display_name": fields.display_name,
        "connection_address": fields.connection_address,
        "webserver": str(fields.webserver) if fields.webserver else None,
        "ansible_groups": list(fields.ansible_groups),
        "notes": fields.notes,
    }
    changes = {
        name: {"from": before[name], "to": after[name]} for name in after if before[name] != after[name]
    }
    server.hostname = fields.hostname
    server.display_name = fields.display_name
    server.connection_address = fields.connection_address
    server.webserver = fields.webserver
    server.ansible_groups = list(fields.ansible_groups)
    server.notes = fields.notes
    if changes:
        try:
            db.flush()
        except IntegrityError:
            raise InventoryEntryError(
                "hostname", f"“{fields.hostname}” is already in the inventory. Use a different hostname."
            ) from None
        record(db, actor, "server.update", "server", str(server.id), {"changes": changes})
    return server


def _history(db: Session, server_id: int) -> dict[str, int]:
    counts = {}
    for label, model, column in (
        ("bindings", Binding, Binding.server_id),
        ("endpoints", Endpoint, Endpoint.server_id),
        ("job rows", JobHost, JobHost.server_id),
    ):
        counts[label] = db.scalar(select(func.count()).select_from(model).where(column == server_id)) or 0
    return {label: count for label, count in counts.items() if count}


def delete_entry(db: Session, server_id: int, actor: Actor) -> None:
    """Delete a manual host that left no history behind; refuse (and offer deactivation) otherwise."""
    server = _entry(db, server_id)
    _require_manual(server)
    history = _history(db, server.id)
    if history:
        listed = ", ".join(f"{count} {label}" for label, count in history.items())
        raise InventoryEntryError(
            "form",
            f"“{server.hostname}” still has {listed}. Deleting it would erase that history: deactivate it instead, "
            "which keeps the rows readable and stops the host being used.",
        )
    record(db, actor, "server.delete", "server", str(server.id), {"hostname": server.hostname})
    db.delete(server)
    db.flush()


def set_entry_active(db: Session, server_id: int, active: bool, actor: Actor) -> Server:
    """Activate or deactivate a manual host. Repository rows are refused: discovery decides those."""
    server = _entry(db, server_id)
    _require_manual(server)
    if bool(server.is_active) == active:
        raise InventoryEntryError(
            "form", f"“{server.hostname}” is already {'active' if active else 'inactive'}."
        )
    server.is_active = active
    record(
        db,
        actor,
        "server.activate" if active else "server.deactivate",
        "server",
        str(server.id),
        {"hostname": server.hostname, "source": MANUAL_SOURCE},
    )
    db.flush()
    return server
