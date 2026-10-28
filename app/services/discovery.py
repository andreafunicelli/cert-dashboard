"""Discovery reconciliation (spec 6.3, 9.5; Plan 3 Contract decisions 10-11).

``reconcile_host`` turns one section 6.2 host document into ``binding`` rows, their derived endpoints and the
audit trail, inside the caller's transaction (it locks the server row and never commits). Unknown
certificates are never imported, and neither servers nor bindings are ever deleted.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.crypto.parse import ParseError, parse_certificates
from app.models import Binding, Certificate, Endpoint, JSONValue, Server
from app.models.enums import WebserverType
from app.services.audit import Actor, record
from app.services.bindings import audit_binding_state, binding_state
from app.services.endpoints import ensure_binding_endpoint, expect_for_binding, settle_endpoints
from app.services.inventory import InventoryHost
from app.services.scans import EndpointInputError

CERTIFICATE_MISSING = "certificate missing or unreadable at discovery"
KEY_MISSING = "key missing or unreadable at discovery"
_NOTE_LIMIT = 1000
_PSEUDO_GROUPS = frozenset({"all", "ungrouped"})

type Identity = tuple[WebserverType, str, int, str, str]


@dataclass(frozen=True)
class InventorySync:
    created: int
    updated: int
    deactivated: int
    server_ids: dict[str, int]


@dataclass(frozen=True)
class ReconcileOutcome:
    added: int
    updated: int
    deactivated: int
    unchanged: int
    endpoints_created: int
    parse_suspected: bool


def _date(now: datetime) -> str:
    return now.astimezone(UTC).strftime("%Y-%m-%d")


# --- servers (spec 6.1, 6.3) ----------------------------------------------------------------------


def _deactivate_server(db: Session, server: Server, actor: Actor, now: datetime) -> None:
    """Deactivate a server and its bindings; the caller settles their endpoints once every removal is staged."""
    server.is_active = False
    record(db, actor, "server.deactivate", "server", str(server.id), {"hostname": server.hostname})
    note = f"server removed from inventory at {_date(now)}"
    for binding in db.scalars(select(Binding).where(Binding.server_id == server.id, Binding.is_active.is_(True)).order_by(Binding.id)):
        previous = binding_state(binding)
        binding.is_active = False
        binding.notes = note
        db.flush()
        audit_binding_state(db, binding, previous, actor, job_id=None, now=now)


def sync_inventory_servers(
    db: Session, hosts: Sequence[InventoryHost], source: str, actor: Actor, now: datetime
) -> InventorySync:
    """Insert inventory hosts without a row, refresh the rest, deactivate active rows the inventory lost.

    ``webserver`` is the inventory variable when valid, else the value discovery detected (kept as is).
    A removed server keeps its bindings and endpoints, all inactive; a returning one is active again.
    """
    existing = {server.hostname: server for server in db.scalars(select(Server).order_by(Server.id))}
    created = updated = 0
    ids: dict[str, int] = {}
    for host in hosts:
        groups = [name for name in host.groups if name not in _PSEUDO_GROUPS]
        address = None if host.connection_address == host.hostname else host.connection_address
        server = existing.get(host.hostname)
        if server is None:
            server = Server(
                hostname=host.hostname,
                ansible_groups=groups,
                connection_address=address,
                webserver=host.webserver,
                inventory_source=source,
                is_active=True,
            )
            db.add(server)
            db.flush()
            record(
                db,
                actor,
                "server.create",
                "server",
                str(server.id),
                {"hostname": host.hostname, "groups": list(groups), "webserver": str(host.webserver) if host.webserver else None},
            )
            created += 1
        else:
            changed = (
                server.ansible_groups != groups
                or server.connection_address != address
                or server.inventory_source != source
                or (host.webserver is not None and server.webserver != host.webserver)
                or not server.is_active
            )
            if not server.is_active:
                server.is_active = True
                record(db, actor, "server.activate", "server", str(server.id), {"hostname": host.hostname})
            server.ansible_groups = groups
            server.connection_address = address
            server.inventory_source = source
            if host.webserver is not None:
                server.webserver = host.webserver
            updated += changed
        ids[host.hostname] = server.id
    removed = [server for hostname, server in existing.items() if hostname not in ids and server.is_active]
    for server in removed:
        _deactivate_server(db, server, actor, now)
    db.flush()
    # after every removal: an endpoint an alias on a surviving server still derives changes owner instead of stopping
    settle_endpoints(db, _owned_by(db, [server.id for server in removed]), actor)
    db.flush()
    return InventorySync(created, updated, len(removed), ids)


def record_host_failure(db: Session, server_id: int, status: Literal["failed", "unreachable"], now: datetime) -> None:
    """A failed attempt: only the status and time change, bindings and endpoints stay as they were (stale)."""
    server = db.get(Server, server_id, with_for_update=True)
    if server is None:
        raise LookupError(server_id)
    server.last_discovery_at = now
    server.last_discovery_status = status
    db.flush()


def _owned_by(db: Session, server_ids: Sequence[int]) -> list[int]:
    """Ids of the endpoints owned by these servers or linked to one of their bindings."""
    if not server_ids:
        return []
    bindings = select(Binding.id).where(Binding.server_id.in_(server_ids))
    query = select(Endpoint.id).where(or_(Endpoint.server_id.in_(server_ids), Endpoint.binding_id.in_(bindings)))
    return list(db.scalars(query))


# --- bindings ---------------------------------------------------------------------------------------


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _stored_hash(value: str | None) -> str | None:
    """What fits the ``char(64)`` columns. Matching uses the collector's text unchanged (no case or colon fixes)."""
    return value if value is not None and len(value) == 64 else None


def _mode(value: object) -> int | None:
    try:
        return int(value, 8) & 0o7777 if isinstance(value, str) and value else None
    except ValueError:
        return None


def _webserver(value: object) -> WebserverType | None:
    try:
        return WebserverType(value) if isinstance(value, str) else None
    except ValueError:
        return None


@dataclass(frozen=True)
class _Seen:
    identity: Identity
    vhost_names: list[str]
    values: dict[str, object]
    fingerprint: str | None
    key_hash: str | None
    cert_missing: bool
    key_missing: bool


def _seen(entry: Mapping[str, JSONValue], default_webserver: WebserverType | None) -> _Seen | None:
    """The identity and observed facts of one document binding; ``None`` when it cannot be a binding."""
    webserver = _webserver(entry.get("webserver")) or default_webserver
    vhost, config_file, cert_path = _text(entry.get("vhost_name")), _text(entry.get("config_file")), _text(entry.get("cert_path"))
    port = entry.get("port", 443)
    if webserver is None or not (vhost and config_file and cert_path) or type(port) is not int or not 1 <= port <= 65535:
        return None
    names = entry.get("vhost_names")
    fingerprint = _text(entry.get("cert_fingerprint")) if entry.get("cert_exists") is True else None
    key_hash = _text(entry.get("key_public_sha256")) if entry.get("key_exists") is True else None
    return _Seen(
        (webserver, config_file, port, vhost, cert_path),
        [name for name in names if isinstance(name, str)] if isinstance(names, list) else [vhost],
        {
            "chain_path": _text(entry.get("chain_path")),
            "key_path": _text(entry.get("key_path")) or "",
            "cert_owner": _text(entry.get("cert_owner")),
            "cert_group": _text(entry.get("cert_group")),
            "cert_mode": _mode(entry.get("cert_mode")),
            "key_owner": _text(entry.get("key_owner")),
            "key_group": _text(entry.get("key_group")),
            "key_mode": _mode(entry.get("key_mode")),
            "on_disk_fingerprint": _stored_hash(fingerprint),
            "on_disk_key_public_sha256": _stored_hash(key_hash),
        },
        fingerprint,
        key_hash,
        fingerprint is None,
        key_hash is None or entry.get("key_unreadable") is True,
    )


def _notes(entry: Mapping[str, JSONValue], seen: _Seen) -> str | None:
    parts = [_text(entry.get("chain_diagnostic"))]
    parts += [CERTIFICATE_MISSING] if seen.cert_missing else []
    parts += [KEY_MISSING] if seen.key_missing else []
    return "; ".join(part for part in parts if part)[:_NOTE_LIMIT] or None


def _spki_by_fingerprint(db: Session, fingerprints: set[str]) -> dict[str, tuple[int, str | None]]:
    """``fingerprint -> (certificate id, SPKI hash of its PEM)`` for the inventory rows among ``fingerprints``."""
    if not fingerprints:
        return {}
    rows = db.execute(
        select(Certificate.id, Certificate.sha256_fingerprint, Certificate.pem).where(
            Certificate.sha256_fingerprint.in_(fingerprints)
        )
    )
    found: dict[str, tuple[int, str | None]] = {}
    for row in rows:
        try:
            spki = parse_certificates(row.pem.encode("ascii"))[0].public_key_sha256
        except (ParseError, IndexError, UnicodeError):
            spki = None
        found[row.sha256_fingerprint] = (row.id, spki)
    return found


def _verdict(seen: _Seen, certificates: Mapping[str, tuple[int, str | None]], previous: int | None) -> tuple[str, int | None]:
    if seen.cert_missing or seen.key_missing:
        return "missing_file", previous  # the certificate identified earlier stays attached
    known = certificates.get(seen.fingerprint or "")
    if known is None:
        return "unknown", None
    certificate_id, spki = known
    return ("matched" if spki is not None and spki == seen.key_hash else "key_mismatch"), certificate_id


def reconcile_host(
    db: Session,
    server_id: int,
    document: Mapping[str, JSONValue],
    *,
    job_id: UUID,
    actor: Actor,
    now: datetime,
) -> ReconcileOutcome:
    """Apply one host document (spec 6.3) to the server's bindings and derived endpoints.

    Locks the server row and commits nothing. ``last_seen_at`` is ``now`` (the discovery time), and every insert
    or change of a binding's (state, fingerprint, active) triple is audited through ``audit_binding_state``.
    """
    server = db.get(Server, server_id, with_for_update=True)
    if server is None:
        raise LookupError(server_id)
    server.last_discovery_at = now
    server.last_discovery_status = "ok"
    default_webserver = _webserver(document.get("webserver"))
    if default_webserver is not None:
        server.webserver = default_webserver
    raw = document.get("bindings")
    seen_items = [
        (entry, item)
        for entry in (raw if isinstance(raw, list) else [])
        if isinstance(entry, Mapping) and (item := _seen(entry, default_webserver)) is not None
    ]
    existing = {
        (b.webserver, b.config_file, b.port, b.vhost_name, b.cert_path): b
        for b in db.scalars(select(Binding).where(Binding.server_id == server_id).order_by(Binding.id))
    }
    if not seen_items and any(b.is_active for b in existing.values()):
        db.flush()
        return ReconcileOutcome(0, 0, 0, 0, 0, True)  # an empty dump of a populated host is a parse failure
    certificates = _spki_by_fingerprint(db, {item.fingerprint for _, item in seen_items if item.fingerprint})
    added = updated = unchanged = endpoints_created = 0
    present: set[Identity] = set()
    current: dict[int, Endpoint | None] = {}
    job = str(job_id)
    for entry, item in seen_items:
        present.add(item.identity)
        binding = existing.get(item.identity)
        previous = binding_state(binding) if binding is not None else None
        state, certificate_id = _verdict(item, certificates, binding.certificate_id if binding else None)
        values = {
            **item.values,
            "vhost_names": item.vhost_names,
            "match_state": state,
            "certificate_id": certificate_id,
            "is_active": True,
            "notes": _notes(entry, item),
        }
        if binding is None:
            webserver, config_file, port, vhost, cert_path = item.identity
            binding = Binding(
                server_id=server_id,
                webserver=webserver,
                config_file=config_file,
                port=port,
                vhost_name=vhost,
                cert_path=cert_path,
                last_seen_at=now,
                **values,
            )
            db.add(binding)
            existing[item.identity] = binding
            added += 1
        else:
            if any(getattr(binding, name) != value for name, value in values.items()):
                updated += 1
            else:
                unchanged += 1
            for name, value in values.items():
                setattr(binding, name, value)
            binding.last_seen_at = now
        db.flush()
        audit_binding_state(db, binding, previous, actor, job_id=job, now=now)
        try:
            current[binding.id], created = ensure_binding_endpoint(db, binding, server, actor)
        except EndpointInputError:
            current[binding.id] = None  # an address that cannot be scanned (not a DNS name or IP literal): no endpoint
            continue
        endpoints_created += created
        if state == "unknown" and previous is not None and previous.match_state != "unknown":
            # the certificate is no longer inventoried: the endpoint reports mismatch until one is set (§4.10).
            # Only on the transition, so an expectation an operator set on an unknown binding's endpoint survives.
            expect_for_binding(db, binding.id, None, actor)
    deactivated = 0
    for identity, binding in existing.items():
        if identity in present or not binding.is_active:
            continue
        previous = binding_state(binding)
        binding.is_active = False
        binding.notes = f"removed from config at {_date(now)}"
        db.flush()
        audit_binding_state(db, binding, previous, actor, job_id=job, now=now)
        deactivated += 1
    db.flush()
    # Last, once every binding is final: ownership, expectation and activity of every endpoint this host touches or
    # owned (a removed binding, a changed address or server name) follow the bindings that derive it, across servers.
    touched = {endpoint.id for endpoint in current.values() if endpoint is not None}
    settle_endpoints(db, touched | set(_owned_by(db, [server_id])), actor, job_id=job)
    db.flush()
    return ReconcileOutcome(added, updated, deactivated, unchanged, endpoints_created, False)
