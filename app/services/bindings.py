"""Append-only audit of a binding's match state (§4.16, Plan 2 Contract decision 22).

The digest's "unknown certificates found by discovery" signal cannot come from ``binding.created_at``:
reconciliation updates an existing binding from ``matched`` to ``unknown`` in place. Plan 3's
reconciliation therefore calls ``audit_binding_state`` for every binding it inserts or updates, in the
same per-server transaction as the change, and no other code path changes ``match_state``,
``on_disk_fingerprint`` or ``is_active`` without calling it.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address

from sqlalchemy.orm import Session

from app.models import AuditLog, Binding
from app.services.audit import Actor, record

BINDING_STATE_ACTION = "binding.match_state"

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_PLAIN_NAME = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")
_PLACEHOLDERS = frozenset({"default", "_"})


def _is_plain_name(name: str) -> bool:
    if len(name) > 253 or name.lower() in _PLACEHOLDERS or _PLAIN_NAME.fullmatch(name) is None:
        return False
    try:
        ip_address(name)
    except ValueError:
        return True
    return False  # an IPv4 literal is not a server name


def verify_sni(vhost_name: str, vhost_names: Sequence[str]) -> str | None:
    """The first plain DNS name of a vhost (its own name first), usable as SNI; ``None`` when there is none.

    Wildcards, the ``default``/``_`` placeholders and IP literals are not server names a client can ask for.
    """
    return next((name for name in (vhost_name, *vhost_names) if _is_plain_name(name)), None)


@dataclass(frozen=True)
class BindingState:
    match_state: str
    on_disk_fingerprint: str | None
    is_active: bool


def binding_state(binding: Binding) -> BindingState:
    return BindingState(binding.match_state, binding.on_disk_fingerprint, bool(binding.is_active))


def audit_binding_state(
    db: Session,
    binding: Binding,
    previous: BindingState | None,
    actor: Actor,
    *,
    job_id: str | None,
    now: datetime,
) -> AuditLog | None:
    """Stage one audit row when the binding was inserted (``previous=None``) or its triple changed.

    The binding must already be flushed (its id is the audit target). Details are metadata only,
    never ``notes`` or paths. ``created_at`` takes ``now`` so audit times share the worker clock
    with ``notification_log.sent_at``. Never flushes or commits.
    """
    current = binding_state(binding)
    if current == previous:
        return None
    if binding.id is None:
        raise ValueError("flush the binding before auditing its state")
    row = record(
        db,
        actor,
        BINDING_STATE_ACTION,
        "binding",
        str(binding.id),
        {
            "from_state": previous.match_state if previous else None,
            "from_fingerprint": previous.on_disk_fingerprint if previous else None,
            "was_active": previous.is_active if previous else False,
            "to_state": current.match_state,
            "on_disk_fingerprint": current.on_disk_fingerprint,
            "is_active": current.is_active,
            "server_id": binding.server_id,
            "job_id": job_id,
        },
    )
    row.created_at = now
    return row
