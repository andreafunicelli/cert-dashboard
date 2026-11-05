"""Inventory source vocabulary and renderers (Slice B decisions D1/D2/D6; card W, contract §7).

A host is either *manual* (created in the dashboard, ``inventory_source = 'manual'``) or belongs to the
configured Git inventory, whose marker is the revision triple ``<ref>:<path>@<sha>``. Git stays
authoritative for every hostname it lists; a manual row is adopted on reconciliation. No repository is
required for manual hosts to be discovered or deployed to, so this module also renders the two inputs a
worker job needs from the dashboard's own data:

* :func:`render_inventory` — the YAML inventory of the active manual hosts (contract §7.1);
* :func:`render_known_hosts` — the mounted known_hosts file followed by one line per dashboard-trusted
  host key (contract §7.4).

Both renderers are pure and dependency-free on purpose, and both **refuse** (raise) any value that
could escape its YAML scalar or known_hosts line: a leading ``-`` (an option), whitespace, a newline or
a control character. Inputs are validated upstream by the Inventory and SSH-keys screens; this is the
defence in depth behind them (contract §7.5), never the first line.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from app.models.ssh_host_key import SSH_HOST_KEY_TYPES

MANUAL_SOURCE = "manual"

# The one sentence the worker failure, the capability banner and the Settings → Status warning share when
# neither a repository nor an active manual host exists (contract §7.2).
NO_INVENTORY = "No inventory: add a host in Inventory or configure a repository."

# Ansible's own default SSH port: rendering ``ansible_port: 22`` would change nothing.
DEFAULT_SSH_PORT = 22
# Host variables this module writes itself; a ``inventory.webserver_var`` with one of these names would
# silently overwrite the connection setting.
_RESERVED_HOST_VARS = frozenset({"ansible_host", "ansible_port", "ansible_user"})
_PSEUDO_GROUPS = frozenset({"all", "ungrouped"})


class InventoryRenderError(ValueError):
    """A value that cannot be rendered safely. The message never repeats the value itself."""


def is_manual(source: str | None) -> bool:
    """True only for the manual marker: every other value is a repository revision."""
    return source == MANUAL_SOURCE


@dataclass(frozen=True)
class ManualHost:
    """One active manual ``server`` row as the inventory renderer sees it."""

    hostname: str
    groups: tuple[str, ...] = ()
    connection_address: str | None = None
    webserver: str | None = None


@dataclass(frozen=True)
class HostKey:
    """One ``ssh_host_key`` row: a host token, an SSH key type and its base64 public key."""

    host: str
    key_type: str
    public_key: str


def _token(value: object, what: str) -> str:
    """``value`` as a renderable token, or :class:`InventoryRenderError`.

    Refused: not a string, empty, a leading ``-`` (an option), any whitespace and any control character.
    """
    if not isinstance(value, str) or not value:
        raise InventoryRenderError(f"{what} is empty")
    if value.startswith("-"):
        raise InventoryRenderError(f"{what} starts with a dash")
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        raise InventoryRenderError(f"{what} contains whitespace or a control character")
    return value


def _port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise InventoryRenderError("the SSH port is not a port number")
    return value


def _quote(value: str) -> str:
    """A JSON string, which is also a YAML scalar: quoted, so ``on``/``22``/``1.2`` stay text."""
    return json.dumps(value, ensure_ascii=True)


def _host_variables(
    host: ManualHost, variable: str, ssh_user: str | None, ssh_port: int | None
) -> list[tuple[str, str]]:
    """The host variables of one manual host, ordered by name so the file is reproducible."""
    variables: list[tuple[str, str]] = []
    if host.connection_address:
        variables.append(("ansible_host", _quote(_token(host.connection_address, "the connection address"))))
    if ssh_user:
        variables.append(("ansible_user", _quote(ssh_user)))
    if ssh_port is not None and ssh_port != DEFAULT_SSH_PORT:
        variables.append(("ansible_port", str(ssh_port)))
    if host.webserver:
        variables.append((variable, _quote(_token(host.webserver, "the web server"))))
    return sorted(variables, key=lambda item: item[0])


def _host_block(lines: list[str], hostname: str, variables: Sequence[tuple[str, str]], indent: int) -> None:
    pad = " " * indent
    if not variables:
        lines.append(f"{pad}{_quote(hostname)}: {{}}")
        return
    lines.append(f"{pad}{_quote(hostname)}:")
    lines.extend(f"{pad}  {name}: {value}" for name, value in variables)


def render_inventory(
    hosts: Sequence[ManualHost],
    *,
    webserver_var: str,
    ssh_user: str | None = None,
    ssh_port: int | None = None,
) -> str:
    """The YAML inventory of these manual hosts (contract §7.1), deterministic and injection-safe.

    Grouped hosts sit under every one of their groups, ungrouped hosts under ``all.hosts``;
    ``ansible_host`` carries the connection address when set, the ``inventory.webserver_var`` host
    variable the web server when set, and ``ansible_user`` / ``ansible_port`` only when configured.
    """
    variable = _token(webserver_var, "the web server variable name")
    if variable in _RESERVED_HOST_VARS:
        raise InventoryRenderError("the web server variable name is reserved by Ansible")
    user = _token(ssh_user, "the SSH user") if ssh_user else None
    port = _port(ssh_port) if ssh_port is not None else None

    specs: dict[str, list[tuple[str, str]]] = {}
    groups: dict[str, list[str]] = {}
    ungrouped: list[str] = []
    for host in hosts:
        hostname = _token(host.hostname, "a hostname")
        if hostname in specs:
            raise InventoryRenderError("the inventory contains the same hostname twice")
        names: list[str] = []
        for group in host.groups:
            name = _token(group, "a group name")
            if name in _PSEUDO_GROUPS:
                raise InventoryRenderError("an Ansible pseudo group cannot be set per host")
            if name not in names:
                names.append(name)
        specs[hostname] = _host_variables(host, variable, user, port)
        for name in names:
            groups.setdefault(name, []).append(hostname)
        if not names:
            ungrouped.append(hostname)

    lines: list[str] = []
    if specs:
        lines.append("all:")
        if groups:
            lines.append("  children:")
            for name in sorted(groups):
                lines.append(f"    {_quote(name)}:")
                lines.append("      hosts:")
                for hostname in sorted(groups[name]):
                    _host_block(lines, hostname, specs[hostname], 8)
        if ungrouped:
            lines.append("  hosts:")
            for hostname in sorted(ungrouped):
                _host_block(lines, hostname, specs[hostname], 4)
    return "\n".join(lines) + "\n" if lines else "{}\n"


def render_known_hosts(mounted: bytes | None, rows: Iterable[HostKey]) -> bytes:
    """The mounted file's content followed by one ``host key_type public_key`` line per row.

    An empty result means there is nothing to trust; the caller decides whether that is a failure by
    asking whether the mounted file exists at all (contract §7.4: the failure applies only when the file
    is absent **and** no key is trusted). The mounted file is read, never written: its bytes are a prefix
    of the result, unchanged except for the final newline the result needs to start a new line.
    """
    text = mounted or b""
    if text and not text.endswith(b"\n"):
        text += b"\n"
    entries: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        host = _token(row.host, "a trusted host")
        if row.key_type not in SSH_HOST_KEY_TYPES:
            raise InventoryRenderError("a trusted host key has an unsupported type")
        if (host, row.key_type) in seen:
            raise InventoryRenderError("the same host trusts the same key type twice")
        seen.add((host, row.key_type))
        entries.append((host, row.key_type, _token(row.public_key, "a trusted public key")))
    entries.sort()
    return text + b"".join(f"{host} {key_type} {public_key}\n".encode() for host, key_type, public_key in entries)
