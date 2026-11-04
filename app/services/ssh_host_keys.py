"""Trusted SSH host keys (Slice B contract §6): parse, validate, store and remove.

The dashboard trusts a host key only after an administrator pasted it and attested that the
fingerprint was compared with the server through an independent channel. This module owns the
rules for that paste: accepted key types, strict base64, the fingerprint format ``ssh-keygen -lf``
prints, host-token normalization, duplicate protection and all-or-nothing refusal. Nothing here
accepts a private key, and no refusal ever echoes the pasted text.

Rows are public material only and immutable (the table grants no ``UPDATE``); removal deletes the
row and writes the audit history. The web layer supplies the CSRF-checked form values and renders
the returned field errors.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import SshHostKey, User
from app.models.ssh_host_key import SSH_HOST_KEY_TYPES
from app.services.audit import Actor, record
from app.services.settings import get_setting

__all__ = [
    "ACCEPTED_KEY_TYPES",
    "MAX_COMMENT",
    "MAX_PASTE_BYTES",
    "VERIFIED_MESSAGE",
    "HostKeyNotFound",
    "HostKeyValidationError",
    "ParsedHostKey",
    "RemovedHostKey",
    "add_host_keys",
    "parse_host_keys",
    "remove_host_key",
    "short_host",
]

ACCEPTED_KEY_TYPES = SSH_HOST_KEY_TYPES
MAX_PASTE_BYTES = 16 * 1024
MAX_LINES = 20
MAX_HOSTS_PER_LINE = 20
MAX_COMMENT = 100

PASTE_COUNT_MESSAGE = "Paste between 1 and 20 host keys."
PRIVATE_KEY_MESSAGE = (
    "This looks like a private key. Paste the host's public key (for example the output of "
    "ssh-keyscan); private keys are never accepted here."
)
HOST_REQUIRED_MESSAGE = "Enter the host this key belongs to."
MARKERS_MESSAGE = "Certificate-authority and revoked entries are not supported."
HASHED_MESSAGE = "Hashed host names are not supported; run ssh-keyscan without -H."
PATTERNS_MESSAGE = "Host patterns are not supported; list each host."
TOO_MANY_HOSTS_MESSAGE = "At most 20 hosts per line."
HOST_SYNTAX_MESSAGE = (
    "Use letters, digits, dots, hyphens or underscores (or an IP address); "
    "a label cannot start or end with a hyphen."
)
BAD_PORT_MESSAGE = "Host ports must be between 1 and 65535."
UNSUPPORTED_TYPE_MESSAGE = (
    "Unsupported key type {key_type}. Accepted: ssh-ed25519, ecdsa-sha2-nistp256, "
    "ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-rsa."
)
BAD_BASE64_MESSAGE = "The key data is not valid base64."
TYPE_MISMATCH_MESSAGE = "The key data does not match its type {key_type}."
INVALID_KEY_MESSAGE = "The key data is not a valid SSH public key."
RSA_SHORT_MESSAGE = "RSA host keys shorter than 2048 bits are refused."
COMMENT_TOO_LONG_MESSAGE = "Comment must be at most 100 characters."
VERIFIED_MESSAGE = "Confirm that you verified the fingerprints with the server before trusting them."
RETRY_MESSAGE = "The key could not be stored because another change was in progress. Try again."

_KEY_TYPE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._+-]*", re.ASCII)
_HOST_LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?", re.ASCII)


@dataclass(frozen=True)
class ParsedHostKey:
    """One validated host/type/blob triple; ``line`` is the textarea line it came from."""

    host: str
    key_type: str
    public_key: str
    fingerprint_sha256: str
    comment: str | None
    line: int


@dataclass(frozen=True)
class RemovedHostKey:
    """What the delete flash may name: no key material beyond the public fingerprint."""

    id: int
    host: str
    key_type: str
    fingerprint_sha256: str


class HostKeyValidationError(ValueError):
    """A refused submission: field name → messages, plus whether the paste must be discarded.

    ``discard_paste`` is set by rule 2: a private key is never re-rendered, logged or echoed.
    """

    def __init__(self, errors: dict[str, list[str]], *, discard_paste: bool = False) -> None:
        super().__init__("The host keys were refused.")
        self.errors = errors
        self.discard_paste = discard_paste


class HostKeyNotFound(LookupError):
    """No trusted host key has this id."""


class _LineError(ValueError):
    """One line's refusal; the parser prefixes it with ``Line <n>:``."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class _HostError(ValueError):
    """One host token's refusal with its user-facing message."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


# --- rule-driven parsing ---------------------------------------------------------------------------


def parse_host_keys(entries: str, hosts: str = "", comment: str = "") -> list[ParsedHostKey]:
    """Validate one paste and return every accepted host key, or raise the field errors.

    Pure: no database, no clock, no request. Rule 1–9 of the contract live here; rule 10 (the
    ``verified`` attestation) is enforced by :func:`add_host_keys` before anything is stored.
    """
    if "PRIVATE KEY" in entries.upper():
        # Rule 2 comes first: the text must never be counted, logged or re-rendered anywhere.
        raise HostKeyValidationError({"entries": [PRIVATE_KEY_MESSAGE]}, discard_paste=True)
    if len(entries.encode("utf-8")) > MAX_PASTE_BYTES:
        raise HostKeyValidationError({"entries": [PASTE_COUNT_MESSAGE]})

    numbered = [(number, line.strip()) for number, line in enumerate(entries.splitlines(), 1)]
    lines = [(number, line) for number, line in numbered if line and not line.startswith("#")]
    if not 1 <= len(lines) <= MAX_LINES:
        raise HostKeyValidationError({"entries": [PASTE_COUNT_MESSAGE]})

    form_comment = comment.strip()
    if len(form_comment) > MAX_COMMENT:
        raise HostKeyValidationError({"comment": [COMMENT_TOO_LONG_MESSAGE]})

    line_errors: list[tuple[int, str]] = []
    parsed: list[ParsedHostKey] = []
    seen: dict[tuple[str, str], ParsedHostKey] = {}
    for number, line in lines:
        try:
            keys = _parse_line(number, line, hosts, form_comment)
        except _LineError as exc:
            line_errors.append((number, exc.message))
            continue
        for key in keys:
            existing = seen.get((key.host, key.key_type))
            if existing is None:
                seen[(key.host, key.key_type)] = key
                parsed.append(key)
            elif existing.public_key != key.public_key:
                line_errors.append(
                    (
                        number,
                        _different_key_message(key.host, key.key_type, existing.fingerprint_sha256),
                    )
                )
    if line_errors:
        raise HostKeyValidationError(
            {"entries": [f"Line {number}: {message}" for number, message in line_errors]}
        )
    return parsed


def _parse_line(number: int, line: str, hosts_field: str, form_comment: str) -> list[ParsedHostKey]:
    if line.startswith(("@cert-authority", "@revoked")):
        raise _LineError(MARKERS_MESSAGE)
    tokens = line.split()
    if tokens[0].startswith("@"):
        raise _LineError(MARKERS_MESSAGE)
    if tokens[0].startswith("|"):
        raise _LineError(HASHED_MESSAGE)

    if len(tokens) >= 2 and _looks_like_key_type(tokens[1]):
        host_tokens = tokens[0]
        key_type = tokens[1]
        data = tokens[2] if len(tokens) > 2 else ""
        line_comment = " ".join(tokens[3:])
    else:
        host_tokens = hosts_field
        key_type = tokens[0]
        data = tokens[1] if len(tokens) > 1 else ""
        line_comment = " ".join(tokens[2:])

    try:
        normalized_hosts = _parse_hosts(host_tokens)
    except _HostError as exc:
        raise _LineError(exc.message) from None
    if key_type not in ACCEPTED_KEY_TYPES:
        raise _LineError(UNSUPPORTED_TYPE_MESSAGE.format(key_type=key_type))
    blob = _decode_blob(data, key_type)

    effective_comment = form_comment or line_comment.strip()
    if len(effective_comment) > MAX_COMMENT:
        raise _LineError(COMMENT_TOO_LONG_MESSAGE)
    comment = effective_comment or None
    canonical = base64.b64encode(blob).decode("ascii")
    fingerprint = fingerprint_sha256(blob)
    return [
        ParsedHostKey(host, key_type, canonical, fingerprint, comment, number)
        for host in normalized_hosts
    ]


def _parse_hosts(raw: str) -> list[str]:
    tokens = [token.strip() for token in raw.split(",") if token.strip()]
    if not tokens:
        raise _HostError(HOST_REQUIRED_MESSAGE)
    if len(tokens) > MAX_HOSTS_PER_LINE:
        raise _HostError(TOO_MANY_HOSTS_MESSAGE)
    return [_parse_host_token(token) for token in tokens]


def _parse_host_token(token: str) -> str:
    candidate = token.strip().lower()
    if any(char in candidate for char in "*?!"):
        raise _HostError(PATTERNS_MESSAGE)
    port: int | None = None
    host = candidate
    if candidate.startswith("["):
        end = candidate.find("]")
        if end == -1:
            raise _HostError(HOST_SYNTAX_MESSAGE)
        host = candidate[1:end]
        rest = candidate[end + 1 :]
        if rest:
            if not rest.startswith(":") or not rest[1:].isdigit():
                raise _HostError(HOST_SYNTAX_MESSAGE)
            port = int(rest[1:])
            if not 1 <= port <= 65535:
                raise _HostError(BAD_PORT_MESSAGE)
    elif ":" in candidate:
        # A bare IPv6 literal; ``host:port`` must be written ``[host]:port``.
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            raise _HostError(HOST_SYNTAX_MESSAGE) from None
        return candidate
    if not _valid_host(host):
        raise _HostError(HOST_SYNTAX_MESSAGE)
    if port is None or port == 22:
        return host
    return f"[{host}]:{port}"


def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if not 1 <= len(host) <= 253:
        return False
    labels = host.split(".")
    return all(_HOST_LABEL.fullmatch(label) for label in labels)


def _looks_like_key_type(token: str) -> bool:
    """True for the token that names an SSH key type (every accepted and refused type has a ``-``).

    Standard base64 never contains ``-``, so a public-key line's blob is never mistaken for a type.
    """
    return "-" in token and _KEY_TYPE_TOKEN.fullmatch(token) is not None


def _decode_blob(data: str, key_type: str) -> bytes:
    try:
        blob = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise _LineError(BAD_BASE64_MESSAGE) from None
    if not blob:
        raise _LineError(BAD_BASE64_MESSAGE)
    if len(blob) < 4:
        raise _LineError(TYPE_MISMATCH_MESSAGE.format(key_type=key_type))
    length = int.from_bytes(blob[:4], "big")
    if length <= 0 or 4 + length > len(blob) or blob[4 : 4 + length] != key_type.encode("ascii", "ignore"):
        raise _LineError(TYPE_MISMATCH_MESSAGE.format(key_type=key_type))
    try:
        public = serialization.load_ssh_public_key(
            key_type.encode("ascii") + b" " + base64.b64encode(blob)
        )
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise _LineError(INVALID_KEY_MESSAGE) from None
    if isinstance(public, rsa.RSAPublicKey) and public.key_size < 2048:
        raise _LineError(RSA_SHORT_MESSAGE)
    return blob


def fingerprint_sha256(blob: bytes) -> str:
    """The ``ssh-keygen -lf`` display fingerprint: ``SHA256:`` + unpadded base64 of SHA-256(blob)."""
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _different_key_message(host: str, key_type: str, fingerprint: str) -> str:
    return (
        f"{host} already has a different trusted {key_type} key ({fingerprint}). "
        "If the host key was rotated, delete the old key first."
    )


# --- transactional store ---------------------------------------------------------------------------


def add_host_keys(
    db: Session,
    *,
    entries: str,
    hosts: str = "",
    comment: str = "",
    verified: str = "",
    actor: Actor,
) -> list[ParsedHostKey]:
    """Store every parsed key in the caller's transaction, or store none and raise.

    Rule 10 is part of this transaction: without ``verified=1`` nothing is parsed into rows and
    nothing is stored. Duplicates are refused against the database and the unique constraint is
    the concurrency backstop; an ``IntegrityError`` is mapped to the same messages.
    """
    errors: dict[str, list[str]] = {}
    parsed: list[ParsedHostKey] = []
    discard_paste = False
    try:
        parsed = parse_host_keys(entries, hosts=hosts, comment=comment)
    except HostKeyValidationError as exc:
        errors.update(exc.errors)
        discard_paste = exc.discard_paste
    if verified != "1":
        errors.setdefault("verified", []).append(VERIFIED_MESSAGE)
    if errors:
        raise HostKeyValidationError(errors, discard_paste=discard_paste)

    timezone_name = _display_timezone(db)
    duplicates = _database_duplicates(db, parsed, timezone_name)
    if duplicates:
        raise HostKeyValidationError({"entries": duplicates})

    rows: list[tuple[SshHostKey, ParsedHostKey]] = []
    for key in parsed:
        row = SshHostKey(
            host=key.host,
            key_type=key.key_type,
            public_key=key.public_key,
            fingerprint_sha256=key.fingerprint_sha256,
            comment=key.comment,
            created_by=actor.user_id,
        )
        db.add(row)
        rows.append((row, key))
    try:
        db.flush()
    except IntegrityError:
        # The unique constraint caught a concurrent insert. Roll back (the transaction holds only
        # this mutation), then report it through the same messages the pre-check produces.
        db.rollback()
        conflicts = _database_duplicates(db, parsed, timezone_name)
        raise HostKeyValidationError({"entries": conflicts or [RETRY_MESSAGE]}) from None

    for row, key in rows:
        record(
            db,
            actor,
            "ssh_host_key.add",
            "ssh_host_key",
            str(row.id),
            {
                "host": key.host,
                "key_type": key.key_type,
                "fingerprint": key.fingerprint_sha256,
                "verified": True,
            },
        )
    return [key for _, key in rows]


def remove_host_key(db: Session, key_id: int, actor: Actor) -> RemovedHostKey:
    """Delete one trusted key and stage its audit row; unknown ids raise :class:`HostKeyNotFound`."""
    row = db.get(SshHostKey, key_id)
    if row is None:
        raise HostKeyNotFound(key_id)
    removed = RemovedHostKey(row.id, row.host, row.key_type, row.fingerprint_sha256)
    record(
        db,
        actor,
        "ssh_host_key.remove",
        "ssh_host_key",
        str(row.id),
        {"host": row.host, "key_type": row.key_type, "fingerprint": row.fingerprint_sha256},
    )
    db.delete(row)
    return removed


def short_host(host: str) -> str:
    """The host token as flashes name it: at most 64 characters, so the flash never truncates."""
    return host[:63] + "…" if len(host) > 64 else host


def _database_duplicates(
    db: Session, parsed: list[ParsedHostKey], timezone_name: str
) -> list[str]:
    if not parsed:
        return []
    pairs = sorted({(key.host, key.key_type) for key in parsed})
    rows = db.execute(
        select(SshHostKey, User.username)
        .outerjoin(User, User.id == SshHostKey.created_by)
        .where(tuple_(SshHostKey.host, SshHostKey.key_type).in_(pairs))
    ).all()
    existing = {(row[0].host, row[0].key_type): row for row in rows}
    messages: list[str] = []
    for key in parsed:
        found = existing.get((key.host, key.key_type))
        if found is None:
            continue
        row, username = found
        if row.public_key == key.public_key:
            messages.append(
                f"{key.host} already trusts this {key.key_type} key ({row.fingerprint_sha256}), "
                f"added {_date(row.created_at, timezone_name)} by {username or 'an unknown administrator'}."
            )
        else:
            messages.append(_different_key_message(key.host, key.key_type, row.fingerprint_sha256))
    return messages


def _date(value: datetime, timezone_name: str) -> str:
    return value.astimezone(ZoneInfo(timezone_name)).strftime("%Y-%m-%d")


def _display_timezone(db: Session) -> str:
    """``ui.timezone`` when it names a real zone, otherwise UTC (same rule as the web layer)."""
    value = get_setting(db, "ui.timezone")
    if isinstance(value, str) and value:
        try:
            ZoneInfo(value)
        except (KeyError, ValueError, OSError):
            return "UTC"
        return value
    return "UTC"
