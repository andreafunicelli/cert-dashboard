"""SSH public keys registered in the dashboard: labels, fingerprints and duplicate protection.

The worker's *private* key keeps its own contract (``services.worker_credentials``: sealed at rest, never
rendered, resolved when a job runs). What this module adds is the public half an operator needs inside the
dashboard: the authorized keys to install on managed servers, each with a label and a fingerprint that can
be compared with ``ssh-keygen -lf``. Only public material is accepted — a pasted private key is refused
with a message that says so, without echoing it — and a key already registered is refused by fingerprint,
so the same key cannot appear twice under two labels.

Parsing uses ``cryptography`` (already a dependency) and normalizes every accepted key to one OpenSSH line
(``type base64 [comment]``), which is exactly the form ``authorized_keys`` expects. The stored fingerprint is
SHA-256 over the DER SubjectPublicKeyInfo — the same identity the rest of the application uses for keys — and
the OpenSSH display fingerprint is derived from the stored line at read time, so there is one source of truth.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import SSHPublicKey, User
from app.services.audit import Actor, record

__all__ = [
    "MAX_KEY_BYTES",
    "MAX_LABEL",
    "PublicKeyMaterial",
    "SSHKeyError",
    "SSHKeyNotFound",
    "SSHKeyRow",
    "add_key",
    "delete_key",
    "list_keys",
    "parse_label",
    "parse_public_key",
]

MAX_KEY_BYTES = 8192
MAX_LABEL = 64
MAX_COMMENT = 128
_OPENSSH_PREFIXES = ("ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-")
_FORMAT = (
    "Paste an SSH public key: one line beginning with ssh-ed25519, ssh-rsa, ecdsa-sha2-… "
    "(the contents of the .pub file)."
)
_PRIVATE = (
    "That is a private key: paste the matching public key (the .pub file). "
    "Private keys are never accepted here."
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class SSHKeyError(ValueError):
    """A refused key or label. ``field`` names the input; ``message`` is user-facing."""

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        self.message = message
        super().__init__(message)


class SSHKeyNotFound(LookupError):
    """No registered key has this id."""


@dataclass(frozen=True)
class PublicKeyMaterial:
    """One validated key: the normalized line plus the two fingerprints an operator compares."""

    key_type: str
    public_key: str
    comment: str
    bits: int | None
    fingerprint_sha256: str
    fingerprint_openssh: str


@dataclass(frozen=True)
class SSHKeyRow:
    """A registered key as the list renders it."""

    id: int
    label: str
    key_type: str
    public_key: str
    comment: str
    bits: int | None
    fingerprint_sha256: str
    fingerprint_openssh: str
    created_at: datetime | None
    created_by: str | None


# --- pure validation -------------------------------------------------------------------------------


def parse_label(value: object) -> str:
    """A trimmed 1..64 character label with no control characters."""
    text = value.strip() if isinstance(value, str) else ""
    if not text:
        raise SSHKeyError("label", "Give the key a label, for example “Ansible production”.")
    if len(text) > MAX_LABEL:
        raise SSHKeyError("label", f"The label must be at most {MAX_LABEL} characters.")
    if _CONTROL.search(text):
        raise SSHKeyError("label", "The label cannot contain control characters.")
    return text


def _bits(key: PublicKeyTypes) -> int | None:
    size = getattr(key, "key_size", None)
    return size if isinstance(size, int) else None


def _der_fingerprint(key: PublicKeyTypes) -> str:
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _openssh_line(key: PublicKeyTypes) -> str:
    return key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode("ascii")


def _openssh_fingerprint(line: str) -> str:
    """``SHA256:<base64>`` exactly as ``ssh-keygen -lf`` prints it: SHA-256 of the wire-format blob."""
    blob = base64.b64decode(line.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def _comment(raw: str) -> str:
    text = _CONTROL.sub(" ", raw).strip()
    return text[:MAX_COMMENT]


def _public(value: str) -> tuple[PublicKeyTypes, str]:
    """The key object and the comment carried by the input line (empty for PEM input)."""
    first = value.splitlines()[0]
    if first.startswith("-----BEGIN"):
        if "PRIVATE" in first:
            raise SSHKeyError("public_key", _PRIVATE)
        if "PUBLIC KEY" not in first:
            raise SSHKeyError("public_key", _FORMAT)
        try:
            key = serialization.load_pem_public_key(value.encode("utf-8"))
        except (ValueError, UnsupportedAlgorithm):
            raise SSHKeyError("public_key", _FORMAT) from None
        return key, ""
    line = " ".join(value.split())
    if not line.startswith(_OPENSSH_PREFIXES):
        raise SSHKeyError("public_key", _FORMAT)
    try:
        key = serialization.load_ssh_public_key(line.encode("utf-8"))
    except (ValueError, UnsupportedAlgorithm, IndexError):
        raise SSHKeyError("public_key", _FORMAT) from None
    parts = line.split(" ", 2)
    return key, parts[2] if len(parts) == 3 else ""


def parse_public_key(value: object) -> PublicKeyMaterial:
    """Validate one pasted public key and normalize it; raise :class:`SSHKeyError` otherwise."""
    if not isinstance(value, str):
        raise SSHKeyError("public_key", _FORMAT)
    # Windows pastes arrive with CRLF; normalize before the line count and the control-character check.
    raw = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not raw:
        raise SSHKeyError("public_key", "Paste an SSH public key, for example the contents of id_ed25519.pub.")
    if len(raw.encode("utf-8")) > MAX_KEY_BYTES:
        raise SSHKeyError("public_key", f"The key is too long: at most {MAX_KEY_BYTES} bytes.")
    if not raw.startswith("-----BEGIN"):
        # One line only: pasting a whole authorized_keys file must not silently register its first key.
        submitted = [line for line in raw.splitlines() if line.strip()]
        if len(submitted) > 1:
            raise SSHKeyError(
                "public_key", f"Paste one key at a time: {len(submitted)} lines were submitted. {_FORMAT}"
            )
        # Any whitespace run is a separator in the OpenSSH format, so tabs collapse before the control check.
        raw = " ".join(raw.split())
    if _CONTROL.search(raw.replace("\n", "")):
        raise SSHKeyError("public_key", _FORMAT)
    key, comment = _public(raw)
    line = _openssh_line(key)
    comment = _comment(comment)
    return PublicKeyMaterial(
        key_type=line.split(" ", 1)[0],
        public_key=f"{line} {comment}".strip(),
        comment=comment,
        bits=_bits(key),
        fingerprint_sha256=_der_fingerprint(key),
        fingerprint_openssh=_openssh_fingerprint(line),
    )


def _derived(public_key: str, fingerprint_sha256: str) -> tuple[str, int | None, str, str]:
    """Best-effort (type, bits, OpenSSH fingerprint, comment) for a stored row, without trusting the parse."""
    try:
        material = parse_public_key(public_key)
    except SSHKeyError:
        return "", None, fingerprint_sha256, ""
    return material.key_type, material.bits, material.fingerprint_openssh, material.comment


# --- reads and mutations ---------------------------------------------------------------------------


def list_keys(db: Session) -> list[SSHKeyRow]:
    """Every registered key, ordered by label, with its derived fingerprints."""
    rows = db.execute(
        select(
            SSHPublicKey.id,
            SSHPublicKey.label,
            SSHPublicKey.public_key,
            SSHPublicKey.key_type,
            SSHPublicKey.fingerprint_sha256,
            SSHPublicKey.created_at,
            SSHPublicKey.created_by,
        ).order_by(func.lower(SSHPublicKey.label), SSHPublicKey.id)
    ).all()
    users = _labels(db, {row.created_by for row in rows if row.created_by is not None})
    result = []
    for row in rows:
        key_type, bits, fingerprint_openssh, comment = _derived(row.public_key, row.fingerprint_sha256)
        result.append(
            SSHKeyRow(
                id=row.id,
                label=row.label,
                key_type=row.key_type or key_type,
                public_key=row.public_key,
                comment=comment,
                bits=bits,
                fingerprint_sha256=row.fingerprint_sha256,
                fingerprint_openssh=fingerprint_openssh,
                created_at=row.created_at,
                created_by=users.get(row.created_by),
            )
        )
    return result


def _labels(db: Session, user_ids: set[int]) -> dict[int, str]:
    if not user_ids:
        return {}
    return dict(db.execute(select(User.id, User.username).where(User.id.in_(user_ids))).all())


def add_key(db: Session, label: object, value: object, actor: Actor) -> SSHPublicKey:
    """Register one key; refuse a duplicate key (by fingerprint) or a duplicate label with a clear message."""
    parsed_label = parse_label(label)
    material = parse_public_key(value)
    existing = db.scalars(
        select(SSHPublicKey).where(SSHPublicKey.fingerprint_sha256 == material.fingerprint_sha256)
    ).first()
    if existing is not None:
        raise SSHKeyError(
            "public_key",
            f"This key is already registered as “{existing.label}” ({material.fingerprint_openssh}). "
            "Register a different key, or delete the existing one first.",
        )
    same_label = db.scalars(
        select(SSHPublicKey).where(func.lower(SSHPublicKey.label) == parsed_label.lower())
    ).first()
    if same_label is not None:
        raise SSHKeyError("label", f"A key labelled “{same_label.label}” already exists.")
    row = SSHPublicKey(
        label=parsed_label,
        public_key=material.public_key,
        key_type=material.key_type,
        fingerprint_sha256=material.fingerprint_sha256,
        created_by=actor.user_id,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        # Two submissions of the same key raced: the unique fingerprint index wins, the message stays clear.
        raise SSHKeyError(
            "public_key",
            f"This key is already registered ({material.fingerprint_openssh}). Register a different key, "
            "or delete the existing one first.",
        ) from None
    record(
        db,
        actor,
        "ssh_key.create",
        "ssh_key",
        str(row.id),
        {"label": row.label, "key_type": row.key_type, "fingerprint": row.fingerprint_sha256},
    )
    return row


def delete_key(db: Session, key_id: int, actor: Actor) -> None:
    """Remove one registered key by id, audited."""
    row = db.get(SSHPublicKey, key_id)
    if row is None:
        raise SSHKeyNotFound(key_id)
    record(
        db,
        actor,
        "ssh_key.delete",
        "ssh_key",
        str(row.id),
        {"label": row.label, "fingerprint": row.fingerprint_sha256},
    )
    db.delete(row)
    db.flush()
