"""Worker credentials: sealed at rest, write-only in the interface, resolved when a job runs.

The worker's three credentials used to be files mounted into the container and read once at startup,
so an operator had no way to supply them from the interface. They are now first-class settings stored
in ``encrypted_setting``: one AES-256-GCM row per credential, wrapped with the certificate keyring and
bound to its own name through the AAD, so a ciphertext cannot be moved from one setting to another.

Resolution happens **when a job runs**, never at process start, so a change takes effect without
restarting the worker:

1. the database row, when present;
2. the mounted file of the same name (``ansible_ssh_key`` and friends), so an installation that only
   has files behaves exactly as before;
3. absent.

Nothing here returns a stored value to the interface: :func:`credential_states` is the read path the
web layer uses and it exposes presence, provenance, who set it, when, and — for the SSH key, which is
a public fact — the key type and the public fingerprint. The value itself never leaves the worker.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.crypto.keyring import Keyring, KeyUnwrapError, WrappedSecret, unwrap, wrap
from app.models import EncryptedSetting, JSONValue, User
from app.services.audit import Actor, record

if TYPE_CHECKING:
    from app.jobs.worker import WorkerCapabilities

__all__ = [
    "INVENTORY_GIT_TOKEN",
    "SSH_PRIVATE_KEY",
    "VAULT_PASSWORD",
    "WORKER_CREDENTIALS",
    "CredentialError",
    "CredentialMetadata",
    "CredentialSpec",
    "CredentialState",
    "credential_configured",
    "credential_state",
    "credential_states",
    "remove_credential",
    "resolve_worker_settings",
    "rotate_credential_row",
    "set_credential",
    "validate_credential",
]

SSH_PRIVATE_KEY = "worker.ssh_private_key"
VAULT_PASSWORD = "worker.vault_password"
INVENTORY_GIT_TOKEN = "inventory.git_token"

_SSH_MAX_BYTES = 16 * 1024
_SECRET_MAX_BYTES = 512


@dataclass(frozen=True)
class CredentialSpec:
    """One credential: its setting name, the mounted file it used to come from, and what it is for."""

    name: str
    label: str
    file_name: str
    description: str
    max_bytes: int


WORKER_CREDENTIALS: tuple[CredentialSpec, ...] = (
    CredentialSpec(
        SSH_PRIVATE_KEY,
        "SSH private key",
        "ansible_ssh_key",
        "The key Ansible, git and ssh use: discovery and deploy stop working without it.",
        _SSH_MAX_BYTES,
    ),
    CredentialSpec(
        VAULT_PASSWORD,
        "Ansible vault password",
        "ansible_vault_password",
        "Password of the inventory's vaulted files, when the inventory uses Ansible Vault.",
        _SECRET_MAX_BYTES,
    ),
    CredentialSpec(
        INVENTORY_GIT_TOKEN,
        "Inventory repository token",
        "inventory_git_token",
        "HTTPS token, needed only when the inventory repository is private.",
        _SECRET_MAX_BYTES,
    ),
)
_SPECS = {spec.name: spec for spec in WORKER_CREDENTIALS}

# Which startup report field proves a worker holds the credential as a mounted file: the web process
# does not mount these files, so its own view of ``secrets_dir`` is empty by design.
_FILE_FLAGS = {
    SSH_PRIVATE_KEY: "ssh_key_present",
    VAULT_PASSWORD: "vault_password_present",
    INVENTORY_GIT_TOKEN: "inventory_token_present",
}


class CredentialError(ValueError):
    """A refused credential. The message is user-facing and never contains the value."""

    def __init__(self, name: str, message: str) -> None:
        self.name = name
        super().__init__(message)


@dataclass(frozen=True)
class CredentialMetadata:
    """What is safe to know about a stored value; both fields are ``None`` for password-shaped ones."""

    key_type: str | None = None
    fingerprint_sha256: str | None = None


@dataclass(frozen=True)
class CredentialState:
    """Presence and provenance of one credential. There is deliberately no value field."""

    name: str
    label: str
    configured: bool
    source: Literal["database", "file"] | None
    updated_at: datetime | None
    updated_by: str | None
    key_type: str | None
    fingerprint_sha256: str | None


# --- validation (what a write enforces) ------------------------------------------------------------

_PUBLIC_HEADERS = (
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN RSA PUBLIC KEY-----",
    b"-----BEGIN OPENSSH PUBLIC KEY-----",
)
_PUBLIC_PREFIXES = (b"ssh-rsa ", b"ssh-ed25519 ", b"ssh-dss ", b"ecdsa-sha2-", b"sk-ssh-", b"sk-ecdsa-")


def validate_credential(name: str, value: bytes | str) -> CredentialMetadata:
    """Refuse an unusable value with a message that never echoes it; return safe metadata otherwise."""
    spec = _spec(name)
    raw = _as_bytes(name, value)
    if name == SSH_PRIVATE_KEY:
        return _validate_ssh_private_key(name, raw)
    _validate_secret_text(spec, raw)
    return CredentialMetadata()


def _as_bytes(name: str, value: bytes | str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise CredentialError(name, "must be text or bytes")


def _validate_secret_text(spec: CredentialSpec, value: bytes) -> None:
    if not value:
        raise CredentialError(spec.name, "must not be empty")
    if len(value) > spec.max_bytes:
        raise CredentialError(spec.name, f"must be at most {spec.max_bytes} bytes")
    if b"\n" in value or b"\r" in value:
        raise CredentialError(spec.name, "must not contain line breaks")
    if any(byte < 0x20 or byte == 0x7F for byte in value):
        raise CredentialError(spec.name, "must not contain control characters")


def _validate_ssh_private_key(name: str, value: bytes) -> CredentialMetadata:
    if not value:
        raise CredentialError(name, "must not be empty")
    if len(value) > _SSH_MAX_BYTES:
        raise CredentialError(name, f"must be at most {_SSH_MAX_BYTES} bytes")
    stripped = value.lstrip()
    if stripped.startswith(_PUBLIC_HEADERS) or stripped.startswith(_PUBLIC_PREFIXES):
        raise CredentialError(name, "this is a public key: paste the private key instead")
    try:
        if stripped.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
            key = serialization.load_ssh_private_key(value.strip() + b"\n", password=None)
        else:
            key = serialization.load_pem_private_key(value, password=None)
    except TypeError:
        # cryptography raises TypeError when a passphrase is needed and none was given.
        raise CredentialError(
            name,
            "this private key has a passphrase: paste an unencrypted private key (no passphrase is stored)",
        ) from None
    except (ValueError, UnsupportedAlgorithm):
        raise CredentialError(
            name, "this is not a private key: expected an unencrypted PEM or OpenSSH private key"
        ) from None
    return CredentialMetadata(_key_type(key), _public_fingerprint(key.public_key()))


def _key_type(key: PrivateKeyTypes) -> str:
    """A short, public description of the key algorithm and size, e.g. ``RSA 3072`` or ``Ed25519``."""
    if isinstance(key, rsa.RSAPrivateKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"ECDSA P-{key.key_size}"
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PrivateKey):
        return "Ed448"
    if isinstance(key, dsa.DSAPrivateKey):
        return f"DSA {key.key_size}"
    return "unknown"


def _public_fingerprint(public_key: PublicKeyTypes) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo — the public fact the audit trail records."""
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


# --- sealing ---------------------------------------------------------------------------------------


def _aad(name: str, version: int) -> str:
    """Bind a ciphertext to its setting name and key version; rebuilt on read, never stored."""
    return f"setting:{name}:{version}"


def _seal(keyring: Keyring, name: str, value: bytes) -> WrappedSecret:
    return wrap(keyring, value, _aad(name, keyring.active))


def _open(keyring: Keyring, name: str, ciphertext: bytes, nonce: bytes, version: int) -> bytes:
    return unwrap(keyring, WrappedSecret(ciphertext, nonce, version), _aad(name, version))


def _spec(name: str) -> CredentialSpec:
    try:
        return _SPECS[name]
    except KeyError:
        raise KeyError(f"unknown credential setting: {name!r}") from None


# --- reads the interface may use -------------------------------------------------------------------


def credential_states(
    db: Session, settings: Settings, *, worker: WorkerCapabilities | None = None
) -> dict[str, CredentialState]:
    """Every credential by setting name, in the order the interface renders them."""
    return {
        spec.name: credential_state(db, settings, spec.name, worker=worker) for spec in WORKER_CREDENTIALS
    }


def credential_state(
    db: Session, settings: Settings, name: str, *, worker: WorkerCapabilities | None = None
) -> CredentialState:
    """Presence, provenance and safe metadata for one credential; never decrypts for the caller.

    ``worker`` is the newest live worker's startup report: it is how the web process learns that a
    credential is still supplied by a mounted file it cannot see.
    """
    spec = _spec(name)
    row = db.get(EncryptedSetting, name)
    if row is not None:
        metadata = _stored_metadata(settings, row)
        return CredentialState(
            spec.name,
            spec.label,
            True,
            "database",
            row.updated_at,
            _username(db, row.updated_by),
            metadata.key_type,
            metadata.fingerprint_sha256,
        )
    if _reported_by_the_worker(worker, name) or _mounted_value(settings, spec) is not None:
        return CredentialState(spec.name, spec.label, True, "file", None, None, None, None)
    return CredentialState(spec.name, spec.label, False, None, None, None, None, None)


def _stored_metadata(settings: Settings, row: EncryptedSetting) -> CredentialMetadata:
    if row.name != SSH_PRIVATE_KEY:
        return CredentialMetadata()
    try:
        value = _open(settings.keyring, row.name, row.ciphertext, row.nonce, row.keyring_version)
    except KeyUnwrapError:
        # A missing master-key version is reported on the status page; the screen still says configured.
        return CredentialMetadata()
    try:
        return _validate_ssh_private_key(row.name, value)
    except CredentialError:
        return CredentialMetadata()
    finally:
        del value


def _reported_by_the_worker(worker: WorkerCapabilities | None, name: str) -> bool:
    if worker is None:
        return False
    return getattr(worker, _FILE_FLAGS[name], False) is True


def _username(db: Session, user_id: int | None) -> str | None:
    if user_id is None:
        return None
    user = db.get(User, user_id)
    return None if user is None else user.username


def credential_configured(db: Session, name: str) -> bool:
    """Whether the database holds a value for ``name``: one primary-key read, no decryption."""
    _spec(name)
    return db.scalar(select(EncryptedSetting.name).where(EncryptedSetting.name == name)) is not None


# --- writes ----------------------------------------------------------------------------------------


def set_credential(
    db: Session, settings: Settings, name: str, value: bytes | str, actor: Actor
) -> CredentialState:
    """Validate, seal and upsert one credential and audit it; the caller owns the transaction.

    Replacing an existing value is allowed (``replaced``); there is no read path that returns it.
    """
    metadata = validate_credential(name, value)
    raw = _as_bytes(name, value)
    sealed = _seal(settings.keyring, name, raw)
    del raw
    row = db.get(EncryptedSetting, name, with_for_update=True)
    action: Literal["set", "replaced"] = "set" if row is None else "replaced"
    if row is None:
        row = EncryptedSetting(name=name)
        db.add(row)
    row.ciphertext, row.nonce, row.keyring_version = sealed.ciphertext, sealed.nonce, sealed.version
    row.updated_by = actor.user_id
    db.flush()
    db.refresh(row)  # updated_at is maintained by the touch_updated_at trigger
    _audit(db, actor, name, action, metadata)
    return credential_state(db, settings, name)


def remove_credential(db: Session, settings: Settings, name: str, actor: Actor) -> CredentialState:
    """Delete the database value so the file (or absence) takes over; no row means no change, no event.

    The removal event names the key being removed through its public fingerprint, derived from the row
    before it is deleted, so an audit trail says *which* key the operator dropped. A row that cannot be
    decrypted is still removable — it is the recovery path — and then there is no metadata to report.
    """
    spec = _spec(name)
    row = db.get(EncryptedSetting, name, with_for_update=True)
    if row is not None:
        metadata = _stored_metadata(settings, row)
        db.delete(row)
        db.flush()
        _audit(db, actor, spec.name, "removed", metadata)
    return credential_state(db, settings, name)


def _audit(db: Session, actor: Actor, name: str, action: str, metadata: CredentialMetadata) -> None:
    """One event per change: the name, the action and safe metadata — never the value."""
    details: dict[str, JSONValue] = {"name": name, "action": action}
    if metadata.key_type is not None:
        details["key_type"] = metadata.key_type
    if metadata.fingerprint_sha256 is not None:
        details["fingerprint_sha256"] = metadata.fingerprint_sha256
    record(db, actor, f"credential.{action}", "credential", name, details)


# --- resolution at job time ------------------------------------------------------------------------


def resolve_worker_settings(db: Session, settings: Settings) -> Settings:
    """The settings one job runs with: database row first, then the mounted file, then absent.

    A present row that cannot be decrypted raises ``KeyUnwrapError`` instead of silently falling back
    to the file: a broken database value must never mask itself as a working file. The file level is
    the file read now, or the value the startup snapshot already read from it — so an installation
    with only the files keeps behaving exactly as it did before this setting existed.
    """
    values: dict[str, bytes | None] = {}
    for spec in WORKER_CREDENTIALS:
        row = db.get(EncryptedSetting, spec.name)
        values[spec.name] = (
            _open(settings.keyring, spec.name, row.ciphertext, row.nonce, row.keyring_version)
            if row is not None
            else _mounted_value(settings, spec)
        )
    return replace(
        settings,
        ansible_ssh_key=values[SSH_PRIVATE_KEY],
        ansible_vault_password=values[VAULT_PASSWORD],
        inventory_git_token=values[INVENTORY_GIT_TOKEN],
    )


def _mounted_value(settings: Settings, spec: CredentialSpec) -> bytes | None:
    """The mounted file, read live, or the bytes the startup snapshot loaded from that same file."""
    value = _file_value(settings.secrets_dir, spec.file_name)
    return value if value is not None else getattr(settings, spec.file_name)


def _file_value(directory: Path, file_name: str) -> bytes | None:
    """The mounted secret file, if this process has one; an unreadable file counts as absent."""
    try:
        raw = (directory / file_name).read_bytes()
    except OSError:
        return None
    value = raw.rstrip(b"\r\n")
    return value or None


def rotate_credential_row(row: EncryptedSetting, keyring: Keyring) -> bool:
    """Rewrap one stored credential under ``keyring.active``; False when it is already current."""
    if row.keyring_version == keyring.active:
        return False
    plaintext = _open(keyring, row.name, row.ciphertext, row.nonce, row.keyring_version)
    try:
        sealed = _seal(keyring, row.name, plaintext)
    finally:
        del plaintext
    row.ciphertext, row.nonce, row.keyring_version = sealed.ciphertext, sealed.nonce, sealed.version
    return True
