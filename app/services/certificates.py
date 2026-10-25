"""Transactional key custody and the deduplicated, audited certificate inventory.

Every mutation stages its audit row in the caller's transaction; nothing here
commits. Typed ``InventoryError`` codes are mapped to 422 by the callers.
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Literal

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy import and_, exists, func, or_, select, text
from sqlalchemy.dialects.postgresql import distinct_on, insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.chain import ChainError, ChainResult, order_chain
from app.crypto.keyring import Keyring, KeyUnwrapError, WrappedSecret, unwrap, wrap
from app.crypto.keys import PrivateKeyObject, _validate, load_private_key, private_key_pem, public_key_sha256
from app.crypto.parse import MAX_INPUT_BYTES, ParsedCertificate, ParseError, parse_certificates
from app.crypto.pfx import PFXError, _is_ca
from app.crypto.pfx_isolated import read_encrypted_key_isolated, read_pfx_isolated
from app.crypto.trust import ChainAssessment, assess_chain
from app.models import (
    AuditLog,
    Binding,
    Certificate,
    Endpoint,
    JSONValue,
    PrivateKey,
    Renewal,
    ScanResult,
    Server,
    User,
)
from app.models.enums import CertificateStatus, ChainStatus, RenewalState
from app.services.audit import Actor, record
from app.services.trust_anchors import enabled_anchors


def store_key(
    db: Session,
    keyring: Keyring,
    key: PrivateKeyObject,
    origin: str,
    actor: Actor,
) -> PrivateKey:
    fingerprint = public_key_sha256(key.public_key())
    existing = db.scalar(select(PrivateKey).where(PrivateKey.public_key_sha256 == fingerprint))
    if existing is not None:
        return existing
    # Sequence reservation avoids ever inserting a partially encrypted row.
    key_id = db.scalar(select(func.nextval(func.pg_get_serial_sequence("private_key", "id"))))
    aad = f"private_key:{key_id}:{keyring.active}"
    plaintext = private_key_pem(key)
    try:
        encrypted = wrap(keyring, plaintext, aad)
    finally:
        del plaintext
    curve = None
    if isinstance(key, ec.EllipticCurvePrivateKey):
        curve = "prime256v1" if isinstance(key.curve, ec.SECP256R1) else "secp384r1"
    statement = (
        insert(PrivateKey)
        .values(
            id=key_id,
            key_type="ecdsa" if curve else "rsa",
            key_size=key.key_size,
            curve=curve,
            ciphertext=encrypted.ciphertext,
            nonce=encrypted.nonce,
            aad=aad,
            master_key_version=encrypted.version,
            public_key_sha256=fingerprint,
            public_key_pem=key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode("ascii"),
            created_by=actor.user_id,
            origin=origin,
        )
        .on_conflict_do_nothing(index_elements=["public_key_sha256"])
        .returning(PrivateKey)
    )
    row = db.scalar(statement)
    if row is None:
        # READ COMMITTED: the winning insert has committed before ON CONFLICT
        # returns, so this new statement sees its complete row.
        return db.scalars(select(PrivateKey).where(PrivateKey.public_key_sha256 == fingerprint)).one()
    record(
        db,
        actor,
        "key.create",
        "private_key",
        str(row.id),
        {
            "origin": origin,
            "key_type": row.key_type,
            "key_size": row.key_size,
            "public_key_sha256": fingerprint,
            "master_key_version": row.master_key_version,
        },
    )
    return row


def unwrap_key(row: PrivateKey, keyring: Keyring) -> PrivateKeyObject:
    expected_aad = f"private_key:{row.id}:{row.master_key_version}"
    if row.aad != expected_aad:
        raise KeyUnwrapError()
    plaintext = unwrap(
        keyring, WrappedSecret(row.ciphertext, row.nonce, row.master_key_version), expected_aad
    )
    try:
        key = load_private_key(plaintext)
        if public_key_sha256(key.public_key()) != row.public_key_sha256:
            raise KeyUnwrapError()
        return key
    except (ValueError, TypeError):
        raise KeyUnwrapError() from None
    finally:
        del plaintext


def missing_master_key_versions(db: Session, keyring: Keyring) -> set[int]:
    versions = set(db.scalars(select(PrivateKey.master_key_version).distinct()))
    versions.update(
        db.scalars(
            select(User.totp_secret_version)
            .where(User.totp_secret_ciphertext.is_not(None), User.totp_secret_version.is_not(None))
            .distinct()
        )
    )
    return versions - set(keyring.keys)


def stale_master_key_rows(db: Session, keyring: Keyring) -> int:
    return db.scalar(
        select(func.count()).select_from(PrivateKey).where(PrivateKey.master_key_version != keyring.active)
    ) + db.scalar(
        select(func.count())
        .select_from(User)
        .where(
            User.totp_secret_ciphertext.is_not(None),
            User.totp_secret_version.is_distinct_from(keyring.active),
        )
    )


def _rewrap(keyring: Keyring, wrapped: WrappedSecret, old_aad: str, new_aad: str) -> WrappedSecret:
    # Keep raw bytes in this one-row helper, never in the batch's ORM collection.
    # Dropping references is not a claim of secure Python-heap zeroization.
    plaintext = unwrap(keyring, wrapped, old_aad)
    try:
        return wrap(keyring, plaintext, new_aad)
    finally:
        del plaintext


def rotate_master_key(db: Session, keyring: Keyring, actor: Actor, batch_size: int = 100) -> int:
    if type(batch_size) is not int or batch_size < 1:
        raise ValueError("batch_size must be a positive integer")
    keys = db.scalars(
        select(PrivateKey)
        .where(PrivateKey.master_key_version != keyring.active)
        .order_by(PrivateKey.id)
        .limit(batch_size)
        .with_for_update()
    ).all()
    for row in keys:
        old_aad = f"private_key:{row.id}:{row.master_key_version}"
        if row.aad != old_aad:
            raise KeyUnwrapError()
        new_aad = f"private_key:{row.id}:{keyring.active}"
        encrypted = _rewrap(
            keyring, WrappedSecret(row.ciphertext, row.nonce, row.master_key_version), old_aad, new_aad
        )
        row.ciphertext, row.nonce = encrypted.ciphertext, encrypted.nonce
        row.aad, row.master_key_version = new_aad, encrypted.version
    users = []
    if len(keys) < batch_size:
        users = db.scalars(
            select(User)
            .where(
                User.totp_secret_ciphertext.is_not(None),
                User.totp_secret_version.is_distinct_from(keyring.active),
            )
            .order_by(User.id)
            .limit(batch_size - len(keys))
            .with_for_update()
        ).all()
    for user in users:
        encrypted = _rewrap(
            keyring,
            WrappedSecret(user.totp_secret_ciphertext, user.totp_secret_nonce, user.totp_secret_version),
            f"user:{user.id}:totp:{user.totp_secret_version}",
            f"user:{user.id}:totp:{keyring.active}",
        )
        user.totp_secret_ciphertext, user.totp_secret_nonce = encrypted.ciphertext, encrypted.nonce
        user.totp_secret_version = encrypted.version
    db.flush()
    remaining = stale_master_key_rows(db, keyring)
    if keys or users:
        record(
            db,
            actor,
            "master_key.rotate",
            "master_key",
            str(keyring.active),
            {
                "keys_rotated": len(keys),
                "users_rotated": len(users),
                "version": keyring.active,
                "remaining": remaining,
            },
        )
    return remaining


# --------------------------------------------------------------------------
# Certificate inventory
# --------------------------------------------------------------------------

SOURCES = frozenset({"upload_pem", "upload_pfx", "pull_endpoint", "renewal", "discovery"})
_TRANSITIONS = frozenset(
    {
        (CertificateStatus.ACTIVE, CertificateStatus.SUPERSEDED),
        (CertificateStatus.ACTIVE, CertificateStatus.REVOKED),
        (CertificateStatus.SUPERSEDED, CertificateStatus.REVOKED),
    }
)
_REASON_LIMIT = 1_000
_METADATA_FIELDS = ("owner_name", "owner_email", "team", "notes")
_METADATA_LIMITS = {"owner_name": 200, "owner_email": 254, "team": 200, "notes": 10_000}


class InventoryError(Exception):
    """Typed inventory failure; ``code`` is stable, ``message`` is safe to show."""

    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


@dataclass(frozen=True)
class CertificateMetadata:
    owner_name: str | None = None
    owner_email: str | None = None
    team: str | None = None
    notes: str | None = None

    def __post_init__(self) -> None:
        for name in _METADATA_FIELDS:
            object.__setattr__(self, name, _clean_metadata(name, getattr(self, name)))
        email = self.owner_email
        if email is not None:
            local, _, domain = email.rpartition("@")
            if not local or not domain or any(ch.isspace() for ch in email):
                raise InventoryError("invalid_metadata", "owner_email must be an email address")


def _clean_metadata(name: str, value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InventoryError("invalid_metadata", f"{name} must be text")
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > _METADATA_LIMITS[name]:
        raise InventoryError("invalid_metadata", f"{name} exceeds {_METADATA_LIMITS[name]} characters")
    return cleaned


@dataclass(frozen=True)
class ImportResult:
    certificate: Certificate
    created: bool
    warnings: tuple[str, ...]
    # Upload import only: a supplied key matches a public-only duplicate and awaits explicit
    # confirmation / this import linked a private key to the certificate.
    key_attachable: bool = False
    key_attached: bool = False


def _lock(db: Session, certificate_id: int) -> Certificate:
    row = db.scalar(
        select(Certificate)
        .where(Certificate.id == certificate_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if row is None:
        raise InventoryError("not_found", "certificate not found")
    return row


def _find_existing(db: Session, leaf: ParsedCertificate) -> Certificate | None:
    same_fingerprint = Certificate.sha256_fingerprint == leaf.sha256_fingerprint
    return db.scalar(
        select(Certificate)
        .where(
            or_(
                same_fingerprint,
                and_(Certificate.issuer_dn == leaf.issuer_dn, Certificate.serial == leaf.serial),
            )
        )
        .order_by(same_fingerprint.desc())
        .limit(1)
        .execution_options(populate_existing=True)
    )


def _assess(db: Session, leaf: x509.Certificate, chain: ChainResult, moment: datetime) -> ChainAssessment:
    intermediates = [item.cert for item in parse_certificates(chain.pem.encode("ascii"))] if chain.pem else []
    return assess_chain(leaf, intermediates, enabled_anchors(db), moment, chain.diagnostic_roots)


def _diagnostics(
    not_after: datetime, chain: ChainResult, assessment: ChainAssessment, moment: datetime
) -> tuple[str, ...]:
    notes: list[str] = []
    if not_after < moment:
        notes.append("expired")
    if assessment.status != ChainStatus.TRUSTED:
        for message in assessment.messages:
            if chain.missing_issuer is not None and (
                message == "missing_issuer" or message.startswith("issuer:")
            ):
                continue
            notes.append(message)
    if chain.missing_issuer is not None:
        notes.append(f"missing_issuer:{chain.missing_issuer}")
    notes.extend(f"chain:{note}" for note in chain.dropped)
    return tuple(dict.fromkeys(notes))


def _matching_key(db: Session, leaf: ParsedCertificate, key_id: int | None) -> PrivateKey | None:
    if key_id is None:
        return None
    key = db.get(PrivateKey, key_id)
    if key is None:
        raise InventoryError("not_found", "private key not found")
    if key.public_key_sha256 != leaf.public_key_sha256:
        raise InventoryError("key_mismatch", "private key does not match the certificate")
    return key


def _lineage_lock(db: Session) -> None:
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('certificate:lineage'))"))


def _require_certificate(db: Session, certificate_id: int) -> None:
    if db.scalar(select(Certificate.id).where(Certificate.id == certificate_id)) is None:
        raise InventoryError("not_found", "certificate not found")


def _is_ancestor(db: Session, ancestor_id: int, of_id: int) -> bool:
    """True when ``ancestor_id`` is ``of_id`` or one of its renews_id ancestors."""
    return (
        db.scalar(
            text(
                "WITH RECURSIVE ancestors(id, renews_id) AS ("
                " SELECT id, renews_id FROM certificate WHERE id = :start"
                " UNION"
                " SELECT c.id, c.renews_id FROM certificate c JOIN ancestors a ON c.id = a.renews_id"
                ") SELECT 1 FROM ancestors WHERE id = :target LIMIT 1"
            ),
            {"start": of_id, "target": ancestor_id},
        )
        is not None
    )


def save_certificate(
    db: Session,
    leaf: ParsedCertificate,
    chain: ChainResult,
    metadata: CertificateMetadata,
    actor: Actor,
    *,
    source: str,
    key_id: int | None = None,
    renews_id: int | None = None,
    validation_time: datetime | None = None,
) -> ImportResult:
    if source not in SOURCES:
        raise InventoryError("invalid_source", "unsupported import source")
    key = _matching_key(db, leaf, key_id)
    moment = validation_time or datetime.now(UTC)
    assessment = _assess(db, leaf.cert, chain, moment)
    warnings = _diagnostics(leaf.not_after, chain, assessment, moment)
    existing = _find_existing(db, leaf)
    if existing is None:
        if renews_id is not None:
            # A new row has no descendants, so only existence needs checking;
            # the lock keeps the shared lineage protocol uniform.
            _lineage_lock(db)
            _require_certificate(db, renews_id)
        row = Certificate(
            common_name=leaf.common_name,
            subject_dn=leaf.subject_dn,
            sans=list(leaf.sans),
            issuer_dn=leaf.issuer_dn,
            issuer_cn=leaf.issuer_cn,
            serial=leaf.serial,
            not_before=leaf.not_before,
            not_after=leaf.not_after,
            sha256_fingerprint=leaf.sha256_fingerprint,
            pem=leaf.pem,
            chain_pem=chain.pem,
            chain_status=assessment.status,
            key_id=key_id,
            owner_name=metadata.owner_name,
            owner_email=metadata.owner_email,
            team=metadata.team,
            notes=metadata.notes,
            renews_id=renews_id,
            imported_from=source,
            created_by=actor.user_id,
        )
        try:
            with db.begin_nested():
                db.add(row)
                db.flush()
        except IntegrityError as exc:
            if getattr(exc.orig, "sqlstate", None) != "23505":
                raise
            # A concurrent import won; its committed row is visible to this new statement.
            existing = _find_existing(db, leaf)
            if existing is None:
                raise
        else:
            details: dict[str, JSONValue] = {
                "source": source,
                "sha256_fingerprint": leaf.sha256_fingerprint,
                "chain_status": assessment.status.value,
                "warnings": list(warnings),
            }
            if key_id is not None:
                details["key_id"] = key_id
            record(db, actor, "certificate.import", "certificate", str(row.id), details)
            return ImportResult(row, True, warnings)
    return _duplicate(db, existing, leaf, key, actor, source, warnings)


def _duplicate(
    db: Session,
    existing: Certificate,
    leaf: ParsedCertificate,
    key: PrivateKey | None,
    actor: Actor,
    source: str,
    warnings: tuple[str, ...],
) -> ImportResult:
    notes = list(warnings)
    if existing.sha256_fingerprint != leaf.sha256_fingerprint:
        notes.append("issuer_serial_collision")
    notes.append("duplicate")
    attached = False
    if key is not None:
        row = _lock(db, existing.id)
        stored_public_key = parse_certificates(row.pem.encode("ascii"))[0].public_key_sha256
        if key.public_key_sha256 != stored_public_key or row.key_id not in (None, key.id):
            raise InventoryError("key_mismatch", "private key does not match the certificate")
        if row.key_id is None:
            row.key_id = key.id
            db.flush()
            attached = True
        existing = row
    record(
        db,
        actor,
        "certificate.import_duplicate",
        "certificate",
        str(existing.id),
        {"sha256_fingerprint": leaf.sha256_fingerprint, "source": source},
    )
    if attached:
        record(
            db,
            actor,
            "certificate.key_attach",
            "certificate",
            str(existing.id),
            {"key_id": key.id, "public_key_sha256": key.public_key_sha256},
        )
    return ImportResult(existing, False, tuple(notes))


def update_certificate(
    db: Session, certificate_id: int, metadata: CertificateMetadata, actor: Actor
) -> Certificate:
    row = _lock(db, certificate_id)
    before: dict[str, JSONValue] = {}
    after: dict[str, JSONValue] = {}
    for name in _METADATA_FIELDS:
        old, new = getattr(row, name), getattr(metadata, name)
        if old != new:
            before[name], after[name] = old, new
            setattr(row, name, new)
    if before:
        db.flush()
        record(
            db, actor, "certificate.update", "certificate", str(row.id), {"before": before, "after": after}
        )
    return row


def set_status(
    db: Session, certificate_id: int, status: CertificateStatus, reason: str, actor: Actor
) -> Certificate:
    try:
        target = CertificateStatus(status)
    except ValueError:
        raise InventoryError("invalid_status", "unknown certificate status") from None
    cleaned = reason.strip() if isinstance(reason, str) else ""
    if not cleaned or len(cleaned) > _REASON_LIMIT:
        raise InventoryError("reason_required", "a reason of 1 to 1,000 characters is required")
    row = _lock(db, certificate_id)
    if (row.status, target) not in _TRANSITIONS:
        raise InventoryError(
            "invalid_status", f"cannot change status from {row.status.value} to {target.value}"
        )
    previous = row.status
    row.status = target
    db.flush()
    record(
        db,
        actor,
        "certificate.status_change",
        "certificate",
        str(row.id),
        {"from": previous.value, "to": target.value, "reason": cleaned},
    )
    return row


def attach_chain(
    db: Session,
    certificate_id: int,
    chain_data: bytes,
    actor: Actor,
    *,
    validation_time: datetime | None = None,
) -> Certificate:
    if not isinstance(chain_data, (bytes, bytearray)) or not chain_data or len(chain_data) > MAX_INPUT_BYTES:
        raise InventoryError("invalid_chain", "chain must be 1 to 1,048,576 bytes")
    row = _lock(db, certificate_id)
    try:
        candidates = [item.cert for item in parse_certificates(bytes(chain_data))]
        leaf = parse_certificates(row.pem.encode("ascii"))[0].cert
        ordered = order_chain(leaf, candidates)
    except (ParseError, ChainError):
        raise InventoryError("invalid_chain", "chain could not be parsed or ordered") from None
    moment = validation_time or datetime.now(UTC)
    assessment = _assess(db, leaf, ordered, moment)
    row.chain_pem = ordered.pem
    row.chain_status = assessment.status
    db.flush()
    record(
        db,
        actor,
        "certificate.chain_upload",
        "certificate",
        str(row.id),
        {
            "chain_fingerprints": list(ordered.fingerprints),
            "chain_status": assessment.status.value,
            "warnings": list(_diagnostics(row.not_after, ordered, assessment, moment)),
        },
    )
    return row


def set_lineage(db: Session, certificate_id: int, previous_id: int, actor: Actor) -> None:
    _lineage_lock(db)
    row = _lock(db, certificate_id)
    if previous_id == certificate_id:
        raise InventoryError("lineage_cycle", "a certificate cannot renew itself")
    _require_certificate(db, previous_id)
    if _is_ancestor(db, certificate_id, previous_id):
        raise InventoryError("lineage_cycle", "lineage would form a cycle")
    if row.renews_id == previous_id:
        return
    row.renews_id = previous_id
    db.flush()
    record(db, actor, "certificate.lineage", "certificate", str(row.id), {"previous_id": previous_id})


# --------------------------------------------------------------------------
# Upload import (PEM / CRT / PFX)
# --------------------------------------------------------------------------

type UploadFormat = Literal["pem", "crt", "pfx"]
_UPLOAD_FORMATS = ("pem", "crt", "pfx")
_PRIVATE_KEY_BLOCK = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_TOO_LARGE = "Input is too large: each file or pasted block is limited to 1 MiB (1,048,576 bytes)."
_UNSUPPORTED_KEY = "Supported keys are RSA 2048/3072/4096 (e=65537) and ECDSA P-256/P-384."
_PFX_FIELD = {
    "invalid_password": "password",
    "invalid_password_or_bundle": "password",
    "unsupported_key": "key",
    "key_mismatch": "key",
}


@dataclass(frozen=True)
class UploadInput:
    data: bytes = field(repr=False)
    format: UploadFormat
    password: str | None = field(default=None, repr=False)
    chain_data: bytes | None = field(default=None, repr=False)
    key_data: bytes | None = field(default=None, repr=False)
    key_password: str | None = field(default=None, repr=False)


class ImportValidationError(Exception):
    """Aggregated, sanitized blocking errors keyed by form field (file/chain/key/password/metadata)."""

    def __init__(self, errors: Mapping[str, tuple[str, ...]]) -> None:
        super().__init__("upload validation failed")
        self.errors: Mapping[str, tuple[str, ...]] = MappingProxyType(
            {name: tuple(messages) for name, messages in errors.items() if messages}
        )


@dataclass(frozen=True)
class PreparedUpload:
    """A fully validated upload; nothing has touched the database yet."""

    leaf: ParsedCertificate
    chain: ChainResult
    key: PrivateKeyObject | None = field(repr=False)
    key_origin: str | None
    source: str


def _looks_like_pfx(data: bytes) -> bool:
    """Cheap structural test (DER SEQUENCE { INTEGER 3, ... }); never runs a KDF."""
    if len(data) < 6 or data[0] != 0x30:
        return False
    offset = 2 + (data[1] & 0x7F) if data[1] & 0x80 else 2
    return data[offset : offset + 3] == b"\x02\x01\x03"


def _describe_key(key: object) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return f"RSA {key.key_size}-bit"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"EC {key.curve.name}"
    return type(key).__name__


def _certificate_part(
    data: bytes, fail: Callable[[str, str], None]
) -> tuple[ParsedCertificate | None, list[x509.Certificate]]:
    if _PRIVATE_KEY_BLOCK.search(data):
        fail(
            "file",
            "This input contains a private key. Upload the certificate here and the key in the private key field.",
        )
        return None, []
    if _looks_like_pfx(data):
        fail(
            "file",
            "This input does not look like a PEM or DER certificate; it looks like a PFX (PKCS#12) bundle. Select the PFX format.",
        )
        return None, []
    try:
        parsed = parse_certificates(data)
    except ParseError:
        fail(
            "file",
            "No valid X.509 certificate was found. The input must be a PEM or DER encoded certificate.",
        )
        return None, []
    leaf = next((item for item in parsed if not _is_ca(item.cert)), parsed[0])
    return leaf, [item.cert for item in parsed if item is not leaf]


def _pfx_part(
    upload: UploadInput, fail: Callable[[str, str], None]
) -> tuple[ParsedCertificate | None, list[x509.Certificate], PrivateKeyObject | None]:
    data = upload.data
    if b"-----BEGIN" in data:
        fail(
            "file",
            "This input does not look like a PFX (PKCS#12) bundle; it looks like PEM text. Select the PEM format.",
        )
        return None, [], None
    if not _looks_like_pfx(data):
        fail("file", "This input does not look like a PFX (PKCS#12) bundle.")
        return None, [], None
    try:
        material = read_pfx_isolated(data, upload.password or None)
        leaf = parse_certificates(material.leaf.public_bytes(serialization.Encoding.DER))[0]
    except PFXError as exc:
        fail(_PFX_FIELD.get(exc.code, "file"), exc.message)
        return None, [], None
    except ParseError:
        fail("file", "The PFX certificate could not be parsed.")
        return None, [], None
    return leaf, list(material.chain), material.key


def _pem_key_part(
    data: bytes, password: str | None, fail: Callable[[str, str], None]
) -> PrivateKeyObject | None:
    if b"PRIVATE KEY" not in data or b"-----BEGIN" not in data:
        fail("key", "The private key must be PEM encoded (a BEGIN ... PRIVATE KEY block).")
        return None
    try:
        if b"ENCRYPTED" in data:
            # Password-based key derivation is attacker-controlled work: sandbox it like PFX.
            key = read_encrypted_key_isolated(data, password or None)
        else:
            key = serialization.load_pem_private_key(data, None)
    except PFXError as exc:
        if exc.code == "invalid_password_or_bundle":
            fail("key", "The private key password is wrong or missing, or the key could not be read.")
        elif exc.code == "unsupported_key":
            fail("key", f"Unsupported private key. {_UNSUPPORTED_KEY}")
        else:
            fail("key", exc.message)
        return None
    except UnsupportedAlgorithm:
        fail("key", f"Unsupported private key algorithm. {_UNSUPPORTED_KEY}")
        return None
    except (ValueError, TypeError):
        fail("key", "The private key could not be read.")
        return None
    try:
        _validate(key)
    except ValueError:
        fail("key", f"Unsupported private key ({_describe_key(key)}). {_UNSUPPORTED_KEY}")
        return None
    return key


def validate_upload(upload: UploadInput) -> PreparedUpload:
    """Check an upload completely, with no database access; aggregate independent errors."""
    errors: dict[str, list[str]] = {}

    def fail(name: str, message: str) -> None:
        errors.setdefault(name, []).append(message)

    if upload.format not in _UPLOAD_FORMATS:
        fail("file", "Choose a supported format: PEM, CRT or PFX.")
    for name, blob in (("file", upload.data), ("chain", upload.chain_data), ("key", upload.key_data)):
        if blob is not None and len(blob) > MAX_INPUT_BYTES:
            fail(name, _TOO_LARGE)  # rejected before any parser sees the bytes
    if not upload.data and "file" not in errors:
        fail("file", "Choose a certificate file or paste its contents.")

    leaf, candidates, pfx_key = None, [], None
    if "file" not in errors:
        if upload.format == "pfx":
            leaf, candidates, pfx_key = _pfx_part(upload, fail)
        else:
            leaf, candidates = _certificate_part(upload.data, fail)

    extra: list[x509.Certificate] = []
    if upload.chain_data and "chain" not in errors:
        try:
            extra = [item.cert for item in parse_certificates(upload.chain_data)]
        except ParseError:
            fail(
                "chain",
                "No valid certificate was found in the chain input (PEM or DER certificates expected).",
            )

    chain = None
    if leaf is not None and "chain" not in errors:
        try:
            chain = order_chain(leaf.cert, [*candidates, *extra])
        except ChainError:
            fail("chain", "The certificate chain could not be ordered; check the intermediates.")

    key, origin = None, None
    if pfx_key is not None:
        if upload.key_data:
            fail("key", "The PFX already contains a private key; remove the separate private key input.")
        else:
            key, origin = pfx_key, "imported_pfx"
    elif upload.key_data and "key" not in errors:
        key = _pem_key_part(upload.key_data, upload.key_password, fail)
        origin = "imported_pem"
        if key is not None and leaf is not None:
            key_hash = public_key_sha256(key.public_key())
            if key_hash != leaf.public_key_sha256:
                fail(
                    "key",
                    "The private key does not match the certificate "
                    f"(key public hash {key_hash}; certificate public hash {leaf.public_key_sha256}).",
                )
                key = None

    if errors or leaf is None or chain is None:
        raise ImportValidationError({name: tuple(messages) for name, messages in errors.items()})
    return PreparedUpload(
        leaf,
        chain,
        key,
        origin if key is not None else None,
        f"upload_{'pfx' if upload.format == 'pfx' else 'pem'}",
    )


class _UnconfirmedAttach(Exception):
    """Internal: a race made a new import a duplicate; roll back instead of attaching a key."""


def import_upload(
    db: Session,
    keyring: Keyring,
    upload: UploadInput,
    metadata: CertificateMetadata,
    actor: Actor,
    *,
    confirm_key: bool = False,
    prepared: PreparedUpload | None = None,
) -> ImportResult:
    """Validate, then import in the caller's transaction: key + certificate, or nothing.

    ``prepared`` lets a caller that already ran ``validate_upload`` skip a second parse.
    A supplied key is stored only for a new certificate or after ``confirm_key`` for a
    public-only duplicate; otherwise the duplicate is returned with ``key_attachable``.
    """
    prep = prepared if prepared is not None else validate_upload(upload)
    try:
        existing = _find_existing(db, prep.leaf)
        if prep.key is None or (existing is not None and not confirm_key):
            result = save_certificate(db, prep.leaf, prep.chain, metadata, actor, source=prep.source)
            offer = prep.key is not None and result.certificate.key_id is None
            return replace(result, key_attachable=offer)
        previous_key_id = existing.key_id if existing is not None else None
        try:
            with db.begin_nested():  # a failure leaves no orphan key row or audit entry
                key_row = store_key(db, keyring, prep.key, prep.key_origin or "imported_pem", actor)
                result = save_certificate(
                    db, prep.leaf, prep.chain, metadata, actor, source=prep.source, key_id=key_row.id
                )
                if not result.created and not confirm_key:
                    raise _UnconfirmedAttach
        except _UnconfirmedAttach:
            result = save_certificate(db, prep.leaf, prep.chain, metadata, actor, source=prep.source)
            return replace(result, key_attachable=result.certificate.key_id is None)
        attached = result.created or (previous_key_id is None and result.certificate.key_id == key_row.id)
        return replace(result, key_attached=attached)
    except InventoryError as exc:
        if exc.code == "key_mismatch":
            raise ImportValidationError({"key": (exc.message,)}) from None
        raise


# --------------------------------------------------------------------------
# Read models: list, expiry buckets, detail (Task 17)
# --------------------------------------------------------------------------

EXPORT_LIMIT = 5_000
PAGE_SIZE_LIMIT = 100
EXPIRY_BUCKETS = ("expired", "lt7", "lt30", "lt60")
TEXT_FILTER_LIMIT = 200
_BUCKET_DAYS = {"lt7": (0, 7), "lt30": (7, 30), "lt60": (30, 60)}
_SORTS = {
    "not_after": Certificate.not_after.asc(),
    "-not_after": Certificate.not_after.desc(),
    "common_name": Certificate.common_name.asc(),
    "-common_name": Certificate.common_name.desc(),
    "issuer_cn": Certificate.issuer_cn.asc(),
    "status": Certificate.status.asc(),
    "created_at": Certificate.created_at.asc(),
    "-created_at": Certificate.created_at.desc(),
}
SORTS = tuple(_SORTS)
_LIKE_ESCAPE = "/"


@dataclass(frozen=True)
class CertificateFilters:
    """Validated list filters; any invalid value raises ``ValueError`` (callers answer 422)."""

    search: str | None = None
    status: CertificateStatus | None = None
    expiry: Literal["expired", "lt7", "lt30", "lt60"] | None = None
    issuer: str | None = None
    team: str | None = None
    owner: str | None = None
    has_key: bool | None = None
    has_bindings: bool | None = None
    renewal_state: RenewalState | None = None

    def __post_init__(self) -> None:
        for name in ("search", "issuer", "team", "owner"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be text")
            value = value.strip() if value else None
            if value and len(value) > TEXT_FILTER_LIMIT:
                raise ValueError(f"{name} is longer than {TEXT_FILTER_LIMIT} characters")
            object.__setattr__(self, name, value or None)
        if self.expiry is not None and self.expiry not in EXPIRY_BUCKETS:
            raise ValueError("unknown expiry bucket")
        for name in ("has_key", "has_bindings"):
            if getattr(self, name) is not None and not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be true or false")
        if self.status is not None:
            object.__setattr__(self, "status", CertificateStatus(self.status))
        if self.renewal_state is not None:
            object.__setattr__(self, "renewal_state", RenewalState(self.renewal_state))


@dataclass(frozen=True)
class CertificatePage:
    items: list[Certificate]
    total: int
    page: int
    page_size: int


def _like(term: str, *, prefix_only: bool = False) -> str:
    escaped = term.replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2).replace("%", "/%").replace("_", "/_")
    return escaped + "%" if prefix_only else f"%{escaped}%"


def _contains(column, term: str):
    return column.ilike(_like(term), escape=_LIKE_ESCAPE)


def _bucket_clause(bucket: str, now: datetime):
    if bucket == "expired":
        return Certificate.not_after < now
    low, high = _BUCKET_DAYS[bucket]
    return and_(Certificate.not_after >= now + timedelta(days=low), Certificate.not_after < now + timedelta(days=high))


def _filter_clauses(filters: CertificateFilters, now: datetime) -> list:
    clauses: list = []
    if filters.search:
        clauses.append(
            or_(
                _contains(Certificate.common_name, filters.search),
                _contains(func.array_to_string(Certificate.sans, "\n"), filters.search),
                _contains(Certificate.serial, filters.search),
                Certificate.sha256_fingerprint.ilike(
                    _like(filters.search, prefix_only=True), escape=_LIKE_ESCAPE
                ),
            )
        )
    if filters.status is not None:
        clauses.append(Certificate.status == filters.status)
    if filters.expiry is not None:
        clauses.append(_bucket_clause(filters.expiry, now))
    if filters.issuer:
        clauses.append(_contains(Certificate.issuer_cn, filters.issuer))
    if filters.team:
        clauses.append(_contains(Certificate.team, filters.team))
    if filters.owner:
        clauses.append(
            or_(_contains(Certificate.owner_name, filters.owner), _contains(Certificate.owner_email, filters.owner))
        )
    if filters.has_key is not None:
        clauses.append(Certificate.key_id.is_not(None) if filters.has_key else Certificate.key_id.is_(None))
    if filters.has_bindings is not None:
        bound = exists().where(Binding.certificate_id == Certificate.id, Binding.is_active.is_(True))
        clauses.append(bound if filters.has_bindings else ~bound)
    if filters.renewal_state is not None:
        clauses.append(
            exists().where(
                Renewal.previous_certificate_id == Certificate.id, Renewal.state == filters.renewal_state
            )
        )
    return clauses


def _select_page(
    db: Session, filters: CertificateFilters, page: int, page_size: int, sort: str, moment: datetime
) -> CertificatePage:
    if type(page) is not int or page < 1:
        raise ValueError("page must be at least 1")
    if not isinstance(sort, str) or sort not in _SORTS:
        raise ValueError("unsupported sort")
    clauses = _filter_clauses(filters, moment)
    total = db.scalar(select(func.count()).select_from(Certificate).where(*clauses)) or 0
    bound = (
        select(Binding.certificate_id.label("certificate_id"), func.count().label("total"))
        .where(Binding.is_active.is_(True), Binding.certificate_id.is_not(None))
        .group_by(Binding.certificate_id)
        .subquery()
    )
    rows = db.execute(
        select(Certificate, func.coalesce(bound.c.total, 0))
        .outerjoin(bound, bound.c.certificate_id == Certificate.id)
        .where(*clauses)
        .order_by(_SORTS[sort], Certificate.id)
        .limit(page_size)
        .offset((page - 1) * page_size)
    ).all()
    items = []
    for row, count in rows:
        row.binding_count = int(count)  # presentation attribute, not a column
        items.append(row)
    return CertificatePage(items, total, page, page_size)


def list_certificates(
    db: Session,
    filters: CertificateFilters,
    page: int = 1,
    page_size: int = 50,
    sort: str = "not_after",
    now: datetime | None = None,
) -> CertificatePage:
    """One page (1-100 rows) of certificates; each item carries ``binding_count``, no N+1."""
    if type(page_size) is not int or not 1 <= page_size <= PAGE_SIZE_LIMIT:
        raise ValueError(f"page_size must be between 1 and {PAGE_SIZE_LIMIT}")
    return _select_page(db, filters, page, page_size, sort, now or datetime.now(UTC))


def export_certificates(
    db: Session,
    filters: CertificateFilters,
    sort: str = "not_after",
    now: datetime | None = None,
    limit: int = EXPORT_LIMIT,
) -> CertificatePage:
    """Every matching certificate up to ``limit`` (at most 5,000) in one page, for the JSON export."""
    if type(limit) is not int or not 1 <= limit <= EXPORT_LIMIT:
        raise ValueError(f"limit must be between 1 and {EXPORT_LIMIT}")
    return _select_page(db, filters, 1, limit, sort, now or datetime.now(UTC))


def expiry_counts(db: Session, now: datetime) -> dict[str, int]:
    """Disjoint expiry buckets over active certificates only, plus the active total."""
    active = Certificate.status == CertificateStatus.ACTIVE
    row = db.execute(
        select(
            func.count().filter(and_(active, _bucket_clause("expired", now))),
            func.count().filter(and_(active, _bucket_clause("lt7", now))),
            func.count().filter(and_(active, _bucket_clause("lt30", now))),
            func.count().filter(and_(active, _bucket_clause("lt60", now))),
            func.count().filter(active),
        ).select_from(Certificate)
    ).one()
    return dict(zip((*EXPIRY_BUCKETS, "total_active"), (int(value) for value in row), strict=True))


def allowed_status_changes(status: CertificateStatus) -> tuple[CertificateStatus, ...]:
    """The statuses a certificate may move to from ``status`` (transitions are one-way)."""
    return tuple(
        target
        for target in (CertificateStatus.SUPERSEDED, CertificateStatus.REVOKED)
        if (status, target) in _TRANSITIONS
    )


def has_certificates(db: Session) -> bool:
    return bool(db.scalar(select(exists().where(Certificate.id.is_not(None)))))


@dataclass(frozen=True)
class ChainDiagnostics:
    """A read-only re-assessment of a stored chain; ``status`` is None when it cannot be checked."""

    status: ChainStatus | None
    messages: tuple[str, ...]


def diagnose_chain(db: Session, row: Certificate, moment: datetime) -> ChainDiagnostics:
    """Re-run the offline trust assessment now (same inputs as the trust-anchor recheck); no writes."""
    try:
        leaf = parse_certificates(row.pem.encode("ascii"))[0].cert
    except (ParseError, UnicodeError):
        return ChainDiagnostics(None, ("unparseable_certificate",))
    intermediates: list[x509.Certificate] = []
    if row.chain_pem.strip():
        try:
            intermediates = [item.cert for item in parse_certificates(row.chain_pem.encode("ascii"))]
        except (ParseError, UnicodeError):
            return ChainDiagnostics(None, ("unparseable_chain",))
    # Report the assessment as it is now. Stored chains omit roots (spec 5.8), so a cached
    # ``untrusted_root`` recorded at import may legitimately come back ``incomplete`` here.
    assessment = assess_chain(leaf, intermediates, enabled_anchors(db), moment)
    return ChainDiagnostics(assessment.status, assessment.messages)


@dataclass(frozen=True)
class CertificateView:
    """The public fields of a certificate: no PEM, no key reference."""

    id: int
    common_name: str
    subject_dn: str
    sans: tuple[str, ...]
    issuer_dn: str
    issuer_cn: str
    serial: str
    not_before: datetime
    not_after: datetime
    sha256_fingerprint: str
    status: CertificateStatus
    chain_status: ChainStatus
    owner_name: str | None
    owner_email: str | None
    team: str | None
    notes: str | None
    imported_from: str
    renews_id: int | None
    created_at: datetime
    updated_at: datetime
    has_key: bool
    has_chain: bool


@dataclass(frozen=True)
class KeyView:
    key_type: str
    key_size: int
    curve: str | None
    public_key_sha256: str
    master_key_version: int
    created_at: datetime
    origin: str


@dataclass(frozen=True)
class LineageLink:
    id: int
    common_name: str
    status: CertificateStatus
    not_after: datetime


@dataclass(frozen=True)
class RenewalView:
    id: str
    state: str
    common_name: str
    previous_certificate_id: int | None
    certificate_id: int | None
    created_at: datetime
    state_changed_at: datetime


@dataclass(frozen=True)
class AuditView:
    action: str
    actor_label: str
    created_at: datetime
    summary: str


@dataclass(frozen=True)
class BindingView:
    server: str
    vhost_name: str
    port: int
    config_file: str
    cert_path: str
    on_disk_fingerprint: str | None
    match_state: str
    is_active: bool
    last_seen_at: datetime


@dataclass(frozen=True)
class EndpointView:
    host: str
    port: int
    sni: str | None
    is_active: bool
    last_scan_status: str | None
    last_scan_at: datetime | None
    observed_fingerprint: str | None = None
    observed_common_name: str | None = None
    observed_issuer_cn: str | None = None
    observed_not_after: datetime | None = None
    scan_error: str | None = None
    matches_expected: bool | None = None  # None: no certificate was observed (not scanned / failed)


@dataclass(frozen=True)
class CertificateDetail:
    certificate: CertificateView
    key: KeyView | None
    previous: LineageLink | None
    next: list[LineageLink]
    diagnostics: ChainDiagnostics
    renewals: list[RenewalView]
    audit: list[AuditView]
    bindings: list[BindingView]
    endpoints: list[EndpointView]


HISTORY_LIMIT = 50


def _lineage(row: Certificate) -> LineageLink:
    return LineageLink(row.id, row.common_name, row.status, row.not_after)


def _audit_summary(action: str, details: object) -> str:
    if action == "certificate.status_change" and isinstance(details, dict):
        return f"{details.get('from', '?')} → {details.get('to', '?')}: {details.get('reason', '')}"
    return ""


def _endpoint_view(item: Endpoint, scan: ScanResult | None, expected_fingerprint: str) -> EndpointView:
    """An endpoint with what its latest scan observed, compared with the certificate it expects."""
    observed = scan.observed_fingerprint if scan is not None else None
    return EndpointView(
        host=item.host,
        port=item.port,
        sni=item.sni,
        is_active=item.is_active,
        last_scan_status=item.last_scan_status.value if item.last_scan_status is not None else None,
        last_scan_at=item.last_scan_at,
        observed_fingerprint=observed,
        observed_common_name=scan.observed_common_name if scan is not None else None,
        observed_issuer_cn=scan.observed_issuer_cn if scan is not None else None,
        observed_not_after=scan.observed_not_after if scan is not None else None,
        scan_error=(scan.error or "")[:300] or None if scan is not None else None,
        matches_expected=None if observed is None else observed.lower() == expected_fingerprint.lower(),
    )


def certificate_detail(db: Session, certificate_id: int, now: datetime) -> CertificateDetail:
    """Everything the detail screen shows, as plain values (never ORM key rows or PEM)."""
    row = db.get(Certificate, certificate_id)
    if row is None:
        raise InventoryError("not_found", "certificate not found")
    key = db.get(PrivateKey, row.key_id) if row.key_id is not None else None
    previous = db.get(Certificate, row.renews_id) if row.renews_id is not None else None
    following = db.scalars(
        select(Certificate).where(Certificate.renews_id == row.id).order_by(Certificate.not_after, Certificate.id)
    ).all()
    renewals = db.scalars(
        select(Renewal)
        .where(or_(Renewal.certificate_id == row.id, Renewal.previous_certificate_id == row.id))
        .order_by(Renewal.created_at.desc(), Renewal.id)
        .limit(HISTORY_LIMIT)
    ).all()
    audits = db.scalars(
        select(AuditLog)
        .where(AuditLog.target_type == "certificate", AuditLog.target_id == str(row.id))
        .order_by(AuditLog.created_at.desc(), AuditLog.id)
        .limit(HISTORY_LIMIT)
    ).all()
    bindings = db.execute(
        select(Binding, Server.hostname)
        .join(Server, Server.id == Binding.server_id)
        .where(Binding.certificate_id == row.id)
        .order_by(Binding.is_active.desc(), Server.hostname, Binding.vhost_name, Binding.port, Binding.id)
        .limit(500)
    ).all()
    endpoints = db.scalars(
        select(Endpoint)
        .where(Endpoint.expected_certificate_id == row.id)
        .order_by(Endpoint.host, Endpoint.port, Endpoint.id)
        .limit(500)
    ).all()
    latest_scans = {}
    if endpoints:
        latest_scans = {
            scan.endpoint_id: scan
            for scan in db.scalars(
                select(ScanResult)
                .where(ScanResult.endpoint_id.in_([item.id for item in endpoints]))
                .ext(distinct_on(ScanResult.endpoint_id))
                .order_by(ScanResult.endpoint_id, ScanResult.checked_at.desc(), ScanResult.id.desc())
            )
        }
    return CertificateDetail(
        certificate=CertificateView(
            id=row.id,
            common_name=row.common_name,
            subject_dn=row.subject_dn,
            sans=tuple(row.sans),
            issuer_dn=row.issuer_dn,
            issuer_cn=row.issuer_cn,
            serial=row.serial,
            not_before=row.not_before,
            not_after=row.not_after,
            sha256_fingerprint=row.sha256_fingerprint,
            status=row.status,
            chain_status=row.chain_status,
            owner_name=row.owner_name,
            owner_email=row.owner_email,
            team=row.team,
            notes=row.notes,
            imported_from=row.imported_from,
            renews_id=row.renews_id,
            created_at=row.created_at,
            updated_at=row.updated_at,
            has_key=key is not None,
            has_chain=bool(row.chain_pem.strip()),
        ),
        key=None
        if key is None
        else KeyView(
            key_type=key.key_type.value if hasattr(key.key_type, "value") else str(key.key_type),
            key_size=key.key_size,
            curve=key.curve,
            public_key_sha256=key.public_key_sha256,
            master_key_version=key.master_key_version,
            created_at=key.created_at,
            origin=key.origin,
        ),
        previous=_lineage(previous) if previous is not None else None,
        next=[_lineage(item) for item in following],
        diagnostics=diagnose_chain(db, row, now),
        renewals=[
            RenewalView(
                id=str(item.id),
                state=item.state.value,
                common_name=item.common_name,
                previous_certificate_id=item.previous_certificate_id,
                certificate_id=item.certificate_id,
                created_at=item.created_at,
                state_changed_at=item.state_changed_at,
            )
            for item in renewals
        ],
        audit=[
            AuditView(item.action, item.actor_label, item.created_at, _audit_summary(item.action, item.details))
            for item in audits
        ],
        bindings=[
            BindingView(
                server=hostname,
                vhost_name=binding.vhost_name,
                port=binding.port,
                config_file=binding.config_file,
                cert_path=binding.cert_path,
                on_disk_fingerprint=binding.on_disk_fingerprint,
                match_state=binding.match_state,
                is_active=binding.is_active,
                last_seen_at=binding.last_seen_at,
            )
            for binding, hostname in bindings
        ],
        endpoints=[_endpoint_view(item, latest_scans.get(item.id), row.sha256_fingerprint) for item in endpoints],
    )
