"""Transactional key custody and the deduplicated, audited certificate inventory.

Every mutation stages its audit row in the caller's transaction; nothing here
commits. Typed ``InventoryError`` codes are mapped to 422 by the callers.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.chain import ChainError, ChainResult, order_chain
from app.crypto.keyring import Keyring, KeyUnwrapError, WrappedSecret, unwrap, wrap
from app.crypto.keys import PrivateKeyObject, load_private_key, private_key_pem, public_key_sha256
from app.crypto.parse import MAX_INPUT_BYTES, ParsedCertificate, ParseError, parse_certificates
from app.crypto.trust import ChainAssessment, assess_chain
from app.models import Certificate, JSONValue, PrivateKey, User
from app.models.enums import CertificateStatus, ChainStatus
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
