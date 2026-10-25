"""Audited, row-locked manual-CA renewal state machine and the issued-certificate gate.

Every transition ``SELECT ... FOR UPDATE``s the renewal, checks the source state *before any
write*, mutates, writes exactly one ``renewal.*`` audit and flushes. Nothing here commits: the
caller owns the transaction, so a failed transition leaves state, inventory and audit untouched.

Typed failures (mapped to HTTP 4xx by the wizard):
``InvalidTransition`` (wrong source state or missing deploy evidence), ``RenewalValidationError``
(field errors), ``IssuedValidationError`` (blocking issued-certificate checks, all reported
together) and ``RenewalError`` (``not_found``, ``previous_not_active``).
"""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Literal
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from sqlalchemy import and_, exists, or_, select
from sqlalchemy.orm import Session

from app.crypto.chain import ChainError, ChainResult, order_chain
from app.crypto.csr import _identity, build_csr, canonical_sans, validate_csr
from app.crypto.keyring import Keyring
from app.crypto.keys import KeySpec, generate_key, public_key_sha256
from app.crypto.parse import ParsedCertificate, ParseError, parse_certificates
from app.models import Certificate, Job, JobHost, JSONValue, PrivateKey, Renewal
from app.models.enums import (
    CertificateStatus,
    ChainStatus,
    JobHostStatus,
    JobStatus,
    JobType,
    RenewalState,
)
from app.services.audit import Actor, record
from app.services.certificates import (
    CertificateMetadata,
    InventoryError,
    _looks_like_pfx,
    diagnose_chain,
    save_certificate,
    set_status,
    store_key,
)

_ORDER_REFERENCE_LIMIT = 200
_CA_NAME_LIMIT = 200
_NOTES_LIMIT = 10_000
_REASON_LIMIT = 1_000
_CANCELLABLE = frozenset(
    {RenewalState.DRAFT, RenewalState.CSR_GENERATED, RenewalState.SUBMITTED, RenewalState.ISSUED}
)
_LISTED_IDENTITIES = 10


class RenewalError(Exception):
    """Typed renewal failure; ``code`` is stable and ``message`` is safe to show."""

    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


class InvalidTransition(RenewalError):
    """The action is not legal from the renewal's current state (or lacks its evidence)."""

    def __init__(self, from_state: RenewalState, action: str, reason: str | None = None) -> None:
        detail = f"cannot {action} a renewal in state {from_state.value}"
        super().__init__(reason or "invalid_transition", detail + (f" ({reason})" if reason else ""))
        self.from_state = from_state
        self.action = action
        self.reason = reason


class _FieldErrors(Exception):
    def __init__(self, errors: Mapping[str, tuple[str, ...]]) -> None:
        self.errors: Mapping[str, tuple[str, ...]] = MappingProxyType(
            {key: tuple(messages) for key, messages in errors.items()}
        )
        super().__init__("; ".join(sorted(self.errors)))


class RenewalValidationError(_FieldErrors):
    """Invalid user input for a transition; ``errors`` maps field name to messages."""


class IssuedValidationError(_FieldErrors):
    """The issued certificate failed blocking checks; nothing was written."""


@dataclass(frozen=True)
class RenewalBasics:
    common_name: str
    sans: tuple[str, ...]
    ca_name: str | None = None
    notes: str | None = None


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _uuid(value: UUID | str) -> UUID | None:
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except ValueError:
        return None


def _lock(db: Session, renewal_id: UUID | str) -> Renewal:
    key = _uuid(renewal_id)
    row = (
        None
        if key is None
        else db.scalar(
            select(Renewal)
            .where(Renewal.id == key)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    )
    if row is None:
        raise RenewalError("not_found", "renewal not found")
    return row


def _guard(db: Session, renewal_id: UUID | str, action: str, allowed: frozenset[RenewalState]) -> Renewal:
    row = _lock(db, renewal_id)
    if row.state not in allowed:
        raise InvalidTransition(row.state, action)
    return row


def _advance(row: Renewal, state: RenewalState, now: datetime) -> None:
    row.state = state
    row.state_changed_at = now


def _message(exc: Exception) -> str:
    # Only crypto-layer ValueErrors carry fixed, input-free messages.
    return str(exc) if isinstance(exc, ValueError) else "invalid value"


def _optional_text(
    field: str, value: object, limit: int, errors: dict[str, tuple[str, ...]]
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        errors[field] = (f"{field} must be text",)
        return None
    cleaned = value.strip()
    if len(cleaned) > limit:
        errors[field] = (f"{field} must be at most {limit:,} characters",)
        return None
    return cleaned or None


def _required_text(field: str, value: object, limit: int) -> str:
    cleaned = value.strip() if isinstance(value, str) else ""
    if not cleaned or len(cleaned) > limit:
        raise RenewalValidationError({field: (f"{field} is required (1 to {limit:,} characters)",)})
    return cleaned


def _clean_basics(basics: RenewalBasics) -> tuple[str, list[str], str | None, str | None]:
    errors: dict[str, tuple[str, ...]] = {}
    common_name = basics.common_name.strip() if isinstance(basics.common_name, str) else ""
    raw_sans = basics.sans if isinstance(basics.sans, (tuple, list)) else ()
    sans = tuple(value.strip() if isinstance(value, str) else value for value in raw_sans)
    try:
        _identity(common_name, [common_name])
    except (ValueError, TypeError) as exc:
        errors["common_name"] = (_message(exc),)
    try:
        canonical_sans(sans)
    except (ValueError, TypeError) as exc:
        errors["sans"] = (_message(exc),)
    values: list[str] = []
    if not errors:
        try:
            common_name, canonical = _identity(common_name, sans)
            values = list(canonical)
        except (ValueError, TypeError) as exc:  # CN inclusion pushed the set past 100 identities.
            errors["sans"] = (_message(exc),)
    ca_name = _optional_text("ca_name", basics.ca_name, _CA_NAME_LIMIT, errors)
    notes = _optional_text("notes", basics.notes, _NOTES_LIMIT, errors)
    if errors:
        raise RenewalValidationError(errors)
    return common_name, values, ca_name, notes


# --------------------------------------------------------------------------
# draft / edit / csr / submit
# --------------------------------------------------------------------------


def create_draft(
    db: Session, previous_id: int | None, basics: RenewalBasics, actor: Actor, now: datetime
) -> Renewal:
    common_name, sans, ca_name, notes = _clean_basics(basics)
    if previous_id is not None:
        previous = db.scalar(select(Certificate).where(Certificate.id == previous_id))
        if previous is None or previous.status != CertificateStatus.ACTIVE:
            raise RenewalError("previous_not_active", "the certificate to renew must exist and be active")
    row = Renewal(
        previous_certificate_id=previous_id,
        state=RenewalState.DRAFT,
        common_name=common_name,
        sans=sans,
        ca_name=ca_name,
        notes=notes,
        state_changed_at=now,
        created_by=actor.user_id,
    )
    db.add(row)
    db.flush()
    record(
        db,
        actor,
        "renewal.create",
        "renewal",
        str(row.id),
        {
            "previous_certificate_id": previous_id,
            "common_name": common_name,
            "sans": list(sans),
            "ca_name": ca_name,
        },
    )
    return row


def edit_draft(
    db: Session, renewal_id: UUID, basics: RenewalBasics, actor: Actor, now: datetime
) -> Renewal:
    row = _guard(db, renewal_id, "edit_draft", frozenset({RenewalState.DRAFT}))
    common_name, sans, ca_name, notes = _clean_basics(basics)
    new = {"common_name": common_name, "sans": sans, "ca_name": ca_name, "notes": notes}
    changed = [name for name, value in new.items() if getattr(row, name) != value]
    for name in changed:
        setattr(row, name, new[name])
    db.flush()
    record(
        db,
        actor,
        "renewal.edit",
        "renewal",
        str(row.id),
        {"changed": changed, "common_name": row.common_name, "sans": list(row.sans)},
    )
    return row


def generate_csr(
    db: Session, renewal_id: UUID, spec: KeySpec, keyring: Keyring, actor: Actor, now: datetime
) -> Renewal:
    row = _guard(db, renewal_id, "generate_csr", frozenset({RenewalState.DRAFT}))
    try:
        key = generate_key(spec)
    except ValueError:
        raise RenewalValidationError(
            {"key": ("Unsupported key: use RSA 2048/3072/4096 or ECDSA P-256/P-384",)}
        ) from None
    key_row = store_key(db, keyring, key, "generated", actor)
    csr = build_csr(key, row.common_name, row.sans)
    row.key_id = key_row.id
    row.csr_pem = csr.pem
    row.csr_sha256 = csr.sha256
    _advance(row, RenewalState.CSR_GENERATED, now)
    db.flush()
    details: dict[str, JSONValue] = {
        "csr_sha256": csr.sha256,
        "key_type": key_row.key_type.value,
        "key_size": key_row.key_size,
        "key_id": key_row.id,
    }
    if key_row.curve is not None:
        details["curve"] = key_row.curve
    record(db, actor, "renewal.csr_generated", "renewal", str(row.id), details)
    return row


def mark_submitted(
    db: Session, renewal_id: UUID, order_reference: str, actor: Actor, now: datetime
) -> Renewal:
    row = _guard(db, renewal_id, "mark_submitted", frozenset({RenewalState.CSR_GENERATED}))
    reference = _required_text("order_reference", order_reference, _ORDER_REFERENCE_LIMIT)
    row.ca_order_reference = reference
    row.submitted_by = actor.user_id
    _advance(row, RenewalState.SUBMITTED, now)
    db.flush()
    record(db, actor, "renewal.submitted", "renewal", str(row.id), {"order_reference": reference})
    return row


# --------------------------------------------------------------------------
# Issued-certificate gate
# --------------------------------------------------------------------------


def _is_self_signed(cert: x509.Certificate) -> bool:
    if cert.subject != cert.issuer:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except Exception:  # noqa: BLE001 - any crypto failure means "not validly self-signed".
        return False
    return True


def _typed_sans(cert: x509.Certificate) -> frozenset[str]:
    """Canonical typed SAN set of a certificate; unsupported or invalid entries never match."""
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return frozenset()
    except (ValueError, x509.DuplicateExtension):
        return frozenset({"unreadable:SAN extension"})
    result: set[str] = set()
    for name in names:
        if isinstance(name, x509.DNSName):
            typed = "DNS:" + name.value
        elif isinstance(name, x509.IPAddress):
            typed = "IP:" + str(name.value)
        elif isinstance(name, x509.RFC822Name):
            typed = "email:" + name.value
        elif isinstance(name, x509.UniformResourceIdentifier):
            typed = "URI:" + name.value
        else:
            result.add("unsupported:" + type(name).__name__)
            continue
        try:
            result.add(canonical_sans([typed])[0])
        except ValueError:
            result.add("invalid:" + typed)
    return frozenset(result)


def _listed(values: set[str]) -> str:
    ordered = sorted(values)
    shown = ", ".join(item[:120] for item in ordered[:_LISTED_IDENTITIES])
    return shown + (f" and {len(ordered) - _LISTED_IDENTITIES} more" if len(ordered) > _LISTED_IDENTITIES else "")


def _check_names(row: Renewal, leaf: ParsedCertificate, errors: dict[str, list[str]]) -> None:
    actual_cns: list[str] = []
    for attribute in leaf.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        try:
            actual_cns.append(canonical_sans([str(attribute.value)])[0])
        except ValueError:
            actual_cns.append(str(attribute.value)[:120])
    if actual_cns != [row.common_name]:
        found = ", ".join(actual_cns) if actual_cns else "none"
        errors.setdefault("common_name", []).append(
            f"The certificate subject CN ({found}) must be exactly {row.common_name}."
        )
    expected, actual = set(row.sans), set(_typed_sans(leaf.cert))
    if actual != expected:
        parts = []
        if expected - actual:
            parts.append(f"missing {_listed(expected - actual)}")
        if actual - expected:
            parts.append(f"unexpected {_listed(actual - expected)}")
        errors.setdefault("sans", []).append(
            "The certificate SANs must match the renewal exactly: " + "; ".join(parts) + "."
        )


def _check_keys(db: Session, row: Renewal, leaf: ParsedCertificate, errors: dict[str, list[str]]) -> None:
    key = db.get(PrivateKey, row.key_id)
    key_hash = key.public_key_sha256 if key is not None else "unavailable"
    if leaf.public_key_sha256 != key_hash:
        errors.setdefault("key_match", []).append(
            f"The certificate public key (SHA-256 {leaf.public_key_sha256}) does not match the "
            f"renewal key (SHA-256 {key_hash})."
        )
    try:
        csr = x509.load_pem_x509_csr((row.csr_pem or "").encode("ascii"))
        signature_valid = csr.is_signature_valid
        csr_hash = public_key_sha256(csr.public_key())
        csr_der_sha256 = hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest()
    except (ValueError, UnicodeError, UnsupportedAlgorithm, TypeError):
        errors.setdefault("csr_signature", []).append("The stored CSR could not be read or verified.")
        return
    if csr_der_sha256 != row.csr_sha256:
        errors.setdefault("csr_hash", []).append(
            f"The stored CSR (SHA-256 {csr_der_sha256}) does not match the frozen CSR hash "
            f"({row.csr_sha256})."
        )
    # The CSR must still say exactly what the renewal froze: CN-only subject and the SAN set.
    identity = [
        message
        for message in validate_csr(row.csr_pem, row.common_name, row.sans, csr_hash)
        if "subject" in message or "SANs" in message
    ]
    if identity:
        errors.setdefault("csr_identity", []).append(
            "The stored CSR subject/SANs do not match the renewal's frozen names: " + "; ".join(identity) + "."
        )
    if not signature_valid:
        errors.setdefault("csr_signature", []).append("The stored CSR signature is invalid.")
    if leaf.public_key_sha256 != csr_hash:
        errors.setdefault("csr_match", []).append(
            f"The certificate public key (SHA-256 {leaf.public_key_sha256}) does not match the "
            f"CSR public key (SHA-256 {csr_hash})."
        )


def _parse_leaf(leaf_data: bytes, errors: dict[str, list[str]]) -> ParsedCertificate | None:
    if not isinstance(leaf_data, (bytes, bytearray)) or not leaf_data:
        errors["parse"] = ["No certificate was supplied."]
        return None
    data = bytes(leaf_data)
    if _looks_like_pfx(data):
        errors["parse"] = [
            ("pfx_not_accepted: PKCS#12/PFX bundles are not accepted here; upload the issued certificate as PEM or DER.")
        ]
        return None
    try:
        parsed = parse_certificates(data)
    except ParseError:
        errors["parse"] = ["The input is not a valid PEM or DER encoded X.509 certificate."]
        return None
    if len(parsed) != 1:
        errors["parse"] = [
            (f"Expected exactly one certificate (the leaf) but found {len(parsed)}; supply intermediates in the chain field.")
        ]
        return None
    return parsed[0]


def _parse_chain(chain_data: bytes, errors: dict[str, list[str]]) -> list[x509.Certificate] | None:
    try:
        return [item.cert for item in parse_certificates(bytes(chain_data))]
    except ParseError:
        errors.setdefault("chain", []).append(
            "The chain could not be parsed: supply PEM or DER encoded intermediate certificates only."
        )
        return None


def _stored_chain(db: Session, row: Renewal, leaf: ParsedCertificate) -> ChainResult:
    """The previous certificate's stored chain, when it actually links to the new leaf."""
    previous = (
        db.get(Certificate, row.previous_certificate_id) if row.previous_certificate_id is not None else None
    )
    if previous is not None and previous.chain_pem.strip():
        try:
            candidates = [item.cert for item in parse_certificates(previous.chain_pem.encode("ascii"))]
            result = order_chain(leaf.cert, candidates)
        except (ParseError, ChainError, UnicodeError):
            result = None
        if result is not None and result.fingerprints:
            return result
    return order_chain(leaf.cert, [])


def attach_issued(
    db: Session,
    renewal_id: UUID,
    leaf_data: bytes,
    chain_data: bytes | None,
    actor: Actor,
    now: datetime,
) -> Renewal:
    row = _guard(db, renewal_id, "attach_issued", frozenset({RenewalState.SUBMITTED}))
    errors: dict[str, list[str]] = {}
    leaf = _parse_leaf(leaf_data, errors)
    chain_supplied = isinstance(chain_data, (bytes, bytearray)) and bool(bytes(chain_data).strip())
    candidates = _parse_chain(chain_data, errors) if chain_supplied else None
    chain: ChainResult | None = None
    if leaf is not None:
        _check_keys(db, row, leaf, errors)
        _check_names(row, leaf, errors)
        if now >= leaf.not_after:
            errors.setdefault("validity", []).append(
                f"The certificate expired on {leaf.not_after.isoformat()}."
            )
        elif now < leaf.not_before:
            errors.setdefault("validity", []).append(
                f"The certificate is not yet valid (valid from {leaf.not_before.isoformat()})."
            )
        if _is_self_signed(leaf.cert):
            errors.setdefault("self_signed", []).append(
                "The certificate is self-signed; it was not issued by a CA."
            )
        existing = db.scalar(
            select(Certificate.id)
            .where(
                or_(
                    Certificate.sha256_fingerprint == leaf.sha256_fingerprint,
                    and_(Certificate.issuer_dn == leaf.issuer_dn, Certificate.serial == leaf.serial),
                )
            )
            .limit(1)
        )
        if existing is not None:
            errors.setdefault("duplicate", []).append(
                f"This certificate (or one with the same issuer and serial) is already in the "
                f"inventory as certificate #{existing}."
            )
        if not chain_supplied:
            chain = _stored_chain(db, row, leaf)
        elif candidates is not None:
            try:
                chain = order_chain(leaf.cert, candidates)
            except ChainError:
                errors.setdefault("chain", []).append(
                    "The chain contains a certificate that claims to be the leaf's issuer but its "
                    "signature does not verify."
                )
    if errors:
        raise IssuedValidationError({key: tuple(messages) for key, messages in errors.items()})
    assert leaf is not None and chain is not None  # no errors implies both were produced.

    previous = (
        db.get(Certificate, row.previous_certificate_id) if row.previous_certificate_id is not None else None
    )
    metadata = (
        CertificateMetadata(
            owner_name=previous.owner_name, owner_email=previous.owner_email, team=previous.team
        )
        if previous is not None
        else CertificateMetadata()
    )
    try:
        # Savepoint: an unexpected inventory failure must not leave a partial import behind.
        with db.begin_nested():
            result = save_certificate(
                db,
                leaf,
                chain,
                metadata,
                actor,
                source="renewal",
                key_id=row.key_id,
                renews_id=row.previous_certificate_id,
                validation_time=now,
            )
            if not result.created:  # lost a race with a concurrent import of the same certificate
                raise IssuedValidationError(
                    {"duplicate": ("This certificate was imported concurrently and is already in the inventory.",)}
                )
    except InventoryError as exc:
        raise IssuedValidationError({"certificate": (exc.message,)}) from None
    certificate = result.certificate
    row.certificate_id = certificate.id
    row.issued_chain_pem = chain.pem
    row.issued_by = actor.user_id
    _advance(row, RenewalState.ISSUED, now)
    db.flush()
    record(
        db,
        actor,
        "renewal.issued",
        "renewal",
        str(row.id),
        {
            "certificate_id": certificate.id,
            "fingerprint": certificate.sha256_fingerprint,
            "chain_status": certificate.chain_status.value,
            "warnings": list(result.warnings),
        },
    )
    return row


def issued_warnings(db: Session, renewal_id: UUID, now: datetime) -> tuple[str, ...]:
    """Non-blocking trust diagnostics of the issued certificate, recomputed at ``now`` (read-only)."""
    row = _peek(db, renewal_id)
    certificate = db.get(Certificate, row.certificate_id) if row.certificate_id is not None else None
    if certificate is None:
        return ()
    warnings: list[str] = []
    if certificate.not_after <= now:
        warnings.append("expired")
    diagnostics = diagnose_chain(db, certificate, now)
    if diagnostics.status != ChainStatus.TRUSTED:
        if certificate.chain_status == ChainStatus.UNTRUSTED_ROOT:
            # Stored chains never contain the root, so only the persisted assessment knows it.
            warnings.append("untrusted_root")
        else:
            warnings.extend(diagnostics.messages)
    return tuple(dict.fromkeys(warnings))


def _peek(db: Session, renewal_id: UUID | str) -> Renewal:
    key = _uuid(renewal_id)
    row = None if key is None else db.get(Renewal, key)
    if row is None:
        raise RenewalError("not_found", "renewal not found")
    return row


# --------------------------------------------------------------------------
# deploy / finalize / cancel
# --------------------------------------------------------------------------


def mark_deployed(
    db: Session, renewal_id: UUID, job_id: UUID, actor: Actor, now: datetime
) -> Renewal:
    """Service hook for the Plan 3 deploy handler; evidence is verified, never trusted."""
    row = _guard(db, renewal_id, "mark_deployed", frozenset({RenewalState.ISSUED}))

    def refuse(reason: str) -> InvalidTransition:
        return InvalidTransition(row.state, "mark_deployed", reason)

    job_key = _uuid(job_id)
    job = db.get(Job, job_key) if job_key is not None else None
    payload = job.payload if job is not None else None
    if (
        job is None
        or job.type != JobType.DEPLOY
        or not isinstance(payload, dict)
        or type(payload.get("certificate_id")) is not int
        or payload["certificate_id"] != row.certificate_id
    ):
        raise refuse("job_unrelated")
    if job.status != JobStatus.SUCCEEDED:
        raise refuse("job_not_succeeded")
    certificate = db.get(Certificate, row.certificate_id)
    has_evidence = db.scalar(
        select(
            exists().where(
                JobHost.job_id == job.id,
                JobHost.status == JobHostStatus.SUCCEEDED,
                JobHost.binding_id.is_not(None),
                JobHost.new_fingerprint == certificate.sha256_fingerprint,
            )
        )
    )
    if not has_evidence:
        raise refuse("no_succeeded_binding")
    row.deployed_by = actor.user_id
    _advance(row, RenewalState.DEPLOYED, now)
    db.flush()
    record(db, actor, "renewal.deployed", "renewal", str(row.id), {"job_id": str(job.id)})
    return row


def finalize(
    db: Session,
    renewal_id: UUID,
    previous_status: Literal["superseded", "revoked"],
    reason: str,
    actor: Actor,
    now: datetime,
) -> Renewal:
    row = _guard(db, renewal_id, "finalize", frozenset({RenewalState.DEPLOYED}))
    errors: dict[str, tuple[str, ...]] = {}
    if previous_status not in ("superseded", "revoked"):
        errors["previous_status"] = ("previous_status must be superseded or revoked",)
    note = reason.strip() if isinstance(reason, str) else ""
    if len(note) > _REASON_LIMIT or (previous_status == "revoked" and not note):
        errors["reason"] = (f"reason is required to revoke (1 to {_REASON_LIMIT:,} characters)",)
    if errors:
        raise RenewalValidationError(errors)
    changed = False
    if row.previous_certificate_id is not None:
        try:
            set_status(
                db,
                row.previous_certificate_id,
                CertificateStatus(previous_status),
                note or f"Superseded by renewal {row.id}",
                actor,
            )
            changed = True
        except InventoryError as exc:
            # Already superseded/revoked by someone else: nothing left to change.
            if exc.code != "invalid_status":
                raise
    _advance(row, RenewalState.DONE, now)
    db.flush()
    record(
        db,
        actor,
        "renewal.done",
        "renewal",
        str(row.id),
        {"previous_status": previous_status, "previous_changed": changed, "reason": note or None},
    )
    return row


def cancel(db: Session, renewal_id: UUID, reason: str, actor: Actor, now: datetime) -> Renewal:
    row = _guard(db, renewal_id, "cancel", _CANCELLABLE)
    cleaned = _required_text("reason", reason, _REASON_LIMIT)
    from_state = row.state
    # The key, CSR and any already-issued certificate are deliberately kept.
    _advance(row, RenewalState.CANCELLED, now)
    db.flush()
    record(
        db,
        actor,
        "renewal.cancelled",
        "renewal",
        str(row.id),
        {"from_state": from_state.value, "reason": cleaned},
    )
    return row
