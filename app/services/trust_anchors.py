"""Trust-anchor uploads, the pinned public bundle, and synchronous rechecks."""

import re
import warnings
from collections.abc import Sequence
from datetime import datetime
from functools import lru_cache
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.parse import ParsedCertificate, ParseError, parse_certificates
from app.crypto.trust import ChainAssessment, assess_chain
from app.models import AppSetting, Certificate, TrustAnchor
from app.models.enums import ChainStatus
from app.services.audit import Actor, record

_MAX_CERTIFICATES = 500
_BUNDLE_BLOCK = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


class AnchorValidationError(ValueError):
    """An uploaded trust anchor is not a usable CA root."""


def _load_bundle_certificate(block: bytes) -> x509.Certificate | None:
    try:
        return x509.load_pem_x509_certificate(block)
    except Exception:  # noqa: BLE001 - skip only unloadable bundle entries.
        return None


@lru_cache(maxsize=1)
def public_bundle_anchors() -> tuple[x509.Certificate, ...]:
    try:
        raw = Path(certifi.where()).read_bytes()
    except OSError:
        return ()
    # The pinned certifi bundle contains a legacy root whose non-positive serial is
    # deprecated by cryptography; suppress only that noise and keep every loadable root.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return tuple(
            certificate
            for block in _BUNDLE_BLOCK.findall(raw)
            if (certificate := _load_bundle_certificate(block)) is not None
        )


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _dedupe(certs: Sequence[x509.Certificate]) -> tuple[x509.Certificate, ...]:
    seen: set[str] = set()
    result: list[x509.Certificate] = []
    for cert in certs:
        fingerprint = _fingerprint(cert)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.append(cert)
    return tuple(result)


def load_anchors(db: Session) -> tuple[x509.Certificate, ...]:
    anchors: list[x509.Certificate] = []
    for row in db.scalars(select(TrustAnchor).order_by(TrustAnchor.id)).all():
        try:
            parsed = parse_certificates(row.pem.encode("ascii"))
        except (ParseError, UnicodeError):
            continue
        if len(parsed) == 1:
            anchors.append(parsed[0].cert)
    return _dedupe(anchors)


def _enabled_anchors(db: Session) -> tuple[x509.Certificate, ...]:
    anchors = list(load_anchors(db))
    setting = db.scalar(select(AppSetting.value).where(AppSetting.key == "trust.include_public_bundle"))
    if bool(setting):
        anchors.extend(public_bundle_anchors())
    return _dedupe(anchors)


def _require_root(pem: bytes) -> ParsedCertificate:
    if not isinstance(pem, (bytes, bytearray)) or b"-----BEGIN CERTIFICATE-----" not in pem:
        raise AnchorValidationError("anchor must be a single PEM certificate")
    try:
        parsed = parse_certificates(bytes(pem))
    except ParseError as exc:
        raise AnchorValidationError(str(exc)) from None
    if len(parsed) != 1:
        raise AnchorValidationError("anchor must be a single PEM certificate")
    cert = parsed[0].cert
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise AnchorValidationError("anchor must be a CA:TRUE certificate") from None
    if not constraints.ca:
        raise AnchorValidationError("anchor must be a CA:TRUE certificate")
    if cert.subject != cert.issuer:
        raise AnchorValidationError("anchor must be a self-signed root")
    try:
        cert.verify_directly_issued_by(cert)
    except Exception:  # noqa: BLE001
        raise AnchorValidationError("anchor self-signature is invalid") from None
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        raise AnchorValidationError("anchor must include KeyUsage with certificate signing") from None
    if not usage.key_cert_sign:
        raise AnchorValidationError("anchor must allow certificate signing")
    return parsed[0]


def add_anchor(
    db: Session,
    pem: bytes,
    notes: str | None,
    actor: Actor,
    validation_time: datetime,
) -> TrustAnchor:
    parsed = _require_root(pem)
    if db.scalar(select(TrustAnchor.id).where(TrustAnchor.sha256_fingerprint == parsed.sha256_fingerprint)):
        raise AnchorValidationError("anchor already exists")
    row = TrustAnchor(
        subject=parsed.subject_dn,
        sha256_fingerprint=parsed.sha256_fingerprint,
        pem=parsed.pem,
        source="uploaded",
        notes=notes,
        created_by=actor.user_id,
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        raise AnchorValidationError("anchor already exists") from None
    record(
        db,
        actor,
        "trust_anchor.add",
        "trust_anchor",
        str(row.id),
        {
            "sha256_fingerprint": parsed.sha256_fingerprint,
            "subject": parsed.subject_dn,
            "notes": notes,
        },
    )
    recheck_chain_statuses(db, validation_time)
    return row


def remove_anchor(db: Session, anchor_id: int, actor: Actor, validation_time: datetime) -> None:
    row = db.get(TrustAnchor, anchor_id)
    if row is None:
        raise AnchorValidationError("anchor not found")
    removed: x509.Certificate | None = None
    try:
        parsed = parse_certificates(row.pem.encode("ascii"))
    except (ParseError, UnicodeError):
        parsed = []
    if len(parsed) == 1:
        removed = parsed[0].cert
    record(
        db,
        actor,
        "trust_anchor.remove",
        "trust_anchor",
        str(row.id),
        {"sha256_fingerprint": row.sha256_fingerprint, "subject": row.subject},
    )
    db.delete(row)
    db.flush()
    recheck_chain_statuses(db, validation_time, (removed,) if removed is not None else ())


def recheck_chain_statuses(
    db: Session,
    validation_time: datetime,
    diagnostic_roots: Sequence[x509.Certificate] = (),
) -> dict[str, int]:
    anchors = _enabled_anchors(db)
    counts: dict[str, int] = {}
    rows = db.scalars(select(Certificate).order_by(Certificate.id).limit(_MAX_CERTIFICATES)).all()
    for row in rows:
        try:
            leaf = parse_certificates(row.pem.encode("ascii"))[0].cert
        except (ParseError, UnicodeError):
            assessment = ChainAssessment(
                ChainStatus.INCOMPLETE, ("unparseable_certificate",), validation_time
            )
        else:
            intermediates: list[x509.Certificate] = []
            if row.chain_pem.strip():
                try:
                    intermediates = [item.cert for item in parse_certificates(row.chain_pem.encode("ascii"))]
                except (ParseError, UnicodeError):
                    intermediates = []
            assessment = assess_chain(leaf, intermediates, anchors, validation_time, diagnostic_roots)
        counts[assessment.status.value] = counts.get(assessment.status.value, 0) + 1
        if row.chain_status != assessment.status:
            row.chain_status = assessment.status
            record(
                db,
                Actor(None, "system"),
                "certificate.chain_check",
                "certificate",
                str(row.id),
                {
                    "status": assessment.status.value,
                    "validation_time": validation_time.isoformat(),
                },
            )
    db.flush()
    return counts
