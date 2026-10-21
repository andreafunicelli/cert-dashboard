"""Offline trust-path assessment against configured anchors; no network access."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.verification import PolicyBuilder, Store

from app.crypto.chain import ChainError, order_chain
from app.models.enums import ChainStatus


@dataclass(frozen=True)
class ChainAssessment:
    status: ChainStatus
    messages: tuple[str, ...]
    validation_time: datetime


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _valid(cert: x509.Certificate, moment: datetime) -> bool:
    return cert.not_valid_before_utc <= moment < cert.not_valid_after_utc


def _unique(certificates: Sequence[x509.Certificate]) -> list[x509.Certificate]:
    seen: set[str] = set()
    result: list[x509.Certificate] = []
    for cert in certificates:
        fingerprint = _fingerprint(cert)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.append(cert)
    return result


def _identity(leaf: x509.Certificate) -> x509.GeneralName | None:
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    for name in names:
        if isinstance(name, x509.DNSName):
            value = name.value
            if value.startswith("*."):
                value = "www." + value[2:]
            if not value or "*" in value:
                return None
            return x509.DNSName(value)
        if isinstance(name, x509.IPAddress):
            return x509.IPAddress(name.value)
    return None


def _issued_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        child.verify_directly_issued_by(issuer)
    except Exception:  # noqa: BLE001 - any crypto failure means "no valid link".
        return False
    return True


def _terminal_root(
    leaf: x509.Certificate,
    path: Sequence[x509.Certificate],
    supplied: Sequence[x509.Certificate],
) -> x509.Certificate | None:
    terminal = path[-1] if path else leaf
    for candidate in supplied:
        if candidate.subject != terminal.issuer or candidate.subject != candidate.issuer:
            continue
        if not _issued_by(terminal, candidate):
            continue
        return candidate
    if terminal.subject == terminal.issuer and _issued_by(terminal, terminal):
        return terminal
    return None


def _verified(
    leaf: x509.Certificate,
    supplied: Sequence[x509.Certificate],
    anchors: Sequence[x509.Certificate],
    identity: x509.GeneralName,
    validation_time: datetime,
) -> bool:
    try:
        verifier = (
            PolicyBuilder()
            .time(validation_time)
            .store(Store(anchors))
            .build_server_verifier(identity)
        )
        verifier.verify(leaf, supplied)
    except Exception:  # noqa: BLE001 - any verifier failure is a non-trusted result.
        return False
    return True


def assess_chain(
    leaf: x509.Certificate,
    intermediates: Sequence[x509.Certificate],
    anchors: Sequence[x509.Certificate],
    validation_time: datetime,
    diagnostic_roots: Sequence[x509.Certificate] = (),
) -> ChainAssessment:
    supplied = _unique([*intermediates, *diagnostic_roots])
    if not _valid(leaf, validation_time):
        return ChainAssessment(ChainStatus.INCOMPLETE, ("leaf_not_valid",), validation_time)
    try:
        structural = order_chain(leaf, supplied)
    except ChainError:
        return ChainAssessment(ChainStatus.INCOMPLETE, ("forged_issuer",), validation_time)
    by_fingerprint = {_fingerprint(cert): cert for cert in supplied}
    path = [by_fingerprint[fp] for fp in structural.fingerprints if fp in by_fingerprint]
    identity = _identity(leaf)
    if identity is None:
        return ChainAssessment(ChainStatus.INCOMPLETE, ("missing_identity",), validation_time)

    anchor_list = _unique(anchors)
    if anchor_list and _verified(leaf, supplied, anchor_list, identity, validation_time):
        return ChainAssessment(ChainStatus.TRUSTED, (), validation_time)
    for cert in path:
        if not _valid(cert, validation_time):
            code = (
                "expired_intermediate"
                if cert.not_valid_after_utc <= validation_time
                else "not_yet_valid_intermediate"
            )
            return ChainAssessment(
                ChainStatus.INCOMPLETE,
                (code, f"intermediate:{cert.subject.rfc4514_string()}"),
                validation_time,
            )

    root = _terminal_root(leaf, path, [*supplied, *anchor_list])
    anchor_fingerprints = {_fingerprint(cert) for cert in anchor_list}
    if root is not None:
        if _fingerprint(root) in anchor_fingerprints:
            return ChainAssessment(ChainStatus.INCOMPLETE, ("policy_failure",), validation_time)
        return ChainAssessment(
            ChainStatus.UNTRUSTED_ROOT,
            ("untrusted_root", f"root:{root.subject.rfc4514_string()}"),
            validation_time,
        )
    if structural.missing_issuer is not None:
        return ChainAssessment(
            ChainStatus.INCOMPLETE,
            ("missing_issuer", f"issuer:{structural.missing_issuer}"),
            validation_time,
        )
    return ChainAssessment(ChainStatus.INCOMPLETE, ("policy_failure",), validation_time)
