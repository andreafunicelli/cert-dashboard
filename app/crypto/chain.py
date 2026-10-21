"""Deterministic structural chain ordering; trust decisions belong to Task 6A."""

from collections.abc import Sequence
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.crypto.parse import ParseError, parse_certificates


class ChainError(ValueError):
    """Chain input is malformed or claims a forged issuer link."""


@dataclass(frozen=True)
class ChainResult:
    pem: str
    fingerprints: tuple[str, ...]
    dropped: tuple[str, ...]
    missing_issuer: str | None
    diagnostic_roots: tuple[x509.Certificate, ...] = field(repr=False, compare=False)


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _verifies(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        child.verify_directly_issued_by(issuer)
    except Exception:  # noqa: BLE001 - any crypto failure means "no valid link".
        return False
    return True


def _self_signed(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer and _verifies(cert, cert)


def order_chain(leaf: x509.Certificate, candidates: Sequence[x509.Certificate]) -> ChainResult:
    if not isinstance(leaf, x509.Certificate):
        raise ChainError("leaf is not a certificate")
    notes: set[str] = set()
    unique: dict[str, x509.Certificate] = {}
    for candidate in candidates:
        if not isinstance(candidate, x509.Certificate):
            raise ChainError("chain contains a non-certificate")
        fingerprint = _fingerprint(candidate)
        if fingerprint in unique:
            notes.add("duplicate")
            continue
        unique[fingerprint] = candidate
    leaf_fingerprint = _fingerprint(leaf)
    if leaf_fingerprint in unique:
        notes.add("duplicate")
        unique.pop(leaf_fingerprint)
    roots = {fp: cert for fp, cert in unique.items() if _self_signed(cert)}

    chain: list[x509.Certificate] = []
    seen = {leaf_fingerprint}
    current = leaf
    missing_issuer: str | None = None
    if not _self_signed(leaf):
        while True:
            claimed = [cert for cert in unique.values() if cert.subject == current.issuer]
            valid = [cert for cert in claimed if _verifies(current, cert)]
            if claimed and not valid:
                raise ChainError("chain claims an issuer with an invalid signature")
            if not valid:
                missing_issuer = current.issuer.rfc4514_string()
                break
            if len(valid) > 1:
                notes.add("ambiguous")
            chosen = min(valid, key=_fingerprint)
            fingerprint = _fingerprint(chosen)
            if fingerprint in seen:
                notes.add("cycle")
                missing_issuer = current.issuer.rfc4514_string()
                break
            if fingerprint in roots:
                notes.add("root")
                break
            chain.append(chosen)
            seen.add(fingerprint)
            current = chosen

    used = {leaf_fingerprint} | {_fingerprint(cert) for cert in chain}
    if any(fp not in used and fp not in roots for fp in unique):
        notes.add("unrelated")
    return ChainResult(
        pem="".join(
            cert.public_bytes(serialization.Encoding.PEM).decode("ascii") for cert in chain
        ),
        fingerprints=tuple(_fingerprint(cert) for cert in chain),
        dropped=tuple(sorted(notes)),
        missing_issuer=missing_issuer,
        diagnostic_roots=tuple(roots[fp] for fp in sorted(roots)),
    )


def fullchain_pem(leaf_pem: str, chain_pem: str) -> str:
    if not isinstance(leaf_pem, str) or not isinstance(chain_pem, str):
        raise ChainError("PEM input must be text")
    try:
        parts = parse_certificates(leaf_pem.encode("ascii"))
        if chain_pem.strip():
            parts += parse_certificates(chain_pem.encode("ascii"))
    except UnicodeError:
        raise ChainError("PEM input must be ASCII") from None
    except ParseError as exc:
        raise ChainError(str(exc)) from None
    return "".join(part.pem for part in parts)
