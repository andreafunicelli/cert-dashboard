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
    alternates: tuple[str, ...] = ()


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


_MAX_DEPTH = 10
_MAX_NODES = 5_000


def _path_key(path: list[x509.Certificate]) -> tuple[str, ...]:
    return tuple(_fingerprint(cert) for cert in path)


def _better(candidate: tuple, current: tuple) -> bool:
    if len(candidate[1]) != len(current[1]):
        return len(candidate[1]) > len(current[1])
    return _path_key(candidate[1]) < _path_key(current[1])


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
    verifications: dict[tuple[str, str], bool] = {}

    def verifies(child: x509.Certificate, issuer: x509.Certificate) -> bool:
        key = (_fingerprint(child), _fingerprint(issuer))
        if key not in verifications:
            verifications[key] = _verifies(child, issuer)
        return verifications[key]

    chain: list[x509.Certificate] = []
    missing_issuer: str | None = None
    alternates: set[str] = set()
    complete = False
    if not _self_signed(leaf):
        nodes = 0

        def walk(
            current: x509.Certificate,
            path: list[x509.Certificate],
            visited: set[str],
            depth: int,
        ) -> tuple[int, list[x509.Certificate], str | None, set[str]]:
            nonlocal nodes
            if depth >= _MAX_DEPTH or nodes >= _MAX_NODES:
                return (1, path, current.issuer.rfc4514_string(), set())
            nodes += 1
            claims = [cert for cert in unique.values() if cert.subject == current.issuer]
            valid = [cert for cert in claims if verifies(current, cert)]
            usable = [cert for cert in valid if _fingerprint(cert) not in visited]
            if not usable:
                if valid:
                    notes.add("cycle")
                return (1, path, current.issuer.rfc4514_string(), set())
            best: tuple[int, list[x509.Certificate], str | None, set[str]] | None = None
            for candidate in sorted(usable, key=_fingerprint):
                fingerprint = _fingerprint(candidate)
                others = {_fingerprint(cert) for cert in usable if cert is not candidate}
                if fingerprint in roots:
                    return (2, path, None, others)
                outcome = walk(candidate, [*path, candidate], visited | {fingerprint}, depth + 1)
                if outcome[0] == 2:
                    return (2, outcome[1], None, others | outcome[3])
                if best is None or _better(outcome, best):
                    best = (1, outcome[1], outcome[2], others | outcome[3])
                if nodes >= _MAX_NODES:
                    break
            if best is None:
                return (1, path, current.issuer.rfc4514_string(), set())
            return best

        kind, chain, missing_issuer, alternate_fingerprints = walk(
            leaf, [], {leaf_fingerprint}, 0
        )
        complete = kind == 2
        alternates = alternate_fingerprints
        terminal = chain[-1] if chain else leaf
        claimed = [cert for cert in unique.values() if cert.subject == terminal.issuer]
        if claimed and not any(verifies(terminal, cert) for cert in claimed):
            raise ChainError("chain claims an issuer with an invalid signature")
        if complete:
            notes.add("root")

    if alternates:
        notes.add("cross-sign")
    used = {leaf_fingerprint} | {_fingerprint(cert) for cert in chain}
    if any(fp not in used and fp not in roots and fp not in alternates for fp in unique):
        notes.add("unrelated")
    return ChainResult(
        pem="".join(
            cert.public_bytes(serialization.Encoding.PEM).decode("ascii") for cert in chain
        ),
        fingerprints=tuple(_fingerprint(cert) for cert in chain),
        dropped=tuple(sorted(notes)),
        missing_issuer=missing_issuer,
        diagnostic_roots=tuple(roots[fp] for fp in sorted(roots)),
        alternates=tuple(sorted(alternates)),
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
