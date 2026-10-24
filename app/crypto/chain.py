"""Deterministic structural chain ordering; trust decisions belong to Task 6A."""

from collections.abc import Sequence
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.crypto.parse import ParseError, parse_certificates

_MAX_DEPTH = 16
_MAX_NODES = 5_000

type Pair = tuple[str, x509.Certificate]


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
    truncated: bool = False


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


def _path_key(path: list[Pair]) -> tuple[str, ...]:
    return tuple(fingerprint for fingerprint, _ in path)


def _better(candidate: tuple, current: tuple) -> bool:
    if len(candidate[1]) != len(current[1]):
        return len(candidate[1]) > len(current[1])
    return _path_key(candidate[1]) < _path_key(current[1])


def order_chain(leaf: x509.Certificate, candidates: Sequence[x509.Certificate]) -> ChainResult:
    if not isinstance(leaf, x509.Certificate):
        raise ChainError("leaf is not a certificate")
    notes: set[str] = set()
    leaf_fingerprint = _fingerprint(leaf)
    pairs: list[Pair] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, x509.Certificate):
            raise ChainError("chain contains a non-certificate")
        fingerprint = _fingerprint(candidate)
        if fingerprint in seen:
            notes.add("duplicate")
            continue
        seen.add(fingerprint)
        pairs.append((fingerprint, candidate))
    if leaf_fingerprint in seen:
        notes.add("duplicate")
        pairs = [(fingerprint, cert) for fingerprint, cert in pairs if fingerprint != leaf_fingerprint]
        seen.discard(leaf_fingerprint)
    roots = {fingerprint: cert for fingerprint, cert in pairs if _self_signed(cert)}
    by_subject: dict[x509.Name, list[Pair]] = {}
    for fingerprint, cert in pairs:
        by_subject.setdefault(cert.subject, []).append((fingerprint, cert))

    verifications: dict[tuple[str, str], bool] = {}

    def verifies(
        child_fingerprint: str,
        child: x509.Certificate,
        issuer_fingerprint: str,
        issuer: x509.Certificate,
    ) -> bool:
        key = (child_fingerprint, issuer_fingerprint)
        if key not in verifications:
            verifications[key] = _verifies(child, issuer)
        return verifications[key]

    path: list[Pair] = []
    missing_issuer: str | None = None
    alternates: set[str] = set()
    truncated = False
    complete = False
    if not _self_signed(leaf):
        nodes = 0

        def walk(
            current_fingerprint: str,
            current: x509.Certificate,
            current_path: list[Pair],
            visited: set[str],
            depth: int,
        ) -> tuple[int, list[Pair], str | None, set[str], str | None]:
            nonlocal nodes
            if depth >= _MAX_DEPTH:
                return (3, current_path, None, set(), "depth-limit")
            if nodes >= _MAX_NODES:
                return (3, current_path, None, set(), "budget")
            nodes += 1
            claims = by_subject.get(current.issuer, [])
            valid = [
                (fingerprint, cert)
                for fingerprint, cert in claims
                if verifies(current_fingerprint, current, fingerprint, cert)
            ]
            usable = [(fingerprint, cert) for fingerprint, cert in valid if fingerprint not in visited]
            if not usable:
                if valid:
                    notes.add("cycle")
                return (1, current_path, current.issuer.rfc4514_string(), set(), None)
            usable_fingerprints = {fingerprint for fingerprint, _ in usable}
            best: tuple[int, list[Pair], str | None, set[str], str | None] | None = None
            for fingerprint, candidate in sorted(usable, key=lambda item: item[0]):
                if nodes >= _MAX_NODES:
                    return (3, current_path, None, set(usable_fingerprints), "budget")
                others = usable_fingerprints - {fingerprint}
                if fingerprint in roots:
                    return (2, current_path, None, others, None)
                outcome = walk(
                    fingerprint,
                    candidate,
                    [*current_path, (fingerprint, candidate)],
                    visited | {fingerprint},
                    depth + 1,
                )
                if outcome[0] == 2:
                    return (2, outcome[1], None, others | outcome[3], None)
                if best is None or _better(outcome, best):
                    best = (outcome[0], outcome[1], outcome[2], others | outcome[3], outcome[4])
            if best is None:
                return (1, current_path, current.issuer.rfc4514_string(), set(), None)
            return best

        kind, path, missing_issuer, alternate_fingerprints, limit = walk(
            leaf_fingerprint, leaf, [], {leaf_fingerprint}, 0
        )
        complete = kind == 2
        truncated = kind == 3
        alternates = alternate_fingerprints
        if truncated:
            if limit is not None:
                notes.add(limit)
        else:
            terminal_fingerprint, terminal = path[-1] if path else (leaf_fingerprint, leaf)
            claimed = by_subject.get(terminal.issuer, [])
            if claimed and not any(
                verifies(terminal_fingerprint, terminal, fingerprint, cert)
                for fingerprint, cert in claimed
            ):
                raise ChainError("chain claims an issuer with an invalid signature")
        if complete:
            notes.add("root")

    if alternates:
        notes.add("cross-sign")
    used = {leaf_fingerprint} | {fingerprint for fingerprint, _ in path}
    if any(
        fingerprint not in used and fingerprint not in roots and fingerprint not in alternates
        for fingerprint, _ in pairs
    ):
        notes.add("unrelated")
    return ChainResult(
        pem="".join(
            cert.public_bytes(serialization.Encoding.PEM).decode("ascii") for _, cert in path
        ),
        fingerprints=tuple(fingerprint for fingerprint, _ in path),
        dropped=tuple(sorted(notes)),
        missing_issuer=missing_issuer,
        diagnostic_roots=tuple(roots[fingerprint] for fingerprint in sorted(roots)),
        alternates=tuple(sorted(alternates)),
        truncated=truncated,
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
