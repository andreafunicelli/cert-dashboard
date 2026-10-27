"""Discovery assembly (Plan 3, Task 8A): parser candidates + per-path facts -> section 6.2 binding objects."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.ansible.parsed import ParsedBinding, WebserverType
from app.crypto.chain import ChainError, order_chain
from app.crypto.parse import ParseError, parse_certificates
from app.models import JSONValue

__all__ = ["CERT_KEY_HASH_COMMAND", "KEY_HASH_COMMAND", "PathFacts", "assemble_bindings"]

# D2: the key identity is SHA-256 of the DER SubjectPublicKeyInfo, i.e. ``public_key_sha256`` in
# ``app/crypto/keys.py``. Both templates take ``{path}`` (already shell-quoted by the caller) and must run
# under ``bash -o pipefail`` so a failing ``openssl`` is not masked by ``sha256sum`` hashing empty input.
# ``-passin pass:`` makes a passphrase-protected key fail instead of prompting (``key_unreadable``).
# Output is ``<lowercase hex>  -``; take the first field, and only when the status is 0: on failure
# ``sha256sum`` still prints the hash of empty input, so stdout must be discarded.
KEY_HASH_COMMAND = "openssl pkey -in {path} -passin pass: -pubout -outform DER | sha256sum"
CERT_KEY_HASH_COMMAND = "openssl x509 -in {path} -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum"


# Fixed ``chain_diagnostic`` texts (D1): no path and no PEM ever enters a diagnostic.
INCOMPLETE_CHAIN = "incomplete chain: no configured file holds this leaf's issuer"
BUNDLE_NOT_CHAINED = "bundle certificates after the leaf do not form a verified chain"
CHAIN_NOT_VERIFYING = "chain file does not verify the leaf; not used as chain"
CHAIN_UNREADABLE = "chain file unreadable; not used as chain"


@dataclass(frozen=True, slots=True)
class PathFacts:
    """What the ``inspect`` phase learned about one path (certificate or key).

    ``certificates_pem`` holds the public certificates of a certificate path, in file order (never key
    material); ``None`` when the path is not a certificate path or could not be read.
    """

    path: str
    exists: bool
    readable: bool
    owner: str | None
    group: str | None
    mode: str | None
    size: int | None
    mtime: str | None
    fingerprint: str | None
    subject: str | None
    issuer: str | None
    key_public_sha256: str | None
    key_unreadable: bool
    certificates_pem: str | None = None


def _mode(value: str | None) -> str | None:
    """Octal permission string, four digits (``644`` and ``0o644`` normalize to ``0644``)."""
    if not value:
        return None
    text = value.strip().lower().removeprefix("0o")
    try:
        return f"{int(text, 8) & 0o7777:04o}"
    except ValueError:
        return None


def _hex(value: str | None) -> str | None:
    return value.replace(":", "").strip().lower() if value else None


def _file_fields(prefix: str, facts: PathFacts | None) -> dict[str, JSONValue]:
    return {
        f"{prefix}_exists": bool(facts and facts.exists),
        f"{prefix}_owner": facts.owner if facts and facts.exists else None,
        f"{prefix}_group": facts.group if facts and facts.exists else None,
        f"{prefix}_mode": _mode(facts.mode) if facts and facts.exists else None,
    }


def _binding(
    parsed: ParsedBinding,
    config_file: str,
    cert_path: str,
    key_path: str | None,
    chain_path: str | None,
    diagnostic: str | None,
    facts: Mapping[str, PathFacts],
) -> dict[str, JSONValue]:
    cert = facts.get(cert_path)
    key = facts.get(key_path) if key_path else None
    present = bool(cert and cert.exists)
    key_present = bool(key and key.exists)
    return {
        "webserver": str(parsed.webserver),
        "vhost_name": parsed.vhost_name,
        "vhost_names": list(parsed.vhost_names),
        "port": parsed.port,
        "config_file": config_file,
        "cert_path": cert_path,
        "chain_path": chain_path,
        "key_path": key_path,
        **_file_fields("cert", cert),
        "cert_fingerprint": _hex(cert.fingerprint) if cert and present else None,
        **_file_fields("key", key),
        "key_public_sha256": _hex(key.key_public_sha256) if key and key_present else None,
        "key_unreadable": bool(key and key.key_unreadable),
        "chain_diagnostic": diagnostic,
    }


type _Certs = tuple[x509.Certificate, ...]


def _certificates(facts: Mapping[str, PathFacts], path: str | None) -> _Certs | None:
    """The certificates of one file in file order; ``None`` when it is missing, unreadable or not PEM/DER."""
    found = facts.get(path) if path else None
    if not found or not found.exists or not found.readable or not found.certificates_pem:
        return None
    try:
        parsed = parse_certificates(found.certificates_pem.encode("ascii"))
    except (ParseError, UnicodeError):
        return None
    return tuple(item.cert for item in parsed) or None


def _signs(issuer: x509.Certificate, child: x509.Certificate) -> bool:
    """``issuer`` really signed ``child`` (signature verified by ``order_chain``; never DNs alone)."""
    try:
        result = order_chain(child, [issuer])
    except ChainError:
        return False
    if result.fingerprints[:1] == (_fingerprint(issuer),):
        return True
    # order_chain leaves a terminating self-signed root out of ``fingerprints``.
    return result.fingerprints == () and "root" in result.dropped


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _self_signed(cert: x509.Certificate) -> bool:
    # With no candidates, order_chain names the missing issuer unless the certificate is its own root.
    result = order_chain(cert, [])
    return result.missing_issuer is None and not result.truncated


def _bundle_is_chain(certs: _Certs) -> bool:
    return all(_signs(certs[i], certs[i - 1]) for i in range(1, len(certs)))


def _apache_roles(candidate: ParsedBinding, facts: Mapping[str, PathFacts]) -> list[int]:
    """Indexes of ``cert_paths`` that are bindings; the others (``chain_like``) only qualify as chains.

    A later ``SSLCertificateFile`` is chain-like when its *first* certificate signed the leaf of another
    certificate file: a file that starts with a leaf (an RSA+ECDSA sibling, even one bundled with its
    intermediate) is a certificate of its own and must never be swallowed as somebody's chain. Unreadable
    files cannot prove anything and stay bindings.
    """
    loaded = [_certificates(facts, path) for path in candidate.cert_paths]
    roles = [0]
    for i in range(1, len(loaded)):
        file_certs = loaded[i]
        signs_a_leaf = file_certs is not None and any(
            other is not None and j != i and _signs(file_certs[0], other[0]) for j, other in enumerate(loaded)
        )
        if not signs_a_leaf:
            roles.append(i)
    return roles


def _chain_for(
    candidate: ParsedBinding, leaf: x509.Certificate, facts: Mapping[str, PathFacts], extras: Sequence[str]
) -> str | None:
    """First file that holds the certificate that signed ``leaf``: the explicit chain file, then the extras."""
    if candidate.chain_path:
        certs = _certificates(facts, candidate.chain_path)
        if certs and any(_signs(cert, leaf) for cert in certs):
            return candidate.chain_path
    for path in extras:
        certs = _certificates(facts, path)
        if certs and _signs(certs[0], leaf):
            return path
    return None


def _assemble_one(
    candidate: ParsedBinding,
    index: int,
    chain_like: Sequence[str],
    facts: Mapping[str, PathFacts],
) -> dict[str, JSONValue]:
    cert_path = candidate.cert_paths[index]
    key_path = candidate.key_paths[index] if index < len(candidate.key_paths) else None
    apache = candidate.webserver == WebserverType.APACHE
    if key_path is None and apache:
        key_path = cert_path  # Apache accepts the key inside the certificate file
    config_file = candidate.cert_files[index] if index < len(candidate.cert_files) else candidate.config_file

    certs = _certificates(facts, cert_path)
    chain_path: str | None = None
    problems: list[str] = []
    explicit = candidate.chain_path if apache else None
    if certs:
        leaf = certs[0]
        if apache:
            chain_path = _chain_for(candidate, leaf, facts, chain_like)
        bundle_link = len(certs) > 1 and _signs(certs[1], leaf)
        if not (_self_signed(leaf) or bundle_link or chain_path):
            problems.append(INCOMPLETE_CHAIN)
        if len(certs) > 1 and not _bundle_is_chain(certs):
            problems.append(BUNDLE_NOT_CHAINED)
    if explicit and chain_path != explicit:
        problems.append(CHAIN_NOT_VERIFYING if _certificates(facts, explicit) else CHAIN_UNREADABLE)
    return _binding(candidate, config_file, cert_path, key_path, chain_path, "; ".join(problems) or None, facts)


def assemble_bindings(
    parsed: Sequence[ParsedBinding], facts: Mapping[str, PathFacts]
) -> list[dict[str, JSONValue]]:
    """Section 6.2 binding objects; every file's role is decided by verifying that file's certificates (D1)."""
    out: list[dict[str, JSONValue]] = []
    for candidate in parsed:
        if candidate.webserver == WebserverType.APACHE:
            roles = _apache_roles(candidate, facts)
        else:
            roles = list(range(len(candidate.cert_paths)))
        chain_like = [path for i, path in enumerate(candidate.cert_paths) if i not in roles]
        out.extend(_assemble_one(candidate, i, chain_like, facts) for i in roles)
    return out
