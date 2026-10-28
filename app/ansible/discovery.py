"""Discovery assembly (Plan 3, Task 8A): parser candidates + per-path facts -> section 6.2 binding objects."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.ansible.parse_apache import ApacheDump, parse_apache
from app.ansible.parse_nginx import MARKER, NGINX_PREFIX, parse_nginx
from app.ansible.parsed import ParsedBinding, ParseResult, WebserverType
from app.ansible.parsed import ParseError as ConfigParseError
from app.ansible.runner import PLAYBOOK_DIR, AnsibleRun, HostResult, RunnerContext, run_playbook
from app.crypto.chain import ChainError, order_chain
from app.crypto.parse import ParseError, parse_certificates
from app.models import JSONValue

__all__ = [
    "CERT_KEY_HASH_COMMAND",
    "KEY_HASH_COMMAND",
    "MAX_CERT_BYTES",
    "MAX_DUMP_BYTES",
    "HostDiscovery",
    "PathFacts",
    "assemble_bindings",
    "discover_hosts",
    "is_safe_name",
]

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
) -> tuple[str | None, bool]:
    """First file that holds the signer of ``leaf`` *and* is itself a verified chain, plus a malformed flag.

    The explicit chain file may hold the signer anywhere, an extra certificate file must start with it.
    A file whose certificates do not each sign the previous one is never a chain (flag ``True``).
    """
    malformed = False
    if candidate.chain_path:
        certs = _certificates(facts, candidate.chain_path)
        if certs and any(_signs(cert, leaf) for cert in certs):
            if _bundle_is_chain(certs):
                return candidate.chain_path, False
            malformed = True
    for path in extras:
        certs = _certificates(facts, path)
        if certs and _signs(certs[0], leaf):
            if _bundle_is_chain(certs):
                return path, False
            malformed = True
    return None, malformed


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
    malformed = False
    problems: list[str] = []
    explicit = candidate.chain_path if apache else None
    if certs:
        leaf = certs[0]
        if apache:
            chain_path, malformed = _chain_for(candidate, leaf, facts, chain_like)
        bundle_link = len(certs) > 1 and _signs(certs[1], leaf)
        if not (_self_signed(leaf) or bundle_link or chain_path or malformed):
            problems.append(INCOMPLETE_CHAIN)
        if malformed or (len(certs) > 1 and not _bundle_is_chain(certs)):
            problems.append(BUNDLE_NOT_CHAINED)
    if explicit and chain_path != explicit and not malformed:
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


# ---------------------------------------------------------------------------------------------------
# Task 8B: ``discover.yml`` driver. Phase ``collect`` (dump on the controller) -> parsers -> phase
# ``inspect`` (per-path facts, certificate contents on the controller) -> ``assemble_bindings``.
# ---------------------------------------------------------------------------------------------------

MAX_DUMP_BYTES = 16 * 1024 * 1024
MAX_CERT_BYTES = 1024 * 1024
MAX_SUMMARY_FILES = 200
PLAYBOOK = PLAYBOOK_DIR / "discover.yml"

_HOSTNAME = re.compile(r"[A-Za-z0-9_.-]{1,253}")


def is_safe_name(name: object) -> bool:
    """True for a name that may be joined into Ansible's ``--limit``: ``[A-Za-z0-9_.-]{1,253}``, no leading ``-``.

    The one predicate shared by the discovery payload, the inventory-selected hosts and ``discover_hosts``.
    """
    return isinstance(name, str) and bool(_HOSTNAME.fullmatch(name)) and not name.startswith("-") and name not in {".", ".."}

_EMPTY_INPUT_SHA256 = hashlib.sha256(b"").hexdigest()
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_FINGERPRINT = re.compile(r"Fingerprint=([0-9A-Fa-f:]+)")
_PEM_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]*?-----END CERTIFICATE-----")

# Fixed texts: nothing peer-supplied (stderr, paths, configuration) ever enters ``error``.
_CAPTURE_FAILURES: dict[str, tuple[str, str]] = {
    "no_webserver": ("dump_failed", "no supported webserver found on the host"),
    "dump_failed": ("dump_failed", "configuration capture failed"),
    "dump_too_large": ("dump_too_large", "configuration dump exceeds the size limit"),
}
_PARSE_FAILED = "configuration could not be parsed"
_INSPECT_FAILED = "inspection of certificate and key files failed"
_UNREACHABLE = "unreachable"
_NOT_RUN = "Ansible did not report this host; check the inventory and the worker image"
_TIMED_OUT = "discovery did not finish within its time limit"


@dataclass(frozen=True, slots=True)
class HostDiscovery:
    """Outcome of discovery for one host: a section 6.2 ``document`` when ``status == 'ok'``, else a fixed reason."""

    hostname: str
    status: Literal["ok", "failed", "unreachable"]
    reason: str | None
    error: str | None
    document: dict[str, JSONValue] | None
    summary: dict[str, JSONValue]
    log_excerpt: str


@dataclass(frozen=True, slots=True)
class _Collected:
    webserver: WebserverType
    parsed: ParseResult
    summary: dict[str, JSONValue]
    excerpt: str


def _check_hostnames(hostnames: Sequence[str]) -> list[str]:
    names: list[str] = []
    for name in hostnames:
        if not is_safe_name(name):
            raise ValueError("invalid hostname")
        if name not in names:
            names.append(name)
    return names


def _write_private(path: Path, text: str) -> None:
    """Write ``text`` as a ``0600`` file, replacing an earlier attempt's file atomically."""
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _failed(
    name: str, reason: str, error: str, excerpt: str = "", summary: dict[str, JSONValue] | None = None
) -> HostDiscovery:
    return HostDiscovery(name, "failed", reason, error, None, summary or {}, excerpt)


def _not_ok(name: str, result: HostResult | None, timed_out: bool, failure: tuple[str, str]) -> HostDiscovery | None:
    """The outcome of a host whose play did not complete; ``None`` when the host ran and published data."""
    if result is None:
        return _failed(name, "host_timeout", _TIMED_OUT) if timed_out else _failed(name, "internal", _NOT_RUN)
    if result.outcome == "unreachable":
        return HostDiscovery(name, "unreachable", _UNREACHABLE, result.log_excerpt, None, {}, result.log_excerpt)
    if result.outcome == "auth":
        return _failed(name, "auth", result.log_excerpt, result.log_excerpt)
    if result.outcome == "failed" or not result.data:
        return _failed(name, failure[0], failure[1], result.log_excerpt)
    return None


def _nginx_prefix(dump: str) -> str:
    """Directory of the dump's first ``# configuration file`` marker (the main configuration)."""
    for line in dump.splitlines():
        if line.startswith(MARKER) and line.rstrip().endswith(":"):
            return posixpath.dirname(line[len(MARKER) :].rstrip()[:-1].strip()) or NGINX_PREFIX
    return NGINX_PREFIX


def _parse_dump(webserver: str, dump: bytes) -> ParseResult:
    if webserver == WebserverType.NGINX:
        text = dump.decode("utf-8", "replace")
        return parse_nginx(text, _nginx_prefix(text))
    try:
        document = json.loads(dump)
    except ValueError as error:
        raise ConfigParseError("not an Apache collector document") from error
    if not isinstance(document, dict):
        raise ConfigParseError("not an Apache collector document")
    return parse_apache(ApacheDump.from_collector(document))


def _collect_one(runner: RunnerContext, name: str, result: HostResult | None, timed_out: bool) -> HostDiscovery | _Collected:
    problem = _not_ok(name, result, timed_out, _CAPTURE_FAILURES["dump_failed"])
    if problem is not None:
        return problem
    assert result is not None
    data = result.data
    webserver = str(data.get("webserver") or "")
    known: dict[str, JSONValue] = {"webserver": webserver or None, "binaries": data.get("binaries") or {}}
    status = str(data.get("capture_status") or "dump_failed")
    if status != "ok":
        reason, error = _CAPTURE_FAILURES.get(status, _CAPTURE_FAILURES["dump_failed"])
        return _failed(name, reason, error, result.log_excerpt, known)
    suffix = "txt" if webserver == WebserverType.NGINX else "json"
    path = runner.artifact_dir / "dumps" / f"{name}.{suffix}"
    try:
        size = path.stat().st_size
        if size > MAX_DUMP_BYTES:
            path.unlink()  # never keep (or truncate) an oversized dump
            return _failed(name, *_CAPTURE_FAILURES["dump_too_large"], excerpt=result.log_excerpt, summary=known)
        dump = path.read_bytes()
    except OSError:
        return _failed(name, *_CAPTURE_FAILURES["dump_failed"], excerpt=result.log_excerpt, summary=known)
    try:
        parsed = _parse_dump(webserver, dump)
    except (ConfigParseError, ValueError):
        return _failed(name, "parse_failed", _PARSE_FAILED, result.log_excerpt, known)
    summary: dict[str, JSONValue] = {
        **known,
        "config_files": list(parsed.config_files[:MAX_SUMMARY_FILES]),
        "bindings": len(parsed.bindings),
        "warnings": list(parsed.warnings),
        "dump_bytes": len(dump),
        "dump_sha256": hashlib.sha256(dump).hexdigest(),
    }
    return _Collected(WebserverType(webserver), parsed, summary, result.log_excerpt)


def _paths_of(parsed: Sequence[ParsedBinding]) -> dict[str, list[str]]:
    """Certificate paths (leaf candidates and chain candidates; never a key path) and key paths to inspect."""
    certs: list[str] = []
    keys: list[str] = []

    def add(target: list[str], path: str) -> None:
        if path not in target:
            target.append(path)

    for candidate in parsed:
        for path in candidate.cert_paths:
            add(certs, path)
        if candidate.chain_path:
            add(certs, candidate.chain_path)
        for path in candidate.key_paths:
            add(keys, path)
        if candidate.webserver == WebserverType.APACHE:  # a certificate without its own key file holds the key
            for path in candidate.cert_paths[len(candidate.key_paths) :]:
                add(keys, path)
    return {"cert_paths": certs, "key_paths": keys}


def _column(block: object, name: str) -> list[object]:
    values = block.get(name) if isinstance(block, dict) else None
    return values if isinstance(values, list) else []


def _iso(epoch: object) -> str | None:
    if isinstance(epoch, bool) or not isinstance(epoch, int | float):
        return None
    try:
        return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _text(value: object) -> str | None:
    return str(value) if value not in (None, "") else None


def _certificates_pem(directory: Path, host: str, path: str, rc: object, size: object) -> str | None:
    """PEM certificates the ``inspect`` phase stored for ``path`` on the controller (``None`` = not usable)."""
    if rc != 0 or not isinstance(size, int) or not 0 < size <= MAX_CERT_BYTES:
        return None
    stored = directory / "certs" / host / f"{hashlib.sha256(path.encode()).hexdigest()}.pem"
    try:
        if stored.stat().st_size > MAX_CERT_BYTES:
            return None
        text = stored.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    blocks = _PEM_CERTIFICATE.findall(text)  # only certificates, whatever else the file held
    return "\n".join(block.strip() for block in blocks) + "\n" if blocks else None


def path_facts(host: str, data: Mapping[str, JSONValue], artifact_dir: Path) -> dict[str, PathFacts]:
    """``PathFacts`` per path from what phase ``inspect`` published (one index per ``paths`` list)."""
    stat_block = data.get("stat")
    fingerprints, key_hashes, certificates = (data.get(k) for k in ("fingerprint", "key_hash", "certificates"))

    def by_path(block: object, *columns: str) -> dict[str, tuple[object, ...]]:
        paths = [p for p in _column(block, "paths") if isinstance(p, str)]
        lists = [_column(block, column) for column in columns]
        return {
            path: tuple(values[i] if i < len(values) else None for values in lists) for i, path in enumerate(paths)
        }

    stats = by_path(stat_block, "results")
    prints = by_path(fingerprints, "rc", "stdout")
    hashes_ = by_path(key_hashes, "rc", "stdout")
    certs = by_path(certificates, "rc", "size")
    facts: dict[str, PathFacts] = {}
    for path, (raw,) in stats.items():
        info: Mapping[str, object] = raw if isinstance(raw, dict) else {}
        exists = bool(info.get("exists"))
        fingerprint = subject = issuer = None
        if path in prints:
            rc, out = prints[path]
            if rc == 0 and isinstance(out, str):
                found = _FINGERPRINT.search(out)
                fingerprint = found[1].replace(":", "").lower() if found else None
                for line in out.splitlines():
                    if line.startswith("subject="):
                        subject = _text(line[len("subject=") :].strip())
                    elif line.startswith("issuer="):
                        issuer = _text(line[len("issuer=") :].strip())
        key_hash = None
        if path in hashes_:
            rc, out = hashes_[path]
            token = out.split()[0].lower() if rc == 0 and isinstance(out, str) and out.split() else ""
            key_hash = token if _SHA256_HEX.fullmatch(token) and token != _EMPTY_INPUT_SHA256 else None
        pem = None
        if path in certs and exists:
            pem = _certificates_pem(artifact_dir, host, path, *certs[path])
        facts[path] = PathFacts(
            path=path,
            exists=exists,
            readable=exists and bool(info.get("readable")) and bool(info.get("isreg", True)),
            owner=_text(info.get("pw_name") or info.get("uid")),
            group=_text(info.get("gr_name") or info.get("gid")),
            mode=_text(info.get("mode")),
            size=info.get("size") if isinstance(info.get("size"), int) else None,
            mtime=_iso(info.get("mtime")),
            fingerprint=fingerprint if exists else None,
            subject=subject if exists else None,
            issuer=issuer if exists else None,
            key_public_sha256=key_hash if exists else None,
            key_unreadable=exists and path in hashes_ and key_hash is None,
            certificates_pem=pem,
        )
    return facts


def discover_hosts(
    runner: RunnerContext,
    hostnames: Sequence[str],
    *,
    webservers: Mapping[str, WebserverType | None],
    now: datetime,
    timeout_seconds: int = 1500,
) -> dict[str, HostDiscovery]:
    """Run ``discover.yml`` for ``hostnames`` and return one outcome (and section 6.2 document) per host.

    ``webservers`` is the inventory's webserver variable per host (``None`` = auto-detect). The dump, the
    certificate contents and each host's document are written under ``runner.artifact_dir`` (``0600``) on the
    controller only. ``timeout_seconds`` bounds both phases together, so the 1800 s job timeout leaves room for
    the caller's bookkeeping.
    """
    names = _check_hostnames(hostnames)
    started = time.monotonic()
    for folder in ("dumps", "certs", "discovery"):
        (runner.artifact_dir / folder).mkdir(mode=0o700, parents=True, exist_ok=True)

    def run(phase: str, hosts: Sequence[str], extra: Mapping[str, JSONValue]):
        remaining = int(timeout_seconds - (time.monotonic() - started))
        if remaining < 1:
            return None
        extravars: dict[str, JSONValue] = {
            "discovery_phase": phase,
            "artifact_dir": str(runner.artifact_dir),
            "max_dump_bytes": MAX_DUMP_BYTES,
            "max_cert_bytes": MAX_CERT_BYTES,
            "webservers": {name: (str(webservers[name]) if webservers.get(name) else None) for name in hosts},
            **extra,
        }
        return run_playbook(runner, AnsibleRun(str(PLAYBOOK), ":".join(hosts), extravars, remaining), ident=f"discover-{phase}")

    results: dict[str, HostDiscovery] = {}
    collected: dict[str, _Collected] = {}
    outcome = run("collect", names, {})
    for name in names:
        timed_out = outcome is None or outcome.status == "timeout"
        step = _collect_one(runner, name, outcome.hosts.get(name) if outcome else None, timed_out)
        if isinstance(step, HostDiscovery):
            results[name] = step
        else:
            collected[name] = step

    inspected: dict[str, HostResult | None] = {}
    needing = [name for name in collected if collected[name].parsed.bindings]
    if needing:
        paths = {name: _paths_of(collected[name].parsed.bindings) for name in needing}
        second = run("inspect", needing, {"paths_by_host": paths})
        for name in needing:
            inspected[name] = second.hosts.get(name) if second else None
        inspect_timed_out = second is None or second.status == "timeout"
    else:
        inspect_timed_out = False

    stamp = now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    for name, found in collected.items():
        excerpt = found.excerpt
        bindings: list[dict[str, JSONValue]] = []
        if found.parsed.bindings:
            result = inspected.get(name)
            problem = _not_ok(name, result, inspect_timed_out, ("dump_failed", _INSPECT_FAILED))
            if problem is not None:
                results[name] = HostDiscovery(
                    name, problem.status, problem.reason, problem.error, None, found.summary,
                    problem.log_excerpt or excerpt,
                )  # fmt: skip
                continue
            assert result is not None
            facts = path_facts(name, result.data, runner.artifact_dir)
            bindings = assemble_bindings(found.parsed.bindings, facts)
            excerpt = "\n".join(part for part in (excerpt, result.log_excerpt) if part)
        document: dict[str, JSONValue] = {
            "hostname": name,
            "webserver": str(found.webserver),
            "collected_at": stamp,
            "bindings": list(bindings),
            "errors": [],
        }
        _write_private(runner.artifact_dir / "discovery" / f"{name}.json", json.dumps(document, indent=2, sort_keys=True))
        results[name] = HostDiscovery(name, "ok", None, None, document, found.summary, excerpt)
    return {name: results[name] for name in names}
