"""Per-host deploy execution: material staging, playbook invocation and outcome mapping (§6.4, §9.6).

This module is the worker-side half of ``deploy.yml``. It stages the new material — public PEMs in the job
artifact directory, the decrypted private key only in the tmpfs staging area (Contract decision 6) — runs
the playbook once per host and maps the run to Contract decision 18.

The two binaries the leaf/key preflight hashes with are resolved here, with ``shutil.which``, and handed to
the playbook as absolute paths: a deploy preflight must not depend on whatever ``PATH`` a worker inherits,
and a missing binary is an ``internal``/``preflight_tool_missing`` outcome *before* any run — never a
``key_mismatch_preflight``.

The mapping is deliberately strict: ``succeeded`` needs ``step == "verified"`` evidence carrying the new
fingerprint for *every* target binding. Task 14's playbook stops after the backup, so a run of it ends
``failed``/``internal`` ("deploy playbook ended before verification") with nothing changed outside
``/var/backups/cert-dashboard/<job_id>``; that is the fail-safe boundary of the task, not a bug.
"""

from __future__ import annotations

import os
import posixpath
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from app.ansible.runner import PLAYBOOK_DIR, AnsibleRun, HostResult, RunnerContext, RunOutcome, run_playbook
from app.ansible.staging import StagingArea
from app.crypto.keys import private_key_pem
from app.models import JSONValue
from app.services.deploy import DeployTarget, FileConflict, plan_file_writes

if TYPE_CHECKING:
    from app.crypto.keys import PrivateKeyObject
    from app.models import Certificate
    from app.models.enums import WebserverType

DEPLOY_PLAYBOOK = PLAYBOOK_DIR / "deploy.yml"
BACKUP_ROOT = "/var/backups/cert-dashboard"
# §6.4 step 1: at least twice the size of the files being written, plus a 10 MB margin.
SPACE_MARGIN = 10 * 1024 * 1024
# Which staged file each planned write takes its content from (Contract decision 17).
SOURCE_VARIABLE = {
    "leaf": "cert_pem_path",
    "chain": "chain_pem_path",
    "fullchain": "fullchain_pem_path",
    "key": "key_pem_path",
}
MATERIAL_FIELD = {"leaf": "cert_pem", "chain": "chain_pem", "fullchain": "fullchain_pem", "key": "key_pem"}

# The steps a playbook publishes once it may have replaced a live file (Contract decision 17). A failure
# from one of them is only a ``rolled_back`` host when the playbook also says the rollback restored it.
WRITE_STEPS = ("writing", "written", "labelled", "config_tested", "reloaded")
# Contract decision 18's fixed text for a run that never produced verification evidence.
INTERNAL_TEXT = "deploy playbook ended before verification"
# A killed run cannot be inspected: it may have replaced any file it had reached (Contract decision 18).
TIMEOUT_ROLLBACK_ERROR = "run timed out; files may be partially written"
LOG_EXCERPT_LIMIT = 8000
# The two binaries the leaf/key preflight pipeline needs. They are resolved here, on the controller, and
# handed to the playbook as paths: a deploy preflight must not depend on whatever PATH a worker happens to
# inherit, and a missing binary must read as `internal`, never as "the key does not match" (D2 contract).
PREFLIGHT_TOOLS = ("openssl", "sha256sum")
TOOL_MISSING_PREFIX = "preflight_tool_missing"

# ``<reason>: <fixed text>`` is the stored ``job_host.error_message`` (§4.11, Contract decision 18). The
# texts are fixed here — never taken from the host — so an operator-facing message cannot carry target
# output, a path or a secret.
REASON_TEXT: dict[str, str] = {
    "drift_detected": "the on-disk certificate changed since discovery",
    "missing_target": "a target file or directory is missing",
    "permission_denied": "a target file or directory is not readable",
    "insufficient_space": "not enough free space for the backup and the write",
    "baseline_config_invalid": "the configuration test already fails before any change",
    "key_mismatch_preflight": "the new certificate and the new private key do not match",
    "backup_failed": "a backup is missing or does not match its manifest",
    "write_failed": "a file could not be replaced",
    "config_test_failed": "the configuration test fails after the write",
    "reload_failed": "the webserver reload failed",
    "verify_failed": "the webserver does not serve the new certificate",
    "unreachable": "host unreachable over SSH",
    "auth": "SSH authentication or host key verification failed; check known_hosts and the deploy key",
    "host_timeout": "the host run exceeded its timeout",
    "binding_blocked": "a target binding is no longer deployable",
    "not_in_inventory": "the host is not in the inventory",
    "file_conflict": "two bindings need the same path with different content",
    "internal": INTERNAL_TEXT,
}
FAILED_REASONS = frozenset(REASON_TEXT)


@dataclass(frozen=True, slots=True)
class HostOutcome:
    """What one host's run produced, in the shape ``job_host`` stores (Contract decision 18)."""

    status: Literal["succeeded", "rolled_back", "failed"]
    reason: str | None = None
    message: str | None = None
    rolled_back: bool = False
    rollback_error: str | None = None
    targets: dict[int, dict[str, JSONValue]] = field(default_factory=dict)
    verify: dict[str, JSONValue] | None = None
    backup_dir: str | None = None
    precheck: dict[str, JSONValue] = field(default_factory=dict)
    return_code: int | None = None
    log_excerpt: str = ""


def failure(reason: str, *, detail: str | None = None, step: str = "") -> HostOutcome:
    """A ``failed`` outcome with the fixed ``<reason>: <text>`` message, for a failure before Ansible ran."""
    text = detail or REASON_TEXT.get(reason) or REASON_TEXT["internal"]
    return HostOutcome(
        "failed", reason, f"{reason}: {text}", precheck={"step": step, "reason": reason}
    )


def _which(name: str) -> str | None:
    """Resolve one preflight binary on the controller; the unit tests replace this seam."""
    return shutil.which(name)


def _tool_missing(name: str) -> HostOutcome:
    """A missing preflight binary: an environment failure, never a key mismatch, and no Ansible run."""
    return HostOutcome(
        "failed",
        "internal",
        f"{TOOL_MISSING_PREFIX}: {name}",
        precheck={"step": "preflight", "reason": "internal", "missing_tool": name},
    )


def _preflight_tools() -> tuple[dict[str, str], HostOutcome | None]:
    """Resolve every binary the preflight hashes with, or say which one is absent."""
    tools: dict[str, str] = {}
    for name in PREFLIGHT_TOOLS:
        path = _which(name)
        if path is None:
            return tools, _tool_missing(name)
        tools[name] = path
    return tools, None


def _message(reason: str) -> str:
    return f"{reason}: {REASON_TEXT[reason]}"


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _mapping(value: object) -> dict[str, JSONValue]:
    return dict(value) if isinstance(value, Mapping) else {}


def _published(hostname: str, outcome: RunOutcome) -> tuple[dict[str, JSONValue], HostResult | None]:
    host = outcome.hosts.get(hostname)
    return (_mapping(host.data) if host is not None else {}), host


def _targets(published: Mapping[str, JSONValue], targets: Sequence[DeployTarget]) -> dict[int, dict[str, JSONValue]]:
    """The per-binding evidence of this run, keyed by binding id and complete for every planned target."""
    reported = _mapping(published.get("targets"))
    return {item.binding_id: _mapping(reported.get(str(item.binding_id))) for item in targets}


def _verify(published: Mapping[str, JSONValue]) -> dict[str, JSONValue] | None:
    value = published.get("verify")
    return dict(value) if isinstance(value, Mapping) else None


def _hash_rc(published: Mapping[str, JSONValue]) -> list[int]:
    """The two pipeline exit codes the playbook publishes, as integers (empty when unreadable)."""
    value = published.get("hash_rc")
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        return []
    codes: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, str)):
            return []
        try:
            codes.append(int(item))
        except ValueError:
            return []
    return codes


def _hash_diagnosis(published: Mapping[str, JSONValue]) -> str:
    """``internal`` text for a hash pipeline that never produced a comparable pair (public side only)."""
    details: list[str] = []
    for key in ("hash_stderr", "hash_msg", "hash_module_stderr"):
        text = published.get(key)
        if isinstance(text, str) and text:
            details.append(text)
    suffix = f" ({'; '.join(details)})" if details else ""
    return f"preflight hash pipeline failed: hash_rc={_hash_rc(published)}{suffix}"


def _excerpt(*texts: str) -> str:
    joined = "\n".join(part for part in texts if part)
    return joined[-LOG_EXCERPT_LIMIT:]


def _precheck(published: Mapping[str, JSONValue], step: str, backup_dir: str | None) -> dict[str, JSONValue]:
    document: dict[str, JSONValue] = {**published, "step": step}
    if backup_dir is not None:
        document["backup_dir"] = backup_dir
    return document


@dataclass(frozen=True, slots=True)
class _Evidence:
    """The fields every outcome carries, whatever the status."""

    targets: dict[int, dict[str, JSONValue]]
    verify: dict[str, JSONValue] | None
    backup_dir: str | None
    precheck: dict[str, JSONValue]
    return_code: int | None
    log_excerpt: str

    def outcome(
        self,
        status: Literal["succeeded", "rolled_back", "failed"],
        reason: str | None,
        *,
        rolled_back: bool = False,
        rollback_error: str | None = None,
        message: str | None = None,
    ) -> HostOutcome:
        return HostOutcome(
            status=status,
            reason=reason,
            message=message if message is not None else (_message(reason) if reason else None),
            rolled_back=rolled_back,
            rollback_error=rollback_error,
            targets=self.targets,
            verify=self.verify,
            backup_dir=self.backup_dir,
            precheck=self.precheck,
            return_code=self.return_code,
            log_excerpt=self.log_excerpt,
        )


def parse_host_result(hostname: str, outcome: RunOutcome, targets: Sequence[DeployTarget]) -> HostOutcome:
    """Map one host's recorded run to Contract decision 18. Pure: no clock, no I/O, no database."""
    published, host = _published(hostname, outcome)
    step = _text(published.get("step")) or ""
    backup_dir = _text(published.get("backup_dir"))
    evidence = _Evidence(
        targets=_targets(published, targets),
        verify=_verify(published),
        backup_dir=backup_dir,
        precheck=_precheck(published, step, backup_dir),
        return_code=outcome.rc,
        log_excerpt=_excerpt(host.log_excerpt if host else "", outcome.log_excerpt),
    )

    if outcome.status == "timeout":
        # The run was killed: nothing is published and nothing can be inspected.
        return evidence.outcome("failed", "host_timeout", rollback_error=TIMEOUT_ROLLBACK_ERROR)
    if host is None:
        return evidence.outcome("failed", "internal")
    if host.outcome in {"unreachable", "auth"}:
        return evidence.outcome("failed", host.outcome)

    reason = _text(published.get("reason"))
    code = reason if reason in FAILED_REASONS else "internal"
    rollback_error = _text(published.get("rollback_error"))
    if rollback_error is not None:
        # A failed rollback is never a clean restore, whatever else the host published.
        return evidence.outcome("failed", code, rollback_error=rollback_error)
    if code == "key_mismatch_preflight" and _hash_rc(published) != [0, 0]:
        # A pipeline that did not run compared nothing: this is an environment failure, never a mismatch.
        return evidence.outcome(
            "failed", "internal", message=f"internal: {_hash_diagnosis(published)}"
        )
    if reason is not None:
        restored = bool(published.get("rolled_back")) and step != "rollback_failed"
        if restored:
            return evidence.outcome("rolled_back", code, rolled_back=True)
        return evidence.outcome("failed", code)
    if step != "verified":
        return evidence.outcome("failed", "internal")
    return _verified(evidence, targets)


def _verified(evidence: _Evidence, targets: Sequence[DeployTarget]) -> HostOutcome:
    """``succeeded`` needs one ``verified`` record per target carrying that target's new fingerprint."""
    if not targets:
        return evidence.outcome("failed", "internal")
    for item in targets:
        record = _mapping(evidence.targets.get(item.binding_id))
        verified = _mapping(record.get("verified"))
        if verified.get("fingerprint") != item.new_fingerprint:
            return evidence.outcome("failed", "internal")
    return evidence.outcome("succeeded", None)


# --- material staging (§6.4 inputs, Contract decision 6) -----------------------------------------


@dataclass(frozen=True, slots=True)
class StagedMaterial:
    """The four files one host run needs: three public PEMs and the key in the tmpfs staging area."""

    cert_pem: Path
    chain_pem: Path
    fullchain_pem: Path
    key_pem: Path


def _public_file(path: Path, data: bytes) -> Path:
    """Create or replace ``path`` with exactly ``data``, 0600, never writing through a symlink."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(data)
    return path


def _pem(data: str) -> bytes:
    encoded = data.encode()
    return encoded if encoded.endswith(b"\n") else encoded + b"\n"


def stage_material(
    certificate: Certificate, key: PrivateKeyObject, artifact_dir: Path, staging: StagingArea
) -> StagedMaterial:
    """Write the public PEMs under ``<artifact_dir>/files`` and the key **only** to the staging area.

    The key file is created by ``StagingArea.write``: ``<key_staging_dir>/<job_id>/tls_key.pem``, mode
    ``0600``, PKCS#8 without a passphrase, removed with the staging area in the caller's ``finally``.
    """
    files_dir = Path(artifact_dir) / "files"
    files_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    cert_pem = _pem(certificate.pem)
    chain_pem = _pem(certificate.chain_pem) if certificate.chain_pem.strip() else b""
    return StagedMaterial(
        cert_pem=_public_file(files_dir / "cert.pem", cert_pem),
        chain_pem=_public_file(files_dir / "chain.pem", chain_pem),
        fullchain_pem=_public_file(files_dir / "fullchain.pem", cert_pem + chain_pem),
        key_pem=staging.write("tls_key.pem", private_key_pem(key)),
    )


# --- one host run (§6.4, Contract decisions 17–18) -----------------------------------------------


def _safe(path: str | None) -> bool:
    """A target path must be absolute and already normalized: the backup tree mirrors it verbatim."""
    if path is None:
        return True
    if not path.startswith("/") or path == "/" or "\x00" in path or "\n" in path:
        return False
    return posixpath.normpath(path) == path


def _files(targets: Sequence[DeployTarget], material: StagedMaterial) -> tuple[list[JSONValue], int]:
    """The ``files`` extra-var plus the bytes those writes need (§6.4 step 1's space check)."""
    paths = {kind: getattr(material, MATERIAL_FIELD[kind]) for kind in MATERIAL_FIELD}
    entries: list[JSONValue] = []
    required = 0
    for write in plan_file_writes(targets):
        entries.append({"path": write.path, "kind": write.kind, "source": SOURCE_VARIABLE[write.kind]})
        required += Path(paths[write.kind]).stat().st_size
    return entries, required


def _extravars(
    hostname: str,
    webserver: WebserverType,
    targets: Sequence[DeployTarget],
    material: StagedMaterial,
    tools: Mapping[str, str],
    *,
    job_id: UUID,
    retention_days: int,
) -> dict[str, JSONValue]:
    entries, written = _files(targets, material)
    planned: list[JSONValue] = [
        {
            "binding_id": item.binding_id,
            "cert_path": item.cert_path,
            "chain_path": item.chain_path,
            "key_path": item.key_path,
            "expected_fingerprint": item.expected_fingerprint,
            "new_fingerprint": item.new_fingerprint,
            "port": item.port,
            "sni": item.sni,
        }
        for item in targets
    ]
    return {
        "job_id": str(job_id),
        "backup_root": BACKUP_ROOT,
        "backup_retention_days": retention_days,
        "space_required_bytes": 2 * written + SPACE_MARGIN,
        "openssl_bin": tools["openssl"],
        "sha256sum_bin": tools["sha256sum"],
        "cert_pem_path": str(material.cert_pem),
        "chain_pem_path": str(material.chain_pem),
        "fullchain_pem_path": str(material.fullchain_pem),
        "key_pem_path": str(material.key_pem),
        "webservers": {hostname: str(webserver)},
        "files": entries,
        "targets": planned,
    }


def run_host_deploy(
    runner: RunnerContext,
    hostname: str,
    webserver: WebserverType,
    targets: Sequence[DeployTarget],
    material: StagedMaterial,
    *,
    job_id: UUID,
    retention_days: int,
    timeout_seconds: int,
) -> HostOutcome:
    """Run ``deploy.yml`` against exactly ``hostname`` and return its Contract decision 18 outcome.

    Host-level failures are returned, never raised: a refusal before Ansible runs (``FileConflict``, a path
    that is not absolute and normalized) costs no run at all, and everything after it is decided by
    ``parse_host_result``.
    """
    for item in targets:
        if not all(_safe(path) for path in (item.cert_path, item.chain_path, item.key_path)):
            return failure("internal", detail="invalid target path")
    tools, missing = _preflight_tools()
    if missing is not None:
        # An absent binary costs no run and no backup directory: it is an environment failure.
        return missing
    try:
        extravars = _extravars(
            hostname, webserver, targets, material, tools, job_id=job_id, retention_days=retention_days
        )
    except FileConflict:
        return failure("file_conflict")
    run = AnsibleRun(str(DEPLOY_PLAYBOOK), hostname, extravars, timeout_seconds)
    return parse_host_result(hostname, run_playbook(runner, run, ident=hostname), targets)
