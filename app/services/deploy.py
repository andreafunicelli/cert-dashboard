"""Deploy planning, preview and enqueue shared by the web process and the worker (§6.4–§6.6, §8.7).

Rollout planning (canary + round-robin batches), the stop-at-first-failure batch executor, the
write-once file map and — Plan 3 Task 13 — the advisory preview plus the guarded enqueue. Nothing
here imports ``app.ansible``: the web process computes previews and enqueues, the worker executes.

File roles follow D1: a ``chain`` write exists only for a target whose ``chain_path`` is set — the
value discovery recorded after verifying the chain file's signature. ``plan_file_writes`` receives
no issuer or subject data and never infers a chain from paths or ordering.

The §8.7 key-version guardrail needs the process keyring. ``configure_keyring`` registers it once at
startup (and in tests); callers that already hold it pass ``keyring=`` explicitly. When neither is
available the preview warns and ``start_deploy`` refuses with ``key_unavailable``: a deploy never
proceeds without a verified key version.
"""

import hashlib
import json
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.keyring import Keyring
from app.jobs.locks import DEPLOY_ENQUEUE_LOCK, xact_lock
from app.jobs.queue import enqueue
from app.models import Binding, Certificate, Job, JobHost, JSONValue, PrivateKey, Renewal, Server
from app.models.enums import (
    CertificateStatus,
    ChainStatus,
    JobHostStatus,
    JobStatus,
    JobType,
    RenewalState,
)
from app.services.audit import Actor, record
from app.services.bindings import verify_sni
from app.services.settings import get_setting
from app.services.trust_anchors import assess_certificate

UNGROUPED = "ungrouped"
DEPLOY_PRIORITY = 300

_STALE_DISCOVERY = timedelta(hours=24)
_NOT_BEFORE_LIMIT = timedelta(days=7)
_OVERRIDE_REASON_MAX = 500
_ACTIVE_DEPLOY_STATUSES = (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.PAUSED)
_EXCLUDED_MATCH_STATES = frozenset({"key_mismatch", "missing_file"})
_ACTIONS: dict[str, Literal["write cert", "write chain", "write key"]] = {
    "leaf": "write cert",
    "fullchain": "write cert",
    "chain": "write chain",
    "key": "write key",
}

_KEYRING: Keyring | None = None


def configure_keyring(keyring: Keyring | None) -> None:
    """Register the process keyring used by the §8.7 key-version guardrail (startup and tests)."""
    global _KEYRING
    _KEYRING = keyring


class PlanError(ValueError):
    """The rollout cannot be planned (empty selection, bad percentage, unknown canary)."""


@dataclass(frozen=True)
class PlanServer:
    server_id: int
    hostname: str
    groups: tuple[str, ...]
    binding_ids: tuple[int, ...]


def batch_size(total_servers: int, batch_percent: int) -> int:
    """``max(1, ceil(total * percent / 100))`` in integer arithmetic; total includes the canary."""
    if total_servers < 1:
        raise PlanError("a rollout needs at least one server")
    if not 1 <= batch_percent <= 100:
        raise PlanError("batch_percent must be between 1 and 100")
    return max(1, -(-total_servers * batch_percent // 100))


def rotation_group(server: PlanServer) -> str:
    """The lexicographically smallest Ansible group, ``ungrouped`` when there is none."""
    return min(server.groups, default=UNGROUPED)


def _order(server: PlanServer) -> tuple[str, int]:
    return (server.hostname, server.server_id)


def default_canary(servers: Sequence[PlanServer]) -> PlanServer:
    """First server by hostname of the smallest group (ties by name), counting every membership."""
    if not servers:
        raise PlanError("a rollout needs at least one server")
    members: dict[str, list[PlanServer]] = defaultdict(list)
    for server in servers:
        for group in server.groups or (UNGROUPED,):
            members[group].append(server)
    smallest = min(members, key=lambda group: (len(members[group]), group))
    return min(members[smallest], key=_order)


def plan_batches(
    servers: Sequence[PlanServer], *, canary_server_id: int | None, batch_percent: int
) -> list[list[PlanServer]]:
    """Batch 0 is the canary; the rest are consecutive chunks of ``batch_size`` taken round-robin
    across rotation groups (groups by name, servers by hostname)."""
    if not servers:
        raise PlanError("a rollout needs at least one server")
    if len({server.server_id for server in servers}) != len(servers):
        raise PlanError("a server appears more than once in the rollout")
    size = batch_size(len(servers), batch_percent)
    if canary_server_id is None:
        canary = default_canary(servers)
    else:
        canary = next((s for s in servers if s.server_id == canary_server_id), None)
        if canary is None:
            raise PlanError(f"canary server {canary_server_id} is not part of the rollout")

    queues: dict[str, list[PlanServer]] = defaultdict(list)
    for server in sorted(servers, key=_order):
        if server.server_id != canary.server_id:
            queues[rotation_group(server)].append(server)
    rotation: list[PlanServer] = []
    columns = [queues[group] for group in sorted(queues)]
    for depth in range(max(map(len, columns), default=0)):
        rotation.extend(column[depth] for column in columns if depth < len(column))
    return [[canary], *(rotation[i : i + size] for i in range(0, len(rotation), size))]


@dataclass(frozen=True)
class BatchRun[H, R]:
    """Outcome of one batch: ``results`` in completion order, hosts never submitted, first failure."""

    results: dict[H, R | BaseException]
    not_started: tuple[H, ...]
    stopped_by: H | None


def run_batch[H, R](
    hosts: Sequence[H],
    *,
    concurrency: int,
    run_one: Callable[[H], R],
    failed: Callable[[R], bool],
    should_stop: Callable[[], bool] = lambda: False,
    _executor_factory: Callable[..., ThreadPoolExecutor] = ThreadPoolExecutor,
) -> BatchRun[H, R]:
    """Run ``hosts`` with incremental submission: a host is submitted only while fewer than
    ``concurrency`` futures are unfinished and no failure (a result for which ``failed`` is true, or
    an exception) or stop request was seen. In-flight hosts always finish; the rest are returned in
    ``not_started``. Never ``executor.map`` / submit-all: a queued future would still run after a
    failure."""
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    if len(set(hosts)) != len(hosts):
        raise ValueError("hosts must be unique")
    results: dict[H, R | BaseException] = {}
    stopped_by: H | None = None
    submitted = 0
    in_flight: dict[Future[R], tuple[int, H]] = {}
    halted = False
    with _executor_factory(max_workers=concurrency) as executor:
        while True:
            halted = halted or should_stop()
            while not halted and len(in_flight) < concurrency and submitted < len(hosts):
                host = hosts[submitted]
                in_flight[executor.submit(run_one, host)] = (submitted, host)
                submitted += 1
                halted = should_stop()
            if not in_flight:
                break
            done, _ = wait(in_flight, timeout=None, return_when=FIRST_COMPLETED)
            for future in sorted(done, key=lambda f: in_flight[f][0]):
                _, host = in_flight.pop(future)
                error = future.exception()
                outcome: R | BaseException = error if error is not None else future.result()
                results[host] = outcome
                if error is not None or failed(outcome):  # type: ignore[arg-type]
                    halted = True
                    if stopped_by is None:
                        stopped_by = host
    return BatchRun(results, tuple(hosts[submitted:]), stopped_by)


class FileConflict(ValueError):
    """One path would need two different contents; ``path`` names it."""

    def __init__(self, path: str) -> None:
        super().__init__(f"conflicting writes planned for {path}")
        self.path = path


@dataclass(frozen=True)
class DeployTarget:
    binding_id: int
    cert_path: str
    chain_path: str | None
    key_path: str
    expected_fingerprint: str | None
    new_fingerprint: str
    port: int
    sni: str | None


@dataclass(frozen=True)
class FileWrite:
    path: str
    kind: Literal["leaf", "fullchain", "chain", "key"]
    binding_ids: tuple[int, ...]


def plan_file_writes(targets: Sequence[DeployTarget]) -> tuple[FileWrite, ...]:
    """Map every distinct path to exactly one write, sorted by path.

    ``cert_path`` gets the leaf when the target has an explicit ``chain_path`` (which gets the
    chain), otherwise the full chain; ``key_path`` gets the key. Bindings sharing a path share one
    write; a path needed with different content raises ``FileConflict``.
    """
    planned: dict[str, tuple[str, str | None, set[int]]] = {}

    def need(path: str, kind: str, content: str | None, binding_id: int) -> None:
        # content: the certificate a cert-type file carries (keys follow that certificate's key).
        current = planned.setdefault(path, (kind, content, set()))
        if current[:2] != (kind, content):
            raise FileConflict(path)
        current[2].add(binding_id)

    for target in targets:
        need(target.key_path, "key", target.new_fingerprint, target.binding_id)
        if target.chain_path is None:
            need(target.cert_path, "fullchain", target.new_fingerprint, target.binding_id)
        else:
            need(target.cert_path, "leaf", target.new_fingerprint, target.binding_id)
            need(target.chain_path, "chain", target.new_fingerprint, target.binding_id)
    return tuple(
        FileWrite(path, kind, tuple(sorted(ids)))  # type: ignore[arg-type]
        for path, (kind, _, ids) in sorted(planned.items())
    )


class DeployBlocked(ValueError):
    """A deploy is refused; ``reasons`` maps a stable code to operator-facing text."""

    def __init__(self, reasons: Mapping[str, str], active_job_id: UUID | None = None) -> None:
        self.reasons = dict(reasons)
        self.active_job_id = active_job_id
        super().__init__("; ".join(self.reasons.values()) or "deploy refused")


@dataclass(frozen=True)
class DeployOptions:
    certificate_id: int
    binding_ids: tuple[int, ...] | None = None
    groups: tuple[str, ...] = ()
    hostnames: tuple[str, ...] = ()
    include_unknown: bool = False
    batch_percent: int | None = None
    pause_after_canary: bool | None = None
    canary_server_id: int | None = None
    not_before: datetime | None = None


@dataclass(frozen=True)
class PreviewBinding:
    binding_id: int
    vhost_name: str
    port: int
    match_state: str
    current_certificate_id: int | None
    current_common_name: str | None
    current_fingerprint: str | None
    current_not_after: datetime | None


@dataclass(frozen=True)
class PreviewFile:
    path: str
    action: Literal["write cert", "write chain", "write key"]
    owner: str | None
    group: str | None
    mode: str | None


@dataclass(frozen=True)
class PreviewHost:
    server_id: int
    hostname: str
    groups: tuple[str, ...]
    batch_no: int
    last_discovery_at: datetime | None
    bindings: tuple[PreviewBinding, ...]
    files: tuple[PreviewFile, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class DeployPreview:
    certificate: Certificate
    renewal_id: UUID | None
    chain_status: str
    needs_override: bool
    hosts: tuple[PreviewHost, ...]
    batches: tuple[int, ...]
    totals: dict[str, int]
    warnings: tuple[str, ...]
    excluded: tuple[PreviewBinding, ...]
    blocked: dict[str, str]
    plan_sha256: str


@dataclass(frozen=True)
class _Candidate:
    binding: Binding
    server: Server
    current: Certificate | None


@dataclass(frozen=True)
class _PlannedRow:
    server_id: int
    binding_id: int
    batch_no: int
    old_fingerprint: str | None


@dataclass(frozen=True)
class _Plan:
    preview: DeployPreview
    rows: tuple[_PlannedRow, ...]
    unknown_binding_ids: tuple[int, ...]
    batch_percent: int
    pause_after_canary: bool
    run_after: datetime
    active_job_id: UUID | None


def _int_setting(db: Session, key: str, default: int) -> int:
    value = get_setting(db, key)
    return value if type(value) is int else default


def _bool_setting(db: Session, key: str, default: bool) -> bool:
    value = get_setting(db, key)
    return value if isinstance(value, bool) else default


def _preview_binding(binding: Binding, current: Certificate | None) -> PreviewBinding:
    return PreviewBinding(
        binding_id=binding.id,
        vhost_name=binding.vhost_name,
        port=binding.port,
        match_state=binding.match_state,
        current_certificate_id=binding.certificate_id,
        current_common_name=current.common_name if current is not None else None,
        current_fingerprint=current.sha256_fingerprint if current is not None else None,
        current_not_after=current.not_after if current is not None else None,
    )


def _deploy_target(candidate: _Candidate, certificate: Certificate) -> DeployTarget:
    binding = candidate.binding
    return DeployTarget(
        binding_id=binding.id,
        cert_path=binding.cert_path,
        chain_path=binding.chain_path,
        key_path=binding.key_path,
        expected_fingerprint=binding.on_disk_fingerprint,
        new_fingerprint=certificate.sha256_fingerprint,
        port=binding.port,
        sni=verify_sni(binding.vhost_name, binding.vhost_names or ()),
    )


def _octal(mode: int | None) -> str | None:
    return None if mode is None else f"{mode:04o}"


def _preview_file(write: FileWrite, candidates: Sequence[_Candidate]) -> PreviewFile:
    """The stored owner/group/mode of the lowest binding id that needs ``write``."""
    binding = min(
        (item.binding for item in candidates if item.binding.id in write.binding_ids),
        key=lambda row: row.id,
    )
    if write.kind == "key":
        owner, group, mode = binding.key_owner, binding.key_group, binding.key_mode
    else:
        owner, group, mode = binding.cert_owner, binding.cert_group, binding.cert_mode
    return PreviewFile(write.path, _ACTIONS[write.kind], owner, group, _octal(mode))


def _plan_sha256(
    certificate: Certificate,
    binding_ids: Sequence[int],
    canary_server_id: int | None,
    batch_percent: int,
    pause_after_canary: bool,
    include_unknown: bool,
    chain_status: str,
) -> str:
    """SHA-256 of the canonical plan the operator confirmed (Contract decision 15)."""
    canonical = {
        "batch_percent": batch_percent,
        "binding_ids": sorted(binding_ids),
        "canary_server_id": canary_server_id,
        "certificate_id": certificate.id,
        "chain_status": chain_status,
        "include_unknown": include_unknown,
        "pause_after_canary": pause_after_canary,
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _active_deploy(db: Session) -> tuple[UUID, JobStatus] | None:
    row = db.execute(
        select(Job.id, Job.status)
        .where(Job.type == JobType.DEPLOY, Job.status.in_(_ACTIVE_DEPLOY_STATUSES))
        .order_by(Job.created_at.desc())
        .limit(1)
    ).first()
    return (row.id, row.status) if row is not None else None


def _renewal_id(db: Session, certificate: Certificate) -> UUID | None:
    return db.scalar(
        select(Renewal.id)
        .where(Renewal.certificate_id == certificate.id, Renewal.state == RenewalState.ISSUED)
        .order_by(Renewal.state_changed_at.desc())
        .limit(1)
    )


def _candidates(db: Session, options: DeployOptions, certificate: Certificate) -> list[_Candidate]:
    query = (
        select(Binding, Server, Certificate)
        .join(Server, Server.id == Binding.server_id)
        .outerjoin(Certificate, Certificate.id == Binding.certificate_id)
        .where(Binding.is_active.is_(True), Server.is_active.is_(True))
    )
    if options.binding_ids is not None:
        query = query.where(Binding.id.in_(tuple(options.binding_ids)))
    else:
        owned = [certificate.id]
        if certificate.renews_id is not None:
            owned.append(certificate.renews_id)
        query = query.where(Binding.certificate_id.in_(owned))
    if options.groups:
        query = query.where(Server.ansible_groups.op("&&")(list(options.groups)))
    if options.hostnames:
        query = query.where(Server.hostname.in_(tuple(options.hostnames)))
    return [
        _Candidate(binding, server, current)
        for binding, server, current in db.execute(query.order_by(Binding.server_id, Binding.id)).all()
    ]


def _plan(db: Session, options: DeployOptions, now: datetime, keyring: Keyring | None) -> _Plan:
    certificate = db.get(Certificate, options.certificate_id)
    if certificate is None:
        raise DeployBlocked({"certificate": f"certificate {options.certificate_id} does not exist"})
    assessment = assess_certificate(db, certificate.id, now)
    chain_status = assessment.status.value

    batch_percent = (
        options.batch_percent
        if options.batch_percent is not None
        else _int_setting(db, "deploy.batch_percent", 10)
    )
    pause_after_canary = (
        options.pause_after_canary
        if options.pause_after_canary is not None
        else _bool_setting(db, "deploy.pause_after_canary", True)
    )
    not_before = options.not_before
    run_after = now if not_before is None else max(_utc(not_before), now)

    included: list[_Candidate] = []
    excluded: list[PreviewBinding] = []
    unknown_binding_ids: list[int] = []
    warnings: list[str] = []
    for candidate in _candidates(db, options, certificate):
        binding, server = candidate.binding, candidate.server
        if binding.match_state in _EXCLUDED_MATCH_STATES:
            excluded.append(_preview_binding(binding, candidate.current))
            warnings.append(
                f"{server.hostname}: {binding.vhost_name}: excluded from the plan ({binding.match_state})"
            )
            continue
        if binding.match_state == "unknown" and not options.include_unknown:
            excluded.append(_preview_binding(binding, candidate.current))
            warnings.append(
                f"{server.hostname}: {binding.vhost_name}: excluded from the plan (unknown certificate; "
                "include unknown bindings to deploy to it)"
            )
            continue
        included.append(candidate)
        if binding.match_state == "unknown":
            unknown_binding_ids.append(binding.id)

    by_server: dict[int, list[_Candidate]] = defaultdict(list)
    for candidate in included:
        by_server[candidate.server.id].append(candidate)
    plan_servers = [
        PlanServer(
            server_id,
            candidates[0].server.hostname,
            tuple(candidates[0].server.ansible_groups or ()),
            tuple(sorted(item.binding.id for item in candidates)),
        )
        for server_id, candidates in sorted(by_server.items())
    ]
    if plan_servers:
        try:
            batches = plan_batches(
                plan_servers, canary_server_id=options.canary_server_id, batch_percent=batch_percent
            )
        except PlanError as exc:
            raise DeployBlocked({"selection": str(exc)}) from None
    else:
        batches = []
    batch_of = {server.server_id: index for index, batch in enumerate(batches) for server in batch}

    hosts: list[PreviewHost] = []
    rows: list[_PlannedRow] = []
    file_conflicts: dict[str, str] = {}
    for server_id, candidates in sorted(by_server.items()):
        server = candidates[0].server
        try:
            writes = plan_file_writes(tuple(_deploy_target(item, certificate) for item in candidates))
        except FileConflict as exc:
            file_conflicts.setdefault(
                "file_conflict", f"{server.hostname}: two different writes are planned for {exc.path}"
            )
            writes = ()
        host_warnings: list[str] = []
        if server.last_discovery_at is None or now - server.last_discovery_at > _STALE_DISCOVERY:
            host_warnings.append(f"{server.hostname}: last discovery is older than 24 hours")
        for candidate in candidates:
            if candidate.binding.certificate_id != certificate.renews_id:
                host_warnings.append(
                    f"{server.hostname}: {candidate.binding.vhost_name}: the current certificate is not "
                    "the one being replaced"
                )
        hosts.append(
            PreviewHost(
                server_id=server_id,
                hostname=server.hostname,
                groups=tuple(server.ansible_groups or ()),
                batch_no=batch_of[server_id],
                last_discovery_at=server.last_discovery_at,
                bindings=tuple(_preview_binding(item.binding, item.current) for item in candidates),
                files=tuple(_preview_file(write, candidates) for write in writes),
                warnings=tuple(host_warnings),
            )
        )
        rows.extend(
            _PlannedRow(
                server_id=server_id,
                binding_id=item.binding.id,
                batch_no=batch_of[server_id],
                old_fingerprint=item.binding.on_disk_fingerprint,
            )
            for item in candidates
        )

    replaced = db.get(Certificate, certificate.renews_id) if certificate.renews_id is not None else None
    if replaced is not None and certificate.not_after < replaced.not_after:
        warnings.append(
            "the new certificate expires before the one it replaces "
            f"({certificate.not_after.date()} < {replaced.not_after.date()})"
        )
    ring = keyring if keyring is not None else _KEYRING
    if ring is None:
        warnings.append("the keyring is unavailable; the certificate key version cannot be verified")
    warnings.extend(warning for host in hosts for warning in host.warnings)

    blocked: dict[str, str] = {}
    key_row = db.get(PrivateKey, certificate.key_id) if certificate.key_id is not None else None
    if key_row is None:
        blocked["no_key"] = "the certificate has no stored private key; import or renew it before deploying"
    elif ring is None:
        blocked["key_unavailable"] = (
            "the keyring is unavailable, so the certificate's key version cannot be verified"
        )
    elif key_row.master_key_version not in ring.keys:
        blocked["key_version"] = f"master-key version {key_row.master_key_version} is missing from the keyring"
    if certificate.not_after <= now:
        blocked["expired"] = f"the certificate expired on {certificate.not_after.isoformat()}"
    elif certificate.not_before > now:
        blocked["not_yet_valid"] = f"the certificate is not valid before {certificate.not_before.isoformat()}"
    if certificate.status == CertificateStatus.REVOKED:
        blocked["revoked"] = "the certificate is revoked"
    if not included:
        blocked["no_targets"] = "no active binding is a deploy target for this certificate"
    elif all(item.binding.on_disk_fingerprint == certificate.sha256_fingerprint for item in included):
        blocked["already_deployed"] = (
            "every target binding already has the new certificate on disk; there is nothing to deploy"
        )
    active = _active_deploy(db)
    if active is not None:
        blocked["active_deploy"] = f"deploy job {active[0]} is {active[1].value}"
    blocked.update(file_conflicts)
    if not_before is not None and _utc(not_before) > now + _NOT_BEFORE_LIMIT:
        blocked["not_before"] = "not before must be at most seven days in the future"

    binding_ids = [row.binding_id for row in rows]
    preview = DeployPreview(
        certificate=certificate,
        renewal_id=_renewal_id(db, certificate),
        chain_status=chain_status,
        needs_override=assessment.status is not ChainStatus.TRUSTED,
        hosts=tuple(hosts),
        batches=tuple(len(batch) for batch in batches),
        totals={
            "hosts": len(hosts),
            "bindings": len(binding_ids),
            "files": sum(len(host.files) for host in hosts),
            "groups": len({rotation_group(server) for server in plan_servers}),
        },
        warnings=tuple(warnings),
        excluded=tuple(excluded),
        blocked=blocked,
        plan_sha256=_plan_sha256(
            certificate,
            binding_ids,
            options.canary_server_id,
            batch_percent,
            pause_after_canary,
            options.include_unknown,
            chain_status,
        ),
    )
    return _Plan(
        preview=preview,
        rows=tuple(rows),
        unknown_binding_ids=tuple(sorted(unknown_binding_ids)),
        batch_percent=batch_percent,
        pause_after_canary=pause_after_canary,
        run_after=run_after,
        active_job_id=active[0] if active is not None else None,
    )


def preview_deploy(
    db: Session, options: DeployOptions, now: datetime, *, keyring: Keyring | None = None
) -> DeployPreview:
    """The advisory §6.6 preview computed from the database (last discovery), with ``plan_sha256``.

    Re-assesses the certificate's chain at ``now`` first, so a changed ``chain_status`` is persisted with
    its ``certificate.chain_check`` audit (Contract decision 16); the caller owns the transaction.
    """
    return _plan(db, options, now, keyring).preview


def start_deploy(
    db: Session,
    options: DeployOptions,
    *,
    plan_sha256: str,
    confirmed: bool,
    override_reason: str | None,
    actor: Actor,
    now: datetime,
    retry_of: UUID | None = None,
    keyring: Keyring | None = None,
) -> Job:
    """Enqueue a guarded deploy job and every ``job_host`` row in the caller's transaction (§6.5)."""
    xact_lock(db, DEPLOY_ENQUEUE_LOCK)
    plan = _plan(db, options, now, keyring)
    preview = plan.preview
    if preview.blocked:
        active = plan.active_job_id if "active_deploy" in preview.blocked else None
        raise DeployBlocked(preview.blocked, active)
    if plan_sha256 != preview.plan_sha256:
        raise DeployBlocked(
            {"plan_changed": "the plan changed since it was previewed; review the new preview and confirm it"}
        )
    canary = next(host for host in preview.hosts if host.batch_no == 0)
    if not confirmed:
        raise DeployBlocked(
            {
                "confirm": f"confirm deploying to {preview.totals['hosts']} hosts with canary "
                f"{canary.hostname} first"
            }
        )
    reason = override_reason.strip() if isinstance(override_reason, str) else ""
    if preview.needs_override and not 1 <= len(reason) <= _OVERRIDE_REASON_MAX:
        raise DeployBlocked(
            {
                "chain_override": f"the certificate chain is {preview.chain_status}; a reason of 1 to "
                f"{_OVERRIDE_REASON_MAX} characters is required"
            }
        )

    payload: dict[str, JSONValue] = {
        "certificate_id": preview.certificate.id,
        "renewal_id": str(preview.renewal_id) if preview.renewal_id is not None else None,
        "batch_percent": plan.batch_percent,
        "pause_after_canary": plan.pause_after_canary,
        "include_unknown": options.include_unknown,
        "chain_override": preview.needs_override,
        "chain_status_at_plan": preview.chain_status,
        "plan_sha256": preview.plan_sha256,
    }
    if retry_of is not None:
        payload["retry_of"] = str(retry_of)
    job = enqueue(
        db,
        JobType.DEPLOY,
        payload,
        actor,
        priority=DEPLOY_PRIORITY,
        run_after=plan.run_after,
        max_attempts=1,
    )
    for row in plan.rows:
        db.add(
            JobHost(
                job_id=job.id,
                server_id=row.server_id,
                binding_id=row.binding_id,
                batch_no=row.batch_no,
                status=JobHostStatus.PENDING,
                old_fingerprint=row.old_fingerprint,
                new_fingerprint=preview.certificate.sha256_fingerprint,
            )
        )
    db.flush()
    if plan.unknown_binding_ids:
        record(
            db,
            actor,
            "deploy.include_unknown",
            "job",
            str(job.id),
            {"binding_ids": list(plan.unknown_binding_ids)},
        )
    if preview.needs_override:
        record(
            db,
            actor,
            "deploy.chain_override",
            "job",
            str(job.id),
            {
                "certificate_id": preview.certificate.id,
                "previous_status": preview.chain_status,
                "job_id": str(job.id),
                "reason": reason,
            },
        )
    record(
        db,
        actor,
        "deploy.start",
        "job",
        str(job.id),
        {
            "certificate_id": preview.certificate.id,
            "hosts": preview.totals["hosts"],
            "bindings": preview.totals["bindings"],
            "canary": canary.hostname,
            "batches": list(preview.batches),
        },
    )
    db.flush()
    return job
