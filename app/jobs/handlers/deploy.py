"""Worker handler for ``deploy/default`` (Plan 3 Task 16; spec §6.4–§6.7, §7.2, §4.6).

The payload is written by ``start_deploy`` (Task 13) and is the only description of the confirmed plan the
worker trusts: exactly the Contract decision 15 keys, validated here before anything runs.

Execution order, fixed once (Contract decisions 4, 16–19, 21):

1. ``ansible_job`` takes ``deploy:global`` non-blocking — busy is a ``JobRequeued`` 30 s out, and no attempt
   is spent — then refreshes the inventory and stages the SSH key;
2. the plan is revalidated at execution time (trust gate, activity, validity) and the stored key is unwrapped
   and compared with the leaf's SubjectPublicKeyInfo hash (D2: DER, lowercase hex). A job-level refusal marks
   every pending row ``skipped``/``job_failed`` before it is raised;
3. the material is staged (public PEMs in the artifact directory, the private key only on the tmpfs);
4. batches run in plan order with incremental submission (``run_batch``). A host holds ``deploy:<hostname>``
   for its own run; a busy host lock is ``skipped``/``locked``, not a failure. The first ``failed`` or
   ``rolled_back`` host stops the rollout: nothing new is submitted, in-flight hosts finish, the unstarted and
   later rows become ``skipped``/``rollout_stopped`` and the job fails with Contract decision 18's message;
5. after a successful canary batch with ``pause_after_canary`` set and hosts still to run, the handler raises
   ``JobPaused(1, ...)``: the worker releases the claim, so no slot, lock or timeout is held and the reaper
   never sees the job. Continue (an operator, or the UI) requeues it at batch 1 and everything above runs
   again — locks, inventory pull, trust gate and every host's drift preflight;
6. an operator cancel marks the pending rows ``skipped``/``cancelled``; ``should_stop`` sees that, so nothing
   new is submitted, the in-flight hosts finish or roll back and the job ends as ``JobCancelled``.

The renewal is advanced to ``deployed`` by ``advance_renewal``, registered here as the success hook and run by
the worker inside the transaction that marks the job ``succeeded`` (Contract decision 3). Paused, failed and
cancelled deploys never advance it.

A deploy policy has exactly one attempt: a single-host retry is a new job (``retry_host`` in the service
module), never an automatic retry of this one.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ansible.deploy import (
    StagedMaterial,
    failure,
    run_host_deploy,
    stage_material,
)
from app.crypto.keyring import Keyring, KeyUnwrapError
from app.crypto.keys import public_key_sha256
from app.crypto.parse import ParseError, parse_certificates
from app.jobs.handlers.ansible_context import AnsibleJob, LockBusy, ansible_job
from app.jobs.locks import DEPLOY_GLOBAL_LOCK, AdvisoryLocks, host_lock_key
from app.jobs.queue import JobCancelled, JobFailure, JobPaused, JobRequeued
from app.models import Binding, Certificate, Job, JobHost, JSONValue, Server
from app.models.enums import ChainStatus, JobHostStatus, JobType, WebserverType
from app.services.audit import Actor
from app.services.bindings import verify_sni
from app.services.certificates import unwrap_key
from app.services.deploy import BatchRun, DeployTarget, run_batch
from app.services.deploy_runtime import (
    CANCELLED_BY_OPERATOR,
    ExecutionGate,
    advance_renewal,
    cancel_accepted,
    claim_host_rows,
    deploy_totals,
    record_host_outcome,
    revalidate_for_execution,
    skip_pending,
)
from app.services.inventory import revision_result
from app.services.settings import get_setting

if TYPE_CHECKING:
    from app.crypto.keys import PrivateKeyObject
    from app.jobs.worker import JobContext, JobRegistry
    from app.services.inventory import InventoryRevision

__all__ = ["deploy", "deploy_handler_registration", "validate_deploy_payload"]

_LOG = logging.getLogger(__name__)

LOCK_RETRY_DELAY = timedelta(seconds=30)
# Contract decision 18's mapping from a host failure reason to the job's error class.
_ERROR_CLASS = {
    "unreachable": "transient_network",
    "auth": "auth",
    "host_timeout": "timeout",
    "internal": "internal",
}
# A rollout stops on the first host that changed nothing or that could not restore what it changed.
_STOPPING_STATUSES = ("failed", "rolled_back")
_EXECUTION_KEY_MISMATCH = "the certificate and its stored private key do not match"

# Contract decision 15: the exact payload keys ``start_deploy`` writes.
_KEYS = frozenset(
    {
        "certificate_id",
        "renewal_id",
        "batch_percent",
        "pause_after_canary",
        "include_unknown",
        "chain_override",
        "chain_status_at_plan",
        "plan_sha256",
        "retry_of",
    }
)
_REQUIRED = _KEYS - {"retry_of"}
_CHAIN_STATUSES = frozenset(status.value for status in ChainStatus)
_HEX = frozenset("0123456789abcdef")


def _uuid_string(name: str, value: object) -> str:
    """A canonical UUID string (``str(UUID(value)) == value``), or ``ValueError``."""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a UUID string")  # noqa: TRY004 - contract: ValueError
    try:
        parsed = UUID(value)
    except ValueError:
        raise ValueError(f"{name} must be a UUID string") from None
    if str(parsed) != value:
        raise ValueError(f"{name} must be a canonical UUID string")
    return value


def _flag(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")  # noqa: TRY004 - contract: ValueError
    return value


def validate_deploy_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Accept exactly the Contract decision 15 payload; anything else — including ``reason`` — is refused.

    ``certificate_id`` is a positive integer, ``batch_percent`` 1–100, ``chain_status_at_plan`` one of the
    ``ChainStatus`` values, ``plan_sha256`` a lowercase SHA-256 hex digest and ``retry_of`` (optional) a
    canonical UUID string. The three flags are real booleans (``0``/``"false"`` are not).
    """
    if not isinstance(payload, Mapping):
        raise ValueError("a deploy payload must be an object")  # noqa: TRY004 - contract: ValueError
    keys = set(payload)
    if keys - _KEYS:
        raise ValueError("a deploy payload takes no keys other than the confirmed plan")
    if _REQUIRED - keys:
        raise ValueError("the deploy payload is incomplete")

    certificate_id = payload["certificate_id"]
    if type(certificate_id) is not int or certificate_id < 1:
        raise ValueError("certificate_id must be a positive integer")

    renewal_id = payload["renewal_id"]
    clean_renewal = None if renewal_id is None else _uuid_string("renewal_id", renewal_id)

    batch_percent = payload["batch_percent"]
    if type(batch_percent) is not int or not 1 <= batch_percent <= 100:
        raise ValueError("batch_percent must be an integer between 1 and 100")

    chain_status = payload["chain_status_at_plan"]
    if not isinstance(chain_status, str) or chain_status not in _CHAIN_STATUSES:
        raise ValueError("chain_status_at_plan must be a chain status")

    plan_sha256 = payload["plan_sha256"]
    if not isinstance(plan_sha256, str) or len(plan_sha256) != 64 or not set(plan_sha256) <= _HEX:
        raise ValueError("plan_sha256 must be a lowercase SHA-256 hex digest")

    clean: dict[str, JSONValue] = {
        "certificate_id": certificate_id,
        "renewal_id": clean_renewal,
        "batch_percent": batch_percent,
        "pause_after_canary": _flag("pause_after_canary", payload["pause_after_canary"]),
        "include_unknown": _flag("include_unknown", payload["include_unknown"]),
        "chain_override": _flag("chain_override", payload["chain_override"]),
        "chain_status_at_plan": chain_status,
        "plan_sha256": plan_sha256,
    }
    if "retry_of" in payload:
        clean["retry_of"] = _uuid_string("retry_of", payload["retry_of"])
    return clean


# --- the handler -------------------------------------------------------------------------------------


def deploy_handler_registration(registry: JobRegistry) -> None:
    """Register ``deploy/default`` with its success hook (called by ``build_registry`` in Task 19)."""
    registry.register(JobType.DEPLOY, deploy, validator=validate_deploy_payload, on_success=advance_renewal)


def deploy(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
    """Execute one confirmed deploy job batch by batch; see the module docstring for the order."""
    pause_after_canary = payload.get("pause_after_canary") is True
    try:
        with ansible_job(context, exclusive=(DEPLOY_GLOBAL_LOCK,)) as job:
            return _deploy(context, job, pause_after_canary)
    except LockBusy:
        # ``deploy:global`` (another rollout) or the inventory lock (a reset) is held: nothing ran.
        raise JobRequeued(context.clock() + LOCK_RETRY_DELAY) from None


def _int_setting(db: Session, key: str, default: int) -> int:
    value = get_setting(db, key)
    return value if type(value) is int else default


def _actor(db: Session, job: Job) -> Actor:
    from app.jobs.queue import SYSTEM_ACTOR
    from app.models import User

    user = db.get(User, job.requested_by) if job.requested_by is not None else None
    return Actor(user.id, user.username) if user is not None else SYSTEM_ACTOR


def _execution_key(gate: ExecutionGate, keyring: Keyring) -> PrivateKeyObject:
    """Unwrap the planned key and compare its DER SPKI hash with the leaf's (D2, Contract decision 16)."""
    key = unwrap_key(gate.key_row, keyring)
    try:
        leaf = parse_certificates(gate.certificate.pem.encode())[0]
    except (ParseError, IndexError):
        raise JobFailure("config_invalid", "the stored certificate cannot be parsed") from None
    if public_key_sha256(key.public_key()) != leaf.public_key_sha256:
        raise JobFailure("config_invalid", _EXECUTION_KEY_MISMATCH)
    return key


def _gate_failure(context: JobContext, now: datetime) -> None:
    """Contract decision 16: a job-level gate refusal skips every pending row with ``job_failed``."""
    with context.factory.begin() as db:
        skip_pending(db, context.job_id, "job_failed", now=now)


@dataclass(frozen=True)
class _Host:
    """One server of the confirmed plan; the batch number is the row's."""

    server_id: int
    hostname: str
    webserver: WebserverType | None


@dataclass(frozen=True)
class _RunOptions:
    """The settings a host run needs, read once per attempt."""

    host_timeout: int
    retention_days: int


@dataclass(frozen=True)
class _HostRun:
    """What ``run_batch`` needs from one host: its status (``None`` = skipped, not a failure) and reason."""

    hostname: str
    status: str | None
    reason: str | None


def _deploy(context: JobContext, job: AnsibleJob, pause_after_canary: bool) -> Mapping[str, JSONValue]:
    if job.revision is None:
        raise JobFailure("internal", "the inventory was not prepared")
    now = context.clock()
    with context.factory() as db:
        row = db.get(Job, context.job_id)
        if row is None:  # pragma: no cover - the worker claimed this row
            raise JobFailure("internal", "job not found")
        actor = _actor(db, row)
    try:
        with context.factory.begin() as db:
            row = db.get(Job, context.job_id)
            gate = revalidate_for_execution(db, row, now)
            key = _execution_key(gate, context.settings.keyring)
    except KeyUnwrapError:
        _gate_failure(context, now)
        raise JobFailure(
            "key_unwrap", "the certificate's private key cannot be unwrapped with the configured keyring"
        ) from None
    except JobFailure:
        _gate_failure(context, now)
        raise

    material = stage_material(gate.certificate, key, job.runner.artifact_dir, job.staging)
    with context.factory() as db:
        row = db.get(Job, context.job_id)
        resume_from_batch = row.resume_from_batch
        concurrency = _int_setting(db, "deploy.concurrency", 5)
        options = _RunOptions(
            host_timeout=_int_setting(db, "deploy.host_timeout_seconds", 600),
            retention_days=_int_setting(db, "deploy.backup_retention_days", 30),
        )
        batches = _batches(db, context.job_id, resume_from_batch)

    for batch_no, hosts in batches:
        run = run_batch(
            hosts,
            concurrency=concurrency,
            run_one=lambda host: _host_task(context, job, material, gate.certificate, host, actor, options),
            failed=lambda outcome: outcome.status in _STOPPING_STATUSES,
            # Contract decision 20: an operator cancel skips the pending rows, so nothing new is submitted.
            should_stop=lambda: _cancelled(context),
        )
        if _cancel_accepted(context):
            # Contract decision 20: an accepted cancel is the job's outcome once the batch has settled.
            # It outranks a host that failed after it — every host keeps its failed/rolled back evidence
            # in its own rows — and the pending rows were already skipped ``cancelled``.
            raise JobCancelled(CANCELLED_BY_OPERATOR, _phase_result(job.revision, context, "cancelled"))
        if run.stopped_by is not None:
            reason = _stopped_reason(run.results.get(run.stopped_by))
            with context.factory.begin() as db:
                skip_pending(db, context.job_id, "rollout_stopped", from_batch=batch_no, now=context.clock())
            raise JobFailure(
                _ERROR_CLASS.get(reason, "config_invalid"),
                f"rollout stopped: {run.stopped_by.hostname} failed ({reason})",
            )
        if batch_no == 0 and pause_after_canary and _canary_succeeded(run) and _has_pending(context):
            raise JobPaused(1, _phase_result(job.revision, context, "paused"))
    if _cancel_accepted(context):
        # A cancel also lands when nothing was left to submit (a resume whose rows were all skipped).
        raise JobCancelled(CANCELLED_BY_OPERATOR, _phase_result(job.revision, context, "cancelled"))
    with context.factory() as db:
        totals = deploy_totals(db, context.job_id)
    return {**revision_result(job.revision), "phase": "done", "totals": totals}


def _phase_result(revision: InventoryRevision, context: JobContext, phase: str) -> dict[str, JSONValue]:
    """The result of a non-terminal outcome: the inventory revision and the totals so far."""
    with context.factory() as db:
        totals = deploy_totals(db, context.job_id)
    return {**revision_result(revision), "phase": phase, "totals": totals}


def _cancelled(context: JobContext) -> bool:
    """True once an operator cancel has left a ``skipped``/``cancelled`` row on this job (Contract decision 20)."""
    with context.factory() as db:
        return (
            db.scalar(
                select(JobHost.id)
                .where(
                    JobHost.job_id == context.job_id,
                    JobHost.status == JobHostStatus.SKIPPED,
                    JobHost.error_message == "cancelled",
                )
                .limit(1)
            )
            is not None
        )


def _cancel_accepted(context: JobContext) -> bool:
    """True once an operator Cancel for this job is committed (Contract decision 20).

    Unlike ``_cancelled`` this does not depend on a skipped row: cancelling the only in-flight host
    leaves every row ``running`` and writes just the ``deploy.cancel`` audit.
    """
    with context.factory() as db:
        return cancel_accepted(db, context.job_id)


def _has_pending(context: JobContext) -> bool:
    """True while any row of the job still has to run (the canary pause needs a later batch)."""
    with context.factory() as db:
        return (
            db.scalar(
                select(JobHost.id)
                .where(JobHost.job_id == context.job_id, JobHost.status == JobHostStatus.PENDING)
                .limit(1)
            )
            is not None
        )


def _canary_succeeded(run: BatchRun) -> bool:
    """The canary batch deployed: every host of batch 0 reported ``succeeded``.

    A host whose lock was busy is ``skipped``, not a success — nothing was written there, so there is no
    canary result to approve and the rollout continues under the plan the operator already confirmed.
    """
    return bool(run.results) and all(
        isinstance(outcome, _HostRun) and outcome.status == "succeeded" for outcome in run.results.values()
    )


def _stopped_reason(result: object) -> str:
    """The reason of the host that stopped the rollout (``internal`` when no outcome is readable)."""
    if isinstance(result, _HostRun):
        return result.reason or "internal"
    return "internal"


def _batches(db: Session, job_id: UUID, resume_from_batch: int) -> list[tuple[int, list[_Host]]]:
    """The still-``pending`` servers per batch, in plan order (batch, then hostname)."""
    rows = db.execute(
        select(Server.id, Server.hostname, Server.webserver, JobHost.batch_no)
        .join(Server, Server.id == JobHost.server_id)
        .where(
            JobHost.job_id == job_id,
            JobHost.status == JobHostStatus.PENDING,
            JobHost.batch_no >= resume_from_batch,
        )
        .distinct()
        .order_by(JobHost.batch_no, Server.hostname, Server.id)
    ).all()
    batches: dict[int, list[_Host]] = {}
    for server_id, hostname, webserver, batch_no in rows:
        batches.setdefault(batch_no, []).append(_Host(server_id, hostname, webserver))
    return sorted(batches.items())


# --- one host ----------------------------------------------------------------------------------------


def _host_task(
    context: JobContext,
    job: AnsibleJob,
    material: StagedMaterial,
    certificate: Certificate,
    host: _Host,
    actor: Actor,
    options: _RunOptions,
) -> _HostRun:
    """Run one host under its own ``deploy:<hostname>`` lock; never raises for a host-level failure."""
    locks = AdvisoryLocks(context.factory.kw["bind"])
    try:
        with locks.session() as session:
            if not session.try_lock(host_lock_key(host.hostname)):
                with context.factory.begin() as db:
                    skip_pending(db, context.job_id, "locked", server_id=host.server_id, now=context.clock())
                return _HostRun(host.hostname, None, None)
            try:
                return _run_host(context, job, material, certificate, host, actor, options)
            except BaseException:
                # Contract decision 18: an exception is this host's ``failed``/``internal`` before it stops
                # the rollout — no row may stay ``running`` after the worker gave up on it.
                _mark_internal(context, host)
                raise
    finally:
        locks.close()


def _run_host(
    context: JobContext,
    job: AnsibleJob,
    material: StagedMaterial,
    certificate: Certificate,
    host: _Host,
    actor: Actor,
    options: _RunOptions,
) -> _HostRun:
    now = context.clock()
    with context.factory.begin() as db:
        rows = claim_host_rows(db, context.job_id, host.server_id, now)
    if not rows:  # cancelled (Task 17) or already handled by another attempt
        return _HostRun(host.hostname, None, None)
    with context.factory() as db:
        targets = _targets(db, rows, certificate)
    if targets is None:
        outcome = failure("binding_blocked")
    elif host.webserver is None:
        outcome = failure("internal", detail="the host's webserver is unknown")
    else:
        outcome = run_host_deploy(
            job.runner,
            host.hostname,
            host.webserver,
            targets,
            material,
            job_id=context.job_id,
            retention_days=options.retention_days,
            timeout_seconds=options.host_timeout,
        )
    with context.factory.begin() as db:
        record_host_outcome(db, context.job_id, host.server_id, outcome, actor, context.clock())
    return _HostRun(host.hostname, outcome.status, outcome.reason)


def _targets(db: Session, rows: Sequence[JobHost], certificate: Certificate) -> tuple[DeployTarget, ...] | None:
    """The host's confirmed targets, or ``None`` when Contract decision 16 blocks the host.

    A binding that is no longer active, belongs to an inactive server, or that discovery found in
    ``key_mismatch``/``missing_file`` is never written to (``binding_blocked``).
    """
    targets: list[DeployTarget] = []
    for row in rows:
        binding = db.get(Binding, row.binding_id) if row.binding_id is not None else None
        if binding is None or not binding.is_active or binding.match_state in {"key_mismatch", "missing_file"}:
            return None
        server = db.get(Server, binding.server_id)
        if server is None or not server.is_active:
            return None
        targets.append(
            DeployTarget(
                binding_id=binding.id,
                cert_path=binding.cert_path,
                chain_path=binding.chain_path,
                key_path=binding.key_path,
                expected_fingerprint=row.old_fingerprint,
                new_fingerprint=row.new_fingerprint or certificate.sha256_fingerprint,
                port=binding.port,
                sni=verify_sni(binding.vhost_name, binding.vhost_names or ()),
            )
        )
    return tuple(targets) or None


def _mark_internal(context: JobContext, host: _Host) -> None:
    """Best-effort: leave no ``running`` row behind when a host task died unexpectedly."""
    outcome = failure("internal")
    try:
        with context.factory.begin() as db:
            now = context.clock()
            rows = db.scalars(
                select(JobHost).where(
                    JobHost.job_id == context.job_id,
                    JobHost.server_id == host.server_id,
                    JobHost.status == JobHostStatus.RUNNING,
                )
            )
            for row in rows:
                row.status = JobHostStatus.FAILED
                row.finished_at = now
                row.error_message = outcome.message
    except Exception as error:  # noqa: BLE001 - the original exception must win
        _LOG.error("could not record the internal failure of %s: %s", host.hostname, type(error).__name__)
