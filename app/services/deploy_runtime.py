"""Worker-side deploy runtime: execution gate, host bookkeeping, timeout and the renewal hook.

Plan 3 Task 16 (Contract decisions 3, 4, 16, 18, 19 and 21). The handler in
``app/jobs/handlers/deploy.py`` drives the rollout; everything that touches the database on the worker
side lives here so the same functions serve Task 17's controls (Continue, Cancel, sweeps) unchanged.

Order of a host run: the handler claims the server's ``pending`` rows (``claim_host_rows``) so a
``pending`` row can never be started twice, then records the playbook outcome (``record_host_outcome``)
in one transaction — the row state of Contract decision 18, the binding's verified state and endpoint
expectation of Contract decision 19, and the rollback audits.

The worker-side endpoint check is informational only: a host is never failed because the worker could not
observe the endpoint it just deployed (§6.4 step 7, A17).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import exists, func, select, update
from sqlalchemy.orm import Session

from app.ansible.deploy import HostOutcome
from app.jobs.queue import SYSTEM_ACTOR, JobFailure, cancel_idle
from app.models import Binding, Certificate, Job, JobHost, JSONValue, PrivateKey, Renewal, Server, User
from app.models.enums import CertificateStatus, ChainStatus, JobHostStatus, JobStatus, JobType, RenewalState
from app.services.audit import Actor, record
from app.services.bindings import audit_binding_state, binding_state, verify_sni
from app.services.deploy import pause_deadline
from app.services.endpoints import expect_for_binding
from app.services.renewals import InvalidTransition, mark_deployed
from app.services.scans import observe_endpoint
from app.services.settings import get_setting
from app.services.trust_anchors import assess_certificate

__all__ = [
    "BINDING_BLOCKED",
    "DEPLOY_TIMEOUT_MARGIN",
    "ExecutionGate",
    "advance_renewal",
    "claim_host_rows",
    "deploy_timeout_seconds",
    "deploy_totals",
    "record_host_outcome",
    "revalidate_for_execution",
    "skip_pending",
    "sweep_deploys",
]

_LOG = logging.getLogger(__name__)

DEPLOY_TIMEOUT_MARGIN = 900
# Contract decision 16's fixed refusal: the certificate is not trusted (anymore) and the planned override
# does not cover the status it has now.
TRUST_CHANGED = "certificate trust changed since the deploy was planned; plan it again"
BINDING_BLOCKED = "a target binding is no longer deployable"
NO_KEY = "the certificate has no stored private key"
# Contract decision 18's skipped reasons; the column holds the reason, there is no separate field.
SKIP_REASONS = frozenset({"locked", "rollout_stopped", "cancelled", "pause_expired", "job_failed", "job_ended"})
# Contract decision 18: a binding in one of these states is never written to.
_BLOCKED_MATCH_STATES = frozenset({"key_mismatch", "missing_file"})
_TOTAL_KEYS = ("succeeded", "failed", "rolled_back", "skipped", "pending")
_ROLLBACK_ACTION = {True: "deploy.rollback", False: "deploy.rollback_failed"}
_VERIFY_STATUS = {"unreachable": "unreachable", "error": "error"}


@dataclass(frozen=True)
class ExecutionGate:
    """What execution-time revalidation hands to the handler: the certificate and its stored key row."""

    certificate: Certificate
    key_row: PrivateKey


def _int_setting(db: Session, key: str, default: int) -> int:
    value = get_setting(db, key)
    return value if type(value) is int else default


def _payload(job: Job) -> dict[str, JSONValue]:
    return dict(job.payload) if isinstance(job.payload, dict) else {}


# --- execution-time revalidation (§5.8, Contract decision 16) ----------------------------------------


def _check_validity(certificate: Certificate, now: datetime) -> None:
    """The certificate must still be active and inside its validity window at execution time."""
    if certificate.status != CertificateStatus.ACTIVE:
        raise JobFailure(
            "config_invalid",
            f"the certificate is {certificate.status.value}; only an active certificate can be deployed",
        )
    if certificate.not_after <= now:
        raise JobFailure("config_invalid", "the certificate expired before the deploy started")
    if certificate.not_before > now:
        raise JobFailure("config_invalid", "the certificate is not valid yet")


def revalidate_for_execution(db: Session, job: Job, now: datetime) -> ExecutionGate:
    """Re-run the trust gate and the guardrails at execution time; raise ``JobFailure`` when they fail.

    ``trusted`` proceeds; a non-trusted status proceeds only with a ``chain_override`` whose
    ``chain_status_at_plan`` equals the status observed *now* — a plan made while trusted, or for another
    non-trusted status, is refused (Contract decision 16). Certificate activity and validity are checked
    unconditionally, and never covered by the override.
    """
    payload = _payload(job)
    certificate_id = payload.get("certificate_id")
    if type(certificate_id) is not int:
        raise JobFailure("config_invalid", "the deploy job does not name a certificate")
    certificate = db.get(Certificate, certificate_id)
    if certificate is None:
        raise JobFailure("config_invalid", "the planned certificate no longer exists")
    status = assess_certificate(db, certificate.id, now).status
    planned_status = payload.get("chain_status_at_plan")
    override = payload.get("chain_override") is True
    if status is not ChainStatus.TRUSTED and not (override and planned_status == status.value):
        raise JobFailure("config_invalid", TRUST_CHANGED)
    _check_validity(certificate, now)
    key_row = db.get(PrivateKey, certificate.key_id) if certificate.key_id is not None else None
    if key_row is None:
        raise JobFailure("key_unwrap", NO_KEY)
    return ExecutionGate(certificate, key_row)


# --- host rows ---------------------------------------------------------------------------------------


def claim_host_rows(db: Session, job_id: UUID, server_id: int, now: datetime) -> list[JobHost]:
    """Move this server's ``pending`` rows to ``running``; an empty list means nothing is left to do.

    The single ``UPDATE … WHERE status = 'pending'`` is the claim (Contract decision 20): a row that was
    cancelled or already claimed in another transaction is never started.
    """
    statement = (
        update(JobHost)
        .where(
            JobHost.job_id == job_id,
            JobHost.server_id == server_id,
            JobHost.status == JobHostStatus.PENDING,
        )
        .values(status=JobHostStatus.RUNNING, started_at=now, finished_at=None)
        .returning(JobHost)
        .execution_options(synchronize_session=False, populate_existing=True)
    )
    return list(db.execute(statement).scalars())


def skip_pending(
    db: Session,
    job_id: UUID,
    reason: str,
    *,
    from_batch: int | None = None,
    server_id: int | None = None,
    now: datetime,
) -> int:
    """Mark the job's ``pending`` rows ``skipped`` with ``reason``; return how many rows were touched.

    ``from_batch`` limits the sweep to that batch and every later one (a stopped rollout), ``server_id``
    to one host (a busy host lock). ``reason`` is a closed Contract decision 18 set, never free text.
    """
    if reason not in SKIP_REASONS:
        raise ValueError(f"unknown skip reason: {reason}")
    statement = update(JobHost).where(JobHost.job_id == job_id, JobHost.status == JobHostStatus.PENDING)
    if from_batch is not None:
        statement = statement.where(JobHost.batch_no >= from_batch)
    if server_id is not None:
        statement = statement.where(JobHost.server_id == server_id)
    statement = (
        statement.values(status=JobHostStatus.SKIPPED, finished_at=now, error_message=reason)
        .execution_options(synchronize_session=False)
    )
    return int(db.execute(statement).rowcount)


def deploy_totals(db: Session, job_id: UUID) -> dict[str, int]:
    """The job's row counters, one key per ``job_host.status`` the deploy report shows."""
    totals: dict[str, int] = {key: 0 for key in _TOTAL_KEYS}
    for status, count in db.execute(
        select(JobHost.status, func.count()).where(JobHost.job_id == job_id).group_by(JobHost.status)
    ):
        name = getattr(status, "value", status)
        if name in totals:
            totals[name] = int(count)
    return totals


def deploy_timeout_seconds(db: Session, job: Job) -> int:
    """Contract decision 21: distinct hosts still to run × host timeout + 900 s.

    Counts the ``pending`` rows of ``batch_no >= job.resume_from_batch``, so a resumed job is timed on what
    is left rather than on the whole rollout. A job with nothing left still gets the 900 s margin (a
    positive timeout is required by ``claim``).
    """
    host_timeout = _int_setting(db, "deploy.host_timeout_seconds", 600)
    remaining = db.scalar(
        select(func.count(func.distinct(JobHost.server_id))).where(
            JobHost.job_id == job.id,
            JobHost.status == JobHostStatus.PENDING,
            JobHost.batch_no >= job.resume_from_batch,
        )
    )
    return int(remaining or 0) * host_timeout + DEPLOY_TIMEOUT_MARGIN


# --- host outcome bookkeeping (§6.4 step 7, Contract decisions 18–19) ---------------------------------


def _observed(db: Session, rows: list[JobHost], timeout_seconds: int) -> dict[int, dict[str, JSONValue]]:
    """The informational endpoint check of Contract decision 19, keyed by binding id. Never raises."""
    observed: dict[int, dict[str, JSONValue]] = {}
    for row in rows:
        binding = db.get(Binding, row.binding_id) if row.binding_id is not None else None
        if binding is None:
            continue
        server = db.get(Server, binding.server_id)
        host = (server.connection_address or server.hostname) if server is not None else None
        if host is None:
            continue
        sni = verify_sni(binding.vhost_name, binding.vhost_names or ())
        expected = row.new_fingerprint
        try:
            observation = observe_endpoint(host, binding.port, sni, timeout_seconds)
        except Exception as error:  # noqa: BLE001 - informational only: never fail the host
            _LOG.warning("worker verify of %s failed: %s", host, type(error).__name__)
            observed[binding.id] = {"status": "error", "fingerprint": None, "matches": False}
            continue
        matches = expected is not None and observation.fingerprint == expected
        status = _VERIFY_STATUS.get(observation.failure or "") or ("ok" if matches else "mismatch")
        observed[binding.id] = {"status": status, "fingerprint": observation.fingerprint, "matches": matches}
    return observed


def _mark_bindings_verified(
    db: Session, rows: list[JobHost], certificate: Certificate, actor: Actor, job_id: UUID, now: datetime
) -> None:
    """Contract decision 19: the binding now carries the deployed material, audited, in this transaction."""
    key_row = db.get(PrivateKey, certificate.key_id) if certificate.key_id is not None else None
    key_sha256 = key_row.public_key_sha256 if key_row is not None else None
    for row in rows:
        binding = db.get(Binding, row.binding_id) if row.binding_id is not None else None
        if binding is None:
            continue
        previous = binding_state(binding)
        binding.on_disk_fingerprint = row.new_fingerprint or certificate.sha256_fingerprint
        binding.on_disk_key_public_sha256 = key_sha256
        binding.certificate_id = certificate.id
        binding.match_state = "matched"
        db.flush()
        audit_binding_state(db, binding, previous, actor, job_id=str(job_id), now=now)
        expect_for_binding(db, binding.id, certificate.id, actor)


def record_host_outcome(
    db: Session,
    job_id: UUID,
    server_id: int,
    outcome: HostOutcome,
    actor: Actor,
    now: datetime,
) -> None:
    """Store one host's run in this transaction: its rows, the binding state and the rollback audit.

    Only rows this attempt claimed (``running``) are written, so a late or duplicated outcome can never
    overwrite a finished host. A successful host also gets its endpoints' expectation updated and the
    worker-side verification recorded under ``precheck.worker_verify``; a rollback — successful or not —
    is audited (Contract decision 18).
    """
    rows = list(
        db.scalars(
            select(JobHost)
            .where(
                JobHost.job_id == job_id,
                JobHost.server_id == server_id,
                JobHost.status == JobHostStatus.RUNNING,
            )
            .order_by(JobHost.binding_id)
            .with_for_update()
        )
    )
    if not rows:
        return
    certificate_id = _deployed_certificate_id(db, job_id)
    certificate = (
        db.get(Certificate, certificate_id)
        if outcome.status == "succeeded" and certificate_id is not None
        else None
    )
    observed = (
        _observed(db, rows, _int_setting(db, "scan.timeout_seconds", 10))
        if certificate is not None
        else {}
    )
    for row in rows:
        row.status = JobHostStatus(outcome.status)
        row.finished_at = now
        row.ansible_return_code = outcome.return_code
        row.log_excerpt = outcome.log_excerpt or None
        row.error_message = outcome.message
        row.rolled_back = outcome.rolled_back
        row.rollback_error = outcome.rollback_error
        precheck = dict(outcome.precheck)
        if row.binding_id is not None and row.binding_id in observed:
            precheck["worker_verify"] = observed[row.binding_id]
        row.precheck = precheck
    if certificate is not None:
        _mark_bindings_verified(db, rows, certificate, actor, job_id, now)
    if outcome.status == "rolled_back" or outcome.rollback_error is not None:
        record(
            db,
            actor,
            _ROLLBACK_ACTION[outcome.rollback_error is None],
            "job",
            str(job_id),
            {
                "server_id": server_id,
                "reason": outcome.reason,
                "rolled_back": outcome.rolled_back,
                "rollback_error": outcome.rollback_error,
            },
        )
    db.flush()


def _deployed_certificate_id(db: Session, job_id: UUID) -> int | None:
    job = db.get(Job, job_id)
    certificate_id = _payload(job).get("certificate_id") if job is not None else None
    return certificate_id if type(certificate_id) is int else None


# --- renewal success hook (Contract decision 3) ------------------------------------------------------


def _requested_actor(db: Session, job: Job) -> Actor:
    if job.requested_by is None:
        return SYSTEM_ACTOR
    user = db.get(User, job.requested_by)
    return Actor(user.id, user.username) if user is not None else SYSTEM_ACTOR


def _renewal_id(db: Session, job: Job) -> UUID | None:
    """``payload.renewal_id``, else the ``issued`` renewal of the deployed certificate."""
    payload = _payload(job)
    raw = payload.get("renewal_id")
    if isinstance(raw, str):
        try:
            return UUID(raw)
        except ValueError:
            return None
    certificate_id = payload.get("certificate_id")
    if type(certificate_id) is not int:
        return None
    return db.scalar(
        select(Renewal.id)
        .where(Renewal.certificate_id == certificate_id, Renewal.state == RenewalState.ISSUED)
        .order_by(Renewal.state_changed_at.desc())
        .limit(1)
    )


def advance_renewal(db: Session, job: Job, now: datetime) -> None:
    """Advance the renewal to ``deployed`` (Contract decision 3); a refusal is audited, never raised.

    ``mark_deployed`` re-reads the evidence itself: the job is ``succeeded`` and at least one succeeded
    binding row carries the new fingerprint. An ``InvalidTransition`` (renewal cancelled meanwhile, no
    evidence) is recorded as ``deploy.renewal_not_advanced`` and never fails the job.
    """
    renewal_id = _renewal_id(db, job)
    if renewal_id is None:
        return
    actor = _requested_actor(db, job)
    try:
        mark_deployed(db, renewal_id, job.id, actor, now)
    except InvalidTransition as error:
        record(
            db,
            actor,
            "deploy.renewal_not_advanced",
            "job",
            str(job.id),
            {"renewal_id": str(renewal_id), "reason": error.reason or error.code},
        )


# --- the deploy sweep (Contract decision 20) ----------------------------------------------------------


def sweep_deploys(db: Session, now: datetime) -> int:
    """The ``deploy_sweep`` tick step: expire paused deploys, then close out terminal ones (§6.5, §7.2).

    A paused deploy whose ``pause_deadline`` has passed is cancelled exactly like an operator cancel, except
    that its remaining rows are ``skipped``/``pause_expired`` and a ``deploy.pause_expired`` audit records the
    pause that was forgotten — the stale authorization must never resume days later against changed hosts.

    A terminal deploy job that still has ``pending`` rows is only possible when something other than the
    handler ended the job (the reaper fails ``running`` rows, never ``pending`` ones); those rows become
    ``skipped``/``job_ended`` so the screen never shows a finished job with work outstanding.

    Returns how many jobs it changed. Both halves lock their rows with ``SKIP LOCKED``, so concurrent
    schedulers never block on each other.
    """
    hours = _int_setting(db, "deploy.pause_timeout_hours", 24)
    changed = 0
    paused = db.scalars(
        select(Job)
        .where(Job.type == JobType.DEPLOY, Job.status == JobStatus.PAUSED)
        .order_by(Job.paused_at, Job.id)
        .with_for_update(skip_locked=True)
        .execution_options(populate_existing=True)
    )
    for job in paused:
        if job.paused_at is None:
            continue
        deadline = pause_deadline(job, hours)
        if deadline > now:
            continue
        skip_pending(db, job.id, "pause_expired", now=now)
        cancel_idle(db, job.id, SYSTEM_ACTOR, now)
        record(
            db,
            SYSTEM_ACTOR,
            "deploy.pause_expired",
            "job",
            str(job.id),
            {"paused_at": job.paused_at.isoformat(), "deadline": deadline.isoformat(), "pause_timeout_hours": hours},
        )
        changed += 1
    db.flush()
    terminal = db.scalars(
        select(Job.id)
        .where(
            Job.type == JobType.DEPLOY,
            Job.status.in_((JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED)),
            exists().where(JobHost.job_id == Job.id, JobHost.status == JobHostStatus.PENDING),
        )
        .order_by(Job.created_at, Job.id)
        .with_for_update(skip_locked=True)
    )
    for job_id in terminal:
        if skip_pending(db, job_id, "job_ended", now=now):
            changed += 1
    db.flush()
    return changed

