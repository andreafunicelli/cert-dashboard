"""Read models for the deploy job screen (spec §8.7; Plan 3 Task 18).

The screen shows what the worker already persisted: this module only reads rows — no Ansible, no git, no SSH.
Its cost is constant however many hosts a rollout has: one query for the job, its certificate and its requester,
one for every ``job_host`` row joined to its server and binding, and the pause timeout setting only while a
job is paused.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Integer, and_, func, or_, select
from sqlalchemy.orm import Session

from app.jobs.queue import ALLOWED_ERROR_CLASSES, TIMEOUT_MESSAGE
from app.models import Binding, Certificate, Job, JobHost, PrivateKey, Renewal, Server, User
from app.models.enums import CertificateStatus, JobHostStatus, JobStatus, JobType, RenewalState
from app.services.deploy import _EXCLUDED_MATCH_STATES, pause_deadline
from app.services.settings import get_setting

# ``_EXCLUDED_MATCH_STATES`` is the one authoritative definition of "never a deploy target" (Contract
# decision 15): the panel reuses it instead of restating the states, so it cannot drift from the preview.

TOTAL_KEYS = ("succeeded", "failed", "rolled_back", "skipped", "pending")

# How the host that stopped the rollout left its files (§8.7 failure banner). Only a failure the playbook
# raises before the first live write may claim that nothing changed; a lost worker left files that may have
# been changed and were never verified (§9.4), and a failed rollback is never a clean restore.
RESTORED = "restored"
RESTORE_FAILED = "restore_failed"
UNVERIFIED = "unverified"
NOTHING_WRITTEN = "nothing_written"

# Contract decision 18's reasons that a playbook raises before the first live write (preflight, backup, a
# run that never started): the task that raises them runs before ``deploy_step=writing``, so the reason alone
# proves that no live file changed. ``internal`` is deliberately absent: the same reason is also what a
# ``step='verified'`` run whose per-binding evidence disagrees maps to, so only the persisted step tells the
# two apart (see ``_restoration``). Transport failures are absent for the same reason and handled below.
PRE_WRITE_REASONS = frozenset(
    {
        "drift_detected",
        "missing_target",
        "permission_denied",
        "insufficient_space",
        "baseline_config_invalid",
        "key_mismatch_preflight",
        "backup_failed",
        "binding_blocked",
        "not_in_inventory",
        "file_conflict",
    }
)
# An SSH connection can be lost at any step, and the runner replaces a dark host's published data with ``{}``
# (``runner._host_results``), so an ``unreachable``/``auth`` row usually has no step to prove it was pre-write.
# Only a persisted pre-write step may claim that nothing changed (§9.4).
TRANSPORT_REASONS = frozenset({"unreachable", "auth"})

# ``precheck.step`` is the last step the playbook published. ``preflight`` and ``backed_up`` are the only ones
# that prove the run stopped before the first live write; Contract decision 17's ``writing`` … ``reloaded``
# steps and the terminal ``verified``/``rolled_back``/``rollback_failed`` are all past it, and an empty step is
# no evidence at all (a killed worker leaves no excerpt of its run).
PRE_WRITE_STEPS = frozenset({"preflight", "backed_up"})

# Contract decision 18: the handler fails the job with ``rollout stopped: <hostname> failed (<reason>)``.
_STOPPED_MESSAGE = re.compile(r"^rollout stopped: (?P<host>\S+) failed \(")
_NEVER = datetime.max.replace(tzinfo=UTC)

# §8.7's failure banner shows "the reason for stopping". A job-level refusal — the execution-time trust, key
# or inventory gate — stops the deploy before any host row fails, so no ``HostView`` carries a reason and the
# job's own failure is the only persisted evidence (Contract decisions 7 and 16). The banner renders one of
# these fixed texts verbatim and nothing else: an exact allowlist, never a filter, so a free-text message (a
# path, a host's stderr, a future handler's message) cannot reach the screen even when it slipped past
# ``safe_error_message``. Each entry is the literal this codebase writes on ``job.error_message``.
JOB_FAILURE_REASONS = frozenset(
    {
        # execution-time gate (app.services.deploy_runtime, Contract decision 16)
        "the deploy job does not name a certificate",
        "the planned certificate no longer exists",
        "certificate trust changed since the deploy was planned; plan it again",
        "the certificate expired before the deploy started",
        "the certificate is not valid yet",
        "the certificate has no stored private key",
        "the certificate's private key cannot be unwrapped with the configured keyring",
        *(f"the certificate is {status.value}; only an active certificate can be deployed" for status in CertificateStatus),
        # the handler's own pre-run checks (app.jobs.handlers.deploy)
        "the stored certificate cannot be parsed",
        "the certificate and its stored private key do not match",
        "the inventory was not prepared",
        "job not found",
        # the shared Ansible context (app.jobs.handlers.ansible_context, Contract decision 7)
        "inventory repository is not configured",
        "SSH known_hosts file is missing",
        "the worker has no ansible_ssh_key",
        "inventory path is outside the checkout",
        "the job artifact directory is not a plain directory",
        # the worker's own outcomes (app.jobs.worker, app.jobs.queue)
        "invalid job payload",
        "no handler registered for this job",
        "master key unavailable for this record",
        "internal error",
        TIMEOUT_MESSAGE,
    }
)
# What the banner says when the persisted message is not on that allowlist: still that no host stopped the
# rollout, plus the job's error class — a closed, already-sanitized token (§9.1) — never the message itself.
_JOB_FAILURE_FRAME = "No host stopped the rollout: "
_JOB_FAILURE_UNKNOWN = "the job itself failed"


# The JSON report is an allowlist: every ``HostView`` field except the (redacted) log excerpt, whose text stays
# in the database, plus one entry per binding carrying that binding's old and new fingerprint.
REPORT_HOST_FIELDS = frozenset(
    {
        "server_id",
        "hostname",
        "batch_no",
        "status",
        "bindings",
        "old_fingerprint",
        "new_fingerprint",
        "duration_seconds",
        "rolled_back",
        "rollback_error",
        "needs_attention",
        "reason",
        "backup_dir",
        "retryable",
    }
)
REPORT_BINDING_FIELDS = frozenset({"binding_id", "vhost_name", "old_fingerprint", "new_fingerprint"})


class DeployJobNotFound(LookupError):
    """No deploy job has this id: the screen answers 404, and a non-deploy job is not a deploy either."""


@dataclass(frozen=True)
class HostView:
    """One server of the rollout, collapsed from its ``job_host`` rows (one row per binding)."""

    server_id: int
    hostname: str
    batch_no: int
    status: str
    bindings: tuple[str, ...]
    old_fingerprint: str | None
    new_fingerprint: str | None
    duration_seconds: int | None
    rolled_back: bool
    rollback_error: str | None
    needs_attention: bool
    reason: str | None
    log_excerpt: str | None
    backup_dir: str | None
    retryable: bool


@dataclass(frozen=True)
class DeployJobView:
    """Everything the deploy job screen and its JSON report show about one job."""

    job_id: UUID
    status: str
    phase: str
    certificate_id: int
    certificate_cn: str
    actor: str
    started_at: datetime | None
    elapsed_seconds: int | None
    totals: dict[str, int]
    batches: list[list[HostView]]
    paused_at: datetime | None
    pause_deadline: datetime | None
    first_failed_host: str | None
    files_restored: bool | None
    job_failure_reason: str | None
    inventory_rev: str | None

    @property
    def hosts(self) -> list[HostView]:
        return [host for batch in self.batches for host in batch]

    @property
    def stopping_host(self) -> HostView | None:
        """The host the failure banner is about: the one that stopped the rollout."""
        return next((host for host in self.hosts if host.hostname == self.first_failed_host), None)

    @property
    def failure_reason(self) -> str | None:
        """The reason code of the host that stopped the rollout, if it has one."""
        host = self.stopping_host
        return host.reason if host is not None else None

    @property
    def failure_restoration(self) -> str | None:
        """How the stopping host's files stand: restored, not restored, or never verified (§8.7)."""
        host = self.stopping_host
        return None if host is None else _state(host)

    @property
    def polling(self) -> bool:
        """Only a job that is still moving is polled; a paused or finished job holds still."""
        return self.status in (JobStatus.QUEUED.value, JobStatus.RUNNING.value)

    @property
    def cancellable(self) -> bool:
        return self.status in (JobStatus.QUEUED.value, JobStatus.RUNNING.value, JobStatus.PAUSED.value)


def _job_row(db: Session, job_id: UUID) -> tuple[Job, Certificate | None, str | None]:
    """The job, its certificate (the id lives in the payload) and its requester, in one query."""
    certificate_id = Job.payload.op("->>")("certificate_id").cast(Integer)
    row = db.execute(
        select(Job, Certificate, User.username)
        .outerjoin(Certificate, Certificate.id == certificate_id)
        .outerjoin(User, User.id == Job.requested_by)
        .where(Job.id == job_id)
    ).first()
    if row is None:
        raise DeployJobNotFound(f"job {job_id} does not exist")
    job, certificate, requester = row
    if JobType(job.type) is not JobType.DEPLOY:
        raise DeployJobNotFound(f"job {job_id} is a {JobType(job.type).value} job, not a deploy")
    return job, certificate, requester


def _rows(db: Session, job_id: UUID) -> list[tuple[JobHost, Server, Binding | None]]:
    """Every host row of the job with its server and binding, in plan order."""
    statement = (
        select(JobHost, Server, Binding)
        .join(Server, Server.id == JobHost.server_id)
        .outerjoin(Binding, Binding.id == JobHost.binding_id)
        .where(JobHost.job_id == job_id)
        .order_by(JobHost.batch_no, Server.hostname, Binding.vhost_name)
    )
    return list(db.execute(statement))


def _reason(row: JobHost) -> str | None:
    """The §4 reason code of a row: ``error_message`` is ``"<reason>: <fixed text>"``."""
    if not row.error_message:
        return None
    return row.error_message.split(": ", 1)[0][:60]


def _worst(statuses: set[JobHostStatus]) -> JobHostStatus:
    """A host whose bindings disagree shows its most severe state."""
    for candidate in (
        JobHostStatus.FAILED,
        JobHostStatus.ROLLED_BACK,
        JobHostStatus.RUNNING,
        JobHostStatus.PENDING,
        JobHostStatus.SKIPPED,
        JobHostStatus.SUCCEEDED,
    ):
        if candidate in statuses:
            return candidate
    return JobHostStatus.PENDING


def _host_view(server: Server, rows: list[tuple[JobHost, Binding | None]], *, terminal: bool) -> HostView:
    first = rows[0][0]
    statuses = {JobHostStatus(row.status) for row, _binding in rows}
    status = first.status if len(statuses) == 1 else _worst(statuses)
    fingerprints = {row.old_fingerprint for row, _binding in rows}
    started = [row.started_at for row, _binding in rows if row.started_at is not None]
    finished = [row.finished_at for row, _binding in rows if row.finished_at is not None]
    precheck_backup = next(
        (
            row.precheck.get("backup_dir")
            for row, _binding in rows
            if isinstance(row.precheck, dict) and isinstance(row.precheck.get("backup_dir"), str)
        ),
        None,
    )
    rollback_error = next((row.rollback_error for row, _binding in rows if row.rollback_error), None)
    reason = next((reason for row, _binding in rows if (reason := _reason(row))), None)
    status_value = getattr(status, "value", status)
    # Contract decision 18 and §9.4: a failed rollback and a host whose files may have changed without
    # verification (worker_lost, a timed-out run, an `internal` run past the first write, an SSH failure with
    # no persisted pre-write step) each need a human; only a proven pre-write failure does not.
    state = _restoration(
        status_value,
        any(row.rolled_back for row, _binding in rows),
        rollback_error,
        reason,
        _write_started(rows),
    )
    needs_attention = state in (RESTORE_FAILED, UNVERIFIED)
    return HostView(
        server_id=server.id,
        hostname=server.hostname,
        batch_no=first.batch_no,
        status=status_value,
        bindings=tuple(binding.vhost_name for _row, binding in rows if binding is not None),
        old_fingerprint=next(iter(fingerprints)) if len(fingerprints) == 1 else None,
        new_fingerprint=first.new_fingerprint,
        duration_seconds=int((max(finished) - min(started)).total_seconds()) if started and finished else None,
        rolled_back=any(row.rolled_back for row, _binding in rows),
        rollback_error=rollback_error,
        needs_attention=needs_attention,
        reason=reason,
        log_excerpt=next((row.log_excerpt for row, _binding in rows if row.log_excerpt), None),
        backup_dir=precheck_backup,
        # Contract decision 20: a failed, rolled back or skipped host of a finished job can be retried as a
        # new job; nothing else can.
        retryable=terminal and getattr(status, "value", status) in ("failed", "rolled_back", "skipped"),
    )


def _phase(job: Job, hosts: list[HostView], status: JobStatus) -> str:
    """The rollout phase label of §8.7: ``canary``, ``batch 2/3``, ``paused``, ``stopped``, ``done``, ``cancelled``."""
    if status is JobStatus.PAUSED:
        return "paused"
    if status is JobStatus.CANCELLED:
        return "cancelled"
    if status is JobStatus.FAILED:
        return "stopped"
    if status is JobStatus.SUCCEEDED:
        return "done"
    if status is not JobStatus.RUNNING:
        return status.value
    current = _current_batch(hosts, job.resume_from_batch)
    total = max((host.batch_no for host in hosts), default=0) + 1
    if current == 0:
        return "canary"
    return f"batch {current + 1}/{total}"


def _current_batch(hosts: list[HostView], resume_from_batch: int) -> int:
    """The batch the rollout is on: the running one, else the next one still pending, else the last one."""
    running = [host.batch_no for host in hosts if host.status == JobHostStatus.RUNNING.value]
    if running:
        return min(running)
    pending = [host.batch_no for host in hosts if host.status == JobHostStatus.PENDING.value]
    if pending:
        return min(pending)
    return max(resume_from_batch, max((host.batch_no for host in hosts), default=0))


def _totals(hosts: list[HostView]) -> dict[str, int]:
    """Host counters; a host that is still running is not finished yet, so it counts as pending."""
    totals: dict[str, int] = {key: 0 for key in TOTAL_KEYS}
    for host in hosts:
        key = "pending" if host.status == JobHostStatus.RUNNING.value else host.status
        if key in totals:
            totals[key] += 1
    return totals


def _inventory_rev(job: Job) -> str | None:
    """Contract decision 5: every discover and deploy result carries the inventory revision it ran on."""
    if isinstance(job.result, dict) and isinstance(job.result.get("inventory_rev"), str):
        return job.result["inventory_rev"]
    return None


def _write_started(rows: list[tuple[JobHost, Binding | None]]) -> bool | None:
    """Whether the host's run reached the first live write, from the step it persisted.

    ``None`` means no step is readable at all (a worker that died before recording its run, or a dark host
    whose published data the runner discarded and whose row therefore carries ``step: ""``); callers must
    treat that as unknown, never as proof that nothing changed.
    """
    steps = [row.precheck.get("step") for row, _binding in rows if isinstance(row.precheck, dict)]
    known = [step for step in steps if isinstance(step, str) and step]
    if not known:
        return None
    return any(step not in PRE_WRITE_STEPS for step in known)


def _restoration(
    status: str,
    rolled_back: bool,
    rollback_error: str | None,
    reason: str | None,
    write_started: bool | None,
) -> str | None:
    """How one host's files stand after it stopped the rollout; ``None`` for a host that did not fail."""
    if status not in (JobHostStatus.FAILED.value, JobHostStatus.ROLLED_BACK.value):
        return None
    if rollback_error is not None:
        return RESTORE_FAILED  # §9.4: the restore itself failed, so the host needs a human
    if rolled_back:
        return RESTORED
    if reason in TRANSPORT_REASONS:
        # SSH can be lost before or after the first write and a dark host publishes no step, so only a
        # persisted pre-write step proves nothing changed; anything else fails closed to manual attention.
        return NOTHING_WRITTEN if write_started is False else UNVERIFIED
    if reason in PRE_WRITE_REASONS:
        return NOTHING_WRITTEN
    if reason == "internal" and write_started is False:
        # Only a run that published a pre-write step proves nothing changed. No persisted step, or a step at
        # or past the first write, fails closed to manual attention (§9.4).
        return NOTHING_WRITTEN
    return UNVERIFIED  # e.g. worker_lost: the files may have changed and were never verified


def _state(host: HostView) -> str:
    """The same four-way classification for a host already collapsed into a ``HostView`` (banner and report)."""
    if host.rollback_error is not None:
        return RESTORE_FAILED
    if host.rolled_back:
        return RESTORED
    return UNVERIFIED if host.needs_attention else NOTHING_WRITTEN


def _job_failure_reason(job: Job) -> str:
    """The safe reason of a rollout that no host stopped (§8.7), from the job's own persisted failure.

    Only a message that is exactly one of ``JOB_FAILURE_REASONS`` is rendered; anything else — a free-text
    message, a known text with something appended, a message a future handler writes — becomes the
    class-only fallback. The screen therefore never echoes a message it does not know.
    """
    message = job.error_message if isinstance(job.error_message, str) else None
    if message in JOB_FAILURE_REASONS:
        return f"{_JOB_FAILURE_FRAME}{message.rstrip('.')}."
    error_class = job.error_class if job.error_class in ALLOWED_ERROR_CLASSES else None
    return f"{_JOB_FAILURE_FRAME}{_JOB_FAILURE_UNKNOWN}" + (f" ({error_class})." if error_class else ".")


def _stopper(job: Job, hosts: list[HostView], rows: list[tuple[JobHost, Server, Binding | None]]) -> HostView | None:
    """The host that stopped the rollout: the one the handler named, else the failure that completed first.

    The batch runs with ``deploy.concurrency`` threads, so the first failed host in hostname order is not
    necessarily the one that stopped the rollout. The handler persists the stopper in the job's failure
    message (Contract decision 18); a job without that evidence falls back to the completion chronology.
    """
    candidates = [host for host in hosts if host.status in (JobHostStatus.FAILED.value, JobHostStatus.ROLLED_BACK.value)]
    if not candidates:
        return None
    message = job.error_message if isinstance(job.error_message, str) else ""
    match = _STOPPED_MESSAGE.match(message)
    if match is not None:
        for host in candidates:
            if host.hostname == match.group("host"):
                return host
    finished: dict[str, datetime] = {}
    for row, server, _binding in rows:
        seen = finished.get(server.hostname)
        if row.finished_at is not None and (seen is None or row.finished_at < seen):
            finished[server.hostname] = row.finished_at
    return min(candidates, key=lambda host: (finished.get(host.hostname, _NEVER), host.batch_no, host.hostname))


def _snapshot(
    db: Session, job_id: UUID, now: datetime | None
) -> tuple[DeployJobView, list[tuple[JobHost, Server, Binding | None]]]:
    """The view and the raw rows it was built from (the report needs each binding's own fingerprints)."""
    job, certificate, requester = _job_row(db, job_id)
    rows = _rows(db, job_id)
    grouped: dict[int, list[tuple[JobHost, Binding | None]]] = {}
    servers: dict[int, Server] = {}
    for row, server, binding in rows:
        servers[server.id] = server
        grouped.setdefault(server.id, []).append((row, binding))
    status = JobStatus(job.status)
    terminal = status in (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED)
    hosts = sorted(
        (_host_view(servers[server_id], host_rows, terminal=terminal) for server_id, host_rows in grouped.items()),
        key=lambda host: (host.batch_no, host.hostname),
    )
    batches: list[list[HostView]] = []
    for host in hosts:
        if not batches or batches[-1][0].batch_no != host.batch_no:
            batches.append([])
        batches[-1].append(host)
    starts = [row.started_at for row, _server, _binding in rows if row.started_at is not None]
    started_at = min(starts) if starts else None
    elapsed = None
    if now is not None and started_at is not None:
        end = job.finished_at or job.paused_at or now
        elapsed = max(0, int((end - started_at).total_seconds()))
    deadline = None
    if status is JobStatus.PAUSED:
        hours = get_setting(db, "deploy.pause_timeout_hours")
        deadline = pause_deadline(job, hours if type(hours) is int else 24)
    payload = job.payload if isinstance(job.payload, dict) else {}
    certificate_id = payload.get("certificate_id")
    stopper = _stopper(job, hosts, rows)
    first_failed = stopper.hostname if stopper is not None else None
    restoration = None if stopper is None else _state(stopper)
    files_restored = True if restoration == RESTORED else False if restoration == RESTORE_FAILED else None
    # Only a failed job with no stopping host falls back to its own failure: when a host did stop the
    # rollout the banner names that host and its restoration instead (§8.7).
    job_failure_reason = _job_failure_reason(job) if status is JobStatus.FAILED and stopper is None else None
    view = DeployJobView(
        job_id=job.id,
        status=status.value,
        phase=_phase(job, hosts, status),
        certificate_id=certificate_id if type(certificate_id) is int else 0,
        certificate_cn=certificate.common_name if certificate is not None else "—",
        actor=requester or "system",
        started_at=started_at,
        elapsed_seconds=elapsed,
        totals=_totals(hosts),
        batches=batches,
        paused_at=job.paused_at,
        pause_deadline=deadline,
        first_failed_host=first_failed,
        files_restored=files_restored,
        job_failure_reason=job_failure_reason,
        inventory_rev=_inventory_rev(job),
    )
    return view, rows


def deploy_job_view(db: Session, job_id: UUID, now: datetime) -> DeployJobView:
    """The screen's view of one deploy job; ``DeployJobNotFound`` for anything that is not a deploy job."""
    return _snapshot(db, job_id, now)[0]


def deploy_report(db: Session, job_id: UUID) -> dict[str, Any]:
    """The allowlisted per-host JSON report: ``HostView`` minus the log excerpt, one entry per binding."""
    view, rows = _snapshot(db, job_id, None)
    bindings: dict[int, list[dict[str, Any]]] = {}
    for row, _server, binding in rows:
        bindings.setdefault(row.server_id, []).append(
            {
                "binding_id": row.binding_id,
                "vhost_name": binding.vhost_name if binding is not None else None,
                "old_fingerprint": row.old_fingerprint,
                "new_fingerprint": row.new_fingerprint,
            }
        )
    hosts = [
        {
            "server_id": host.server_id,
            "hostname": host.hostname,
            "batch_no": host.batch_no,
            "status": host.status,
            "bindings": bindings.get(host.server_id, []),
            "old_fingerprint": host.old_fingerprint,
            "new_fingerprint": host.new_fingerprint,
            "duration_seconds": host.duration_seconds,
            "rolled_back": host.rolled_back,
            "rollback_error": host.rollback_error,
            "needs_attention": host.needs_attention,
            "reason": host.reason,
            "backup_dir": host.backup_dir,
            "retryable": host.retryable,
        }
        for host in view.hosts
    ]
    return {
        "job_id": str(view.job_id),
        "status": view.status,
        "phase": view.phase,
        "certificate_id": view.certificate_id,
        "certificate_cn": view.certificate_cn,
        "actor": view.actor,
        "started_at": view.started_at.isoformat() if view.started_at is not None else None,
        "totals": view.totals,
        "paused_at": view.paused_at.isoformat() if view.paused_at is not None else None,
        "first_failed_host": view.first_failed_host,
        "files_restored": view.files_restored,
        "inventory_rev": view.inventory_rev,
        "hosts": hosts,
    }


# --- the start screen and the certificate deploy panel (§8.7, §6.6, §8.4; Plan 3 Task 19) --------
#
# Read models only: the certificate picker, the recent-deploy lists and the panel's guardrail display.
# The authoritative gate stays ``app.services.deploy.start_deploy``; the codes here are the same closed set,
# rendered for the operator so the panel and the start screen never disagree about *why* a deploy is refused.

ACTIVE_DEPLOY_STATUSES = (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.PAUSED)
CANDIDATE_LIMIT = 50
RECENT_DEPLOY_LIMIT = 20
PANEL_DEPLOY_LIMIT = 5


@dataclass(frozen=True)
class DeployCandidate:
    """One certificate the start screen offers: an issued renewal first, else an active keyed certificate."""

    certificate_id: int
    common_name: str
    not_after: datetime
    renewal_id: UUID | None
    chain_status: str


@dataclass(frozen=True)
class DeployJobSummary:
    """One deploy job as a list or a panel shows it: its target, where it stands and its host totals."""

    job_id: UUID
    certificate_id: int | None
    certificate_cn: str
    status: str
    created_at: datetime
    finished_at: datetime | None
    totals: dict[str, int]


@dataclass(frozen=True)
class CertificateDeployPanel:
    """§8.4's deploy panel: the newest deploys of one certificate, the active deploy and the guardrails."""

    certificate_id: int
    jobs: tuple[DeployJobSummary, ...]
    active: DeployJobSummary | None
    blocked: dict[str, str]


def _payload_certificate_id():
    """The certificate id a deploy payload carries (Contract decision 15), as an integer expression."""
    return Job.payload.op("->>")("certificate_id").cast(Integer)


def _issued_renewal_id():
    """The newest ``issued`` renewal that produced this certificate, if any."""
    return (
        select(Renewal.id)
        .where(Renewal.certificate_id == Certificate.id, Renewal.state == RenewalState.ISSUED)
        .order_by(Renewal.state_changed_at.desc(), Renewal.id.desc())
        .limit(1)
        .scalar_subquery()
    )


def deploy_candidates(db: Session, now: datetime, limit: int = CANDIDATE_LIMIT) -> list[DeployCandidate]:
    """The certificate picker: issued renewals first, then active keyed certificates, expiring ones first."""
    renewal_id = _issued_renewal_id()
    rows = db.execute(
        select(Certificate, renewal_id.label("renewal_id"))
        .where(
            or_(
                renewal_id.is_not(None),
                and_(Certificate.status == CertificateStatus.ACTIVE, Certificate.key_id.is_not(None)),
            )
        )
        .order_by(
            renewal_id.is_(None),  # an issued renewal is what the operator is here for
            Certificate.not_after <= now,  # then the certificates that are still valid
            Certificate.not_after,
            Certificate.id,
        )
        .limit(limit)
    ).all()
    return [
        DeployCandidate(
            certificate_id=certificate.id,
            common_name=certificate.common_name,
            not_after=certificate.not_after,
            renewal_id=renewal,
            chain_status=certificate.chain_status.value,
        )
        for certificate, renewal in rows
    ]


def _host_totals(db: Session, job_ids: Sequence[UUID]) -> dict[UUID, dict[str, int]]:
    """One grouped query for the host totals of every listed job (constant cost, whatever the host count)."""
    totals: dict[UUID, dict[str, int]] = {job_id: {key: 0 for key in TOTAL_KEYS} for job_id in job_ids}
    if not job_ids:
        return totals
    rows = db.execute(
        select(JobHost.job_id, JobHost.status, func.count())
        .where(JobHost.job_id.in_(tuple(job_ids)))
        .group_by(JobHost.job_id, JobHost.status)
    ).all()
    for job_id, status, count in rows:
        key = getattr(status, "value", status)
        if key in totals[job_id]:
            totals[job_id][key] = int(count)
    return totals


def _summaries(db: Session, condition, limit: int) -> tuple[DeployJobSummary, ...]:
    """Deploy jobs newest first, each with its certificate and its host totals, in two queries."""
    statement = (
        select(Job, Certificate)
        .outerjoin(Certificate, Certificate.id == _payload_certificate_id())
        .where(Job.type == JobType.DEPLOY)
    )
    if condition is not None:
        statement = statement.where(condition)
    rows = db.execute(
        statement.order_by(Job.created_at.desc(), Job.id.desc()).limit(limit)
    ).all()
    totals = _host_totals(db, [job.id for job, _certificate in rows])
    return tuple(
        DeployJobSummary(
            job_id=job.id,
            certificate_id=certificate.id if certificate is not None else None,
            certificate_cn=certificate.common_name if certificate is not None else "—",
            status=JobStatus(job.status).value,
            created_at=job.created_at,
            finished_at=job.finished_at,
            totals=totals[job.id],
        )
        for job, certificate in rows
    )


def recent_deploys(db: Session, limit: int = RECENT_DEPLOY_LIMIT) -> list[DeployJobSummary]:
    """The newest deploy jobs, whatever their status (the Deploy screen's history)."""
    return list(_summaries(db, None, limit))


def active_deploy(db: Session) -> DeployJobSummary | None:
    """The one deploy that holds the window (queued, running or paused), or ``None`` (Contract decision 15)."""
    jobs = _summaries(db, Job.status.in_(ACTIVE_DEPLOY_STATUSES), 1)
    return jobs[0] if jobs else None


def _target_bindings(db: Session, certificate: Certificate) -> tuple[list[Binding], set[str]]:
    """The bindings a default deploy of ``certificate`` would target, plus the states that kept others out.

    ``key_mismatch`` and ``missing_file`` bindings are excluded from every plan (Contract decision 15), so
    the panel must not count them as targets: counting them would either claim ``already_deployed`` or hide
    the ``no_targets`` refusal the authoritative preview raises. Their states are returned so the panel can
    keep the reason visible.
    """
    owned = [certificate.id] + ([certificate.renews_id] if certificate.renews_id is not None else [])
    rows = list(
        db.scalars(
            select(Binding)
            .join(Server, Server.id == Binding.server_id)
            .where(
                Binding.is_active.is_(True),
                Server.is_active.is_(True),
                Binding.certificate_id.in_(owned),
            )
        )
    )
    targets = [binding for binding in rows if binding.match_state not in _EXCLUDED_MATCH_STATES]
    excluded = {binding.match_state for binding in rows if binding.match_state in _EXCLUDED_MATCH_STATES}
    return targets, excluded


def _panel_blocked(
    db: Session, certificate: Certificate, now: datetime, active: DeployJobSummary | None
) -> dict[str, str]:
    """The guardrails of §8.7 for one certificate, as the panel explains them before the operator clicks."""
    blocked: dict[str, str] = {}
    key_row = db.get(PrivateKey, certificate.key_id) if certificate.key_id is not None else None
    if key_row is None:
        blocked["no_key"] = "the certificate has no stored private key; import or renew it before deploying"
    if certificate.not_after <= now:
        blocked["expired"] = f"the certificate expired on {certificate.not_after.isoformat()}"
    elif certificate.not_before > now:
        blocked["not_yet_valid"] = f"the certificate is not valid before {certificate.not_before.isoformat()}"
    if certificate.status != CertificateStatus.ACTIVE:
        blocked[certificate.status.value] = (
            f"the certificate is {certificate.status.value}; only an active certificate can be deployed"
        )
    targets, excluded_states = _target_bindings(db, certificate)
    if not targets:
        reason = "no active binding is a deploy target for this certificate"
        if excluded_states:
            reason += (
                f" ({', '.join(sorted(excluded_states))} bindings are excluded from every plan)"
            )
        blocked["no_targets"] = reason
    elif all(binding.on_disk_fingerprint == certificate.sha256_fingerprint for binding in targets):
        blocked["already_deployed"] = (
            "every target binding already has the new certificate on disk; there is nothing to deploy"
        )
    if active is not None:
        blocked["active_deploy"] = f"deploy job {active.job_id} is {active.status}"
    return blocked


def certificate_deploy_panel(db: Session, certificate_id: int, now: datetime) -> CertificateDeployPanel:
    """§8.4's deploy panel for one certificate: its newest deploys, the active deploy and the guardrails."""
    certificate = db.get(Certificate, certificate_id)
    if certificate is None:
        raise DeployJobNotFound(f"certificate {certificate_id} does not exist")
    active = active_deploy(db)
    return CertificateDeployPanel(
        certificate_id=certificate_id,
        jobs=_summaries(db, _payload_certificate_id() == certificate_id, PANEL_DEPLOY_LIMIT),
        active=active,
        blocked=_panel_blocked(db, certificate, now, active),
    )
