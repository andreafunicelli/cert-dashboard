"""Read models for the deploy job screen (spec §8.7; Plan 3 Task 18).

The screen shows what the worker already persisted: this module only reads rows — no Ansible, no git, no SSH.
Its cost is constant however many hosts a rollout has: one query for the job, its certificate and its requester,
one for every ``job_host`` row joined to its server and binding, and the pause timeout setting only while a
job is paused.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Integer, select
from sqlalchemy.orm import Session

from app.models import Binding, Certificate, Job, JobHost, Server, User
from app.models.enums import JobHostStatus, JobStatus, JobType
from app.services.deploy import pause_deadline
from app.services.settings import get_setting

TOTAL_KEYS = ("succeeded", "failed", "rolled_back", "skipped", "pending")

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
    inventory_rev: str | None

    @property
    def hosts(self) -> list[HostView]:
        return [host for batch in self.batches for host in batch]

    @property
    def failure_reason(self) -> str | None:
        """The reason code of the host that stopped the rollout, if it has one."""
        for host in self.hosts:
            if host.hostname == self.first_failed_host:
                return host.reason
        return None

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
    # Contract decision 18 and §9.4: a failed rollback, a host that timed out and a host whose worker was lost
    # all leave files that may be wrong and were never verified, so each one needs a human.
    needs_attention = rollback_error is not None or reason == "worker_lost"
    return HostView(
        server_id=server.id,
        hostname=server.hostname,
        batch_no=first.batch_no,
        status=getattr(status, "value", status),
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


def _view(db: Session, job_id: UUID, now: datetime | None) -> DeployJobView:
    return _snapshot(db, job_id, now)[0]


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
    first_failed, files_restored = _failure(hosts)
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
        inventory_rev=_inventory_rev(job),
    )
    return view, rows


def _failure(hosts: list[HostView]) -> tuple[str | None, bool | None]:
    """The host that stopped the rollout and whether its files were put back (§8.7 failure banner)."""
    for host in hosts:
        if host.status in (JobHostStatus.FAILED.value, JobHostStatus.ROLLED_BACK.value):
            if host.rolled_back and host.rollback_error is None:
                return host.hostname, True
            if host.rollback_error is not None:
                return host.hostname, False
            return host.hostname, None  # preflight failure: nothing was written, nothing to restore
    return None, None


def deploy_job_view(db: Session, job_id: UUID, now: datetime) -> DeployJobView:
    """The screen's view of one deploy job; ``DeployJobNotFound`` for anything that is not a deploy job."""
    return _view(db, job_id, now)


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
