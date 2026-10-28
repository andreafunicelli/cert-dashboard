"""Worker handler for ``discover/default`` (Plan 3 Contract decision 12, spec 6.2, 6.3, 6.7, 7.1, 9.5).

Order of work: inventory preparation (``ansible_job``: locks, pull, staged secrets) -> ``ansible-inventory
--list`` -> ``sync_inventory_servers`` (one transaction, always the *whole* inventory, so a narrow scope never
deactivates a server) -> scope -> one ``job_host`` row per target (``running``) -> ``discover_hosts`` (the only
step that touches the targets, read-only) -> one transaction per host (``reconcile_host`` or
``record_host_failure`` plus the row) -> one ``discovery.run`` audit per attempt -> the result, or a retryable
``transient_network`` failure for hosts that were unreachable.

Attempts: unreachable hosts are retried alone (3 attempts, 30/120 s): the retry discovers only the hosts whose
row in *this job* is still ``unreachable``. Authentication failures are never retried. Every host is committed
before the retryable failure is raised, so a retry never repeats work that succeeded.

Names: ``--limit`` is built by ``discover_hosts`` from validated inventory hostnames joined with ``:``. A payload
only *selects* inventory hosts (by exact name or group membership), so a name can never become a pattern.
"""

import logging
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ansible.discovery import HostDiscovery, discover_hosts
from app.ansible.runner import build_env
from app.jobs.handlers.ansible_context import AnsibleJob, LockBusy, ansible_job
from app.jobs.queue import RETRY_POLICY, SYSTEM_ACTOR, JobFailure, JobRequeued, enqueue
from app.jobs.worker import JobContext
from app.models import AuditLog, Job, JobHost, JSONValue, Server, User
from app.models.enums import JobHostStatus, JobType
from app.services.audit import Actor, record, redact
from app.services.discovery import (
    ReconcileOutcome,
    reconcile_host,
    record_host_failure,
    sync_inventory_servers,
)
from app.services.inventory import InventoryHost, inventory_source, list_inventory, revision_result

__all__ = ["ON_DEMAND_PRIORITY", "discover", "request_discovery", "validate_discover_payload"]

_LOG = logging.getLogger(__name__)

ON_DEMAND_PRIORITY = 200
MAX_HOSTS = 500
MAX_GROUPS = 50
LOCK_RETRY_DELAY = timedelta(seconds=30)
RUN_ACTION = "discovery.run"

_NAME = re.compile(r"[A-Za-z0-9_.-]{1,253}")
_KEYS = frozenset({"hosts", "groups"})
_EXCERPT_LIMIT = 4000

# Fixed texts: nothing a host said (stderr, paths, configuration) enters a row's ``error_message``.
_UNREACHABLE = "unreachable"
_AUTH = "auth"
_PREFIX = {name: f"{name}: " for name in (_UNREACHABLE, _AUTH)}
_UNREACHABLE_TEXT = "the host could not be reached over SSH"
_AUTH_TEXT = "SSH authentication or host key verification failed; check the deploy key and the known_hosts file"
_APPLY_FAILED = "the discovery document could not be applied"
_ABORTED = "internal: the discovery run did not finish"
_NO_TARGET = "none of the requested hosts or groups is in the inventory"
_COUNTERS = (
    "bindings_added",
    "bindings_updated",
    "bindings_deactivated",
    "endpoints_created",
    "servers_created",
    "servers_deactivated",
)


# --- payload and on-demand request ----------------------------------------------------------------


def _names(value: object, limit: int) -> list[JSONValue]:
    if not isinstance(value, list) or not 1 <= len(value) <= limit:
        raise ValueError(f"expected 1-{limit} names")
    for name in value:
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name.startswith("-") or name in {".", ".."}:
            raise ValueError("invalid name")
    if len(set(value)) != len(value):
        raise ValueError("duplicate names")
    return list(value)


def validate_discover_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Accept ``{}`` (whole inventory), ``{"hosts": [...]}`` (1-500) or ``{"groups": [...]}`` (1-50).

    Names are unique and match ``[A-Za-z0-9_.-]{1,253}`` without a leading ``-``: no Ansible pattern syntax
    (``* ! & : ,`` or spaces) can pass. Anything else, including ``action``, raises ``ValueError``.
    """
    if not isinstance(payload, Mapping) or not set(payload) <= _KEYS or len(payload) > 1:
        raise ValueError("a discovery targets hosts or groups, not both, and takes no other key")
    if "hosts" in payload:
        return {"hosts": _names(payload["hosts"], MAX_HOSTS)}
    if "groups" in payload:
        return {"groups": _names(payload["groups"], MAX_GROUPS)}
    return {}


def request_discovery(db: Session, payload: Mapping[str, JSONValue], actor: Actor, now: datetime) -> Job:
    """Validate and enqueue an on-demand ``discover/default`` job; the web process never runs Ansible."""
    return enqueue(
        db,
        JobType.DISCOVER,
        validate_discover_payload(payload),
        actor,
        priority=ON_DEMAND_PRIORITY,
        run_after=now,
        max_attempts=RETRY_POLICY[JobType.DISCOVER].max_attempts,
    )


# --- the handler ------------------------------------------------------------------------------------


def discover(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
    try:
        with ansible_job(context) as job:
            return _discover(context, payload, job)
    except LockBusy:
        # A reset of the inventory checkout is in progress. Nothing ran, so the claim is simply handed back.
        raise JobRequeued(context.clock() + LOCK_RETRY_DELAY) from None


def _discover(context: JobContext, payload: Mapping[str, JSONValue], job: AnsibleJob) -> Mapping[str, JSONValue]:
    if job.revision is None or job.config is None or job.inventory_path is None:
        raise JobFailure("internal", "the inventory was not prepared")
    with context.factory() as db:
        row = db.get(Job, context.job_id)
        if row is None:  # pragma: no cover - the worker claimed this row
            raise JobFailure("internal", "job not found")
        attempt, max_attempts = row.attempt, row.max_attempts
        user = db.get(User, row.requested_by) if row.requested_by is not None else None
        actor = Actor(user.id, user.username) if user is not None else SYSTEM_ACTOR
        source = "scheduled" if row.requested_by is None else "manual"
        has_rows = bool(db.scalar(select(func.count()).select_from(JobHost).where(JobHost.job_id == context.job_id)))

    inventory = list_inventory(
        job.inventory_path,
        webserver_var=job.config.webserver_var,
        env=build_env(job.runner.secrets, job.runner.run_dir),
    )
    with context.factory.begin() as db:
        sync = sync_inventory_servers(db, inventory, inventory_source(job.config, job.revision.rev), actor, context.clock())

    retrying = attempt > 1 and has_rows
    targets = _scope(context, payload, inventory, retry_only=retrying)
    counts = dict.fromkeys(_COUNTERS, 0)
    counts["servers_created"], counts["servers_deactivated"] = sync.created, sync.deactivated
    if targets:
        _start_rows(context, [sync.server_ids[host.hostname] for host in targets])
        outcomes = _run(context, job, targets)
        for host in targets:
            result = _record_host(context, actor, host.hostname, sync.server_ids[host.hostname], outcomes[host.hostname])
            if result is not None:
                counts["bindings_added"] += result.added
                counts["bindings_updated"] += result.updated
                counts["bindings_deactivated"] += result.deactivated
                counts["endpoints_created"] += result.endpoints_created

    with context.factory.begin() as db:
        summary = _summary(db, context.job_id)
        detail: dict[str, JSONValue] = {"source": source, "attempt": attempt, "hosts": len(targets), **counts}
        detail.update(_this_attempt(summary, [host.hostname for host in targets]))
        record(db, actor, RUN_ACTION, "job", str(context.job_id), detail)
        db.flush()
        totals = _totals(db, context.job_id, summary)
    if summary.unreachable and attempt < max_attempts:
        raise JobFailure(
            "transient_network", f"{summary.unreachable} of {summary.total} hosts unreachable; retrying them", retryable=True
        )
    if summary.total and not summary.ok:
        if summary.auth:
            raise JobFailure("auth", f"{_AUTH_TEXT} ({summary.auth} of {summary.total} hosts)")
        raise JobFailure("transient_network", f"no host could be discovered ({summary.total} failed)")
    return {**revision_result(job.revision), **totals}


# --- scope and rows ---------------------------------------------------------------------------------


def _scope(
    context: JobContext, payload: Mapping[str, JSONValue], inventory: Sequence[InventoryHost], *, retry_only: bool
) -> list[InventoryHost]:
    """Inventory hosts to discover, in inventory order; on a retry only this job's still-unreachable rows."""
    usable = [host for host in inventory if _NAME.fullmatch(host.hostname) and host.hostname not in {".", ".."}]
    if retry_only:
        with context.factory() as db:
            wanted = set(
                db.scalars(
                    select(Server.hostname)
                    .join(JobHost, JobHost.server_id == Server.id)
                    .where(
                        JobHost.job_id == context.job_id,
                        JobHost.binding_id.is_(None),
                        JobHost.status == JobHostStatus.FAILED,
                        JobHost.error_message.startswith(_PREFIX[_UNREACHABLE], autoescape=True),
                    )
                )
            )
        return [host for host in usable if host.hostname in wanted]
    if "hosts" in payload:
        names = set(payload["hosts"])  # type: ignore[arg-type]
        selected = [host for host in usable if host.hostname in names]
    elif "groups" in payload:
        groups = set(payload["groups"])  # type: ignore[arg-type]
        selected = [host for host in usable if groups & set(host.groups)]
    else:
        return usable
    if not selected:
        raise JobFailure("config_invalid", _NO_TARGET)
    return selected


def _row(db: Session, job_id: UUID, server_id: int) -> JobHost:
    row = db.scalars(
        select(JobHost).where(JobHost.job_id == job_id, JobHost.server_id == server_id, JobHost.binding_id.is_(None))
    ).first()
    if row is None:
        row = JobHost(job_id=job_id, server_id=server_id, binding_id=None)
        db.add(row)
    return row


def _start_rows(context: JobContext, server_ids: Sequence[int]) -> None:
    with context.factory.begin() as db:
        now = context.clock()
        for server_id in server_ids:
            row = _row(db, context.job_id, server_id)
            row.status = JobHostStatus.RUNNING
            row.started_at, row.finished_at = now, None
            row.error_message = row.log_excerpt = row.precheck = None


def _run(context: JobContext, job: AnsibleJob, targets: Sequence[InventoryHost]) -> dict[str, HostDiscovery]:
    try:
        return discover_hosts(
            job.runner,
            [host.hostname for host in targets],
            webservers={host.hostname: host.webserver for host in targets},
            now=context.clock(),
        )
    except Exception:
        # No row may stay ``running`` after a run that died: the failure itself is classified by the caller.
        with context.factory.begin() as db:
            now = context.clock()
            for row in db.scalars(
                select(JobHost).where(
                    JobHost.job_id == context.job_id, JobHost.binding_id.is_(None), JobHost.status == JobHostStatus.RUNNING
                )
            ):
                row.status, row.finished_at, row.error_message = JobHostStatus.FAILED, now, _ABORTED
        raise


def _bounded(text: str | None) -> str | None:
    return str(redact(text))[-_EXCERPT_LIMIT:] or None if text else None


def _failure_text(outcome: HostDiscovery) -> tuple[str, str]:
    reason = outcome.reason or "internal"
    if outcome.status == _UNREACHABLE:
        return _UNREACHABLE, _UNREACHABLE_TEXT
    if reason == _AUTH:
        return _AUTH, _AUTH_TEXT
    return reason, str(redact(outcome.error or "discovery failed"))


def _record_host(
    context: JobContext, actor: Actor, hostname: str, server_id: int, outcome: HostDiscovery
) -> ReconcileOutcome | None:
    """One transaction per host: its bindings and endpoints (or its failure status) and its ``job_host`` row."""
    if outcome.status == "ok" and outcome.document is not None:
        try:
            with context.factory.begin() as db:
                now = context.clock()
                result = reconcile_host(db, server_id, outcome.document, job_id=context.job_id, actor=actor, now=now)
                row = _row(db, context.job_id, server_id)
                row.status, row.finished_at, row.error_message = JobHostStatus.SUCCEEDED, now, None
                row.precheck = {**outcome.summary, "parse_suspected": result.parse_suspected}
                row.log_excerpt = _bounded(outcome.log_excerpt)
            return result
        except Exception as error:  # noqa: BLE001 - one host's document must not fail the other hosts
            _LOG.error("discovery of %s could not be applied: %s", hostname, type(error).__name__)
            outcome = HostDiscovery(hostname, "failed", "parse_failed", _APPLY_FAILED, None, outcome.summary, "")
    reason, text = _failure_text(outcome)
    with context.factory.begin() as db:
        now = context.clock()
        record_host_failure(db, server_id, "unreachable" if outcome.status == _UNREACHABLE else "failed", now)
        row = _row(db, context.job_id, server_id)
        row.status, row.finished_at, row.error_message = JobHostStatus.FAILED, now, f"{reason}: {text}"
        row.precheck = dict(outcome.summary) or None
        row.log_excerpt = _bounded(outcome.log_excerpt)
    return None


# --- summaries --------------------------------------------------------------------------------------


class _Summary:
    """The state of every ``job_host`` row of this job after the attempt."""

    def __init__(self, rows: Sequence[tuple[str, JobHost]]) -> None:
        self.rows = {hostname: row for hostname, row in rows}
        failed = [row for row in self.rows.values() if row.status == JobHostStatus.FAILED]
        self.total = len(self.rows)
        self.ok = sum(row.status == JobHostStatus.SUCCEEDED for row in self.rows.values())
        self.unreachable = sum(_failed_with(row, _UNREACHABLE) for row in failed)
        self.auth = sum(_failed_with(row, _AUTH) for row in failed)
        self.failed = len(failed) - self.unreachable
        self.suspected = sorted(name for name, row in self.rows.items() if (row.precheck or {}).get("parse_suspected") is True)


def _failed_with(row: JobHost, reason: str) -> bool:
    return (row.error_message or "").startswith(_PREFIX[reason])


def _summary(db: Session, job_id: UUID) -> _Summary:
    rows = db.execute(
        select(Server.hostname, JobHost)
        .join(Server, Server.id == JobHost.server_id)
        .where(JobHost.job_id == job_id, JobHost.binding_id.is_(None))
        .order_by(Server.hostname)
    ).all()
    return _Summary([(hostname, row) for hostname, row in rows])


def _this_attempt(summary: _Summary, hostnames: Sequence[str]) -> dict[str, JSONValue]:
    rows = [summary.rows[name] for name in hostnames if name in summary.rows]
    unreachable = sum(_failed_with(row, _UNREACHABLE) for row in rows)
    ok = sum(row.status == JobHostStatus.SUCCEEDED for row in rows)
    return {
        "ok": ok,
        "unreachable": unreachable,
        "failed": len(rows) - ok - unreachable,
        "parse_suspected": sum(name in summary.suspected for name in hostnames),
    }


def _totals(db: Session, job_id: UUID, summary: _Summary) -> dict[str, JSONValue]:
    """Result counters over every attempt: row states from the rows, additive counters from the run audits."""
    sums = dict.fromkeys(_COUNTERS, 0)
    for details in db.scalars(select(AuditLog.details).where(AuditLog.action == RUN_ACTION, AuditLog.target_id == str(job_id))):
        for name in _COUNTERS:
            value = details.get(name, 0)
            sums[name] += value if isinstance(value, int) else 0
    totals: dict[str, JSONValue] = {
        "hosts": summary.total,
        "ok": summary.ok,
        "failed": summary.failed,
        "unreachable": summary.unreachable,
        **sums,
        "parse_suspected": list(summary.suspected),
    }
    return totals
