"""Canary pause, Continue, Cancel, pause expiry and single-host retry (Plan 3 Task 17).

Spec §6.5, §7.1, §7.2, §8.7 and §3.6; Contract decisions 2 and 20. Every test drives the real worker against
the SSH targets, so this module needs Docker and runs only in CI.

The world is Task 16's ``deploy_ready``: three discovered servers (``web01`` is the canary, ``web02`` and
``web03`` share ``ring_a``), four ``matched`` bindings, an issued renewal of the certificate they serve and
the fixture root as a trust anchor. What is asserted here is the §6.5 approval gate: a paused deploy holds no
claim, slot, lock or timeout; Continue re-locks, re-pulls, re-runs the trust gate and every host's drift
preflight; Cancel lets the in-flight hosts finish and starts nothing new; a forgotten pause auto-cancels with
``deploy.pause_expired``; and a single-host retry is a new audited job that leaves the original untouched.
"""

import threading

import pytest
from sqlalchemy import select

from app.jobs.handlers import deploy as deploy_handler
from app.jobs.queue import InvalidJobState, JobPaused, claim, enqueue, finish, reap
from app.jobs.worker import timeout_for
from app.models import AuditLog, Binding, Job, JobHost, Renewal, Server
from app.models.enums import JobType
from app.services.audit import Actor
from app.services.deploy import DeployBlocked, cancel_deploy, continue_deploy, pause_deadline, retry_host
from app.services.trust_anchors import remove_anchor
from tests.integration.conftest import (
    audit_actions,
    create_login_user,
    disable_schedules,
    fetch,
    set_setting,
)

WEB01, WEB02, WEB03 = "web01.example.internal", "web02.example.internal", "web03.example.internal"
WWW = "www.example.internal"
SERVICES = ("ssh-nginx-1", "ssh-nginx-2", "ssh-apache")
CANCELLED_BY_OPERATOR = "cancelled by operator"


@pytest.fixture(autouse=True)
def isolated(queue_factory):
    """Only what the test queues itself may run: no schedule may enqueue anything during a controls test."""
    disable_schedules(queue_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup", "discovery")


@pytest.fixture
def actor(queue_factory):
    """The operator of the controls, persisted in the private queue database.

    The conftest ``actor`` fixture lives on the rollback-per-test database, but every control here writes
    through ``queue_factory`` and audits the acting user, so the row must exist in that database.
    """
    user = create_login_user(queue_factory, "deploy-operator")
    return Actor(user.id, user.username)


# --- helpers ------------------------------------------------------------------------------------


def rows_of(factory, job_id):
    """``(hostname, row)`` for every ``job_host`` row of the job, in plan order."""
    with factory() as db:
        return list(
            db.execute(
                select(Server.hostname, JobHost)
                .join(Server, Server.id == JobHost.server_id)
                .where(JobHost.job_id == job_id)
                .order_by(JobHost.batch_no, Server.hostname, JobHost.binding_id)
            ).all()
        )


def rows_by_host(factory, job_id):
    grouped: dict[str, list[JobHost]] = {}
    for hostname, row in rows_of(factory, job_id):
        grouped.setdefault(hostname, []).append(row)
    return grouped


def host_status(factory, job_id, hostname):
    """The single status of every row of one host (``web01`` has two bindings, the others one)."""
    statuses = {row.status for row in rows_by_host(factory, job_id)[hostname]}
    assert len(statuses) == 1, statuses
    return statuses.pop()


def host_reason(factory, job_id, hostname):
    """``(status, reason)`` of one host: the §4 reason a row carries, without the fixed text."""
    pairs = {(row.status, _reason(row)) for row in rows_by_host(factory, job_id)[hostname]}
    assert len(pairs) == 1, pairs
    return pairs.pop()


def _reason(row):
    return row.error_message.split(": ", 1)[0] if row.error_message else None


def server_of(factory, hostname):
    with factory() as db:
        return db.scalars(select(Server).where(Server.hostname == hostname)).one()


def binding_id_of(factory, hostname, vhost=WWW):
    """The id of one host's ``vhost`` binding, for a job that targets exactly one server."""
    with factory() as db:
        return db.scalar(
            select(Binding.id)
            .join(Server, Server.id == Binding.server_id)
            .where(Server.hostname == hostname, Binding.vhost_name == vhost)
        )


def audits_of(factory, action, target_id):
    with factory() as db:
        return list(
            db.scalars(
                select(AuditLog)
                .where(AuditLog.action == action, AuditLog.target_id == str(target_id))
                .order_by(AuditLog.created_at, AuditLog.id)
            )
        )


def audit_trail(factory, target_id):
    """The job's audit actions in transaction order: one sorted tuple per transaction.

    ``audit_log.created_at`` is ``now()``, the *transaction* timestamp, so the rows one transaction writes
    tie exactly — ``start_deploy`` writes ``job.enqueue`` and ``deploy.start`` together, and no column
    records which of the two was inserted first (``id`` is a random UUID). Ties are therefore sorted by
    action; every other step of a deploy is its own transaction and keeps its position.
    """
    with factory() as db:
        rows = db.execute(
            select(AuditLog.action, AuditLog.created_at)
            .where(AuditLog.target_id == str(target_id))
            .order_by(AuditLog.created_at, AuditLog.action)
        ).all()
    groups: list[tuple[str, ...]] = []
    previous = None
    for action, created_at in rows:
        if groups and created_at == previous:
            groups[-1] = (*groups[-1], action)
        else:
            groups.append((action,))
        previous = created_at
    return groups


def drift(ssh_targets, deploy_ready):
    """Overwrite web02's certificate after planning: the on-disk leaf is neither the old nor the new one."""
    ssh_targets.put("ssh-nginx-2", "/etc/nginx/ssl/www.crt", deploy_ready.other_cert_pem, mode=0o644)


# --- the canary pause and Continue --------------------------------------------------------------


def test_canary_pauses_then_continue_rechecks_drift(
    ssh_targets, fresh_targets, queue_factory, deploy_ready, clock, actor
):
    enqueued_at = clock()
    job_id = deploy_ready.start(batch_percent=50, pause_after_canary=True)
    deploy_ready.worker.run_queued(timeout=600)

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.resume_from_batch, job.timeout_at, job.locked_by) == ("paused", 1, None, None)
    assert job.paused_at == enqueued_at  # the pause is recorded, so the 24 h window has a start
    assert job.attempt == 0  # a released claim is refunded: the job has not spent its single attempt
    assert host_status(queue_factory, job_id, WEB01) == "succeeded"
    assert host_status(queue_factory, job_id, WEB02) == "pending"
    # A paused job is claimable by nobody: no schedule, no worker poll picks it up again.
    assert deploy_ready.worker.run_queued(timeout=60) == 0
    assert fetch(queue_factory, Job, job_id).status == "paused"

    drift(ssh_targets, deploy_ready)  # the host changed while the operator was thinking
    clock.advance(hours=3)
    with queue_factory.begin() as db:
        continue_deploy(db, job_id, actor, clock())
    deploy_ready.worker.run_queued(timeout=600)

    assert host_reason(queue_factory, job_id, WEB02) == ("failed", "drift_detected")
    assert fetch(queue_factory, Job, job_id).status == "failed"
    # The plan's sequence — job.enqueue, deploy.start, job.paused, deploy.continue, job.failed — with the
    # one transaction ``start_deploy`` writes as a single group (see ``audit_trail``).
    assert audit_trail(queue_factory, job_id) == [
        ("deploy.start", "job.enqueue"),
        ("job.paused",),
        ("deploy.continue",),
        ("job.failed",),
    ]


def test_paused_deploy_auto_cancels_after_the_timeout(
    ssh_targets, fresh_targets, queue_factory, deploy_ready, clock, actor
):
    job_id = deploy_ready.start(batch_percent=50, pause_after_canary=True)
    deploy_ready.worker.run_queued(timeout=600)
    paused = fetch(queue_factory, Job, job_id)
    assert paused.status == "paused" and paused.paused_at is not None

    clock.advance(hours=24, seconds=30)
    # Continue is refused once the window has passed, before the sweep has run.
    with pytest.raises(InvalidJobState), queue_factory.begin() as db:
        continue_deploy(db, job_id, actor, clock())
    assert fetch(queue_factory, Job, job_id).status == "paused"

    deploy_ready.worker.tick()  # the deploy_sweep tick step

    job = fetch(queue_factory, Job, job_id)
    assert job.status == "cancelled"
    assert host_reason(queue_factory, job_id, WEB02) == ("skipped", "pause_expired")
    assert host_reason(queue_factory, job_id, WEB03) == ("skipped", "pause_expired")
    assert host_status(queue_factory, job_id, WEB01) == "succeeded"  # the canary stays deployed
    [expired] = audits_of(queue_factory, "deploy.pause_expired", job_id)
    assert expired.details["pause_timeout_hours"] == 24
    assert expired.details["paused_at"] == paused.paused_at.isoformat()
    # Nothing is left for a worker to pick up, and the renewal is not advanced by a cancelled job (§4.6).
    assert deploy_ready.worker.run_queued(timeout=60) == 0
    assert fetch(queue_factory, Renewal, deploy_ready.renewal.id).state == "issued"


# --- Cancel -------------------------------------------------------------------------------------


def test_cancel_running_deploy_lets_in_flight_hosts_finish(
    ssh_targets, fresh_targets, queue_factory, deploy_ready, clock, actor, monkeypatch
):
    """Cancel while batch 1 runs with concurrency 1: web02 finishes, web03 never starts."""
    set_setting(queue_factory, "deploy.concurrency", 1)
    started, release = threading.Event(), threading.Event()
    real = deploy_handler.run_host_deploy

    def blocked(runner, hostname, *args, **kwargs):
        if hostname == WEB02:
            started.set()
            assert release.wait(300), "the test never released the in-flight host"
        return real(runner, hostname, *args, **kwargs)

    monkeypatch.setattr(deploy_handler, "run_host_deploy", blocked)
    job_id = deploy_ready.start(batch_percent=50, pause_after_canary=False)
    runner = threading.Thread(target=deploy_ready.worker.run_queued, kwargs={"timeout": 900}, daemon=True)
    runner.start()
    try:
        assert started.wait(300), "the canary batch never finished"
        with queue_factory.begin() as db:
            assert cancel_deploy(db, job_id, actor, clock()).status == "running"
        assert host_reason(queue_factory, job_id, WEB03) == ("skipped", "cancelled")
        assert host_status(queue_factory, job_id, WEB02) == "running"  # in flight, not cancelled
    finally:
        release.set()
        runner.join(900)
    assert not runner.is_alive()

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_message) == ("cancelled", CANCELLED_BY_OPERATOR)
    assert job.result["phase"] == "cancelled"
    assert host_status(queue_factory, job_id, WEB02) == "succeeded"  # the in-flight host finished
    assert host_reason(queue_factory, job_id, WEB03) == ("skipped", "cancelled")
    [cancel] = audits_of(queue_factory, "deploy.cancel", job_id)
    assert cancel.details["from_status"] == "running"
    assert "job.cancelled" in audit_actions(queue_factory, str(job_id))
    # A cancelled deploy never advances the renewal (§4.6), even though the canary and web02 succeeded.
    assert fetch(queue_factory, Renewal, deploy_ready.renewal.id).state == "issued"


def test_cancel_in_flight_only_host_ends_cancelled(
    ssh_targets, fresh_targets, queue_factory, deploy_ready, clock, actor, monkeypatch
):
    """A cancel with zero pending rows must still end the job cancelled.

    The single-host retry has one batch only, so when the cancel commits every row is already
    ``running``: ``_skip_cancelled_rows`` changes nothing and the ``deploy.cancel`` audit is the only
    signal. The in-flight host finishes, the job ends ``cancelled`` and the renewal is not advanced
    (Contract decision 20).
    """
    drift(ssh_targets, deploy_ready)
    original_id = deploy_ready.start(batch_percent=33, pause_after_canary=False)  # [web01], [web02], [web03]
    deploy_ready.worker.run_queued(timeout=900)
    assert fetch(queue_factory, Job, original_id).status == "failed"
    web03 = server_of(queue_factory, WEB03)
    with queue_factory.begin() as db:
        retry_id = retry_host(db, original_id, web03.id, "retry the host the rollout never touched", actor, clock()).id

    started, release = threading.Event(), threading.Event()
    real = deploy_handler.run_host_deploy

    def blocked(runner, hostname, *args, **kwargs):
        if hostname == WEB03:
            started.set()
            assert release.wait(300), "the test never released the in-flight host"
        return real(runner, hostname, *args, **kwargs)

    monkeypatch.setattr(deploy_handler, "run_host_deploy", blocked)
    runner = threading.Thread(target=deploy_ready.worker.run_queued, kwargs={"timeout": 900}, daemon=True)
    runner.start()
    try:
        assert started.wait(300), "the retry host never started"
        with queue_factory.begin() as db:
            assert cancel_deploy(db, retry_id, actor, clock()).status == "running"
        assert {row.status for _, row in rows_of(queue_factory, retry_id)} == {"running"}  # no pending row
        [cancel] = audits_of(queue_factory, "deploy.cancel", retry_id)
        assert cancel.details["pending_rows"] == 0
    finally:
        release.set()
        runner.join(900)
    assert not runner.is_alive()

    job = fetch(queue_factory, Job, retry_id)
    assert (job.status, job.error_message) == ("cancelled", CANCELLED_BY_OPERATOR)
    assert job.result["phase"] == "cancelled"
    assert host_status(queue_factory, retry_id, WEB03) == "succeeded"  # the in-flight host finished
    assert "job.cancelled" in audit_actions(queue_factory, str(retry_id))
    assert "job.succeeded" not in audit_actions(queue_factory, str(retry_id))
    # A cancelled deploy never advances the renewal (§4.6), even though the only host succeeded.
    assert fetch(queue_factory, Renewal, deploy_ready.renewal.id).state == "issued"


def test_cancel_while_in_flight_host_fails_ends_cancelled(
    ssh_targets, fresh_targets, queue_factory, deploy_ready, clock, actor, monkeypatch
):
    """An accepted cancel outranks a host that fails after it, once the batch has settled.

    The cancel is committed while web02 is in flight; web02 then fails its drift preflight and web03
    was already skipped ``cancelled``. The job ends ``cancelled`` — not ``failed`` — and web02 keeps
    its own failure evidence (Contract decision 20).
    """
    set_setting(queue_factory, "deploy.concurrency", 1)
    drift(ssh_targets, deploy_ready)  # web02 will fail its drift preflight
    started, release = threading.Event(), threading.Event()
    real = deploy_handler.run_host_deploy

    def blocked(runner, hostname, *args, **kwargs):
        if hostname == WEB02:
            started.set()
            assert release.wait(300), "the test never released the in-flight host"
        return real(runner, hostname, *args, **kwargs)

    monkeypatch.setattr(deploy_handler, "run_host_deploy", blocked)
    job_id = deploy_ready.start(batch_percent=50, pause_after_canary=False)
    runner = threading.Thread(target=deploy_ready.worker.run_queued, kwargs={"timeout": 900}, daemon=True)
    runner.start()
    try:
        assert started.wait(300), "the canary batch never finished"
        with queue_factory.begin() as db:
            assert cancel_deploy(db, job_id, actor, clock()).status == "running"
        assert host_reason(queue_factory, job_id, WEB03) == ("skipped", "cancelled")
        assert host_status(queue_factory, job_id, WEB02) == "running"  # in flight, not cancelled
    finally:
        release.set()
        runner.join(900)
    assert not runner.is_alive()

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_message) == ("cancelled", CANCELLED_BY_OPERATOR)
    assert job.result["phase"] == "cancelled"
    assert host_reason(queue_factory, job_id, WEB02) == ("failed", "drift_detected")  # evidence retained
    assert host_reason(queue_factory, job_id, WEB03) == ("skipped", "cancelled")
    assert "job.cancelled" in audit_actions(queue_factory, str(job_id))
    assert "job.failed" not in audit_actions(queue_factory, str(job_id))
    assert fetch(queue_factory, Renewal, deploy_ready.renewal.id).state == "issued"


def test_cancel_accepted_after_the_handler_check_cannot_race_a_success(
    ssh_targets, fresh_targets, queue_factory, deploy_ready, clock, actor, monkeypatch
):
    """A cancel that commits after the handler's last check is still finalised as ``cancelled``.

    The handler's durable check is stubbed out to simulate the race window between its last look and
    the worker's finalization: the job-row fence in ``_finish`` must see the committed
    ``deploy.cancel`` and end the job ``cancelled`` without running the renewal success hook.
    """
    monkeypatch.setattr(deploy_handler, "_cancel_accepted", lambda context: False)
    started, release = threading.Event(), threading.Event()
    real = deploy_handler.run_host_deploy

    def blocked(runner, hostname, *args, **kwargs):
        if hostname == WEB02:
            started.set()
            assert release.wait(300), "the test never released the in-flight host"
        return real(runner, hostname, *args, **kwargs)

    monkeypatch.setattr(deploy_handler, "run_host_deploy", blocked)
    job_id = deploy_ready.start(
        binding_ids=(binding_id_of(queue_factory, WEB02),), batch_percent=100, pause_after_canary=False
    )  # web02 only: batch 0 is the whole rollout
    runner = threading.Thread(target=deploy_ready.worker.run_queued, kwargs={"timeout": 900}, daemon=True)
    runner.start()
    try:
        assert started.wait(300), "the only host never started"
        with queue_factory.begin() as db:
            assert cancel_deploy(db, job_id, actor, clock()).status == "running"
        [cancel] = audits_of(queue_factory, "deploy.cancel", job_id)
        assert cancel.details["pending_rows"] == 0
    finally:
        release.set()
        runner.join(900)
    assert not runner.is_alive()

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_message) == ("cancelled", CANCELLED_BY_OPERATOR)
    assert job.result["phase"] == "cancelled"
    assert "job.cancelled" in audit_actions(queue_factory, str(job_id))
    assert "job.succeeded" not in audit_actions(queue_factory, str(job_id))
    assert fetch(queue_factory, Renewal, deploy_ready.renewal.id).state == "issued"


def test_cancel_committed_before_the_pause_transition_ends_cancelled(queue_factory, make_worker, clock, actor):
    """A Cancel committed in the pause handoff must beat the pause (Contract decision 20).

    The handler's last Cancel check can pass, and then ``cancel_deploy`` commits, before the worker
    releases the claim as a pause. The pause transition takes the job row's lock, so it must read the
    committed ``deploy.cancel`` and finish the job ``cancelled`` — never ``paused`` and never, later,
    ``pause_expired``. No SSH target is involved: the fence under test is the worker runtime's.
    """
    worker = make_worker(queue_factory)
    with queue_factory.begin() as db:
        job = enqueue(
            db, JobType.DEPLOY, {"action": "default"}, actor, priority=0, run_after=clock(), max_attempts=1
        )
        job_id = job.id
        claimed = claim(db, worker.worker_id, clock(), timeout_for)
        assert claimed is not None and claimed.id == job_id
    with queue_factory.begin() as db:
        assert cancel_deploy(db, job_id, actor, clock()).status == "running"

    assert worker._settle_control(job_id, JobPaused(1, {"phase": "paused"})) == "cancelled"

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_message) == ("cancelled", CANCELLED_BY_OPERATOR)
    assert job.result["phase"] == "cancelled"
    actions = audit_actions(queue_factory, str(job_id))
    assert "job.cancelled" in actions
    assert "job.paused" not in actions


def test_cancel_accepted_during_the_pause_handoff_ends_cancelled(
    ssh_targets, fresh_targets, queue_factory, deploy_ready, clock, actor, monkeypatch
):
    """A Cancel that commits while the handler decides to pause still ends the job cancelled.

    ``_has_pending`` is wrapped: it runs the real check and then commits ``cancel_deploy`` from
    another session, recreating the window between the handler's last Cancel check and the worker's
    pause transition. The pause fence must see ``deploy.cancel`` under the job-row lock, so the job
    ends ``cancelled`` with no ``job.paused`` and the sweep can never turn it into ``pause_expired``.
    """
    real = deploy_handler._has_pending
    cancelled: list = []

    def has_pending_then_cancel(context):
        pending = real(context)
        if pending and not cancelled:
            with queue_factory.begin() as db:
                cancel_deploy(db, context.job_id, actor, clock())
            cancelled.append(context.job_id)
        return pending

    monkeypatch.setattr(deploy_handler, "_has_pending", has_pending_then_cancel)
    job_id = deploy_ready.start(batch_percent=50, pause_after_canary=True)  # [web01], [web02, web03]
    deploy_ready.worker.run_queued(timeout=900)

    assert cancelled == [job_id], "the cancel never committed inside the pause handoff window"
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_message) == ("cancelled", CANCELLED_BY_OPERATOR)
    assert job.result["phase"] == "cancelled"
    actions = audit_actions(queue_factory, str(job_id))
    assert "job.cancelled" in actions
    assert "job.paused" not in actions
    assert host_status(queue_factory, job_id, WEB01) == "succeeded"  # the canary stays deployed
    assert host_reason(queue_factory, job_id, WEB02) == ("skipped", "cancelled")
    assert host_reason(queue_factory, job_id, WEB03) == ("skipped", "cancelled")

    deploy_ready.worker.tick()  # the deploy_sweep tick step must find nothing to expire
    assert fetch(queue_factory, Job, job_id).status == "cancelled"
    assert "deploy.pause_expired" not in audit_actions(queue_factory, str(job_id))
    assert fetch(queue_factory, Renewal, deploy_ready.renewal.id).state == "issued"


def test_cancel_queued_or_paused_deploy(ssh_targets, fresh_targets, queue_factory, deploy_ready, clock, actor):
    queued_id = deploy_ready.start(batch_percent=50, pause_after_canary=False)
    with queue_factory.begin() as db:
        assert cancel_deploy(db, queued_id, actor, clock()).status == "cancelled"
    assert {row.status for _, row in rows_of(queue_factory, queued_id)} == {"skipped"}
    assert {row.error_message for _, row in rows_of(queue_factory, queued_id)} == {"cancelled"}
    assert {"job.cancelled", "deploy.cancel"} <= set(audit_actions(queue_factory, str(queued_id)))
    assert all(ssh_targets.unchanged_since_reset(service) for service in SERVICES), ssh_targets.last_changes

    paused_id = deploy_ready.start(batch_percent=50, pause_after_canary=True)
    deploy_ready.worker.run_queued(timeout=600)
    assert fetch(queue_factory, Job, paused_id).status == "paused"
    with queue_factory.begin() as db:
        assert cancel_deploy(db, paused_id, actor, clock()).status == "cancelled"
    assert host_status(queue_factory, paused_id, WEB01) == "succeeded"
    assert host_reason(queue_factory, paused_id, WEB02) == ("skipped", "cancelled")
    [cancel] = audits_of(queue_factory, "deploy.cancel", paused_id)
    assert cancel.details["from_status"] == "paused"
    assert deploy_ready.worker.run_queued(timeout=60) == 0
    assert fetch(queue_factory, Job, paused_id).status == "cancelled"
    assert fetch(queue_factory, Renewal, deploy_ready.renewal.id).state == "issued"


# --- the sweep ----------------------------------------------------------------------------------


def test_terminal_job_never_keeps_pending_rows(ssh_targets, fresh_targets, queue_factory, deploy_ready, clock):
    """The reaper only fails ``running`` rows; the sweep closes the ``pending`` ones with ``job_ended``."""
    job_id = deploy_ready.start(batch_percent=33, pause_after_canary=False)
    with queue_factory.begin() as db:
        claimed = claim(db, "reaper-probe", clock(), timeout_for)
        assert claimed is not None and claimed.id == job_id
    clock.advance(seconds=3 * 600 + 900 + 1)  # past ``timeout_at`` of three remaining hosts
    with queue_factory.begin() as db:
        assert reap(db, clock()) == 1
    assert fetch(queue_factory, Job, job_id).status == "failed"
    assert {row.status for _, row in rows_of(queue_factory, job_id)} == {"pending"}

    deploy_ready.worker.tick()  # the deploy_sweep tick step

    assert {row.status for _, row in rows_of(queue_factory, job_id)} == {"skipped"}
    assert {row.error_message for _, row in rows_of(queue_factory, job_id)} == {"job_ended"}
    assert all(ssh_targets.unchanged_since_reset(service) for service in SERVICES), ssh_targets.last_changes


# --- single-host retry --------------------------------------------------------------------------


def test_retry_single_host_is_a_new_audited_job(
    ssh_targets, fresh_targets, queue_factory, deploy_ready, clock, actor
):
    drift(ssh_targets, deploy_ready)
    original_id = deploy_ready.start(batch_percent=33, pause_after_canary=False)  # [web01], [web02], [web03]
    deploy_ready.worker.run_queued(timeout=900)
    original = fetch(queue_factory, Job, original_id)
    assert (original.status, original.error_class) == ("failed", "config_invalid")
    assert host_reason(queue_factory, original_id, WEB03) == ("skipped", "rollout_stopped")
    web03 = server_of(queue_factory, WEB03)
    reason = "retry the host the stopped rollout never touched"

    with pytest.raises(DeployBlocked) as missing_reason, queue_factory.begin() as db:
        retry_host(db, original_id, web03.id, "  ", actor, clock())
    assert "reason" in missing_reason.value.reasons

    # The trust gate is asked again: without the anchor the certificate is not trusted any more.
    with queue_factory.begin() as db:
        remove_anchor(db, deploy_ready.anchor.id, Actor(None, "tester"), clock())
    with pytest.raises(DeployBlocked) as untrusted, queue_factory.begin() as db:
        retry_host(db, original_id, web03.id, reason, actor, clock())
    assert "chain_override" in untrusted.value.reasons

    override = "chain is untrusted after the anchor was removed; accepted for the retry"
    with queue_factory.begin() as db:
        new_id = retry_host(db, original_id, web03.id, reason, actor, clock(), override_reason=override).id
    new = fetch(queue_factory, Job, new_id)
    assert new.payload["retry_of"] == str(original_id)
    assert new.payload["pause_after_canary"] is False
    assert new.payload["chain_override"] is True
    rows = rows_by_host(queue_factory, new_id)
    assert set(rows) == {WEB03}
    assert [row.batch_no for row in rows[WEB03]] == [0]  # canary only, never a second batch
    assert {row.binding_id for row in rows[WEB03]} == {
        row.binding_id for row in rows_by_host(queue_factory, original_id)[WEB03]
    }
    [retry_audit] = audits_of(queue_factory, "deploy.retry_host", new_id)
    assert retry_audit.details == {"from_job": str(original_id), "server_id": web03.id, "reason": reason}
    assert "deploy.start" in audit_actions(queue_factory, str(new_id))

    # One deploy at a time: the queued retry job already holds the slot.
    with pytest.raises(DeployBlocked) as active, queue_factory.begin() as db:
        retry_host(db, original_id, web03.id, reason, actor, clock(), override_reason=override)
    assert "active_deploy" in active.value.reasons

    deploy_ready.worker.run_queued(timeout=900)
    assert fetch(queue_factory, Job, new_id).status == "succeeded"
    assert ssh_targets.served_fingerprint("ssh-apache", WWW) == deploy_ready.new.sha256_fingerprint
    # The original job is untouched: same status, same rows, and its renewal was never advanced by it.
    assert fetch(queue_factory, Job, original_id).status == "failed"
    assert host_reason(queue_factory, original_id, WEB02) == ("failed", "drift_detected")
    assert host_reason(queue_factory, original_id, WEB03) == ("skipped", "rollout_stopped")


# --- state guards -------------------------------------------------------------------------------


def test_controls_require_the_right_state(ssh_targets, fresh_targets, queue_factory, deploy_ready, clock, actor):
    running_id = deploy_ready.start(batch_percent=100, pause_after_canary=False)
    with queue_factory.begin() as db:
        assert claim(db, "state-probe", clock(), timeout_for).id == running_id
    with pytest.raises(InvalidJobState), queue_factory.begin() as db:
        continue_deploy(db, running_id, actor, clock())
    with pytest.raises(InvalidJobState), queue_factory.begin() as db:
        retry_host(db, running_id, server_of(queue_factory, WEB01).id, "not finished yet", actor, clock())
    with pytest.raises(InvalidJobState):
        pause_deadline(fetch(queue_factory, Job, running_id), 24)  # a running job is not paused

    with queue_factory.begin() as db:  # end the probe job so the next deploy can start
        finish(db, running_id, "state-probe", "failed", clock(), error_class="internal", error_message="probe")
    with pytest.raises(InvalidJobState), queue_factory.begin() as db:
        continue_deploy(db, running_id, actor, clock())
    with pytest.raises(InvalidJobState), queue_factory.begin() as db:
        cancel_deploy(db, running_id, actor, clock())

    done_id = deploy_ready.start(batch_percent=100, pause_after_canary=False)
    deploy_ready.worker.run_queued(timeout=900)
    assert fetch(queue_factory, Job, done_id).status == "succeeded"
    with pytest.raises(DeployBlocked) as healthy, queue_factory.begin() as db:
        retry_host(db, done_id, server_of(queue_factory, WEB01).id, "retry a healthy host", actor, clock())
    assert "host_not_retryable" in healthy.value.reasons
    with pytest.raises(InvalidJobState), queue_factory.begin() as db:
        cancel_deploy(db, done_id, actor, clock())
