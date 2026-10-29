"""``deploy/default`` end to end (Plan 3 Task 16; spec §6.4–§6.7, §7.2, §4.6, §10.2 scenario 9).

Every test here runs the real worker against the real SSH targets, so this module needs Docker and runs only
in CI (see the Plan 3 test harness). The fixture ``deploy_ready`` prepares the world: three discovered
servers with four ``matched`` bindings, an issued renewal of the certificate they serve, the new certificate
with its own key, and the fixture root as a trust anchor.

The rollout assertions are the ones the plan names: canary first, batches of
``max(1, ceil(total × percent / 100))``, the first failed host stops it, in-flight hosts finish, a locked
host is skipped without stopping it, and only a succeeded job advances the renewal (§4.6).
"""

from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app.jobs.handlers.discover import request_discovery
from app.jobs.locks import DEPLOY_GLOBAL_LOCK, AdvisoryLocks, host_lock_key
from app.jobs.queue import claim, retry_due
from app.jobs.worker import timeout_for
from app.models import AuditLog, Binding, Endpoint, Job, JobHost, Renewal, Server
from app.services.audit import Actor
from tests.integration.conftest import disable_schedules, fetch, set_setting

WEB01, WEB02, WEB03 = "web01.example.internal", "web02.example.internal", "web03.example.internal"
WWW, LEGACY = "www.example.internal", "legacy.example.internal"
SERVICES = ("ssh-nginx-1", "ssh-nginx-2", "ssh-apache")


@pytest.fixture(autouse=True)
def isolated(queue_factory):
    """Only what the test queues itself may run: no schedule may enqueue anything during a deploy test."""
    disable_schedules(queue_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup", "discovery")


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


def binding_by(factory, hostname, vhost=WWW):
    with factory() as db:
        return db.scalars(
            select(Binding)
            .join(Server, Server.id == Binding.server_id)
            .where(Server.hostname == hostname, Binding.vhost_name == vhost)
        ).one()


def endpoint_of(factory, binding_id):
    with factory() as db:
        return db.scalars(select(Endpoint).where(Endpoint.binding_id == binding_id)).one()


def audits_of(factory, action, target_id=None):
    with factory() as db:
        query = select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.created_at, AuditLog.id)
        if target_id is not None:
            query = query.where(AuditLog.target_id == str(target_id))
        return list(db.scalars(query))


def started_order(factory, job_id):
    """Hostnames in the order their rows were started (one entry per host)."""
    started = sorted(
        (row.started_at, hostname) for hostname, row in rows_of(factory, job_id) if row.started_at is not None
    )
    return list(dict.fromkeys(hostname for _, hostname in started))


def drift(ssh_targets, deploy_ready):
    """Overwrite web02's certificate after planning: the on-disk leaf is neither the old nor the new one."""
    ssh_targets.put("ssh-nginx-2", "/etc/nginx/ssl/www.crt", deploy_ready.other_cert_pem, mode=0o644)


def run_root(job):
    return Path(job.ansible_artifact_dir) / "run" / "artifacts"


# --- the full rollout ---------------------------------------------------------------------------


def test_canary_then_full_rollout_marks_the_renewal_deployed(deploy_ready, queue_factory, ssh_targets):
    job_id = deploy_ready.start(batch_percent=100, pause_after_canary=False)  # web01 canary, then web02 + web03
    deploy_ready.worker.run_queued(timeout=900)

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_class) == ("succeeded", None), (job.error_message, job.result)
    assert job.result["totals"] == {"succeeded": 4, "failed": 0, "rolled_back": 0, "skipped": 0, "pending": 0}
    assert job.result["inventory_rev"] == deploy_ready.repo.head
    assert fetch(queue_factory, Renewal, deploy_ready.renewal.id).state == "deployed"
    for service in SERVICES:
        assert ssh_targets.served_fingerprint(service, WWW) == deploy_ready.new.sha256_fingerprint
    www = binding_by(queue_factory, WEB02)
    assert (www.match_state, www.certificate_id, www.on_disk_fingerprint) == (
        "matched",
        deploy_ready.new.id,
        deploy_ready.new.sha256_fingerprint,
    )
    assert www.on_disk_key_public_sha256 == deploy_ready.new.key_public_sha256  # D2: the DER SPKI hash
    assert endpoint_of(queue_factory, www.id).expected_certificate_id == deploy_ready.new.id
    assert all(row.precheck["worker_verify"]["matches"] for _, row in rows_of(queue_factory, job_id))
    assert started_order(queue_factory, job_id)[0] == WEB01

    # The next discovery must find nothing left to change on the deployed host: no spurious transition audit.
    before = len(audits_of(queue_factory, "binding.match_state"))
    with queue_factory.begin() as db:
        request_discovery(db, {"hosts": [WEB02]}, Actor(None, "tester"), deploy_ready.clock())
    deploy_ready.worker.run_queued(timeout=300)
    assert binding_by(queue_factory, WEB02).match_state == "matched"
    assert len(audits_of(queue_factory, "binding.match_state")) == before


def test_rollout_stops_at_the_first_failed_host(deploy_ready, queue_factory, ssh_targets):
    """§10.2 scenario 9 at 33% (Contract decision 23): batches [web01], [web02], [web03]."""
    drift(ssh_targets, deploy_ready)
    job_id = deploy_ready.start(batch_percent=33, pause_after_canary=False)
    deploy_ready.worker.run_queued(timeout=900)

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_class) == ("failed", "config_invalid")
    assert job.error_message == f"rollout stopped: {WEB02} failed (drift_detected)"
    rows = rows_by_host(queue_factory, job_id)
    assert {row.status for row in rows[WEB01]} == {"succeeded"}
    assert {row.status for row in rows[WEB02]} == {"failed"}
    assert rows[WEB02][0].error_message.startswith("drift_detected: ")
    assert {row.status for row in rows[WEB03]} == {"skipped"}
    assert rows[WEB03][0].error_message == "rollout_stopped"
    # The canary was deployed and stays deployed; the renewal is not advanced by a failed job (§4.6).
    assert ssh_targets.served_fingerprint("ssh-nginx-1", WWW) == deploy_ready.new.sha256_fingerprint
    assert fetch(queue_factory, Renewal, deploy_ready.renewal.id).state == "issued"
    # A deploy is never retried automatically (spec §7.2).
    with queue_factory.begin() as db:
        assert retry_due(db, deploy_ready.clock()) == 0
    assert fetch(queue_factory, Job, job_id).status == "failed"


def test_in_flight_host_of_the_failing_batch_finishes(deploy_ready, queue_factory, ssh_targets):
    """50% with concurrency 2: web02 fails, web03 is already running and still succeeds."""
    set_setting(queue_factory, "deploy.concurrency", 2)
    drift(ssh_targets, deploy_ready)
    job_id = deploy_ready.start(batch_percent=50, pause_after_canary=False)
    deploy_ready.worker.run_queued(timeout=900)

    rows = rows_by_host(queue_factory, job_id)
    assert [row.batch_no for row in rows[WEB02]] == [1]
    assert [row.batch_no for row in rows[WEB03]] == [1]  # same batch as the failing host
    assert {row.status for row in rows[WEB02]} == {"failed"}
    assert {row.status for row in rows[WEB03]} == {"succeeded"}
    assert fetch(queue_factory, Job, job_id).status == "failed"


def test_unstarted_host_of_the_failing_batch_is_never_started(deploy_ready, queue_factory, ssh_targets):
    """Concurrency 1 and a batch larger than one: the second host of the batch is never submitted."""
    set_setting(queue_factory, "deploy.concurrency", 1)
    drift(ssh_targets, deploy_ready)
    ssh_targets.mark_baseline("ssh-apache")
    job_id = deploy_ready.start(batch_percent=100, pause_after_canary=False)
    deploy_ready.worker.run_queued(timeout=900)

    job = fetch(queue_factory, Job, job_id)
    rows = rows_by_host(queue_factory, job_id)
    assert [row.batch_no for row in rows[WEB02]] == [1] and [row.batch_no for row in rows[WEB03]] == [1]
    [web03] = rows[WEB03]
    assert (web03.status, web03.error_message, web03.started_at, web03.log_excerpt) == (
        "skipped",
        "rollout_stopped",
        None,
        None,
    )
    assert ssh_targets.backups("ssh-apache") == []
    assert ssh_targets.unchanged_since_reset("ssh-apache"), ssh_targets.last_changes
    # ``run_host_deploy`` uses ident ``<hostname>``: an untouched host has no Ansible run directory at all.
    assert (run_root(job) / WEB02).is_dir()
    assert not (run_root(job) / WEB03).exists()


def test_locked_host_is_skipped_and_the_rollout_continues(deploy_ready, queue_factory):
    """A host locked by ``deploy:<hostname>`` is ``skipped``/``locked``; it is not a failure."""
    held = AdvisoryLocks(queue_factory.kw["bind"])
    try:
        with held.session() as session:
            assert session.try_lock(host_lock_key(WEB03))
            job_id = deploy_ready.start(batch_percent=100, pause_after_canary=False)
            deploy_ready.worker.run_queued(timeout=900)
    finally:
        held.close()

    rows = rows_by_host(queue_factory, job_id)
    assert {row.status for row in rows[WEB03]} == {"skipped"}
    assert {row.error_message for row in rows[WEB03]} == {"locked"}
    assert {row.status for row in rows[WEB01] + rows[WEB02]} == {"succeeded"}
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.result["totals"]["skipped"]) == ("succeeded", 1)


def test_busy_global_lock_requeues_without_spending_the_attempt(deploy_ready, queue_factory, ssh_targets):
    """``deploy:global`` held elsewhere: the job goes back to ``queued`` for 30 s and spends no attempt."""
    held = AdvisoryLocks(queue_factory.kw["bind"])
    try:
        with held.session() as session:
            assert session.try_lock(DEPLOY_GLOBAL_LOCK)
            job_id = deploy_ready.start(batch_percent=100, pause_after_canary=False)
            deploy_ready.worker.run_queued(timeout=120)
            job = fetch(queue_factory, Job, job_id)
            assert (job.status, job.attempt) == ("queued", 0)
            assert job.run_after == deploy_ready.clock() + timedelta(seconds=30)
            assert all(row.status == "pending" and row.started_at is None for _, row in rows_of(queue_factory, job_id))
            assert all(ssh_targets.unchanged_since_reset(service) for service in ssh_targets.hosts), (
                ssh_targets.last_changes
            )
    finally:
        held.close()
    deploy_ready.clock.advance(seconds=31)
    deploy_ready.worker.run_queued(timeout=900)
    assert fetch(queue_factory, Job, job_id).status == "succeeded"


# --- job-level refusals at execution time --------------------------------------------------------


def test_trust_change_after_planning_fails_closed(deploy_ready, queue_factory, ssh_targets):
    from app.services.trust_anchors import remove_anchor

    job_id = deploy_ready.start(batch_percent=100, pause_after_canary=False)
    with queue_factory.begin() as db:
        remove_anchor(db, deploy_ready.anchor.id, Actor(None, "tester"), deploy_ready.clock())
    deploy_ready.worker.run_queued(timeout=300)

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_class) == ("failed", "config_invalid")
    assert job.error_message == "certificate trust changed since the deploy was planned; plan it again"
    assert {row.status for _, row in rows_of(queue_factory, job_id)} == {"skipped"}
    assert {row.error_message for _, row in rows_of(queue_factory, job_id)} == {"job_failed"}
    assert ssh_targets.unchanged_since_reset("ssh-nginx-1"), ssh_targets.last_changes


def test_key_unwrap_failure_marks_no_host_failed(deploy_ready, queue_factory, ssh_targets):
    from app.crypto.keyring import Keyring

    job_id = deploy_ready.start(batch_percent=100, pause_after_canary=False)
    broken = deploy_ready.build_worker(keyring=Keyring(1, {2: bytes(range(32))}))
    broken.run_queued(timeout=300)

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_class) == ("failed", "key_unwrap")
    assert {row.status for _, row in rows_of(queue_factory, job_id)} == {"skipped"}
    assert {row.error_message for _, row in rows_of(queue_factory, job_id)} == {"job_failed"}
    assert ssh_targets.unchanged_since_reset("ssh-nginx-1"), ssh_targets.last_changes


def test_execution_key_mismatch_fails_closed(deploy_ready, queue_factory, ssh_targets, keyring):
    """D2: the stored key must hash to the leaf's DER SPKI, so a swapped key version is refused at execution."""
    from cryptography.hazmat.primitives.asymmetric import ec

    from app.models import Certificate, PrivateKey
    from app.services.certificates import store_key

    job_id = deploy_ready.start(batch_percent=100, pause_after_canary=False)
    with queue_factory.begin() as db:
        other = store_key(db, keyring, ec.generate_private_key(ec.SECP256R1()), "generated", Actor(None, "tester"))
        db.get(Certificate, deploy_ready.new.id).key_id = other.id
        assert db.get(PrivateKey, other.id).public_key_sha256 != deploy_ready.new.key_public_sha256
    deploy_ready.worker.run_queued(timeout=300)

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_class) == ("failed", "config_invalid")
    assert job.error_message == "the certificate and its stored private key do not match"
    assert {row.status for _, row in rows_of(queue_factory, job_id)} == {"skipped"}
    assert {row.error_message for _, row in rows_of(queue_factory, job_id)} == {"job_failed"}
    assert ssh_targets.unchanged_since_reset("ssh-nginx-1"), ssh_targets.last_changes


def test_binding_turned_key_mismatch_is_blocked_at_execution(deploy_ready, queue_factory, ssh_targets):
    job_id = deploy_ready.start(batch_percent=100, pause_after_canary=False)
    with queue_factory.begin() as db:
        binding = db.scalars(
            select(Binding)
            .join(Server, Server.id == Binding.server_id)
            .where(Server.hostname == WEB02, Binding.vhost_name == WWW)
        ).one()
        binding.match_state = "key_mismatch"
    deploy_ready.worker.run_queued(timeout=900)

    rows = rows_by_host(queue_factory, job_id)
    assert {row.status for row in rows[WEB02]} == {"failed"}
    assert rows[WEB02][0].error_message.startswith("binding_blocked: ")
    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_class) == ("failed", "config_invalid")
    assert ssh_targets.unchanged_since_reset("ssh-nginx-2"), ssh_targets.last_changes


def test_rollback_failure_is_audited(deploy_ready, queue_factory, ssh_targets):
    """Task 15's fault: the config test fails on a partial selection and the rollback's reload cannot run."""
    www = binding_by(queue_factory, WEB01)
    ssh_targets.signal_webserver("ssh-nginx-1", "KILL")  # the rollback's ``nginx -s reload`` then fails
    job_id = deploy_ready.start(batch_percent=100, pause_after_canary=False, binding_ids=(www.id,))
    deploy_ready.worker.run_queued(timeout=900)

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_class) == ("failed", "config_invalid")
    [row] = rows_by_host(queue_factory, job_id)[WEB01]
    assert (row.status, row.rolled_back, row.rollback_error) == ("failed", False, "reload failed after restore")
    assert row.error_message.startswith("config_test_failed: ")
    [audit] = audits_of(queue_factory, "deploy.rollback_failed", job_id)
    assert (audit.target_type, audit.details["server_id"]) == ("job", www.server_id)
    assert audits_of(queue_factory, "deploy.rollback") == []


def test_rollback_success_is_audited(deploy_ready, queue_factory, ssh_targets):
    """Task 15's fault with the nginx master alive: the partial write is rolled back and audited (§9.6)."""
    www = binding_by(queue_factory, WEB01)
    before = {
        path: (ssh_targets.read("ssh-nginx-1", path), ssh_targets.stat("ssh-nginx-1", path))
        for path in ("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key")
    }
    job_id = deploy_ready.start(batch_percent=100, pause_after_canary=False, binding_ids=(www.id,))
    deploy_ready.worker.run_queued(timeout=900)

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_class) == ("failed", "config_invalid")
    assert job.error_message == f"rollout stopped: {WEB01} failed (config_test_failed)"
    [row] = rows_by_host(queue_factory, job_id)[WEB01]
    assert (row.status, row.rolled_back, row.rollback_error) == ("rolled_back", True, None)
    assert row.error_message.startswith("config_test_failed: ")
    # The rollback restored the original bytes with their owner/group/mode, and the target serves them again.
    for path, (data, stat) in before.items():
        assert ssh_targets.read("ssh-nginx-1", path) == data, path
        assert ssh_targets.stat("ssh-nginx-1", path)[:3] == stat[:3], path
    assert ssh_targets.served_fingerprint("ssh-nginx-1", WWW) == ssh_targets.old.fingerprint
    # A rolled-back host is not a verified host: the binding keeps pointing at the certificate it still serves.
    rolled_back = binding_by(queue_factory, WEB01)
    assert (rolled_back.match_state, rolled_back.certificate_id) == (
        "matched",
        deploy_ready.renewal.previous_certificate_id,
    )
    [audit] = audits_of(queue_factory, "deploy.rollback", job_id)
    assert (audit.target_type, audit.details["server_id"]) == ("job", www.server_id)
    assert (audit.details["reason"], audit.details["rolled_back"], audit.details["rollback_error"]) == (
        "config_test_failed",
        True,
        None,
    )
    assert audits_of(queue_factory, "deploy.rollback_failed") == []
    assert fetch(queue_factory, Renewal, deploy_ready.renewal.id).state == "issued"


def test_host_task_exception_is_recorded_as_failed_internal(
    deploy_ready, queue_factory, ssh_targets, monkeypatch
):
    """An unexpected exception after ``claim_host_rows`` must leave no ``running`` row and stop the rollout."""
    from app.jobs.handlers import deploy as deploy_handler

    real = deploy_handler.run_host_deploy

    def explode(runner, hostname, *args, **kwargs):
        if hostname == WEB02:
            raise RuntimeError("unexpected host task failure")
        return real(runner, hostname, *args, **kwargs)

    monkeypatch.setattr(deploy_handler, "run_host_deploy", explode)
    ssh_targets.mark_baseline("ssh-apache")
    job_id = deploy_ready.start(batch_percent=33, pause_after_canary=False)
    deploy_ready.worker.run_queued(timeout=900)

    job = fetch(queue_factory, Job, job_id)
    assert (job.status, job.error_class) == ("failed", "internal")
    assert job.error_message == f"rollout stopped: {WEB02} failed (internal)"
    rows = rows_by_host(queue_factory, job_id)
    assert {row.status for row in rows[WEB01]} == {"succeeded"}
    [web02] = rows[WEB02]
    assert (web02.status, web02.error_message, web02.rolled_back, web02.rollback_error) == (
        "failed",
        "internal: deploy playbook ended before verification",
        False,
        None,
    )
    assert web02.started_at is not None and web02.finished_at is not None
    assert web02.log_excerpt is None
    [web03] = rows[WEB03]
    assert (web03.status, web03.error_message, web03.started_at) == ("skipped", "rollout_stopped", None)
    assert ssh_targets.backups("ssh-apache") == []
    assert ssh_targets.unchanged_since_reset("ssh-apache"), ssh_targets.last_changes
    assert not (run_root(job) / WEB03).exists()
    assert fetch(queue_factory, Renewal, deploy_ready.renewal.id).state == "issued"
    with queue_factory.begin() as db:
        assert retry_due(db, deploy_ready.clock()) == 0


# --- timeout, secrets ----------------------------------------------------------------------------


def test_deploy_timeout_counts_remaining_hosts(deploy_ready, queue_factory, clock):
    set_setting(queue_factory, "deploy.host_timeout_seconds", 600)
    job_id = deploy_ready.start(batch_percent=33, pause_after_canary=False)
    with queue_factory.begin() as db:
        job = claim(db, "timeout-probe", clock(), timeout_for)
        assert job is not None and job.id == job_id
        assert job.timeout_at == clock() + timedelta(seconds=3 * 600 + 900)


def test_staged_key_is_removed_and_never_in_artifacts(deploy_ready, queue_factory):
    job_id = deploy_ready.start(batch_percent=100, pause_after_canary=False)
    deploy_ready.worker.run_queued(timeout=900)

    job = fetch(queue_factory, Job, job_id)
    assert job.status == "succeeded"
    assert not (deploy_ready.key_staging_dir / str(job_id)).exists()
    body = deploy_ready.new.key_pem.splitlines()[1]
    files = [path for path in Path(job.ansible_artifact_dir).rglob("*") if path.is_file()]
    assert files
    for path in files:
        content = path.read_bytes()
        assert b"PRIVATE KEY" not in content, f"key material reached {path}"
        assert body not in content, f"key material reached {path}"
    assert all("PRIVATE KEY" not in (row.log_excerpt or "") for _, row in rows_of(queue_factory, job_id))
