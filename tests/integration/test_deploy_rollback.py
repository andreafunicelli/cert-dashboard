"""Automatic, single-attempt rollback of a failed host deploy (Plan 3 Task 15).

Spec 6.4 steps 3–8, 9.6, 10.2 scenarios 5 and 6. The faults are real webserver behaviour, never a test hook
in the production playbook: a ``SIGSTOP``ped master keeps the old certificate in its workers while
``nginx -s reload`` still succeeds (§10.2 scenario 6, the stale worker), and a killed master makes the
rollback's own reload fail. Every assertion reads the container through ``docker compose exec``.
"""

from __future__ import annotations

import json

from app.ansible.deploy import run_host_deploy
from app.models.enums import WebserverType
from tests.integration.conftest import JOB_ID, task_starts
from tests.integration.test_deploy_playbook import APACHE_CHAIN, APACHE_CRT, APACHE_KEY, BACKUP_ROOT
from tests.integration.test_deploy_preflight import describe, web01_targets

WWW_CRT = "/etc/nginx/ssl/www.crt"
WWW_KEY = "/etc/nginx/ssl/www.key"
WWW_VHOST = "www.example.internal"


def only_www(material, expected):
    """The deploy that only writes the www binding of web01, so ``nginx -t`` fails after the write."""
    return [
        material.target(
            binding_id=1, cert_path=WWW_CRT, key_path=WWW_KEY, port=18443, sni=WWW_VHOST, expected=expected
        )
    ]


def test_verify_failure_rolls_back(ssh_targets, fresh_targets, deploy_material, tmp_path):
    # §10.2 scenario 6: a SIGSTOPped master keeps its workers on the old certificate. The reload succeeds,
    # so only the on-target verification can notice, and all three attempts must run before the rollback.
    before = {
        path: (ssh_targets.read("ssh-nginx-1", path), ssh_targets.stat("ssh-nginx-1", path))
        for path in (WWW_CRT, WWW_KEY)
    }
    ssh_targets.signal_webserver("ssh-nginx-1", "STOP")
    try:
        outcome = run_host_deploy(
            deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX,
            web01_targets(deploy_material, ssh_targets.old.fingerprint), deploy_material.staged,
            job_id=JOB_ID, retention_days=30, timeout_seconds=600,
        )  # fmt: skip
    finally:
        ssh_targets.signal_webserver("ssh-nginx-1", "CONT")
    assert (outcome.status, outcome.reason, outcome.rolled_back, outcome.rollback_error) == (
        "rolled_back", "verify_failed", True, None), describe(outcome)  # fmt: skip
    verify = outcome.verify
    assert verify is not None and verify["attempts"] == 3, "three attempts, two seconds apart, before the rollback"
    assert outcome.precheck["step"] == "rolled_back"
    assert ssh_targets.served_fingerprint("ssh-nginx-1", WWW_VHOST) == ssh_targets.old.fingerprint
    for path, (data, stat) in before.items():
        assert ssh_targets.read("ssh-nginx-1", path) == data
        assert ssh_targets.stat("ssh-nginx-1", path)[:3] == stat[:3]
    assert f"{BACKUP_ROOT}/{JOB_ID}" in ssh_targets.backups("ssh-nginx-1")


def test_failed_rollback_needs_manual_attention(ssh_targets, fresh_targets, deploy_material, tmp_path):
    # The write breaks the configuration (partial selection) and the killed master makes the rollback's own
    # reload fail: the host is reported with `rolled_back: false` and a rollback error, and the backup stays.
    ssh_targets.signal_webserver("ssh-nginx-1", "KILL")
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX,
        only_www(deploy_material, ssh_targets.old.fingerprint), deploy_material.staged,
        job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (outcome.status, outcome.reason, outcome.rolled_back, outcome.rollback_error) == (
        "failed", "config_test_failed", False, "reload failed after restore"), describe(outcome)  # fmt: skip
    assert outcome.precheck["step"] == "rollback_failed"
    assert f"{BACKUP_ROOT}/{JOB_ID}" in ssh_targets.backups("ssh-nginx-1")


def test_rollback_never_runs_twice(ssh_targets, fresh_targets, deploy_material, tmp_path):
    # A failed rollback must not trigger another restore: the event stream shows each restore task once.
    ssh_targets.signal_webserver("ssh-nginx-1", "KILL")
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX,
        only_www(deploy_material, ssh_targets.old.fingerprint), deploy_material.staged,
        job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert outcome.rollback_error == "reload failed after restore", describe(outcome)
    starts = task_starts(tmp_path / "run")
    assert starts.count("Roll this host back to its backups") == 1
    for name in (
        "Plan the restore of every manifest path",
        "Create the empty restore file of every manifest path",
        "Fill every restore file with its backed-up content",
        "Restore every manifest path atomically",
    ):
        assert starts.count(name) == 1, f"{name} ran {starts.count(name)} times"
    # and the failed rollback is never followed by a second rollback attempt
    assert starts.count("Restore every manifest path atomically") == 1


def test_rolled_back_apache_host_restores_leaf_and_chain(ssh_targets, fresh_targets, deploy_material, tmp_path):
    # §10.2 scenario 5's "all three files": Apache serves from www.crt + www.chain.pem + www.key, and a
    # SIGSTOPped parent makes the verification fail while `apachectl graceful` still exits 0.
    live = (APACHE_CRT, APACHE_CHAIN, APACHE_KEY)
    before = {
        path: (ssh_targets.read("ssh-apache", path), ssh_targets.stat("ssh-apache", path)) for path in live
    }
    targets = [
        deploy_material.target(
            binding_id=9, cert_path=APACHE_CRT, chain_path=APACHE_CHAIN, key_path=APACHE_KEY,
            port=18445, sni=WWW_VHOST, expected=ssh_targets.old.fingerprint,
        )
    ]  # fmt: skip
    ssh_targets.signal_webserver("ssh-apache", "STOP")
    try:
        outcome = run_host_deploy(
            deploy_material.runner(tmp_path), "web03.example.internal", WebserverType.APACHE, targets,
            deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
        )  # fmt: skip
    finally:
        ssh_targets.signal_webserver("ssh-apache", "CONT")
    assert (outcome.status, outcome.reason, outcome.rolled_back, outcome.rollback_error) == (
        "rolled_back", "verify_failed", True, None), describe(outcome)  # fmt: skip
    for path, (data, stat) in before.items():
        assert ssh_targets.read("ssh-apache", path) == data, path
        assert ssh_targets.stat("ssh-apache", path)[:3] == stat[:3], path
    assert ssh_targets.served_fingerprint("ssh-apache", WWW_VHOST) == ssh_targets.old.fingerprint
    manifest = json.loads(ssh_targets.read("ssh-apache", f"{BACKUP_ROOT}/{JOB_ID}/manifest.json"))
    assert sorted(manifest["files"]) == sorted(live)
