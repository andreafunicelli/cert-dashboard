"""Preflight and backup of a host deploy (Plan 3 Task 14; spec 6.4 steps 1–2, 9.6, 10.2 scenario 7).

These tests never inspect the code's own output: they read, stat and fingerprint the running containers
through ``docker compose exec`` (``ssh_targets``), so "nothing changed" means the bytes, inode, mode and
owner on the target are untouched. Task 14's playbook stops after the backup, so every passing preflight
here ends ``failed``/``internal`` with ``step: backed_up`` — the fail-safe boundary of the task.
"""

import json
from uuid import uuid4

from app.ansible.deploy import run_host_deploy
from app.models.enums import WebserverType
from tests.integration.conftest import JOB_ID

WWW_CRT = "/etc/nginx/ssl/www.crt"
WWW_KEY = "/etc/nginx/ssl/www.key"
LEGACY_KEY = "/etc/nginx/ssl/legacy.key"
WWW_VHOST = "www.example.internal"
LEGACY_VHOST = "legacy.example.internal"
BACKUP_ROOT = "/var/backups/cert-dashboard"


def describe(outcome) -> str:
    """Everything a failing assertion needs: the outcome, the published diagnostics and the log tail."""
    return (
        f"status={outcome.status} reason={outcome.reason} message={outcome.message} "
        f"step={outcome.precheck.get('step')} failed_task={outcome.precheck.get('failed_task')} "
        f"hash_rc={outcome.precheck.get('hash_rc')} "
        f"hash_stderr={outcome.precheck.get('hash_stderr')!r} backup_dir={outcome.backup_dir}\n"
        f"{outcome.log_excerpt[-2500:]}"
    )


def web01_targets(material, expected):
    """The two nginx bindings of web01: they share ``www.crt`` but have their own key."""
    return [
        material.target(
            binding_id=1, cert_path=WWW_CRT, key_path=WWW_KEY, port=18443, sni=WWW_VHOST, expected=expected
        ),
        material.target(
            binding_id=2, cert_path=WWW_CRT, key_path=LEGACY_KEY, port=18443, sni=LEGACY_VHOST, expected=expected
        ),
    ]


def test_backup_tree_and_manifest_without_touching_live_files(ssh_targets, fresh_targets, deploy_material, tmp_path):
    live = ("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "/etc/nginx/ssl/legacy.key")
    before = {path: (ssh_targets.read("ssh-nginx-1", path), ssh_targets.stat("ssh-nginx-1", path)) for path in live}
    targets = web01_targets(deploy_material, ssh_targets.old.fingerprint)
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, targets,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (outcome.status, outcome.reason, outcome.precheck["step"]) == ("failed", "internal", "backed_up"), describe(outcome)
    assert {path: (ssh_targets.read("ssh-nginx-1", path), ssh_targets.stat("ssh-nginx-1", path)) for path in live} == before
    assert ssh_targets.served_fingerprint("ssh-nginx-1", WWW_VHOST) == ssh_targets.old.fingerprint
    backup = f"/var/backups/cert-dashboard/{JOB_ID}"
    assert ssh_targets.stat("ssh-nginx-1", backup)[:3] == (0o700, "root", "root")
    assert ssh_targets.read("ssh-nginx-1", backup + "/etc/nginx/ssl/www.crt") == ssh_targets.old.fullchain_pem
    assert ssh_targets.stat("ssh-nginx-1", backup + "/etc/nginx/ssl/legacy.key").mode == 0o600
    manifest = json.loads(ssh_targets.read("ssh-nginx-1", backup + "/manifest.json"))
    assert sorted(manifest["files"]) == sorted(live) and manifest["job_id"] == str(JOB_ID)  # www.crt once
    assert manifest["created_at"].endswith("Z")
    assert manifest["files"][WWW_CRT]["fingerprint"] == ssh_targets.old.fingerprint
    assert manifest["files"][WWW_CRT]["owner"] == "root" and manifest["files"][WWW_CRT]["mode"] == "0644"


def test_drift_aborts_before_any_backup(ssh_targets, fresh_targets, deploy_material, tmp_path):
    # §10.2 scenario 7: somebody else replaced the certificate after discovery.
    ssh_targets.put("ssh-nginx-2", WWW_CRT, deploy_material.other_fullchain_pem, mode=0o644)
    ssh_targets.mark_baseline("ssh-nginx-2")
    job = uuid4()
    targets = [
        deploy_material.target(
            binding_id=3, cert_path=WWW_CRT, key_path=WWW_KEY, port=18444, sni=WWW_VHOST,
            expected=ssh_targets.old.fingerprint,
        )
    ]  # fmt: skip
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web02.example.internal", WebserverType.NGINX, targets,
        deploy_material.staged, job_id=job, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (outcome.status, outcome.reason) == ("failed", "drift_detected"), describe(outcome)
    assert outcome.rollback_error is None and outcome.rolled_back is False
    assert ssh_targets.unchanged_since_reset("ssh-nginx-2")
    assert ssh_targets.backups("ssh-nginx-2") == []


def test_preflight_refusals_change_nothing(ssh_targets, fresh_targets, deploy_material, tmp_path):
    def deploy(job, targets, staged=None):
        return run_host_deploy(
            deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, targets,
            staged or deploy_material.staged, job_id=job, retention_days=30, timeout_seconds=600,
        )  # fmt: skip

    def assert_refused(job, outcome, reason):
        assert (outcome.status, outcome.reason) == ("failed", reason), describe(outcome)
        assert ssh_targets.backups("ssh-nginx-1") == []
        assert not any(str(job) in entry for entry in ssh_targets.backups("ssh-nginx-1"))
        assert ssh_targets.unchanged_since_reset("ssh-nginx-1")

    # 1. the staged key does not belong to the staged leaf (D2's DER hash comparison)
    ssh_targets.mark_baseline("ssh-nginx-1")
    mismatch_job = uuid4()
    assert_refused(
        mismatch_job,
        deploy(mismatch_job, web01_targets(deploy_material, ssh_targets.old.fingerprint), deploy_material.mismatched_staged),
        "key_mismatch_preflight",
    )

    # 2. a target file that does not exist
    missing_job = uuid4()
    assert_refused(
        missing_job,
        deploy(
            missing_job,
            [
                deploy_material.target(
                    binding_id=4, cert_path="/etc/nginx/ssl/absent.crt", key_path=WWW_KEY, port=18443,
                    sni=WWW_VHOST, expected=ssh_targets.old.fingerprint,
                )
            ],
        ),
        "missing_target",
    )

    # 3. a configuration test that already fails: a rollback could not prove anything
    ssh_targets.put(
        "ssh-nginx-1", "/etc/nginx/conf.d/broken.conf", b"include /etc/nginx/conf.d/absent-include.conf;\n", mode=0o644
    )
    ssh_targets.mark_baseline("ssh-nginx-1")
    broken_job = uuid4()
    assert_refused(
        broken_job, deploy(broken_job, web01_targets(deploy_material, ssh_targets.old.fingerprint)), "baseline_config_invalid"
    )


def test_apache_backup_covers_leaf_chain_and_key(ssh_targets, fresh_targets, deploy_material, tmp_path):
    live = (
        "/etc/apache2/ssl/www.crt",
        "/etc/apache2/ssl/www.chain.pem",
        "/etc/apache2/ssl/www.key",
    )
    before = {path: (ssh_targets.read("ssh-apache", path), ssh_targets.stat("ssh-apache", path)) for path in live}
    job = uuid4()
    targets = [
        deploy_material.target(
            binding_id=9, cert_path="/etc/apache2/ssl/www.crt", chain_path="/etc/apache2/ssl/www.chain.pem",
            key_path="/etc/apache2/ssl/www.key", port=18445, sni=WWW_VHOST,
            expected=ssh_targets.old.fingerprint,
        )
    ]  # fmt: skip
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web03.example.internal", WebserverType.APACHE, targets,
        deploy_material.staged, job_id=job, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (outcome.status, outcome.precheck["step"]) == ("failed", "backed_up"), describe(outcome)
    assert {path: (ssh_targets.read("ssh-apache", path), ssh_targets.stat("ssh-apache", path)) for path in live} == before
    backup = f"{BACKUP_ROOT}/{job}"
    manifest = json.loads(ssh_targets.read("ssh-apache", backup + "/manifest.json"))
    assert sorted(manifest["files"]) == sorted(live)
    assert ssh_targets.stat("ssh-apache", backup + "/etc/apache2/ssl/www.key")[:3] == (0o600, "root", "root")
    assert ssh_targets.read("ssh-apache", backup + "/etc/apache2/ssl/www.chain.pem") == ssh_targets.old.chain_pem
    for path in ("/etc/apache2/ssl/www.crt", "/etc/apache2/ssl/www.chain.pem"):
        assert ssh_targets.stat("ssh-apache", backup + path).mode & 0o777 <= 0o644
        assert ssh_targets.stat("ssh-apache", backup + path)[1:3] == ("root", "root")


def test_file_conflict_never_runs_ansible(ssh_targets, fresh_targets, deploy_material, tmp_path):
    conflict = [
        deploy_material.target(
            binding_id=1, cert_path=WWW_CRT, key_path=WWW_KEY, port=18443, sni=WWW_VHOST,
            expected=ssh_targets.old.fingerprint,
        ),
        deploy_material.target(
            binding_id=2, cert_path="/etc/nginx/ssl/other.crt", key_path=WWW_CRT, port=18443, sni=LEGACY_VHOST,
            expected=ssh_targets.old.fingerprint,
        ),
    ]  # fmt: skip
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, conflict,
        deploy_material.staged, job_id=uuid4(), retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (outcome.status, outcome.reason) == ("failed", "file_conflict")
    assert not (tmp_path / "run").exists()  # no ansible-runner directory at all
    assert ssh_targets.backups("ssh-nginx-1") == []
    assert ssh_targets.unchanged_since_reset("ssh-nginx-1")


def test_no_secret_in_artifacts_or_excerpt(ssh_targets, fresh_targets, deploy_material, tmp_path):
    key_pem = deploy_material.staged.key_pem.read_bytes()
    body = key_pem.splitlines()[1]
    targets = web01_targets(deploy_material, ssh_targets.old.fingerprint)
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, targets,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert outcome.precheck["step"] == "backed_up", describe(outcome)

    artifacts = [path for path in (tmp_path / "run").rglob("*") if path.is_file()]
    assert artifacts
    for path in artifacts:
        content = path.read_bytes()
        assert b"PRIVATE KEY" not in content, f"key material reached {path}"
        assert body not in content, f"key material reached {path}"
    assert "PRIVATE KEY" not in outcome.log_excerpt
    assert body.decode() not in outcome.log_excerpt
    # the staged key itself is the only copy, and it lives outside the run directory
    assert deploy_material.staged.key_pem.is_file()
    assert tmp_path / "run" not in deploy_material.staged.key_pem.parents


def test_a_second_run_of_the_same_job_reuses_its_backup_directory(ssh_targets, fresh_targets, deploy_material, tmp_path):
    """Two runs cannot collide on the path: the backup is rewritten and the manifest stays complete."""
    targets = web01_targets(deploy_material, ssh_targets.old.fingerprint)
    first = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, targets,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    second = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, targets,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert first.precheck["step"] == second.precheck["step"] == "backed_up", describe(second)
    manifest = json.loads(
        ssh_targets.read("ssh-nginx-1", f"{BACKUP_ROOT}/{JOB_ID}/manifest.json")
    )
    assert sorted(manifest["files"]) == sorted((WWW_CRT, WWW_KEY, LEGACY_KEY))
    assert ssh_targets.read("ssh-nginx-1", f"{BACKUP_ROOT}/{JOB_ID}" + WWW_CRT) == ssh_targets.old.fullchain_pem
    # the job id names the directory, so a re-run of the same job never piles up copies of the same path
    assert ssh_targets.backups("ssh-nginx-1") == [f"{BACKUP_ROOT}/{JOB_ID}"]
