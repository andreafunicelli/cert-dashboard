"""Preflight, backup and the write path of a host deploy (Plan 3 Tasks 14–15; spec 6.4 steps 1–3).

These tests never inspect the code's own output: they read, stat and fingerprint the running containers
through ``docker compose exec`` (``ssh_targets``), so "nothing changed" means the bytes, inode, mode and
owner on the target are untouched.

Task 14's playbook stopped after the backup, so every passing preflight ended ``failed``/``internal``; from
Task 15 the same run goes on to write, reload and verify, so a passing preflight ends ``succeeded``. The
boundary that remains — and that this file still proves — is that the backup of every affected file is
complete and matches its manifest **before** the first live write starts.
"""

import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.ansible.deploy import run_host_deploy
from app.models.enums import WebserverType
from tests.integration.conftest import JOB_ID, task_starts

WWW_CRT = "/etc/nginx/ssl/www.crt"
WWW_KEY = "/etc/nginx/ssl/www.key"
LEGACY_KEY = "/etc/nginx/ssl/legacy.key"
WWW_VHOST = "www.example.internal"
LEGACY_VHOST = "legacy.example.internal"
BACKUP_ROOT = "/var/backups/cert-dashboard"
PRUNE_SCRIPT = Path(__file__).resolve().parents[2] / "app" / "ansible" / "playbooks" / "files" / "prune_backups.py"


def load_prune_script():
    """Load the standalone target-side script the retention step (Task 15) will run."""
    spec = importlib.util.spec_from_file_location("prune_backups_under_test", PRUNE_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def describe(outcome) -> str:
    """Everything a failing assertion needs: the outcome, the published diagnostics and the log tail."""
    precheck = outcome.precheck
    return (
        f"status={outcome.status} reason={outcome.reason} message={outcome.message} "
        f"step={precheck.get('step')} failed_task={precheck.get('failed_task')} "
        f"hash_rc={precheck.get('hash_rc')} hash_stderr={precheck.get('hash_stderr')!r} "
        f"hash_msg={precheck.get('hash_msg')!r} hash_module_stderr={precheck.get('hash_module_stderr')!r} "
        f"hash_failed={precheck.get('hash_failed')!r} backup_dir={outcome.backup_dir}\n"
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


def test_backup_is_complete_before_the_first_write(ssh_targets, fresh_targets, deploy_material, tmp_path):
    live = ("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "/etc/nginx/ssl/legacy.key")
    before = {path: (ssh_targets.read("ssh-nginx-1", path), ssh_targets.stat("ssh-nginx-1", path)) for path in live}
    targets = web01_targets(deploy_material, ssh_targets.old.fingerprint)
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, targets,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (outcome.status, outcome.reason, outcome.precheck["step"]) == (
        "succeeded", None, "verified"), describe(outcome)  # fmt: skip
    assert ssh_targets.served_fingerprint("ssh-nginx-1", WWW_VHOST) == deploy_material.fingerprint
    backup = f"/var/backups/cert-dashboard/{JOB_ID}"
    assert ssh_targets.stat("ssh-nginx-1", backup)[:3] == (0o700, "root", "root")
    # every backup holds the bytes that were live before this run, not the new material
    assert ssh_targets.read("ssh-nginx-1", backup + "/etc/nginx/ssl/www.crt") == ssh_targets.old.fullchain_pem
    assert ssh_targets.stat("ssh-nginx-1", backup + "/etc/nginx/ssl/legacy.key").mode == 0o600
    manifest = json.loads(ssh_targets.read("ssh-nginx-1", backup + "/manifest.json"))
    assert sorted(manifest["files"]) == sorted(live) and manifest["job_id"] == str(JOB_ID)  # www.crt once
    assert manifest["created_at"].endswith("Z")
    assert manifest["files"][WWW_CRT]["fingerprint"] == ssh_targets.old.fingerprint
    assert manifest["files"][WWW_CRT]["owner"] == "root" and manifest["files"][WWW_CRT]["mode"] == "0644"
    for path, (data, stat) in before.items():
        assert manifest["files"][path]["sha256"] == hashlib.sha256(data).hexdigest()
        assert manifest["files"][path]["size"] == stat.size
    # the backup is checked against its manifest before anything live is replaced: the assert task
    # finishes before the first write task starts
    starts = task_starts(tmp_path / "run")
    backup_assert = starts.index("Refuse to go on when a backup is missing or does not match its manifest")
    first_write = starts.index("Create the empty temporary file of every changed path with its final metadata")
    assert backup_assert < first_write
    # The manifest this run wrote must be one the retention tool can read (Task 15 runs it): an over-strict
    # pruner would keep every backup forever. A synthetic newer manifest of the same paths makes this one
    # removable, so an empty plan below means the real manifest is unusable.
    pruner = load_prune_script()
    newer = {**manifest, "job_id": "newer", "created_at": "2999-01-01T00:00:00Z"}
    later = datetime(3000, 1, 1, tzinfo=UTC)
    assert pruner.prune_plan({str(JOB_ID): manifest, "newer": newer}, later, 30) == [str(JOB_ID)]


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
    assert (outcome.status, outcome.precheck["step"]) == ("succeeded", "verified"), describe(outcome)
    backup = f"{BACKUP_ROOT}/{job}"
    manifest = json.loads(ssh_targets.read("ssh-apache", backup + "/manifest.json"))
    assert sorted(manifest["files"]) == sorted(live)
    assert ssh_targets.stat("ssh-apache", backup + "/etc/apache2/ssl/www.key")[:3] == (0o600, "root", "root")
    assert ssh_targets.read("ssh-apache", backup + "/etc/apache2/ssl/www.chain.pem") == ssh_targets.old.chain_pem
    assert ssh_targets.read("ssh-apache", backup + "/etc/apache2/ssl/www.crt") == ssh_targets.old.cert_pem
    for path in ("/etc/apache2/ssl/www.crt", "/etc/apache2/ssl/www.chain.pem"):
        assert ssh_targets.stat("ssh-apache", backup + path).mode & 0o777 <= 0o644
        assert ssh_targets.stat("ssh-apache", backup + path)[1:3] == ("root", "root")


def test_backup_mode_is_the_bitmask_of_the_original(ssh_targets, fresh_targets, deploy_material, tmp_path):
    """Contract decision 17 / Task 14: the copy keeps exactly ``original & 0o644``.

    Only the mode of the live certificate changes (its bytes stay the discovery snapshot), so each run is a
    normal happy-path preflight. Digit clamping instead of the bitmask would copy 0500 and 0620 unchanged.
    """
    targets = web01_targets(deploy_material, ssh_targets.old.fingerprint)
    for original in (0o500, 0o620, 0o711):
        # Every iteration starts from the pristine target: the previous run deployed the new key material, so
        # writing the old certificate back without the old keys would break `nginx -t` before the backup.
        ssh_targets.reset("ssh-nginx-1")
        ssh_targets.put("ssh-nginx-1", WWW_CRT, ssh_targets.old.fullchain_pem, mode=original)
        job = uuid4()
        outcome = run_host_deploy(
            deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, targets,
            deploy_material.staged, job_id=job, retention_days=30, timeout_seconds=600,
        )  # fmt: skip
        assert outcome.precheck["step"] == "verified", describe(outcome)
        backup = f"{BACKUP_ROOT}/{job}"
        copied = ssh_targets.stat("ssh-nginx-1", backup + WWW_CRT)
        assert copied.mode == original & 0o644, f"{original:04o} -> {copied.mode:04o}"
        assert copied[1:3] == ("root", "root")
        # the manifest records what was there (the original mode), not what was copied
        manifest = json.loads(ssh_targets.read("ssh-nginx-1", backup + "/manifest.json"))
        assert manifest["files"][WWW_CRT]["mode"] == f"{original:04o}"
        assert manifest["files"][WWW_CRT]["size"] == len(ssh_targets.old.fullchain_pem)


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
    assert outcome.precheck["step"] == "verified", describe(outcome)

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
    assert first.precheck["step"] == second.precheck["step"] == "verified", describe(second)
    manifest = json.loads(
        ssh_targets.read("ssh-nginx-1", f"{BACKUP_ROOT}/{JOB_ID}/manifest.json")
    )
    assert sorted(manifest["files"]) == sorted((WWW_CRT, WWW_KEY, LEGACY_KEY))
    # the second run backed up the content the first run wrote and then wrote nothing itself
    assert ssh_targets.read("ssh-nginx-1", f"{BACKUP_ROOT}/{JOB_ID}" + WWW_CRT) == ssh_targets.read(
        "ssh-nginx-1", WWW_CRT
    )
    # the job id names the directory, so a re-run of the same job never piles up copies of the same path
    assert ssh_targets.backups("ssh-nginx-1") == [f"{BACKUP_ROOT}/{JOB_ID}"]
