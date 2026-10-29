"""Writing, labelling, reloading and verifying a host deploy (Plan 3 Task 15).

Spec 6.4 steps 3–7, 9.6 and 10.2 scenarios 5, 6 and 8. Every assertion reads the running container through
``docker compose exec`` (``ssh_targets``): the bytes, owner, group, mode, inode and mtime on the target are
the evidence, never the code's own output. The job events ``ansible-runner`` writes under ``tmp_path/run``
are the evidence for *which* task ran and in which order.
"""

from __future__ import annotations

import hashlib
import json
from uuid import uuid4

from app.ansible.deploy import run_host_deploy
from app.models.enums import WebserverType
from tests.integration.conftest import JOB_ID, spki_of, task_starts, writes_of
from tests.integration.test_deploy_preflight import describe, web01_targets

WWW_CRT = "/etc/nginx/ssl/www.crt"
WWW_KEY = "/etc/nginx/ssl/www.key"
LEGACY_KEY = "/etc/nginx/ssl/legacy.key"
WWW_VHOST = "www.example.internal"
LEGACY_VHOST = "legacy.example.internal"
APACHE_CRT = "/etc/apache2/ssl/www.crt"
APACHE_CHAIN = "/etc/apache2/ssl/www.chain.pem"
APACHE_KEY = "/etc/apache2/ssl/www.key"
BACKUP_ROOT = "/var/backups/cert-dashboard"


def seed_backup(ssh_targets, service: str, name: str, *, created_at: str, paths: tuple[str, ...]) -> None:
    """Seed one old backup directory the retention tool can read (a manifest plus one file per path)."""
    directory = f"{BACKUP_ROOT}/{name}"
    ssh_targets.exec(service, "mkdir", "-p", f"{directory}/etc/nginx/ssl")
    files: dict[str, dict[str, object]] = {}
    for path in paths:
        content = f"backup {name} of {path}\n".encode()
        ssh_targets.put(service, f"{directory}{path}", content, mode=0o644)
        files[path] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "fingerprint": "",
            "owner": "root",
            "group": "root",
            "mode": "0644",
            "size": len(content),
        }
    manifest = {"job_id": name, "created_at": created_at, "files": files}
    ssh_targets.put(service, f"{directory}/manifest.json", json.dumps(manifest).encode(), mode=0o600)


def test_deploy_writes_once_and_verifies(ssh_targets, fresh_targets, deploy_material, tmp_path):
    targets = web01_targets(deploy_material, ssh_targets.old.fingerprint)
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, targets,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (outcome.status, outcome.rolled_back, outcome.precheck["step"]) == (
        "succeeded", False, "verified"), describe(outcome)  # fmt: skip
    # D1: nginx has no chain_path, so the certificate file carries leaf + chain and no chain file is written
    assert ssh_targets.read("ssh-nginx-1", WWW_CRT) == deploy_material.fullchain_pem
    written_files = outcome.precheck["files"]
    assert isinstance(written_files, dict)
    assert sorted(written_files) == sorted((WWW_CRT, WWW_KEY, LEGACY_KEY))
    assert ssh_targets.stat("ssh-nginx-1", WWW_CRT)[:3] == (0o644, "root", "root")
    for key in (WWW_KEY, LEGACY_KEY):
        assert spki_of(ssh_targets.read("ssh-nginx-1", key)) == deploy_material.spki_sha256
        assert ssh_targets.stat("ssh-nginx-1", key)[:3] == (0o600, "root", "root")
    for vhost in (WWW_VHOST, LEGACY_VHOST):
        assert ssh_targets.served_fingerprint("ssh-nginx-1", vhost) == deploy_material.fingerprint
    verify = outcome.verify
    assert verify is not None
    assert verify["attempts"] == 1 and verify["chain_length"] == deploy_material.served_chain_length
    assert all(record.get("written") is True for record in outcome.targets.values())
    assert writes_of(outcome, WWW_CRT) == 1  # written once, for both bindings
    # no temporary file is left behind next to a live file
    listing = ssh_targets.exec("ssh-nginx-1", "ls", "-a", "/etc/nginx/ssl").stdout.split()
    assert not [name for name in listing if "cert-dashboard" in name]
    # the backup of this job stays on the host for manual recovery
    assert ssh_targets.backups("ssh-nginx-1") == [f"{BACKUP_ROOT}/{JOB_ID}"]


def test_stale_temp_files_do_not_survive_into_the_live_files(ssh_targets, fresh_targets, deploy_material, tmp_path):
    # An interrupted attempt can leave a nonempty temp file next to a live path, and `file: state=touch` never
    # empties one: the write path removes it before creating its own empty temp (Contract decision 17).
    stale = b"stale content from an interrupted deploy\n"
    for path in (WWW_CRT, WWW_KEY, LEGACY_KEY):
        directory, name = path.rsplit("/", 1)
        ssh_targets.put("ssh-nginx-1", f"{directory}/.{name}.cert-dashboard.tmp", stale, mode=0o644)
    targets = web01_targets(deploy_material, ssh_targets.old.fingerprint)
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, targets,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (outcome.status, outcome.precheck["step"]) == ("succeeded", "verified"), describe(outcome)
    assert ssh_targets.read("ssh-nginx-1", WWW_CRT) == deploy_material.fullchain_pem
    assert stale not in ssh_targets.read("ssh-nginx-1", WWW_CRT)
    for key in (WWW_KEY, LEGACY_KEY):
        assert spki_of(ssh_targets.read("ssh-nginx-1", key)) == deploy_material.spki_sha256
        assert stale not in ssh_targets.read("ssh-nginx-1", key)
    listing = ssh_targets.exec("ssh-nginx-1", "ls", "-a", "/etc/nginx/ssl").stdout.split()
    assert not [name for name in listing if "cert-dashboard" in name]
    starts = task_starts(tmp_path / "run")
    remove = "Remove any stale temporary file of every changed path"
    assert starts.count(remove) == 1, "removed once for every changed path, before the temp file is created"
    assert starts.index(remove) < starts.index("Fill every temporary file with its new content")


def test_config_test_failure_restores_every_file_byte_for_byte(ssh_targets, fresh_targets, deploy_material, tmp_path):
    before = {
        path: (ssh_targets.read("ssh-nginx-1", path), ssh_targets.stat("ssh-nginx-1", path))
        for path in (WWW_CRT, WWW_KEY)
    }
    # §6.4: only the www binding is deployed, so the shared www.crt no longer matches legacy.key and
    # `nginx -t` fails after the write — the rollback must undo what the write phase already changed.
    only_www = [
        deploy_material.target(
            binding_id=1, cert_path=WWW_CRT, key_path=WWW_KEY, port=18443, sni=WWW_VHOST,
            expected=ssh_targets.old.fingerprint,
        )
    ]  # fmt: skip
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, only_www,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (outcome.status, outcome.reason, outcome.rolled_back, outcome.rollback_error) == (
        "rolled_back", "config_test_failed", True, None), describe(outcome)  # fmt: skip
    assert outcome.precheck["step"] == "rolled_back"
    for path, (data, stat) in before.items():
        after = ssh_targets.stat("ssh-nginx-1", path)
        assert ssh_targets.read("ssh-nginx-1", path) == data and after[:3] == stat[:3]
    assert ssh_targets.served_fingerprint("ssh-nginx-1", WWW_VHOST) == ssh_targets.old.fingerprint
    listing = ssh_targets.exec("ssh-nginx-1", "ls", "-a", "/etc/nginx/ssl").stdout.split()
    assert not [name for name in listing if "cert-dashboard" in name]


def test_idempotent_rerun_writes_nothing_and_still_verifies(ssh_targets, fresh_targets, deploy_material, tmp_path):
    # §10.2 scenario 8: the same deploy twice; the second run is a no-op that still verifies.
    targets = web01_targets(deploy_material, ssh_targets.old.fingerprint)
    first = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, targets,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert first.status == "succeeded", describe(first)
    before = {path: ssh_targets.stat("ssh-nginx-1", path) for path in (WWW_CRT, WWW_KEY, LEGACY_KEY)}
    second = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, targets,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (second.status, second.precheck["step"]) == ("succeeded", "verified"), describe(second)
    # same inode and mtime: the file was not rewritten, and neither was its metadata
    assert {path: ssh_targets.stat("ssh-nginx-1", path) for path in before} == before
    assert not any(record.get("written") for record in second.targets.values())
    assert writes_of(second, WWW_CRT) == 0 and writes_of(second, WWW_KEY) == 0
    verify = second.verify
    assert verify is not None and verify["attempts"] == 1, "config test, reload and verification still ran"
    assert ssh_targets.served_fingerprint("ssh-nginx-1", WWW_VHOST) == deploy_material.fingerprint


def test_apache_leaf_and_chain_files_and_preserved_stricter_mode(
    ssh_targets, fresh_targets, deploy_material, ca, tmp_path
):
    # D1: the Apache binding has a chain_path, so the leaf goes to www.crt and the chain to www.chain.pem.
    # A stricter mode on the leaf (0640) must survive: the write keeps `old_mode & 0o644`. The fixture issues
    # the old and the new leaf from the same CA, so the staged chain equals the live one; a different valid
    # chain (intermediate + root) is installed first so the chain write is exercised rather than skipped.
    ssh_targets.put("ssh-apache", APACHE_CRT, ssh_targets.old.cert_pem, mode=0o640)
    ssh_targets.put("ssh-apache", APACHE_CHAIN, ca.chain_with_root_pem, mode=0o644)
    targets = [
        deploy_material.target(
            binding_id=9, cert_path=APACHE_CRT, chain_path=APACHE_CHAIN, key_path=APACHE_KEY,
            port=18445, sni=WWW_VHOST, expected=ssh_targets.old.fingerprint,
        )
    ]  # fmt: skip
    outcome = run_host_deploy(
        deploy_material.runner(tmp_path), "web03.example.internal", WebserverType.APACHE, targets,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (outcome.status, outcome.reason) == ("succeeded", None), describe(outcome)
    assert ssh_targets.read("ssh-apache", APACHE_CRT) == deploy_material.cert_pem
    assert ssh_targets.read("ssh-apache", APACHE_CHAIN) == deploy_material.chain_pem
    assert ssh_targets.stat("ssh-apache", APACHE_CRT)[:3] == (0o640, "root", "root")
    assert ssh_targets.stat("ssh-apache", APACHE_CHAIN)[:3] == (0o644, "root", "root")
    assert ssh_targets.stat("ssh-apache", APACHE_KEY)[:3] == (0o600, "root", "root")
    assert spki_of(ssh_targets.read("ssh-apache", APACHE_KEY)) == deploy_material.spki_sha256
    assert writes_of(outcome, APACHE_CRT) == 1 and writes_of(outcome, APACHE_CHAIN) == 1
    assert writes_of(outcome, APACHE_KEY) == 1
    assert ssh_targets.served_fingerprint("ssh-apache", WWW_VHOST) == deploy_material.fingerprint


def test_old_backups_are_pruned_but_the_newest_per_path_is_kept(ssh_targets, fresh_targets, deploy_material, tmp_path):
    # Two backups past retention: one this deploy supersedes for every path it holds, one that still holds
    # the newest copy of a path this deploy does not touch (so it must never be pruned away).
    seed_backup(
        ssh_targets, "ssh-nginx-1", "old-superseded",
        created_at="2000-01-01T00:00:00Z", paths=(WWW_CRT, WWW_KEY, LEGACY_KEY),
    )  # fmt: skip
    seed_backup(
        ssh_targets, "ssh-nginx-1", "old-unique",
        created_at="2000-01-01T00:00:00Z", paths=(WWW_CRT, "/etc/nginx/ssl/retired.crt"),
    )  # fmt: skip
    seeded = {f"{BACKUP_ROOT}/old-superseded", f"{BACKUP_ROOT}/old-unique"}
    only_www = [
        deploy_material.target(
            binding_id=1, cert_path=WWW_CRT, key_path=WWW_KEY, port=18443, sni=WWW_VHOST,
            expected=ssh_targets.old.fingerprint,
        )
    ]  # fmt: skip
    rolled_back = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX, only_www,
        deploy_material.staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert rolled_back.status == "rolled_back", describe(rolled_back)
    assert seeded <= set(ssh_targets.backups("ssh-nginx-1")), "a host that did not verify prunes nothing"
    full = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX,
        web01_targets(deploy_material, ssh_targets.old.fingerprint), deploy_material.staged,
        job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert full.status == "succeeded", describe(full)
    backups = set(ssh_targets.backups("ssh-nginx-1"))
    assert f"{BACKUP_ROOT}/old-superseded" not in backups, "superseded for every one of its paths"
    assert f"{BACKUP_ROOT}/old-unique" in backups, "still the newest backup of retired.crt"
    assert f"{BACKUP_ROOT}/{JOB_ID}" in backups


def test_no_secret_in_artifacts_or_excerpt_on_the_write_path(ssh_targets, fresh_targets, deploy_material, tmp_path):
    key_pem = deploy_material.staged.key_pem.read_bytes()
    body = key_pem.splitlines()[1]
    only_www = [
        deploy_material.target(
            binding_id=1, cert_path=WWW_CRT, key_path=WWW_KEY, port=18443, sni=WWW_VHOST,
            expected=ssh_targets.old.fingerprint,
        )
    ]  # fmt: skip
    # a rollback restores the key from its backup: that task must be censored too. It runs first, while the
    # host still has the old material that makes the partial deploy's config test fail.
    restored = run_host_deploy(
        deploy_material.runner(tmp_path / "rollback"), "web01.example.internal", WebserverType.NGINX,
        only_www, deploy_material.staged, job_id=uuid4(), retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert (restored.status, restored.reason) == ("rolled_back", "config_test_failed"), describe(restored)
    written = run_host_deploy(
        deploy_material.runner(tmp_path), "web01.example.internal", WebserverType.NGINX,
        web01_targets(deploy_material, ssh_targets.old.fingerprint), deploy_material.staged,
        job_id=JOB_ID, retention_days=30, timeout_seconds=600,
    )  # fmt: skip
    assert written.status == "succeeded", describe(written)
    for run in (written, restored):
        assert "PRIVATE KEY" not in run.log_excerpt and body.decode() not in run.log_excerpt
    for root in (tmp_path / "run", tmp_path / "rollback" / "run"):
        artifacts = [path for path in root.rglob("*") if path.is_file()]
        assert artifacts
        for path in artifacts:
            content = path.read_bytes()
            assert b"PRIVATE KEY" not in content, f"key material reached {path}"
            assert body not in content, f"key material reached {path}"
    # the staged key itself is the only copy, and it lives outside every run directory
    assert deploy_material.staged.key_pem.is_file()
    assert not any(run in deploy_material.staged.key_pem.parents for run in (tmp_path / "run",))
