import json
import posixpath
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def compose(name="docker-compose.yml"):
    path = ROOT / name
    assert path.exists(), f"Missing runtime topology: {name}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def secret_targets(service):
    return {s if isinstance(s, str) else s.get("target", s["source"]) for s in service.get("secrets", [])}


def test_web_has_no_ssh_credentials_or_worker_volumes():
    cfg = compose()
    web = cfg["services"]["web"]
    assert set(cfg["services"]) == {"web", "worker", "db"}
    assert secret_targets(web) == {"master_key", "db_password", "session_secret"}
    assert not web.get("volumes")
    assert web["ports"] == ["127.0.0.1:8000:8000"]
    assert "ports" not in cfg["services"]["worker"]
    assert "ports" not in cfg["services"]["db"]


def test_worker_decrypted_keys_are_tmpfs_only():
    worker = compose()["services"]["worker"]
    mount = next(x for x in worker["tmpfs"] if x.startswith("/run/cert-keys:"))
    assert {"size=16m", "mode=0700", "uid=10001", "gid=10001", "noexec", "nosuid", "nodev"} <= set(mount.split(":", 1)[1].split(","))
    assert worker["volumes"] == ["inventory:/srv/inventory", "artifacts:/srv/artifacts"]
    assert worker["command"] == ["python", "-m", "app.jobs.worker"]


def test_application_services_are_hardened():
    services = compose()["services"]
    for name in ("web", "worker"):
        svc = services[name]
        assert svc["user"] == "10001:10001"
        assert svc["read_only"] is True
        assert svc["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in svc["security_opt"]
        assert svc["mem_limit"]
        assert svc["restart"] == "unless-stopped"
        assert svc["logging"]["options"] == {"max-size": "50m", "max-file": "5"}
    assert services["web"]["image"] == services["worker"]["image"]
    assert services["web"]["command"] == ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--no-access-log"]


def test_owner_secret_only_reaches_db_or_one_shot_migration():
    cfg = compose()
    assert secret_targets(cfg["services"]["db"]) == {"db_password", "db_owner_password"}
    for name in ("web", "worker"):
        assert "db_owner_password" not in secret_targets(cfg["services"][name])
    migration_services = compose("docker-compose.migrate.yml")["services"]
    assert set(migration_services) == {"migrate"}
    migrate = migration_services["migrate"]
    assert migrate["environment"]["DB_USER"] == "db_owner"
    assert {x["source"] for x in migrate["secrets"]} == {"db_owner_password"}
    assert {x["target"] for x in migrate["secrets"]} == {"db_password"}


def test_credentials_override_only_mounts_into_worker():
    cfg = compose("docker-compose.credentials.yml")
    assert set(cfg["services"]) == {"worker"}
    assert secret_targets(cfg["services"]["worker"]) == {"ansible_ssh_key", "ansible_vault_password", "inventory_git_token", "smtp_password"}
    assert all("mode" not in secret for secret in cfg["services"]["worker"]["secrets"])


def test_compose_never_promises_unsupported_secret_permission_remapping():
    for name in ("docker-compose.yml", "docker-compose.credentials.yml", "docker-compose.migrate.yml", "docker-compose.test.yml"):
        for svc in compose(name)["services"].values():
            assert all("mode" not in secret for secret in svc.get("secrets", []) if isinstance(secret, dict))
    migration = compose("docker-compose.migrate.yml")["services"]["migrate"]
    assert migration["user"] == "999:999"


def test_line_endings_and_build_context_exclude_secrets():
    attrs = ROOT / ".gitattributes"
    assert attrs.exists(), "Missing LF enforcement"
    rules = {line.split()[0]: line.split()[1:] for line in attrs.read_text().splitlines() if line.strip() and not line.startswith("#")}
    for pattern in ("*.py", "*.yml", "*.yaml", "*.sh", "*.j2", "*.cfg", "Dockerfile"):
        assert "eol=lf" in rules[pattern]
    excluded = (ROOT / ".dockerignore").read_text().splitlines()
    assert "secrets/" in excluded and ".venv/" in excluded and ".git/" in excluded


def test_compose_secrets_are_file_references_without_values():
    cfg = compose()
    for secret in cfg["secrets"].values():
        assert set(secret) == {"file"}
        assert "/etc/cert-dashboard/secrets/" in secret["file"]
    for svc in cfg["services"].values():
        for key in svc.get("environment", {}):
            assert key not in {"DB_PASSWORD", "MASTER_KEY", "SESSION_SECRET", "POSTGRES_PASSWORD"}


def test_test_stack_contains_real_postgres_and_application_image():
    cfg = compose("docker-compose.test.yml")
    assert cfg["services"]["db"]["image"].startswith("postgres:16-bookworm@sha256:")
    assert cfg["services"]["app"]["build"]["target"] == "test"
    assert cfg["services"]["app"]["environment"]["DB_HOST"] == "db"


TARGET_SERVICES = {"tls-nginx", "tls-apache", "smtp"}


def test_test_targets_are_pinned_profiled_and_loopback_only():
    for name in ("docker-compose.yml", "docker-compose.credentials.yml", "docker-compose.migrate.yml"):
        cfg = compose(name)
        assert not TARGET_SERVICES & set(cfg["services"]), f"test targets leaked into {name}"
        assert "targets" not in yaml.safe_dump(cfg)
    services = compose("docker-compose.test.yml")["services"]
    targets = {name: services[name] for name in TARGET_SERVICES}
    for name, svc in targets.items():
        assert svc["profiles"] == ["targets"], name
        assert "network_mode" not in svc and "secrets" not in svc, name
        assert "build" not in svc, name  # no build of external content: images are pulled by digest or prebuilt
        assert svc["ports"] and all(re.fullmatch(r"127\.0\.0\.1::\d+", port) for port in svc["ports"]), name
        assert not any(
            key.upper().endswith(("PASSWORD", "SECRET", "TOKEN", "KEY")) for key in svc.get("environment", {})
        ), name
    assert re.fullmatch(r"nginx:[\w.-]+@sha256:[0-9a-f]{64}", targets["tls-nginx"]["image"])
    assert re.fullmatch(r"httpd:[\w.-]+@sha256:[0-9a-f]{64}", targets["tls-apache"]["image"])
    for name in ("tls-nginx", "tls-apache"):
        volumes = targets[name]["volumes"]
        assert targets[name]["ports"] == ["127.0.0.1::8443"]
        assert all(volume.endswith(":ro") for volume in volumes), name
        assert f"${{TLS_TARGET_DIR:-./secrets/test/tls-targets}}/{name}:/etc/certs:ro" in volumes
        configs = [v for v in volumes if v.startswith("./tests/fixtures/targets/")]
        assert len(configs) == 1 and (ROOT / configs[0].split(":")[0]).is_file(), name
    smtp = targets["smtp"]
    assert smtp["image"] == "cert-dashboard:test" and smtp["user"] == "10001:10001"
    assert smtp["read_only"] is True and smtp["cap_drop"] == ["ALL"]
    assert smtp["command"] == ["python", "-m", "tests.fixtures.smtp_capture", "--listen", "0.0.0.0:1025", "--spool", "/spool"]
    assert smtp["tmpfs"] == ["/spool"] and smtp["ports"] == ["127.0.0.1::1025"]


SSH_TARGETS = {"ssh-nginx-1": ("nginx", 18443), "ssh-nginx-2": ("nginx", 18444), "ssh-apache": ("apache", 18445)}
FIXTURE_BIND = "${SSH_TARGET_DIR:-./secrets/test/ssh-targets}/%s:/fixture:ro"


def test_ssh_targets_are_pinned_profiled_and_loopback_only():
    for name in ("docker-compose.yml", "docker-compose.credentials.yml", "docker-compose.migrate.yml"):
        cfg = compose(name)
        assert not set(SSH_TARGETS) & set(cfg["services"]), f"SSH targets leaked into {name}"
        assert "ssh-targets" not in yaml.safe_dump(cfg)
    dockerfile = (ROOT / "tests/fixtures/targets/Dockerfile").read_text()
    pinned = re.findall(r"^FROM debian:bookworm-slim@sha256:[0-9a-f]{64}$", dockerfile, re.MULTILINE)
    assert len(pinned) == 1 and re.findall(r"^FROM .*$", dockerfile, re.MULTILINE) == pinned
    cfg = compose("docker-compose.test.yml")
    assert cfg["networks"]["ssh-targets"]["driver"] == "bridge"
    for name, (webserver, tls_port) in SSH_TARGETS.items():
        svc = cfg["services"][name]
        assert svc["profiles"] == ["ssh-targets"], name
        assert svc["init"] is True and svc["networks"] == ["ssh-targets"], name
        assert svc["image"] == f"cert-dashboard-target:{webserver}", name
        for forbidden in ("secrets", "privileged", "network_mode", "cap_add", "devices", "pid", "ipc"):
            assert forbidden not in svc, f"{name}: {forbidden}"
        assert svc["ports"] == ["127.0.0.1::22", f"127.0.0.1:{tls_port}:{tls_port}"], name
        assert svc["volumes"] == [FIXTURE_BIND % name], name
        assert svc["environment"]["TARGET_TLS_PORT"] == str(tls_port), name
        assert not any(
            key.upper().endswith(("PASSWORD", "SECRET", "TOKEN", "KEY")) for key in svc["environment"]
        ), name
        health = " ".join(svc["healthcheck"]["test"])
        process = "nginx" if webserver == "nginx" else "apache2"
        assert "pgrep -x sshd" in health and f"pgrep -x {process}" in health, name
    builds = {name: svc["build"] for name, svc in cfg["services"].items() if name in SSH_TARGETS and "build" in svc}
    assert builds == {
        name: {"context": "./tests/fixtures/targets", "args": {"WEBSERVER": webserver}}
        for name, webserver in (("ssh-nginx-1", "nginx"), ("ssh-apache", "apache"))
    }


def test_ci_builds_ssh_target_images_after_the_pull_and_before_pytest():
    path = ROOT / ".github/workflows/ci.yml"
    if not path.exists():
        pytest.skip("CI workflow checked in the host checkout")
    commands = [step.get("run", "") for step in yaml.safe_load(path.read_text())["jobs"]["verify"]["steps"]]
    pull = next(i for i, c in enumerate(commands) if "--profile targets pull" in c)
    build = next(i for i, c in enumerate(commands) if "--profile ssh-targets build" in c)
    pytest_run = next(i for i, c in enumerate(commands) if "pytest" in c and not c.startswith("docker run"))
    assert pull < build < pytest_run
    assert commands[build].startswith("docker compose -f docker-compose.test.yml --profile ssh-targets build")
    assert "docker compose -f docker-compose.test.yml --profile ssh-targets config --quiet" in commands


def test_htmx_is_packaged_for_offline_runtime():
    import hashlib

    path = ROOT / "app/static/htmx.min.js"
    assert path.exists(), "Missing vendored htmx runtime"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == "22283ef68cb7545914f0a88a1bdedc7256a703d1d580c1d255217d0a50d31313"
    assert (ROOT / "app/static/htmx.LICENSE").exists()


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker CLI required; run authoritative suite in Linux")
def test_rendered_migration_has_exactly_one_password_source():
    result = subprocess.run(
        ["docker", "compose", "--profile", "*", "-f", "docker-compose.yml", "-f", "docker-compose.migrate.yml", "config", "--format", "json"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    cfg = json.loads(result.stdout)
    migrate = cfg["services"].get("migrate")
    assert migrate is not None, "Migrations require their own service"
    assert [(secret_path(s["target"]), s["source"]) for s in migrate["secrets"]] == [
        ("/run/secrets/db_password", "db_owner_password")
    ]
    assert migrate["image"] == cfg["services"]["web"]["image"]
    assert migrate["user"] == "999:999" and migrate["read_only"] is True
    assert migrate["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in migrate["security_opt"]
    assert not migrate.get("ports")
    assert migrate["command"] == ["alembic", "upgrade", "head"]
    assert migrate["environment"]["DB_USER"] == "db_owner"


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker CLI required; run authoritative suite in Linux")
def test_rendered_ssh_targets_publish_loopback_only_and_mount_one_read_only_bind():
    result = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.test.yml", "--profile", "ssh-targets", "config", "--format", "json"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    services = json.loads(result.stdout)["services"]
    for name, (_, tls_port) in SSH_TARGETS.items():
        svc = services[name]
        assert [(p["host_ip"], p["target"], str(p["published"]) if p.get("published") else None) for p in svc["ports"]] == [
            ("127.0.0.1", 22, None), ("127.0.0.1", tls_port, str(tls_port))
        ], name
        assert svc["init"] is True and list(svc["networks"]) == ["ssh-targets"], name
        assert [(v["type"], v["target"], v.get("read_only")) for v in svc["volumes"]] == [("bind", "/fixture", True)], name
        assert not svc.get("privileged") and not svc.get("cap_add") and not svc.get("secrets"), name
        assert svc.get("network_mode") is None, name


def secret_path(target):
    return posixpath.normpath(target if target.startswith("/") else "/run/secrets/" + target)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker CLI required; run authoritative suite in Linux")
@pytest.mark.parametrize("files", [
    ["docker-compose.yml"],
    ["docker-compose.yml", "docker-compose.credentials.yml"],
    ["docker-compose.yml", "docker-compose.migrate.yml"],
    ["docker-compose.yml", "docker-compose.credentials.yml", "docker-compose.migrate.yml"],
    ["docker-compose.test.yml"],
])
@pytest.mark.parametrize("profile", ["*", "targets", "ssh-targets"])
def test_rendered_services_never_mount_two_secrets_at_the_same_path(files, profile):
    command = ["docker", "compose", "--profile", profile]
    for name in files:
        command.extend(["-f", name])
    result = subprocess.run(command + ["config", "--format", "json"], cwd=ROOT,
                            capture_output=True, text=True, check=True)
    for name, service in json.loads(result.stdout)["services"].items():
        targets = [secret_path(s.get("target", s["source"])) for s in service.get("secrets", [])]
        assert len(targets) == len(set(targets)), f"Duplicate secret path in {files}: {name}: {targets}"


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="Git mode checked in the host checkout")
def test_postgres_initializer_is_executable_in_git():
    result = subprocess.run(["git", "ls-files", "--stage", "--", "app/migrations/init_roles.sh"],
                            cwd=ROOT, capture_output=True, text=True, check=True)
    assert result.stdout.split()[0] == "100755"


def test_ci_container_smoke_runs_only_unit_tests():
    path = ROOT / ".github/workflows/ci.yml"
    if not path.exists():
        pytest.skip("CI workflow checked in the host checkout")
    workflow = yaml.safe_load(path.read_text())
    commands = [step.get("run", "") for step in workflow["jobs"]["verify"]["steps"]]
    smoke = [command for command in commands if command.startswith("docker run ")]
    assert smoke == ["docker run --rm cert-dashboard:test pytest -q tests/unit -p no:cacheprovider"]


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker CLI required; run authoritative suite in Linux")
def test_runtime_dump_client_matches_postgres16():
    result = subprocess.run(
        ["docker", "run", "--rm", "--pull=never", "--entrypoint", "pg_dump", "cert-dashboard:test", "--version"],
        capture_output=True, text=True, check=True,
    )
    assert result.stdout.startswith("pg_dump (PostgreSQL) 16.")


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker CLI required; run authoritative suite in Linux")
def test_install_secrets_applies_actual_owner_and_modes_in_isolated_container():
    script = ROOT / "scripts/install-secrets.sh"
    assert script.exists(), "Missing secret ownership installer"
    program = '''
import os, pathlib, subprocess, sys
p=pathlib.Path('/secrets')
names=['master_key','session_secret','db_password','db_owner_password','ansible_ssh_key']
for name in names: (p/name).write_bytes(b'test-only')
subprocess.run(['sh','/scripts/install-secrets.sh',str(p)],check=True)
expected={'master_key':(10001,10001,0o400),'session_secret':(10001,10001,0o400),
 'db_password':(10001,999,0o440),'db_owner_password':(999,999,0o400),
 'ansible_ssh_key':(10001,10001,0o400)}
for name,want in expected.items():
 s=(p/name).stat(); assert (s.st_uid,s.st_gid,s.st_mode & 0o777)==want
s=p.stat(); assert (s.st_uid,s.st_gid,s.st_mode & 0o777)==(0,0,0o711)
for uid,gid,allowed,denied in [(10001,10001,['master_key','db_password'],['db_owner_password']),
                              (999,999,['db_password','db_owner_password'],['master_key'])]:
 for name in allowed:
  r=subprocess.run([sys.executable,'-c',"from pathlib import Path; Path('/secrets/"+name+"').read_bytes()"],user=uid,group=gid,extra_groups=[],capture_output=True)
  assert r.returncode==0
 for name in denied:
  r=subprocess.run([sys.executable,'-c',"from pathlib import Path; Path('/secrets/"+name+"').read_bytes()"],user=uid,group=gid,extra_groups=[],capture_output=True)
  assert r.returncode!=0 and b'PermissionError' in r.stderr
print('secret ownership and modes verified')
'''
    result = subprocess.run(
        ["docker", "run", "--rm", "--pull=never", "--user", "0:0", "--read-only",
         "--tmpfs", "/secrets", "--mount", f"type=bind,src={ROOT / 'scripts'},dst=/scripts,readonly",
         "--entrypoint", "python", "cert-dashboard:test", "-c", program],
        capture_output=True, text=True, check=True,
    )
    assert "secret ownership and modes verified" in result.stdout


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker CLI required; run authoritative suite in Linux")
def test_database_bootstrap_limits_runtime_role_and_uses_distinct_owner_password(tmp_path):
    import os
    import secrets
    import uuid

    owner_password = secrets.token_urlsafe(32)
    app_password = "test-quote'and;special-" + secrets.token_urlsafe(32)
    for name, value in {"db_password": app_password, "db_owner_password": owner_password,
                        "master_key": "unused-test-key", "session_secret": "unused-test-session"}.items():
        (tmp_path / name).write_text(value)
        (tmp_path / name).chmod(0o444)
    env = {**os.environ, "TEST_SECRETS_DIR": str(tmp_path), "PGPASSWORD": app_password}
    command = ["docker", "compose", "-p", "certdash-task1-" + uuid.uuid4().hex[:10],
               "-f", "docker-compose.test.yml"]
    try:
        subprocess.run(command + ["up", "-d", "--wait", "--pull", "never", "db"],
                       cwd=ROOT, env=env, capture_output=True, text=True, check=True, timeout=90)
        address = subprocess.run(command + ["exec", "-T", "db", "hostname", "-i"],
                                 cwd=ROOT, env=env, capture_output=True, text=True, check=True).stdout.split()[0]
        psql = command + ["exec", "-T", "-e", "PGPASSWORD", "db", "psql", "-X", "-h", address,
                          "-U", "app_role", "-d", "cert_dashboard", "-Atc"]
        result = subprocess.run(psql + ["SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolreplication FROM pg_roles WHERE rolname=current_user"],
                                cwd=ROOT, env=env, capture_output=True, text=True, check=True)
        assert result.stdout.strip() == "app_role|f|f|f|f"
        for sql in ["SET ROLE db_owner", "CREATE TABLE should_be_denied(id int)"]:
            denied = subprocess.run(psql + [sql], cwd=ROOT, env=env, capture_output=True, text=True, check=False)
            assert denied.returncode != 0 and "permission denied" in denied.stderr
        owner_login = psql.copy()
        owner_login[owner_login.index("app_role")] = "db_owner"
        denied = subprocess.run(owner_login + ["SELECT 1"], cwd=ROOT, env=env, capture_output=True, text=True, check=False)
        assert denied.returncode != 0 and "password authentication failed" in denied.stderr
        owner_env = {**env, "PGPASSWORD": owner_password}
        allowed = subprocess.run(owner_login + ["SELECT 1"], cwd=ROOT, env=owner_env,
                                 capture_output=True, text=True, check=True)
        assert allowed.stdout.strip() == "1"
        backup = subprocess.run(
            ["docker", "run", "--rm", "--pull=never", "--network", command[3] + "_default", "-e", "PGPASSWORD",
             "--entrypoint", "sh", "cert-dashboard:test", "-c",
             "pg_dump -h db -U db_owner -d cert_dashboard -Fc -f /tmp/test.dump && pg_restore --list /tmp/test.dump"],
            cwd=ROOT, env=owner_env, capture_output=True, text=True, check=True,
        )
        assert "dbname: cert_dashboard" in backup.stdout
        uid = subprocess.run(command + ["exec", "-T", "db", "id", "postgres"],
                             cwd=ROOT, env=env, capture_output=True, text=True, check=True)
        assert "uid=999(postgres) gid=999(postgres)" in uid.stdout
    finally:
        subprocess.run(command + ["down", "--remove-orphans"], cwd=ROOT, env=env,
                       capture_output=True, text=True, check=True, timeout=30)
