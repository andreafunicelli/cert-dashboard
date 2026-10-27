import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from app.ansible.runner import (
    GIT_ASKPASS,
    LOG_EXCERPT_LINES,
    PLAYBOOK_DIR,
    VAULT_CLIENT,
    AnsibleRun,
    RunnerContext,
    RunnerSecrets,
    build_env,
    classify_unreachable,
    run_playbook,
    stage_runner_secrets,
)
from app.ansible.staging import StagingArea, StagingError

ROOT = Path(__file__).resolve().parents[2]
LOCAL_INVENTORY = ROOT / "tests/fixtures/ansible/local.ini"
PROBE = "tests/fixtures/ansible/probe.yml"


def write_vaulted_vars(path: Path, data: dict, password: str) -> None:
    from ansible.parsing.vault import VaultLib, VaultSecret

    lib = VaultLib([("default", VaultSecret(password.encode()))])
    path.write_bytes(lib.encrypt(json.dumps(data).encode()))


def write_playbook(path: Path, tasks: str, hosts: str = "all") -> Path:
    path.write_text(f"---\n- hosts: {hosts}\n  gather_facts: false\n  tasks:\n{tasks}")
    return path


def make_context(tmp_path: Path, secrets: RunnerSecrets, inventory: Path = LOCAL_INVENTORY) -> RunnerContext:
    return RunnerContext(secrets, inventory, tmp_path / "run", tmp_path / "artifacts")


def plain_secrets(tmp_path: Path, vault_password: bytes | None = None) -> RunnerSecrets:
    key = tmp_path / "ssh_key"
    key.write_bytes(b"unused")
    return RunnerSecrets(key, tmp_path / "known_hosts", vault_password)


def test_vault_password_and_hidden_output_never_reach_artifacts(tmp_path):
    password, vaulted = "vault-canary-6b1f", "vaulted-canary-93ad"
    write_vaulted_vars(tmp_path / "vars.yml", {"probe_secret": vaulted}, password)
    with StagingArea(tmp_path / "keys", uuid4()) as area:
        secrets = RunnerSecrets(area.write("ssh_key", b"unused"), tmp_path / "known_hosts", password.encode())
        context = RunnerContext(secrets, LOCAL_INVENTORY, tmp_path / "run", tmp_path / "artifacts")
        outcome = run_playbook(
            context,
            AnsibleRun(PROBE, None, {"vars_file": str(tmp_path / "vars.yml")}, timeout_seconds=120),
            ident="probe",
        )
    assert outcome.status == "successful"
    assert outcome.rc == 0
    assert {name: host.data["probe"] for name, host in outcome.hosts.items()} == {
        "localhost": "decrypted",
        "probe2": "decrypted",
    }
    assert "probe visible line" in outcome.log_excerpt and vaulted not in outcome.log_excerpt
    files = [path for path in (tmp_path / "run").rglob("*") if path.is_file()]
    assert files
    for path in files:
        content = path.read_bytes()
        assert password.encode() not in content, path
        assert vaulted.encode() not in content, path
    assert not (tmp_path / "keys").exists() or not any((tmp_path / "keys").iterdir())


def test_each_host_gets_its_own_result_and_excerpt(tmp_path):
    write_vaulted_vars(tmp_path / "vars.yml", {"probe_secret": "s"}, "pw")
    context = make_context(tmp_path, plain_secrets(tmp_path, b"pw"))
    outcome = run_playbook(
        context, AnsibleRun(PROBE, "probe2", {"vars_file": str(tmp_path / "vars.yml")}, 120), ident="one"
    )
    assert set(outcome.hosts) == {"probe2"}
    host = outcome.hosts["probe2"]
    assert host.outcome == "ok" and host.failed_task is None and host.hostname == "probe2"
    assert "probe visible line" in host.log_excerpt


def test_environment_is_explicit(tmp_path, monkeypatch):
    monkeypatch.setenv("ANSIBLE_STRATEGY", "free")
    monkeypatch.setenv("ANSIBLE_SSH_ARGS", "-o StrictHostKeyChecking=no")
    monkeypatch.setenv("ANSIBLE_CONFIG", "/tmp/evil.cfg")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("http_proxy", "http://proxy.invalid:3128")
    monkeypatch.setenv("PYTHONPATH", "/tmp/evil")
    monkeypatch.setenv("CERT_DASHBOARD_GIT_TOKEN", "must-not-leak")
    run_dir = tmp_path / "run"
    base = RunnerSecrets(tmp_path / "keys" / "ssh_key", tmp_path / "known hosts")

    env = build_env(base, run_dir)

    common = {
        "PATH",
        "HOME",
        "ANSIBLE_LOCAL_TEMP",
        "ANSIBLE_HOST_KEY_CHECKING",
        "ANSIBLE_SSH_ARGS",
        "ANSIBLE_PRIVATE_KEY_FILE",
        "ANSIBLE_NOCOLOR",
        "ANSIBLE_RETRY_FILES_ENABLED",
        "ANSIBLE_PYTHON_INTERPRETER",
        "ANSIBLE_DEPRECATION_WARNINGS",
        "ANSIBLE_COLLECTIONS_PATH",
    }
    assert set(env) == common
    assert env["PATH"].split(os.pathsep)[0] == str(Path(sys.executable).parent)
    assert Path(env["HOME"]).parent == run_dir and Path(env["ANSIBLE_LOCAL_TEMP"]).parent == run_dir
    assert Path(env["ANSIBLE_COLLECTIONS_PATH"]).parent == run_dir
    assert env["ANSIBLE_HOST_KEY_CHECKING"] == "True"
    assert env["ANSIBLE_PRIVATE_KEY_FILE"] == str(base.ssh_key)
    ssh_args = env["ANSIBLE_SSH_ARGS"]
    assert "-o StrictHostKeyChecking=yes" in ssh_args
    assert "-o IdentitiesOnly=yes" in ssh_args and "-o BatchMode=yes" in ssh_args
    assert f"UserKnownHostsFile={base.known_hosts}" in ssh_args or f"'{base.known_hosts}'" in ssh_args
    assert "StrictHostKeyChecking=no" not in ssh_args
    assert not [key for key in env if key.lower().endswith("_proxy")]
    assert "must-not-leak" not in "".join(env.values())

    with_vault = build_env(replace(base, vault_password=b"vault-canary"), run_dir)
    assert set(with_vault) == common | {"ANSIBLE_VAULT_PASSWORD_FILE", "CERT_DASHBOARD_VAULT_PASSWORD"}
    assert with_vault["CERT_DASHBOARD_VAULT_PASSWORD"] == "vault-canary"
    assert with_vault["ANSIBLE_VAULT_PASSWORD_FILE"] == str(VAULT_CLIENT)
    assert [key for key, value in with_vault.items() if "vault-canary" in value] == [
        "CERT_DASHBOARD_VAULT_PASSWORD"
    ]


def test_runner_secrets_repr_hides_the_password(tmp_path):
    secrets = RunnerSecrets(tmp_path / "k", tmp_path / "h", b"vault-canary-repr")
    assert "vault-canary-repr" not in repr(secrets) and "vault_password" not in repr(secrets)
    with pytest.raises(AttributeError):
        secrets.vault_password = None  # type: ignore[misc]


def test_child_process_does_not_inherit_the_worker_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("CERT_DASHBOARD_GIT_TOKEN", "git-canary-77")
    monkeypatch.setenv("ANSIBLE_STRATEGY", "does-not-exist")
    playbook = write_playbook(
        tmp_path / "env.yml",
        "    - ansible.builtin.set_stats:\n"
        "        data: >-\n"
        "          {{ {'cert_dashboard': {inventory_hostname: {\n"
        "          'proxy': lookup('ansible.builtin.env', 'HTTPS_PROXY'),\n"
        "          'token': lookup('ansible.builtin.env', 'CERT_DASHBOARD_GIT_TOKEN'),\n"
        "          'pin': lookup('ansible.builtin.env', 'ANSIBLE_HOST_KEY_CHECKING')}}} }}\n",
    )
    outcome = run_playbook(
        make_context(tmp_path, plain_secrets(tmp_path)),
        AnsibleRun(str(playbook), "localhost", {}, 60),
        ident="env",
    )
    assert outcome.status == "successful"
    assert outcome.hosts["localhost"].data == {"proxy": "", "token": "", "pin": "True"}


def test_run_timeout_is_reported(tmp_path):
    playbook = write_playbook(tmp_path / "slow.yml", "    - ansible.builtin.command: sleep 30\n")
    started = time.monotonic()
    outcome = run_playbook(
        make_context(tmp_path, plain_secrets(tmp_path)),
        AnsibleRun(str(playbook), None, {}, timeout_seconds=3),
        ident="slow",
    )
    assert outcome.status == "timeout"
    assert time.monotonic() - started < 15


@pytest.mark.parametrize(
    "message",
    [
        "Permission denied (publickey).",
        "Host key verification failed.",
        "@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @",
        "No ED25519 host key is known for [127.0.0.1]:2222",
        "No RSA host key is known for web01 and you have requested strict checking.",
        "host key for [10.0.0.5]:22 not known",
    ],
)
def test_authentication_unreachable_messages_are_classified_auth(message):
    assert classify_unreachable(message) == "auth"


@pytest.mark.parametrize(
    "message",
    [
        "ssh: connect to host 127.0.0.1 port 22: Connection refused",
        "Connection timed out during banner exchange",
        "Could not resolve hostname web01: Name or service not known",
        "",
    ],
)
def test_other_unreachable_messages_are_transient(message):
    assert classify_unreachable(message) == "transient_network"


def test_closed_ssh_port_is_transient(tmp_path):
    if shutil.which("ssh") is None:
        pytest.skip("ssh client binary not available")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    inventory = tmp_path / "closed.ini"
    inventory.write_text(f"[all]\nclosed ansible_host=127.0.0.1 ansible_port={port} ansible_user=nobody\n")
    (tmp_path / "known_hosts").write_text("")
    playbook = write_playbook(tmp_path / "ping.yml", "    - ansible.builtin.ping:\n")
    outcome = run_playbook(
        make_context(tmp_path, plain_secrets(tmp_path), inventory),
        AnsibleRun(str(playbook), None, {}, 60),
        ident="closed",
    )
    assert outcome.status == "failed"
    host = outcome.hosts["closed"]
    assert host.outcome == "unreachable"
    assert "Connection refused" not in host.log_excerpt  # the peer text is never stored
    assert str(port) not in outcome.log_excerpt


def test_task_failures_are_reported_per_host(tmp_path):
    playbook = write_playbook(
        tmp_path / "fail.yml",
        "    - name: break on probe2\n"
        "      ansible.builtin.fail:\n"
        "        msg: deliberate failure\n"
        "      when: inventory_hostname == 'probe2'\n",
    )
    outcome = run_playbook(
        make_context(tmp_path, plain_secrets(tmp_path)), AnsibleRun(str(playbook), None, {}, 60), ident="fail"
    )
    assert outcome.status == "failed"
    assert outcome.hosts["localhost"].outcome == "ok"
    failed = outcome.hosts["probe2"]
    assert failed.outcome == "failed" and failed.failed_task == "break on probe2"
    assert "deliberate failure" in failed.log_excerpt


def test_playbook_errors_are_job_level(tmp_path):
    playbook = tmp_path / "broken.yml"
    playbook.write_text("---\n- hosts: all\n  tasks:\n    - ansible.builtin.debug: [unclosed\n")
    outcome = run_playbook(
        make_context(tmp_path, plain_secrets(tmp_path)),
        AnsibleRun(str(playbook), None, {}, 60),
        ident="broken",
    )
    assert outcome.status == "failed"
    assert outcome.hosts == {}


def test_missing_playbook_is_refused_before_running(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_playbook(
            make_context(tmp_path, plain_secrets(tmp_path)),
            AnsibleRun("tests/fixtures/ansible/absent.yml", None, {}, 60),
            ident="x",
        )


def test_log_excerpt_is_redacted_and_skips_censored_events(tmp_path):
    playbook = write_playbook(
        tmp_path / "log.yml",
        "    - ansible.builtin.debug:\n"
        "        msg: 'connecting with password=hunter2-canary now'\n"
        "    - ansible.builtin.debug:\n"
        "        msg: 'hidden-canary-8812'\n"
        "      no_log: true\n"
        "    - ansible.builtin.debug:\n"
        "        msg: 'after the hidden task'\n",
    )
    outcome = run_playbook(
        make_context(tmp_path, plain_secrets(tmp_path)),
        AnsibleRun(str(playbook), "localhost", {}, 60),
        ident="log",
    )
    for text in (outcome.log_excerpt, outcome.hosts["localhost"].log_excerpt):
        assert "after the hidden task" in text
        assert "hunter2-canary" not in text
        assert "hidden-canary-8812" not in text
        assert "censored" not in text


def test_log_excerpt_is_bounded_in_lines_and_bytes(tmp_path):
    many = write_playbook(
        tmp_path / "many.yml",
        "    - ansible.builtin.debug:\n        msg: 'line {{ item }}'\n      loop: \"{{ range(0, 400) | list }}\"\n",
    )
    outcome = run_playbook(
        make_context(tmp_path, plain_secrets(tmp_path)),
        AnsibleRun(str(many), "localhost", {}, 60),
        ident="many",
    )
    assert LOG_EXCERPT_LINES == 200
    assert len(outcome.log_excerpt.splitlines()) <= LOG_EXCERPT_LINES
    assert "line 399" in outcome.log_excerpt and "line 0\n" not in outcome.log_excerpt

    wide = write_playbook(
        tmp_path / "wide.yml",
        '    - ansible.builtin.debug:\n        msg: "{{ \'word \' * 800 }}"\n      loop: "{{ range(0, 60) | list }}"\n',
    )
    outcome = run_playbook(
        make_context(tmp_path, plain_secrets(tmp_path)),
        AnsibleRun(str(wide), "localhost", {}, 60),
        ident="wide",
    )
    assert 0 < len(outcome.log_excerpt.encode()) <= 64 * 1024
    assert 0 < len(outcome.hosts["localhost"].log_excerpt.encode()) <= 64 * 1024


def test_runner_uses_private_run_and_artifact_directories(tmp_path):
    write_vaulted_vars(tmp_path / "vars.yml", {"probe_secret": "s"}, "pw")
    context = make_context(tmp_path, plain_secrets(tmp_path, b"pw"))
    run_playbook(
        context, AnsibleRun(PROBE, "localhost", {"vars_file": str(tmp_path / "vars.yml")}, 120), ident="dirs"
    )
    run_dir = tmp_path / "run"
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
    assert (run_dir / "artifacts" / "dirs").is_dir()
    assert not (run_dir / "env").exists()  # suppress_env_files


def test_stage_runner_secrets_writes_the_key_and_returns_paths(tmp_path):
    from app.config import Settings  # noqa: F401  (type of the argument)

    class FakeSettings:
        ansible_ssh_key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----\n"
        ansible_vault_password = b"vault-canary-stage"
        known_hosts_file = tmp_path / "ssh_known_hosts"

    with StagingArea(tmp_path / "keys", uuid4()) as area:
        secrets = stage_runner_secrets(FakeSettings(), area)  # type: ignore[arg-type]
        assert secrets.ssh_key == area.path / "ssh_key"
        assert secrets.ssh_key.read_bytes() == FakeSettings.ansible_ssh_key
        assert stat.S_IMODE(secrets.ssh_key.stat().st_mode) == 0o600
        assert secrets.known_hosts == FakeSettings.known_hosts_file
        assert secrets.vault_password == b"vault-canary-stage"


def test_stage_runner_secrets_requires_an_ssh_key(tmp_path):
    class NoKey:
        ansible_ssh_key = None
        ansible_vault_password = None
        known_hosts_file = tmp_path / "ssh_known_hosts"

    with StagingArea(tmp_path / "keys", uuid4()) as area, pytest.raises(StagingError):
        stage_runner_secrets(NoKey(), area)  # type: ignore[arg-type]


def helper_env(**extra: str) -> dict[str, str]:
    return {"PATH": os.environ["PATH"], **extra}


def run_helper(path: Path, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(path), *args], env=env, capture_output=True, text=True, timeout=30, check=False
    )


def test_vault_client_prints_only_the_password_and_fails_closed():
    assert VAULT_CLIENT.name == "vault_client.py"
    assert os.access(VAULT_CLIENT, os.X_OK)
    done = run_helper(VAULT_CLIENT, env=helper_env(CERT_DASHBOARD_VAULT_PASSWORD="s3cret value"))
    assert done.returncode == 0 and done.stdout == "s3cret value\n" and done.stderr == ""
    done = run_helper(
        VAULT_CLIENT, "--vault-id", "default", env=helper_env(CERT_DASHBOARD_VAULT_PASSWORD="pw")
    )
    assert done.returncode == 0 and done.stdout == "pw\n"
    for env in (helper_env(), helper_env(CERT_DASHBOARD_VAULT_PASSWORD="")):
        done = run_helper(VAULT_CLIENT, env=env)
        assert done.returncode != 0 and done.stdout == ""


def test_git_askpass_answers_username_and_password():
    assert GIT_ASKPASS.name == "git_askpass.py"
    assert os.access(GIT_ASKPASS, os.X_OK)
    env = helper_env(CERT_DASHBOARD_GIT_TOKEN="tok-canary")
    done = run_helper(GIT_ASKPASS, "Username for 'https://git.example.internal': ", env=env)
    assert done.returncode == 0 and done.stdout == "x-access-token\n"
    done = run_helper(GIT_ASKPASS, "Password for 'https://x-access-token@git.example.internal': ", env=env)
    assert done.returncode == 0 and done.stdout == "tok-canary\n" and done.stderr == ""
    for prompt in ("Enter passphrase for key '/x': ", "Anything else", ""):
        done = run_helper(GIT_ASKPASS, prompt, env=env)
        assert done.returncode != 0 and done.stdout == "" and "tok-canary" not in done.stderr
    for prompt in (
        "Username for 'https://git.example.internal': ",
        "Password for 'https://git.example.internal': ",
    ):
        for bare in (helper_env(), helper_env(CERT_DASHBOARD_GIT_TOKEN="")):
            done = run_helper(GIT_ASKPASS, prompt, env=bare)
            assert done.returncode != 0 and done.stdout == ""
    done = run_helper(GIT_ASKPASS, env=env)
    assert done.returncode != 0 and done.stdout == ""


@pytest.mark.parametrize("path", [VAULT_CLIENT, GIT_ASKPASS])
def test_helpers_import_no_application_code(path):
    source = path.read_text()
    assert source.startswith("#!")
    assert "import app" not in source and "from app" not in source
    assert path.stat().st_mode & stat.S_IXUSR


def test_playbook_dir_is_the_packaged_directory():
    assert PLAYBOOK_DIR == ROOT / "app" / "ansible" / "playbooks"


def test_dockerfile_copies_the_helpers_with_an_explicit_executable_bit():
    lines = (ROOT / "Dockerfile").read_text().splitlines()
    copies = [line for line in lines if line.startswith("COPY") and "--chmod=0755" in line]
    for helper in ("vault_client.py", "git_askpass.py"):
        assert any(f"app/ansible/{helper}" in line for line in copies), helper
