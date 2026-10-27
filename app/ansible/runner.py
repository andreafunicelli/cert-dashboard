"""`ansible-runner` wrapper: explicit child environment, file-only secrets, event parsing.

Secrets reach the child only as file *paths* (SSH key, known_hosts) or as the two documented
environment variables read by the executable helpers; nothing secret is ever put in argv,
extra-vars or an `ansible-runner` env file. Peer-supplied error text is classified in memory
and never stored.
"""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from app.ansible.staging import StagingArea, StagingError
from app.services.audit import redact

if TYPE_CHECKING:
    from app.config import Settings
    from app.models import JSONValue

_PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = _PACKAGE_DIR.parents[1]
PLAYBOOK_DIR = _PACKAGE_DIR / "playbooks"
VAULT_CLIENT = _PACKAGE_DIR / "vault_client.py"
GIT_ASKPASS = _PACKAGE_DIR / "git_askpass.py"
LOG_EXCERPT_LINES = 200
LOG_EXCERPT_BYTES = 64 * 1024

_UNREACHABLE_TEXT = "host unreachable over SSH"
_AUTH_TEXT = "SSH authentication or host key verification failed; check known_hosts and the deploy key"
# What ansible-runner itself adds to the environment it builds; everything else is dropped.
_RUNNER_KEYS = ("ANSIBLE_STDOUT_CALLBACK", "ANSIBLE_CALLBACK_PLUGINS", "AWX_ISOLATED_DATA_DIR")
_SECRET_ENV_KEYS = frozenset({"CERT_DASHBOARD_VAULT_PASSWORD", "CERT_DASHBOARD_GIT_TOKEN"})


@dataclass(frozen=True)
class RunnerSecrets:
    ssh_key: Path
    known_hosts: Path
    vault_password: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class RunnerContext:
    secrets: RunnerSecrets
    inventory: Path
    run_dir: Path
    # The caller's job artifact directory (public outputs such as discovery documents). The
    # runner's own artifacts live under ``run_dir`` so one directory removal discards them all.
    artifact_dir: Path


@dataclass(frozen=True)
class AnsibleRun:
    playbook: str
    limit: str | None
    extravars: Mapping[str, JSONValue]
    timeout_seconds: int
    forks: int = 20


@dataclass(frozen=True)
class HostResult:
    hostname: str
    outcome: Literal["ok", "failed", "unreachable", "auth"]
    failed_task: str | None
    data: Mapping[str, JSONValue]
    log_excerpt: str


@dataclass(frozen=True)
class RunOutcome:
    status: Literal["successful", "failed", "timeout"]
    rc: int | None
    hosts: dict[str, HostResult]
    log_excerpt: str


def build_env(secrets: RunnerSecrets, run_dir: Path) -> dict[str, str]:
    """The complete child environment, built from scratch (nothing is inherited)."""
    ssh_args = " ".join(
        [
            "-o StrictHostKeyChecking=yes",
            f"-o UserKnownHostsFile={shlex.quote(str(secrets.known_hosts))}",
            "-o IdentitiesOnly=yes",
            "-o BatchMode=yes",
            "-o ControlMaster=auto",
            "-o ControlPersist=60s",
        ]
    )
    env = {
        "PATH": os.pathsep.join([str(Path(sys.executable).parent), "/usr/local/bin", "/usr/bin", "/bin"]),
        "HOME": str(run_dir / "home"),
        "ANSIBLE_LOCAL_TEMP": str(run_dir / "tmp"),
        "ANSIBLE_HOST_KEY_CHECKING": "True",
        "ANSIBLE_SSH_ARGS": ssh_args,
        "ANSIBLE_PRIVATE_KEY_FILE": str(secrets.ssh_key),
        "ANSIBLE_NOCOLOR": "True",
        "ANSIBLE_RETRY_FILES_ENABLED": "False",
        "ANSIBLE_PYTHON_INTERPRETER": "auto_silent",
        "ANSIBLE_DEPRECATION_WARNINGS": "False",
        "ANSIBLE_COLLECTIONS_PATH": str(run_dir / "collections"),
        # Short on purpose: ssh adds 17 random characters to the multiplexing socket path and a Unix
        # socket path holds at most 107, so ~/.ansible/cp under a deep run directory kills the connection.
        "ANSIBLE_SSH_CONTROL_PATH_DIR": str(run_dir / "cp"),
    }
    if secrets.vault_password is not None:
        env["ANSIBLE_VAULT_PASSWORD_FILE"] = str(VAULT_CLIENT)
        env["CERT_DASHBOARD_VAULT_PASSWORD"] = secrets.vault_password.decode()
    return env


def classify_unreachable(message: str) -> Literal["auth", "transient_network"]:
    """Authentication / host-key failures are `auth`; every other unreachable is transient."""
    lowered = message.lower()
    if (
        "permission denied" in lowered
        or "host key verification failed" in lowered
        or "remote host identification has changed" in lowered
        or ("host key" in lowered and "not known" in lowered)
        or ("host key" in lowered and "is known" in lowered and lowered.startswith("no "))
    ):
        return "auth"
    return "transient_network"


def stage_runner_secrets(settings: Settings, area: StagingArea) -> RunnerSecrets:
    """Write the SSH key to the staging area; known_hosts and the vault password pass through."""
    if settings.ansible_ssh_key is None:
        raise StagingError("no ansible_ssh_key is configured")
    key = settings.ansible_ssh_key
    if not key.endswith(b"\n"):
        key += b"\n"
    return RunnerSecrets(
        area.write("ssh_key", key), settings.known_hosts_file, settings.ansible_vault_password
    )


def _resolve_playbook(name: str) -> Path:
    path = Path(name)
    if not path.is_absolute():
        path = REPO_ROOT / path
    if not path.is_file():
        raise FileNotFoundError("playbook not found")
    return path


def _prepare_dirs(run_dir: Path) -> None:
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(run_dir, 0o700)
    for name in ("home", "tmp", "collections", "cp"):
        (run_dir / name).mkdir(mode=0o700, exist_ok=True)


def _is_censored(result: Mapping[str, Any]) -> bool:
    return bool(result.get("_ansible_no_log") or "censored" in result)


def _excerpt(lines: list[str]) -> str:
    text = "\n".join(lines[-LOG_EXCERPT_LINES:])
    text = redact(text)
    assert isinstance(text, str)
    # Redaction can only shorten or mask; bound afterwards so the cap is on what is stored.
    lines_after = text.splitlines()[-LOG_EXCERPT_LINES:]
    encoded = "\n".join(lines_after).encode()[-LOG_EXCERPT_BYTES:]
    return encoded.decode(errors="ignore")


class _CommandSink:
    """Keeps ansible-runner's `command` record (it holds the full child environment) off disk.

    ansible-runner opens ``<artifact_dir>/command`` for writing and dumps the environment into
    it before the child starts. Planting a FIFO there makes that write land in a pipe drained
    by an in-process thread; after the run the masked record replaces the FIFO as a regular
    0600 file. The secret therefore never exists in a file of the artifact tree.
    """

    def __init__(self, directory: Path) -> None:
        self.path = directory / "command"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()
        os.mkfifo(self.path, 0o600)
        self._chunks: list[bytes] = []
        # Reader first (a non-blocking open succeeds without a writer), then a holding writer
        # so the reader sees EOF only when we close it, whenever ansible-runner opens the FIFO.
        self._read_fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK)
        os.set_blocking(self._read_fd, True)
        self._hold_fd: int | None = os.open(self.path, os.O_WRONLY)
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        try:
            while chunk := os.read(self._read_fd, 65536):
                self._chunks.append(chunk)
        finally:
            os.close(self._read_fd)

    def finish(self) -> None:
        """Replace the FIFO with the record minus the secret environment values."""
        if self._hold_fd is not None:
            os.close(self._hold_fd)
            self._hold_fd = None
        self._thread.join()
        self.path.unlink()
        try:
            document = json.loads(b"".join(self._chunks).decode())
            env = document.get("env")
            if isinstance(env, dict):
                document["env"] = {k: "[removed]" if k in _SECRET_ENV_KEYS else v for k, v in env.items()}
            text = json.dumps(document)
        except ValueError:
            text = "{}"
        self._chunks.clear()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(text)


class _Collector:
    """Receives ansible-runner events in memory (they are also kept on disk by the runner)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.stdout: list[tuple[str | None, str]] = []  # (host or None, line) for visible events
        self.failed_task: dict[str, str] = {}
        self.unreachable: dict[str, str] = {}  # host -> classification
        self.stats: dict[str, Any] | None = None

    def __call__(self, event: Mapping[str, Any]) -> bool:
        name = event.get("event")
        data = event.get("event_data") or {}
        host = data.get("host")
        result = data.get("res") or {}
        with self.lock:
            if name == "runner_on_unreachable" and host:
                self.unreachable[host] = classify_unreachable(str(result.get("msg", "")))
            elif name == "runner_on_failed" and host:
                self.failed_task.setdefault(host, str(data.get("task") or ""))
            elif name == "playbook_on_stats":
                self.stats = dict(data)
            if name == "runner_on_unreachable" or _is_censored(result):
                return True
            text = event.get("stdout")
            if text:
                self.stdout.extend((host, line) for line in str(text).splitlines())
        return True


def run_playbook(context: RunnerContext, run: AnsibleRun, *, ident: str) -> RunOutcome:
    from ansible_runner.interface import init_runner

    playbook = _resolve_playbook(run.playbook)
    run_dir = context.run_dir
    _prepare_dirs(run_dir)
    env = build_env(context.secrets, run_dir)
    collector = _Collector()
    artifact_root = run_dir / "artifacts"
    command_dir = artifact_root / ident

    runner = init_runner(
        private_data_dir=str(run_dir),
        playbook=str(playbook),
        inventory=str(context.inventory),
        limit=run.limit,
        extravars=dict(run.extravars),
        envvars=env,
        ident=ident,
        quiet=True,
        suppress_env_files=True,
        timeout=run.timeout_seconds,
        forks=run.forks,
        artifact_dir=str(artifact_root),
        event_handler=collector,
        # Never let ansible-runner install its own SIGTERM/SIGINT handlers in the worker.
        cancel_callback=lambda: False,
    )
    # ansible-runner seeds the child environment with a copy of os.environ; replace it outright.
    runner.config.env = {**{k: runner.config.env[k] for k in _RUNNER_KEYS if k in runner.config.env}, **env}
    # ansible-runner writes the child environment (secrets included) to `command` right
    # before it starts the child; the sink makes that write go to a pipe, not to the disk.
    sink = _CommandSink(command_dir)
    try:
        runner.run()
    finally:
        sink.finish()

    status: Literal["successful", "failed", "timeout"]
    if runner.status == "timeout":
        status = "timeout"
    elif runner.status == "successful":
        status = "successful"
    else:
        status = "failed"
    hosts = _host_results(collector)
    summary = [line for _, line in collector.stdout]
    if not collector.stdout and not hosts:
        summary = _stdout_tail(command_dir)
    return RunOutcome(status, runner.rc, hosts, _excerpt(summary))


def _stdout_tail(artifact_dir: Path) -> list[str]:
    try:
        return (artifact_dir / "stdout").read_text(errors="replace").splitlines()[-LOG_EXCERPT_LINES:]
    except OSError:
        return []


def _host_results(collector: _Collector) -> dict[str, HostResult]:
    stats = collector.stats or {}
    published = (stats.get("artifact_data") or {}).get("cert_dashboard") or {}
    names = sorted(stats.get("processed") or {})
    results: dict[str, HostResult] = {}
    for name in names:
        lines = [line for host, line in collector.stdout if host == name]
        data = published.get(name)
        data = data if isinstance(data, dict) else {}
        if (stats.get("dark") or {}).get(name):
            kind = collector.unreachable.get(name, "transient_network")
            if kind == "auth":
                results[name] = HostResult(name, "auth", None, {}, _AUTH_TEXT)
            else:
                results[name] = HostResult(name, "unreachable", None, {}, _UNREACHABLE_TEXT)
        elif (stats.get("failures") or {}).get(name):
            results[name] = HostResult(
                name, "failed", collector.failed_task.get(name) or None, data, _excerpt(lines)
            )
        else:
            results[name] = HostResult(name, "ok", None, data, _excerpt(lines))
    return results
