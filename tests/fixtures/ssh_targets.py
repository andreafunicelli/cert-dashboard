"""SSH-enabled nginx and Apache targets (compose profile ``ssh-targets``) for the Plan 3 tests.

Everything here is throwaway test material: ed25519 host and client keys and an "old" leaf are generated
per session and written to a temporary directory that the containers see as a read-only ``/fixture`` bind.
Assertions on a target run ``docker compose exec`` as root, never through the code under test.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tarfile
import uuid
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from app.crypto.keys import public_key_sha256

if TYPE_CHECKING:
    from app.models import JSONValue
    from tests.fixtures.ca import FixtureCA

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = "docker-compose.test.yml"
PROFILE = "ssh-targets"
RESET_STAMP = "/run/target-reset.stamp"
BACKUP_ROOT = "/var/backups/cert-dashboard"
VHOSTS = ("www.example.internal", "legacy.example.internal")
SIGNALS = frozenset({"STOP", "CONT", "KILL", "TERM", "HUP", "USR1", "USR2", "QUIT"})


class TargetSpec(NamedTuple):
    inventory_name: str
    groups: tuple[str, ...]
    webserver_type: str | None  # the ``webserver_type`` inventory variable (absent: auto-detected)
    tls_port: int
    kind: str  # the installed webserver: ``nginx`` or ``apache``
    config_root: str


# The host/port/vhost table of the Plan 3 test harness (normative).
SPECS: dict[str, TargetSpec] = {
    "ssh-nginx-1": TargetSpec("web01.example.internal", ("canary_ring",), "nginx", 18443, "nginx", "/etc/nginx"),
    "ssh-nginx-2": TargetSpec("web02.example.internal", ("ring_a",), None, 18444, "nginx", "/etc/nginx"),
    "ssh-apache": TargetSpec("web03.example.internal", ("ring_a",), "apache", 18445, "apache", "/etc/apache2"),
}
SERVICES = tuple(SPECS)
_PROCESS = {"nginx": "nginx", "apache": "apache2"}


class SshKey(NamedTuple):
    private_pem: bytes  # OpenSSH format, unencrypted
    public_line: str  # ``ssh-ed25519 AAAA...``


def new_ed25519() -> SshKey:
    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return SshKey(private, public.decode("ascii"))


@dataclass(frozen=True)
class TargetHost:
    service: str
    inventory_name: str
    groups: tuple[str, ...]
    webserver: str | None
    ssh_port: int
    tls_port: int


@dataclass(frozen=True)
class TargetMaterial:
    cert_pem: bytes
    chain_pem: bytes
    fullchain_pem: bytes
    key_pem: bytes
    fingerprint: str
    spki_sha256: str
    chain_fingerprints: tuple[str, ...]


class FileStat(NamedTuple):
    mode: int
    owner: str
    group: str
    size: int
    inode: int
    mtime_ns: int


class TargetCommandError(subprocess.CalledProcessError):
    """``CalledProcessError`` whose message carries the (bounded) stderr of the failed command."""

    def __str__(self) -> str:
        stderr = self.stderr.decode(errors="replace") if isinstance(self.stderr, bytes) else (self.stderr or "")
        return f"{super().__str__()}\n{stderr[-2000:]}"


def issue_old_material(ca: FixtureCA) -> TargetMaterial:
    """The "old" leaf for both vhosts, issued by the session CA, with its chain (intermediate, no root)."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert_pem = ca.issue(public_key=key.public_key(), common_name=VHOSTS[0], sans=list(VHOSTS))
    chain_pem = ca.chain_pem
    leaf = x509.load_pem_x509_certificate(cert_pem)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return TargetMaterial(
        cert_pem=cert_pem,
        chain_pem=chain_pem,
        fullchain_pem=cert_pem + chain_pem,
        key_pem=key_pem,
        fingerprint=leaf.fingerprint(hashes.SHA256()).hex(),
        spki_sha256=public_key_sha256(key.public_key()),
        chain_fingerprints=tuple(
            cert.fingerprint(hashes.SHA256()).hex() for cert in x509.load_pem_x509_certificates(chain_pem)
        ),
    )


_CERT_DIRECTIVE = re.compile(r"^(?P<file>[^:]+):\s*(?:ssl_certificate|SSLCertificateFile)\s+(?P<path>[^\s;]+)\s*;?\s*$")
_SERVER_NAME = re.compile(r"^\s*(?:server_name|ServerName)\s+(?P<name>[^\s;]+)", re.MULTILINE)


def parse_certificate_directives(grep_output: str) -> list[tuple[str, str]]:
    """``(config file, certificate path)`` from ``grep -RH`` output over certificate directives."""
    found = []
    for line in grep_output.splitlines():
        match = _CERT_DIRECTIVE.match(line)
        if match:
            found.append((match["file"], match["path"].strip("\"'")))
    return found


def first_server_name(config_text: str) -> str | None:
    match = _SERVER_NAME.search(config_text)
    return match["name"] if match else None


class TargetStack:
    """The three running targets plus the keys, pinned ``known_hosts`` and old certificate they were started with.

    ``hosts`` is keyed by compose service name. Constructing the stack only writes files; ``up()`` starts the
    containers and learns the random loopback SSH ports.
    """

    def __init__(self, directory: Path, ca: FixtureCA) -> None:
        self.directory = directory
        self.project = "certdash-ssh-" + uuid.uuid4().hex[:10]
        self.env = {
            **os.environ,
            "SSH_TARGET_DIR": str(directory / "targets"),
            "TEST_SECRETS_DIR": str(directory / "secrets"),
        }
        self.known_hosts = directory / "known_hosts"
        self.old = issue_old_material(ca)
        client = new_ed25519()
        self.client_key = client.private_pem
        self._client_public = client.public_line
        self._host_keys = {service: new_ed25519() for service in SPECS}
        self.hosts: dict[str, TargetHost] = {
            service: TargetHost(service, spec.inventory_name, spec.groups, spec.webserver_type, 0, spec.tls_port)
            for service, spec in SPECS.items()
        }
        self.last_changes: dict[str, str] = {}
        self._prepare()

    # --- files ---------------------------------------------------------------------------------

    def _prepare(self) -> None:
        secrets = self.directory / "secrets"
        secrets.mkdir(parents=True)
        compose = yaml.safe_load((ROOT / COMPOSE_FILE).read_text(encoding="utf-8"))
        for name in compose["secrets"]:  # compose insists on every declared secret file existing
            (secrets / name).write_text("dummy-target-secret")
        material = self.old
        tls = {
            "ssh-nginx-1": {"www.crt": material.fullchain_pem, "www.key": material.key_pem,
                            "legacy.key": material.key_pem},
            "ssh-nginx-2": {"www.crt": material.fullchain_pem, "www.key": material.key_pem},
            "ssh-apache": {"www.crt": material.cert_pem, "www.key": material.key_pem,
                           "www.chain.pem": material.chain_pem},
        }
        for service in SPECS:
            folder = self.directory / "targets" / service
            (folder / "tls").mkdir(parents=True)
            (folder / "ssh_host_ed25519_key").write_bytes(self._host_keys[service].private_pem)
            (folder / "authorized_keys").write_text(self._client_public + "\n")
            for name, data in tls[service].items():
                (folder / "tls" / name).write_bytes(data)

    def _known_hosts_text(self, foreign: str | None = None) -> str:
        lines = []
        for service, host in self.hosts.items():
            key = new_ed25519() if service == foreign else self._host_keys[service]
            lines.append(f"[127.0.0.1]:{host.ssh_port} {key.public_line}\n")
        return "".join(lines)

    def known_hosts_with_foreign_key(self, service: str) -> str:
        """The pinned file with ``service``'s host key replaced by an unrelated ed25519 key."""
        return self._known_hosts_text(foreign=service)

    def apply_ports(self, ssh_ports: Mapping[str, int]) -> None:
        """Record SSH ports (``up``/``start`` read them from compose) and rewrite the pinned ``known_hosts``."""
        for service, port in ssh_ports.items():
            self.hosts[service] = replace(self.hosts[service], ssh_port=port)
        self.known_hosts.write_text(self._known_hosts_text())

    # --- compose -------------------------------------------------------------------------------

    def _compose(self, *args: str, check: bool = True, timeout: int = 120, input: bytes | str | None = None,
                 text: bool = True) -> subprocess.CompletedProcess:
        command = ["docker", "compose", "-p", self.project, "-f", COMPOSE_FILE, "--profile", PROFILE, *args]
        result = subprocess.run(command, cwd=ROOT, env=self.env, capture_output=True, input=input,
                                text=text, encoding="utf-8" if text else None, errors="replace" if text else None,
                                check=False, timeout=timeout)
        if check and result.returncode:
            raise TargetCommandError(result.returncode, command, result.stdout, result.stderr)
        return result

    def _ssh_port(self, service: str) -> int:
        output = self._compose("port", service, "22").stdout.strip()
        return int(output.splitlines()[0].rpartition(":")[2])

    def up(self) -> None:
        try:
            self._compose("up", "-d", "--wait", "--no-build", "--pull", "never", *SERVICES, timeout=600)
            self.apply_ports({service: self._ssh_port(service) for service in SPECS})
        except subprocess.CalledProcessError as error:
            logs = self._compose("logs", "--no-color", "--tail", "60", check=False).stdout[-6000:]
            self.down()
            raise RuntimeError(f"SSH targets failed to start: {error}\n{logs}") from None

    def down(self) -> None:
        self._compose("down", "-v", "--remove-orphans", "-t", "2", check=False)
        shutil.rmtree(self.directory, ignore_errors=True)

    def stop(self, service: str) -> None:
        self._compose("stop", "-t", "2", service)

    def start(self, service: str) -> None:
        """Start a stopped target again; its random SSH port may change, so ``known_hosts`` is rewritten."""
        self._compose("up", "-d", "--wait", "--no-build", "--pull", "never", service, timeout=300)
        self.apply_ports({service: self._ssh_port(service)})

    # --- inventory -----------------------------------------------------------------------------

    def inventory_hosts(self, **overrides: JSONValue) -> dict[str, dict[str, JSONValue]]:
        """Host variables per inventory name; each override is set on every host (``None`` removes it)."""
        hosts: dict[str, dict[str, JSONValue]] = {}
        for host in self.hosts.values():
            variables: dict[str, JSONValue] = {
                "ansible_host": "127.0.0.1",
                "ansible_port": host.ssh_port,
                "ansible_user": "cdeploy",
                "groups": list(host.groups),
            }
            if host.webserver is not None:
                variables["webserver_type"] = host.webserver
            variables.update(overrides)
            hosts[host.inventory_name] = {k: v for k, v in variables.items() if v is not None}
        return hosts

    def inventory_file(self, directory: Path, **overrides: JSONValue) -> Path:
        """A YAML inventory (``groups`` becomes child groups, not a host variable) in ``directory``."""
        hosts = self.inventory_hosts(**overrides)
        children: dict[str, dict[str, dict[str, dict]]] = {}
        for name, variables in hosts.items():
            for group in variables.get("groups", []):
                children.setdefault(group, {"hosts": {}})["hosts"][name] = {}
        document = {
            "all": {
                "hosts": {name: {k: v for k, v in variables.items() if k != "groups"}
                          for name, variables in hosts.items()},
                "children": children,
            }
        }
        path = Path(directory) / "inventory.yml"
        path.write_text(yaml.safe_dump(document, sort_keys=True), encoding="utf-8")
        return path

    # --- assertions and fault injection on a target (always as root, via compose exec) -------------

    def exec(self, service: str, *argv: str, check: bool = True) -> subprocess.CompletedProcess:
        return self._compose("exec", "-T", service, *argv, check=check)

    def read(self, service: str, path: str) -> bytes:
        return self._compose("exec", "-T", service, "cat", "--", path, text=False).stdout

    def stat(self, service: str, path: str) -> FileStat:
        program = (
            "import grp, os, pwd, stat, sys\n"
            "s = os.stat(sys.argv[1])\n"
            "print(stat.S_IMODE(s.st_mode), pwd.getpwuid(s.st_uid).pw_name, grp.getgrgid(s.st_gid).gr_name,"
            " s.st_size, s.st_ino, s.st_mtime_ns)\n"
        )
        mode, owner, group, size, inode, mtime_ns = self.exec(service, "python3", "-c", program, path).stdout.split()
        return FileStat(int(mode), owner, group, int(size), int(inode), int(mtime_ns))

    def put(self, service: str, path: str, data: bytes, *, mode: int, owner: str = "root", group: str = "root") -> None:
        """Replace ``path`` atomically with ``data`` (a new inode), mode, owner and group as given."""
        script = (
            'set -e; umask 077; tmp="$1.put"; cat > "$tmp"; chmod "$2" "$tmp"; chown "$3:$4" "$tmp"; '
            'mv -f "$tmp" "$1"'
        )
        self._compose("exec", "-T", service, "sh", "-c", script, "sh", path, f"{mode:o}", owner, group,
                      input=data, text=False)

    def copy_in(self, service: str, local_dir: Path, remote_dir: str, owner: str) -> None:
        """Replace ``remote_dir`` with a copy of ``local_dir`` owned by ``owner`` (``user`` or ``user:group``)."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            archive.add(str(local_dir), arcname=".")
        script = 'set -e; rm -rf "$1"; mkdir -p "$1"; tar -x -f - -C "$1"; chown -R "$2" "$1"'
        self._compose("exec", "-T", service, "sh", "-c", script, "sh", remote_dir, owner,
                      input=buffer.getvalue(), text=False)

    def served_fingerprint(self, service: str, sni: str) -> str:
        """SHA-256 of the leaf the target itself serves for ``sni`` (``openssl s_client`` inside the target)."""
        script = (
            'openssl s_client -connect "127.0.0.1:$1" -servername "$2" </dev/null 2>/dev/null'
            " | openssl x509 -noout -fingerprint -sha256"
        )
        output = self.exec(service, "sh", "-c", script, "sh", str(SPECS[service].tls_port), sni).stdout
        return output.strip().partition("=")[2].replace(":", "").lower()

    def signal_webserver(self, service: str, signal_name: str) -> None:
        """Send a signal (``STOP``, ``CONT``, ``KILL``...) to the webserver master process only."""
        name = signal_name.removeprefix("SIG").upper()
        if name not in SIGNALS:
            raise ValueError(f"unsupported signal: {signal_name}")
        self.exec(service, "sh", "-c", 'kill -s "$1" "$(pgrep -o -x "$2")"', "sh", name,
                  _PROCESS[SPECS[service].kind])

    def backups(self, service: str) -> list[str]:
        """Absolute paths of the per-job backup directories, sorted."""
        script = f'for d in {BACKUP_ROOT}/*/; do [ -d "$d" ] && echo "${{d%/}}"; done; true'
        return sorted(self.exec(service, "sh", "-c", script).stdout.split())

    def grep_ssl_certificate(self) -> dict[str, set[tuple[str, str]]]:
        """Per inventory host, the ``(vhost, certificate path)`` pairs a ``grep`` over its config finds."""
        found: dict[str, set[tuple[str, str]]] = {}
        for service, spec in SPECS.items():
            output = self.exec(
                service, "grep", "-RHE", r"^[[:space:]]*(ssl_certificate|SSLCertificateFile)[[:space:]]+",
                spec.config_root, check=False,
            ).stdout
            pairs: set[tuple[str, str]] = set()
            for config_file, path in parse_certificate_directives(output):
                vhost = first_server_name(self.read(service, config_file).decode("utf-8", "replace"))
                if vhost is not None:  # a snippet without a server name is not a vhost
                    pairs.add((vhost, path))
            found[spec.inventory_name] = pairs
        return found

    # --- state --------------------------------------------------------------------------------

    def reset(self, service: str) -> None:
        self._compose("exec", "-T", service, "target-reset", timeout=180)

    def reset_all(self) -> None:
        with ThreadPoolExecutor(max_workers=len(SPECS)) as pool:
            list(pool.map(self.reset, SPECS))

    def unchanged_since_reset(self, service: str) -> bool:
        """True when nothing under ``/etc`` or ``/var/backups`` is newer than the reset stamp.

        Docker-managed ``/etc/hosts``, ``/etc/hostname`` and ``/etc/resolv.conf`` are not the code's doing.
        """
        script = (
            f"find /etc /var/backups -newer {RESET_STAMP} "
            "! -path /etc/hosts ! -path /etc/hostname ! -path /etc/resolv.conf | head -n 20"
        )
        changed = self.exec(service, "sh", "-c", script).stdout.strip()
        self.last_changes[service] = changed
        return not changed

    def mark_baseline(self, service: str) -> None:
        """Re-touch the stamp so ``unchanged_since_reset`` covers only what happens after this call."""
        self.exec(service, "touch", RESET_STAMP)
