"""Task 8B: ``discover_hosts`` against local-connection hosts with fake ``nginx``/``apachectl`` binaries.

The real playbook runs through ``ansible-runner`` exactly as in production (collect phase, parser, inspect
phase, assembly), but over ``ansible_connection=local`` and without ``become``: no Docker, no sshd. The SSH
targets prove the same paths in ``tests/integration/test_discover_playbook.py``.
"""

import getpass
import hashlib
import json
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.ansible import discovery
from app.ansible.discovery import HostDiscovery, discover_hosts
from app.ansible.runner import RunnerContext, RunnerSecrets
from app.crypto.keys import public_key_sha256
from tests.fixtures.ca import FixtureCA

pytestmark = pytest.mark.skipif(
    not (Path(sys.executable).parent / "ansible-playbook").exists(), reason="ansible is not installed"
)

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
WEB = "web.example.internal"
APACHE = "apache.example.internal"


def fingerprint(pem: bytes) -> str:
    return x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256()).hex()


class Tls:
    """A leaf issued by the fixture CA with its key and chain, written below ``root`` like a target would."""

    def __init__(self, root: Path) -> None:
        self.ca = FixtureCA(NOW)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert_pem = self.ca.issue(public_key=self.key.public_key(), common_name=WEB, sans=[WEB])
        self.key_pem = self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        self.dir = root / "tls"
        self.dir.mkdir(parents=True)
        self.crt = self.write("www.crt", self.cert_pem, 0o644)
        self.keyfile = self.write("www.key", self.key_pem, 0o600)
        self.chain = self.write("www.chain.pem", self.ca.chain_pem, 0o644)

    def write(self, name: str, data: bytes, mode: int) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        path.chmod(mode)
        return path

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.cert_pem)

    @property
    def spki(self) -> str:
        return public_key_sha256(self.key.public_key())


def executable(path: Path, text: str) -> str:
    path.write_text(text)
    path.chmod(0o755)
    return str(path)


def fake_nginx(tmp_path: Path, config: str, rc: int = 0, stderr_noise: str = "") -> str:
    """An ``nginx`` whose ``-T`` prints ``config`` (one main file at ``tmp_path/nginx/nginx.conf``)."""
    main = tmp_path / "nginx" / "nginx.conf"
    text = f"{stderr_noise}\n# configuration file {main}:\n{config}\n"
    (tmp_path / "nginx.out").write_text(text)
    return executable(tmp_path / "nginx", f'#!/bin/sh\ncat "{tmp_path}/nginx.out"\nexit {rc}\n')


def server_block(tls: Tls, *, port: int = 18443, cert: Path | None = None, key: Path | None = None) -> str:
    return (
        f"http {{ server {{ listen {port} ssl; server_name {WEB};"
        f" ssl_certificate {cert or tls.crt}; ssl_certificate_key {key or tls.keyfile}; }} }}"
    )


def local_host(tmp_path: Path, **variables: object) -> dict:
    return {
        "ansible_connection": "local",
        "ansible_python_interpreter": "{{ ansible_playbook_python }}",
        "ansible_become": False,  # the targets use sudo; the unit test host is the current user
        # Like tests/fixtures/ansible/local.ini: the CI image's user has no passwd home to expand `~` to. The
        # delegated (implicit localhost) tasks must name theirs in the playbook, which the run directory proves.
        "ansible_remote_tmp": str(tmp_path / "host-tmp"),
        **variables,
    }


def context(tmp_path: Path, hosts: dict[str, dict]) -> RunnerContext:
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(yaml.safe_dump({"all": {"hosts": hosts}}))
    key = tmp_path / "ssh_key"
    key.write_bytes(b"unused")
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")
    return RunnerContext(RunnerSecrets(key, known_hosts), inventory, tmp_path / "run", tmp_path / "artifacts")


def discover(tmp_path: Path, hosts: dict[str, dict], webservers: dict | None = None) -> dict[str, HostDiscovery]:
    run = context(tmp_path, hosts)
    names = list(hosts)
    return discover_hosts(run, names, webservers=webservers or dict.fromkeys(names), now=NOW, timeout_seconds=300)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def tls(tmp_path) -> Tls:
    return Tls(tmp_path)


def test_nginx_document_facts_dump_and_nothing_secret_in_events(tmp_path, tls):
    nginx = fake_nginx(tmp_path, server_block(tls))
    found = discover(tmp_path, {WEB: local_host(tmp_path, nginx_binary=nginx)})

    result = found[WEB]
    assert (result.status, result.reason, result.error) == ("ok", None, None), result
    document = result.document
    assert document is not None
    assert (document["hostname"], document["webserver"], document["collected_at"]) == (
        WEB, "nginx", "2026-10-19T12:00:00Z")  # fmt: skip
    assert document["errors"] == []
    [binding] = document["bindings"]
    assert (binding["vhost_name"], binding["port"], binding["cert_path"], binding["key_path"]) == (
        WEB, 18443, str(tls.crt), str(tls.keyfile))  # fmt: skip
    assert binding["config_file"] == str(tmp_path / "nginx" / "nginx.conf")
    assert (binding["cert_mode"], binding["key_mode"]) == ("0644", "0600")
    assert (binding["cert_owner"], binding["cert_exists"], binding["key_exists"]) == (getpass.getuser(), True, True)
    assert (binding["cert_fingerprint"], binding["key_public_sha256"]) == (tls.fingerprint, tls.spki)
    assert binding["key_unreadable"] is False
    assert binding["chain_diagnostic"] is not None  # the leaf alone: its issuer is not configured anywhere

    artifacts = tmp_path / "artifacts"
    dump = artifacts / "dumps" / f"{WEB}.txt"
    assert mode(dump) == 0o600 and f"# configuration file {tmp_path}/nginx/nginx.conf:" in dump.read_text()
    assert result.summary["dump_bytes"] == dump.stat().st_size
    assert result.summary["dump_sha256"] == hashlib.sha256(dump.read_bytes()).hexdigest()
    assert (result.summary["webserver"], result.summary["bindings"]) == ("nginx", 1)
    assert result.summary["config_files"] == [str(tmp_path / "nginx" / "nginx.conf")]
    written = artifacts / "discovery" / f"{WEB}.json"
    assert mode(written) == 0o600 and json.loads(written.read_text()) == document
    certs = list((artifacts / "certs" / WEB).glob("*.pem"))
    assert certs and all(mode(path) == 0o600 for path in certs)
    events = list((tmp_path / "run").rglob("job_events/*.json"))
    assert events
    assert not any("ssl_certificate" in path.read_text() for path in events)
    assert not any("PRIVATE KEY" in path.read_text() for path in events)
    # the delegated tasks used the run's HOME (named in the playbook), not the passwd home of the user
    assert (tmp_path / "run" / "home" / ".ansible" / "tmp").is_dir()


def test_a_private_key_in_a_combined_file_is_never_read_out(tmp_path, tls):
    combined = tls.write("combined.pem", tls.cert_pem + tls.key_pem, 0o600)
    nginx = fake_nginx(tmp_path, server_block(tls, cert=combined, key=combined))
    found = discover(tmp_path, {WEB: local_host(tmp_path, nginx_binary=nginx)})

    [binding] = found[WEB].document["bindings"]
    assert (binding["cert_fingerprint"], binding["key_public_sha256"]) == (tls.fingerprint, tls.spki)
    stored = list((tmp_path / "artifacts" / "certs" / WEB).glob("*.pem"))
    assert stored
    for path in stored:
        text = path.read_text()
        assert "BEGIN CERTIFICATE" in text and "PRIVATE KEY" not in text


def test_passphrase_protected_and_missing_files_are_reported_and_the_rest_is_processed(tmp_path, tls):
    protected = tls.write(
        "locked.key",
        tls.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw")
        ),
        0o600,
    )
    config = (
        f"http {{ server {{ listen 18443 ssl; server_name locked.example.internal;"
        f" ssl_certificate {tls.crt}; ssl_certificate_key {protected}; }}"
        f" server {{ listen 18444 ssl; server_name gone.example.internal;"
        f" ssl_certificate {tls.dir}/missing.crt; ssl_certificate_key {tls.dir}/missing.key; }}"
        f" server {{ listen 18445 ssl; server_name ok.example.internal;"
        f" ssl_certificate {tls.crt}; ssl_certificate_key {tls.keyfile}; }} }}"
    )
    found = discover(tmp_path, {WEB: local_host(tmp_path, nginx_binary=fake_nginx(tmp_path, config))})

    assert found[WEB].status == "ok"
    rows = {b["vhost_name"]: b for b in found[WEB].document["bindings"]}
    locked, gone, fine = rows["locked.example.internal"], rows["gone.example.internal"], rows["ok.example.internal"]
    assert (locked["key_exists"], locked["key_unreadable"], locked["key_public_sha256"]) == (True, True, None)
    assert locked["cert_fingerprint"] == tls.fingerprint
    assert (gone["cert_exists"], gone["key_exists"], gone["cert_fingerprint"], gone["key_unreadable"]) == (
        False, False, None, False)  # fmt: skip
    assert (fine["key_unreadable"], fine["key_public_sha256"]) == (False, tls.spki)


def test_a_failed_capture_is_reported_without_stderr(tmp_path, tls):
    nginx = fake_nginx(tmp_path, "http {", rc=1, stderr_noise="nginx: [emerg] STDERR-CANARY ssl_certificate")
    found = discover(tmp_path, {WEB: local_host(tmp_path, nginx_binary=nginx)})

    result = found[WEB]
    assert (result.status, result.reason, result.document) == ("failed", "dump_failed", None)
    assert "STDERR-CANARY" not in f"{result.error} {result.log_excerpt} {result.summary}"
    assert "exit code 1" in result.log_excerpt
    assert not (tmp_path / "artifacts" / "discovery" / f"{WEB}.json").exists()


def test_a_host_without_a_webserver_is_a_failed_capture(tmp_path):
    found = discover(tmp_path, {WEB: local_host(tmp_path, nginx_binary="", apachectl_binary="")})  # nothing to detect on a CI runner
    assert (found[WEB].status, found[WEB].reason, found[WEB].document) == ("failed", "dump_failed", None)
    assert found[WEB].error == "no supported webserver found on the host"


def test_an_oversized_dump_fails_instead_of_being_truncated(tmp_path, tls, monkeypatch):
    monkeypatch.setattr(discovery, "MAX_DUMP_BYTES", 200)
    nginx = fake_nginx(tmp_path, server_block(tls) + "\n" + "# padding\n" * 100)
    found = discover(tmp_path, {WEB: local_host(tmp_path, nginx_binary=nginx)})

    assert (found[WEB].status, found[WEB].reason, found[WEB].document) == ("failed", "dump_too_large", None)
    assert not (tmp_path / "artifacts" / "dumps" / f"{WEB}.txt").exists()


def test_an_unparseable_dump_is_parse_failed(tmp_path):
    found = discover(tmp_path, {WEB: local_host(tmp_path, nginx_binary=fake_nginx(tmp_path, "http { server { listen 443 ssl;"))})
    assert (found[WEB].status, found[WEB].reason, found[WEB].document) == ("failed", "parse_failed", None)
    assert found[WEB].error == "configuration could not be parsed"


def test_a_host_without_tls_has_an_empty_document(tmp_path):
    found = discover(tmp_path, {WEB: local_host(tmp_path, nginx_binary=fake_nginx(tmp_path, "http { server { listen 80; } }"))})
    assert found[WEB].status == "ok" and found[WEB].document["bindings"] == []
    assert (tmp_path / "artifacts" / "discovery" / f"{WEB}.json").exists()


def fake_apache(tmp_path: Path, tls: Tls) -> str:
    root = tmp_path / "apache2"
    (root / "sites-enabled").mkdir(parents=True)
    (root / "apache2.conf").write_text(f'ServerRoot "{root}"\nIncludeOptional sites-enabled/*.conf\n')
    site = root / "sites-enabled" / "www.conf"
    site.write_text(
        "<VirtualHost *:18445>\n"
        f"  ServerName {WEB}\n  SSLEngine on\n"
        f"  SSLCertificateFile {tls.crt}\n  SSLCertificateKeyFile {tls.keyfile}\n"
        f"  SSLCertificateChainFile {tls.chain}\n</VirtualHost>\n"
        "<VirtualHost *:80>\n  ServerName plain.example.internal\n</VirtualHost>\n"
    )
    ctl = tmp_path / "ctl"
    ctl.mkdir()
    (ctl / "s.out").write_text(
        f'VirtualHost configuration:\n*:18445                {WEB} ({site}:1)\n*:80                   plain.example.internal ({site}:7)\n'
        f'ServerRoot: "{root}"\n'
    )
    (ctl / "v.out").write_text(f' -D HTTPD_ROOT="{root}"\n -D SERVER_CONFIG_FILE="apache2.conf"\n')
    return executable(
        ctl / "apachectl",
        f'#!/bin/sh\ncase "$1" in\n  -V) cat "{ctl}/v.out";;\n  -S) cat "{ctl}/s.out";;\n  *) exit 64;;\nesac\n',
    )


def test_apache_document_verifies_the_chain_file_and_keeps_the_json_dump(tmp_path, tls):
    found = discover(tmp_path, {APACHE: local_host(tmp_path, apachectl_binary=fake_apache(tmp_path, tls))}, {APACHE: "apache"})

    result = found[APACHE]
    assert (result.status, result.reason) == ("ok", None), result
    [binding] = result.document["bindings"]
    assert (binding["vhost_name"], binding["port"]) == (WEB, 18445)
    assert binding["chain_path"] == str(tls.chain) and binding["chain_diagnostic"] is None  # D1: it verifies the leaf
    assert (binding["cert_fingerprint"], binding["key_public_sha256"]) == (tls.fingerprint, tls.spki)
    assert result.document["webserver"] == "apache"
    dump = tmp_path / "artifacts" / "dumps" / f"{APACHE}.json"
    assert mode(dump) == 0o600
    collector = json.loads(dump.read_text())
    assert str(tmp_path / "apache2" / "sites-enabled" / "www.conf") in collector["files_from_includes"]
    assert str(tmp_path / "apache2" / "apache2.conf") not in collector["files_from_includes"]


def test_a_chain_file_that_does_not_sign_the_leaf_is_not_a_chain(tmp_path, tls):
    other = FixtureCA(NOW)  # an unrelated CA
    tls.write("www.chain.pem", other.chain_pem, 0o644)
    found = discover(tmp_path, {APACHE: local_host(tmp_path, apachectl_binary=fake_apache(tmp_path, tls))}, {APACHE: "apache"})

    [binding] = found[APACHE].document["bindings"]
    assert binding["chain_path"] is None
    # Task 8A's diagnostic for a leaf-only file whose configured chain does not verify it: both facts, in order.
    assert binding["chain_diagnostic"] == (
        "incomplete chain: no configured file holds this leaf's issuer; "
        "chain file does not verify the leaf; not used as chain"
    )


def test_a_missing_chain_file_is_reported_and_the_host_is_still_processed(tmp_path, tls):
    tls.chain.unlink()
    found = discover(tmp_path, {APACHE: local_host(tmp_path, apachectl_binary=fake_apache(tmp_path, tls))}, {APACHE: "apache"})

    [binding] = found[APACHE].document["bindings"]
    assert binding["chain_path"] is None and "unreadable" in binding["chain_diagnostic"]
    assert binding["cert_fingerprint"] == tls.fingerprint


def test_an_unreachable_host_is_reported_beside_a_healthy_one(tmp_path, tls):
    dead = {"ansible_connection": "ssh", "ansible_host": "127.0.0.1", "ansible_port": 1, "ansible_user": "nobody"}
    nginx = fake_nginx(tmp_path, server_block(tls))
    found = discover(tmp_path, {WEB: local_host(tmp_path, nginx_binary=nginx), "dead.example.internal": dead})

    assert found[WEB].status == "ok"
    gone = found["dead.example.internal"]
    assert (gone.status, gone.reason, gone.document) == ("unreachable", "unreachable", None)
    assert gone.error == "host unreachable over SSH"


def test_a_host_missing_from_the_inventory_fails_with_a_fixed_text(tmp_path, tls):
    run = context(tmp_path, {WEB: local_host(tmp_path, nginx_binary=fake_nginx(tmp_path, server_block(tls)))})
    found = discover_hosts(run, [WEB, "nowhere.example.internal"], webservers={}, now=NOW, timeout_seconds=300)
    assert found[WEB].status == "ok"
    assert (found["nowhere.example.internal"].status, found["nowhere.example.internal"].reason) == ("failed", "internal")


@pytest.mark.parametrize("name", ["", "a b", "x:y", "../up", "..", "web*", "a" * 254, "web;rm"])
def test_invalid_hostnames_are_refused_before_any_run(tmp_path, name):
    run = context(tmp_path, {WEB: local_host(tmp_path)})
    with pytest.raises(ValueError, match="hostname"):
        discover_hosts(run, [name], webservers={}, now=NOW)
    assert not (tmp_path / "run").exists()


def test_the_runner_timeout_defaults_to_1500_seconds():
    import inspect

    assert inspect.signature(discover_hosts).parameters["timeout_seconds"].default == 1500
