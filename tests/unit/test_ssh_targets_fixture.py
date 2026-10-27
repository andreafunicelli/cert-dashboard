import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from tests.fixtures.ca import FixtureCA
from tests.fixtures.ssh_targets import (
    SERVICES,
    TargetStack,
    first_server_name,
    parse_certificate_directives,
)

PORTS = {"ssh-nginx-1": 40001, "ssh-nginx-2": 40002, "ssh-apache": 40003}
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def ca():
    return FixtureCA(datetime(2026, 10, 19, 12, 0, tzinfo=UTC))


@pytest.fixture
def stack(tmp_path, ca):
    stack = TargetStack(tmp_path / "stack", ca)  # writes files only: no Docker needed
    stack.apply_ports(PORTS)
    return stack


def test_old_material_is_one_leaf_with_its_chain_and_key(stack):
    old = stack.old
    leaf = x509.load_pem_x509_certificate(old.cert_pem)
    assert leaf.fingerprint(hashes.SHA256()).hex() == old.fingerprint
    names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(names.get_values_for_type(x509.DNSName)) == {"www.example.internal", "legacy.example.internal"}
    assert old.fullchain_pem == old.cert_pem + old.chain_pem
    assert len(old.chain_fingerprints) == 1 and len(old.spki_sha256) == 64


def test_fixture_directories_hold_the_pinned_keys_and_the_initial_tls_material(stack):
    base = stack.directory / "targets"
    for service in SERVICES:
        assert (base / service / "ssh_host_ed25519_key").read_bytes().startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
        authorized = (base / service / "authorized_keys").read_text()
        assert authorized.startswith("ssh-ed25519 ") and authorized.endswith("\n")
    assert stack.client_key.endswith(b"-----END OPENSSH PRIVATE KEY-----\n")
    one, two, apache = (base / name / "tls" for name in SERVICES)
    assert {p.name for p in one.iterdir()} == {"www.crt", "www.key", "legacy.key"}
    assert (one / "www.crt").read_bytes() == stack.old.fullchain_pem
    assert (one / "legacy.key").read_bytes() == (one / "www.key").read_bytes() == stack.old.key_pem
    assert {p.name for p in two.iterdir()} == {"www.crt", "www.key"}
    assert {p.name for p in apache.iterdir()} == {"www.crt", "www.key", "www.chain.pem"}
    assert (apache / "www.crt").read_bytes() == stack.old.cert_pem
    assert (apache / "www.chain.pem").read_bytes() == stack.old.chain_pem
    assert len({(base / s / "ssh_host_ed25519_key").read_bytes() for s in SERVICES}) == 3
    secrets = {p.name for p in (stack.directory / "secrets").iterdir()}
    assert secrets == set(yaml.safe_load((ROOT / "docker-compose.test.yml").read_text())["secrets"])


def test_known_hosts_pins_each_target_and_a_foreign_key_replaces_exactly_one(stack):
    pinned = stack.known_hosts.read_text().splitlines()
    assert [line.split()[0] for line in pinned] == [f"[127.0.0.1]:{PORTS[s]}" for s in SERVICES]
    forged = stack.known_hosts_with_foreign_key("ssh-nginx-1").splitlines()
    assert forged[1:] == pinned[1:]
    assert forged[0].split()[:2] == pinned[0].split()[:2]  # same host and key type...
    assert forged[0].split()[2] != pinned[0].split()[2]  # ...but a different key


def test_inventory_hosts_follow_the_harness_table(stack):
    assert stack.inventory_hosts() == {
        "web01.example.internal": {"ansible_host": "127.0.0.1", "ansible_port": 40001, "ansible_user": "cdeploy",
                                   "groups": ["canary_ring"], "webserver_type": "nginx"},
        "web02.example.internal": {"ansible_host": "127.0.0.1", "ansible_port": 40002, "ansible_user": "cdeploy",
                                   "groups": ["ring_a"]},
        "web03.example.internal": {"ansible_host": "127.0.0.1", "ansible_port": 40003, "ansible_user": "cdeploy",
                                   "groups": ["ring_a"], "webserver_type": "apache"},
    }
    overridden = stack.inventory_hosts(ansible_user="root", webserver_type=None)
    assert all(v["ansible_user"] == "root" and "webserver_type" not in v for v in overridden.values())


def test_inventory_file_is_parsed_by_ansible_with_groups_and_no_groups_variable(stack, tmp_path):
    inventory = stack.inventory_file(tmp_path)
    tool = Path(sys.executable).parent / "ansible-inventory"
    if not tool.exists() and shutil.which("ansible-inventory") is None:
        pytest.skip("ansible-inventory not installed")
    result = subprocess.run([str(tool) if tool.exists() else "ansible-inventory", "-i", str(inventory), "--list"],
                            capture_output=True, text=True, check=True)
    document = json.loads(result.stdout)
    assert document["canary_ring"]["hosts"] == ["web01.example.internal"]
    assert document["ring_a"]["hosts"] == ["web02.example.internal", "web03.example.internal"]
    host_vars = document["_meta"]["hostvars"]
    assert host_vars["web03.example.internal"]["ansible_port"] == 40003
    assert host_vars["web03.example.internal"]["webserver_type"] == "apache"
    assert "webserver_type" not in host_vars["web02.example.internal"]
    assert "groups" not in yaml.safe_load(inventory.read_text())["all"]["hosts"]["web01.example.internal"]


def test_ping_playbook_is_valid_and_becomes_root():
    tool = Path(sys.executable).parent / "ansible-playbook"
    if not tool.exists():
        pytest.skip("ansible-playbook not installed")
    playbook = ROOT / "tests/fixtures/ansible/ping.yml"
    subprocess.run([str(tool), "--syntax-check", "-i", "localhost,", str(playbook)], capture_output=True,
                   text=True, check=True)
    (play,) = yaml.safe_load(playbook.read_text())
    assert play["become"] is True and play["hosts"] == "all" and play["gather_facts"] is False


def test_certificate_directives_are_paired_with_the_vhost_of_their_file():
    output = (
        "/etc/nginx/conf.d/www.conf:    ssl_certificate /etc/nginx/ssl/www.crt;\n"
        "/etc/apache2/sites-available/www.conf:    SSLCertificateFile /etc/apache2/ssl/www.crt\n"
        "not a grep line\n"
    )
    assert parse_certificate_directives(output) == [
        ("/etc/nginx/conf.d/www.conf", "/etc/nginx/ssl/www.crt"),
        ("/etc/apache2/sites-available/www.conf", "/etc/apache2/ssl/www.crt"),
    ]
    assert first_server_name("server {\n    listen 1 ssl;\n    server_name legacy.example.internal;\n}") == "legacy.example.internal"
    assert first_server_name("<VirtualHost *:80>\n  ServerName www.example.internal\n</VirtualHost>") == "www.example.internal"
    assert first_server_name("ssl_certificate /etc/ssl/certs/snakeoil.pem;") is None
