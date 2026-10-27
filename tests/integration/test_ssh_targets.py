from dataclasses import replace

import pytest

from app.ansible.runner import AnsibleRun, RunnerContext, run_playbook
from app.services.scans import observe_endpoint
from tests.fixtures.ssh_targets import SERVICES, new_ed25519

PING = "tests/fixtures/ansible/ping.yml"
WEB01, WEB02, WEB03 = "web01.example.internal", "web02.example.internal", "web03.example.internal"


def context(runner_secrets, ssh_targets, tmp_path, secrets=None):
    return RunnerContext(
        secrets or runner_secrets, ssh_targets.inventory_file(tmp_path), tmp_path / "run", tmp_path / "artifacts"
    )


def test_every_target_answers_over_pinned_ssh_with_become(ssh_targets, runner_secrets, tmp_path):
    run = context(runner_secrets, ssh_targets, tmp_path)
    outcome = run_playbook(run, AnsibleRun(PING, None, {}, timeout_seconds=120, forks=3), ident="ping")
    assert outcome.status == "successful"
    assert {name: (host.outcome, host.data["become_user"]) for name, host in outcome.hosts.items()} == {
        WEB01: ("ok", "root"), WEB02: ("ok", "root"), WEB03: ("ok", "root")}


def test_a_wrong_host_key_is_auth_and_never_accepted(ssh_targets, runner_secrets, tmp_path):
    forged = tmp_path / "known_hosts"
    forged.write_text(ssh_targets.known_hosts_with_foreign_key("ssh-nginx-1"))
    run = context(replace(runner_secrets, known_hosts=forged), ssh_targets, tmp_path)
    outcome = run_playbook(run, AnsibleRun(PING, WEB01, {}, 60), ident="forged")
    assert outcome.hosts[WEB01].outcome == "auth"
    assert forged.read_text().count("[127.0.0.1]") == 3  # nothing was learned or rewritten


def test_unknown_host_key_is_auth(ssh_targets, runner_secrets, tmp_path):
    empty = tmp_path / "known_hosts"
    empty.write_text("")
    run = context(replace(runner_secrets, known_hosts=empty), ssh_targets, tmp_path)
    outcome = run_playbook(run, AnsibleRun(PING, WEB02, {}, 60), ident="unknown")
    assert outcome.hosts[WEB02].outcome == "auth"
    assert empty.read_text() == ""


def test_wrong_client_key_is_auth(ssh_targets, runner_secrets, tmp_path):
    stranger = tmp_path / "stranger_key"
    stranger.write_bytes(new_ed25519().private_pem)
    stranger.chmod(0o600)
    run = context(replace(runner_secrets, ssh_key=stranger), ssh_targets, tmp_path)
    outcome = run_playbook(run, AnsibleRun(PING, WEB03, {}, 60), ident="stranger")
    assert outcome.hosts[WEB03].outcome == "auth"


def test_stopped_target_is_transient_network(ssh_targets, runner_secrets, tmp_path):
    run = context(runner_secrets, ssh_targets, tmp_path)
    ssh_targets.stop("ssh-nginx-2")
    try:
        outcome = run_playbook(run, AnsibleRun(PING, WEB02, {}, 60), ident="stopped")
        assert outcome.hosts[WEB02].outcome == "unreachable"
    finally:
        ssh_targets.start("ssh-nginx-2")
    again = context(runner_secrets, ssh_targets, tmp_path)  # the SSH port may change on restart
    outcome = run_playbook(again, AnsibleRun(PING, WEB02, {}, 60), ident="restarted")
    assert outcome.hosts[WEB02].outcome == "ok"


@pytest.mark.parametrize("service", SERVICES)
def test_targets_serve_the_old_certificate_on_their_fixed_ports(ssh_targets, fresh_targets, service):
    old, host = ssh_targets.old, ssh_targets.hosts[service]
    observed = observe_endpoint("127.0.0.1", host.tls_port, "www.example.internal", 5)
    assert observed.failure is None
    assert observed.fingerprint == old.fingerprint
    assert ssh_targets.served_fingerprint(service, "www.example.internal") == old.fingerprint
    if service == "ssh-apache":  # the leaf plus the chain file
        assert observed.chain_length == 1 + len(old.chain_fingerprints)
    if service == "ssh-nginx-1":  # the second vhost is served from the same certificate file
        assert ssh_targets.served_fingerprint(service, "legacy.example.internal") == old.fingerprint
    assert host.tls_port == {"ssh-nginx-1": 18443, "ssh-nginx-2": 18444, "ssh-apache": 18445}[service]


def tree(ssh_targets, service, root):
    """Path, type, mode, owner, symlink target and content hash of everything below ``root``."""
    script = (
        'cd "$1" && find . -printf "%P|%y|%m|%u:%g|%l\\n" | sort && '
        'find . -type f -exec sha256sum {} + | sort -k2'
    )
    return ssh_targets.exec(service, "sh", "-c", script, "sh", root).stdout


@pytest.mark.parametrize(
    ("service", "root", "config"),
    [
        ("ssh-nginx-1", "/etc/nginx", "/etc/nginx/conf.d/www.conf"),
        ("ssh-nginx-2", "/etc/nginx", "/etc/nginx/conf.d/www.conf"),
        ("ssh-apache", "/etc/apache2", "/etc/apache2/sites-available/www.conf"),
    ],
)
def test_reset_restores_the_initial_state(ssh_targets, fresh_targets, service, root, config):
    before = tree(ssh_targets, service, root)
    assert ssh_targets.unchanged_since_reset(service)
    assert ssh_targets.backups(service) == []

    ssh_targets.put(service, config, b"# tampered\n", mode=0o600)
    ssh_targets.put(service, f"{root}/ssl/stray.crt", b"stray\n", mode=0o644)
    ssh_targets.put(service, f"{root}/stray-snippet.conf", b"# stray\n", mode=0o644)
    ssh_targets.exec(service, "rm", "-f", f"{root}/ssl/www.key")
    ssh_targets.exec(service, "sh", "-c", "mkdir -p /var/backups/cert-dashboard/job-1 && "
                     "echo x > /var/backups/cert-dashboard/job-1/manifest.json && mkdir -p /home/cdeploy/inventory.git")
    assert tree(ssh_targets, service, root) != before
    assert not ssh_targets.unchanged_since_reset(service)
    assert ssh_targets.backups(service) == ["/var/backups/cert-dashboard/job-1"]

    ssh_targets.mark_baseline(service)  # a test's own setup writes are excluded from "read-only" assertions
    assert ssh_targets.unchanged_since_reset(service)

    ssh_targets.reset(service)
    assert tree(ssh_targets, service, root) == before
    assert ssh_targets.unchanged_since_reset(service)
    assert ssh_targets.backups(service) == []
    assert ssh_targets.exec(service, "test", "!", "-e", "/home/cdeploy/inventory.git", check=False).returncode == 0
    assert ssh_targets.served_fingerprint(service, "www.example.internal") == ssh_targets.old.fingerprint


def test_grep_ssl_certificate_lists_the_vhost_certificate_paths(ssh_targets, fresh_targets):
    assert ssh_targets.grep_ssl_certificate() == {
        WEB01: {("www.example.internal", "/etc/nginx/ssl/www.crt"), ("legacy.example.internal", "/etc/nginx/ssl/www.crt")},
        WEB02: {("www.example.internal", "/etc/nginx/ssl/www.crt")},
        WEB03: {("www.example.internal", "/etc/apache2/ssl/www.crt")},
    }


def test_put_read_stat_and_signals_work_as_root_on_the_target(ssh_targets, fresh_targets):
    ssh_targets.put("ssh-nginx-2", "/etc/nginx/ssl/probe.key", b"probe\n", mode=0o600)
    assert ssh_targets.read("ssh-nginx-2", "/etc/nginx/ssl/probe.key") == b"probe\n"
    stat = ssh_targets.stat("ssh-nginx-2", "/etc/nginx/ssl/probe.key")
    assert (stat.mode, stat.owner, stat.group, stat.size) == (0o600, "root", "root", 6)
    assert ssh_targets.stat("ssh-nginx-2", "/etc/nginx/ssl").mode == 0o755
    ssh_targets.signal_webserver("ssh-nginx-2", "STOP")
    try:
        state = ssh_targets.exec("ssh-nginx-2", "sh", "-c", 'ps -o stat= -p "$(pgrep -o -x nginx)"').stdout.strip()
        assert state.startswith("T")
    finally:
        ssh_targets.signal_webserver("ssh-nginx-2", "CONT")
