"""Task 8B against the SSH targets: pinned SSH, sudo, real nginx/Apache, nothing written on the targets (§10.2 scenario 2)."""

import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.ansible.discovery import discover_hosts
from app.ansible.runner import RunnerContext
from tests.fixtures.ca import FixtureCA

WEB01, WEB02, WEB03 = "web01.example.internal", "web02.example.internal", "web03.example.internal"
WEBSERVERS = {WEB01: "nginx", WEB02: None, WEB03: "apache"}
INCOMPLETE = "incomplete chain: no configured file holds this leaf's issuer"
NOT_VERIFYING = "chain file does not verify the leaf; not used as chain"
UNREADABLE = "chain file unreadable; not used as chain"
WWW_CRT, WWW_KEY = "/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key"


def runner_for(runner_secrets, ssh_targets, tmp_path) -> RunnerContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return RunnerContext(runner_secrets, ssh_targets.inventory_file(tmp_path), tmp_path / "run", tmp_path / "artifacts")


def discover(runner_secrets, ssh_targets, tmp_path, now, *hostnames):
    return discover_hosts(
        runner_for(runner_secrets, ssh_targets, tmp_path),
        list(hostnames),
        webservers={name: WEBSERVERS[name] for name in hostnames},
        now=now,
    )


def find(document, vhost, port=None):
    [row] = [b for b in document["bindings"] if b["vhost_name"] == vhost and port in (None, b["port"])]
    return row


def certificate_fingerprints(pem: str) -> list[str]:
    return [c.fingerprint(hashes.SHA256()).hex() for c in x509.load_pem_x509_certificates(pem.encode())]


# --- §10.2 scenario 2 --------------------------------------------------------------------------------


def test_nginx_documents_match_the_target_and_nothing_is_written(
    ssh_targets, fresh_targets, runner_secrets, tmp_path, now
):
    found = discover(runner_secrets, ssh_targets, tmp_path, now, WEB01, WEB02)

    web01 = found[WEB01]
    assert (web01.status, web01.reason) == ("ok", None), web01
    rows = {(b["vhost_name"], b["key_path"]): b for b in web01.document["bindings"]}
    www = rows[("www.example.internal", WWW_KEY)]
    assert (www["port"], www["cert_path"], www["config_file"]) == (18443, WWW_CRT, "/etc/nginx/conf.d/www.conf")
    assert (www["cert_owner"], www["cert_group"], www["cert_mode"], www["key_mode"]) == (
        "root", "root", "0644", "0600")  # fmt: skip
    assert (www["cert_fingerprint"], www["key_public_sha256"]) == (ssh_targets.old.fingerprint, ssh_targets.old.spki_sha256)
    assert rows[("legacy.example.internal", "/etc/nginx/ssl/legacy.key")]["cert_path"] == WWW_CRT
    assert found[WEB02].document["webserver"] == "nginx"  # auto-detected

    dump = tmp_path / "artifacts" / "dumps" / f"{WEB01}.txt"
    assert dump.stat().st_mode & 0o777 == 0o600
    assert "# configuration file /etc/nginx/conf.d/legacy.conf:" in dump.read_text()
    document_file = tmp_path / "artifacts" / "discovery" / f"{WEB01}.json"
    assert document_file.stat().st_mode & 0o777 == 0o600 and json.loads(document_file.read_text()) == web01.document
    events = list((tmp_path / "run").rglob("job_events/*.json"))
    assert events and not any("ssl_certificate" in p.read_text() for p in events)
    assert not any("PRIVATE KEY" in p.read_text() for p in events)
    assert ssh_targets.unchanged_since_reset("ssh-nginx-1") and ssh_targets.unchanged_since_reset("ssh-nginx-2")


def test_apache_document_with_chain_file(ssh_targets, fresh_targets, runner_secrets, tmp_path, now):
    found = discover(runner_secrets, ssh_targets, tmp_path, now, WEB03)

    web03 = found[WEB03]
    assert (web03.status, web03.reason) == ("ok", None), web03
    [www] = web03.document["bindings"]  # the plain :80 vhost has no binding
    assert (www["vhost_name"], www["port"], www["config_file"]) == (
        "www.example.internal", 18445, "/etc/apache2/sites-enabled/www.conf")  # fmt: skip
    assert (www["cert_path"], www["key_path"]) == ("/etc/apache2/ssl/www.crt", "/etc/apache2/ssl/www.key")
    # D1: the chain file is the chain because its certificate verifies the leaf's signature
    assert www["chain_path"] == "/etc/apache2/ssl/www.chain.pem" and www["chain_diagnostic"] is None
    assert www["cert_mode"] == "0644"
    assert www["cert_fingerprint"] == ssh_targets.old.fingerprint
    assert www["cert_fingerprint"] not in ssh_targets.old.chain_fingerprints  # the chain is not mistaken for the leaf
    assert www["key_public_sha256"] == ssh_targets.old.spki_sha256

    dump = tmp_path / "artifacts" / "dumps" / f"{WEB03}.json"
    assert dump.stat().st_mode & 0o777 == 0o600
    collector = json.loads(dump.read_text())
    assert "/etc/apache2/ports.conf" in collector["files_from_includes"]  # the recursive Include walk ran
    assert "/etc/apache2/sites-enabled/www.conf" in collector["files_from_includes"]
    assert "# configuration file /etc/apache2/apache2.conf:" in collector["config"]
    assert ssh_targets.unchanged_since_reset("ssh-apache")


def test_globally_included_tls_config_is_discovered_read_only(
    ssh_targets, fresh_targets, runner_secrets, tmp_path, now
):
    global_conf = "SSLCertificateFile /etc/apache2/ssl/www.crt\nSSLCertificateKeyFile /etc/apache2/ssl/www.key\n"
    ssh_targets.put("ssh-apache", "/etc/apache2/conf-enabled/zz-global-tls.conf", global_conf.encode(), mode=0o644)
    status = ssh_targets.exec("ssh-apache", "sh", "-c", "apache2ctl -S 2>&1", check=False).stdout
    assert "zz-global-tls.conf" not in status  # `apachectl -S` does not list the file that holds the global TLS config
    ssh_targets.mark_baseline("ssh-apache")

    found = discover(runner_secrets, ssh_targets, tmp_path, now, WEB03)

    assert found[WEB03].status == "ok", found[WEB03]
    default = find(found[WEB03].document, "default")
    assert (default["port"], default["config_file"]) == (18445, "/etc/apache2/conf-enabled/zz-global-tls.conf")
    assert default["cert_path"] == "/etc/apache2/ssl/www.crt"
    assert find(found[WEB03].document, "www.example.internal")["chain_path"] == "/etc/apache2/ssl/www.chain.pem"
    assert ssh_targets.unchanged_since_reset("ssh-apache"), ssh_targets.last_changes


# --- D3: TLS directives in includes -------------------------------------------------------------------


def test_nginx_key_in_a_relative_include_inside_the_server_block(
    ssh_targets, fresh_targets, runner_secrets, tmp_path, now
):
    before = find(discover(runner_secrets, ssh_targets, tmp_path / "before", now, WEB01)[WEB01].document, "www.example.internal")
    config = ssh_targets.read("ssh-nginx-1", "/etc/nginx/conf.d/www.conf").decode()
    moved, count = re.subn(r"^\s*ssl_certificate_key\s+\S+;\n", "    include snippets/www-key.conf;\n", config, flags=re.MULTILINE)
    assert count == 1
    ssh_targets.exec("ssh-nginx-1", "mkdir", "-p", "/etc/nginx/snippets")
    ssh_targets.put("ssh-nginx-1", "/etc/nginx/snippets/www-key.conf", f"ssl_certificate_key {WWW_KEY};\n".encode(), mode=0o644)
    ssh_targets.put("ssh-nginx-1", "/etc/nginx/conf.d/www.conf", moved.encode(), mode=0o644)
    ssh_targets.mark_baseline("ssh-nginx-1")

    found = discover(runner_secrets, ssh_targets, tmp_path / "after", now, WEB01)

    assert found[WEB01].status == "ok", found[WEB01]
    after = find(found[WEB01].document, "www.example.internal")
    for field in ("port", "cert_path", "key_path", "key_exists", "key_mode", "cert_fingerprint", "key_public_sha256"):
        assert after[field] == before[field], field
    assert after["key_path"] == WWW_KEY and after["key_public_sha256"] == ssh_targets.old.spki_sha256
    dump = (tmp_path / "after" / "artifacts" / "dumps" / f"{WEB01}.txt").read_text()
    assert "# configuration file /etc/nginx/snippets/www-key.conf:" in dump
    assert ssh_targets.unchanged_since_reset("ssh-nginx-1"), ssh_targets.last_changes


def test_apache_key_in_an_include_optional_glob_inside_the_virtualhost(
    ssh_targets, fresh_targets, runner_secrets, tmp_path, now
):
    before = find(discover(runner_secrets, ssh_targets, tmp_path / "before", now, WEB03)[WEB03].document, "www.example.internal")
    path = "/etc/apache2/sites-available/www.conf"
    config = ssh_targets.read("ssh-apache", path).decode()
    moved, count = re.subn(r"^\s*SSLCertificateKeyFile\s+\S+\n", "    IncludeOptional tls.d/*.conf\n", config, flags=re.MULTILINE)
    assert count == 1
    ssh_targets.exec("ssh-apache", "mkdir", "-p", "/etc/apache2/tls.d")
    ssh_targets.put("ssh-apache", "/etc/apache2/tls.d/www-key.conf", b"SSLCertificateKeyFile /etc/apache2/ssl/www.key\n", mode=0o644)
    ssh_targets.put("ssh-apache", path, moved.encode(), mode=0o644)
    ssh_targets.mark_baseline("ssh-apache")

    found = discover(runner_secrets, ssh_targets, tmp_path / "after", now, WEB03)

    assert found[WEB03].status == "ok", found[WEB03]
    after = find(found[WEB03].document, "www.example.internal")
    for field in ("port", "cert_path", "key_path", "key_exists", "key_mode", "cert_fingerprint", "key_public_sha256", "chain_path"):
        assert after[field] == before[field], field
    assert after["key_path"] == "/etc/apache2/ssl/www.key" and after["key_public_sha256"] == ssh_targets.old.spki_sha256
    assert ssh_targets.unchanged_since_reset("ssh-apache"), ssh_targets.last_changes


# --- D1: a chain file is a chain only when it verifies the leaf ---------------------------------------------


def test_a_chain_file_that_does_not_sign_the_leaf_is_not_used_as_chain(
    ssh_targets, fresh_targets, runner_secrets, tmp_path, now
):
    stranger = FixtureCA(now).chain_pem  # a CA that has nothing to do with the leaf
    ssh_targets.put("ssh-apache", "/etc/apache2/ssl/www.chain.pem", stranger, mode=0o644)
    ssh_targets.mark_baseline("ssh-apache")

    found = discover(runner_secrets, ssh_targets, tmp_path, now, WEB03)

    [www] = found[WEB03].document["bindings"]
    assert www["chain_path"] is None
    # Task 8A reports both facts for a leaf-only certificate file: no file holds the issuer, and the chain file fails
    assert www["chain_diagnostic"] == f"{INCOMPLETE}; {NOT_VERIFYING}"
    assert www["cert_fingerprint"] == ssh_targets.old.fingerprint
    assert ssh_targets.unchanged_since_reset("ssh-apache")


# --- D1 transport: only certificates leave the target ---------------------------------------------------------


def test_certificate_contents_reach_the_controller_as_certificates_only(
    ssh_targets, fresh_targets, runner_secrets, tmp_path, now
):
    old = ssh_targets.old
    ssh_targets.put("ssh-nginx-2", WWW_CRT, old.fullchain_pem + old.key_pem, mode=0o600)  # certificates and the key
    ssh_targets.mark_baseline("ssh-nginx-2")

    found = discover(runner_secrets, ssh_targets, tmp_path, now, WEB02, WEB01)

    stored = tmp_path / "artifacts" / "certs"
    web02_file = stored / WEB02 / f"{hashlib.sha256(WWW_CRT.encode()).hexdigest()}.pem"
    assert web02_file.stat().st_mode & 0o777 == 0o600
    assert "PRIVATE KEY" not in web02_file.read_text()
    assert certificate_fingerprints(web02_file.read_text()) == [old.fingerprint, *old.chain_fingerprints]
    [www] = found[WEB02].document["bindings"]
    assert (www["cert_fingerprint"], www["key_public_sha256"]) == (old.fingerprint, old.spki_sha256)
    # the key was found inside the certificate file's neighbour; the combined file never travelled as such
    assert all("PRIVATE KEY" not in p.read_text() for p in stored.rglob("*.pem"))
    assert found[WEB01].status == "ok"
    assert ssh_targets.unchanged_since_reset("ssh-nginx-2")


def test_the_dump_and_certificate_contents_never_enter_the_job_events(
    ssh_targets, fresh_targets, runner_secrets, tmp_path, now
):
    discover(runner_secrets, ssh_targets, tmp_path, now, WEB01, WEB03)
    events = [p.read_text() for p in (tmp_path / "run").rglob("job_events/*.json")]
    assert events
    for text in events:
        assert "BEGIN CERTIFICATE" not in text and "ssl_certificate" not in text and "SSLCertificate" not in text


# --- reports for broken inputs ------------------------------------------------------------------------------


def test_missing_and_passphrase_keys_are_reported(ssh_targets, fresh_targets, runner_secrets, tmp_path, now):
    key = serialization.load_pem_private_key(ssh_targets.old.key_pem, None)
    locked = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw")
    )
    # nginx loads every key at `nginx -T`, so an encrypted key needs its ssl_password_file to be a working config
    legacy_conf = ssh_targets.read("ssh-nginx-1", "/etc/nginx/conf.d/legacy.conf").decode()
    with_password = legacy_conf.replace(
        "ssl_certificate_key /etc/nginx/ssl/legacy.key;",
        "ssl_certificate_key /etc/nginx/ssl/legacy.key;\n    ssl_password_file /etc/nginx/ssl/legacy.pass;",
    )
    assert with_password != legacy_conf
    ssh_targets.put("ssh-nginx-1", "/etc/nginx/ssl/legacy.pass", b"pw\n", mode=0o600)
    ssh_targets.put("ssh-nginx-1", "/etc/nginx/conf.d/legacy.conf", with_password.encode(), mode=0o644)
    ssh_targets.put("ssh-nginx-1", "/etc/nginx/ssl/legacy.key", locked, mode=0o600)
    ssh_targets.exec("ssh-apache", "rm", "-f", "/etc/apache2/ssl/www.chain.pem")
    ssh_targets.mark_baseline("ssh-nginx-1")
    ssh_targets.mark_baseline("ssh-apache")

    found = discover(runner_secrets, ssh_targets, tmp_path, now, WEB01, WEB03)

    web01 = found[WEB01].document
    legacy = find(web01, "legacy.example.internal")
    assert (legacy["key_exists"], legacy["key_unreadable"], legacy["key_public_sha256"]) == (True, True, None)
    www = find(web01, "www.example.internal")  # the rest of the host is processed
    assert (www["key_unreadable"], www["key_public_sha256"]) == (False, ssh_targets.old.spki_sha256)
    assert legacy["cert_fingerprint"] == ssh_targets.old.fingerprint

    [apache] = found[WEB03].document["bindings"]
    assert apache["chain_path"] is None and UNREADABLE in apache["chain_diagnostic"]
    assert apache["cert_fingerprint"] == ssh_targets.old.fingerprint
    assert ssh_targets.unchanged_since_reset("ssh-nginx-1") and ssh_targets.unchanged_since_reset("ssh-apache")


def test_failed_dump_is_reported_without_stderr_in_the_document(
    ssh_targets, fresh_targets, runner_secrets, tmp_path, now
):
    ssh_targets.put("ssh-nginx-2", "/etc/nginx/conf.d/broken.conf", b"ssl_certificate_canary 9f3b;\n", mode=0o644)
    ssh_targets.mark_baseline("ssh-nginx-2")

    found = discover(runner_secrets, ssh_targets, tmp_path, now, WEB02, WEB01)

    broken = found[WEB02]
    assert (broken.status, broken.reason, broken.document) == ("failed", "dump_failed", None)
    shown = f"{broken.error} {broken.summary} {broken.log_excerpt}"
    assert "unknown directive" not in shown and "ssl_certificate_canary" not in shown and "9f3b" not in shown
    assert "exit code" in broken.log_excerpt
    assert not (tmp_path / "artifacts" / "discovery" / f"{WEB02}.json").exists()
    assert found[WEB01].status == "ok"  # other hosts are unaffected
    assert ssh_targets.unchanged_since_reset("ssh-nginx-2")


def test_unreachable_host_is_reported(ssh_targets, fresh_targets, runner_secrets, tmp_path, now):
    runner = runner_for(runner_secrets, ssh_targets, tmp_path)
    ssh_targets.stop("ssh-nginx-2")
    try:
        found = discover_hosts(runner, [WEB01, WEB02], webservers={WEB01: "nginx", WEB02: None}, now=now)
    finally:
        ssh_targets.start("ssh-nginx-2")
    assert (found[WEB02].status, found[WEB02].reason, found[WEB02].document) == ("unreachable", "unreachable", None)
    assert found[WEB01].status == "ok"


def test_a_pinned_host_key_mismatch_is_an_auth_failure(ssh_targets, fresh_targets, runner_secrets, tmp_path, now):
    forged = tmp_path / "known_hosts"
    forged.write_text(ssh_targets.known_hosts_with_foreign_key("ssh-apache"))
    runner = runner_for(replace(runner_secrets, known_hosts=forged), ssh_targets, tmp_path)
    found = discover_hosts(runner, [WEB03], webservers={WEB03: "apache"}, now=now)
    assert (found[WEB03].status, found[WEB03].reason, found[WEB03].document) == ("failed", "auth", None)
    assert Path(forged).read_text().count("[127.0.0.1]") == 3
