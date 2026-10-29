"""The §10.4 acceptance checklist, automated against the container targets (Plan 3 Task 20).

One ordered scenario, one step per §10.4 item, driven through the real HTTP forms and the real worker: the
admin is bootstrapped by ``app.cli``, 2FA is enrolled and used, the SMTP capture receives the test mail and a
real expiry alert, the inventory is served over SSH from ``ssh-nginx-1`` and set through the validated
Settings form, discovery is spot-checked against ``grep ssl_certificate``, a real PFX makes the round trip, a
renewal runs end to end with the fixture CA standing in for the CA portal, the deploy runs canary-first with a
pause and a Continue, the digest is clean, a stopped nginx master forces a real rollback, and the database is
restored into a staging database where one key still decrypts with the same keyring.

The automated run does **not** replace the "§10.4 acceptance on real hosts" runbook in
``docs/operations.md``: this suite proves the code paths, the runbook proves one real installation.

D1–D3 shape the scenario: every certificate file's role is decided by verifying its content (``chain_path``
only where a file really signs the leaf), the on-disk key hash is the DER SPKI hash compared with
``public_key_sha256``, and TLS directives are read both inline and from includes — so the scenario moves each
webserver's key directive into a nested include before discovery.
"""

from __future__ import annotations

import re
from datetime import timedelta
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from sqlalchemy import select

from app.crypto.keys import public_key_sha256
from app.crypto.pfx import build_pfx
from app.models import Binding, Certificate, PrivateKey, Server
from app.services.certificates import unwrap_key

WEB01 = "web01.example.internal"
WEB02 = "web02.example.internal"
WEB03 = "web03.example.internal"
WWW = "www.example.internal"
LEGACY = "legacy.example.internal"
NGINX_CRT = "/etc/nginx/ssl/www.crt"
NGINX_KEY = "/etc/nginx/ssl/www.key"
NGINX_LEGACY_KEY = "/etc/nginx/ssl/legacy.key"
NGINX_KEY_INCLUDE = "/etc/nginx/ssl-key.conf"
APACHE_CRT = "/etc/apache2/ssl/www.crt"
APACHE_KEY = "/etc/apache2/ssl/www.key"
APACHE_CHAIN = "/etc/apache2/ssl/www.chain.pem"
APACHE_KEY_INCLUDE = "/etc/apache2/ssl-keys/www.key.conf"
SHA256_LENGTH = 64
_SCENARIO: SimpleNamespace | None = None
_SCENARIO_ERROR: BaseException | None = None


# --- D3: put each webserver's key directive inside an include, before discovery ------------------


def move_key_directives_into_includes(ssh_targets) -> dict[str, str]:
    """Move one key directive per webserver into a nested include (D3).

    nginx: an ``include`` inside the ``server`` block. Apache: an ``IncludeOptional`` glob inside the
    ``<VirtualHost>``. Both webservers must still start, so every move ends with a real config test.
    """
    nginx_path = "/etc/nginx/conf.d/www.conf"
    nginx = ssh_targets.read("ssh-nginx-1", nginx_path).decode("utf-8")
    directive = f"ssl_certificate_key {NGINX_KEY};"
    assert directive in nginx, nginx
    ssh_targets.exec(
        "ssh-nginx-1",
        "sh",
        "-c",
        f"install -d -m 0755 /etc/nginx && printf '%s\\n' '{directive}' > {NGINX_KEY_INCLUDE}",
    )
    ssh_targets.put(
        "ssh-nginx-1",
        nginx_path,
        nginx.replace(directive, f"include {NGINX_KEY_INCLUDE};").encode("utf-8"),
        mode=0o644,
    )
    ssh_targets.exec("ssh-nginx-1", "nginx", "-t")
    ssh_targets.exec("ssh-nginx-1", "nginx", "-s", "reload")

    apache_path = "/etc/apache2/sites-available/www.conf"
    apache = ssh_targets.read("ssh-apache", apache_path).decode("utf-8")
    apache_directive = f"SSLCertificateKeyFile {APACHE_KEY}"
    assert apache_directive in apache, apache
    ssh_targets.exec(
        "ssh-apache",
        "sh",
        "-c",
        f"install -d -m 0755 /etc/apache2/ssl-keys && printf '%s\\n' '{apache_directive}' > {APACHE_KEY_INCLUDE}",
    )
    ssh_targets.put(
        "ssh-apache",
        apache_path,
        apache.replace(apache_directive, "IncludeOptional /etc/apache2/ssl-keys/*.conf").encode("utf-8"),
        mode=0o644,
    )
    ssh_targets.exec("ssh-apache", "sh", "-c", ". /etc/apache2/envvars && apache2ctl configtest")
    ssh_targets.exec("ssh-apache", "sh", "-c", ". /etc/apache2/envvars && apache2ctl graceful")
    return {"nginx": NGINX_KEY_INCLUDE, "apache": APACHE_KEY_INCLUDE}


# --- helpers ------------------------------------------------------------------------------------


def bindings_of(factory, hostname: str) -> list[Binding]:
    """Every active binding of ``hostname`` as the last discovery left it."""
    with factory() as db:
        return list(
            db.scalars(
                select(Binding)
                .join(Server, Server.id == Binding.server_id)
                .where(Server.hostname == hostname, Binding.is_active.is_(True))
                .order_by(Binding.id)
            )
        )


def certificate_row(factory, certificate_id: int) -> Certificate:
    """Reload one certificate row in a fresh session."""
    with factory() as db:
        return db.get(Certificate, certificate_id)


def binding_snapshot(factory) -> dict[tuple[str, str], SimpleNamespace]:
    """Every active binding, with the fields the acceptance steps compare (D1/D2 and the deploy state)."""
    with factory() as db:
        rows = db.execute(
            select(Server.hostname, Binding)
            .join(Server, Server.id == Binding.server_id)
            .where(Binding.is_active.is_(True))
            .order_by(Server.hostname, Binding.vhost_name, Binding.id)
        ).all()
    return {
        (hostname, binding.vhost_name): SimpleNamespace(
            cert_path=binding.cert_path,
            key_path=binding.key_path,
            chain_path=binding.chain_path,
            match_state=str(binding.match_state),
            certificate_id=binding.certificate_id,
            fingerprint=binding.on_disk_fingerprint,
            key_hash=binding.on_disk_key_public_sha256,
            notes=binding.notes,
        )
        for hostname, binding in rows
    }


def stored_key_hash(factory, certificate_id: int) -> str:
    """The DER SPKI hash of the key stored for a certificate (D2's ``public_key_sha256``)."""
    with factory() as db:
        certificate = db.get(Certificate, certificate_id)
        return db.get(PrivateKey, certificate.key_id).public_key_sha256


def public_material(pfx_bytes: bytes, password: str) -> tuple[str, str]:
    """``(leaf DER hex, DER SPKI hash)`` of a PKCS#12 bundle: the only thing compared across the round trip."""
    _key, leaf, _chain = pkcs12.load_key_and_certificates(pfx_bytes, password.encode("utf-8"))
    assert leaf is not None
    return leaf.public_bytes(serialization.Encoding.DER).hex(), public_key_sha256(leaf.public_key())


def pem_certificates(data: bytes) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(data)


def fingerprint(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


# --- the ordered §10.4 scenario -----------------------------------------------------------------


def run_scenario(stack, ssh_targets, compose_targets, staging_restore) -> SimpleNamespace:
    """Every §10.4 item, in order. Returns the evidence the two tests below assert on."""
    record = SimpleNamespace()
    factory = stack.factory

    # 1. Bootstrap an admin, log in, enroll 2FA, log out, log back in with 2FA.
    stack.bootstrap_admin_with_cli()
    stack.login()
    record.totp_secret = stack.enroll_totp()
    stack.logout()
    stack.login(with_totp=True)
    record.account = stack.get("/account")
    record.home = stack.get("/")
    # The trust gate needs an anchor: the fixture root plays the role of the internal CA in the trust store.
    stack.upload_trust_anchor()

    # 2. SMTP settings, the test mail, and a real expiry alert for a certificate 7 days out.
    stack.configure_smtp()
    record.smtp_delivered = stack.send_test_email()
    record.expiring, _pem = stack.import_pem(
        common_name="expiring.example.internal", not_after=stack.clock() + timedelta(days=7)
    )
    record.expiry_job = stack.run_expiry_check().id
    record.expiry_mail = stack.mail_for(record.expiring)

    # 3. The real inventory over SSH, set through the validated form; Test pull; discovery; spot-check.
    record.inventory_url = stack.configure_inventory_over_ssh()
    record.pull = stack.test_pull()
    record.includes = move_key_directives_into_includes(ssh_targets)  # D3: before the first discovery
    record.discovery = stack.discover_all()
    record.grep = ssh_targets.grep_ssl_certificate()
    record.bindings = {
        host: {(binding.vhost_name, binding.cert_path) for binding in bindings_of(factory, host)}
        for host in (WEB01, WEB02, WEB03)
    }
    record.keys = {
        host: {(binding.vhost_name, binding.key_path) for binding in bindings_of(factory, host)}
        for host in (WEB01, WEB02, WEB03)
    }

    # 4. Import the certificate the targets serve as PFX and export it again; compare public material.
    old = ssh_targets.old
    old_pfx = build_pfx(
        serialization.load_pem_private_key(old.key_pem, password=None),
        pem_certificates(old.cert_pem)[0],
        pem_certificates(old.chain_pem),
        stack.secrets.pfx,
        WWW,
    )
    record.pfx_certificate = stack.import_pfx(old_pfx, password=stack.secrets.pfx)
    record.exported = stack.export_pfx(record.pfx_certificate, pfx_password=stack.secrets.export)
    record.imported_material = public_material(old_pfx, stack.secrets.pfx)
    record.exported_material = public_material(record.exported, stack.secrets.export)
    # Importing the certificate must match the bindings, which is what makes them deployable at all.
    record.match_discovery = stack.discover_all()
    # The evidence for step 4 is the state right after the import's discovery, not the state days of deploy
    # later: later steps legitimately move the bindings onto the new certificate.
    record.matched = binding_snapshot(factory)

    # 5. One real renewal end to end, with the fixture CA standing in for the CA portal.
    record.renewal, record.new_certificate = stack.renew(record.pfx_certificate)
    record.renewal_state_issued = stack.renewal_state(record.renewal)

    # 6. Deploy with canary + 100% to two hosts, pause, Continue.
    record.deploy_job = stack.deploy(
        record.new_certificate,
        binding_ids=[binding.id for binding in bindings_of(factory, WEB01)]
        + [binding.id for binding in bindings_of(factory, WEB02)],
        batch_percent=100,
        pause_after_canary=True,
    )
    stack.run_worker(timeout=1200)  # the canary runs, then the job releases its claim and pauses
    record.paused_job = stack.job(record.deploy_job)
    if record.paused_job.status != "paused":
        raise AssertionError(
            "the canary did not pause the deploy: "
            f"status={record.paused_job.status} class={record.paused_job.error_class} "
            f"message={record.paused_job.error_message} result={record.paused_job.result} "
            f"hosts={stack.host_rows(record.deploy_job)}"
        )
    record.paused = stack.report(record.deploy_job)
    stack.continue_deploy(record.deploy_job)
    record.deployed = stack.report(record.deploy_job)
    record.renewal_state_deployed = stack.renewal_state(record.renewal)
    record.nginx_cert = ssh_targets.read("ssh-nginx-2", NGINX_CRT)
    record.nginx_chain_file = ssh_targets.exec(
        "ssh-nginx-2", "sh", "-c", "test -e /etc/nginx/ssl/www.chain.pem", check=False
    ).returncode

    # D1: Apache keeps its own chain file, so the same deploy writes the leaf on its own to ``cert_path``.
    record.web03_chain_paths = {
        (binding.vhost_name, binding.chain_path) for binding in bindings_of(factory, WEB03)
    }
    record.nginx_chain_paths = {
        (binding.vhost_name, binding.chain_path) for binding in bindings_of(factory, WEB01)
    }
    record.web03_deploy = stack.deploy(
        record.new_certificate,
        binding_ids=[binding.id for binding in bindings_of(factory, WEB03)],
        batch_percent=100,
        pause_after_canary=False,
    )
    stack.run_worker(timeout=1200)
    record.web03_report = stack.report(record.web03_deploy)
    record.apache_cert = ssh_targets.read("ssh-apache", APACHE_CRT)
    record.apache_chain = ssh_targets.read("ssh-apache", APACHE_CHAIN)
    record.apache_served = ssh_targets.served_fingerprint("ssh-apache", WWW)

    # D1/D2: a fresh discovery after the deploys: every binding matched, key hash equal to the stored one.
    record.verify_discovery = stack.discover_all()
    record.after_deploy = binding_snapshot(factory)

    record.scan = stack.scan_all()
    record.web02_scan = stack.scan_status_for(WEB02, WWW)
    record.digest = stack.digest()

    # 7. Force a rollback on a test host: put the previous certificate back, then deploy into a stopped master.
    stack.restore_previous_material("ssh-nginx-1")
    record.rollback_discovery = stack.discover(WEB01)
    record.pre_rollback = binding_snapshot(factory)
    ssh_targets.signal_webserver("ssh-nginx-1", "STOP")
    try:
        record.rollback_job = stack.deploy(
            record.new_certificate,
            binding_ids=[binding.id for binding in bindings_of(factory, WEB01)],
            batch_percent=100,
            pause_after_canary=False,
        )
        stack.run_worker(timeout=1200)
    finally:
        ssh_targets.signal_webserver("ssh-nginx-1", "CONT")
    record.rollback = stack.report_host(record.rollback_job, WEB01)
    record.rollback_host_rows = stack.host_rows(record.rollback_job)
    # The rollback restored the files; the operator's next step (runbook §11.5) is a discovery, which must
    # agree with the restored material instead of keeping the deploy's temporary state.
    record.post_rollback_discovery = stack.discover(WEB01)
    record.post_rollback = binding_snapshot(factory)

    # 8. Restore the database and the same master key into a staging database; decrypt one key, export one PFX.
    record.restored = stack.decrypt_one_key_from(staging_restore())
    return record


def scenario(acceptance_stack, ssh_targets, compose_targets, staging_restore) -> SimpleNamespace:
    """Run the ordered scenario once per module; the artifacts test asserts on the same run."""
    global _SCENARIO, _SCENARIO_ERROR
    if _SCENARIO_ERROR is not None:
        raise _SCENARIO_ERROR  # never re-run a failed scenario (the admin now exists, the targets are dirty)
    if _SCENARIO is None:
        try:
            _SCENARIO = run_scenario(acceptance_stack, ssh_targets, compose_targets, staging_restore)
        except BaseException as error:
            _SCENARIO_ERROR = error
            raise
    return _SCENARIO


# --- the §10.4 checklist ------------------------------------------------------------------------


def test_v1_acceptance_against_container_targets(acceptance_stack, ssh_targets, compose_targets, staging_restore):
    factory = acceptance_stack.factory
    s = scenario(acceptance_stack, ssh_targets, compose_targets, staging_restore)

    # 1. Bootstrap an admin, log in, enroll 2FA, log out, log back in with 2FA.
    assert s.home.status_code == 200, "the CLI-created admin could not sign in"
    assert "/account/totp/disable" in s.account.text, "2FA is not enabled after the enrollment"
    assert s.totp_secret and len(s.totp_secret) >= 16

    # 2. SMTP settings, the test email, and a real expiry alert for a certificate set 7 days out.
    assert s.smtp_delivered == 1, "the SMTP test form did not deliver exactly one message"
    # The shipped alert subject is ``Certificate <CN> <phrase>`` (``app/services/alerts.py``); the plan's
    # sketch assumed a ``[Cert Dashboard]`` prefix that neither the spec nor the implementation has.
    assert s.expiry_mail["subject"] == "Certificate expiring.example.internal expires in 7 days", (
        s.expiry_mail["subject"]
    )
    assert "expiring.example.internal" in s.expiry_mail.as_string()

    # 3. Discovery of the real inventory: every binding agrees with ``grep ssl_certificate``.
    assert s.inventory_url.startswith("ssh://cdeploy@127.0.0.1:")
    assert s.pull.result["hosts"] == 3
    assert s.discovery.status == "succeeded", s.discovery.error_message
    assert s.bindings == s.grep, (s.bindings, s.grep)
    # D3: the directives are read inline *and* from includes. The vhost files are reached through the main
    # configuration's includes, and each webserver's key directive now lives in the nested include below —
    # the bindings still carry the right key path, which only a parser that follows the include can produce.
    assert s.includes == {"nginx": NGINX_KEY_INCLUDE, "apache": APACHE_KEY_INCLUDE}
    assert b"ssl_certificate_key /etc/nginx/ssl/www.key;" in ssh_targets.read("ssh-nginx-1", NGINX_KEY_INCLUDE)
    assert b"SSLCertificateKeyFile /etc/apache2/ssl/www.key" in ssh_targets.read("ssh-apache", APACHE_KEY_INCLUDE)
    assert b"IncludeOptional sites-enabled/*.conf" in ssh_targets.read("ssh-apache", "/etc/apache2/apache2.conf")
    assert b"include /etc/nginx/conf.d/*.conf;" in ssh_targets.read("ssh-nginx-1", "/etc/nginx/nginx.conf")
    assert s.keys[WEB01] == {(WWW, NGINX_KEY), (LEGACY, NGINX_LEGACY_KEY)}, "the parser missed the included key"
    assert s.keys[WEB03] == {(WWW, APACHE_KEY)}

    # 4. Import a real certificate and its key via PFX; export it again and compare the public material.
    assert s.imported_material == s.exported_material
    assert s.match_discovery.status == "succeeded"
    # The state captured right after the import's discovery: every binding (web01 has two vhosts sharing
    # ``www.crt``) matches the certificate that was just imported.
    matched = {key: (state.match_state, state.certificate_id) for key, state in s.matched.items()}
    assert set(matched.values()) == {("matched", s.pfx_certificate)}, matched

    # 5. One real renewal end to end with the actual CA portal.
    assert s.renewal_state_issued == "issued"
    assert certificate_row(factory, s.new_certificate).renews_id == s.pfx_certificate

    # 6. Deploy with canary + 100% to two hosts: a pause after the canary, then Continue.
    assert s.paused["phase"] == "paused", s.paused
    assert s.deployed["status"] == "succeeded", s.deployed["status"]
    assert s.deployed["totals"]["failed"] == 0 and s.deployed["totals"]["rolled_back"] == 0
    # Totals count hosts, not bindings: the job targets web01's two vhosts and web02's one (3 bindings, 2 hosts).
    assert s.deployed["totals"]["succeeded"] == 2, s.deployed["totals"]
    assert s.deployed["totals"]["pending"] == 0, s.deployed["totals"]
    assert s.renewal_state_deployed == "deployed"
    new = certificate_row(factory, s.new_certificate)
    assert ssh_targets.served_fingerprint("ssh-nginx-1", WWW) == new.sha256_fingerprint
    assert ssh_targets.served_fingerprint("ssh-nginx-2", WWW) == new.sha256_fingerprint
    # D1: nginx receives the full chain in ``cert_path`` and no separate chain file is ever created.
    assert [fingerprint(cert) for cert in pem_certificates(s.nginx_cert)] == [
        new.sha256_fingerprint,
        *[
            cert.fingerprint(hashes.SHA256()).hex()
            for cert in pem_certificates(bytes(ssh_targets.old.chain_pem))
        ],
    ]
    assert s.nginx_chain_file == 1, "nginx must not get a separate chain file"
    assert s.nginx_chain_paths == {(WWW, None), (LEGACY, None)}
    # D1: the Apache binding keeps its verified chain file as ``chain_path``; its deploy writes the leaf
    # alone to ``cert_path`` and the chain to the chain file.
    assert s.web03_chain_paths == {(WWW, APACHE_CHAIN)}
    assert s.web03_report["status"] == "succeeded", s.web03_report["status"]
    assert [fingerprint(cert) for cert in pem_certificates(s.apache_cert)] == [new.sha256_fingerprint]
    assert [fingerprint(cert) for cert in pem_certificates(s.apache_chain)] == [
        cert.fingerprint(hashes.SHA256()).hex() for cert in pem_certificates(bytes(ssh_targets.old.chain_pem))
    ]
    assert s.apache_served == new.sha256_fingerprint
    # D2: after the deploy a fresh discovery reports every binding matched, with the DER SPKI hash of the
    # stored key — the same value an operator's ``openssl ... | sha256sum`` prints on the host.
    for (host, vhost), state in s.after_deploy.items():
        assert state.match_state == "matched", (host, vhost, state)
        assert state.certificate_id is not None, (host, vhost, state)
        assert re.fullmatch(r"[0-9a-f]{64}", state.key_hash), (host, vhost, state.key_hash)
        assert state.key_hash == stored_key_hash(factory, state.certificate_id), (host, vhost, state)
        assert state.fingerprint == certificate_row(factory, state.certificate_id).sha256_fingerprint, (
            host,
            vhost,
            state,
        )
    # A clean digest: no failed job, no rolled-back host, no mismatch for the deployed vhosts.
    assert s.digest["failed_jobs"] == 0 and s.digest["rolled_back_hosts"] == 0, s.digest
    assert s.digest["new_mismatches"] == 0 and s.digest["mismatches"] == 0, s.digest
    assert s.digest["failed_notifications"] == 0, s.digest
    assert s.scan.status == "succeeded", s.scan.error_message
    assert s.web02_scan == "ok"

    # 7. Force a rollback on a test host and confirm the operator-facing report is accurate.
    assert s.rollback["status"] == "rolled_back", (s.rollback, s.rollback_host_rows, s.pre_rollback)
    assert s.rollback["reason"] == "verify_failed", (s.rollback, s.rollback_host_rows)
    assert s.rollback["files_restored"] is True, (s.rollback, s.rollback_host_rows)
    # ``served`` is what the host serves after the rollback: the certificate the backup restored, i.e. the
    # one the renewal replaced (the plan's ``fingerprint_of(renewal)`` read as "the material now on the host").
    assert s.rollback["served"] == ssh_targets.old.fingerprint, (s.rollback, s.rollback_host_rows)
    # The restored files are what a discovery afterwards must report (runbook §11.5: recover, then Discover).
    restored = {key: state for key, state in s.post_rollback.items() if key[0] == WEB01}
    assert {(key[1], state.match_state, state.certificate_id) for key, state in restored.items()} == {
        (WWW, "matched", s.pfx_certificate),
        (LEGACY, "matched", s.pfx_certificate),
    }, (restored, s.rollback_host_rows)
    assert all(state.fingerprint == ssh_targets.old.fingerprint for state in restored.values()), restored

    # 8. Restore the database and the same master key into a staging stack and decrypt one key (§11.6).
    assert s.restored.certificate_id > 0 and len(s.restored.public_key_sha256) == SHA256_LENGTH
    _key, leaf, _chain = pkcs12.load_key_and_certificates(
        s.restored.pfx, acceptance_stack.secrets.export.encode("utf-8")
    )
    assert leaf is not None and public_key_sha256(leaf.public_key()) == s.restored.public_key_sha256


def test_acceptance_artifacts_hold_no_secrets(acceptance_stack, ssh_targets, compose_targets, staging_restore):
    """After the scenario: no secret in any artifact or run file, and the staging directory is empty."""
    s = scenario(acceptance_stack, ssh_targets, compose_targets, staging_restore)
    factory = acceptance_stack.factory
    with factory() as db:
        certificate = db.get(Certificate, s.new_certificate)
        key_row = db.get(PrivateKey, certificate.key_id)
        key_pem = unwrap_key(key_row, acceptance_stack.keyring).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    body = b"".join(key_pem.splitlines()[1:-1])[:96]
    sentinels = {
        "vault password": acceptance_stack.secrets.vault.encode(),
        "SMTP password": acceptance_stack.secrets.smtp.encode(),
        "PFX password": acceptance_stack.secrets.pfx.encode(),
        "export password": acceptance_stack.secrets.export.encode(),
        "private key PEM header": b"PRIVATE KEY",
        "staged key bytes": body,
    }
    root = acceptance_stack.artifacts_root
    files = [path for path in root.rglob("*") if path.is_file()]
    assert any(path.name.startswith("job_events") or "job_events" in path.parts for path in files), (
        "the scenario produced no run artifacts to check"
    )
    for path in files:
        data = path.read_bytes()
        for name, sentinel in sentinels.items():
            assert sentinel not in data, f"{name} found in {path}"
    staging = acceptance_stack.settings.key_staging_dir
    assert not staging.exists() or list(staging.iterdir()) == [], "the tmpfs key staging area was not emptied"
