"""A1: the Overview setup checklist and its six server-side facts (real HTTP, real Postgres)."""

import re

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.jobs.worker import record_worker_start
from app.models import AppSetting, Certificate, EncryptedSetting, Server, SshHostKey, WorkerHeartbeat
from app.services.audit import Actor
from app.services.inventory_sources import MANUAL_SOURCE
from app.services.setup_status import setup_status
from app.services.worker_credentials import SSH_PRIVATE_KEY, set_credential
from tests.integration.conftest import expiring, set_setting


@pytest.fixture(autouse=True)
def isolated(web_factory):
    """The module-scoped factory is shared: start every test from an empty installation."""
    with web_factory.begin() as db:
        for model in (Certificate, Server, SshHostKey, EncryptedSetting, AppSetting, WorkerHeartbeat):
            db.query(model).delete()


def _step(page, number: int) -> str:
    match = re.search(rf'data-setup-step="{number}" data-done="(true|false)"', page)
    assert match is not None, f"step {number} missing"
    return match.group(1)


def _ssh_private_key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    )


def _manual_server(db, hostname: str, **columns) -> Server:
    server = Server(hostname=hostname, inventory_source=MANUAL_SOURCE, is_active=True, **columns)
    db.add(server)
    db.flush()
    return server


def _trust_host_key(web_factory, user_id: int) -> None:
    with web_factory.begin() as db:
        db.add(
            SshHostKey(
                host="web01.example.test",
                key_type="ssh-ed25519",
                public_key="AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialOnly",
                fingerprint_sha256="SHA256:fixture",
                created_by=user_id,
            )
        )


def test_checklist_is_open_without_a_certificate_and_counts_done_steps(signed_in):
    page = signed_in.get("/").text
    assert '<details class="setup-checklist" data-setup-done="0" open>' in page
    assert "Setup: 0 of 6 steps done" in page
    for number in range(1, 7):
        assert _step(page, number) == "false"
    assert page.count(">To do<") == 6 and ">Done<" not in page


def test_each_step_flips_from_to_do_to_done(signed_in, web_factory, web_settings, web_user, clock):
    assert _step(signed_in.get("/").text, 2) == "false"
    with web_factory.begin() as db:
        _manual_server(db, "web01.example.test")
    assert _step(signed_in.get("/").text, 2) == "true"

    assert _step(signed_in.get("/").text, 1) == "false"
    expiring(web_factory, 30)
    assert _step(signed_in.get("/").text, 1) == "true"

    assert _step(signed_in.get("/").text, 3) == "false"
    with web_factory.begin() as db:
        set_credential(db, web_settings, SSH_PRIVATE_KEY, _ssh_private_key(), Actor(web_user.id, "fixture"))
    assert _step(signed_in.get("/").text, 3) == "true"

    assert _step(signed_in.get("/").text, 4) == "false"
    _trust_host_key(web_factory, web_user.id)
    assert _step(signed_in.get("/").text, 4) == "true"

    assert _step(signed_in.get("/").text, 5) == "false"
    set_setting(web_factory, "smtp.host", "mail.example.test")
    assert _step(signed_in.get("/").text, 5) == "true"

    assert _step(signed_in.get("/").text, 6) == "false"
    with web_factory.begin() as db:
        _manual_server(db, "discovered.example.test", last_discovery_status="ok")
    page = signed_in.get("/").text
    # Step 6 was the only one left: once it is done the checklist hides itself (spec §2.2).
    assert 'class="setup-checklist"' not in page
    assert "Setup: 6 of 6 steps done" not in page


def test_checklist_is_collapsed_with_a_certificate_and_absent_when_complete(
    signed_in, web_factory, web_settings, web_user
):
    expiring(web_factory, 30)
    page = signed_in.get("/").text
    assert '<details class="setup-checklist" data-setup-done="1">' in page
    assert '<details class="setup-checklist" data-setup-done="1" open>' not in page
    assert "Setup: 1 of 6 steps done" in page

    with web_factory.begin() as db:
        _manual_server(db, "web01.example.test", last_discovery_status="ok")
        set_credential(db, web_settings, SSH_PRIVATE_KEY, _ssh_private_key(), Actor(web_user.id, "fixture"))
    _trust_host_key(web_factory, web_user.id)
    set_setting(web_factory, "smtp.host", "mail.example.test")
    page = signed_in.get("/").text
    assert "Setup: 6 of 6 steps done" not in page
    assert 'class="setup-checklist"' not in page


def test_key_and_host_trust_are_independent_steps_without_a_reporting_worker(
    signed_in, web_factory, web_settings, web_user
):
    with web_factory.begin() as db:
        set_credential(db, web_settings, SSH_PRIVATE_KEY, _ssh_private_key(), Actor(web_user.id, "fixture"))
    page = signed_in.get("/").text
    assert _step(page, 3) == "true"
    assert _step(page, 4) == "false"
    assert 'href="/ssh-keys"' in page
    assert page.count("Worker not reporting") == 2


def test_a_reporting_worker_counts_its_mounted_key_and_known_hosts(signed_in, web_factory, make_worker, clock, tmp_path):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")
    worker = make_worker(web_factory, ansible_ssh_key=_ssh_private_key(), known_hosts_file=known_hosts)
    record_worker_start(web_factory, worker.settings, worker.worker_id, clock())
    worker.tick()
    page = signed_in.get("/").text
    assert _step(page, 3) == "true"
    assert _step(page, 4) == "true"
    assert "Worker not reporting" not in page


def test_status_strip_counts_hosts_by_source_and_names_the_optional_repository(signed_in, web_factory):
    with web_factory.begin() as db:
        _manual_server(db, "manual-1.example.test")
        _manual_server(db, "manual-2.example.test")
        db.add(Server(hostname="repo-1.example.test", inventory_source="main:hosts.yml@abc123", is_active=True))
    page = signed_in.get("/").text
    assert "<strong>Inventory</strong> <span class=\"mono\">3</span> active hosts (<span class=\"mono\">2</span> manual, <span class=\"mono\">1</span> repository)" in page
    assert "No repository (optional)" in page


def test_setup_status_is_constant_cost(web_factory, clock, count_statements):
    with web_factory() as db, count_statements() as counter:
        status = setup_status(db, clock())
    assert counter.count <= 8
    assert status.done == 0
