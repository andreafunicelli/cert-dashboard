"""A1: the Administration hub (``/administration``) — links, status lines, no secrets.

The hub is read-only: every entry is a link to the screen that edits the value, plus one status line
computed server-side. These tests run against the real HTTP stack and PostgreSQL.
"""

import re

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

from app.models import (
    AppSetting,
    EncryptedSetting,
    Server,
    SshHostKey,
    User,
    WorkerHeartbeat,
)
from app.services.audit import Actor
from app.services.worker_credentials import (
    INVENTORY_GIT_TOKEN,
    SSH_PRIVATE_KEY,
    VAULT_PASSWORD,
    set_credential,
)
from tests.integration.conftest import add_server, create_login_user, set_setting

HUB_ROUTES = [
    "/users", "/account", "/inventory", "/settings?tab=inventory", "/settings?tab=worker", "/ssh-keys",
    "/settings?tab=smtp", "/settings?tab=alerts", "/settings?tab=deployment", "/settings?tab=schedule",
    "/settings?tab=trust", "/settings?tab=status", "/settings?tab=maintenance", "/audit",
]


@pytest.fixture(autouse=True)
def isolated(web_factory):
    """The module-scoped factory is shared: start every test from an empty installation."""
    with web_factory.begin() as db:
        for model in (Server, SshHostKey, EncryptedSetting, AppSetting, WorkerHeartbeat):
            db.query(model).delete()


def _content(page: str) -> str:
    return page.split("<main", 1)[1]


def _ssh_private_key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    )


def test_administration_requires_sign_in(client):
    anonymous = client
    response = anonymous.get("/administration", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert anonymous.get("/administration", headers={"Accept": "application/json"}).status_code == 401


def test_every_entry_links_to_its_route_and_the_page_has_no_form(signed_in):
    response = signed_in.get("/administration")
    assert response.status_code == 200 and "no-store" in response.headers["cache-control"]
    content = _content(response.text)
    for href in HUB_ROUTES:
        assert f'href="{href}"' in content, href
    assert "<form" not in content
    for group in ("People and access", "Servers and access", "Alerts and email", "Operations policy", "System"):
        assert group in content


def test_empty_installations_show_next_actions_and_unknown_worker_facts(signed_in):
    content = _content(signed_in.get("/administration").text)
    assert "No hosts yet" in content and '<a href="/inventory">Add a host</a>' in content
    assert "Not configured — optional" in content
    assert "SSH key: missing · Vault password: not set · Git token: not set" in content
    assert "0 trusted in the dashboard · Mounted known_hosts: unknown" in content
    assert "Two-factor authentication off" in content
    assert "Not configured" in content  # SMTP
    assert re.search(r"\d+ warnings", content)


def test_configured_state_reports_each_fact_without_values(signed_in, web_factory, web_settings, web_user):
    key = _ssh_private_key()
    with web_factory.begin() as db:
        db.add(Server(hostname="manual-1.example.test", is_active=True, inventory_source="manual"))
        db.add(Server(hostname="manual-2.example.test", is_active=True, inventory_source="manual"))
        add_server(db, "repo-1.example.test", is_active=True)
        db.add(
            SshHostKey(
                host="web01.example.test",
                key_type="ssh-ed25519",
                public_key="AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialOnly",
                fingerprint_sha256="SHA256:fixture",
                created_by=web_user.id,
            )
        )
        db.get(User, web_user.id).totp_enabled = True
        set_credential(db, web_settings, SSH_PRIVATE_KEY, key, Actor(web_user.id, "fixture"))
        set_credential(db, web_settings, VAULT_PASSWORD, "fixture-vault-password", Actor(web_user.id, "fixture"))
        set_credential(db, web_settings, INVENTORY_GIT_TOKEN, "fixture-token", Actor(web_user.id, "fixture"))
    set_setting(web_factory, "inventory.repo_url", "https://git.example.test/team/inventory.git")
    set_setting(web_factory, "inventory.ref", "main")
    set_setting(web_factory, "smtp.host", "mail.example.test")
    set_setting(web_factory, "alert.recipients", ["ops@example.test"])

    content = _content(signed_in.get("/administration").text)
    assert "3 active hosts (2 manual, 1 repository)" in content
    assert "https://git.example.test/team/inventory.git @ main" in content
    assert "SSH key: configured (Ed25519" in content
    assert "Vault password: set · Git token: set" in content
    assert "1 trusted in the dashboard" in content
    assert "Two-factor authentication on" in content
    assert "Configured" in content
    assert "1 recipient" in content


def test_repository_credentials_never_reach_the_hub(signed_in, web_factory):
    set_setting(web_factory, "inventory.repo_url", "https://user:secret@git.example.test/team/inventory.git")
    content = _content(signed_in.get("/administration").text)
    assert "secret" not in content
    assert "user:" not in content
    assert "https://git.example.test/team/inventory.git @ HEAD" in content


def test_inactive_users_are_counted_separately(signed_in, web_factory):
    create_login_user(web_factory, "inactive-fixture", is_active=False)
    with web_factory() as db:
        active = db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(True)))
        inactive = db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(False)))
    content = _content(signed_in.get("/administration").text)
    assert f"{active} active users · {inactive} inactive" in content
