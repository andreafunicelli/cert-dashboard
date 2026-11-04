"""SSH keys screen (real Postgres, real HTTP stack): public-key registry plus the worker key card.

The validation rules themselves are unit-tested; here the contract is persistence, duplicate protection,
inline errors that never echo key material, audit rows, and the worker key metadata card.
"""

import hashlib
import re

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select

from app.models import AuditLog, SSHPublicKey
from app.services.audit import Actor
from app.services.ssh_keys import parse_public_key
from app.services.worker_credentials import SSH_PRIVATE_KEY, set_credential
from tests.integration.conftest import create_login_user


@pytest.fixture
def web_factory(queue_factory):
    return queue_factory


@pytest.fixture
def web_user(web_factory):
    return create_login_user(web_factory, "admin")


@pytest.fixture
def csrf(signed_in):
    return signed_in.fixture_csrf


def _key(comment="ansible@laptop") -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def _public(key, comment="ansible@laptop") -> str:
    line = (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode("ascii")
    )
    return f"{line} {comment}".strip()


def _rows(factory):
    with factory() as db:
        return list(db.scalars(select(SSHPublicKey).order_by(SSHPublicKey.id)))


def _audit(factory, action):
    with factory() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


def _add(signed_in, csrf, label, public):
    return signed_in.post(
        "/ssh-keys", data={"csrf_token": csrf, "label": label, "public_key": public}, follow_redirects=False
    )


def test_empty_state_and_worker_key_card_without_a_configured_key(signed_in):
    page = signed_in.get("/ssh-keys")
    assert page.status_code == 200
    assert 'data-empty="ssh-keys"' in page.text and "No public keys registered" in page.text
    assert "No worker SSH key configured" in page.text
    assert 'href="/settings?tab=worker#worker-ssh"' in page.text


def test_add_public_key_registers_it_with_a_fingerprint_and_an_audit_row(signed_in, csrf, web_factory):
    key = _key()
    response = _add(signed_in, csrf, "Ansible production", _public(key))
    assert response.status_code == 303 and response.headers["location"] == "/ssh-keys"
    rows = _rows(web_factory)
    assert len(rows) == 1
    row = rows[0]
    assert row.label == "Ansible production" and row.key_type == "ssh-ed25519"
    assert row.public_key.endswith(" ansible@laptop")
    assert re.fullmatch(r"[0-9a-f]{64}", row.fingerprint_sha256)
    assert row.created_by is not None
    created = _audit(web_factory, "ssh_key.create")
    assert len(created) == 1 and created[0].details["label"] == "Ansible production"
    page = signed_in.get("/ssh-keys")
    assert f'data-ssh-key-id="{row.id}"' in page.text
    assert "Ansible production" in page.text
    assert parse_public_key(_public(key)).fingerprint_openssh in page.text
    assert row.fingerprint_sha256 in page.text


def test_htmx_add_navigates_and_shows_the_success_note(signed_in, csrf, web_factory):
    """htmx cannot observe a 303: success answers HX-Redirect so the browser lands on the list and its flash."""
    response = signed_in.post(
        "/ssh-keys",
        data={"csrf_token": csrf, "label": "Ansible production", "public_key": _public(_key())},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert response.headers["HX-Redirect"] == "/ssh-keys"
    assert response.cookies.get("cd_flash")
    page = signed_in.get("/ssh-keys")
    assert 'data-banner="flash"' in page.text
    assert "registered" in page.text


def test_an_invalid_key_is_an_inline_error_and_writes_nothing(signed_in, csrf, web_factory):
    response = _add(signed_in, csrf, "Broken", "not a key")
    assert response.status_code == 422
    assert 'data-field="public_key"' in response.text and "ssh-ed25519" in response.text
    assert _rows(web_factory) == [] and _audit(web_factory, "ssh_key.create") == []


def test_a_private_key_is_refused_and_never_echoed_back(signed_in, csrf, web_factory):
    private = (
        _key()
        .private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
        )
        .decode("ascii")
    )
    body = [line for line in private.splitlines() if line and not line.startswith("-----")][1]
    response = _add(signed_in, csrf, "Mistake", private)
    assert response.status_code == 422
    assert "private key" in response.text.lower()
    assert body not in response.text  # the pasted secret is not echoed into the page or the error
    assert "Mistake" in response.text  # the label alone is safe to keep
    assert _rows(web_factory) == []


def test_a_duplicate_key_is_refused_under_its_existing_label(signed_in, csrf, web_factory):
    key = _key()
    assert _add(signed_in, csrf, "Ansible production", _public(key, "first")).status_code == 303
    duplicate = _add(signed_in, csrf, "Same key again", _public(key, "second"))
    assert duplicate.status_code == 422
    assert "already registered as “Ansible production”" in duplicate.text
    assert len(_rows(web_factory)) == 1


def test_a_duplicate_label_is_refused_even_for_a_different_key(signed_in, csrf, web_factory):
    assert _add(signed_in, csrf, "Ansible production", _public(_key())).status_code == 303
    duplicate = _add(signed_in, csrf, "ansible PRODUCTION", _public(_key()))
    assert duplicate.status_code == 422
    assert 'data-field="label"' in duplicate.text
    assert len(_rows(web_factory)) == 1


def test_delete_removes_the_key_and_is_audited(signed_in, csrf, web_factory):
    _add(signed_in, csrf, "Ansible production", _public(_key()))
    row = _rows(web_factory)[0]
    response = signed_in.post(f"/ssh-keys/{row.id}/delete", data={"csrf_token": csrf}, follow_redirects=False)
    assert response.status_code == 303
    assert _rows(web_factory) == []
    deleted = _audit(web_factory, "ssh_key.delete")
    assert len(deleted) == 1 and deleted[0].details["label"] == "Ansible production"
    assert signed_in.post("/ssh-keys/999999/delete", data={"csrf_token": csrf}).status_code == 404


def test_the_worker_key_card_shows_type_and_public_fingerprint_but_never_the_value(
    signed_in, web_factory, web_settings, web_user, clock
):
    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    ).decode("ascii")
    with web_factory.begin() as db:
        set_credential(db, web_settings, SSH_PRIVATE_KEY, private, Actor(web_user.id, web_user.username, "192.0.2.10"))
    expected = hashlib.sha256(
        key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()
    page = signed_in.get("/ssh-keys")
    assert page.status_code == 200
    assert "Ed25519" in page.text and expected in page.text
    assert "Replace or remove the private key" in page.text
    assert "No worker SSH key configured" not in page.text
    assert private.splitlines()[1] not in page.text  # the sealed value is never rendered


def test_a_post_without_the_csrf_token_is_refused(signed_in, web_factory):
    response = signed_in.post("/ssh-keys", data={"label": "x", "public_key": _public(_key())}, follow_redirects=False)
    assert response.status_code == 403
    assert _rows(web_factory) == []
