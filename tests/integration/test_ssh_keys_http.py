"""Slice B SSH keys (contract §6): trusted host keys over the real HTTP stack and PostgreSQL.

Every test runs with no inventory repository configured (the seeded default), so these prove the
store works with GitHub/Git unconfigured. The module's ``web_factory`` database is shared, so the
fixtures delete the trust rows they create and audit assertions filter by action and target.
"""

import re

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select, text

from app.models import AuditLog, SshHostKey
from app.services.audit import Actor
from app.services.settings import get_setting
from app.services.worker_credentials import SSH_PRIVATE_KEY, set_credential

REPOSITORY_UNSET = "inventory.repo_url"

ED25519 = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
)
ED25519_FP = "SHA256:lbmsoA0yIEcEiVDRnMWuzm+nV+3ZEEpVIURqFoeSspg"
ED25519_ALT = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU"
)
ED25519_ALT_FP = "SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4"
RSA3072 = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDldI9449gAz7AbLf401ZYTWtJhPt0q9fhoUQIy/BhU1/U0"
    "cFkH4gX4QB4RLlM6jmNfiUxQIoAQtmGkXJgbtZRzSIfuV6/0UuCiID7BYFwTL+g4xFakxGTijQqPAUJxVJmTb"
    "562e41MHDBTF6hyz0AaAEKTbLzENiyL33qtOUJ17f3cDpIyK8MaXon6K/f0sABAtmW2NeU/OO9uuXMgPqCRNO"
    "yVwL3MG5yCq8VVHiKeMzdY4F4lVHa8FeHKsEdEWNHMSthuQwqpPQ9EpRP+GzHbdny7nOICcvMLx7+CYd4sCo"
    "CQVT5CbF3viscWq7xr/I/r193mZrTclSm6Q6rkt2Qw3gbJrMSIgwi66LjPwwzESH1u1ygNe6KNuNNdEOFZXuY"
    "3892n0uFKsfcFYzn5FWxxLRcJ2ARm9ehJKFeqZ8SENOH8ex61fDOhWjDq/sPSWspY2UuMgr3/m8bkLtnrxAwb"
    "zRzD5SJXQIdLgSfK/KvMh+UuRV6HCvCmMjF3TqAeXHs= fixture-rsa3072"
)
RSA3072_FP = "SHA256:tb3+Woam4pRweJHGKqrFz+TW3blN0jXY1vVOGfMWc3I"
PRIVATE_KEY_PASTE = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "QyNTUxOQAAACD0fixture0fixture0fixture0fixture0fixture0fixture0fixtureAAAAA\n"
    "-----END OPENSSH PRIVATE KEY-----"
)
CONFIRM_MESSAGE = "Confirm the action to continue."


@pytest.fixture
def clean_host_keys(web_factory):
    def clear():
        with web_factory.begin() as db:
            db.execute(text("DELETE FROM ssh_host_key"))

    clear()
    yield clear
    clear()


@pytest.fixture
def no_repository(web_factory):
    """The seeded default must stay unset: SSH key management never needs a repository."""
    with web_factory() as db:
        assert get_setting(db, REPOSITORY_UNSET) == ""


def _post(client, path, headers=None, follow_redirects=False, **fields):
    return client.post(
        path,
        data={"csrf_token": client.fixture_csrf, **fields},
        headers=headers or {},
        follow_redirects=follow_redirects,
    )


def _add(client, entries, headers=None, follow_redirects=False, **fields):
    return _post(
        client,
        "/ssh-keys/host-keys",
        headers=headers,
        follow_redirects=follow_redirects,
        entries=entries,
        verified="1",
        **fields,
    )


def _rows(factory):
    with factory() as db:
        return list(db.scalars(select(SshHostKey).order_by(SshHostKey.id)))


def _audits(factory, action, target_id=None):
    with factory() as db:
        query = select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)
        if target_id is not None:
            query = query.where(AuditLog.target_id == str(target_id))
        return list(db.scalars(query))


def _textarea_content(page: str) -> str:
    match = re.search(r"<textarea[^>]*name=\"entries\"[^>]*>(.*?)</textarea>", page, re.DOTALL)
    assert match, page[:1200]
    return match.group(1)


def _verified_input(page: str) -> str:
    match = re.search(r"<input[^>]*name=\"verified\"[^>]*>", page)
    assert match, page[:1200]
    return match.group(0)


def test_page_works_without_a_repository_and_shows_the_open_add_form(
    signed_in, clean_host_keys, no_repository
):
    page = signed_in.get("/ssh-keys")
    assert page.status_code == 200
    assert "Worker client key" in page.text
    assert "Not configured" in page.text
    assert "Mounted known_hosts file" in page.text
    assert "Unknown (no worker has reported recently)" in page.text
    assert "No host keys trusted in the dashboard yet." in page.text
    assert 'id="add-host-key"' in page.text
    assert 'action="/ssh-keys/host-keys"' in page.text
    assert "Only trust a key whose fingerprint you checked with the server itself." in page.text
    assert "ssh-keyscan does not authenticate the server." in page.text
    assert "/static/pages/ssh-keys.css" in page.text
    assert 'id="ssh-host-keys-panel"' in page.text
    assert "checked" not in _verified_input(page.text)


def test_add_ssh_keyscan_line_lists_it_and_writes_the_audit_row(
    signed_in, web_factory, web_user, clean_host_keys, no_repository
):
    response = _add(signed_in, f"web01.example.test {ED25519}", comment="lab host")
    assert response.status_code == 303
    assert response.headers["location"] == "/ssh-keys"

    [row] = _rows(web_factory)
    assert (row.host, row.key_type, row.public_key) == (
        "web01.example.test",
        "ssh-ed25519",
        ED25519.split()[1],
    )
    assert row.fingerprint_sha256 == ED25519_FP
    assert row.comment == "lab host"
    assert row.created_by == web_user.id

    [audit] = _audits(web_factory, "ssh_host_key.add", row.id)
    assert audit.target_type == "ssh_host_key"
    assert audit.details == {
        "host": "web01.example.test",
        "key_type": "ssh-ed25519",
        "fingerprint": ED25519_FP,
        "verified": True,
    }
    assert audit.actor_user_id == web_user.id

    page = signed_in.get("/ssh-keys")
    assert "web01.example.test" in page.text
    assert "ssh-ed25519" in page.text
    assert ED25519_FP in page.text
    assert "lab host" in page.text
    assert web_user.username in page.text


def test_success_is_a_flash_on_the_next_page(signed_in, clean_host_keys, no_repository):
    response = _add(signed_in, f"web01.example.test {ED25519}\nweb02.example.test {RSA3072}",
                    follow_redirects=True)
    assert response.status_code == 200
    assert "Trusted 2 host key(s)." in response.text


def test_htmx_add_answers_hx_redirect_and_the_flash_survives(
    signed_in, clean_host_keys, no_repository
):
    response = _add(signed_in, f"web01.example.test {ED25519}", headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert response.headers["HX-Redirect"] == "/ssh-keys"
    assert "HX-Redirect" in response.headers
    page = signed_in.get("/ssh-keys")
    assert "Trusted 1 host key(s)." in page.text


def test_public_key_format_uses_the_hosts_field_and_normalizes_the_host(
    signed_in, web_factory, clean_host_keys, no_repository
):
    response = _add(signed_in, ED25519, hosts="[Web01.Example.Test]:22")
    assert response.status_code == 303
    [row] = _rows(web_factory)
    assert row.host == "web01.example.test"


def test_ecdsa_and_rsa_keys_are_accepted_with_ssh_keygen_fingerprints(
    signed_in, web_factory, clean_host_keys, no_repository
):
    ecdsa = (
        "ecdsa-sha2-nistp256 "
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCkZ3Ha5Z8u1e4O0XudXdtC1aZjc"
        "JURwNRitr4tzqEbv+BDdyvU46KYcZ3FYekJazDGXsRrG9ghsCwyfVOm6F1I="
    )
    response = _add(signed_in, f"web01.example.test {ecdsa}\nweb02.example.test {RSA3072}")
    assert response.status_code == 303
    rows = _rows(web_factory)
    assert [(row.key_type, row.fingerprint_sha256) for row in rows] == [
        ("ecdsa-sha2-nistp256", "SHA256:wJoy5NygV5xD8+o5777f+8GCFnl3PU47e9Fo86eVaLE"),
        ("ssh-rsa", RSA3072_FP),
    ]
    audits = _audits(web_factory, "ssh_host_key.add")
    assert {audit.details["fingerprint"] for audit in audits} >= {
        "SHA256:wJoy5NygV5xD8+o5777f+8GCFnl3PU47e9Fo86eVaLE",
        RSA3072_FP,
    }


def test_invalid_key_format_is_an_inline_422_and_stores_nothing(
    signed_in, web_factory, clean_host_keys, no_repository
):
    pasted = f"web01.example.test ssh-rsa {ED25519.split()[1]}"
    response = _add(signed_in, pasted)
    assert response.status_code == 422
    assert "The key data does not match its type ssh-rsa." in response.text
    assert 'role="alert"' in response.text
    assert 'id="error-entries"' in response.text
    assert 'aria-invalid="true"' in response.text
    assert pasted in response.text  # the attempted input is preserved
    assert _rows(web_factory) == []
    assert "checked" not in _verified_input(response.text)


def test_duplicate_key_is_refused_with_the_existing_fingerprint(
    signed_in, web_factory, web_user, clean_host_keys, no_repository
):
    assert _add(signed_in, f"web01.example.test {ED25519}").status_code == 303
    response = _add(signed_in, f"web01.example.test {ED25519}")
    assert response.status_code == 422
    assert (
        f"web01.example.test already trusts this ssh-ed25519 key ({ED25519_FP}), "
        f"added " in response.text
    )
    assert f"by {web_user.username}." in response.text
    assert len(_rows(web_factory)) == 1


def test_a_different_key_for_the_same_host_and_type_is_refused(
    signed_in, web_factory, clean_host_keys, no_repository
):
    assert _add(signed_in, f"web01.example.test {ED25519}").status_code == 303
    response = _add(signed_in, f"web01.example.test {ED25519_ALT}")
    assert response.status_code == 422
    assert (
        f"web01.example.test already has a different trusted ssh-ed25519 key ({ED25519_FP}). "
        "If the host key was rotated, delete the old key first." in response.text
    )
    [row] = _rows(web_factory)
    assert row.fingerprint_sha256 == ED25519_FP


def test_private_key_paste_is_refused_discarded_and_never_echoed(
    signed_in, web_factory, clean_host_keys, no_repository
):
    response = _add(signed_in, PRIVATE_KEY_PASTE)
    assert response.status_code == 422
    assert "This looks like a private key." in response.text
    assert "BEGIN OPENSSH PRIVATE KEY" not in response.text
    assert "b3BlbnNzaC1rZXktdjEAAAAA" not in response.text
    assert _textarea_content(response.text).strip() == ""
    assert _rows(web_factory) == []


def test_verified_is_required_and_the_checkbox_is_unchecked_on_every_422(
    signed_in, web_factory, clean_host_keys, no_repository
):
    response = _post(signed_in, "/ssh-keys/host-keys", entries=f"web01.example.test {ED25519}")
    assert response.status_code == 422
    assert (
        "Confirm that you verified the fingerprints with the server before trusting them."
        in response.text
    )
    assert "checked" not in _verified_input(response.text)
    assert _rows(web_factory) == []


def test_delete_with_confirmation_removes_the_row_flashes_and_audits(
    signed_in, web_factory, web_user, clean_host_keys, no_repository
):
    assert _add(signed_in, f"web01.example.test {ED25519}").status_code == 303
    [row] = _rows(web_factory)

    response = _post(
        signed_in,
        f"/ssh-keys/host-keys/{row.id}/delete",
        confirm="1",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert (
        "Removed the dashboard-trusted ssh-ed25519 key for web01.example.test. "
        "The mounted known_hosts file and other trusted keys still apply." in response.text
    )
    assert _rows(web_factory) == []
    [audit] = _audits(web_factory, "ssh_host_key.remove", row.id)
    assert audit.details == {
        "host": "web01.example.test",
        "key_type": "ssh-ed25519",
        "fingerprint": ED25519_FP,
    }
    assert audit.actor_user_id == web_user.id


def test_delete_without_confirmation_is_refused_and_keeps_the_row(
    signed_in, web_factory, clean_host_keys, no_repository
):
    assert _add(signed_in, f"web01.example.test {ED25519}").status_code == 303
    [row] = _rows(web_factory)
    response = _post(signed_in, f"/ssh-keys/host-keys/{row.id}/delete")
    assert response.status_code == 422
    assert CONFIRM_MESSAGE in response.text
    assert 'id="field-confirm"' in response.text
    assert len(_rows(web_factory)) == 1


def test_delete_unknown_id_is_404(signed_in, clean_host_keys, no_repository):
    response = _post(signed_in, "/ssh-keys/host-keys/999999/delete", confirm="1")
    assert response.status_code == 404


def test_delete_flash_keeps_a_long_host_under_the_flash_limit(
    signed_in, web_factory, web_user, clean_host_keys, no_repository
):
    long_host = "a" * 248 + ".test"
    assert len(long_host) == 253
    with web_factory.begin() as db:
        row = SshHostKey(
            host=long_host,
            key_type="ssh-ed25519",
            public_key=ED25519.split()[1],
            fingerprint_sha256=ED25519_FP,
            created_by=web_user.id,
        )
        db.add(row)
        db.flush()
        key_id = row.id
    expected = (
        f"Removed the dashboard-trusted ssh-ed25519 key for {long_host[:63]}…. "
        "The mounted known_hosts file and other trusted keys still apply."
    )
    assert len(expected) <= 240
    response = _post(signed_in, f"/ssh-keys/host-keys/{key_id}/delete", confirm="1",
                     follow_redirects=True)
    assert response.status_code == 200
    assert expected in response.text


def test_worker_key_card_shows_type_and_fingerprint_but_never_the_value(
    signed_in, web_factory, web_settings, clean_host_keys, no_repository
):
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    with web_factory.begin() as db:
        state = set_credential(
            db, web_settings, SSH_PRIVATE_KEY, pem, Actor(None, "fixture-admin")
        )
    try:
        assert state.key_type == "Ed25519" and state.fingerprint_sha256
        page = signed_in.get("/ssh-keys")
        assert page.status_code == 200
        assert "Configured" in page.text
        assert "Dashboard" in page.text
        assert "Ed25519" in page.text
        assert state.fingerprint_sha256 in page.text
        assert "BEGIN OPENSSH PRIVATE KEY" not in page.text
    finally:
        with web_factory.begin() as db:
            db.execute(text("DELETE FROM encrypted_setting WHERE name = :name"), {"name": SSH_PRIVATE_KEY})


def test_anonymous_users_are_sent_to_login(client):
    response = client.get("/ssh-keys", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_post_without_a_csrf_token_is_refused(signed_in, web_factory, clean_host_keys, no_repository):
    response = signed_in.post(
        "/ssh-keys/host-keys",
        data={"entries": f"web01.example.test {ED25519}", "verified": "1"},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert _rows(web_factory) == []
