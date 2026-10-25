"""Task 22: local user administration and last-active-user protection (real Postgres, real HTTP stack)."""

import json
import re
import threading
from datetime import timedelta
from html import unescape

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from app.auth.local import (
    UserAdminError,
    begin_totp,
    confirm_totp,
    create_user,
    deactivate_user,
    reset_password,
    reset_totp,
    update_user,
)
from app.models import AuditLog, User, UserSession
from app.services.audit import Actor
from tests.integration.conftest import LOGIN_PASSWORD, create_login_user

TEMP_PASSWORD = "temporary-pass-9137"
NEW_PASSWORD = "brand-new-pass-4412"


# --- fixtures --------------------------------------------------------------------------------------


@pytest.fixture
def web_factory(queue_factory):
    """A private, migrated database per test: user rows and audit rows are committed by design."""
    return queue_factory


@pytest.fixture
def web_user(web_factory):
    """The signed-in administrator; unlike the shared fixture it has a real password."""
    return create_login_user(web_factory, "admin")


@pytest.fixture
def sole_admin(web_user):
    return web_user


@pytest.fixture
def csrf(signed_in):
    return signed_in.fixture_csrf


# --- helpers ---------------------------------------------------------------------------------------


def _user(factory, user_id) -> User:
    with factory() as db:
        return db.get(User, user_id)


def _by_name(factory, username) -> User | None:
    with factory() as db:
        return db.scalar(select(User).where(User.username == username))


def _audit(factory, action):
    with factory() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


def _session_for(factory, user_id, clock):
    from app.auth.sessions import issue_session

    with factory.begin() as db:
        return issue_session(db, user_id, clock(), "192.0.2.77", "other-browser").id


def _cookie_status(web_app, cookie) -> int:
    """Status of GET /account in a separate browser holding `cookie`."""
    with TestClient(
        web_app, base_url="https://testserver", client=("192.0.2.250", 4000), raise_server_exceptions=False
    ) as other:
        other.cookies.set("cd_session", cookie, domain="testserver.local", path="/")
        return other.get("/account", headers={"Accept": "application/json"}).status_code


def _post(client, csrf, path, **data):
    return client.post(path, data={**data, "csrf_token": csrf}, follow_redirects=False)


def _make(web_factory, username, backend="local", **extra):
    return create_login_user(web_factory, username, backend=backend, **extra)


def _enroll_totp(web_factory, web_settings, clock, user):
    actor = Actor(user.id, user.username, "192.0.2.90")
    with web_factory.begin() as db:
        enrollment = begin_totp(db, user.id, web_settings.keyring, actor)
    with web_factory.begin() as db:
        code = pyotp.TOTP(enrollment.secret).at(clock())
        assert confirm_totp(db, user.id, code, web_settings.keyring, clock(), actor)
    return enrollment


def _all_audit_text(factory) -> str:
    with factory() as db:
        return json.dumps(
            [
                [row.action, row.actor_label, row.target_type, row.target_id, row.details]
                for row in db.scalars(select(AuditLog))
            ],
            default=str,
        )


# --- plan test -------------------------------------------------------------------------------------


def test_last_active_user_cannot_be_deactivated(signed_in, sole_admin, csrf, web_factory):
    response = signed_in.post(f"/users/{sole_admin.id}/deactivate", data={"csrf_token": csrf})
    assert response.status_code == 422
    assert _user(web_factory, sole_admin.id).is_active


def test_last_active_user_refusal_is_explained_after_valid_reauthentication(
    signed_in, sole_admin, csrf, web_factory
):
    response = _post(
        signed_in, csrf, f"/users/{sole_admin.id}/deactivate", current_password=sole_admin.password
    )
    assert response.status_code == 422 and "last active user" in response.text.lower()
    assert _user(web_factory, sole_admin.id).is_active
    assert _audit(web_factory, "user.deactivate") == []
    # The session survives a refused self-deactivation.
    assert signed_in.get("/users").status_code == 200


def test_two_concurrent_deactivations_preserve_one_active_user(queue_factory):
    with queue_factory.begin() as db:
        first = create_user(db, "first", "first@example.test", None, LOGIN_PASSWORD, Actor(None, "test"))
        second = create_user(db, "second", "second@example.test", None, LOGIN_PASSWORD, Actor(None, "test"))
        ids = (first.id, second.id)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def run(actor_id, target_id):
        try:
            barrier.wait(timeout=10)
            with queue_factory.begin() as db:
                from datetime import UTC, datetime

                deactivate_user(db, target_id, Actor(actor_id, f"user-{actor_id}"), datetime.now(UTC))
            outcomes.append("deactivated")
        except UserAdminError as exc:
            outcomes.append(exc.code)

    threads = [
        threading.Thread(target=run, args=(ids[0], ids[1])),
        threading.Thread(target=run, args=(ids[1], ids[0])),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(outcomes) == ["deactivated", "last_active_user"]
    with queue_factory() as db:
        assert db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(True))) == 1


# --- list ------------------------------------------------------------------------------------------


def test_list_shows_columns_and_never_secrets(signed_in, web_factory, web_settings, clock, sole_admin):
    other = _make(web_factory, "<b>carol</b>", must_change_password=True)
    enrollment = _enroll_totp(web_factory, web_settings, clock, other)
    with web_factory.begin() as db:
        db.execute(update(User).where(User.id == other.id).values(locked_until=clock() + timedelta(hours=1)))
    directory = _make(web_factory, "dave", backend="ldap")
    page = signed_in.get("/users")
    assert page.status_code == 200
    html = unescape(page.text)
    for heading in (
        "Username",
        "Display name",
        "Email",
        "Backend",
        "Active",
        "2FA",
        "Must change password",
        "Last login",
        "Locked until",
    ):
        assert heading in html
    assert "&lt;b&gt;carol&lt;/b&gt;" in page.text and "<b>carol</b>" not in page.text
    assert "admin@example.test" in html and directory.username in html
    with web_factory() as db:
        hashes = [value for value in db.scalars(select(User.password_hash)) if value]
        ciphertexts = [
            bytes(value).hex() for value in db.scalars(select(User.totp_secret_ciphertext)) if value
        ]
    assert hashes and ciphertexts
    haystack = page.text.lower().replace("-", "")
    for forbidden in (
        *hashes,
        *ciphertexts,
        enrollment.secret,
        *enrollment.recovery_codes,
        "$argon2",
        "password_hash",
        "recovery_codes",
        "totp_secret",
    ):
        assert forbidden.lower().replace("-", "") not in haystack, forbidden
    assert "no-store" in page.headers["cache-control"]


def test_users_requires_a_session_and_csrf(client, signed_in, csrf, web_user):
    anonymous = TestClient(
        client.app, base_url="https://testserver", client=("192.0.2.251", 4000), raise_server_exceptions=False
    )
    with anonymous:
        assert anonymous.get("/users", headers={"Accept": "application/json"}).status_code == 401
        assert anonymous.post("/users", data={}, follow_redirects=False).status_code == 403
    for path in ("/users", f"/users/{web_user.id}/edit", f"/users/{web_user.id}/deactivate"):
        assert signed_in.post(path, data={}, follow_redirects=False).status_code == 403


# --- create ----------------------------------------------------------------------------------------


def _create(client, csrf, **overrides):
    data = {
        "username": "alice",
        "email": "alice@example.test",
        "display_name": "Alice A.",
        "password": TEMP_PASSWORD,
        "confirm_password": TEMP_PASSWORD,
    }
    return _post(client, csrf, "/users", **{**data, **overrides})


def test_create_user_is_local_must_change_password_and_audited_without_secrets(
    signed_in, csrf, web_factory, sole_admin
):
    response = _create(signed_in, csrf)
    assert response.status_code == 303 and response.headers["location"].startswith("/users")
    created = _by_name(web_factory, "alice")
    assert created.auth_backend == "local" and created.is_active and created.must_change_password
    assert created.password_hash.startswith("$argon2id$") and created.display_name == "Alice A."
    [row] = _audit(web_factory, "user.create")
    assert row.target_type == "user" and row.target_id == str(created.id)
    assert row.actor_user_id == sole_admin.id
    assert row.details == {"username": "alice", "email": "alice@example.test"}
    assert TEMP_PASSWORD not in _all_audit_text(web_factory)


def test_new_user_must_change_password_before_any_other_screen(signed_in, csrf, web_app, web_factory):
    assert _create(signed_in, csrf).status_code == 303
    with TestClient(
        web_app, base_url="https://testserver", client=("192.0.2.231", 4000), raise_server_exceptions=False
    ) as browser:
        token = re.search(r'name="csrf_token" value="([^"]+)"', browser.get("/login").text).group(1)
        login = browser.post(
            "/login",
            data={"username": "alice", "password": TEMP_PASSWORD, "csrf_token": token},
            follow_redirects=False,
        )
        assert login.status_code == 303
        for path in ("/", "/certificates", "/users", "/audit"):
            blocked = browser.get(path, follow_redirects=False)
            assert blocked.status_code == 303 and blocked.headers["location"] == "/account", path
        assert browser.get("/account").status_code == 200


def test_duplicate_username_is_rejected_case_insensitively(signed_in, csrf, web_factory):
    assert _create(signed_in, csrf, username="Alice").status_code == 303
    response = _create(signed_in, csrf, username="aLiCe", email="other@example.test")
    assert response.status_code == 422 and "already exists" in response.text
    with web_factory() as db:
        assert db.scalar(select(func.count()).select_from(User).where(User.username == "alice")) == 1
    assert len(_audit(web_factory, "user.create")) == 1


@pytest.mark.parametrize(
    ("password", "confirm", "fragment"),
    [
        ("short-pass1", "short-pass1", "at least 12"),
        ("letmein", "letmein", "too common"),
        (TEMP_PASSWORD, TEMP_PASSWORD + "x", "do not match"),
        ("x" * 1025, "x" * 1025, "1024"),
    ],
)
def test_create_enforces_password_policy_and_never_echoes_it(
    signed_in, csrf, web_factory, password, confirm, fragment
):
    response = _create(signed_in, csrf, password=password, confirm_password=confirm)
    assert response.status_code == 422 and fragment in response.text
    assert password not in response.text and confirm not in response.text
    assert _by_name(web_factory, "alice") is None
    # The non-secret fields are kept so the administrator does not retype them.
    assert 'value="alice"' in response.text


@pytest.mark.parametrize(
    "overrides",
    [
        {"username": ""},
        {"username": "has space"},
        {"username": "a" * 151},
        {"username": "semi;colon"},
        {"email": "not-an-email"},
        {"email": "a@b.test" + "x" * 250},
        {"email": "two@@example.test"},
        {"display_name": "d" * 201},
    ],
)
def test_create_validates_username_email_and_display_name(signed_in, csrf, web_factory, overrides):
    response = _create(signed_in, csrf, **overrides)
    assert response.status_code == 422
    with web_factory() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 1  # only the administrator
    assert _audit(web_factory, "user.create") == []


def test_create_accepts_boundary_username_and_blank_display_name(signed_in, csrf, web_factory):
    name = "u" * 150
    assert _create(signed_in, csrf, username=name, display_name="").status_code == 303
    assert _by_name(web_factory, name).display_name is None
    assert _create(signed_in, csrf, username="x.y_z@host-1").status_code == 303


# --- edit ------------------------------------------------------------------------------------------


def test_edit_changes_email_and_display_name_with_before_after_audit(signed_in, csrf, web_factory):
    target = _make(web_factory, "erin")
    response = _post(
        signed_in, csrf, f"/users/{target.id}/edit", email="erin.new@example.test", display_name="Erin N."
    )
    assert response.status_code == 303
    row = _user(web_factory, target.id)
    assert row.email == "erin.new@example.test" and row.display_name == "Erin N."
    [audit] = _audit(web_factory, "user.update")
    assert audit.target_id == str(target.id)
    assert audit.details == {
        "before": {"email": "erin@example.test", "display_name": "erin"},
        "after": {"email": "erin.new@example.test", "display_name": "Erin N."},
    }


def test_edit_audits_only_changed_fields_and_skips_noops(signed_in, csrf, web_factory):
    target = _make(web_factory, "frank")
    assert (
        _post(
            signed_in, csrf, f"/users/{target.id}/edit", email="frank@example.test", display_name="Frank"
        ).status_code
        == 303
    )
    [audit] = _audit(web_factory, "user.update")
    assert audit.details == {"before": {"display_name": "frank"}, "after": {"display_name": "Frank"}}
    assert (
        _post(
            signed_in, csrf, f"/users/{target.id}/edit", email="frank@example.test", display_name="Frank"
        ).status_code
        == 303
    )
    assert len(_audit(web_factory, "user.update")) == 1


def test_edit_rejects_invalid_email_and_unknown_user(signed_in, csrf, web_factory):
    target = _make(web_factory, "gina")
    bad = _post(signed_in, csrf, f"/users/{target.id}/edit", email="nope", display_name="x")
    assert bad.status_code == 422 and _user(web_factory, target.id).email == "gina@example.test"
    missing = _post(signed_in, csrf, "/users/999999/edit", email="a@example.test", display_name="x")
    assert missing.status_code == 422
    huge = _post(signed_in, csrf, f"/users/{2**70}/edit", email="a@example.test", display_name="x")
    assert huge.status_code == 422
    assert _audit(web_factory, "user.update") == []


def test_edit_cannot_change_security_fields(signed_in, csrf, web_factory):
    target = _make(web_factory, "hank")
    before = _user(web_factory, target.id)
    response = _post(
        signed_in,
        csrf,
        f"/users/{target.id}/edit",
        email="hank@example.test",
        display_name="Hank",
        username="renamed",
        is_active="false",
        password_hash="x",
        auth_backend="ldap",
    )
    assert response.status_code == 303
    after = _user(web_factory, target.id)
    assert (after.username, after.is_active, after.password_hash, after.auth_backend) == (
        before.username,
        before.is_active,
        before.password_hash,
        before.auth_backend,
    )


# --- reset password --------------------------------------------------------------------------------


def test_reset_password_sets_must_change_unlocks_and_revokes_sessions(
    signed_in, csrf, web_app, web_factory, sole_admin, clock
):
    target = _make(web_factory, "ivan")
    with web_factory.begin() as db:
        db.execute(
            update(User)
            .where(User.id == target.id)
            .values(failed_attempts=10, locked_until=clock() + timedelta(minutes=10))
        )
    old_cookie = _session_for(web_factory, target.id, clock)
    assert _cookie_status(web_app, old_cookie) == 200
    old_hash = _user(web_factory, target.id).password_hash

    response = _post(
        signed_in,
        csrf,
        f"/users/{target.id}/reset-password",
        new_password=TEMP_PASSWORD,
        confirm_password=TEMP_PASSWORD,
        current_password=sole_admin.password,
    )
    assert response.status_code == 303 and TEMP_PASSWORD not in response.text
    row = _user(web_factory, target.id)
    assert row.password_hash != old_hash and row.must_change_password
    assert row.failed_attempts == 0 and row.locked_until is None
    assert _cookie_status(web_app, old_cookie) == 401  # revoked immediately, no grace
    with web_factory() as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(UserSession)
                .where(UserSession.user_id == target.id, UserSession.revoked_at.is_(None))
            )
            == 0
        )
    [audit] = _audit(web_factory, "user.password_reset")
    assert audit.target_id == str(target.id) and audit.actor_user_id == sole_admin.id
    assert TEMP_PASSWORD not in _all_audit_text(web_factory) and row.password_hash not in _all_audit_text(
        web_factory
    )
    # The admin's own session is unaffected.
    assert signed_in.get("/users").status_code == 200
    # The temporary password works once, and then forces a change.
    with TestClient(
        web_app, base_url="https://testserver", client=("192.0.2.232", 4000), raise_server_exceptions=False
    ) as browser:
        token = re.search(r'name="csrf_token" value="([^"]+)"', browser.get("/login").text).group(1)
        login = browser.post(
            "/login",
            data={"username": "ivan", "password": TEMP_PASSWORD, "csrf_token": token},
            follow_redirects=False,
        )
        assert login.status_code == 303
        assert browser.get("/certificates", follow_redirects=False).headers["location"] == "/account"


@pytest.mark.parametrize(
    ("new", "confirm", "fragment"),
    [
        ("tooshort", "tooshort", "at least 12"),
        ("letmein", "letmein", "too common"),
        (NEW_PASSWORD, "different-pass-0000", "do not match"),
    ],
)
def test_reset_password_rejects_bad_passwords_without_echo_or_change(
    signed_in, csrf, web_factory, sole_admin, clock, web_app, new, confirm, fragment
):
    target = _make(web_factory, "judy")
    cookie = _session_for(web_factory, target.id, clock)
    before = _user(web_factory, target.id)
    response = _post(
        signed_in,
        csrf,
        f"/users/{target.id}/reset-password",
        new_password=new,
        confirm_password=confirm,
        current_password=sole_admin.password,
    )
    assert response.status_code == 422 and fragment in response.text
    for secret in (new, confirm, sole_admin.password):
        assert secret not in response.text
    after = _user(web_factory, target.id)
    assert after.password_hash == before.password_hash and not after.must_change_password
    assert _cookie_status(web_app, cookie) == 200
    assert _audit(web_factory, "user.password_reset") == []


def test_ldap_user_password_reset_is_disabled_in_html_and_refused_by_server(
    signed_in, csrf, web_factory, sole_admin
):
    target = _make(web_factory, "kim", backend="ldap")
    page = signed_in.get("/users")
    row = re.search(rf'<tr[^>]*data-user-id="{target.id}".*?</tr>', page.text, re.DOTALL)
    assert row is not None
    reset_form = re.search(r"<form[^>]*reset-password.*?</form>", row.group(0), re.DOTALL)
    assert reset_form is not None and "disabled" in reset_form.group(0)
    response = _post(
        signed_in,
        csrf,
        f"/users/{target.id}/reset-password",
        new_password=TEMP_PASSWORD,
        confirm_password=TEMP_PASSWORD,
        current_password=sole_admin.password,
    )
    assert response.status_code == 422 and "directory" in response.text.lower()
    after = _user(web_factory, target.id)
    assert after.password_hash is None and not after.must_change_password
    assert _audit(web_factory, "user.password_reset") == []


# --- reset 2FA -------------------------------------------------------------------------------------


@pytest.mark.parametrize("backend", ["local", "ldap"])
def test_reset_totp_clears_every_factor_and_revokes_sessions(
    signed_in, csrf, web_app, web_factory, web_settings, sole_admin, clock, backend
):
    target = _make(web_factory, "leo", backend=backend)
    enrollment = _enroll_totp(web_factory, web_settings, clock, target)
    assert _user(web_factory, target.id).totp_enabled and enrollment.recovery_codes
    cookie = _session_for(web_factory, target.id, clock)
    if backend == "local":  # the directory backend is a stub that cannot resolve a session owner yet
        assert _cookie_status(web_app, cookie) == 200

    response = _post(signed_in, csrf, f"/users/{target.id}/reset-totp", current_password=sole_admin.password)
    assert response.status_code == 303
    with web_factory() as db:
        assert db.get(UserSession, cookie).revoked_at is not None
    row = _user(web_factory, target.id)
    assert not row.totp_enabled and row.totp_confirmed_at is None and row.totp_last_used_step is None
    assert row.totp_secret_ciphertext is None and row.totp_secret_nonce is None
    assert row.totp_secret_version is None and list(row.recovery_codes) == []
    assert _cookie_status(web_app, cookie) == 401
    [audit] = _audit(web_factory, "user.totp_reset")
    assert audit.target_id == str(target.id) and audit.actor_user_id == sole_admin.id
    assert enrollment.secret not in _all_audit_text(web_factory)


# --- deactivate ------------------------------------------------------------------------------------


def test_deactivate_revokes_sessions_immediately_and_is_audited(
    signed_in, csrf, web_app, web_factory, sole_admin, clock
):
    target = _make(web_factory, "mia")
    cookie = _session_for(web_factory, target.id, clock)
    assert _cookie_status(web_app, cookie) == 200
    response = _post(signed_in, csrf, f"/users/{target.id}/deactivate", current_password=sole_admin.password)
    assert response.status_code == 303 and response.headers["location"].startswith("/users")
    assert not _user(web_factory, target.id).is_active
    assert _cookie_status(web_app, cookie) == 401
    [audit] = _audit(web_factory, "user.deactivate")
    assert audit.target_id == str(target.id) and audit.actor_user_id == sole_admin.id
    # Inactive accounts cannot sign in.
    with TestClient(
        web_app, base_url="https://testserver", client=("192.0.2.233", 4000), raise_server_exceptions=False
    ) as browser:
        token = re.search(r'name="csrf_token" value="([^"]+)"', browser.get("/login").text).group(1)
        login = browser.post(
            "/login",
            data={"username": "mia", "password": LOGIN_PASSWORD, "csrf_token": token},
            follow_redirects=False,
        )
        assert login.status_code != 303 or login.headers["location"] != "/"
    again = _post(signed_in, csrf, f"/users/{target.id}/deactivate", current_password=sole_admin.password)
    assert again.status_code == 422 and "already inactive" in again.text.lower()
    assert len(_audit(web_factory, "user.deactivate")) == 1


def test_self_deactivation_with_another_active_user_signs_the_admin_out(
    signed_in, csrf, web_app, web_factory, sole_admin
):
    _make(web_factory, "nora")
    cookie = signed_in.cookies["cd_session"]
    response = _post(
        signed_in, csrf, f"/users/{sole_admin.id}/deactivate", current_password=sole_admin.password
    )
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert "cd_session=" in response.headers["set-cookie"] and "Max-Age=0" in response.headers["set-cookie"]
    assert not _user(web_factory, sole_admin.id).is_active
    assert _cookie_status(web_app, cookie) == 401


def test_last_active_user_survives_when_the_other_is_inactive(signed_in, csrf, web_factory, sole_admin):
    other = _make(web_factory, "otto", is_active=False)
    response = _post(
        signed_in, csrf, f"/users/{sole_admin.id}/deactivate", current_password=sole_admin.password
    )
    assert response.status_code == 422 and _user(web_factory, sole_admin.id).is_active
    assert not _user(web_factory, other.id).is_active


def test_there_is_no_hard_delete_or_reactivation_route(signed_in, csrf, web_factory):
    target = _make(web_factory, "pam")
    for path in (f"/users/{target.id}/delete", f"/users/{target.id}/reactivate", f"/users/{target.id}"):
        assert signed_in.post(path, data={"csrf_token": csrf}).status_code in (404, 405)
    assert signed_in.delete(f"/users/{target.id}", headers={"X-CSRF-Token": csrf}).status_code in (404, 405)
    assert _user(web_factory, target.id) is not None


# --- re-authentication -----------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["deactivate", "reset-password", "reset-totp"])
def test_wrong_current_password_persists_the_failure_and_changes_nothing(
    signed_in, csrf, web_app, web_factory, web_settings, sole_admin, clock, action
):
    target = _make(web_factory, "quinn")
    _enroll_totp(web_factory, web_settings, clock, target)
    cookie = _session_for(web_factory, target.id, clock)
    before = _user(web_factory, target.id)
    extra = (
        {"new_password": TEMP_PASSWORD, "confirm_password": TEMP_PASSWORD}
        if action == "reset-password"
        else {}
    )
    response = _post(
        signed_in, csrf, f"/users/{target.id}/{action}", current_password="wrong-password-123", **extra
    )
    assert response.status_code == 422 and "incorrect" in response.text.lower()
    assert "wrong-password-123" not in response.text and TEMP_PASSWORD not in response.text
    after = _user(web_factory, target.id)
    assert (after.is_active, after.password_hash, after.totp_enabled, after.must_change_password) == (
        before.is_active,
        before.password_hash,
        before.totp_enabled,
        before.must_change_password,
    )
    assert _cookie_status(web_app, cookie) == 200
    admin = _user(web_factory, sole_admin.id)
    assert admin.failed_attempts == 1  # committed although the request was refused
    assert [row.details for row in _audit(web_factory, "auth.login_failed")] == [
        {"reason": "invalid_current_password"}
    ]
    for name in ("user.deactivate", "user.password_reset", "user.totp_reset"):
        assert _audit(web_factory, name) == []


@pytest.mark.parametrize("action", ["deactivate", "reset-password", "reset-totp"])
def test_missing_current_password_is_refused(signed_in, csrf, web_factory, action):
    target = _make(web_factory, "rita")
    extra = (
        {"new_password": TEMP_PASSWORD, "confirm_password": TEMP_PASSWORD}
        if action == "reset-password"
        else {}
    )
    response = _post(signed_in, csrf, f"/users/{target.id}/{action}", **extra)
    assert response.status_code == 422
    assert _user(web_factory, target.id).is_active


def test_repeated_wrong_passwords_lock_the_administrator_out_of_security_actions(
    signed_in, csrf, web_factory, sole_admin
):
    target = _make(web_factory, "sam")
    for _ in range(10):
        _post(signed_in, csrf, f"/users/{target.id}/deactivate", current_password="wrong-password-123")
    admin = _user(web_factory, sole_admin.id)
    assert admin.failed_attempts == 10 and admin.locked_until is not None
    locked = _post(signed_in, csrf, f"/users/{target.id}/deactivate", current_password=sole_admin.password)
    assert locked.status_code == 423 and _user(web_factory, target.id).is_active
    assert _audit(web_factory, "auth.lockout")


def test_create_and_edit_need_csrf_only(signed_in, csrf, web_factory):
    # No current_password: Task 22 requires re-authentication for security actions only.
    assert _create(signed_in, csrf).status_code == 303
    target = _by_name(web_factory, "alice")
    assert (
        _post(
            signed_in, csrf, f"/users/{target.id}/edit", email="a2@example.test", display_name="A"
        ).status_code
        == 303
    )


# --- service contract ------------------------------------------------------------------------------


def test_services_raise_typed_errors(db, actor, now):
    created = create_user(db, "Svc", "svc@example.test", "Svc", LOGIN_PASSWORD, actor)
    with pytest.raises(UserAdminError) as duplicate:
        create_user(db, "svc", "other@example.test", None, LOGIN_PASSWORD, actor)
    assert duplicate.value.code == "duplicate_username"
    for call, code in (
        (lambda: create_user(db, "n1", "n1@example.test", None, "short", actor), "policy"),
        (lambda: create_user(db, "n2", "bad", None, LOGIN_PASSWORD, actor), "invalid_email"),
        (lambda: update_user(db, created.id, "bad", None, actor), "invalid_email"),
        (lambda: update_user(db, 424242, "ok@example.test", None, actor), "not_found"),
        (lambda: deactivate_user(db, 424242, actor, now), "not_found"),
        (lambda: reset_password(db, 424242, LOGIN_PASSWORD, actor, now), "not_found"),
        (lambda: reset_totp(db, 424242, actor, now), "not_found"),
        (lambda: reset_password(db, created.id, "short", actor, now), "policy"),
    ):
        with pytest.raises(UserAdminError) as error:
            call()
        assert error.value.code == code
    deactivate_user(db, created.id, actor, now)
    with pytest.raises(UserAdminError) as inactive:
        deactivate_user(db, created.id, actor, now)
    assert inactive.value.code == "already_inactive"


def test_reset_password_service_refuses_non_local_backend(db, actor, now):
    directory = User(username="dir-user", email="d@example.test", auth_backend="ldap")
    db.add(directory)
    db.flush()
    with pytest.raises(UserAdminError) as error:
        reset_password(db, directory.id, LOGIN_PASSWORD, actor, now)
    assert error.value.code == "not_supported"
    assert directory.password_hash is None and not directory.must_change_password
