"""Slice B USR: the user detail page, create/edit, deactivate and reactivate.

Real Postgres and the real HTTP stack. Each test owns a migrated database (``queue_factory``)
because user rows and audit rows are committed by design.
"""

import re
from datetime import timedelta
from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from app.auth.local import UserAdminError, deactivate_user, reactivate_user
from app.models import AuditLog, User
from app.services.audit import Actor, record
from tests.integration.conftest import LOGIN_PASSWORD, create_login_user

TEMP_PASSWORD = "temporary-pass-9137"
NEW_PASSWORD = "brand-new-pass-4412"


@pytest.fixture
def web_factory(queue_factory):
    return queue_factory


@pytest.fixture
def web_user(web_factory):
    return create_login_user(web_factory, "admin")


@pytest.fixture
def csrf(signed_in):
    return signed_in.fixture_csrf


def _post(client, csrf, path, headers=None, **data):
    return client.post(
        path, data={**data, "csrf_token": csrf}, headers=headers or {}, follow_redirects=False
    )


def _make(web_factory, username, backend="local", **extra):
    return create_login_user(web_factory, username, backend=backend, **extra)


def _user(factory, user_id) -> User:
    with factory() as db:
        return db.get(User, user_id)


def _audit(factory, action):
    with factory() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


def _add_history(factory, user_id, action="user.update"):
    with factory.begin() as db:
        record(
            db,
            Actor(1, "fixture-admin"),
            action,
            "user",
            str(user_id),
            {"before": {"display_name": "old"}, "after": {"display_name": "new"}},
        )


def _flash(response) -> str:
    return response.cookies.get("cd_flash") or ""


def _follow(client, response):
    """Carry the flash cookie to the redirect target exactly as a browser would."""
    target = response.headers["location"]
    cookie = _flash(response)
    if cookie:
        client.cookies.set("cd_flash", cookie)
    return client.get(target, follow_redirects=False)


class _ElementIds(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids: list[str] = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.append(attributes["id"])


# --- detail page ----------------------------------------------------------------------------------


def test_detail_page_shows_identity_state_actions_and_history(signed_in, web_factory, clock, csrf):
    target = _make(web_factory, "dana", must_change_password=True)
    with web_factory.begin() as db:
        db.execute(update(User).where(User.id == target.id).values(locked_until=clock() + timedelta(hours=1)))
    _add_history(web_factory, target.id)
    page = signed_in.get(f"/users/{target.id}")
    assert page.status_code == 200
    assert 'id="user-detail-panel"' in page.text
    for fragment in (
        "dana",
        "dana@example.test",
        "Deactivate",
        "Reset password",
        "Reset two-factor authentication",
        "Recent activity",
        "user.update",
        "Locked until",
        "Must change password",
        'href="/audit?target_type=user&amp;target_id=' + str(target.id),
        'href="/users"',
    ):
        assert fragment in page.text, fragment
    assert "password_hash" not in page.text and "$argon2" not in page.text
    ids = _ElementIds()
    ids.feed(page.text)
    assert len(ids.ids) == len(set(ids.ids)), "duplicate ids on the detail page"


def test_detail_page_unknown_ids_are_404_and_anonymous_requests_are_401(
    client, signed_in, web_factory, web_user
):
    assert signed_in.get("/users/999999").status_code == 404
    assert signed_in.get(f"/users/{2**70}").status_code == 404
    anonymous = TestClient(
        client.app, base_url="https://testserver", client=("192.0.2.251", 4000), raise_server_exceptions=False
    )
    with anonymous:
        assert (
            anonymous.get(f"/users/{web_user.id}", headers={"Accept": "application/json"}).status_code == 401
        )


def test_list_has_contract_columns_states_and_manage_links(signed_in, web_factory, clock):
    inactive = _make(web_factory, "inactive-user", is_active=False)
    locked = _make(web_factory, "locked-user")
    with web_factory.begin() as db:
        db.execute(update(User).where(User.id == locked.id).values(locked_until=clock() + timedelta(hours=2)))
    _make(web_factory, "changing-user", must_change_password=True)
    page = signed_in.get("/users").text
    for heading in ("Username", "Display name", "Email", "Sign-in", "2FA", "State", "Last login", "Manage"):
        assert f"<th scope=\"col\">{heading}</th>" in page, heading
    for target in (inactive, locked):
        assert f'href="/users/{target.id}"' in page
    assert "Inactive" in page and "Locked until" in page and "Must change password" in page
    assert ">local<" in page


def test_only_user_sees_the_lockout_warning_and_add_user_action(signed_in, web_factory, web_user):
    page = signed_in.get("/users").text
    assert "You are the only user" in page
    assert "Add another administrator so the dashboard is never locked out." in page
    assert 'href="/users?create=1#create-heading"' in page


def test_legacy_notice_query_parameter_is_ignored(signed_in):
    page = signed_in.get("/users?notice=created").text
    assert "User created." not in page and 'data-banner="flash"' not in page


# --- create ---------------------------------------------------------------------------------------


def test_create_redirects_to_the_detail_page_with_a_flash(signed_in, csrf, web_factory):
    response = _post(
        signed_in,
        csrf,
        "/users",
        username="alice",
        email="alice@example.test",
        display_name="Alice A.",
        password=TEMP_PASSWORD,
        confirm_password=TEMP_PASSWORD,
    )
    created = _user(web_factory, int(response.headers["location"].rsplit("/", 1)[1]))
    assert response.status_code == 303 and response.headers["location"] == f"/users/{created.id}"
    target = _follow(signed_in, response)
    assert target.status_code == 200 and 'data-banner="flash"' in target.text
    assert "User alice created. They must change the temporary password at first sign-in." in target.text
    assert TEMP_PASSWORD not in target.text


def test_create_invalid_input_renders_inline_field_errors_and_keeps_values(
    signed_in, csrf, web_factory
):
    duplicate = _post(
        signed_in,
        csrf,
        "/users",
        username="alice",
        email="alice@example.test",
        display_name="Alice A.",
        password=TEMP_PASSWORD,
        confirm_password=TEMP_PASSWORD,
    )
    assert duplicate.status_code == 303
    refused = _post(
        signed_in,
        csrf,
        "/users",
        username="Alice",
        email="other@example.test",
        display_name="Alice Again",
        password=TEMP_PASSWORD,
        confirm_password=TEMP_PASSWORD,
    )
    assert refused.status_code == 422
    assert 'id="error-username"' in refused.text
    assert 'aria-invalid="true" aria-describedby="error-username"' in refused.text
    assert 'href="#field-username"' in refused.text and "already exists" in refused.text
    assert 'value="Alice"' in refused.text and 'value="other@example.test"' in refused.text
    assert TEMP_PASSWORD not in refused.text

    bad_email = _post(
        signed_in,
        csrf,
        "/users",
        username="bob",
        email="not-an-email",
        display_name="",
        password=TEMP_PASSWORD,
        confirm_password=TEMP_PASSWORD,
    )
    assert bad_email.status_code == 422 and 'id="error-email"' in bad_email.text
    assert "valid email" in bad_email.text and 'value="bob"' in bad_email.text

    bad_password = _post(
        signed_in,
        csrf,
        "/users",
        username="carol",
        email="carol@example.test",
        display_name="",
        password="short",
        confirm_password="short",
    )
    assert bad_password.status_code == 422 and 'id="error-password"' in bad_password.text
    assert "at least 12" in bad_password.text and "short" not in bad_password.text


# --- edit -----------------------------------------------------------------------------------------


def test_edit_redirects_to_detail_with_flash_and_audit(signed_in, csrf, web_factory):
    target = _make(web_factory, "erin")
    response = _post(
        signed_in,
        csrf,
        f"/users/{target.id}/edit",
        email="erin.new@example.test",
        display_name="Erin N.",
    )
    assert response.status_code == 303 and response.headers["location"] == f"/users/{target.id}"
    page = _follow(signed_in, response)
    assert "User erin updated." in page.text and 'data-banner="flash"' in page.text
    row = _user(web_factory, target.id)
    assert row.email == "erin.new@example.test" and row.display_name == "Erin N."
    assert [audit.action for audit in _audit(web_factory, "user.update")] == ["user.update"]


def test_edit_invalid_values_re_render_the_detail_page_inline(signed_in, csrf, web_factory):
    target = _make(web_factory, "gina")
    response = _post(
        signed_in, csrf, f"/users/{target.id}/edit", email="nope", display_name="Gina G."
    )
    assert response.status_code == 422
    assert f'<h1>Manage {target.username}</h1>' in response.text
    assert 'id="error-email"' in response.text and 'href="#field-email"' in response.text
    assert 'value="nope"' in response.text and 'value="Gina G."' in response.text
    assert _user(web_factory, target.id).email == "gina@example.test"
    assert signed_in.get("/users/999999").status_code == 404


# --- deactivate -----------------------------------------------------------------------------------


def test_deactivate_redirects_to_detail_with_flash_and_audit(signed_in, csrf, web_factory, web_user):
    target = _make(web_factory, "mia")
    response = _post(
        signed_in, csrf, f"/users/{target.id}/deactivate", current_password=web_user.password
    )
    assert response.status_code == 303 and response.headers["location"] == f"/users/{target.id}"
    page = _follow(signed_in, response)
    assert "User mia deactivated and signed out." in page.text
    assert not _user(web_factory, target.id).is_active
    [audit] = _audit(web_factory, "user.deactivate")
    assert audit.target_id == str(target.id)


def test_deactivate_wrong_current_password_commits_the_admin_failure(
    signed_in, csrf, web_factory, web_user
):
    target = _make(web_factory, "nina")
    before = _user(web_factory, target.id)
    response = _post(
        signed_in, csrf, f"/users/{target.id}/deactivate", current_password="wrong-password-123"
    )
    assert response.status_code == 422 and "incorrect" in response.text.lower()
    assert "wrong-password-123" not in response.text
    # A fresh session sees the committed re-authentication failure and the unchanged target.
    with web_factory() as db:
        admin = db.get(User, web_user.id)
        after = db.get(User, target.id)
        assert admin.failed_attempts == 1
        assert (after.is_active, after.must_change_password, after.password_hash) == (
            before.is_active,
            before.must_change_password,
            before.password_hash,
        )
        assert db.scalar(select(func.count()).select_from(AuditLog).where(
            AuditLog.action == "auth.login_failed"
        )) == 1
    assert _audit(web_factory, "user.deactivate") == []


@pytest.mark.parametrize("action", ["deactivate", "reactivate"])
def test_repeated_wrong_passwords_lock_the_acting_admin(
    signed_in, csrf, web_factory, web_user, action
):
    target = _make(web_factory, "olga", is_active=action == "reactivate")
    extra = {"password": NEW_PASSWORD} if action == "reactivate" else {}
    for _ in range(10):
        refused = _post(
            signed_in,
            csrf,
            f"/users/{target.id}/{action}",
            current_password="wrong-password-123",
            **extra,
        )
        assert refused.status_code == 422
    locked = _post(
        signed_in, csrf, f"/users/{target.id}/{action}", current_password=web_user.password, **extra
    )
    assert locked.status_code == 423 and "temporarily locked" in locked.text.lower()
    assert _user(web_factory, target.id).is_active is (action == "reactivate")


# --- reactivate -----------------------------------------------------------------------------------


def test_reactivate_issues_a_temporary_password_and_forces_a_change(
    signed_in, csrf, web_app, web_factory, web_user
):
    target = _make(web_factory, "pia", is_active=False)
    response = _post(
        signed_in,
        csrf,
        f"/users/{target.id}/reactivate",
        current_password=web_user.password,
        password=NEW_PASSWORD,
    )
    assert response.status_code == 303 and response.headers["location"] == f"/users/{target.id}"
    page = _follow(signed_in, response)
    assert (
        "User pia reactivated. They must change the temporary password at next sign-in." in page.text
    )
    row = _user(web_factory, target.id)
    assert row.is_active and row.must_change_password
    assert row.failed_attempts == 0 and row.locked_until is None
    [audit] = _audit(web_factory, "user.reactivate")
    assert audit.target_id == str(target.id) and audit.details == {"username": "pia"}
    assert NEW_PASSWORD not in str(audit.details)
    with TestClient(
        web_app, base_url="https://testserver", client=("192.0.2.234", 4000), raise_server_exceptions=False
    ) as browser:
        token = re.search(r'name="csrf_token" value="([^"]+)"', browser.get("/login").text).group(1)
        login = browser.post(
            "/login",
            data={"username": "pia", "password": NEW_PASSWORD, "csrf_token": token},
            follow_redirects=False,
        )
        assert login.status_code == 303
        assert browser.get("/certificates", follow_redirects=False).headers["location"] == "/account"


def test_reactivate_refusals_render_on_the_detail_page(signed_in, csrf, web_factory, web_user):
    active = _make(web_factory, "quinn")
    already = _post(
        signed_in,
        csrf,
        f"/users/{active.id}/reactivate",
        current_password=web_user.password,
        password=NEW_PASSWORD,
    )
    assert already.status_code == 422 and "already active" in already.text.lower()
    assert _user(web_factory, active.id).must_change_password is False

    inactive = _make(web_factory, "rita", is_active=False)
    policy = _post(
        signed_in,
        csrf,
        f"/users/{inactive.id}/reactivate",
        current_password=web_user.password,
        password="short",
    )
    assert policy.status_code == 422 and "at least 12" in policy.text
    assert "short" not in policy.text
    assert not _user(web_factory, inactive.id).is_active

    directory = _make(web_factory, "sam", backend="ldap", is_active=False)
    unsupported = _post(
        signed_in,
        csrf,
        f"/users/{directory.id}/reactivate",
        current_password=web_user.password,
        password=NEW_PASSWORD,
    )
    assert unsupported.status_code == 422 and "directory" in unsupported.text.lower()
    assert not _user(web_factory, directory.id).is_active
    assert _audit(web_factory, "user.reactivate") == []


def test_reactivate_wrong_current_password_commits_the_admin_failure(
    signed_in, csrf, web_factory, web_user
):
    target = _make(web_factory, "tina", is_active=False)
    before = _user(web_factory, target.id)
    response = _post(
        signed_in,
        csrf,
        f"/users/{target.id}/reactivate",
        current_password="wrong-password-123",
        password=NEW_PASSWORD,
    )
    assert response.status_code == 422 and "incorrect" in response.text.lower()
    assert "wrong-password-123" not in response.text and NEW_PASSWORD not in response.text
    with web_factory() as db:
        admin = db.get(User, web_user.id)
        after = db.get(User, target.id)
        assert admin.failed_attempts == 1
        assert (after.is_active, after.password_hash, after.must_change_password) == (
            before.is_active,
            before.password_hash,
            before.must_change_password,
        )
        assert db.scalar(select(func.count()).select_from(AuditLog).where(
            AuditLog.action == "auth.login_failed"
        )) == 1
    assert _audit(web_factory, "user.reactivate") == []


# --- reset actions from the detail page -----------------------------------------------------------


def test_reset_password_and_totp_land_on_the_detail_page_with_flashes(
    signed_in, csrf, web_factory, web_user
):
    target = _make(web_factory, "vera")
    reset = _post(
        signed_in,
        csrf,
        f"/users/{target.id}/reset-password",
        new_password=TEMP_PASSWORD,
        confirm_password=TEMP_PASSWORD,
        current_password=web_user.password,
    )
    assert reset.status_code == 303 and reset.headers["location"] == f"/users/{target.id}"
    page = _follow(signed_in, reset)
    assert "Password reset." in page.text and TEMP_PASSWORD not in page.text

    totp = _post(
        signed_in, csrf, f"/users/{target.id}/reset-totp", current_password=web_user.password
    )
    assert totp.status_code == 303 and totp.headers["location"] == f"/users/{target.id}"
    page = _follow(signed_in, totp)
    assert "Two-factor authentication reset." in page.text
    assert _audit(web_factory, "user.password_reset") and _audit(web_factory, "user.totp_reset")


# --- htmx and destructive routing -----------------------------------------------------------------


def test_htmx_edit_and_deactivate_return_hx_redirect_and_flash(signed_in, csrf, web_factory, web_user):
    target = _make(web_factory, "wanda")
    edit = _post(
        signed_in,
        csrf,
        f"/users/{target.id}/edit",
        headers={"HX-Request": "true"},
        email="wanda.new@example.test",
        display_name="Wanda",
    )
    assert edit.status_code == 200 and edit.headers["hx-redirect"] == f"/users/{target.id}"
    assert _flash(edit)
    deactivate = _post(
        signed_in,
        csrf,
        f"/users/{target.id}/deactivate",
        headers={"HX-Request": "true"},
        current_password=web_user.password,
    )
    assert deactivate.status_code == 200 and deactivate.headers["hx-redirect"] == f"/users/{target.id}"
    assert not _user(web_factory, target.id).is_active


def test_htmx_refusal_re_renders_the_same_page_for_swapping(signed_in, csrf, web_factory):
    target = _make(web_factory, "xena")
    response = _post(
        signed_in,
        csrf,
        f"/users/{target.id}/edit",
        headers={"HX-Request": "true"},
        email="nope",
        display_name="Xena",
    )
    assert response.status_code == 422 and 'id="user-detail-panel"' in response.text
    assert 'id="error-email"' in response.text


def test_there_is_no_hard_delete_route(signed_in, csrf, web_factory):
    target = _make(web_factory, "yara")
    assert signed_in.post(
        f"/users/{target.id}/delete", data={"csrf_token": csrf}, follow_redirects=False
    ).status_code in (404, 405)
    assert signed_in.delete(
        f"/users/{target.id}", headers={"X-CSRF-Token": csrf}
    ).status_code in (404, 405)
    assert _user(web_factory, target.id) is not None


def test_new_routes_require_csrf(signed_in, csrf, web_factory, web_user):
    target = _make(web_factory, "zoe", is_active=False)
    for path in (
        f"/users/{target.id}/reactivate",
        f"/users/{target.id}/reset-password",
        f"/users/{target.id}/reset-totp",
    ):
        assert signed_in.post(path, data={}, follow_redirects=False).status_code == 403


# --- service contract -----------------------------------------------------------------------------


def test_reactivate_service_contract(db, actor, now):
    from app.auth.local import create_user

    created = create_user(db, "svc-react", "svc-react@example.test", None, LOGIN_PASSWORD, actor)
    deactivate_user(db, created.id, actor, now)
    reactivated = reactivate_user(db, created.id, LOGIN_PASSWORD, actor, now)
    assert reactivated.is_active and reactivated.must_change_password
    assert reactivated.failed_attempts == 0 and reactivated.locked_until is None
    with pytest.raises(UserAdminError) as already:
        reactivate_user(db, created.id, LOGIN_PASSWORD, actor, now)
    assert already.value.code == "already_active"
    deactivate_user(db, created.id, actor, now)
    with pytest.raises(UserAdminError) as policy:
        reactivate_user(db, created.id, "short", actor, now)
    assert policy.value.code == "policy"
    with pytest.raises(UserAdminError) as missing:
        reactivate_user(db, 424242, LOGIN_PASSWORD, actor, now)
    assert missing.value.code == "not_found"
    directory = User(username="svc-directory", email="svc-directory@example.test", auth_backend="ldap")
    db.add(directory)
    db.flush()
    with pytest.raises(UserAdminError) as unsupported:
        reactivate_user(db, directory.id, LOGIN_PASSWORD, actor, now)
    assert unsupported.value.code == "not_supported"
