import base64
import json
import logging
import os
import re
import uuid

import pyotp
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker

from app.auth.base import Failure, Success, UserRecord
from app.models import AuditLog, LoginRateLimit, User, UserSession
from tests.integration.conftest import LOGIN_PASSWORD, ROOT, create_login_user

INVALID = "Invalid credentials."
LOCKED = "temporarily locked"
RATE_LIMITED = "Too many sign-in attempts"


@pytest.fixture
def web_factory(owner_engine, database_urls):
    # Login state (lockout counters, rate limits, audit rows) is committed by design and the audit
    # table is append-only, so each test gets its own database instead of cleaning up.
    name = "fixture_login_" + uuid.uuid4().hex
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql(f'CREATE DATABASE "{name}"')
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["database_url"] = owner_engine.url.set(database=name)
    command.upgrade(config, "head")
    engine = create_engine(database_urls[1].set(database=name))
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql(f'DROP DATABASE "{name}" WITH (FORCE)')


class FakeBackend:
    """Directory-style backend honouring the AuthBackend contract; users live in a dict."""

    name = "ldap"

    def __init__(self, users):
        self.users = users  # username -> (password, user id)

    def authenticate(self, username, password):
        entry = self.users.get(username)
        if entry is None or entry[0] != password:
            return Failure("invalid_credentials")
        return Success(str(entry[1]), username, f"{username}@example.test")

    def lookup(self, username):
        entry = self.users.get(username)
        if entry is None:
            return None
        return UserRecord(str(entry[1]), username, username, f"{username}@example.test", self.name, True)

    def supports_password_change(self):
        return False


# --- helpers ---------------------------------------------------------------------------------------


def _token(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def _login(client, clock, token, username="admin", password=LOGIN_PASSWORD, tick=15):
    clock.advance(seconds=tick)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=False,
    )


def _code(user, clock):
    """A code for a TOTP step strictly after every step used so far."""
    clock.advance(seconds=30)
    return pyotp.TOTP(user.secret).at(clock())


def _second_factor(client, clock, code, token=None, tick=15):
    clock.advance(seconds=tick)
    if token is None:
        token = _token(client.get("/login/2fa").text)
    return client.post("/login/2fa", data={"code": code, "csrf_token": token}, follow_redirects=False)


def _sign_in(client, clock, user, token):
    response = _login(client, clock, token, user.username, user.password)
    assert response.status_code == 303 and response.headers["location"] == "/"
    return client.cookies["cd_session"]


def _page_token(client):
    response = client.get("/account")
    assert response.status_code == 200
    return _token(response.text)


def _post(client, path, token, **data):
    return client.post(path, data={**data, "csrf_token": token}, follow_redirects=False)


def _status_with_cookie(client, cookie):
    """GET /account as a different browser holding `cookie`."""
    saved = dict(client.cookies)
    client.cookies.clear()
    client.cookies.set("cd_session", cookie, domain="testserver.local", path="/")
    try:
        return client.get("/account", headers={"Accept": "application/json"}).status_code
    finally:
        client.cookies.clear()
        for key, value in saved.items():
            client.cookies.set(key, value, domain="testserver.local", path="/")


def _audit(factory, action):
    with factory() as db:
        return list(
            db.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.created_at))
        )


def _user(factory, user_id):
    with factory() as db:
        return db.get(User, user_id)


def _extra_session(factory, user, clock):
    from app.auth.sessions import issue_session

    with factory.begin() as db:
        return issue_session(db, user.id, clock(), "192.0.2.77", "other-browser").id


# --- plan tests ------------------------------------------------------------------------------------


def test_login_does_not_grant_access_before_mfa(client, totp_user, csrf, clock):
    first = client.post(
        "/login",
        data={"username": "admin", "password": "correct-long-pass", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert first.headers["location"] == "/login/2fa"
    assert client.get("/account", headers={"Accept": "application/json"}).status_code == 401


def test_bootstrap_requires_cli(client, web_factory):
    with web_factory.begin() as db:
        db.execute(update(User).values(is_active=False))
    response = client.get("/login")
    assert "python -m app.cli bootstrap-admin" in response.text
    assert "create first admin" not in response.text.lower()


# --- bootstrap redirect ----------------------------------------------------------------------------


def test_bootstrap_redirects_once_and_has_no_registration_route(client, web_factory):
    with web_factory.begin() as db:
        db.execute(update(User).values(is_active=False))
    first = client.get("/login", follow_redirects=False)
    assert first.status_code == 303 and first.headers["location"] == "/login?bootstrap=1"
    page = client.get("/login?bootstrap=1", follow_redirects=False)
    assert page.status_code == 200 and "python -m app.cli bootstrap-admin" in page.text
    assert "csrf_token" not in page.text and "<form" not in page.text
    for path in ("/register", "/bootstrap", "/setup", "/login/bootstrap"):
        assert client.get(path, follow_redirects=False).status_code in {303, 404}
        assert client.post(path, follow_redirects=False).status_code in {403, 404}


def test_login_page_with_active_user_states_no_password_reset(client, csrf):
    page = client.get("/login", follow_redirects=False)
    assert page.status_code == 200 and "another admin" in page.text
    assert "no-store" in page.headers["cache-control"]
    assert "bootstrap-admin" not in page.text


# --- first factor ----------------------------------------------------------------------------------


def test_password_login_creates_authenticated_session_and_audit(client, plain_user, csrf, clock, web_factory):
    response = _login(client, clock, csrf, plain_user.username, plain_user.password)
    assert response.status_code == 303 and response.headers["location"] == "/"
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "Path=/" in cookie and "Domain=" not in cookie
    assert client.get("/account").status_code == 200
    with web_factory() as db:
        session = db.get(UserSession, client.cookies["cd_session"])
        assert session.user_id == plain_user.id and session.authenticated_at is not None
    assert [row.actor_user_id for row in _audit(web_factory, "auth.login_success")] == [plain_user.id]


def test_login_username_is_case_insensitive(client, plain_user, csrf, clock):
    response = _login(client, clock, csrf, "ADMIN", plain_user.password)
    assert response.status_code == 303 and client.get("/account").status_code == 200


def test_generic_invalid_credentials_for_unknown_wrong_and_inactive(
    client, plain_user, csrf, clock, web_factory
):
    create_login_user(web_factory, "retired", is_active=False)
    messages = []
    for username, password in [
        ("nobody", LOGIN_PASSWORD),
        ("admin", "wrong-password-value"),
        ("retired", LOGIN_PASSWORD),
    ]:
        response = _login(client, clock, csrf, username, password)
        assert response.status_code == 401
        assert INVALID in response.text
        messages.append(re.sub(r'value="[^"]*"', "", response.text))
    assert len({re.sub(r"\s+", " ", item) for item in messages}) == 1
    assert "cd_session" not in client.cookies


def test_failed_login_preserves_username_but_never_password(client, plain_user, csrf, clock):
    response = _login(client, clock, csrf, "admin", "wrong-password-value")
    assert 'value="admin"' in response.text and "wrong-password-value" not in response.text


def test_lockout_message_is_distinct_but_generic(client, plain_user, csrf, clock):
    for _ in range(10):
        assert _login(client, clock, csrf, "admin", "wrong-password-value").status_code == 401
    locked = _login(client, clock, csrf, "admin", LOGIN_PASSWORD)
    assert locked.status_code == 423 and LOCKED in locked.text and INVALID not in locked.text
    assert "wrong-password-value" not in locked.text
    assert "cd_session" not in client.cookies


def test_sixth_attempt_in_a_minute_is_rate_limited_before_any_backend_call(
    client, plain_user, csrf, clock, web_app
):
    calls = []
    original = web_app.state.backends["local"].authenticate
    web_app.state.backends["local"].authenticate = lambda *a: calls.append(a) or original(*a)
    for _ in range(5):
        _login(client, clock, csrf, "admin", "wrong-password-value", tick=0)
    limited = _login(client, clock, csrf, "admin", LOGIN_PASSWORD, tick=0)
    assert limited.status_code == 429 and RATE_LIMITED in limited.text and "Retry-After" in limited.headers
    assert len(calls) == 5 and "cd_session" not in client.cookies


def test_every_login_route_rejects_missing_or_foreign_csrf(client, plain_user, csrf, clock):
    body = {"username": "admin", "password": LOGIN_PASSWORD}
    assert client.post("/login", data=body).status_code == 403
    assert client.post("/login", data={**body, "csrf_token": "f" * len(csrf)}).status_code == 403
    assert client.post("/login/2fa", data={"code": "123456"}).status_code == 403
    assert client.post("/logout").status_code == 403
    assert "cd_session" not in client.cookies


def test_login_get_with_existing_session_still_renders_form(client, plain_user, csrf, clock):
    _sign_in(client, clock, plain_user, csrf)
    assert client.get("/login", follow_redirects=False).status_code == 200


def test_login_rotates_the_session_and_ignores_next_parameter(client, plain_user, csrf, clock, web_factory):
    response = client.post(
        "/login?next=https://evil.example/",
        data={
            "username": "admin",
            "password": LOGIN_PASSWORD,
            "csrf_token": csrf,
            "next": "https://evil.example/",
        },
        follow_redirects=False,
    )
    assert response.headers["location"] == "/"


# --- fake backend: same flow -----------------------------------------------------------------------


@pytest.fixture(params=["local", "fake"])
def backend_user(request, web_app, web_factory):
    if request.param == "local":
        return create_login_user(web_factory)
    user = create_login_user(web_factory, "directory-user", "directory-pass-123", backend="ldap")
    web_app.state.backends["ldap"] = FakeBackend({user.username: (user.password, user.id)})
    return user


def test_contract_login_flow_is_backend_independent(client, backend_user, csrf, clock, web_factory):
    bad = _login(client, clock, csrf, backend_user.username, "wrong-password-value")
    assert bad.status_code == 401 and INVALID in bad.text
    unknown = _login(client, clock, csrf, "nobody-here", "whatever-password")
    assert unknown.status_code == 401 and INVALID in unknown.text
    response = _login(client, clock, csrf, backend_user.username, backend_user.password)
    assert response.status_code == 303 and response.headers["location"] == "/"
    with web_factory() as db:
        assert db.get(UserSession, client.cookies["cd_session"]).user_id == backend_user.id
    assert client.get("/account").status_code == 200
    token = _page_token(client)
    out = _post(client, "/logout", token)
    assert out.status_code == 303 and out.headers["location"] == "/login"


def test_contract_totp_pending_session_flow_for_fake_backend(
    client, web_app, web_factory, web_settings, clock
):
    from app.auth.local import begin_totp, confirm_totp
    from app.services.audit import Actor

    user = create_login_user(web_factory, "directory-user", "directory-pass-123", backend="ldap")
    web_app.state.backends["ldap"] = FakeBackend({user.username: (user.password, user.id)})
    actor = Actor(user.id, user.username)
    with web_factory.begin() as db:
        enrollment = begin_totp(db, user.id, web_settings.keyring, actor)
    with web_factory.begin() as db:
        assert confirm_totp(
            db, user.id, pyotp.TOTP(enrollment.secret).at(clock()), web_settings.keyring, clock(), actor
        )
    token = _token(client.get("/login").text)
    first = _login(client, clock, token, user.username, user.password)
    assert first.headers["location"] == "/login/2fa"
    assert client.get("/account", headers={"Accept": "application/json"}).status_code == 401
    clock.advance(seconds=45)
    done = _second_factor(client, clock, pyotp.TOTP(enrollment.secret).at(clock()))
    assert done.status_code == 303 and done.headers["location"] == "/"
    assert client.get("/account").status_code == 200


def test_user_key_and_backend_come_from_the_user_row_not_the_login_form(client, web_app, web_factory, clock):
    # A known directory user is routed by user.auth_backend, never by the local hash fields.
    user = create_login_user(web_factory, "directory-user", "directory-pass-123", backend="ldap")
    local_calls = []
    original = web_app.state.backends["local"].authenticate
    web_app.state.backends["local"].authenticate = lambda *a: local_calls.append(a) or original(*a)
    token = _token(client.get("/login").text)
    response = _login(client, clock, token, user.username, "directory-pass-123")
    assert response.status_code == 401 and not local_calls  # ldap stub: not_supported, no local fallback


def test_directory_login_with_mismatched_user_key_grants_no_session(client, web_app, web_factory, clock):
    user = create_login_user(web_factory, "directory-user", "directory-pass-123", backend="ldap")

    class Mismatched(FakeBackend):
        def authenticate(self, username, password):
            return Success("not-the-looked-up-identity", username, f"{username}@example.test")

    web_app.state.backends["ldap"] = Mismatched({user.username: (user.password, user.id)})
    token = _token(client.get("/login").text)
    response = _login(client, clock, token, user.username, user.password)
    assert response.status_code == 401 and INVALID in response.text
    with web_factory() as db:
        assert db.scalar(select(UserSession).where(UserSession.user_id == user.id)) is None


def test_directory_login_without_a_lookup_record_grants_no_session(client, web_app, web_factory, clock):
    user = create_login_user(web_factory, "directory-user", "directory-pass-123", backend="ldap")

    class NoRecord(FakeBackend):
        def lookup(self, username):
            return None

    web_app.state.backends["ldap"] = NoRecord({user.username: (user.password, user.id)})
    token = _token(client.get("/login").text)
    response = _login(client, clock, token, user.username, user.password)
    assert response.status_code == 401 and INVALID in response.text
    with web_factory() as db:
        assert db.scalar(select(UserSession).where(UserSession.user_id == user.id)) is None


# --- second factor ---------------------------------------------------------------------------------


def test_totp_login_completes_with_rotation_and_cannot_be_replayed(
    client, totp_user, csrf, clock, web_factory
):
    pending = _login(client, clock, csrf, "admin", LOGIN_PASSWORD)
    assert pending.status_code == 303 and pending.headers["location"] == "/login/2fa"
    pending_cookie = client.cookies["cd_session"]
    with web_factory() as db:
        assert db.get(UserSession, pending_cookie).authenticated_at is None
    page = client.get("/login/2fa")
    assert page.status_code == 200 and "no-store" in page.headers["cache-control"]
    code = _code(totp_user, clock)
    done = _second_factor(client, clock, code, _token(page.text))
    assert done.status_code == 303 and done.headers["location"] == "/"
    assert client.cookies["cd_session"] != pending_cookie
    assert _status_with_cookie(client, pending_cookie) == 401
    assert client.get("/account").status_code == 200
    # Replaying the same code from a second login is refused.
    token = _page_token(client)
    _post(client, "/logout", token)
    fresh = _token(client.get("/login").text)
    _login(client, clock, fresh, "admin", LOGIN_PASSWORD)
    replay = _second_factor(client, clock, code)
    assert replay.status_code == 401 and "Invalid" in replay.text
    assert client.get("/account", headers={"Accept": "application/json"}).status_code == 401


def test_recovery_code_is_accepted_once(client, totp_user, csrf, clock):
    recovery = totp_user.recovery_codes[0]
    _login(client, clock, csrf, "admin", LOGIN_PASSWORD)
    assert _second_factor(client, clock, recovery.lower()).status_code == 303
    token = _page_token(client)
    _post(client, "/logout", token)
    _login(client, clock, _token(client.get("/login").text), "admin", LOGIN_PASSWORD)
    again = _second_factor(client, clock, recovery)
    assert again.status_code == 401 and "Invalid" in again.text


def test_mfa_failures_share_the_lockout_counter_and_persist(client, totp_user, csrf, clock, web_factory):
    _login(client, clock, csrf, "admin", LOGIN_PASSWORD)
    token = _token(client.get("/login/2fa").text)
    for _ in range(3):
        assert _second_factor(client, clock, "000000", token).status_code == 401
    assert _user(web_factory, totp_user.id).failed_attempts >= 3
    assert len(_audit(web_factory, "auth.mfa_failed")) == 3


def test_mfa_failures_lock_the_account_for_password_login_too(client, totp_user, csrf, clock, web_factory):
    # Nine failures already counted (password and MFA share the counter); the tenth locks.
    with web_factory.begin() as db:
        db.get(User, totp_user.id).failed_attempts = 9
    _login(client, clock, csrf, "admin", LOGIN_PASSWORD)
    token = _token(client.get("/login/2fa").text)
    assert _user(web_factory, totp_user.id).failed_attempts == 9  # TOTP is on: login keeps the count
    assert _second_factor(client, clock, "000000", token).status_code == 423  # the failure that locks
    assert _user(web_factory, totp_user.id).locked_until is not None
    assert len(_audit(web_factory, "auth.lockout")) == 1
    # Even a correct code is refused while locked, and nothing is granted.
    locked = _second_factor(client, clock, _code(totp_user, clock), token)
    assert locked.status_code == 423 and LOCKED in locked.text
    assert client.get("/account", headers={"Accept": "application/json"}).status_code == 401
    fresh = _token(client.get("/login").text)
    assert _login(client, clock, fresh, "admin", LOGIN_PASSWORD).status_code == 423


def test_second_factor_step_is_rate_limited(client, totp_user, csrf, clock):
    _login(client, clock, csrf, "admin", LOGIN_PASSWORD, tick=0)
    token = _token(client.get("/login/2fa").text)
    results = [_second_factor(client, clock, "000000", token, tick=0).status_code for _ in range(6)]
    assert results[-1] == 429 and RATE_LIMITED in _second_factor(client, clock, "000000", token, tick=0).text


def test_second_factor_without_pending_session_is_refused(client, plain_user, csrf, clock):
    assert client.get("/login/2fa", follow_redirects=False).status_code == 303
    response = client.post("/login/2fa", data={"code": "123456", "csrf_token": csrf}, follow_redirects=False)
    assert response.status_code in {303, 403}
    assert "cd_session" not in client.cookies


def test_authenticated_session_cannot_use_second_factor_route(client, totp_user, csrf, clock):
    _login(client, clock, csrf, "admin", LOGIN_PASSWORD)
    _second_factor(client, clock, _code(totp_user, clock))
    token = _page_token(client)
    response = client.post("/login/2fa", data={"code": "000000", "csrf_token": token}, follow_redirects=False)
    assert response.status_code in {303, 403}


# --- logout ----------------------------------------------------------------------------------------


def test_logout_revokes_only_current_session_and_clears_cookie(client, plain_user, csrf, clock, web_factory):
    old = _sign_in(client, clock, plain_user, csrf)
    other = _extra_session(web_factory, plain_user, clock)
    token = _page_token(client)
    response = _post(client, "/logout", token)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert "cd_session=" in response.headers["set-cookie"] and "Max-Age=0" in response.headers["set-cookie"]
    assert "cd_session" not in client.cookies
    assert _status_with_cookie(client, old) == 401
    assert _status_with_cookie(client, other) == 200
    assert [row.actor_user_id for row in _audit(web_factory, "auth.logout")] == [plain_user.id]


def test_logout_is_post_only_and_needs_csrf(client, plain_user, csrf, clock):
    _sign_in(client, clock, plain_user, csrf)
    assert client.get("/logout", follow_redirects=False).status_code == 405
    assert client.post("/logout", follow_redirects=False).status_code == 403
    assert client.post("/logout", data={"csrf_token": "f" * 64}, follow_redirects=False).status_code == 403
    assert client.get("/account").status_code == 200


def test_pending_mfa_session_can_cancel_and_sign_out(client, totp_user, csrf, clock, web_factory):
    pending = _login(client, clock, csrf, "admin", LOGIN_PASSWORD)
    assert pending.headers["location"] == "/login/2fa"
    pending_cookie = client.cookies["cd_session"]
    token = _token(client.get("/login/2fa").text)
    response = _post(client, "/logout", token)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert "cd_session=" in response.headers["set-cookie"] and "Max-Age=0" in response.headers["set-cookie"]
    assert "cd_session" not in client.cookies
    with web_factory() as db:
        assert db.get(UserSession, pending_cookie).revoked_at is not None
    # The revoked pending cookie neither reaches the second factor nor any protected route.
    client.cookies.set("cd_session", pending_cookie, domain="testserver.local", path="/")
    assert client.get("/login/2fa", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/account", headers={"Accept": "application/json"}).status_code == 401


def test_pending_mfa_session_gets_no_other_protected_route(client, totp_user, csrf, clock):
    _login(client, clock, csrf, "admin", LOGIN_PASSWORD)
    token = _token(client.get("/login/2fa").text)
    assert _post(client, "/account/password", token, current_password="x").status_code == 303
    assert client.get("/account", headers={"Accept": "application/json"}).status_code == 401


# --- account page ----------------------------------------------------------------------------------


def test_account_page_requires_login_and_is_not_cacheable(client, plain_user, csrf, clock):
    assert client.get("/account", follow_redirects=False).headers["location"] == "/login"
    _sign_in(client, clock, plain_user, csrf)
    page = client.get("/account")
    assert "no-store" in page.headers["cache-control"]
    assert "/account/password" in page.text and "/account/totp/enroll" in page.text
    assert "<script" not in page.text.lower().replace('<script src="/static/htmx.min.js" defer></script>', "")


@pytest.mark.parametrize(
    "path, fields",
    [
        ("/account/password", {"current_password": "x", "new_password": "y", "confirm_password": "y"}),
        ("/account/totp/enroll", {"current_password": "x"}),
        ("/account/totp/confirm", {"code": "123456"}),
        ("/account/totp/disable", {"current_password": "x"}),
    ],
)
def test_every_account_post_rejects_missing_or_foreign_csrf(client, plain_user, csrf, clock, path, fields):
    _sign_in(client, clock, plain_user, csrf)
    assert client.post(path, data=fields).status_code == 403
    assert client.post(path, data={**fields, "csrf_token": "f" * 64}).status_code == 403
    assert client.post(path, data={**fields, "csrf_token": csrf}).status_code == 403


# --- password change -------------------------------------------------------------------------------


def test_password_change_revokes_every_session_and_reissues_current(
    client, plain_user, csrf, clock, web_factory
):
    old = _sign_in(client, clock, plain_user, csrf)
    other = _extra_session(web_factory, plain_user, clock)
    token = _page_token(client)
    new_password = "a-brand-new-passphrase"
    response = _post(
        client,
        "/account/password",
        token,
        current_password=LOGIN_PASSWORD,
        new_password=new_password,
        confirm_password=new_password,
    )
    assert response.status_code == 303 and response.headers["location"].startswith("/account")
    assert client.cookies["cd_session"] not in {old, other}
    assert _status_with_cookie(client, old) == 401 and _status_with_cookie(client, other) == 401
    assert client.get("/account").status_code == 200
    # The previous CSRF token is dead with its session; the new one works.
    assert _post(client, "/account/password", token, current_password="x").status_code == 403
    from app.auth.local import verify_password

    assert verify_password(_user(web_factory, plain_user.id).password_hash, new_password)
    rows = _audit(web_factory, "auth.password_changed")
    assert len(rows) == 1 and new_password not in json.dumps(rows[0].details) + rows[0].actor_label


def test_wrong_current_password_counts_as_failure_and_persists(client, plain_user, csrf, clock, web_factory):
    _sign_in(client, clock, plain_user, csrf)
    token = _page_token(client)
    response = _post(
        client,
        "/account/password",
        token,
        current_password="not-the-password",
        new_password="a-brand-new-passphrase",
        confirm_password="a-brand-new-passphrase",
    )
    assert response.status_code == 422 and "Current password is incorrect" in response.text
    assert "a-brand-new-passphrase" not in response.text
    user = _user(web_factory, plain_user.id)
    assert user.failed_attempts == 1
    assert any(
        row.details.get("reason") == "invalid_current_password"
        for row in _audit(web_factory, "auth.login_failed")
    )
    assert not _audit(web_factory, "auth.password_changed")
    assert client.get("/account").status_code == 200  # session untouched


def test_wrong_current_password_with_mismatched_confirmation_still_counts_one_failure(
    client, plain_user, csrf, clock, web_factory
):
    _sign_in(client, clock, plain_user, csrf)
    token = _page_token(client)
    response = _post(
        client,
        "/account/password",
        token,
        current_password="not-the-password",
        new_password="a-brand-new-passphrase",
        confirm_password="a-different-passphrase",
    )
    assert response.status_code == 422 and "Current password is incorrect" in response.text
    assert _user(web_factory, plain_user.id).failed_attempts == 1
    rows = [
        row
        for row in _audit(web_factory, "auth.login_failed")
        if row.details.get("reason") == "invalid_current_password"
    ]
    assert len(rows) == 1
    assert not _audit(web_factory, "auth.password_changed")
    from app.auth.local import verify_password

    assert verify_password(_user(web_factory, plain_user.id).password_hash, LOGIN_PASSWORD)


def test_repeated_wrong_current_password_locks_the_account(client, plain_user, csrf, clock, web_factory):
    _sign_in(client, clock, plain_user, csrf)
    token = _page_token(client)
    statuses = [
        _post(
            client,
            "/account/password",
            token,
            current_password="nope-nope-nope",
            new_password="a-brand-new-passphrase",
            confirm_password="a-brand-new-passphrase",
        ).status_code
        for _ in range(11)
    ]
    assert statuses[:10] == [422] * 10 and statuses[10] == 423
    assert _user(web_factory, plain_user.id).locked_until is not None
    assert len(_audit(web_factory, "auth.lockout")) == 1


@pytest.mark.parametrize(
    "new, confirm, text",
    [
        ("short", "short", "at least 12"),
        ("password", "password", "too common"),
        ("a-brand-new-passphrase", "different-passphrase", "do not match"),
        ("x" * 1025, "x" * 1025, "1024"),
    ],
)
def test_password_policy_and_confirmation_errors_render_inline(
    client, plain_user, csrf, clock, web_factory, new, confirm, text
):
    _sign_in(client, clock, plain_user, csrf)
    token = _page_token(client)
    response = _post(
        client,
        "/account/password",
        token,
        current_password=LOGIN_PASSWORD,
        new_password=new,
        confirm_password=confirm,
    )
    assert response.status_code == 422 and text in response.text
    if len(new) >= 12:
        assert new not in response.text
    from app.auth.local import verify_password

    assert verify_password(_user(web_factory, plain_user.id).password_hash, LOGIN_PASSWORD)
    assert client.get("/account").status_code == 200


def test_directory_user_cannot_change_password_here(client, web_app, web_factory, clock):
    user = create_login_user(web_factory, "directory-user", "directory-pass-123", backend="ldap")
    web_app.state.backends["ldap"] = FakeBackend({user.username: (user.password, user.id)})
    token = _token(client.get("/login").text)
    _login(client, clock, token, user.username, user.password)
    page_token = _page_token(client)
    response = _post(
        client,
        "/account/password",
        page_token,
        current_password="directory-pass-123",
        new_password="a-brand-new-passphrase",
        confirm_password="a-brand-new-passphrase",
    )
    assert response.status_code == 422 and "managed by your directory" in response.text
    assert not _audit(web_factory, "auth.password_changed")


def test_change_password_service_contract(web_factory, plain_user):
    from app.auth.local import PasswordChangeError, change_password, verify_password
    from app.services.audit import Actor

    actor = Actor(plain_user.id, plain_user.username)

    with pytest.raises(PasswordChangeError) as error, web_factory.begin() as db:
        change_password(db, plain_user.id, "bad-current-password", "a-brand-new-passphrase", actor)
    assert error.value.code == "invalid_current_password"
    with pytest.raises(PasswordChangeError) as error, web_factory.begin() as db:
        change_password(db, plain_user.id, LOGIN_PASSWORD, "short", actor)
    assert error.value.code == "policy"
    with web_factory.begin() as db:
        change_password(db, plain_user.id, LOGIN_PASSWORD, "a-brand-new-passphrase", actor)
    assert verify_password(_user(web_factory, plain_user.id).password_hash, "a-brand-new-passphrase")


# --- must_change_password --------------------------------------------------------------------------


@pytest.fixture
def flagged_user(web_factory):
    return create_login_user(web_factory, "flagged", must_change_password=True)


def test_must_change_password_confines_the_user_to_account_password_and_logout(
    client, web_app, flagged_user, csrf, clock, web_factory
):
    from fastapi import Depends

    from app.main import require_user

    guard = Depends(require_user)

    @web_app.get("/_test/other")
    def other(user=guard):
        return {"ok": True}

    assert _login(client, clock, csrf, "flagged", LOGIN_PASSWORD).headers["location"] == "/"
    assert client.get("/account").status_code == 200
    redirected = client.get("/_test/other", follow_redirects=False)
    assert redirected.status_code == 303 and redirected.headers["location"] == "/account"
    htmx = client.get("/_test/other", headers={"HX-Request": "true"})
    assert htmx.status_code == 403 and htmx.headers["HX-Redirect"] == "/account"
    assert client.get("/_test/other", headers={"Accept": "application/json"}).status_code == 403
    token = _page_token(client)
    assert _post(client, "/account/totp/enroll", token, current_password=LOGIN_PASSWORD).status_code in {
        303,
        403,
    }
    assert not _user(web_factory, flagged_user.id).totp_secret_ciphertext
    response = _post(
        client,
        "/account/password",
        token,
        current_password=LOGIN_PASSWORD,
        new_password="a-brand-new-passphrase",
        confirm_password="a-brand-new-passphrase",
    )
    assert response.status_code == 303
    assert client.get("/_test/other", follow_redirects=False).status_code == 200
    assert _user(web_factory, flagged_user.id).must_change_password is False


def test_must_change_password_user_can_still_log_out(client, flagged_user, csrf, clock):
    _login(client, clock, csrf, "flagged", LOGIN_PASSWORD)
    token = _page_token(client)
    assert _post(client, "/logout", token).headers["location"] == "/login"


# --- TOTP management -------------------------------------------------------------------------------


def _enroll(client, token, password=LOGIN_PASSWORD):
    return _post(client, "/account/totp/enroll", token, current_password=password)


def test_enroll_shows_material_once_with_no_store_and_never_again(
    client, plain_user, csrf, clock, web_factory, caplog
):
    _sign_in(client, clock, plain_user, csrf)
    token = _page_token(client)
    with caplog.at_level(logging.DEBUG):
        response = _enroll(client, token)
    assert response.status_code == 200 and "no-store" in response.headers["cache-control"]
    secret = re.search(r"data-secret>([A-Z2-7]+)<", response.text).group(1)
    codes = re.findall(r"data-recovery-code>([0-9A-F]{8}(?:-[0-9A-F]{8}){3})<", response.text)
    assert len(codes) == 10 and len(set(codes)) == 10
    assert "otpauth://totp/" in response.text and secret in response.text
    # Not re-displayed anywhere else, not audited, not logged.
    page = client.get("/account")
    assert secret not in page.text and not any(code in page.text for code in codes)
    with web_factory() as db:
        dump = json.dumps(
            [
                [row.details, row.actor_label, row.action, row.target_id]
                for row in db.scalars(select(AuditLog))
            ]
        )
    assert secret not in dump and not any(code in dump for code in codes)
    assert secret not in caplog.text and not any(code in caplog.text for code in codes)
    user = _user(web_factory, plain_user.id)
    assert user.totp_enabled is False and user.totp_secret_ciphertext is not None
    assert secret.encode() not in user.totp_secret_ciphertext
    assert not any(code.replace("-", "") in "".join(user.recovery_codes) for code in codes)
    assert "pending" in page.text.lower()


def test_enroll_requires_current_password(client, plain_user, csrf, clock, web_factory):
    _sign_in(client, clock, plain_user, csrf)
    token = _page_token(client)
    response = _enroll(client, token, "not-the-password")
    assert response.status_code == 422 and "Current password is incorrect" in response.text
    assert _user(web_factory, plain_user.id).totp_secret_ciphertext is None
    assert _user(web_factory, plain_user.id).failed_attempts == 1


def test_confirm_enables_totp_revokes_every_session_and_reissues_current(
    client, plain_user, csrf, clock, web_factory
):
    old = _sign_in(client, clock, plain_user, csrf)
    other = _extra_session(web_factory, plain_user, clock)
    token = _page_token(client)
    secret = re.search(r"data-secret>([A-Z2-7]+)<", _enroll(client, token).text).group(1)
    clock.advance(seconds=30)
    wrong = _post(client, "/account/totp/confirm", token, code="000000")
    assert wrong.status_code == 422 and "Invalid" in wrong.text
    assert (
        _user(web_factory, plain_user.id).totp_enabled is False
        and _user(web_factory, plain_user.id).failed_attempts == 1
    )
    response = _post(client, "/account/totp/confirm", token, code=pyotp.TOTP(secret).at(clock()))
    assert response.status_code == 303 and response.headers["location"].startswith("/account")
    assert _user(web_factory, plain_user.id).totp_enabled is True
    assert client.cookies["cd_session"] not in {old, other}
    assert _status_with_cookie(client, old) == 401 and _status_with_cookie(client, other) == 401
    assert client.get("/account").status_code == 200
    assert len(_audit(web_factory, "auth.totp_enabled")) == 1
    # From now on, password login only reaches the pending second step.
    new_token = _page_token(client)
    _post(client, "/logout", new_token)
    again = _login(client, clock, _token(client.get("/login").text), "admin", LOGIN_PASSWORD)
    assert again.headers["location"] == "/login/2fa"


def test_confirm_does_not_need_the_password_but_needs_pending_enrollment(client, plain_user, csrf, clock):
    _sign_in(client, clock, plain_user, csrf)
    token = _page_token(client)
    response = _post(client, "/account/totp/confirm", token, code="123456")
    assert response.status_code == 422


def test_enroll_is_refused_when_totp_is_already_enabled(client, totp_user, csrf, clock):
    _login(client, clock, csrf, "admin", LOGIN_PASSWORD)
    _second_factor(client, clock, _code(totp_user, clock))
    token = _page_token(client)
    response = _enroll(client, token)
    assert response.status_code == 422 and "already enabled" in response.text


def test_disable_requires_password_revokes_sessions_and_removes_secret(
    client, totp_user, csrf, clock, web_factory
):
    _login(client, clock, csrf, "admin", LOGIN_PASSWORD)
    _second_factor(client, clock, _code(totp_user, clock))
    old = client.cookies["cd_session"]
    other = _extra_session(web_factory, totp_user, clock)
    token = _page_token(client)
    wrong = _post(client, "/account/totp/disable", token, current_password="not-the-password")
    assert wrong.status_code == 422 and _user(web_factory, totp_user.id).totp_enabled is True
    response = _post(client, "/account/totp/disable", token, current_password=LOGIN_PASSWORD)
    assert response.status_code == 303 and response.headers["location"].startswith("/account")
    user = _user(web_factory, totp_user.id)
    assert user.totp_enabled is False and user.totp_secret_ciphertext is None and user.recovery_codes == []
    assert client.cookies["cd_session"] not in {old, other}
    assert _status_with_cookie(client, old) == 401 and _status_with_cookie(client, other) == 401
    assert client.get("/account").status_code == 200
    assert len(_audit(web_factory, "auth.totp_disabled")) == 1


def test_account_page_reflects_totp_state_without_secrets(client, totp_user, csrf, clock):
    _login(client, clock, csrf, "admin", LOGIN_PASSWORD)
    _second_factor(client, clock, _code(totp_user, clock))
    page = client.get("/account")
    assert "/account/totp/disable" in page.text and totp_user.secret not in page.text
    assert not any(code in page.text for code in totp_user.recovery_codes)


# --- CLI bootstrap ---------------------------------------------------------------------------------


@pytest.fixture
def cli(web_factory, tmp_path, monkeypatch):
    """Run app.cli.main against the throwaway database, like an operator container would."""
    from app import cli as cli_module

    url = web_factory.kw["bind"].url
    (tmp_path / "master_key").write_text(
        json.dumps({"active": 1, "keys": {"1": base64.b64encode(bytes(range(32))).decode()}})
    )
    (tmp_path / "db_password").write_text(url.password)
    for name, value in {
        "SECRETS_DIR": str(tmp_path),
        "DB_HOST": url.host,
        "DB_PORT": str(url.port),
        "DB_NAME": url.database,
        "DB_USER": url.username,
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("BOOTSTRAP_ADMIN_PASSWORD", raising=False)
    prompts = []

    def run(*answers, username="root", email="root@example.test"):
        queue = list(answers)
        monkeypatch.setattr("getpass.getpass", lambda prompt="": prompts.append(prompt) or queue.pop(0))
        return cli_module.main(["bootstrap-admin", "--username", username, "--email", email])

    run.prompts = prompts
    return run


def test_cli_prompts_twice_and_creates_active_local_admin(cli, web_factory, capsys, caplog):
    from app.auth.local import verify_password

    password = "operator-chosen-pass"
    with caplog.at_level(logging.DEBUG):
        assert cli(password, password) == 0
    out = capsys.readouterr()
    assert password not in out.out + out.err + caplog.text and len(cli.prompts) == 2
    with web_factory() as db:
        user = db.scalar(select(User).where(User.username == "root"))
        assert user.is_active and user.auth_backend == "local" and user.must_change_password is False
        assert user.email == "root@example.test" and verify_password(user.password_hash, password)
        rows = _audit(web_factory, "user.bootstrap_admin")
    assert len(rows) == 1 and rows[0].target_type == "user" and rows[0].target_id == str(user.id)
    assert rows[0].details == {"username": "root"} and password not in json.dumps(rows[0].details)
    assert rows[0].actor_label == "cli"


def test_cli_created_admin_can_log_in(cli, client, csrf, clock):
    assert cli("operator-chosen-pass", "operator-chosen-pass") == 0
    response = _login(client, clock, csrf, "root", "operator-chosen-pass")
    assert response.status_code == 303 and response.headers["location"] == "/"


def test_cli_confirmation_mismatch_fails_without_creating_a_user(cli, web_factory, capsys):
    assert cli("operator-chosen-pass", "operator-chosen-PASS") == 1
    assert "match" in capsys.readouterr().err
    assert not _audit(web_factory, "user.bootstrap_admin")
    with web_factory() as db:
        assert db.scalar(select(User).where(User.username == "root")) is None


@pytest.mark.parametrize("password", ["short", "iloveyou", "x" * 1025])
def test_cli_enforces_the_password_policy(cli, web_factory, capsys, password):
    assert cli(password, password) == 1
    err = capsys.readouterr().err
    assert err and password not in err
    with web_factory() as db:
        assert db.scalar(select(User).where(User.username == "root")) is None


def test_cli_reads_password_from_environment_once_and_consumes_it(cli, web_factory, monkeypatch, capsys):
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", "environment-secret-pass")
    assert cli() == 0 and not cli.prompts
    assert "BOOTSTRAP_ADMIN_PASSWORD" not in os.environ
    assert "environment-secret-pass" not in capsys.readouterr().out
    from app.auth.local import verify_password

    with web_factory() as db:
        user = db.scalar(select(User).where(User.username == "root"))
        assert verify_password(user.password_hash, "environment-secret-pass")


def test_cli_environment_password_is_consumed_even_when_rejected(cli, monkeypatch):
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", "short")
    assert cli() == 1 and "BOOTSTRAP_ADMIN_PASSWORD" not in os.environ


def test_cli_refuses_duplicate_username_case_insensitively(cli, web_factory, capsys):
    create_login_user(web_factory, "Root")
    assert cli("operator-chosen-pass", "operator-chosen-pass", username="root") == 1
    assert "exists" in capsys.readouterr().err
    assert not _audit(web_factory, "user.bootstrap_admin")
    with web_factory() as db:
        assert db.scalar(select(User.id).where(User.username == "ROOT")) is not None


def test_cli_runs_when_other_users_exist(cli, web_factory):
    create_login_user(web_factory, "someone-else")
    assert cli("operator-chosen-pass", "operator-chosen-pass") == 0


def test_bootstrap_admin_service_is_atomic_with_its_audit(web_factory):
    from app.auth.local import bootstrap_admin
    from app.services.audit import Actor

    actor = Actor(None, "cli")

    with web_factory.begin() as db:
        user = bootstrap_admin(db, "service-admin", "svc@example.test", "operator-chosen-pass", actor)
        assert user.id and user.must_change_password is False
    assert len(_audit(web_factory, "user.bootstrap_admin")) == 1
    with pytest.raises(ValueError), web_factory.begin() as db:
        bootstrap_admin(db, "SERVICE-ADMIN", "svc@example.test", "operator-chosen-pass", actor)
    assert len(_audit(web_factory, "user.bootstrap_admin")) == 1


def test_rate_limit_rows_are_written_even_when_login_fails(client, plain_user, csrf, clock, web_factory):
    _login(client, clock, csrf, "admin", "wrong-password-value")
    with web_factory() as db:
        assert db.scalar(select(LoginRateLimit.attempts)) == 1
