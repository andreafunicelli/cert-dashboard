import hmac
import json
import logging
import os
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import replace
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models import User, UserSession


def _preauth(client):
    response = client.get("/_test/login-form")
    assert response.status_code == 200
    return client.cookies["cd_login_csrf"]


def test_session_shape_expiry_and_revocation(web_factory, web_user, now):
    from app.auth.sessions import issue_session, resolve_session, revoke_sessions

    with web_factory.begin() as db:
        session = issue_session(db, web_user.id, now, "192.0.2.101", "fixture-browser")
        assert len(session.id) == len(session.csrf_token) == 64 and session.id != session.csrf_token
        assert session.authenticated_at == session.created_at == session.last_seen_at == now
        assert session.expires_at == now + timedelta(hours=24)
    with web_factory.begin() as db:
        assert resolve_session(db, session.id, now + timedelta(hours=8)) is None
        assert resolve_session(db, "not-a-session", now) is None
        assert resolve_session(db, secrets.token_hex(32), now) is None
        assert revoke_sessions(db, web_user.id, now) == 1
        assert resolve_session(db, session.id, now) is None


@pytest.mark.parametrize("hours, valid", [(7.999, True), (8, False), (24, False)])
def test_idle_and_absolute_boundaries(web_factory, web_user, now, hours, valid):
    from app.auth.sessions import issue_session, resolve_session

    with web_factory.begin() as db:
        session = issue_session(db, web_user.id, now, "", "")
        if hours == 24:
            session.last_seen_at = now + timedelta(hours=23)
    with web_factory.begin() as db:
        assert (resolve_session(db, session.id, now + timedelta(hours=hours)) is not None) is valid


def test_activity_never_extends_absolute_lifetime(web_factory, web_user, now):
    from app.auth.sessions import issue_session, resolve_session

    with web_factory.begin() as db:
        session = issue_session(db, web_user.id, now, "", "")
    for hour in [7, 14, 21, 23]:
        with web_factory.begin() as db:
            assert resolve_session(db, session.id, now + timedelta(hours=hour))
    with web_factory.begin() as db:
        assert resolve_session(db, session.id, now + timedelta(hours=24)) is None


def test_cookie_flags_login_rotation_and_csrf_replacement(signed_in, web_factory, clock):
    old = signed_in.cookies["cd_session"]
    response = signed_in.post("/_test/login", data={"csrf_token": signed_in.fixture_csrf})
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie and "Path=/" in cookie
    assert "Domain=" not in cookie and signed_in.cookies["cd_session"] != old
    with web_factory() as db:
        assert db.get(UserSession, old).revoked_at == clock()
    assert signed_in.post("/_test/protected", data={"csrf_token": signed_in.fixture_csrf}).status_code == 403
    assert (
        signed_in.post(
            "/_test/protected", headers={"X-CSRF-Token": response.json()["csrf_token"]}
        ).status_code
        == 200
    )


def test_mfa_pending_has_no_admin_authority_and_rotates_after_completion(
    client, web_factory, web_user, clock
):
    with web_factory.begin() as db:
        db.get(User, web_user.id).totp_enabled = True
    token = _preauth(client)
    response = client.post("/_test/login", data={"csrf_token": token})
    assert response.status_code == 200 and response.json()["pending"]
    pending = client.cookies["cd_session"]
    assert client.get("/_test/protected", headers={"Accept": "application/json"}).status_code == 401
    with web_factory() as db:
        assert db.get(UserSession, pending).authenticated_at is None
    completed = client.post("/_test/mfa", data={"csrf_token": response.json()["csrf_token"]})
    assert completed.status_code == 200 and client.cookies["cd_session"] != pending
    assert client.get("/_test/protected").status_code == 200
    with web_factory() as db:
        assert db.get(UserSession, pending).revoked_at == clock()


def test_pending_expiry_exactly_ten_minutes(client, web_factory, web_user, clock):
    from app.auth.sessions import issue_session, resolve_session

    with web_factory.begin() as db:
        session = issue_session(db, web_user.id, clock(), "", "", authenticated=False)
    with web_factory.begin() as db:
        assert resolve_session(db, session.id, clock() + timedelta(minutes=10)) is None


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete", "head", "options"])
def test_every_non_get_requires_csrf_before_dispatch(signed_in, web_app, method):
    assert getattr(signed_in, method)("/_test/protected").status_code == 403
    assert web_app.state.calls == 0


def test_csrf_form_body_survives_middleware_and_foreign_token_is_rejected(signed_in):
    assert signed_in.post("/_test/protected", data={"csrf_token": "f" * 64}).status_code == 403
    response = signed_in.post(
        "/_test/protected", data={"csrf_token": signed_in.fixture_csrf, "echo": "fixture-echo"}
    )
    assert response.status_code == 200 and response.json()["echo"] == "fixture-echo"
    assert (
        signed_in.post(
            "/_test/protected", headers={"X-CSRF-Token": signed_in.fixture_csrf}, json={}
        ).status_code
        == 200
    )


def test_csrf_uses_constant_time_compare(signed_in, monkeypatch):
    original, calls = hmac.compare_digest, []

    def compare(first, second):
        calls.append(1)
        return original(first, second)

    monkeypatch.setattr(hmac, "compare_digest", compare)
    assert (
        signed_in.post("/_test/protected", headers={"X-CSRF-Token": signed_in.fixture_csrf}).status_code
        == 200
    )
    assert calls


def test_logout_requires_csrf_and_revokes_cookie(signed_in):
    assert signed_in.post("/_test/logout").status_code == 403
    assert signed_in.get("/_test/protected").status_code == 200
    response = signed_in.post("/_test/logout", data={"csrf_token": signed_in.fixture_csrf})
    assert response.status_code == 200
    assert signed_in.get("/_test/protected", headers={"Accept": "application/json"}).status_code == 401


def test_pre_auth_csrf_is_signed_bound_and_expires(client, clock):
    token = _preauth(client)
    assert client.post("/_test/login", data={"csrf_token": "f" * len(token)}).status_code == 403
    client.cookies.set("cd_login_csrf", "unsigned", domain="testserver.local", path="/")
    assert client.post("/_test/login", data={"csrf_token": "unsigned"}).status_code == 403
    token = _preauth(client)
    clock.advance(minutes=10)
    assert client.post("/_test/login", data={"csrf_token": token}).status_code == 403


def test_sixth_ip_login_attempt_is_blocked_after_independent_transactions(client, clock):
    for _ in range(5):
        token = _preauth(client)
        response = client.post("/_test/login", data={"csrf_token": token})
        assert response.status_code == 200
        client.cookies.delete("cd_session")
    token = _preauth(client)
    response = client.post("/_test/login", data={"csrf_token": token})
    assert response.status_code == 429 and int(response.headers["Retry-After"]) > 0
    clock.advance(minutes=1)
    token = _preauth(client)
    assert client.post("/_test/login", data={"csrf_token": token}).status_code == 200


@pytest.mark.parametrize(
    "trusted,peer,forwarded,expected",
    [
        ((), "192.0.2.10", "198.51.100.9", "192.0.2.10"),
        (("10.0.0.0/8",), "192.0.2.10", "198.51.100.9", "192.0.2.10"),
        (("10.0.0.0/8",), "10.0.0.2", "198.51.100.9, 10.0.0.1", "198.51.100.9"),
        (("10.0.0.0/8",), "10.0.0.2", "spoofed, 198.51.100.9", "10.0.0.2"),
        (("10.0.0.0/8",), "10.0.0.2", "192.0.2.55, 198.51.100.9, 10.0.0.1", "198.51.100.9"),
        (("2001:db8:1::/64",), "2001:db8:1::2", "2001:db8:2::5, 2001:db8:1::1", "2001:db8:2::5"),
    ],
)
def test_client_ip_trust_policy(trusted, peer, forwarded, expected):
    from starlette.requests import Request

    from app.auth.sessions import client_ip

    request = Request(
        {"type": "http", "client": (peer, 1234), "headers": [(b"x-forwarded-for", forwarded.encode())]}
    )
    assert client_ip(request, trusted) == expected


def test_trusted_proxy_env_is_canonical_and_invalid_network_is_rejected(secret_files):
    from app.config import ConfigurationError, load_settings

    settings = load_settings("web", {"TRUSTED_PROXIES": "10.1.2.3/8, 2001:db8::1/64"}, secret_files)
    assert settings.trusted_proxies == ("10.0.0.0/8", "2001:db8::/64")
    assert load_settings("web", {}, secret_files).trusted_proxies == ()
    with pytest.raises(ConfigurationError, match="TRUSTED_PROXIES"):
        load_settings("web", {"TRUSTED_PROXIES": "fixture-bad-network"}, secret_files)


def test_unauthenticated_html_json_and_htmx_errors(client):
    assert client.get("/_test/protected", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/_test/protected", headers={"Accept": "application/json"}).status_code == 401
    response = client.get("/_test/protected", headers={"HX-Request": "true"})
    assert response.status_code == 401 and response.headers["HX-Redirect"] == "/login"


@pytest.mark.parametrize("status", [403, 404, 422, 500, 503])
def test_styled_errors_are_sanitized_and_have_request_ids(signed_in, status):
    response = signed_in.get(f"/_test/error/{status}")
    assert response.status_code == status and "<html" in response.text.lower()
    assert response.headers["X-Request-ID"] in response.text
    assert "fixture-should" not in response.text
    if status == 503:
        assert int(response.headers["Retry-After"]) > 0


def test_unhandled_validation_and_exception_text_never_expose_session_or_password(signed_in, caplog):
    token = signed_in.cookies["cd_session"]
    with caplog.at_level(logging.INFO):
        response = signed_in.get("/_test/boom", headers={"Accept": "application/json"})
    assert response.status_code == 500
    assert token not in response.text + caplog.text and "fixture-internal" not in response.text + caplog.text
    assert "Traceback" not in response.text
    response = signed_in.get("/_test/validation", params={"number": "password=fixture-validation"})
    assert response.status_code == 422 and "fixture-validation" not in response.text


def test_revoked_and_inactive_users_are_rejected(signed_in, web_factory, web_user, clock):
    token = signed_in.cookies["cd_session"]
    with web_factory.begin() as db:
        db.get(User, web_user.id).is_active = False
    assert signed_in.get("/_test/protected", headers={"Accept": "application/json"}).status_code == 401
    with web_factory.begin() as db:
        db.get(User, web_user.id).is_active = True
        db.get(UserSession, token).revoked_at = clock()
    assert signed_in.get("/_test/protected", headers={"Accept": "application/json"}).status_code == 401


def test_base_template_escapes_users_and_offline_assets_exist(signed_in):
    response = signed_in.get("/_test/page")
    assert response.status_code == 200 and "&lt;script&gt;fixture&lt;/script&gt;" in response.text
    assert "<script>fixture</script>" not in response.text
    assert "htmx.min.js" in response.text and '<nav aria-label="Main">' in response.text
    # Every navigation area is implemented now (Plan 3 Task 19 enabled Deploy), so none is disabled.
    assert 'aria-disabled="true"' not in response.text
    assert signed_in.get("/static/app.css").status_code == 200
    assert signed_in.get("/static/htmx.min.js").status_code == 200


def test_import_does_not_load_production_secrets(monkeypatch):
    from app import main

    def forbidden(*args, **kwargs):
        pytest.fail("import loaded production secrets")

    monkeypatch.setattr(main, "load_settings", forbidden)
    # create_app() itself also defers defaults; lifespan owns loading.
    assert main.create_app() is not None


def test_startup_missing_key_versions_does_not_disable_public_reads(
    web_settings, web_factory, web_user, clock
):
    from app.main import create_app

    with web_factory.begin() as db:
        user = db.get(User, web_user.id)
        user.totp_secret_ciphertext, user.totp_secret_nonce, user.totp_secret_version = (
            b"fixture",
            b"x" * 12,
            99,
        )
    app = create_app(web_settings)
    app.state.factory, app.state.clock = web_factory, clock
    with TestClient(app, base_url="https://testserver", client=("192.0.2.200", 4000)) as client:
        assert 99 in app.state.missing_key_versions
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 200


def test_web_profile_rejects_missing_signing_secret(web_settings, web_factory):
    from app.config import ConfigurationError
    from app.main import create_app

    app = create_app(replace(web_settings, session_secret=None))
    app.state.factory = web_factory
    with pytest.raises(ConfigurationError, match="session_secret"), TestClient(app):
        pass


def test_connection_acquisition_retries_once_without_replaying_action(signed_in, web_app, monkeypatch):
    from sqlalchemy.exc import OperationalError
    from sqlalchemy.orm import Session

    original, calls = Session.connection, []

    def connect(self, *args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise OperationalError("fixture-connect", {}, Exception("fixture-private"))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Session, "connection", connect)
    response = signed_in.get("/_test/protected")
    assert response.status_code == 200 and len(calls) == 2 and web_app.state.calls == 1


def test_database_failure_rolls_back_and_never_replays_mutation_or_logs_session(
    signed_in, web_factory, web_user, web_app, caplog
):
    token = signed_in.cookies["cd_session"]
    with caplog.at_level(logging.INFO):
        response = signed_in.post("/_test/db-mutation", headers={"X-CSRF-Token": signed_in.fixture_csrf})
    assert response.status_code == 503 and int(response.headers["Retry-After"]) > 0
    assert web_app.state.calls == 1
    with web_factory() as db:
        assert (
            db.scalar(select(User.id).where(User.username == "fixture-rollback-" + web_user.username)) is None
        )
    assert token not in caplog.text + response.text and "fixture-private" not in caplog.text + response.text


def test_multipart_csrf_preserves_files_and_does_not_spool_plaintext(signed_in, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("multipart upload spooled plaintext to disk")

    monkeypatch.setattr(tempfile.SpooledTemporaryFile, "rollover", forbidden)
    response = signed_in.post(
        "/_test/protected",
        data={"csrf_token": signed_in.fixture_csrf, "echo": "fixture-multipart"},
        files={"file": ("fixture.pem", b"x" * 1_048_577, "application/octet-stream")},
    )
    assert response.status_code == 200 and response.json()["echo"] == "fixture-multipart"


def test_total_body_is_bounded_before_action(signed_in, web_app):
    response = signed_in.post(
        "/_test/protected",
        headers={"X-CSRF-Token": signed_in.fixture_csrf},
        content=b"x" * (4 * 1024 * 1024 + 1),
    )
    assert response.status_code == 413 and web_app.state.calls == 0


def test_timezone_filter_formats_an_explicit_zone():
    from datetime import UTC, datetime

    from app.main import format_datetime

    assert format_datetime(datetime(2026, 10, 19, 12, tzinfo=UTC), "Europe/Rome") == "2026-10-19 14:00 CEST"


@pytest.mark.parametrize("surface", ["image", "compose"])
def test_runtime_server_does_not_reinterpret_forwarding_headers_or_log_urls(surface):
    if shutil.which("docker") is None:
        pytest.skip("host Docker required")
    arguments = (
        ["docker", "image", "inspect", "cert-dashboard:local", "--format", "{{json .Config.Cmd}}"]
        if surface == "image"
        else ["docker", "compose", "-f", "docker-compose.yml", "config", "--format", "json"]
    )
    result = subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "TRUSTED_PROXIES": "10.0.0.1/32"},
    )
    rendered = json.loads(result.stdout)
    command = rendered if surface == "image" else rendered["services"]["web"]["command"]
    assert "--no-proxy-headers" in command and "--no-access-log" in command
    if surface == "compose":
        assert rendered["services"]["web"]["environment"]["TRUSTED_PROXIES"] == "10.0.0.1/32"


@pytest.mark.parametrize("echo", [True, "debug"])
def test_sql_debug_logging_cannot_expose_session_bind_values(signed_in, web_factory, caplog, echo):
    engine = web_factory.kw["bind"]
    token = signed_in.cookies["cd_session"]
    engine.echo = echo
    try:
        with caplog.at_level(logging.INFO, logger="sqlalchemy.engine.Engine"):
            assert signed_in.get("/_test/protected").status_code == 200
    finally:
        engine.echo = False
    assert token not in caplog.text
