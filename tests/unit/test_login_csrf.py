"""Pre-auth CSRF: the signed double-submit cookie a login form carries.

A form left open in another tab must keep working, so a still-valid cookie is reused instead of
rotated on every ``GET /login``. These are the pure pieces; they run without Postgres.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import Response
from starlette.requests import Request

from app.auth.sessions import (
    CSRF_REJECTED,
    LOGIN_CSRF_COOKIE,
    CsrfRejected,
    check_csrf,
    issue_login_csrf,
    login_csrf_token,
    valid_login_csrf,
)

SECRET = b"fixture-session-signing-secret-32-bytes"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


def _request(cookies: dict[str, str] | None = None, token: str | None = None, method: str = "GET") -> Request:
    headers = []
    if cookies:
        joined = "; ".join(f"{name}={value}" for name, value in cookies.items())
        headers.append((b"cookie", joined.encode("ascii")))
    if token is not None:
        headers.append((b"x-csrf-token", token.encode("ascii")))
    app = SimpleNamespace(state=SimpleNamespace(clock=lambda: NOW, settings=SimpleNamespace(session_secret=SECRET)))
    return Request({"type": "http", "method": method, "headers": headers, "path": "/login", "app": app})


def _token(now: datetime = NOW) -> str:
    return issue_login_csrf(Response(), SECRET, now)


def test_a_fresh_token_is_signed_over_timestamp_and_nonce():
    token = _token()
    issued, nonce, signature = token.split(".")
    assert valid_login_csrf(token, SECRET, NOW)
    assert not valid_login_csrf(token, b"another-session-signing-secret-32!", NOW)
    assert not valid_login_csrf(f"{issued}.{'f' * 64}.{signature}", SECRET, NOW)
    assert not valid_login_csrf(f"{int(issued) + 1}.{nonce}.{signature}", SECRET, NOW)
    assert not valid_login_csrf(f"{issued}.{nonce}.{'0' * 64}", SECRET, NOW)
    for malformed in (nonce, "unsigned", "", "..", "1.2.3.4", None, 7):
        assert not valid_login_csrf(malformed, SECRET, NOW)


def test_a_token_is_accepted_before_ten_minutes_and_rejected_after():
    token = _token()
    assert valid_login_csrf(token, SECRET, NOW + timedelta(seconds=599))
    assert not valid_login_csrf(token, SECRET, NOW + timedelta(seconds=600))
    assert not valid_login_csrf(token, SECRET, NOW - timedelta(seconds=1))


def test_the_cookie_a_browser_already_holds_is_reused_verbatim():
    token = _token()
    reused, cookie = login_csrf_token(_request({LOGIN_CSRF_COOKIE: token}), SECRET, NOW + timedelta(seconds=300))
    assert reused == token and cookie is None


def test_a_missing_invalid_or_expired_cookie_is_replaced():
    stale = _token()
    for cookies, now in (
        ({}, NOW),
        ({LOGIN_CSRF_COOKIE: "unsigned"}, NOW),
        ({LOGIN_CSRF_COOKIE: stale}, NOW + timedelta(seconds=600)),
    ):
        token, cookie = login_csrf_token(_request(cookies), SECRET, now)
        assert token != stale and valid_login_csrf(token, SECRET, now)
        assert cookie is not None and cookie.startswith(f"{LOGIN_CSRF_COOKIE}={token}")
        assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
        assert "Max-Age=600" in cookie and "Path=/" in cookie


def test_a_post_without_its_matching_signed_cookie_is_csrf_rejected():
    token = _token()
    assert check_csrf(_request(), None) is None
    assert check_csrf(_request({LOGIN_CSRF_COOKIE: token}, token=token, method="POST"), None) is None
    for request in (
        _request(method="POST"),
        _request({LOGIN_CSRF_COOKIE: token}, token="f" * 64, method="POST"),
        _request(token=token, method="POST"),
    ):
        with pytest.raises(CsrfRejected) as rejected:
            check_csrf(request, None)
        assert rejected.value.status_code == 403 and rejected.value.detail == CSRF_REJECTED
        # The request log names the failure even though routing never ran ("<unmatched>").
        assert request.state.error_class == CSRF_REJECTED
