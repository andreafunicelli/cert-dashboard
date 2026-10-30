"""Opaque database sessions, signed pre-auth CSRF and explicit proxy trust."""

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta
from ipaddress import IPv6Address, ip_address, ip_network

from fastapi import HTTPException, Request, Response
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import User, UserSession

_TOKEN = re.compile(r"[0-9a-f]{64}\Z")
SESSION_COOKIE = "cd_session"
LOGIN_CSRF_COOKIE = "cd_login_csrf"
# Pre-auth double-submit token lifetime; the cookie carries the same max-age.
_CSRF_MAX_AGE = 600
CSRF_REJECTED = "csrf_rejected"


def _aware(now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Session time must be timezone-aware.")


def issue_session(
    db: Session, user_id: int, now: datetime, ip: str, user_agent: str, authenticated: bool = True
) -> UserSession:
    _aware(now)
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise ValueError("User is unavailable.")
    session = UserSession(
        id=secrets.token_hex(32),
        csrf_token=secrets.token_hex(32),
        user_id=user_id,
        created_at=now,
        last_seen_at=now,
        expires_at=now + (timedelta(hours=24) if authenticated else timedelta(minutes=10)),
        authenticated_at=now if authenticated else None,
        ip=ip,
        user_agent=user_agent[:512],
    )
    db.add(session)
    db.flush()
    return session


def resolve_session(db: Session, cookie: str, now: datetime) -> UserSession | None:
    _aware(now)
    if not isinstance(cookie, str) or not _TOKEN.fullmatch(cookie):
        return None
    session = db.scalar(
        select(UserSession)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.id == cookie, User.is_active.is_(True))
        .with_for_update(of=UserSession)
        .execution_options(populate_existing=True)
    )
    if session is None or session.revoked_at is not None:
        return None
    absolute = session.created_at + (
        timedelta(hours=24) if session.authenticated_at is not None else timedelta(minutes=10)
    )
    if now >= min(absolute, session.expires_at, session.last_seen_at + timedelta(hours=8)):
        return None
    if now < session.created_at or now < session.last_seen_at:
        return None
    session.last_seen_at = now
    return session


def revoke_sessions(db: Session, user_id: int, now: datetime) -> int:
    _aware(now)
    return db.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    ).rowcount


def revoke_session(db: Session, session_id: str, now: datetime) -> int:
    """Revoke exactly one session (logout); the user's other sessions stay valid."""
    _aware(now)
    return db.execute(
        update(UserSession)
        .where(UserSession.id == session_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    ).rowcount


def rotate_session(
    db: Session,
    previous: UserSession | None,
    user_id: int,
    now: datetime,
    ip: str,
    user_agent: str,
    authenticated: bool = True,
) -> UserSession:
    if previous is not None:
        db.execute(
            update(UserSession)
            .where(UserSession.id == previous.id, UserSession.revoked_at.is_(None))
            .values(revoked_at=now)
        )
    return issue_session(db, user_id, now, ip, user_agent, authenticated)


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")


def set_session_cookie(response: Response, session: UserSession) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        session.id,
        max_age=86400 if session.authenticated_at is not None else 600,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    response.delete_cookie(LOGIN_CSRF_COOKIE, path="/", secure=True, httponly=True, samesite="lax")


def _signature(payload: str, secret: bytes) -> str:
    return hmac.new(secret, ("login-csrf:" + payload).encode("ascii"), hashlib.sha256).hexdigest()


def issue_login_csrf(response: Response, secret: bytes, now: datetime) -> str:
    _aware(now)
    payload = f"{int(now.timestamp())}.{secrets.token_hex(32)}"
    token = payload + "." + _signature(payload, secret)
    response.set_cookie(
        LOGIN_CSRF_COOKIE, token, max_age=_CSRF_MAX_AGE, path="/", secure=True, httponly=True, samesite="lax"
    )
    return token


def valid_login_csrf(token: object, secret: bytes, now: datetime) -> bool:
    """True when ``token`` is a pre-auth double-submit value this server signed under 600 s ago."""
    _aware(now)
    if not isinstance(token, str) or not token.isascii() or len(token) > 256:
        return False
    try:
        issued, nonce, signature = token.split(".")
        instant = int(issued)
    except (ValueError, UnicodeError):
        return False
    payload = issued + "." + nonce
    age = int(now.timestamp()) - instant
    return (
        bool(_TOKEN.fullmatch(nonce))
        and 0 <= age < _CSRF_MAX_AGE
        and hmac.compare_digest(signature, _signature(payload, secret))
    )


def login_csrf_token(request: Request, secret: bytes, now: datetime) -> tuple[str, str | None]:
    """The pre-auth token to render, reusing the caller's cookie for as long as it is valid.

    Reuse is what keeps a form open in another tab usable: minting on every ``GET /login`` replaced
    the cookie and orphaned every token already rendered. Returns ``(token, set_cookie)``, where
    ``set_cookie`` is the ``Set-Cookie`` header value only when a new cookie had to be minted.
    """
    existing = request.cookies.get(LOGIN_CSRF_COOKIE, "")
    if valid_login_csrf(existing, secret, now):
        return existing, None
    holder = Response()
    return issue_login_csrf(holder, secret, now), holder.headers["set-cookie"]


class CsrfRejected(HTTPException):
    """A non-GET request whose CSRF token did not match its session token or signed cookie.

    The check runs in middleware, before routing, so the request log would otherwise only show
    ``route: "<unmatched>"``. The distinct type lets the error page name the real cause and the log
    line carry ``error_class: "csrf_rejected"``; the status stays 403.
    """

    def __init__(self) -> None:
        super().__init__(status_code=403, detail=CSRF_REJECTED)


def _equal(first: object, second: str) -> bool:
    return (
        isinstance(first, str)
        and first.isascii()
        and len(first) <= 256
        and hmac.compare_digest(first, second)
    )


def check_csrf(request: Request, session: UserSession | None) -> None:
    if request.method == "GET":
        return
    supplied = request.headers.get("X-CSRF-Token")
    if supplied is None:
        supplied = getattr(request.state, "csrf_token", None)
    if session is not None:
        valid = _equal(supplied, session.csrf_token)
    else:
        cookie = request.cookies.get(LOGIN_CSRF_COOKIE, "")
        valid = _equal(supplied, cookie) and valid_login_csrf(
            cookie, request.app.state.settings.session_secret, request.app.state.clock()
        )
    if not valid:
        # Like require_user's password_change_required: name the cause where it is decided, so both
        # the error page and the "<unmatched>" request log line can say what happened.
        request.state.error_class = CSRF_REJECTED
        raise CsrfRejected()


def _address(value: str):
    if "%" in value or "/" in value:
        raise ValueError
    result = ip_address(value)
    return result.ipv4_mapped if isinstance(result, IPv6Address) and result.ipv4_mapped else result


def client_ip(request: Request, trusted_proxies: tuple[str, ...]) -> str:
    try:
        peer = _address(request.client.host)
    except (ValueError, AttributeError):
        raise HTTPException(400) from None
    networks = tuple(ip_network(value, strict=False) for value in trusted_proxies)
    trusted = lambda address: any(address in network for network in networks)
    if not trusted(peer):
        return str(peer)
    forwarded = ",".join(request.headers.getlist("X-Forwarded-For"))
    try:
        if not forwarded or len(forwarded) > 4096:
            return str(peer)
        hops = forwarded.split(",")
        if len(hops) > 32:
            return str(peer)
        addresses = [_address(value.strip()) for value in hops]
    except ValueError:
        return str(peer)
    for address in reversed(addresses):
        if not trusted(address):
            return str(address)
    return str(peer)
