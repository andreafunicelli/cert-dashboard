"""Web foundation. Default secret loading belongs to lifespan, never import."""

import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from sqlalchemy import exists, select
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.formparsers import MultiPartParser

from app.auth.base import Failure
from app.auth.ldap import LDAPAuthBackend
from app.auth.local import (
    LocalAuthBackend,
    PasswordChangeError,
    begin_totp,
    change_password,
    confirm_totp,
    consume_second_factor,
    disable_totp,
    reauthenticate,
)
from app.auth.sessions import (
    check_csrf,
    clear_session_cookie,
    client_ip,
    issue_session,
    resolve_session,
    revoke_session,
    rotate_session,
    set_session_cookie,
)
from app.config import ConfigurationError, Settings, load_settings
from app.crypto.keyring import KeyUnwrapError
from app.db import assert_database_ready, create_session_factory
from app.jobs.worker import worker_liveness
from app.models import User
from app.models.enums import JobType
from app.services.audit import SecretRedactionFilter, record
from app.services.certificates import missing_master_key_versions
from app.web.audit import register_audit_routes
from app.web.certificates import register_certificate_routes
from app.web.common import (
    _actor,
    _error_response,
    _form_page,
    _render,
    _transact,
    enforce_login_rate_limit,
    format_datetime,
    require_admin,
    require_user,
    unsupported_reason,
)
from app.web.overview import register_overview_routes
from app.web.renewals import register_renewal_routes
from app.web.settings import register_settings_routes
from app.web.users import register_user_routes

__all__ = [
    "_actor",
    "_error_response",
    "_form_page",
    "_render",
    "_transact",
    "app",
    "create_app",
    "enforce_login_rate_limit",
    "format_datetime",
    "require_admin",
    "require_user",
]

_ROOT = Path(__file__).parent
_LOG = logging.getLogger("cert_dashboard.web")
# Sign-in lands on the Overview. A user flagged must_change_password is bounced from there to /account.
# There is deliberately no next/return-to parameter, which rules out open redirects.
POST_LOGIN_URL = "/"
# Unknown usernames are routed here so their failure is indistinguishable from a wrong password.
DEFAULT_BACKEND = "local"
_MESSAGE_INVALID = "Invalid credentials."
_MESSAGE_LOCKED = "This account is temporarily locked. Try again later or contact another admin."
_MESSAGE_RATE_LIMITED = "Too many sign-in attempts. Wait a minute and try again."
_MESSAGE_UNAVAILABLE = "Sign-in is temporarily unavailable. Try again shortly."
_MESSAGE_DIRECTORY = "Your password is managed by your directory; this action is not available here."
_NOTICES = {
    "password_changed": "Password changed. All other sessions were signed out.",
    "totp_enabled": "Two-factor authentication is now enabled. All other sessions were signed out.",
    "totp_disabled": "Two-factor authentication is disabled. All other sessions were signed out.",
}
_MAX_BODY = 4 * 1024 * 1024
# The ASGI body cap also bounds every multipart part. Keep uploads in memory,
# including downstream form parsing, so private-key uploads cannot spool to disk.
MultiPartParser.spool_max_size = _MAX_BODY


class _JSONFormatter(logging.Formatter):
    def format(self, record):
        fields = {"event": record.getMessage()}
        for name in ("request_id", "method", "route", "status", "error_class"):
            if hasattr(record, name):
                fields[name] = getattr(record, name)
        return json.dumps(fields)


class _SQLMetadataOnly(logging.Filter):
    def filter(self, record):
        # SQL echo includes raw result rows, not just bind values. Never emit
        # data-level SQL logs in web; request failures already log safe metadata.
        return record.levelno >= logging.WARNING


def _configure_logging() -> None:
    sql_logger = logging.getLogger("sqlalchemy.engine.Engine")
    if not any(isinstance(item, _SQLMetadataOnly) for item in sql_logger.filters):
        sql_logger.addFilter(_SQLMetadataOnly())
    if not any(getattr(handler, "_cert_dashboard", False) for handler in _LOG.handlers):
        handler = logging.StreamHandler()
        handler._cert_dashboard = True
        handler.addFilter(SecretRedactionFilter())
        handler.setFormatter(_JSONFormatter())
        _LOG.addHandler(handler)
    _LOG.setLevel(logging.INFO)


def _acquire(factory):
    # Retry connection acquisition once only. Never replay a query/transaction/action.
    for attempt in range(2):
        db = factory()
        try:
            db.connection()
            return db
        except DBAPIError:
            db.close()
            if attempt:
                raise


# The worker banner is computed per request but the heartbeat is read at most this often.
_WORKER_STATE_TTL = timedelta(seconds=30)


def _probe_worker(app: FastAPI, now: datetime) -> bool:
    """True when the worker is stale. Any failure fails closed: no banner, the page still renders."""
    try:
        with app.state.factory() as db:  # no connection retry: a failed probe just means no banner
            return worker_liveness(db, now) == "stale"
    except Exception as exc:  # noqa: BLE001 - a banner must never break a page
        _LOG.warning("worker liveness check failed", extra={"error_class": type(exc).__name__})
        return False


async def _worker_is_stale(app: FastAPI, now: datetime) -> bool:
    cached = getattr(app.state, "worker_state", None)
    if cached is not None and timedelta(0) <= now - cached[0] < _WORKER_STATE_TTL:
        return cached[1]
    stale = await run_in_threadpool(_probe_worker, app, now)
    app.state.worker_state = (now, stale)
    return stale


def _identity(app: FastAPI, cookie: str, now: datetime):
    db = _acquire(app.state.factory)
    try:
        session = resolve_session(db, cookie, now)
        identity, must_change = None, False
        if session is not None and session.authenticated_at is not None:
            user = db.get(User, session.user_id)
            identity = (str(user.auth_backend), user.username)
            must_change = bool(user.must_change_password)
        db.flush()
        if session is not None:
            db.expunge(session)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    backend = app.state.backends.get(identity[0]) if identity else None
    record = backend.lookup(identity[1]) if backend is not None else None
    return session, record, must_change


async def _form_csrf(request: Request, body: bytes):
    content_type = request.headers.get("content-type", "").lower()
    if content_type.startswith("application/x-www-form-urlencoded"):
        try:
            values = parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=1000).get(
                "csrf_token", []
            )
        except (ValueError, UnicodeError):
            raise HTTPException(400) from None
        return values[0] if len(values) == 1 else None
    if content_type.startswith("multipart/form-data"):

        async def stream():
            yield body
            yield b""

        try:
            form = await MultiPartParser(
                request.headers, stream(), max_files=8, max_fields=100, max_part_size=_MAX_BODY
            ).parse()
        except Exception:  # noqa: BLE001 - hostile multipart errors must be sanitized.
            raise HTTPException(400) from None
        try:
            values = form.getlist("csrf_token")
            return values[0] if len(values) == 1 and isinstance(values[0], str) else None
        finally:
            await form.close()
    return None


class _WebFoundation:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope, receive)
        request.state.request_id = secrets.token_hex(16)
        request.state.session, request.state.user = None, None
        request.state.must_change_password = False
        request.state.worker_stale = False
        started, status = False, 500

        async def secured_send(message):
            nonlocal started, status
            if message["type"] == "http.response.start":
                started, status = True, message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request.state.request_id
                headers["Cache-Control"] = "no-store"
            await send(message)

        try:
            app = request.app
            now = app.state.clock()
            request.state.client_ip = client_ip(request, app.state.settings.trusted_proxies)
            path = scope["path"]
            probe = path in {"/health/live", "/health/ready", "/healthz"} or path.startswith("/static/")
            cookie = request.cookies.get("cd_session")
            if not probe:
                request.state.worker_stale = await _worker_is_stale(app, now)
            if cookie and not probe:
                (
                    request.state.session,
                    request.state.user,
                    request.state.must_change_password,
                ) = await run_in_threadpool(_identity, app, cookie, now)
            downstream_receive = receive
            if request.method != "GET":
                chunks, total = [], 0
                async for chunk in request.stream():
                    total += len(chunk)
                    if total > _MAX_BODY:
                        raise HTTPException(413)
                    chunks.append(chunk)
                body = b"".join(chunks)
                request.state.csrf_token = (
                    await _form_csrf(request, body) if "X-CSRF-Token" not in request.headers else None
                )
                check_csrf(request, request.state.session)
                replayed = False

                async def replay():
                    nonlocal replayed
                    if not replayed:
                        replayed = True
                        return {"type": "http.request", "body": body, "more_body": False}
                    return await receive()

                downstream_receive = replay
            if not probe and path not in app.state.public_paths:
                require_user(request)
            await self.app(scope, downstream_receive, secured_send)
        except StarletteHTTPException as exc:
            if not started:
                await _error_response(request, exc.status_code, exc.headers)(scope, receive, secured_send)
        except Exception as exc:  # noqa: BLE001 - final HTTP error boundary; never expose exception text.
            _LOG.error(
                "Request failed",
                extra={"request_id": request.state.request_id, "error_class": type(exc).__name__},
            )
            if not started:
                await _error_response(request, 503 if isinstance(exc, SQLAlchemyError) else 500)(
                    scope, receive, secured_send
                )
        finally:
            route = getattr(scope.get("route"), "path", "<unmatched>")
            _LOG.info(
                "HTTP request",
                extra={
                    "request_id": request.state.request_id,
                    "method": request.method,
                    "route": route,
                    "status": status,
                },
            )


def _submitted_token(request: Request) -> str:
    # CSRF already validated this value; echoing it avoids churning the pre-auth cookie on errors.
    return request.headers.get("X-CSRF-Token") or getattr(request.state, "csrf_token", None) or ""


def _has_active_user(factory) -> bool:
    with factory() as db:
        return bool(db.scalar(select(exists().where(User.is_active.is_(True)))))


def _backend_for(app: FastAPI, username: str):
    """Known users are routed by user.auth_backend; unknown names use the default backend."""
    with app.state.factory() as db:
        stored = db.scalar(select(User.auth_backend).where(User.username == username))
    return app.state.backends.get(str(stored) if stored is not None else DEFAULT_BACKEND)


def _session_user_id(db, backend, username: str, user_key: str) -> int | None:
    """Bind the backend's authenticated identity to exactly one local user row.

    The backend's own lookup must return an active record whose key equals Success.user_key,
    and that key (the stringified local user id) must name a row of this backend and username.
    Anything else grants no session.
    """
    found = backend.lookup(username)
    if (
        found is None
        or not found.is_active
        or found.backend != backend.name
        or found.user_key != user_key
        or found.username.casefold() != username.casefold()
        or not user_key.isascii()
        or not user_key.isdecimal()
    ):
        return None
    return db.scalar(
        select(User.id).where(
            User.id == int(user_key), User.username == found.username, User.auth_backend == backend.name
        )
    )


def _redirect_with_session(location: str, session) -> RedirectResponse:
    response = RedirectResponse(location, status_code=303)
    set_session_cookie(response, session)
    return response


_PASSWORD_ERRORS = {
    "invalid_current_password": (422, "Current password is incorrect."),
    "locked": (423, _MESSAGE_LOCKED),
    "not_supported": (422, _MESSAGE_DIRECTORY),
    "mismatch": (422, "New passwords do not match."),
    "already_enabled": (422, "Two-factor authentication is already enabled."),
    "not_enabled": (422, "Two-factor authentication is not enabled."),
}
_KEY_UNAVAILABLE = (
    "Two-factor verification is unavailable: key material cannot be decrypted with the configured master key."
)


def _password_error(exc: PasswordChangeError) -> tuple[int, str]:
    if exc.code == "policy":
        return 422, exc.message or "Password does not meet the policy."
    return _PASSWORD_ERRORS.get(exc.code, (422, "Request could not be completed."))


def _account_page(request: Request, status: int = 200, token: str | None = None, **context):
    app = request.app
    session = request.state.session
    with app.state.factory() as db:
        row = db.get(User, session.user_id)
        backend = app.state.backends.get(str(row.auth_backend))
        facts = {
            "totp_enabled": bool(row.totp_enabled),
            "totp_pending": not row.totp_enabled and row.totp_secret_ciphertext is not None,
            "recovery_remaining": len(row.recovery_codes or []),
            "must_change": bool(row.must_change_password),
            "can_change_password": bool(backend and backend.supports_password_change()),
            "username": row.username,
        }
    return _render(
        request,
        "account.html.j2",
        status,
        csrf_token=token or session.csrf_token,
        notice=_NOTICES.get(request.query_params.get("notice", "")),
        **{"enrollment": None, **facts, **context},
    )


def _register_auth_routes(app: FastAPI) -> None:
    @app.get("/login")
    def login_form(request: Request, bootstrap: str | None = None):
        if not _has_active_user(app.state.factory):
            # Redirect once; the bootstrap URL itself renders the CLI hint and never redirects again.
            if bootstrap != "1":
                return RedirectResponse("/login?bootstrap=1", status_code=303)
            return _render(request, "bootstrap.html.j2")
        return _form_page(request, "login.html.j2", username="")

    @app.post("/login")
    def login_submit(request: Request, username: str = Form(""), password: str = Form("")):
        token, username = _submitted_token(request), username.strip()

        def fail(message: str, status: int = 401):
            return _form_page(request, "login.html.j2", status, token, error=message, username=username[:254])

        try:
            enforce_login_rate_limit(request)  # committed before any backend is invoked
        except HTTPException:
            response = fail(_MESSAGE_RATE_LIMITED, 429)
            response.headers["Retry-After"] = "60"
            return response
        if not username or len(username) > 254:
            return fail(_MESSAGE_INVALID)
        backend = _backend_for(app, username)
        if backend is None:
            return fail(_MESSAGE_INVALID)
        result = backend.authenticate(username, password)
        if isinstance(result, Failure):
            if result.reason == "locked":
                return fail(_MESSAGE_LOCKED, 423)
            if result.reason == "backend_unavailable":
                return fail(_MESSAGE_UNAVAILABLE, 503)
            return fail(_MESSAGE_INVALID)  # invalid, unknown, inactive, not_supported: one message
        now = app.state.clock()
        with app.state.factory.begin() as db:
            user_id = _session_user_id(db, backend, username, result.user_key)
            user = db.get(User, user_id) if user_id is not None else None
            if user is None or not user.is_active:
                session = None
            else:
                pending = bool(user.totp_enabled)
                session = rotate_session(
                    db,
                    request.state.session,
                    user.id,
                    now,
                    request.state.client_ip,
                    request.headers.get("user-agent", ""),
                    authenticated=not pending,
                )
                if not pending:
                    user.last_login_at = now
        if session is None:
            return fail(_MESSAGE_INVALID)
        return _redirect_with_session(
            "/login/2fa" if session.authenticated_at is None else POST_LOGIN_URL, session
        )

    @app.get("/login/2fa")
    def second_factor_form(request: Request):
        session = request.state.session
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if session.authenticated_at is not None:
            return RedirectResponse(POST_LOGIN_URL, status_code=303)
        return _render(request, "login_2fa.html.j2", csrf_token=session.csrf_token)

    @app.post("/login/2fa")
    def second_factor_submit(request: Request, code: str = Form("")):
        session = request.state.session
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if session.authenticated_at is not None:
            return RedirectResponse(POST_LOGIN_URL, status_code=303)

        def fail(message: str, status: int = 401):
            return _render(request, "login_2fa.html.j2", status, csrf_token=session.csrf_token, error=message)

        try:
            enforce_login_rate_limit(request)
        except HTTPException:
            response = fail(_MESSAGE_RATE_LIMITED, 429)
            response.headers["Retry-After"] = "60"
            return response
        now, fresh, locked = app.state.clock(), None, False
        try:
            with app.state.factory.begin() as db:  # False results commit too: counter and audit persist
                owner = db.get(User, session.user_id)
                actor = _actor(request, owner.id, owner.username)
                if consume_second_factor(db, owner.id, code, app.state.settings.keyring, now, actor):
                    fresh = rotate_session(
                        db,
                        session,
                        owner.id,
                        now,
                        request.state.client_ip,
                        request.headers.get("user-agent", ""),
                    )
                    owner.last_login_at = now
                else:
                    locked = owner.locked_until is not None and owner.locked_until > now
        except KeyUnwrapError:
            return fail(_KEY_UNAVAILABLE, 503)
        if fresh is None:
            return fail(_MESSAGE_LOCKED, 423) if locked else fail("Invalid code.")
        return _redirect_with_session(POST_LOGIN_URL, fresh)

    @app.post("/logout")
    def logout(request: Request):
        # Public path (CSRF still enforced): a pending-MFA session must be able to cancel and sign out.
        session = request.state.session
        if session is not None:
            with app.state.factory.begin() as db:
                revoke_session(db, session.id, app.state.clock())  # this browser only
                record(db, _actor(request), "auth.logout", "user", str(session.user_id), {})
        response = RedirectResponse("/login", status_code=303)
        clear_session_cookie(response)
        return response

    @app.get("/account")
    def account(request: Request):
        return _account_page(request)

    @app.post("/account/password")
    def account_password(
        request: Request,
        current_password: str = Form(""),
        new_password: str = Form(""),
        confirm_password: str = Form(""),
    ):
        user_id = request.state.session.user_id

        def work(db, now, actor):
            if new_password != confirm_password:
                # Re-authenticate first so a wrong current password always counts as a failure.
                reauthenticate(db, user_id, current_password, actor, now)
                raise PasswordChangeError("mismatch")
            change_password(db, user_id, current_password, new_password, actor, now)
            return issue_session(
                db, user_id, now, request.state.client_ip, request.headers.get("user-agent", "")
            )

        fresh, error = _transact(request, work)
        if error is not None:
            status, message = _password_error(error)
            return _account_page(request, status, password_error=message)
        return _redirect_with_session("/account?notice=password_changed", fresh)

    @app.post("/account/totp/enroll")
    def account_totp_enroll(request: Request, current_password: str = Form("")):
        user_id = request.state.session.user_id

        def work(db, now, actor):
            user = reauthenticate(db, user_id, current_password, actor, now)
            if user.totp_enabled:
                raise PasswordChangeError("already_enabled")
            restarted = user.totp_secret_ciphertext is not None
            enrollment = begin_totp(db, user_id, app.state.settings.keyring, actor)
            # Restarting an unconfirmed enrollment revokes every session; keep this browser signed in.
            fresh = (
                issue_session(
                    db, user_id, now, request.state.client_ip, request.headers.get("user-agent", "")
                )
                if restarted
                else None
            )
            return enrollment, fresh

        result, error = _transact(request, work)
        if error is not None:
            status, message = _password_error(error)
            return _account_page(request, status, enroll_error=message)
        enrollment, fresh = result
        response = _account_page(
            request,
            token=fresh.csrf_token if fresh is not None else None,
            enrollment=enrollment,
        )
        if fresh is not None:
            set_session_cookie(response, fresh)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/account/totp/confirm")
    def account_totp_confirm(request: Request, code: str = Form("")):
        user_id = request.state.session.user_id

        def work(db, now, actor):
            if confirm_totp(db, user_id, code, app.state.settings.keyring, now, actor):
                return issue_session(
                    db, user_id, now, request.state.client_ip, request.headers.get("user-agent", "")
                ), False
            owner = db.get(User, user_id)
            return None, owner.locked_until is not None and owner.locked_until > now

        try:
            result, _ = _transact(request, work)
        except KeyUnwrapError:
            return _account_page(request, 503, confirm_error=_KEY_UNAVAILABLE)
        fresh, locked = result
        if fresh is None:
            return (
                _account_page(request, 423, confirm_error=_MESSAGE_LOCKED)
                if locked
                else _account_page(request, 422, confirm_error="Invalid code.")
            )
        return _redirect_with_session("/account?notice=totp_enabled", fresh)

    @app.post("/account/totp/disable")
    def account_totp_disable(request: Request, current_password: str = Form("")):
        user_id = request.state.session.user_id

        def work(db, now, actor):
            user = reauthenticate(db, user_id, current_password, actor, now)
            if not user.totp_enabled:
                raise PasswordChangeError("not_enabled")
            disable_totp(db, user_id, actor)
            return issue_session(
                db, user_id, now, request.state.client_ip, request.headers.get("user-agent", "")
            )

        fresh, error = _transact(request, work)
        if error is not None:
            status, message = _password_error(error)
            return _account_page(request, status, disable_error=message)
        return _redirect_with_session("/account?notice=totp_disabled", fresh)


def create_app(settings: Settings | None = None) -> FastAPI:
    from app.jobs.handlers import build_registry  # late: handlers import the worker module

    registry = build_registry()  # capability checks for the navigation only; the worker owns execution
    deploy_reason = unsupported_reason(registry, "Plan 3", (JobType.DEPLOY, "default")) or "Available in a later plan"
    scan_reason = unsupported_reason(registry, "Plan 2", (JobType.SCAN, "default")) or "Available in a later plan"

    @asynccontextmanager
    async def lifespan(app):
        snapshot = settings or load_settings("web", os.environ, Path("/run/secrets"))
        if snapshot.profile != "web" or snapshot.session_secret is None or len(snapshot.session_secret) < 32:
            raise ConfigurationError("session_secret: web requires at least 32 random bytes")
        if len(snapshot.keyring.keys.get(snapshot.keyring.active, b"")) != 32:
            raise ConfigurationError("master_key: invalid active key")
        app.state.settings = snapshot
        owned = not hasattr(app.state, "factory")
        if owned:
            app.state.factory = create_session_factory(snapshot)
        engine = app.state.factory.kw["bind"]
        engine.hide_parameters = True
        await run_in_threadpool(assert_database_ready, engine)
        with app.state.factory() as db:
            app.state.missing_key_versions = missing_master_key_versions(db, snapshot.keyring)
        if app.state.missing_key_versions:
            app.state.status_banner = "key material cannot be decrypted with the configured master key"
        app.state.backends = {
            "local": LocalAuthBackend(app.state.factory, app.state.clock),
            "ldap": LDAPAuthBackend(),
        }
        _configure_logging()
        try:
            yield
        finally:
            if owned:
                engine.dispose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.clock = lambda: datetime.now(UTC)
    app.state.status_banner = ""
    app.state.public_paths = {"/login", "/login/2fa", "/logout", "/health/live", "/health/ready", "/healthz"}
    app.state.navigation = [
        {"label": label, "url": url, "enabled": enabled, "reason": reason}
        for label, url, enabled, reason in [
            ("Overview", "/", True, ""),
            ("Certificates", "/certificates", True, ""),
            ("Servers", "/servers", False, "Available in a later plan"),
            ("Deploy", "/deploy", False, deploy_reason),
            ("Scans", "/scans", False, scan_reason),
            ("Audit", "/audit", True, ""),
            ("Settings", "/settings", True, ""),
        ]
    ]
    app.state.templates = Jinja2Templates(
        env=Environment(loader=FileSystemLoader(str(_ROOT / "templates")), autoescape=True)
    )
    app.state.templates.env.filters["datetime"] = format_datetime
    app.add_middleware(_WebFoundation)
    app.mount("/static", StaticFiles(directory=_ROOT / "static"), name="static")
    _register_auth_routes(app)
    register_certificate_routes(app)
    register_overview_routes(app)
    register_renewal_routes(app)
    register_audit_routes(app)
    register_user_routes(app)
    register_settings_routes(app)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request, exc):
        return _error_response(request, exc.status_code, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        return _error_response(request, 422)

    @app.get("/health/live")
    def live():
        return {"status": "ok"}

    @app.get("/health/ready")
    def ready():
        db = _acquire(app.state.factory)
        try:
            db.execute(select(1))
        finally:
            db.close()
        return {"status": "ok"}

    @app.get("/healthz")
    def healthz():
        try:
            db = _acquire(app.state.factory)
            try:
                liveness = worker_liveness(db, app.state.clock())
            finally:
                db.close()
        except SQLAlchemyError:
            return JSONResponse(
                {"web": "ok", "worker": "unknown", "db": "unavailable"},
                503,
                {"Retry-After": "5"},
            )
        return {"web": "ok", "worker": liveness, "db": "ok"}

    return app


app = create_app()
