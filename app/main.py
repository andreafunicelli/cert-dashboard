"""Web foundation. Default secret loading belongs to lifespan, never import."""

import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.formparsers import MultiPartParser

from app.auth.base import UserRecord
from app.auth.ldap import LDAPAuthBackend
from app.auth.local import LocalAuthBackend, allow_login_attempt
from app.auth.sessions import check_csrf, client_ip, resolve_session
from app.config import ConfigurationError, Settings, load_settings
from app.db import assert_database_ready, create_session_factory
from app.models import User
from app.services.audit import SecretRedactionFilter
from app.services.certificates import missing_master_key_versions

_ROOT = Path(__file__).parent
_LOG = logging.getLogger("cert_dashboard.web")
_MAX_BODY = 4 * 1024 * 1024
# The ASGI body cap also bounds every multipart part. Keep uploads in memory,
# including downstream form parsing, so private-key uploads cannot spool to disk.
MultiPartParser.spool_max_size = _MAX_BODY
_MESSAGES = {
    400: "Invalid request.",
    401: "Sign in to continue.",
    403: "Access denied.",
    404: "Page not found.",
    405: "Method not allowed.",
    413: "Request is too large.",
    422: "Request validation failed.",
    429: "Too many attempts. Try again later.",
    500: "An unexpected error occurred.",
    503: "Service temporarily unavailable.",
}


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


def format_datetime(value: datetime, timezone_name: str = "UTC") -> str:
    return value.astimezone(ZoneInfo(timezone_name)).strftime("%Y-%m-%d %H:%M %Z")


def require_user(request: Request) -> UserRecord:
    user = getattr(request.state, "user", None)
    session = getattr(request.state, "session", None)
    if user is None or not user.is_active or session is None or session.authenticated_at is None:
        raise HTTPException(401)
    return user


def require_admin(request: Request) -> UserRecord:
    # v1: every active, fully authenticated user is an administrator.
    return require_user(request)


def enforce_login_rate_limit(request: Request) -> None:
    if not allow_login_attempt(request.app.state.factory, request.state.client_ip, request.app.state.clock()):
        raise HTTPException(429, headers={"Retry-After": "60"})


def _error_response(request: Request, status: int, headers=None):
    request_id = getattr(request.state, "request_id", secrets.token_hex(16))
    response_headers = dict(headers or {})
    if status == 503:
        response_headers.setdefault("Retry-After", "5")
    if status == 429:
        response_headers.setdefault("Retry-After", "60")
    if status == 401:
        if request.headers.get("HX-Request", "").lower() == "true":
            response_headers["HX-Redirect"] = "/login"
        elif "application/json" not in request.headers.get("Accept", ""):
            return RedirectResponse("/login", status_code=303)
    message = _MESSAGES.get(status, "Request could not be completed.")
    if "application/json" in request.headers.get("Accept", ""):
        return JSONResponse({"error": message, "request_id": request_id}, status, response_headers)
    content = request.app.state.templates.get_template("error.html.j2").render(
        request=request,
        status=status,
        message=message,
        request_id=request_id,
        user=getattr(request.state, "user", None),
        navigation=request.app.state.navigation,
        status_banner=request.app.state.status_banner,
    )
    return HTMLResponse(content, status, response_headers)


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


def _identity(app: FastAPI, cookie: str, now: datetime):
    db = _acquire(app.state.factory)
    try:
        session = resolve_session(db, cookie, now)
        identity = None
        if session is not None and session.authenticated_at is not None:
            user = db.get(User, session.user_id)
            identity = (str(user.auth_backend), user.username)
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
    return session, record


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
            if cookie and not probe:
                request.state.session, request.state.user = await run_in_threadpool(
                    _identity, app, cookie, now
                )
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


def create_app(settings: Settings | None = None) -> FastAPI:
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
    app.state.public_paths = {"/login", "/login/2fa", "/health/live", "/health/ready", "/healthz"}
    app.state.navigation = [
        {"label": label, "url": url, "enabled": False, "reason": "Available in a later implementation task"}
        for label, url in [
            ("Overview", "/"),
            ("Certificates", "/certificates"),
            ("Servers", "/servers"),
            ("Deploy", "/deploy"),
            ("Scans", "/scans"),
            ("Audit", "/audit"),
            ("Settings", "/settings"),
        ]
    ]
    app.state.templates = Jinja2Templates(
        env=Environment(loader=FileSystemLoader(str(_ROOT / "templates")), autoescape=True)
    )
    app.state.templates.env.filters["datetime"] = format_datetime
    app.add_middleware(_WebFoundation)
    app.mount("/static", StaticFiles(directory=_ROOT / "static"), name="static")

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
    @app.get("/healthz")
    def ready():
        db = _acquire(app.state.factory)
        try:
            db.execute(select(1))
        finally:
            db.close()
        return {"status": "ok"}

    return app


app = create_app()
