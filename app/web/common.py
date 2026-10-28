"""Shared web helpers: rendering, request actor, transactions, auth dependencies, typed errors.

Feature routes live in ``app/web/<area>.py`` and import from here; ``app.main``
re-exports these names for backward compatibility.
"""

import base64
import hashlib
import hmac
import json
import secrets
from collections.abc import Iterable
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from markupsafe import Markup
from sqlalchemy.orm import Session

from app.auth.base import UserRecord
from app.auth.local import PasswordChangeError, allow_login_attempt
from app.auth.sessions import issue_login_csrf
from app.jobs.worker import worker_capabilities
from app.models.enums import JobType
from app.services.audit import Actor
from app.services.settings import get_setting

# While must_change_password is set, only these (method, path) pairs pass require_user.
_PASSWORD_CHANGE_ALLOWED = frozenset(
    {("GET", "/account"), ("POST", "/account/password"), ("POST", "/logout")}
)

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


FLASH_COOKIE = "cd_flash"
_FLASH_MAX_NOTES = 6
_FLASH_NOTE_CHARS = 240
_FLASH_MAX_AGE = 120


def _flash_signature(payload: str, secret: bytes) -> str:
    return hmac.new(secret, ("flash:" + payload).encode("ascii"), hashlib.sha256).hexdigest()


def set_flash(response: Response, secret: bytes, notes: Iterable[str]) -> None:
    """Carry short, non-secret, non-blocking notes to the next full page (one-shot, signed cookie)."""
    trimmed = [note[:_FLASH_NOTE_CHARS] for note in notes][:_FLASH_MAX_NOTES]
    if not trimmed:
        return
    payload = base64.urlsafe_b64encode(json.dumps(trimmed).encode("utf-8")).decode("ascii")
    response.set_cookie(
        FLASH_COOKIE,
        payload + "." + _flash_signature(payload, secret),
        max_age=_FLASH_MAX_AGE,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def read_flash(request: Request) -> tuple[str, ...]:
    """Notes from a validly signed flash cookie; anything else (tampered, malformed) yields nothing."""
    raw = request.cookies.get(FLASH_COOKIE)
    secret = request.app.state.settings.session_secret
    if not raw or secret is None or len(raw) > 4096 or not raw.isascii():
        return ()
    payload, _, signature = raw.partition(".")
    if not hmac.compare_digest(signature, _flash_signature(payload, secret)):
        return ()
    try:
        notes = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except ValueError:
        return ()
    if not isinstance(notes, list):
        return ()
    return tuple(note[:_FLASH_NOTE_CHARS] for note in notes if isinstance(note, str))[:_FLASH_MAX_NOTES]


def _consume_flash(request: Request, response: Response) -> None:
    if FLASH_COOKIE in request.cookies:
        response.delete_cookie(FLASH_COOKIE, path="/", secure=True, httponly=True, samesite="lax")


def format_datetime(value: datetime, timezone_name: str = "UTC") -> str:
    return value.astimezone(ZoneInfo(timezone_name)).strftime("%Y-%m-%d %H:%M %Z")


def require_user(request: Request) -> UserRecord:
    user = getattr(request.state, "user", None)
    session = getattr(request.state, "session", None)
    if user is None or not user.is_active or session is None or session.authenticated_at is None:
        raise HTTPException(401)
    if (
        getattr(request.state, "must_change_password", False)
        and (
            request.method,
            request.url.path,
        )
        not in _PASSWORD_CHANGE_ALLOWED
    ):
        request.state.password_change_required = True
        raise HTTPException(403)
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
    if status == 403 and getattr(request.state, "password_change_required", False):
        # must_change_password: send the user to the only screen that can clear the flag.
        message = "Change your password to continue."
        if request.headers.get("HX-Request", "").lower() == "true":
            response_headers["HX-Redirect"] = "/account"
        elif "application/json" not in request.headers.get("Accept", ""):
            return RedirectResponse("/account", status_code=303)
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
        flash=read_flash(request),
    )
    response = HTMLResponse(content, status, response_headers)
    _consume_flash(request, response)
    return response


def unsupported_reason(registry, plan: str, *required: tuple[JobType, str]) -> str:
    """Why a control is disabled: the registered-handler gap as text, or "" when everything exists."""
    missing = [f"{job_type.value}/{action}" for job_type, action in required if not registry.supports(job_type, action)]
    return f"handler {', '.join(missing)} not registered ({plan})" if missing else ""


NO_SSH_KEY = "Discovery and deploy are unavailable: the worker has no ansible_ssh_key"
NO_KNOWN_HOSTS = "Discovery and deploy are unavailable: the worker has no known_hosts file"
NO_INVENTORY = "No inventory repository is configured: set the repository URL first."
# The only screens that carry the capability banner (spec 9.2): where discovery and deploy are started or configured.
_CAPABILITY_SCREENS = ("/servers", "/bindings", "/deploy", "/settings")


def ansible_unavailable_reason(db: Session, now: datetime) -> str:
    """Why discovery and deploy cannot run, or "" when a live worker holds the SSH key and ``known_hosts``.

    A worker that has not reported (none alive, or one that started before it wrote its start row) is a
    hint rather than a reason: a dead worker already raises its own banner, and the jobs simply wait.
    """
    capabilities = worker_capabilities(db, now)
    if capabilities is None:
        return ""
    if not capabilities.ssh_key_present:
        return NO_SSH_KEY
    if not capabilities.known_hosts_present:
        return NO_KNOWN_HOSTS
    return ""


def inventory_unconfigured_reason(db: Session) -> str:
    """"" when an inventory repository URL is set; discovery and test pull cannot work without one."""
    return "" if get_setting(db, "inventory.repo_url") else NO_INVENTORY


def _capability_banner(request: Request) -> str:
    path = request.url.path
    if not any(path == screen or path.startswith(screen + "/") for screen in _CAPABILITY_SCREENS):
        return ""
    with request.app.state.factory() as db:
        return ansible_unavailable_reason(db, request.app.state.clock())


def _actor(request: Request, user_id: int | None = None, label: str | None = None) -> Actor:
    session = request.state.session
    if user_id is None and session is not None:
        user_id = session.user_id
    user = request.state.user
    label = label or (user.username if user is not None else "anonymous")
    return Actor(user_id, label, request.state.client_ip, request.headers.get("user-agent", "")[:512])


def _render(request: Request, name: str, status: int = 200, **context) -> HTMLResponse:
    app = request.app
    response = app.state.templates.TemplateResponse(
        request=request,
        name=name,
        status_code=status,
        context={
            "user": request.state.user,
            "navigation": app.state.navigation,
            "status_banner": app.state.status_banner,
            "flash": read_flash(request),
            "capability_banner": _capability_banner(request),
            **context,
        },
    )
    _consume_flash(request, response)
    response.headers["Cache-Control"] = "no-store"
    return response


def _form_page(request: Request, name: str, status: int = 200, token: str | None = None, **context):
    """Render a pre-account form with the right CSRF token for the caller's current state."""
    session = request.state.session
    mint = token is None and session is None
    if token is None:
        holder = Response()
        token = (
            issue_login_csrf(holder, request.app.state.settings.session_secret, request.app.state.clock())
            if mint
            else session.csrf_token
        )
    response = _render(request, name, status, csrf_token=token, **context)
    if mint:
        response.headers.append("set-cookie", holder.headers["set-cookie"])
    return response


def _transact(request: Request, work):
    """Run work(db, now, actor) in one transaction. A PasswordChangeError is committed first.

    Re-authentication failures increment the shared lockout counter and write audit rows;
    they must persist even though the requested change is refused.
    """
    app = request.app
    db = app.state.factory()
    try:
        try:
            result = work(db, app.state.clock(), _actor(request))
        except PasswordChangeError as exc:
            db.commit()
            return None, exc
        db.commit()
        return result, None
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# --------------------------------------------------------------------------
# Presentation helpers shared by the inventory screens (Task 17)
# --------------------------------------------------------------------------


def display_timezone(db: Session) -> str:
    """The ``ui.timezone`` display setting; anything missing or unknown means UTC."""
    value = get_setting(db, "ui.timezone")
    if isinstance(value, str) and value:
        try:
            ZoneInfo(value)
        except (KeyError, ValueError, OSError):
            return "UTC"
        return value
    return "UTC"


def time_tag(value: datetime | None, timezone_name: str = "UTC") -> Markup:
    """A ``<time>`` element: UTC machine value, local display text."""
    if value is None:
        return Markup("—")
    machine = value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return Markup('<time datetime="{}">{}</time>').format(machine, format_datetime(value, timezone_name))


def expiry_chip(not_after: datetime, now: datetime) -> dict[str, str]:
    """Colour class and label for the days-remaining chip (same boundaries as the expiry buckets)."""
    seconds = (not_after - now).total_seconds()
    if seconds < 0:
        days = int(-seconds // 86400)
        label = "Expired today" if days == 0 else f"Expired {days} day{'s' if days != 1 else ''} ago"
        return {"css": "chip-expired", "label": label}
    days = int(seconds // 86400)
    label = "< 1 day" if days == 0 else f"{days} day{'s' if days != 1 else ''}"
    if seconds < 7 * 86400:
        css = "chip-critical"
    elif seconds < 30 * 86400:
        css = "chip-warning"
    elif seconds < 60 * 86400:
        css = "chip-soon"
    else:
        css = "chip-ok"
    return {"css": css, "label": label}


def hostport(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def install_template_helpers(app: FastAPI) -> None:
    app.state.templates.env.globals.update(time_tag=time_tag, expiry_chip=expiry_chip, hostport=hostport)


def render_block(request: Request, name: str, block: str, status: int = 200, **context) -> HTMLResponse:
    """Render one named block of a template (an htmx fragment) with the usual request context."""
    template = request.app.state.templates.env.get_template(name)
    scope = {"request": request, "user": request.state.user, **context}
    html = "".join(template.blocks[block](template.new_context(scope)))
    return HTMLResponse(html, status, headers={"Cache-Control": "no-store"})
