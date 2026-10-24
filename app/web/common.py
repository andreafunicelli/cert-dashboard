"""Shared web helpers: rendering, request actor, transactions, auth dependencies, typed errors.

Feature routes live in ``app/web/<area>.py`` and import from here; ``app.main``
re-exports these names for backward compatibility.
"""

import secrets
from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from app.auth.base import UserRecord
from app.auth.local import PasswordChangeError, allow_login_attempt
from app.auth.sessions import issue_login_csrf
from app.services.audit import Actor

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
    )
    return HTMLResponse(content, status, response_headers)


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
            **context,
        },
    )
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
