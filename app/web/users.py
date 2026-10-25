"""Local user administration (``/users``, Task 22).

Every active, fully authenticated user is an administrator in v1. Creating and editing users needs
CSRF only; deactivation, password reset and 2FA reset also re-authenticate the acting administrator
with their current password (a failure is committed before the 422, so the lockout counter holds).
The administrator-chosen temporary password is read once from the form and is never echoed back,
not even on a validation error. There is deliberately no delete or reactivation route.
"""

from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from app.auth.local import (
    UserAdminError,
    create_user,
    deactivate_user,
    lock_user_admin,
    reauthenticate,
    reset_password,
    reset_totp,
    update_user,
)
from app.auth.sessions import clear_session_cookie
from app.models import User
from app.models.enums import AuthBackend
from app.web.common import _render, _transact, display_timezone, install_template_helpers

_NOTICES = {
    "created": "User created. They must change the temporary password at first sign-in.",
    "updated": "User updated.",
    "deactivated": "User deactivated and signed out.",
    "password_reset": "Password reset. The user is signed out and must choose a new password at next sign-in.",
    "totp_reset": "Two-factor authentication reset. The user is signed out everywhere.",
}
_ADMIN_MESSAGES = {
    "duplicate_username": "A user with this username already exists.",
    "invalid_email": "Enter a valid email address (at most 254 characters).",
    "invalid_username": "Username must be 1–150 characters: letters, digits, . _ @ -",
    "invalid_display_name": "Display name must be at most 200 characters.",
    "last_active_user": "The last active user cannot be deactivated.",
    "not_supported": "The password of this account is managed by its directory and cannot be reset here.",
    "not_found": "User not found.",
    "already_inactive": "This user is already inactive.",
}
_REAUTH_MESSAGES = {
    "invalid_current_password": (422, "Your current password is incorrect."),
    "locked": (423, "Your account is temporarily locked after repeated failures. Try again later."),
    "not_supported": (422, "Re-authentication is unavailable for accounts managed by a directory."),
}
_FORM_FIELDS = ("username", "email", "display_name")


def _admin_message(error: UserAdminError) -> str:
    if error.code == "policy":
        return error.message or "Password does not meet the policy."
    return _ADMIN_MESSAGES.get(error.code, "Request could not be completed.")


def _listing(request: Request) -> list[dict]:
    """Explicit allowlist of list columns: hashes, TOTP material and recovery codes are never selected."""
    now = request.app.state.clock()
    with request.app.state.factory() as db:
        rows = db.execute(
            select(
                User.id,
                User.username,
                User.display_name,
                User.email,
                User.auth_backend,
                User.is_active,
                User.totp_enabled,
                User.must_change_password,
                User.last_login_at,
                User.locked_until,
            ).order_by(User.username, User.id)
        ).all()
    return [
        {
            "id": row.id,
            "username": row.username,
            "display_name": row.display_name,
            "email": row.email,
            "backend": str(row.auth_backend),
            "is_active": row.is_active,
            "totp_enabled": bool(row.totp_enabled),
            "must_change": bool(row.must_change_password),
            "last_login_at": row.last_login_at,
            "locked_until": row.locked_until if row.locked_until and row.locked_until > now else None,
            "local": row.auth_backend == AuthBackend.LOCAL,
        }
        for row in rows
    ]


def _page(request: Request, status: int = 200, error: str | None = None, values: dict | None = None):
    with request.app.state.factory() as db:
        timezone_name = display_timezone(db)
    return _render(
        request,
        "users.html.j2",
        status,
        csrf_token=request.state.session.csrf_token,
        users=_listing(request),
        current_user_id=request.state.session.user_id,
        notice=_NOTICES.get(request.query_params.get("notice", "")),
        error=error,
        values={name: "" for name in _FORM_FIELDS} | (values or {}),
        tz=timezone_name,
    )


def _signed_out() -> RedirectResponse:
    """The acting session was revoked together with the target's (self-service on one's own account)."""
    response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(response)
    return response


def _perform(request: Request, work, notice: str, target_id: int | None = None, values: dict | None = None):
    """Run `work` in one transaction; map typed refusals to a 422 page and success to a 303."""
    try:
        _, refused = _transact(request, work)
    except UserAdminError as exc:
        return _page(request, 422, _admin_message(exc), values)
    if refused is not None:
        status, message = _REAUTH_MESSAGES.get(refused.code, (422, "Request could not be completed."))
        return _page(request, status, message, values)
    if target_id is not None and target_id == request.state.session.user_id:
        return _signed_out()
    return RedirectResponse(f"/users?notice={notice}", status_code=303)


def _reauthenticated(request: Request, current_password: str, work):
    """Wrap `work(db, now, actor)` with the shared lock order and the administrator's re-authentication."""
    acting = request.state.session.user_id

    def guarded(db, now, actor):
        lock_user_admin(db)  # before any row lock, so concurrent administrators cannot deadlock
        reauthenticate(db, acting, current_password, actor, now)
        return work(db, now, actor)

    return guarded


def register_user_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/users")
    def users_page(request: Request):
        return _page(request)

    @app.post("/users")
    def users_create(
        request: Request,
        username: str = Form(""),
        email: str = Form(""),
        display_name: str = Form(""),
        password: str = Form(""),
        confirm_password: str = Form(""),
    ):
        values = {"username": username[:200], "email": email[:300], "display_name": display_name[:300]}

        def work(db, now, actor):
            if password != confirm_password:
                raise UserAdminError("policy", "The passwords do not match.")
            return create_user(db, username, email, display_name, password, actor)

        return _perform(request, work, "created", values=values)

    @app.post("/users/{user_id}/edit")
    def users_edit(request: Request, user_id: int, email: str = Form(""), display_name: str = Form("")):
        def work(db, now, actor):
            return update_user(db, user_id, email, display_name, actor)

        return _perform(request, work, "updated")

    @app.post("/users/{user_id}/deactivate")
    def users_deactivate(request: Request, user_id: int, current_password: str = Form("")):
        def work(db, now, actor):
            return deactivate_user(db, user_id, actor, now)

        return _perform(
            request, _reauthenticated(request, current_password, work), "deactivated", target_id=user_id
        )

    @app.post("/users/{user_id}/reset-password")
    def users_reset_password(
        request: Request,
        user_id: int,
        new_password: str = Form(""),
        confirm_password: str = Form(""),
        current_password: str = Form(""),
    ):
        def work(db, now, actor):
            if new_password != confirm_password:
                raise UserAdminError("policy", "The passwords do not match.")
            return reset_password(db, user_id, new_password, actor, now)

        return _perform(
            request, _reauthenticated(request, current_password, work), "password_reset", target_id=user_id
        )

    @app.post("/users/{user_id}/reset-totp")
    def users_reset_totp(request: Request, user_id: int, current_password: str = Form("")):
        def work(db, now, actor):
            return reset_totp(db, user_id, actor, now)

        return _perform(
            request, _reauthenticated(request, current_password, work), "totp_reset", target_id=user_id
        )
