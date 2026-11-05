"""Local user administration (``/users``, Slice B USR).

Every active, fully authenticated user is an administrator in v1. Creating and editing users needs
CSRF only; deactivation, reactivation, password reset and 2FA reset also re-authenticate the acting
administrator with their current password (a failure is committed before the 422, so the lockout
counter holds — contract C7). The administrator-chosen temporary password is read once from the
form and is never echoed back, not even on a validation error. There is deliberately no hard
delete: deactivation only (spec §9.3), with reactivation issuing a new temporary password.
"""

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select

from app.auth.local import (
    UserAdminError,
    create_user,
    deactivate_user,
    lock_user_admin,
    reactivate_user,
    reauthenticate,
    reset_password,
    reset_totp,
    update_user,
)
from app.auth.sessions import clear_session_cookie
from app.models import AuditLog, User
from app.models.enums import AuthBackend
from app.web.common import _render, _transact, display_timezone, install_template_helpers
from app.web.management import done, is_htmx

_ADMIN_MESSAGES = {
    "duplicate_username": "A user with this username already exists.",
    "invalid_email": "Enter a valid email address (at most 254 characters).",
    "invalid_username": "Username must be 1–150 characters: letters, digits, . _ @ -",
    "invalid_display_name": "Display name must be at most 200 characters.",
    "last_active_user": "The last active user cannot be deactivated.",
    "not_supported": "The password of this account is managed by its directory and cannot be reset here.",
    "not_found": "User not found.",
    "already_inactive": "This user is already inactive.",
    "already_active": "This user is already active.",
}
_REAUTH_MESSAGES = {
    "invalid_current_password": (422, "Your current password is incorrect."),
    "locked": (423, "Your account is temporarily locked after repeated failures. Try again later."),
    "not_supported": (422, "Re-authentication is unavailable for accounts managed by a directory."),
}
# Validation codes that name a form field; anything else is a business refusal shown at panel level.
_FORM_CODES = {
    "duplicate_username": "username",
    "invalid_username": "username",
    "invalid_email": "email",
    "invalid_display_name": "display_name",
}
_FORM_FIELDS = ("username", "email", "display_name")
_NOTICES = {
    "password_reset": "Password reset. The user is signed out and must choose a new password at next sign-in.",
    "totp_reset": "Two-factor authentication reset. The user is signed out everywhere.",
}
_HISTORY_LIMIT = 8
_BIGINT_MAX = 2**63 - 1


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


def _managed(db, user_id: int, now) -> dict | None:
    """Explicit allowlist for the detail page; the password hash and 2FA material never leave the DB."""
    if not isinstance(user_id, int) or not 0 < user_id <= _BIGINT_MAX:
        return None
    row = db.execute(
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
        ).where(User.id == user_id)
    ).first()
    if row is None:
        return None
    return {
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


def _history(db, user_id: int) -> list[dict]:
    rows = db.execute(
        select(AuditLog.action, AuditLog.actor_label, AuditLog.created_at)
        .where(AuditLog.target_type == "user", AuditLog.target_id == str(user_id))
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(_HISTORY_LIMIT)
    ).all()
    return [
        {"action": row.action, "actor": row.actor_label, "created_at": row.created_at} for row in rows
    ]


def _page(
    request: Request,
    status: int = 200,
    errors: dict | None = None,
    error: str | None = None,
    values: dict | None = None,
):
    with request.app.state.factory() as db:
        timezone_name = display_timezone(db)
    users = _listing(request)
    current_user_id = request.state.session.user_id
    return _render(
        request,
        "users.html.j2",
        status,
        csrf_token=request.state.session.csrf_token,
        users=users,
        current_user_id=current_user_id,
        only_user=len(users) == 1 and users[0]["id"] == current_user_id,
        error=error,
        errors=errors or {},
        values={name: "" for name in _FORM_FIELDS} | (values or {}),
        create_open=request.query_params.get("create") == "1" or values is not None,
        tz=timezone_name,
    )


def _detail_page(
    request: Request,
    user_id: int,
    status: int = 200,
    errors: dict | None = None,
    action_error: str | None = None,
    values: dict | None = None,
):
    now = request.app.state.clock()
    with request.app.state.factory() as db:
        managed = _managed(db, user_id, now)
        if managed is None:
            raise HTTPException(404)
        history = _history(db, user_id)
        timezone_name = display_timezone(db)
    return _render(
        request,
        "users/detail.html.j2",
        status,
        csrf_token=request.state.session.csrf_token,
        managed=managed,
        history=history,
        current_user_id=request.state.session.user_id,
        errors=errors or {},
        action_error=action_error,
        values={"email": managed["email"], "display_name": managed["display_name"] or ""}
        | (values or {}),
        tz=timezone_name,
    )


def _detail_failure(request: Request, user_id: int, values: dict | None = None, prefix: str = ""):
    """Build the 422/423 re-render for a detail-page form, preserving non-secret values.

    Several security forms on one page share field names (``current_password``), so their error
    keys are prefixed per action: the anchor/aria ids stay unique while still following C3.
    """

    def on_error(status: int, message: str, field: str | None):
        key = f"{prefix}-{field}" if prefix and field else field
        return _detail_page(
            request,
            user_id,
            status,
            errors={key: [message]} if key else None,
            action_error=None if key else message,
            values=values,
        )

    return on_error


def _signed_out(request: Request) -> Response:
    """The acting session was revoked together with the target's (self-service on one's own account)."""
    if is_htmx(request):
        response = Response(status_code=200)
        response.headers["HX-Redirect"] = "/login"
    else:
        response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(response)
    return response


def _perform(
    request: Request,
    work,
    *,
    location,
    note,
    on_error,
    target_id: int | None = None,
    policy_field: str | None = None,
):
    """Run `work` in one transaction; map typed refusals inline and success to a flash + redirect."""
    try:
        outcome, refused = _transact(request, work)
    except UserAdminError as exc:
        if exc.code == "not_found":
            raise HTTPException(404) from None
        field = policy_field if exc.code == "policy" else _FORM_CODES.get(exc.code)
        return on_error(422, _admin_message(exc), field)
    if refused is not None:
        status, message = _REAUTH_MESSAGES.get(refused.code, (422, "Request could not be completed."))
        return on_error(status, message, "current_password")
    if target_id is not None and target_id == request.state.session.user_id:
        return _signed_out(request)
    where = location(outcome) if callable(location) else location
    text = note(outcome) if callable(note) else note
    return done(request, where, text)


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

    @app.get("/users/{user_id}")
    def users_detail(request: Request, user_id: int):
        return _detail_page(request, user_id)

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

        def on_error(status: int, message: str, field: str | None):
            return _page(request, status, errors={field or "username": [message]}, values=values)

        return _perform(
            request,
            work,
            location=lambda user: f"/users/{user.id}",
            note=lambda user: (
                f"User {user.username} created. They must change the temporary password at first sign-in."
            ),
            on_error=on_error,
            policy_field="password",
        )

    @app.post("/users/{user_id}/edit")
    def users_edit(request: Request, user_id: int, email: str = Form(""), display_name: str = Form("")):
        values = {"email": email[:300], "display_name": display_name[:300]}

        def work(db, now, actor):
            return update_user(db, user_id, email, display_name, actor)

        return _perform(
            request,
            work,
            location=f"/users/{user_id}",
            note=lambda user: f"User {user.username} updated.",
            on_error=_detail_failure(request, user_id, values),
        )

    @app.post("/users/{user_id}/deactivate")
    def users_deactivate(request: Request, user_id: int, current_password: str = Form("")):
        def work(db, now, actor):
            deactivate_user(db, user_id, actor, now)
            return db.scalar(select(User.username).where(User.id == user_id))

        return _perform(
            request,
            _reauthenticated(request, current_password, work),
            location=f"/users/{user_id}",
            note=lambda username: f"User {username} deactivated and signed out.",
            on_error=_detail_failure(request, user_id, prefix="deactivate"),
            target_id=user_id,
        )

    @app.post("/users/{user_id}/reactivate")
    def users_reactivate(
        request: Request,
        user_id: int,
        current_password: str = Form(""),
        password: str = Form(""),
    ):
        def work(db, now, actor):
            return reactivate_user(db, user_id, password, actor, now)

        return _perform(
            request,
            _reauthenticated(request, current_password, work),
            location=f"/users/{user_id}",
            note=lambda user: (
                f"User {user.username} reactivated. They must change the temporary password at next sign-in."
            ),
            on_error=_detail_failure(request, user_id, prefix="reactivate"),
            target_id=user_id,
            policy_field="password",
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
            request,
            _reauthenticated(request, current_password, work),
            location=f"/users/{user_id}",
            note=_NOTICES["password_reset"],
            on_error=_detail_failure(request, user_id, prefix="reset_password"),
            target_id=user_id,
            policy_field="new_password",
        )

    @app.post("/users/{user_id}/reset-totp")
    def users_reset_totp(request: Request, user_id: int, current_password: str = Form("")):
        def work(db, now, actor):
            return reset_totp(db, user_id, actor, now)

        return _perform(
            request,
            _reauthenticated(request, current_password, work),
            location=f"/users/{user_id}",
            note=_NOTICES["totp_reset"],
            on_error=_detail_failure(request, user_id, prefix="reset_totp"),
            target_id=user_id,
        )
