"""Replaceable logo: public serving, the shell resolver and the Settings → Branding screens.

``/branding/logo`` is the only new public path: the sign-in page needs the current logo before a
session exists. It serves only sanitized bytes from the singleton asset row; drafts, arbitrary
paths, database errors and uploaded originals are never reachable here. A missing, unreadable or
corrupt row falls back to the first-party mark without exposing an error or breaking sign-in.

This module also owns the settings routes (``docs/ui/branding.md`` §"Endpoint / form contract") and
the ``brand`` template value the shared shell reads. The shell never guesses: the server checks the
stored asset and only then points the mark slots at ``/branding/logo?v=<sha256>``; any lookup error
falls back to the default static identity, so a broken row cannot break navigation or sign-in.

A staged preview is addressed by a random 256-bit token. The browser keeps that token in an
HttpOnly, SameSite=Lax cookie scoped to ``/settings`` (never localStorage, never a public URL and
never a log line); only its SHA-256 exists in the database, bound to the authenticated session.
"""

from __future__ import annotations

import hashlib

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.exc import SQLAlchemyError
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException

from app.services.branding import (
    DRAFT_TTL,
    BrandingDraftExpired,
    BrandingDraftNotFound,
    BrandingRevisionMismatch,
    BrandingStorageUnavailable,
    clear_open_draft,
    current_asset,
    discard_draft,
    draft_image,
    find_draft,
    purge_branding_drafts,
    reset_branding,
    save_draft,
    stage_draft,
)
from app.services.branding_image import (
    MAX_DIMENSION,
    MAX_FILE_BYTES,
    MAX_REQUEST_BYTES,
    MESSAGES,
    PNG_MIME,
    SVG_MIME,
    BrandingImageError,
    request_within_limit,
)
from app.web.common import _actor, set_flash

DEFAULT_LOGO_PATH = "/static/branding/mark.svg"
SVG_CSP = "default-src 'none'; style-src 'none'; script-src 'none'; sandbox"
_PNG_DISPOSITION = 'inline; filename="logo.png"'
_SVG_DISPOSITION = 'inline; filename="logo.svg"'

# Default identity (docs/ui/branding.md). Keys never change; a saved asset only fills the mark slots.
DEFAULT_BRAND = {
    "lockup": "/static/branding/lockup.svg",
    "lockup_light": "/static/branding/lockup-light.svg",
    "mark": "/static/branding/mark.svg",
    "mark_light": "/static/branding/mark-light.svg",
    "favicon_svg": "/static/branding/favicon.svg",
    "favicon_png": "/static/branding/favicon-32.png",
    "custom": False,
}

# The browser-held draft token: HttpOnly, Secure, SameSite=Lax, scoped to the settings screens.
DRAFT_COOKIE = "cd_branding_draft"
DRAFT_COOKIE_PATH = "/settings"

UNCHANGED = "Your current logo has not changed."
MISSING = "Choose an SVG or PNG to preview."
SAVED = "Logo saved. It is now shown in navigation and on the sign-in page."
DISCARDED = "Preview discarded. Your current logo has not changed."
RESTORED = "Default logo restored."
EXPIRED = "Logo preview expired. Choose the file again and select Preview logo."
CONFLICT = (
    "Branding changed since you opened this page. Review the current logo and preview your file "
    "again before saving."
)
STORE_FAILED = "Logo could not be stored. Try Preview logo again."
SAVE_FAILED = "Logo could not be saved. Your current logo has not changed. Try Save logo again."
RESET_FAILED = "Logo could not be reset. Your current logo has not changed. Try again."
RESET_CONFIRMATION = "Type RESET to confirm resetting the logo."

__all__ = [
    "CONFLICT",
    "DEFAULT_BRAND",
    "DEFAULT_LOGO_PATH",
    "DISCARDED",
    "DRAFT_COOKIE",
    "EXPIRED",
    "RESTORED",
    "SAVED",
    "SVG_CSP",
    "apply_draft_cookie",
    "brand_context",
    "branding_context",
    "readable_asset",
    "register_branding_routes",
    "resolve_brand",
]


def readable_asset(asset) -> bool:
    """Only a complete, self-consistent, canonical stored row is shown or picked by the shell."""
    return (
        asset is not None
        and asset.mime in {SVG_MIME, PNG_MIME}
        and 0 < len(asset.content) <= MAX_FILE_BYTES
        and 1 <= asset.width <= MAX_DIMENSION
        and 1 <= asset.height <= MAX_DIMENSION
        and hashlib.sha256(asset.content).hexdigest() == asset.revision
    )


def _default_logo() -> RedirectResponse:
    return RedirectResponse(DEFAULT_LOGO_PATH, status_code=307)


# --- shell resolver and settings page context -----------------------------------------------------


def resolve_brand(request: Request) -> dict:
    """The ``brand`` template value: the default identity, or the saved image behind the mark keys.

    The asset is checked before its URL is chosen; every lookup failure (no row, unreadable bytes,
    database error) falls back to the static default so no page can break on a broken logo.
    """
    cached = getattr(request.state, "brand", None)
    if cached is not None:
        return cached
    brand = dict(DEFAULT_BRAND)
    try:
        with request.app.state.factory() as db:
            asset = current_asset(db)
        if readable_asset(asset):
            brand.update(
                custom=True,
                logo=f"/branding/logo?v={asset.revision}",
                width=asset.width,
                height=asset.height,
            )
    except Exception:  # noqa: BLE001 - a logo must never break a page or sign-in.
        brand = dict(DEFAULT_BRAND)
    request.state.brand = brand
    return brand


def brand_context(request: Request) -> dict:
    return {"brand": resolve_brand(request)}


def _current_view(asset) -> dict:
    if asset is None:
        return {
            "kind": "default",
            "revision": "default",
            "mime": "",
            "width": 0,
            "height": 0,
            "filename": "",
            "url": "",
        }
    if not readable_asset(asset):
        return {
            "kind": "unavailable",
            "revision": asset.revision,
            "mime": asset.mime,
            "width": asset.width,
            "height": asset.height,
            "filename": asset.display_filename,
            "url": "",
        }
    return {
        "kind": "custom",
        "revision": asset.revision,
        "mime": asset.mime,
        "width": asset.width,
        "height": asset.height,
        "filename": asset.display_filename,
        "url": f"/branding/logo?v={asset.revision}",
    }


def _draft_view(token: str, row) -> dict:
    size = row.byte_size or 0
    return {
        "token": token,
        "mime": row.mime or "",
        "width": row.width or 0,
        "height": row.height or 0,
        "filename": row.display_filename or "",
        "byte_size": size,
        "kib": -(-size // 1024),
        "sha256": row.sha256 or "",
        "base_revision": row.base_revision,
        "expires_at": row.expires_at,
        "url": f"/settings/branding/draft/{token}",
    }


def branding_context(request: Request) -> dict:
    """Current identity plus this session's unexpired draft (resumed after a redirect)."""
    session = request.state.session
    now = request.app.state.clock()
    token = request.cookies.get(DRAFT_COOKIE)
    asset = None
    draft = None
    with request.app.state.factory.begin() as db:
        purge_branding_drafts(db, now)
        asset = current_asset(db)
        if token and session is not None:
            try:
                row = find_draft(db, session_id=session.id, token=token, now=now)
            except BrandingDraftExpired:
                row = None
            if row is not None and row.consumed_at is None and row.content:
                draft = _draft_view(token, row)
    request.state.branding_draft_token = None if draft is None else draft["token"]
    current = _current_view(asset)
    return {
        "branding": {
            "current": current,
            "draft": draft,
            "base_revision": current["revision"],
            "max_bytes": MAX_FILE_BYTES,
        }
    }


def apply_draft_cookie(request: Request, response: Response) -> Response:
    """Mirror the current draft into (or out of) the browser-held token cookie."""
    token = getattr(request.state, "branding_draft_token", None)
    if token:
        response.set_cookie(
            DRAFT_COOKIE,
            token,
            max_age=int(DRAFT_TTL.total_seconds()),
            path=DRAFT_COOKIE_PATH,
            secure=True,
            httponly=True,
            samesite="lax",
        )
    else:
        response.delete_cookie(
            DRAFT_COOKIE, path=DRAFT_COOKIE_PATH, secure=True, httponly=True, samesite="lax"
        )
    return response


# --- settings routes ------------------------------------------------------------------------------


def _render(request: Request, status: int = 200, errors: dict | None = None, *, conflict: bool = False):
    from app.web.settings import render_branding  # local: settings imports this module for its tab

    return render_branding(request, status, errors=errors, conflict=conflict)


def _error(
    request: Request, status: int, message: str, *, field: str | None = "logo", conflict: bool = False
):
    if status in {409, 410, 413, 503} and UNCHANGED not in message:
        # branding.md: every failed upload/apply states plainly that the current logo still stands.
        message = f"{message} {UNCHANGED}"
    errors = {field: [message]} if field else {"form": [message]}
    return _render(request, status, errors, conflict=conflict)


def _clear_session_draft(request: Request) -> None:
    with request.app.state.factory.begin() as db:
        clear_open_draft(db, request.state.session.id)


def _set_draft_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        DRAFT_COOKIE,
        token,
        max_age=int(DRAFT_TTL.total_seconds()),
        path=DRAFT_COOKIE_PATH,
        secure=True,
        httponly=True,
        samesite="lax",
    )


def _too_large(request: Request):
    _clear_session_draft(request)
    return _error(request, 413, f"{MESSAGES['too_large']} {UNCHANGED}")


def _handle_preview(request: Request, form) -> Response:
    upload = form.get("logo")
    if not isinstance(upload, UploadFile) or not upload.filename:
        return _error_missing(request)
    data = upload.file.read(MAX_FILE_BYTES + 1)
    # A refused upload must never leave an older candidate one click away from being saved.
    _clear_session_draft(request)
    if len(data) > MAX_FILE_BYTES:
        return _error(request, 413, f"{MESSAGES['too_large']} {UNCHANGED}")
    try:
        with request.app.state.factory.begin() as db:
            staged = stage_draft(
                db,
                session_id=request.state.session.id,
                filename=upload.filename,
                content_type=upload.content_type,
                data=data,
                now=request.app.state.clock(),
            )
    except BrandingImageError as exc:
        return _error(request, 422, f"{exc} {UNCHANGED}")
    except (BrandingStorageUnavailable, SQLAlchemyError):
        return _error(request, 503, f"{STORE_FAILED} {UNCHANGED}")
    response = RedirectResponse("/settings?tab=branding", status_code=303)
    _set_draft_cookie(response, staged.token)
    return response


def _error_missing(request: Request) -> Response:
    _clear_session_draft(request)
    return _error(request, 422, f"{MISSING} {UNCHANGED}")


def _handle_save(request: Request, form) -> Response:
    token, base_revision = form.get("draft_token"), form.get("base_revision")
    if not isinstance(token, str) or not token or not isinstance(base_revision, str) or not base_revision:
        return _error(request, 410, EXPIRED)
    try:
        with request.app.state.factory.begin() as db:
            save_draft(
                db,
                session_id=request.state.session.id,
                token=token,
                base_revision=base_revision,
                actor=_actor(request),
                now=request.app.state.clock(),
            )
    except (BrandingDraftNotFound, BrandingDraftExpired):
        return _error(request, 410, EXPIRED)
    except BrandingRevisionMismatch:
        return _error(request, 409, CONFLICT, conflict=True)
    except SQLAlchemyError:
        return _error(request, 503, SAVE_FAILED)
    response = RedirectResponse("/settings?tab=branding", status_code=303)
    set_flash(response, request.app.state.settings.session_secret, [SAVED])
    return apply_draft_cookie(request, response)


def _handle_discard(request: Request, form) -> Response:
    token = form.get("draft_token")
    if isinstance(token, str) and token:
        with request.app.state.factory.begin() as db:
            discard_draft(
                db, session_id=request.state.session.id, token=token, now=request.app.state.clock()
            )
    response = RedirectResponse("/settings?tab=branding", status_code=303)
    set_flash(response, request.app.state.settings.session_secret, [DISCARDED])
    request.state.branding_draft_token = None
    return apply_draft_cookie(request, response)


def _handle_reset(request: Request, form) -> Response:
    if form.get("confirm") != "RESET":
        return _error(request, 422, RESET_CONFIRMATION, field=None)
    base_revision = form.get("base_revision")
    if not isinstance(base_revision, str) or not base_revision:
        return _error(request, 409, CONFLICT, field=None, conflict=True)
    try:
        with request.app.state.factory.begin() as db:
            reset_branding(
                db,
                session_id=request.state.session.id,
                base_revision=base_revision,
                actor=_actor(request),
                now=request.app.state.clock(),
            )
    except BrandingRevisionMismatch:
        return _error(request, 409, CONFLICT, field=None, conflict=True)
    except SQLAlchemyError:
        return _error(request, 503, RESET_FAILED, field=None)
    response = RedirectResponse("/settings?tab=branding", status_code=303)
    set_flash(response, request.app.state.settings.session_secret, [RESTORED])
    request.state.branding_draft_token = None
    return apply_draft_cookie(request, response)


async def _submit(request: Request, handler, *, max_files: int = 0):
    # The route already bounded the request; accept anything inside that bound so the file-size
    # refusal keeps its exact 413 copy instead of collapsing into a generic multipart 400.
    form = await request.form(
        max_files=max_files, max_fields=20, max_part_size=MAX_REQUEST_BYTES
    )
    try:
        return await run_in_threadpool(handler, request, form)
    finally:
        await form.close()


async def _preview_submit(request: Request):
    if not request_within_limit(request.headers.get("content-length")):
        return await run_in_threadpool(_too_large, request)
    try:
        return await _submit(request, _handle_preview, max_files=1)
    except (MultiPartException, HTTPException) as exc:
        if isinstance(exc, HTTPException) and exc.status_code != 400:
            raise
        # Starlette turns an over-limit part into a 400; for this form it is the size refusal.
        return await run_in_threadpool(_too_large, request)


def register_branding_routes(app: FastAPI) -> None:
    @app.get("/branding/logo")
    def branding_logo(request: Request):
        try:
            with request.app.state.factory() as db:
                asset = current_asset(db)
        except Exception:  # noqa: BLE001 - a broken logo must never break sign-in.
            return _default_logo()
        if not readable_asset(asset):
            return _default_logo()
        assert asset is not None
        svg = asset.mime == SVG_MIME
        headers = {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": _SVG_DISPOSITION if svg else _PNG_DISPOSITION,
        }
        if svg:
            headers["Content-Security-Policy"] = SVG_CSP
        # A mismatched ``v`` is intentionally irrelevant: only the current bytes exist.
        return Response(content=asset.content, media_type=asset.mime, headers=headers)

    # Literal paths first: ``/settings/branding…`` must win over ``/settings/{tab}``.
    @app.get("/settings/branding/draft/{draft_token}")
    def branding_draft_image(request: Request, draft_token: str):
        try:
            with request.app.state.factory.begin() as db:
                staged, data = draft_image(
                    db,
                    session_id=request.state.session.id,
                    token=draft_token,
                    now=request.app.state.clock(),
                )
        except BrandingDraftExpired:
            raise HTTPException(410) from None
        except BrandingDraftNotFound:
            raise HTTPException(404) from None
        svg = staged.mime == SVG_MIME
        headers = {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": _SVG_DISPOSITION if svg else _PNG_DISPOSITION,
        }
        if svg:
            headers["Content-Security-Policy"] = SVG_CSP
        return Response(content=data, media_type=staged.mime, headers=headers)

    @app.post("/settings/branding/preview")
    async def branding_preview_submit(request: Request):
        return await _preview_submit(request)

    @app.post("/settings/branding")
    async def branding_save_submit(request: Request):
        return await _submit(request, _handle_save)

    @app.post("/settings/branding/discard")
    async def branding_discard_submit(request: Request):
        return await _submit(request, _handle_discard)

    @app.post("/settings/branding/reset")
    async def branding_reset_submit(request: Request):
        return await _submit(request, _handle_reset)
