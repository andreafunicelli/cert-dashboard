"""Public logo serving (``docs/ux-spec.md`` A2-D4).

``/branding/logo`` is the only new public path: the sign-in page needs the current logo before a
session exists. It serves only sanitized bytes from the singleton asset row; drafts, arbitrary
paths, database errors and uploaded originals are never reachable here. A missing, unreadable or
corrupt row falls back to the first-party mark without exposing an error or breaking sign-in.
"""

import hashlib

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response

from app.services.branding import current_asset
from app.services.branding_image import MAX_DIMENSION, MAX_FILE_BYTES, PNG_MIME, SVG_MIME

DEFAULT_LOGO_PATH = "/static/branding/mark.svg"
SVG_CSP = "default-src 'none'; style-src 'none'; script-src 'none'; sandbox"
_PNG_DISPOSITION = 'inline; filename="logo.png"'
_SVG_DISPOSITION = 'inline; filename="logo.svg"'


def _default_logo() -> RedirectResponse:
    return RedirectResponse(DEFAULT_LOGO_PATH, status_code=307)


def _readable(asset) -> bool:
    """Only a complete, self-consistent, canonical stored row is served."""
    return (
        asset is not None
        and asset.mime in {SVG_MIME, PNG_MIME}
        and 0 < len(asset.content) <= MAX_FILE_BYTES
        and 1 <= asset.width <= MAX_DIMENSION
        and 1 <= asset.height <= MAX_DIMENSION
        and hashlib.sha256(asset.content).hexdigest() == asset.revision
    )


def register_branding_routes(app: FastAPI) -> None:
    @app.get("/branding/logo")
    def branding_logo(request: Request):
        try:
            with request.app.state.factory() as db:
                asset = current_asset(db)
        except Exception:  # noqa: BLE001 - a broken logo must never break sign-in.
            return _default_logo()
        if not _readable(asset):
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
