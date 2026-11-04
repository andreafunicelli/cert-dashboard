"""Shared management-page conventions for Slice B (contract §8, C1–C10).

Feature modules import these helpers and never re-implement them:

- ``done()`` is the only success channel: native ``303`` or, for an htmx request, ``200`` +
  ``HX-Redirect``; both carry exactly one signed flash note rendered by the existing base banner.
- ``management_head()`` links the shared management stylesheet plus the page stylesheet and emits
  the ``htmx-config`` meta: 422 swaps refresh the targeted panel, 403 (a stale form rejected by the
  CSRF check) swaps into ``#main-content`` so the shared "Your form expired" text is visible.
- the Jinja partials in ``_management_ui.html.j2`` render error summaries, field errors, confirmation
  disclosures, empty states and source/state badges.

No route here answers with a redirect outside the dashboard (C10).
"""

import html
import json

from fastapi import Request
from fastapi.responses import RedirectResponse, Response
from markupsafe import Markup

from app.web.common import set_flash

# htmx 2 response handling. 4xx/5xx do not swap by default; a validation refusal (422) must swap the
# re-rendered panel, and a stale form (403 from the CSRF gate) must replace the whole main region.
_HTMX_CONFIG = {
    "responseHandling": [
        {"code": "204", "swap": False},
        {"code": "[23]..", "swap": True},
        {"code": "422", "swap": True, "error": True},
        {"code": "403", "swap": True, "error": True, "target": "#main-content"},
        {"code": "[45]..", "swap": False, "error": True},
    ]
}


def management_head(page_css: str | None = None) -> Markup:
    """Stylesheet links plus the htmx configuration for a management page (use in ``extra_css``)."""
    links = ['<link rel="stylesheet" href="/static/pages/management.css">']
    if page_css:
        links.append(f'<link rel="stylesheet" href="{html.escape(page_css, quote=True)}">')
    config = html.escape(json.dumps(_HTMX_CONFIG, separators=(",", ":")), quote=True)
    links.append(f'<meta name="htmx-config" content="{config}">')
    return Markup("".join(links))


def is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request", "").strip().lower() == "true"


def done(request: Request, location: str, note: str) -> Response:
    """Finish a successful mutation: one flash note, then the next full page at ``location``.

    Native forms get a ``303``; htmx prefers ``HX-Redirect`` with ``200`` so the browser performs a
    full navigation and the signed flash cookie is read by the existing base banner (C2).
    """
    if is_htmx(request):
        response = Response(status_code=200)
        response.headers["HX-Redirect"] = location
    else:
        response = RedirectResponse(location, status_code=303)
    set_flash(response, request.app.state.settings.session_secret, [note])
    return response


def install_management_helpers(app) -> None:
    """Expose ``management_head()`` to every template; safe to call from more than one area."""
    app.state.templates.env.globals.setdefault("management_head", management_head)
