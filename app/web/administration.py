"""Administration hub (``GET /administration``) and the shell template globals (UX spec §2.3, §5.5, §5.6).

The hub is a read-only page: every entry is a link to the screen that edits the value, plus one status
line computed server-side from the existing read models. The page has no form and stores nothing.

This module also owns the two values the shared shell needs:

``htmx_config``
    One JSON document for the single ``<meta name="htmx-config">`` that ``base.html.j2`` emits first in
    ``<head>``. It is the rule list of ``app/web/management.py`` (imported, never copied) extended with
    the same ``#main-content`` swap for 404, 500 and 503, so a CSRF refusal, a missing page and a
    server error are announced on every page instead of only on Slice B screens (UX-08).

``brand``
    The default logo URLs, re-exported from ``app.web.branding``. A2b's resolver returns the custom
    asset behind the same keys when one is saved; the templates only ever read the keys.

``app/web/users.py`` keeps ``/users`` only: the hub handler moved here with the navigation rebuild
(the single A1 edit to that Slice B file).

Security: values read from the database are HTML-escaped here, and repository credentials never reach
the page — only a redacted origin is shown.
"""

import html
import json
from urllib.parse import urlsplit, urlunsplit

from fastapi import FastAPI, Request
from markupsafe import Markup
from sqlalchemy import func, select

from app.jobs.worker import worker_capabilities
from app.models import SshHostKey, TrustAnchor, User
from app.services.branding import current_asset
from app.services.settings import get_setting, status_snapshot
from app.services.setup_status import setup_status
from app.services.worker_credentials import (
    INVENTORY_GIT_TOKEN,
    SSH_PRIVATE_KEY,
    VAULT_PASSWORD,
    credential_states,
)
from app.web.branding import DEFAULT_BRAND, readable_asset
from app.web.common import _render, install_template_helpers
from app.web.management import _HTMX_CONFIG

# The management rules keep their order; 204, [23].., 422 and 403 already mean the same everywhere.
# 404/500/503 get the 403 treatment: swap the error page into the main region so it is visible.
_RULES = list(_HTMX_CONFIG["responseHandling"])
_LAST_RULE = _RULES.pop()  # "[45].." stays the catch-all after the explicit codes.
HTMX_CONFIG = {
    "responseHandling": _RULES
    + [
        {
            "code": code,
            "swap": True,
            "error": True,
            "target": "#main-content",
            "select": "#main-content",
            "swapOverride": "outerHTML",
        }
        for code in ("404", "500", "503")
    ]
    + [_LAST_RULE]
}

HTMX_CONFIG_JSON = json.dumps(HTMX_CONFIG, separators=(",", ":"))


def _text(value: object) -> Markup:
    return Markup(html.escape(str(value)))


def _link(label: str, href: str) -> Markup:
    return Markup(f'<a href="{html.escape(href, quote=True)}">{html.escape(label)}</a>')


def _status(*parts: object) -> Markup:
    """Join escaped text and trusted fragments without escaping either twice."""
    return Markup("").join(part if isinstance(part, Markup) else _text(part) for part in parts)


def _redacted_repository(url: str, ref: object) -> str:
    """``<origin and path> @ <ref>``; userinfo, query and fragment never reach the page."""
    parts = urlsplit(url)
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    origin = urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    return f"{origin} @ {ref}"


def _credential_lines(states) -> str:
    ssh = states[SSH_PRIVATE_KEY]
    if ssh.configured and ssh.key_type:
        detail = f"configured ({ssh.key_type}"
        if ssh.fingerprint_sha256:
            detail += f", {ssh.fingerprint_sha256}"
        detail += ")"
    else:
        detail = "configured" if ssh.configured else "missing"
    vault = "set" if states[VAULT_PASSWORD].configured else "not set"
    token = "set" if states[INVENTORY_GIT_TOKEN].configured else "not set"
    return f"SSH key: {detail} · Vault password: {vault} · Git token: {token}"


def _as_list(value: object) -> list[object]:
    """A list-valued setting; anything else is treated as unset."""
    return list(value) if isinstance(value, list) else []


def _status_line(warning_count: int) -> str:
    return f"{warning_count} warning" if warning_count == 1 else f"{warning_count} warnings"


def _hub_context(request: Request) -> dict:
    app = request.app
    now = app.state.clock()
    with app.state.factory() as db:
        setup = setup_status(db, now)
        capabilities = worker_capabilities(db, now)
        active_users, inactive_users = db.execute(
            select(
                func.count().filter(User.is_active.is_(True)),
                func.count().filter(User.is_active.is_(False)),
            )
        ).one()
        current = db.get(User, request.state.session.user_id)
        trusted_host_keys = db.scalar(select(func.count()).select_from(SshHostKey)) or 0
        anchors = db.scalar(select(func.count()).select_from(TrustAnchor)) or 0
        credentials = credential_states(db, app.state.settings, worker=capabilities)
        repository = get_setting(db, "inventory.repo_url")
        repository_ref = get_setting(db, "inventory.ref") or "HEAD"
        smtp_configured = bool(get_setting(db, "smtp.host"))
        thresholds = _as_list(get_setting(db, "alert.thresholds_days"))
        recipients = _as_list(get_setting(db, "alert.recipients"))
        public_bundle = get_setting(db, "trust.include_public_bundle") is not False
        snapshot = status_snapshot(
            db, app.state.settings.keyring, now, keyring_sha256=app.state.settings.keyring_sha256
        )
        retention_days = get_setting(db, "retention.days")
        deploy_batch = get_setting(db, "deploy.batch_percent")
        deploy_concurrency = get_setting(db, "deploy.concurrency")
        deploy_canary = get_setting(db, "deploy.pause_after_canary")
        nightly_discovery = get_setting(db, "discovery.nightly_at")
        scan_timeout = get_setting(db, "scan.timeout_seconds")
        branding_status = "Custom logo" if readable_asset(current_asset(db)) else "Default logo"

    if setup.hosts:
        host_status = _status(
            f"{setup.host_counts[0]} active hosts ({setup.host_counts[1]} manual, "
            f"{setup.host_counts[2]} repository)"
        )
    else:
        host_status = _status("No hosts yet · ", _link("Add a host", "/inventory"))
    mounted = "unknown" if capabilities is None else ("present" if capabilities.known_hosts_present else "absent")
    repository_status = (
        "Not configured — optional"
        if not repository
        else _redacted_repository(str(repository), repository_ref)
    )
    groups = [
        {
            "name": "People and access",
            "entries": [
                {
                    "label": "Users",
                    "href": "/users",
                    "status": _status(
                        f"{active_users} active users · {inactive_users} inactive"
                    ),
                },
                {
                    "label": "My account",
                    "href": "/account",
                    "status": "Two-factor authentication " + ("on" if current is not None and current.totp_enabled else "off"),
                },
            ],
        },
        {
            "name": "Servers and access",
            "entries": [
                {"label": "Inventory hosts", "href": "/inventory", "status": host_status},
                {
                    "label": "Inventory repository (optional)",
                    "href": "/settings?tab=inventory",
                    "status": repository_status,
                },
                {
                    "label": "Worker credentials",
                    "href": "/settings?tab=worker",
                    "status": _credential_lines(credentials),
                },
                {
                    "label": "SSH host keys",
                    "href": "/ssh-keys",
                    "status": f"{trusted_host_keys} trusted in the dashboard · Mounted known_hosts: {mounted}",
                },
            ],
        },
        {
            "name": "Alerts and email",
            "entries": [
                {
                    "label": "SMTP",
                    "href": "/settings?tab=smtp",
                    "status": "Configured" if smtp_configured else "Not configured",
                },
                {
                    "label": "Alerts",
                    "href": "/settings?tab=alerts",
                    "status": "Thresholds: "
                    + ", ".join(str(item) for item in thresholds)
                    + " days · "
                    + (f"{len(recipients)} recipient" + ("" if len(recipients) == 1 else "s") if recipients else "No recipients"),
                },
            ],
        },
        {
            "name": "Operations policy",
            "entries": [
                {
                    "label": "Deployment",
                    "href": "/settings?tab=deployment",
                    "status": f"Batch {deploy_batch}% · concurrency {deploy_concurrency} · canary pause {'on' if deploy_canary else 'off'}",
                },
                {
                    "label": "Schedule and scans",
                    "href": "/settings?tab=schedule",
                    "status": f"Nightly discovery {nightly_discovery} · scan timeout {scan_timeout} s",
                },
                {
                    "label": "Trust anchors",
                    "href": "/settings?tab=trust",
                    "status": f"{anchors} uploaded roots · public bundle {'included' if public_bundle else 'excluded'}",
                },
            ],
        },
        {
            "name": "System",
            "entries": [
                {
                    "label": "Status",
                    "href": "/settings?tab=status",
                    "status": _status_line(
                        len(snapshot["warnings"]) if isinstance(snapshot["warnings"], list) else 0
                    ),
                },
                {
                    "label": "System and maintenance",
                    "href": "/settings?tab=maintenance",
                    "status": f"Job retention: {retention_days} days",
                },
                {
                    "label": "Branding",
                    "href": "/settings?tab=branding",
                    "status": branding_status,
                },
                {"label": "Audit", "href": "/audit", "status": "Append-only record of actions"},
            ],
        },
    ]
    return {"setup": setup, "groups": groups}


def register_administration_routes(app: FastAPI) -> None:
    install_template_helpers(app)
    env = app.state.templates.env
    env.globals.setdefault("htmx_config", Markup(HTMX_CONFIG_JSON))
    env.globals.setdefault("brand", DEFAULT_BRAND)

    @app.get("/administration")
    def administration_page(request: Request):
        return _render(request, "administration.html.j2", **_hub_context(request))
