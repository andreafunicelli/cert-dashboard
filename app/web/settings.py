"""Settings page (``/settings``, Task 23 part A): the seven configuration tabs.

Each tab posts short field names that map onto typed ``app_setting`` keys (the allowlist and all value
validation live in ``app.services.settings``; this module only parses form text into JSON values).

Field map per tab (form field -> setting key)::

    smtp        host smtp.host, port smtp.port, security smtp.security, from smtp.from,
                username smtp.username, tls_verify smtp.tls_verify
    alerts      thresholds_days alert.thresholds_days (comma separated),
                recipients alert.recipients (one per line),
                digest_enabled alert.digest_enabled, expiry_check_enabled expiry_check.enabled
    inventory   repo_url inventory.repo_url, ref inventory.ref, path inventory.path,
                webserver_var inventory.webserver_var
    deployment  batch_percent deploy.batch_percent, concurrency deploy.concurrency,
                pause_after_canary deploy.pause_after_canary,
                pause_timeout_hours deploy.pause_timeout_hours,
                backup_retention_days deploy.backup_retention_days,
                host_timeout_seconds deploy.host_timeout_seconds
    scanning    timeout_seconds scan.timeout_seconds, daily_at scan.daily_at, enabled scan.enabled
    schedule    discovery_nightly_at discovery.nightly_at, discovery_enabled discovery.enabled,
                expiry_check_daily_at expiry_check.daily_at, digest_daily_at digest.daily_at,
                cleanup_daily_at cleanup.daily_at, cleanup_enabled cleanup.enabled
    general     timezone ui.timezone, retention_days retention.days

POST semantics are PATCH: only submitted fields change. Booleans are rendered as a hidden ``false``
plus a checkbox ``true`` (the last value wins) and are optional for API-style posts. Any other field
name (``smtp_password`` included) refuses the whole post with 422 and writes nothing. ``trust.*``,
Status and Maintenance belong to part B and render a placeholder until then.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from starlette.datastructures import FormData

from app.jobs.handlers import build_registry
from app.models import JSONValue
from app.models.enums import JobType
from app.services.settings import SettingsValidationError, get_setting, update_settings
from app.web.common import _render, _transact, install_template_helpers, render_block

_MAX_FIELD = 20_000
_INTEGER = re.compile(r"[+-]?[0-9]{1,9}")
_TRUE, _FALSE = frozenset({"true", "on", "1"}), frozenset({"false", "off", "0"})


@dataclass(frozen=True)
class _Field:
    name: str
    key: str
    kind: str  # text | int | int? | bool | ints | lines
    label: str
    widget: str = "text"  # text | select | textarea | checkbox
    hint: str = ""
    choices: tuple[tuple[str, str], ...] = ()
    placeholder: str = ""


_TIME_HINT = "UTC, HH:MM (00:00–23:59)"

_SMTP = (
    _Field("host", "smtp.host", "text", "Host", hint="Empty = SMTP not configured."),
    _Field("port", "smtp.port", "int?", "Port", hint="1–65535; empty = unset."),
    _Field(
        "security",
        "smtp.security",
        "text",
        "Security",
        "select",
        "Empty = SMTP not configured.",
        (("", "(not configured)"), ("starttls", "STARTTLS"), ("ssl", "SSL/TLS"), ("none", "None")),
    ),
    _Field("from", "smtp.from", "text", "From address"),
    _Field("username", "smtp.username", "text", "Username"),
    _Field("tls_verify", "smtp.tls_verify", "bool", "Verify the SMTP server's TLS certificate", "checkbox"),
)
_ALERTS = (
    _Field(
        "thresholds_days",
        "alert.thresholds_days",
        "ints",
        "Alert thresholds (days before expiry)",
        hint="1–10 distinct whole numbers, 0–365, comma separated.",
    ),
    _Field("recipients", "alert.recipients", "lines", "Recipients", "textarea", "One email address per line (at most 50)."),
    _Field("digest_enabled", "alert.digest_enabled", "bool", "Send the daily digest", "checkbox"),
    _Field("expiry_check_enabled", "expiry_check.enabled", "bool", "Run the daily expiry check", "checkbox"),
)
_INVENTORY = (
    _Field(
        "repo_url",
        "inventory.repo_url",
        "text",
        "Repository URL",
        hint="https://host/path, ssh://[user@]host/path or user@host:path. No passwords or tokens.",
    ),
    _Field("ref", "inventory.ref", "text", "Ref (branch, tag or commit)", hint="Empty = the remote default."),
    _Field("path", "inventory.path", "text", "Path inside the repository", hint="Relative, no '..'; empty = the root."),
    _Field("webserver_var", "inventory.webserver_var", "text", "Web server variable name"),
)
_DEPLOYMENT = (
    _Field("batch_percent", "deploy.batch_percent", "int", "Batch size (%)", hint="1–100."),
    _Field("concurrency", "deploy.concurrency", "int", "Concurrency", hint="1–50 hosts at a time."),
    _Field("pause_after_canary", "deploy.pause_after_canary", "bool", "Pause after the canary host", "checkbox"),
    _Field("pause_timeout_hours", "deploy.pause_timeout_hours", "int", "Pause timeout (hours)", hint="1–168."),
    _Field(
        "backup_retention_days",
        "deploy.backup_retention_days",
        "int",
        "Target backup retention (days)",
        hint="0–3650. 0 keeps backups on the targets forever.",
    ),
    _Field("host_timeout_seconds", "deploy.host_timeout_seconds", "int", "Per-host timeout (seconds)", hint="60–7200."),
)
_SCANNING = (
    _Field("timeout_seconds", "scan.timeout_seconds", "int", "Connection timeout (seconds)", hint="1–60."),
    _Field("daily_at", "scan.daily_at", "text", "Daily scan time", hint=_TIME_HINT, placeholder="HH:MM"),
    _Field("enabled", "scan.enabled", "bool", "Run the daily scan", "checkbox"),
)
_SCHEDULE = (
    _Field("discovery_nightly_at", "discovery.nightly_at", "text", "Nightly discovery", hint=_TIME_HINT, placeholder="HH:MM"),
    _Field("discovery_enabled", "discovery.enabled", "bool", "Run nightly discovery", "checkbox"),
    _Field("expiry_check_daily_at", "expiry_check.daily_at", "text", "Expiry check", hint=_TIME_HINT, placeholder="HH:MM"),
    _Field("digest_daily_at", "digest.daily_at", "text", "Daily digest", hint=_TIME_HINT, placeholder="HH:MM"),
    _Field("cleanup_daily_at", "cleanup.daily_at", "text", "Retention cleanup", hint=_TIME_HINT, placeholder="HH:MM"),
    _Field("cleanup_enabled", "cleanup.enabled", "bool", "Run the retention cleanup", "checkbox"),
)
_GENERAL = (
    _Field("timezone", "ui.timezone", "text", "Display time zone", hint="An IANA name such as Europe/Rome. Stored times stay UTC."),
    _Field("retention_days", "retention.days", "int", "Job retention (days)", hint="1–3650. Audit rows are never removed."),
)

_TAB_FIELDS: dict[str, tuple[_Field, ...]] = {
    "smtp": _SMTP,
    "alerts": _ALERTS,
    "inventory": _INVENTORY,
    "deployment": _DEPLOYMENT,
    "scanning": _SCANNING,
    "schedule": _SCHEDULE,
    "general": _GENERAL,
}
_TAB_LABELS = {
    "smtp": "SMTP",
    "alerts": "Alerts",
    "inventory": "Inventory",
    "deployment": "Deployment",
    "scanning": "Scanning",
    "schedule": "Schedule",
    "general": "General",
    "trust": "Trust anchors",
    "status": "Status",
    "maintenance": "Maintenance",
}
_PLACEHOLDER_TABS = frozenset({"trust", "status", "maintenance"})  # part B replaces these
_TAB_LINKS = [{"name": name, "label": label} for name, label in _TAB_LABELS.items()]


# --- form text -> JSON values ----------------------------------------------------------------------


def _parse(field: _Field, raw: str) -> JSONValue:
    """Raises ValueError(message) when the text cannot even be read as the field's type."""
    text = raw.strip()
    match field.kind:
        case "bool":
            lowered = text.lower()
            if lowered in _TRUE:
                return True
            if lowered in _FALSE:
                return False
            raise ValueError("must be true or false")
        case "int" | "int?":
            if text == "" and field.kind == "int?":
                return None
            if not _INTEGER.fullmatch(text):
                raise ValueError("must be a whole number")
            return int(text)
        case "ints":
            tokens = [token for token in re.split(r"[,\s]+", text) if token]
            if not all(_INTEGER.fullmatch(token) for token in tokens):
                raise ValueError("must be whole numbers separated by commas")
            return [int(token) for token in tokens]
        case "lines":
            return [line.strip() for line in raw.splitlines() if line.strip()]
        case _:
            return text


def _display(field: _Field, value: JSONValue) -> JSONValue:
    """A stored value as form text (booleans stay booleans)."""
    if field.kind == "ints":
        return ", ".join(str(item) for item in value)  # type: ignore[attr-defined]
    if field.kind == "lines":
        return "\n".join(value)  # type: ignore[arg-type]
    return "" if value is None else value


def _current_values(db: Session, tab: str) -> dict[str, JSONValue]:
    return {field.name: _display(field, get_setting(db, field.key)) for field in _TAB_FIELDS[tab]}


# --- rendering -------------------------------------------------------------------------------------


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request", "").lower() == "true"


def _capabilities() -> dict[str, str]:
    """Why a control is disabled: computed from what the worker registry can actually run."""
    registry = build_registry()
    reasons = {}
    if not (registry.supports(JobType.DIGEST) and registry.supports(JobType.ALERT_EXPIRY)):
        reasons["test_email"] = "requires the alert/digest handler (Plan 2)"
    if not registry.supports(JobType.DISCOVER):
        reasons["test_pull"] = "requires the discovery handler (Plan 3)"
    return reasons


def _page(
    request: Request,
    tab: str,
    status: int = 200,
    values: Mapping[str, JSONValue] | None = None,
    errors: Mapping[str, list[str]] | None = None,
):
    context: dict = {
        "tab": tab,
        "tab_label": _TAB_LABELS[tab],
        "tabs": _TAB_LINKS,
        "placeholder": tab in _PLACEHOLDER_TABS,
        "fields": _TAB_FIELDS.get(tab, ()),
        "errors": errors or {},
        "saved": request.query_params.get("saved") == "1" and status == 200,
        "csrf_token": request.state.session.csrf_token,
        "disabled": _capabilities(),
        "values": {},
        "tls_unsafe": False,
    }
    if tab not in _PLACEHOLDER_TABS:
        with request.app.state.factory() as db:
            context["values"] = _current_values(db, tab) | dict(values or {})
            context["tls_unsafe"] = tab == "smtp" and get_setting(db, "smtp.tls_verify") is False
    if status == 422 and _is_htmx(request):
        return render_block(request, "settings.html.j2", "panel", status, **context)
    return _render(request, "settings.html.j2", status, **context)


def _refuse(request: Request, tab: str, form: FormData, errors: dict[str, list[str]]):
    """422 re-render with the submitted values of the tab's own fields (never anything else)."""
    values: dict[str, JSONValue] = {}
    for field in _TAB_FIELDS[tab]:
        if field.name not in form or field.name in errors and field.key == "inventory.repo_url":
            continue  # a rejected repository URL may carry a credential: show the stored value instead
        raw = form.getlist(field.name)[-1]
        if isinstance(raw, str):
            values[field.name] = _submitted(field, raw[:_MAX_FIELD])
    return _page(request, tab, 422, values, errors)


def _submitted(field: _Field, raw: str) -> JSONValue:
    if field.kind == "bool":
        return raw.strip().lower() in _TRUE
    return raw


def _handle_post(request: Request, tab: str, form: FormData):
    fields = {field.name: field for field in _TAB_FIELDS[tab]}
    errors: dict[str, list[str]] = {}
    if any(name != "csrf_token" and name not in fields for name in form):
        # Never echo names or values: the post may carry a secret (e.g. smtp_password).
        errors["form"] = ["Unrecognised fields were submitted; nothing was saved."]
    changes: dict[str, JSONValue] = {}
    for name, field in fields.items():
        if name not in form:
            continue
        raw = form.getlist(name)[-1]
        if not isinstance(raw, str) or len(raw) > _MAX_FIELD:
            errors[name] = ["is not a valid value"]
            continue
        try:
            changes[field.key] = _parse(field, raw)
        except ValueError as exc:
            errors[name] = [str(exc)]
    if errors:
        return _refuse(request, tab, form, errors)

    def work(db, now, actor):
        update_settings(db, changes, actor)

    try:
        _transact(request, work)
    except SettingsValidationError as exc:
        by_key = {field.key: field.name for field in fields.values()}
        return _refuse(request, tab, form, {by_key.get(key, "form"): list(msgs) for key, msgs in exc.errors.items()})
    return RedirectResponse(f"/settings?tab={tab}&saved=1", status_code=303)


def register_settings_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/settings")
    def settings_page(request: Request, tab: str = "smtp") -> HTMLResponse:
        if tab not in _TAB_LABELS:
            raise HTTPException(404)
        return _page(request, tab)

    @app.post("/settings/{tab}")
    async def settings_submit(request: Request, tab: str):
        if tab not in _TAB_FIELDS:
            raise HTTPException(404)
        form = await request.form(max_files=0, max_fields=50, max_part_size=_MAX_FIELD * 2)
        try:
            return await run_in_threadpool(_handle_post, request, tab, form)
        finally:
            await form.close()
