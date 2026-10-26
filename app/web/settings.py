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
name (``smtp_password`` included) refuses the whole post with 422 and writes nothing.

Part B adds the three remaining tabs and their actions (every POST is CSRF-protected, audited and 303s
back to the tab; refusals are 422 and change nothing)::

    trust        POST /settings/trust                          include_public_bundle (toggle + recheck)
                 POST /settings/trust-anchors                  file | pem, notes   (add_anchor + recheck)
                 POST /settings/trust-anchors/{id}/delete      confirm=DELETE      (remove_anchor + recheck)
                 POST /settings/trust-anchors/recheck          (no fields)         (enqueue scan/trust_recheck)
    status       read-only ``status_snapshot``
    maintenance  POST /settings/maintenance/prune              confirm=PRUNE OLD JOBS (enqueue cleanup)
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from importlib.metadata import version as package_version

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.datastructures import FormData, UploadFile

from app.crypto.parse import MAX_INPUT_BYTES
from app.jobs.handlers import build_registry
from app.jobs.handlers.trust_recheck import TRUST_RECHECK_ACTION
from app.jobs.queue import enqueue
from app.models import Certificate, JSONValue, TrustAnchor, User
from app.models.enums import JobType
from app.services.audit import record
from app.services.scans import ON_DEMAND_PRIORITY
from app.services.settings import (
    SettingsValidationError,
    get_setting,
    is_valid_setting,
    status_snapshot,
    update_settings,
)
from app.services.trust_anchors import (
    AnchorValidationError,
    add_anchor,
    public_bundle_anchors,
    recheck_chain_statuses,
    remove_anchor,
)
from app.web.common import (
    _render,
    _transact,
    display_timezone,
    install_template_helpers,
    render_block,
    set_flash,
    unsupported_reason,
)

_MAX_FIELD = 20_000
_MAX_NOTES = 1_000
_INTEGER = re.compile(r"[+-]?[0-9]{1,9}")
_TRUE, _FALSE = frozenset({"true", "on", "1"}), frozenset({"false", "off", "0"})
_DELETE_CONFIRMATION = "DELETE"
_PRUNE_CONFIRMATION = "PRUNE OLD JOBS"
_PRUNE_PRIORITY = 10
_UNRECOGNISED = "Unrecognised fields were submitted; nothing was saved."


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
    reasons = {
        "test_email": unsupported_reason(
            registry, "Plan 2", (JobType.ALERT_EXPIRY, "default"), (JobType.DIGEST, "default")
        ),
        "test_pull": unsupported_reason(registry, "Plan 3", (JobType.DISCOVER, "default")),
        "trust_recheck": unsupported_reason(registry, "Plan 2", (JobType.SCAN, TRUST_RECHECK_ACTION)),
    }
    return {key: reason for key, reason in reasons.items() if reason}


_WARNINGS = {
    "smtp_not_configured": "SMTP is not configured: alert and digest e-mails cannot be sent.",
    "inventory_not_configured": "No inventory repository is configured: discovery cannot run.",
    "no_alert_recipients": "No alert recipients are set and some active certificates have no owner e-mail.",
    "missing_key_versions": "Stored key material refers to master-key versions that are not in the keyring.",
    "worker_stale": "The worker has not sent a heartbeat for more than 5 minutes.",
}


def _human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def _when(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def _trust_context(db: Session) -> dict:
    rows = db.execute(
        select(TrustAnchor, User.username)
        .outerjoin(User, User.id == TrustAnchor.created_by)
        .order_by(TrustAnchor.id)
    ).all()
    anchors = [
        {
            "id": anchor.id,
            "subject": anchor.subject,
            "fingerprint": anchor.sha256_fingerprint,
            "source": getattr(anchor.source, "value", anchor.source),
            "notes": anchor.notes or "",
            "created_at": anchor.created_at,
            "created_by": username or "—",
        }
        for anchor, username in rows
    ]
    return {
        "anchors": anchors,
        "bundle": {
            "version": package_version("certifi"),
            "roots": len(public_bundle_anchors()),
            "enabled": get_setting(db, "trust.include_public_bundle") is not False,
        },
        "timezone": display_timezone(db),
        "max_notes": _MAX_NOTES,
    }


def _status_context(request: Request, db: Session) -> dict:
    settings = request.app.state.settings
    snapshot = status_snapshot(
        db, settings.keyring, request.app.state.clock(), keyring_sha256=settings.keyring_sha256
    )
    return {
        "snapshot": snapshot,
        "warning_text": _WARNINGS,
        "db_size": _human_bytes(snapshot["db_size_bytes"]),
        "timezone": display_timezone(db),
        "when": _when,
        "next_version": max(settings.keyring.keys) + 1,
        "prune_confirmation": _PRUNE_CONFIRMATION,
    }


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
        "fields": _TAB_FIELDS.get(tab, ()),
        "errors": errors or {},
        "saved": request.query_params.get("saved") == "1" and status == 200,
        "csrf_token": request.state.session.csrf_token,
        "disabled": _capabilities(),
        "values": {},
        "tls_unsafe": False,
    }
    with request.app.state.factory() as db:
        if tab in _TAB_FIELDS:
            context["values"] = _current_values(db, tab) | dict(values or {})
            context["tls_unsafe"] = tab == "smtp" and get_setting(db, "smtp.tls_verify") is False
        elif tab == "trust":
            context.update(_trust_context(db))
        else:  # status and maintenance both render the snapshot (maintenance shows the keyring state)
            context.update(_status_context(request, db))
    if status == 422 and _is_htmx(request):
        return render_block(request, "settings.html.j2", "panel", status, **context)
    return _render(request, "settings.html.j2", status, **context)


def _refuse(request: Request, tab: str, form: FormData, errors: dict[str, list[str]]):
    """422 re-render with the submitted values of the tab's own fields (never anything else)."""
    values: dict[str, JSONValue] = {}
    for field in _TAB_FIELDS[tab]:
        if field.name not in form:
            continue
        raw = form.getlist(field.name)[-1]
        if not isinstance(raw, str):
            continue
        value = _submitted(field, raw[:_MAX_FIELD])
        if field.key == "inventory.repo_url" and not is_valid_setting(field.key, value):
            continue  # unvalidated/rejected: it may carry a credential, so show the stored value instead
        values[field.name] = value
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
        errors["form"] = [_UNRECOGNISED]
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


# --- part B: trust anchors, maintenance --------------------------------------------------------------


def _refused(request: Request, tab: str, *messages: str):
    return _page(request, tab, 422, errors={"form": list(messages)})


def _done(request: Request, tab: str, *notes: str) -> RedirectResponse:
    response = RedirectResponse(f"/settings?tab={tab}", status_code=303)
    set_flash(response, request.app.state.settings.session_secret, notes)
    return response


def _chain_summary(db: Session) -> str:
    """The stored chain statuses after a synchronous recheck, e.g. ``trusted 3, untrusted_root 1``."""
    counts = {
        getattr(status, "value", status): count
        for status, count in db.execute(
            select(Certificate.chain_status, func.count()).group_by(Certificate.chain_status)
        )
    }
    return ", ".join(f"{status} {counts[status]}" for status in sorted(counts)) or "no certificates"


def _recheck_note(summary: str) -> str:
    return f"Chain statuses rechecked: {summary}"


def _only(form: FormData, *names: str) -> bool:
    """True when the post carries nothing but ``names`` (and the CSRF token)."""
    return all(name == "csrf_token" or name in names for name in form)


def _handle_trust_toggle(request: Request, form: FormData):
    if not _only(form, "include_public_bundle"):
        return _refused(request, "trust", _UNRECOGNISED)
    raw = form.getlist("include_public_bundle")
    value = raw[-1].strip().lower() if raw and isinstance(raw[-1], str) else ""
    if value not in _TRUE | _FALSE:
        return _refused(request, "trust", "Public bundle: choose true or false.")
    enabled = value in _TRUE

    def work(db, now, actor):
        update_settings(db, {"trust.include_public_bundle": enabled}, actor)
        recheck_chain_statuses(db, now)  # same transaction: the setting and the statuses never disagree
        return _chain_summary(db)

    summary, _ = _transact(request, work)
    state = "included" if enabled else "excluded"
    return _done(request, "trust", f"Public CA bundle {state}.", _recheck_note(summary))


def _read_pem(form: FormData) -> bytes:
    """The uploaded file if one was chosen, else the pasted text; never more than cap + 1 bytes."""
    upload = form.get("file")
    if isinstance(upload, UploadFile) and upload.filename:
        data = upload.file.read(MAX_INPUT_BYTES + 1)
        if data:
            return data
    text = form.get("pem")
    if isinstance(text, str) and text.strip():
        return text.encode("utf-8")[: MAX_INPUT_BYTES + 1]
    return b""


def _handle_anchor_upload(request: Request, form: FormData):
    if not _only(form, "file", "pem", "notes"):
        return _refused(request, "trust", _UNRECOGNISED)
    raw_notes = form.get("notes")
    notes = raw_notes.strip() if isinstance(raw_notes, str) else ""
    if len(notes) > _MAX_NOTES:
        return _refused(request, "trust", f"Notes must be at most {_MAX_NOTES:,} characters.")
    pem = _read_pem(form)
    if not pem:
        return _refused(request, "trust", "Choose a PEM file or paste one PEM certificate.")

    def work(db, now, actor):
        add_anchor(db, pem, notes or None, actor, now)
        return _chain_summary(db)

    try:
        summary, _ = _transact(request, work)
    except AnchorValidationError as exc:
        return _refused(request, "trust", str(exc))
    return _done(request, "trust", "Trust anchor added.", _recheck_note(summary))


def _handle_anchor_delete(request: Request, anchor_id: int, form: FormData):
    confirm = form.get("confirm")
    if not _only(form, "confirm") or confirm != _DELETE_CONFIRMATION:
        return _refused(request, "trust", f"Type {_DELETE_CONFIRMATION} to confirm removing the trust anchor.")

    def work(db, now, actor):
        remove_anchor(db, anchor_id, actor, now)
        return _chain_summary(db)

    try:
        summary, _ = _transact(request, work)
    except AnchorValidationError:
        raise HTTPException(404) from None
    return _done(request, "trust", "Trust anchor removed.", _recheck_note(summary))


def _handle_trust_recheck(request: Request, form: FormData):
    """Queue the background recheck; the web process never evaluates chains for this button."""
    if not _only(form):
        return _refused(request, "trust", _UNRECOGNISED)

    def work(db, now, actor):
        # max_attempts=2: the recheck is idempotent, so one retry after a transient failure is safe.
        enqueue(
            db,
            JobType.SCAN,
            {"action": TRUST_RECHECK_ACTION},
            actor,
            priority=ON_DEMAND_PRIORITY,
            run_after=now,
            max_attempts=2,
        )

    _transact(request, work)
    return _done(request, "trust", "Trust recheck queued; chain statuses update once the worker has run it.")


def _handle_prune(request: Request, form: FormData):
    if not _only(form, "confirm") or form.get("confirm") != _PRUNE_CONFIRMATION:
        return _refused(request, "maintenance", f"Type {_PRUNE_CONFIRMATION} exactly to confirm.")

    def work(db, now, actor):
        # max_attempts is capped at 2 for cleanup jobs by the shared retry policy.
        enqueue(
            db,
            JobType.CLEANUP,
            {"reason": "manual_prune"},
            actor,
            priority=_PRUNE_PRIORITY,
            run_after=now,
            max_attempts=2,
        )
        record(db, actor, "maintenance.prune_requested", "maintenance", None, {"reason": "manual_prune"})

    _transact(request, work)
    return _done(request, "maintenance", "Retention cleanup queued; audit rows are never removed.")


async def _submit(request: Request, handler, *args, max_files: int = 0):
    form = await request.form(max_files=max_files, max_fields=20, max_part_size=MAX_INPUT_BYTES * 2)
    try:
        return await run_in_threadpool(handler, request, *args, form)
    finally:
        await form.close()


def register_settings_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/settings")
    def settings_page(request: Request, tab: str = "smtp") -> HTMLResponse:
        if tab not in _TAB_LABELS:
            raise HTTPException(404)
        return _page(request, tab)

    # Literal paths first: ``/settings/trust`` and ``/settings/trust-anchors`` would otherwise match
    # the generic ``/settings/{tab}`` route below.
    @app.post("/settings/trust")
    async def trust_toggle_submit(request: Request):
        return await _submit(request, _handle_trust_toggle)

    @app.post("/settings/trust-anchors")
    async def trust_anchor_upload_submit(request: Request):
        return await _submit(request, _handle_anchor_upload, max_files=1)

    @app.post("/settings/trust-anchors/recheck")
    async def trust_recheck_submit(request: Request):
        return await _submit(request, _handle_trust_recheck)

    @app.post("/settings/trust-anchors/{anchor_id:int}/delete")
    async def trust_anchor_delete_submit(request: Request, anchor_id: int):
        return await _submit(request, _handle_anchor_delete, anchor_id)

    @app.post("/settings/maintenance/prune")
    async def maintenance_prune_submit(request: Request):
        return await _submit(request, _handle_prune)

    @app.post("/settings/{tab}")
    async def settings_submit(request: Request, tab: str):
        if tab not in _TAB_FIELDS:
            raise HTTPException(404)
        form = await request.form(max_files=0, max_fields=50, max_part_size=_MAX_FIELD * 2)
        try:
            return await run_in_threadpool(_handle_post, request, tab, form)
        finally:
            await form.close()
