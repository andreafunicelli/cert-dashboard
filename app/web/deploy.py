"""Deploy screens (spec §8.7): the start screen, its htmx preview, the live job screen and the JSON report.

Every route here only reads rows the worker already wrote; the web process never runs Ansible, git or SSH.
Operator controls delegate to ``app.services.deploy``, which owns the state machine, the audit rows and the
guardrails, so the screen cannot invent a transition: a refused control comes back as a 422 fragment (htmx)
or as the page itself (no JavaScript) with the reason inline.

The start screen is §6.6's preview plus §8.7's confirmation: the options are a plain GET form (so the whole
plan is bookmarkable and works without JavaScript), htmx only re-renders the preview fragment on a change, and
the enqueue POST echoes the previewed ``plan_sha256`` so a plan that changed under the operator is refused
with the new preview instead of starting a rollout nobody confirmed.
"""

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import or_, select
from starlette.concurrency import run_in_threadpool

from app.jobs.queue import InvalidJobState
from app.models import Binding, Server
from app.models.enums import JobType
from app.services.deploy import (
    DeployBlocked,
    DeployOptions,
    cancel_deploy,
    continue_deploy,
    preview_deploy,
    retry_host,
    start_deploy,
)
from app.services.deploy_views import (
    DeployCandidate,
    DeployJobNotFound,
    DeployJobSummary,
    DeployJobView,
    active_deploy,
    deploy_candidates,
    deploy_job_view,
    deploy_report,
)
from app.services.settings import get_setting
from app.web.common import (
    _render,
    _transact,
    ansible_unavailable_reason,
    display_timezone,
    install_template_helpers,
    set_flash,
    unsupported_reason,
)

_CONTROL_FIELDS = frozenset({"csrf_token"})
_RETRY_FIELDS = frozenset({"csrf_token", "reason", "override_reason"})
# Every field the start screen's forms may submit; anything else is a 422 (repo convention).
_START_FIELDS = frozenset(
    {
        "csrf_token",
        "certificate_id",
        "plan_sha256",
        "confirm",
        "override_reason",
        "group",
        "host",
        "binding_id",
        "selection",
        "include_unknown",
        "pause_after_canary",
        "batch_percent",
        "canary_server_id",
        "not_before",
    }
)
_START_MAX_FIELDS = 240  # 1 certificate + 1 plan hash + up to 200 explicitly selected bindings
_PLAN_SHA256 = re.compile(r"[0-9a-f]{64}")
_DEFAULT_BATCH_PERCENT = 10
_DEFAULT_PAUSE = True


def _view(request: Request, job_id: UUID) -> tuple[DeployJobView, str]:
    """One job's view under the request's clock; anything that is not a deploy job is a 404."""
    with request.app.state.factory() as db:
        try:
            view = deploy_job_view(db, job_id, request.app.state.clock())
        except DeployJobNotFound:
            raise HTTPException(404) from None
        return view, display_timezone(db)


def _hours_left(deadline: datetime | None, now: datetime) -> int:
    """Whole hours before the pause auto-cancels (``0`` means less than one hour)."""
    if deadline is None:
        return 0
    return max(0, int((deadline - now).total_seconds() // 3600))


def _text(value: object) -> str:
    """A submitted text field: stripped, and never anything but a string."""
    return value.strip() if isinstance(value, str) else ""


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request", "").lower() == "true"


def _context(request: Request, view: DeployJobView, timezone_name: str, errors: dict[str, str]) -> dict:
    return {
        "view": view,
        "tz": timezone_name,
        "hours_left": _hours_left(view.pause_deadline, request.app.state.clock()),
        "errors": errors,
        "csrf_token": request.state.session.csrf_token,
    }


def _job_page(request: Request, job_id: UUID, status: int = 200, errors: dict[str, str] | None = None):
    view, timezone_name = _view(request, job_id)
    return _render(request, "deploy/job.html.j2", status, **_context(request, view, timezone_name, errors or {}))


def _live(request: Request, job_id: UUID, status: int = 200, errors: dict[str, str] | None = None) -> HTMLResponse:
    """The live region alone: the page includes it, htmx polls it, and a refused control re-renders it."""
    view, timezone_name = _view(request, job_id)
    return _render(request, "deploy/_progress.html.j2", status, **_context(request, view, timezone_name, errors or {}))


def _refused(request: Request, job_id: UUID, errors: dict[str, str], status: int = 422) -> HTMLResponse:
    """A refused control: the live region for htmx, the whole page without JavaScript."""
    if _is_htmx(request):
        return _live(request, job_id, status, errors)
    return _job_page(request, job_id, status, errors)


def _redirect(request: Request, location: str, note: str) -> Response:
    """Success: a 303 for a browser, ``HX-Redirect`` for htmx, which cannot observe a 303 (repo convention)."""
    if _is_htmx(request):
        response: Response = Response(status_code=200, headers={"HX-Redirect": location})
    else:
        response = RedirectResponse(location, 303)
    set_flash(response, request.app.state.settings.session_secret, [note])
    return response


def _only(form, allowed: frozenset[str]) -> None:
    if set(form.keys()) - allowed:
        raise HTTPException(422)


def _run(request: Request, work):
    """Run one control in its transaction; the caller decides how a refusal is rendered."""
    result, _refusal = _transact(request, work)
    return result


# --- the start screen (§8.7, §6.6; Plan 3 Task 19) ------------------------------------------------


@dataclass(frozen=True)
class _Choice:
    """One binding the operator can tick or untick before the preview is computed."""

    binding_id: int
    hostname: str
    vhost_name: str
    port: int
    cert_path: str
    match_state: str
    checked: bool


def _int(value: object) -> int | None:
    """A submitted non-negative integer, or ``None`` (never anything else)."""
    text = _text(value)
    return int(text) if text.isdigit() else None


def _flag(params, name: str) -> bool:
    """A checkbox rendered as ``<input type="hidden" name=… value="0">`` plus ``value="1"`` when ticked."""
    return "1" in params.getlist(name)


def _tri_flag(params, name: str) -> bool | None:
    """A checkbox that may be absent: ``None`` means "use the configured default"."""
    values = params.getlist(name)
    return None if not values else "1" in values


def _not_before(value: object, timezone_name: str) -> tuple[datetime | None, str | None]:
    """``datetime-local`` in ``ui.timezone`` → UTC; ``None`` when the operator left it empty."""
    text = _text(value)
    if not text:
        return None, None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None, "not before must be a date and time, for example 2026-11-01T02:00"
    if parsed.tzinfo is None:
        try:
            parsed = parsed.replace(tzinfo=ZoneInfo(timezone_name))
        except (ZoneInfoNotFoundError, ValueError):
            parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC), None


def _options(params, timezone_name: str) -> tuple[DeployOptions | None, dict[str, str]]:
    """The ``DeployOptions`` a GET or POST asked for, plus the field errors to show instead."""
    errors: dict[str, str] = {}
    raw_certificate = params.get("certificate_id")
    certificate_id = _int(raw_certificate)
    if certificate_id is None and _text(raw_certificate):
        errors["certificate"] = "choose a certificate from the list"
    batch_percent = _int(params.get("batch_percent"))
    if _text(params.get("batch_percent")) and batch_percent is None:
        errors["batch_percent"] = "batch percent must be a whole number between 1 and 100"
    elif batch_percent is not None and not 1 <= batch_percent <= 100:
        errors["batch_percent"] = "batch percent must be between 1 and 100"
    canary_server_id = _int(params.get("canary_server_id"))
    if _text(params.get("canary_server_id")) and canary_server_id is None:
        errors["canary_server_id"] = "choose a canary server from the list"
    not_before, not_before_error = _not_before(params.get("not_before"), timezone_name)
    if not_before_error is not None:
        errors["not_before"] = not_before_error
    binding_ids = tuple(sorted({value for raw in params.getlist("binding_id") if (value := _int(raw))}))
    # The checkbox list belongs to one certificate; the form carries that id in ``selection_for``. A no-JS
    # Preview after changing the picker still submits the previous certificate's ticked ids: they must not
    # become an explicit selection of targets the operator never ticked (the page's htmx picker reloads the
    # server-rendered screen instead). A request without the marker — a bookmarkable URL or the confirmation
    # POST, which echoes the previewed ids — is trusted as is.
    selection_for = _int(params.get("selection_for"))
    scoped = selection_for is None or selection_for == certificate_id
    explicit = scoped and (_text(params.get("selection")) == "explicit" or bool(binding_ids))
    group, host = _text(params.get("group")), _text(params.get("host"))
    if certificate_id is None:
        return None, errors
    return (
        DeployOptions(
            certificate_id=certificate_id,
            # An explicit selection is exactly what the operator ticked: unticking everything is a plan with
            # no target (and its guardrail), never a silent fallback to the default target set.
            binding_ids=binding_ids if explicit else None,
            groups=(group,) if group else (),
            hostnames=(host,) if host else (),
            include_unknown=_flag(params, "include_unknown"),
            batch_percent=batch_percent,
            pause_after_canary=_tri_flag(params, "pause_after_canary"),
            canary_server_id=canary_server_id,
            not_before=not_before,
        ),
        errors,
    )


def _batch_default(db) -> int:
    value = get_setting(db, "deploy.batch_percent")
    return value if type(value) is int else _DEFAULT_BATCH_PERCENT


def _pause_default(db) -> bool:
    value = get_setting(db, "deploy.pause_after_canary")
    return value if isinstance(value, bool) else _DEFAULT_PAUSE


def _choices(db, options: DeployOptions, certificate) -> list[_Choice]:
    """The bindings the operator chooses between, rendered in the options form.

    The certificate's own targets come ticked. Bindings whose certificate is ``unknown`` are listed (so the
    operator can see them and include them) but ticked only while ``include_unknown`` is on, because only then
    may they enter a plan (Contract decision 15). Anything else was ticked by hand and stays listed so it can
    be unticked again.
    """
    owned = {certificate.id} | ({certificate.renews_id} if certificate.renews_id is not None else set())
    conditions = [Binding.certificate_id.in_(owned), Binding.match_state == "unknown"]
    if options.binding_ids is not None:
        conditions.append(Binding.id.in_(options.binding_ids))
    rows = db.execute(
        select(Binding, Server)
        .join(Server, Server.id == Binding.server_id)
        .where(Binding.is_active.is_(True), Server.is_active.is_(True), or_(*conditions))
        .order_by(Server.hostname, Binding.vhost_name, Binding.id)
    ).all()
    selected = set(options.binding_ids) if options.binding_ids is not None else None
    choices = []
    for binding, server in rows:
        default = binding.certificate_id in owned or options.include_unknown
        choices.append(
            _Choice(
                binding_id=binding.id,
                hostname=server.hostname,
                vhost_name=binding.vhost_name,
                port=binding.port,
                cert_path=binding.cert_path,
                match_state=binding.match_state,
                checked=(binding.id in selected) if selected is not None else default,
            )
        )
    return choices


def _binding_notes(db, preview) -> dict[int, str]:
    """The discovery note of every binding in the preview, one query (D1: a chain diagnostic is shown)."""
    ids = [binding.binding_id for host in preview.hosts for binding in host.bindings]
    if not ids:
        return {}
    rows = db.execute(
        select(Binding.id, Binding.notes).where(Binding.id.in_(tuple(ids)), Binding.notes.is_not(None))
    ).all()
    return {binding_id: notes for binding_id, notes in rows if notes}


def _form_values(params) -> dict[str, str]:
    """What the options form re-renders after a refusal (never anything but text)."""
    return {
        key: _text(params.get(key))
        for key in ("certificate_id", "group", "host", "batch_percent", "canary_server_id", "not_before",
                    "override_reason")
    }


def _start_context(request: Request, params, errors: dict[str, str] | None = None) -> dict:
    """Everything the start screen and its preview fragment need, in one transaction."""
    now = request.app.state.clock()
    registry = request.app.state.job_registry
    keyring = request.app.state.settings.keyring
    collected: dict[str, str] = {}
    preview = None
    blocked: dict[str, str] = {}
    choices: list[_Choice] = []
    notes: dict[int, str] = {}
    active: DeployJobSummary | None = None
    candidates: list[DeployCandidate] = []
    confirm: dict[str, object] = {}
    with request.app.state.factory() as db:
        timezone_name = display_timezone(db)
        candidates = deploy_candidates(db, now)
        options, option_errors = _options(params, timezone_name)
        collected.update(option_errors)
        collected.update(errors or {})
        if options is None and candidates and not option_errors:
            # No choice yet: offer the first candidate (an issued renewal, when there is one).
            options = DeployOptions(certificate_id=candidates[0].certificate_id)
        if options is not None:
            try:
                preview = preview_deploy(db, options, now, keyring=keyring)
                blocked = dict(preview.blocked)
            except DeployBlocked as exc:
                blocked = dict(exc.reasons)
            active = active_deploy(db)
            if preview is not None:
                notes = _binding_notes(db, preview)
                choices = _choices(db, options, preview.certificate)
        unavailable = ansible_unavailable_reason(db, now) or unsupported_reason(
            registry, "Plan 3", (JobType.DEPLOY, "default")
        )
        batch_percent = options.batch_percent if options and options.batch_percent is not None else _batch_default(db)
        pause_after_canary = (
            options.pause_after_canary if options and options.pause_after_canary is not None else _pause_default(db)
        )
        if options is not None and preview is not None:
            canary = next((host for host in preview.hosts if host.batch_no == 0), None)
            confirm = {
                "certificate_id": preview.certificate.id,
                "plan_sha256": preview.plan_sha256,
                "batch_percent": batch_percent,
                "pause_after_canary": "1" if pause_after_canary else "0",
                "include_unknown": "1" if options.include_unknown else "0",
                "canary_server_id": canary.server_id if canary is not None else "",
                "not_before": _form_values(params)["not_before"],
                "binding_ids": [row.binding_id for host in preview.hosts for row in host.bindings],
            }
    return {
        "candidates": candidates,
        "preview": preview,
        "blocked": blocked,
        "errors": collected,
        "active": active,
        "notes": notes,
        "choices": choices,
        "confirm": confirm,
        "canary": next((host for host in preview.hosts if host.batch_no == 0), None) if preview else None,
        "form": _form_values(params),
        # The certificate the checkbox list was rendered for: a later request that names a different one
        # must use that certificate's defaults instead of the ids still in the DOM (see ``_options``).
        "selection_for": preview.certificate.id if preview is not None else "",
        "batch_percent": batch_percent,
        "pause_after_canary": pause_after_canary,
        "include_unknown": bool(options.include_unknown) if options else False,
        "deploy_unavailable": unavailable,
        "start_reason": unavailable or "; ".join(blocked.values()),
        "tz": timezone_name,
        "csrf_token": request.state.session.csrf_token,
    }


def _start_page(request: Request, params, status: int = 200, errors: dict[str, str] | None = None) -> HTMLResponse:
    return _render(request, "deploy/start.html.j2", status, **_start_context(request, params, errors))


def _preview_fragment(request: Request, params, status: int = 200, errors: dict[str, str] | None = None) -> HTMLResponse:
    """The preview alone: htmx swaps it into ``#deploy-preview`` and a refused POST re-renders it."""
    return _render(request, "deploy/_preview.html.j2", status, **_start_context(request, params, errors))


def _refused_start(request: Request, params, errors: dict[str, str]) -> HTMLResponse:
    if _is_htmx(request):
        return _preview_fragment(request, params, 422, errors)
    return _start_page(request, params, 422, errors)


def _create(request: Request, form) -> Response:
    """The §8.7 enqueue: guardrails, plan hash and confirmation all checked by ``start_deploy``."""
    with request.app.state.factory() as db:
        timezone_name = display_timezone(db)
    options, errors = _options(form, timezone_name)
    if options is None:
        return _refused_start(request, form, errors or {"certificate": "choose a certificate from the list"})
    if errors:
        return _refused_start(request, form, errors)
    plan_sha256 = _text(form.get("plan_sha256"))
    if not _PLAN_SHA256.fullmatch(plan_sha256):
        return _refused_start(
            request, form, {"plan_sha256": "the plan hash is missing; preview the plan again and confirm it"}
        )
    confirmed = _text(form.get("confirm")).lower() in {"yes", "on", "1", "true"}
    override_reason = _text(form.get("override_reason")) or None
    try:
        job = _run(
            request,
            lambda db, now, actor: start_deploy(
                db,
                options,
                plan_sha256=plan_sha256,
                confirmed=confirmed,
                override_reason=override_reason,
                actor=actor,
                now=now,
                keyring=request.app.state.settings.keyring,
            ),
        )
    except DeployBlocked as exc:
        return _refused_start(request, form, dict(exc.reasons))
    return _redirect(
        request,
        f"/deploy/{job.id}",
        f"Deploy queued for {options.certificate_id}: the canary runs first and the rollout stops at the "
        "first failed host.",
    )



def register_deploy_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    # The start screen's routes come first: ``/deploy/preview`` must win over ``/deploy/{job_id}``.
    @app.get("/deploy")
    def deploy_start(request: Request):
        return _start_page(request, request.query_params)

    @app.get("/deploy/preview")
    def deploy_preview(request: Request):
        return _preview_fragment(request, request.query_params)

    @app.post("/deploy")
    async def deploy_create(request: Request):
        form = await request.form(max_files=0, max_fields=_START_MAX_FIELDS)
        try:
            _only(form, _START_FIELDS)
            return await run_in_threadpool(_create, request, form)
        finally:
            await form.close()

    @app.get("/deploy/{job_id}")
    def deploy_job(request: Request, job_id: UUID):
        return _job_page(request, job_id)

    @app.get("/jobs/{job_id}/progress")
    def deploy_progress(request: Request, job_id: UUID):
        return _live(request, job_id)

    @app.get("/deploy/{job_id}/report.json")
    def deploy_job_report(request: Request, job_id: UUID):
        with request.app.state.factory() as db:
            try:
                report = deploy_report(db, job_id)
            except DeployJobNotFound:
                raise HTTPException(404) from None
        return JSONResponse(
            report,
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": f'attachment; filename="deploy-{job_id}.json"',
            },
        )

    @app.post("/deploy/{job_id}/continue")
    async def deploy_continue(request: Request, job_id: UUID):
        form = await request.form(max_files=0, max_fields=5)
        try:
            _only(form, _CONTROL_FIELDS)
            try:
                await run_in_threadpool(
                    _run, request, lambda db, now, actor: continue_deploy(db, job_id, actor, now)
                )
            except InvalidJobState as exc:
                return await run_in_threadpool(_refused, request, job_id, {"state": str(exc)})
            return _redirect(
                request,
                f"/deploy/{job_id}",
                "Continue accepted: the job is queued again and re-checks drift on every host.",
            )
        finally:
            await form.close()

    @app.post("/deploy/{job_id}/cancel")
    async def deploy_cancel(request: Request, job_id: UUID):
        form = await request.form(max_files=0, max_fields=5)
        try:
            _only(form, _CONTROL_FIELDS)
            try:
                await run_in_threadpool(_run, request, lambda db, now, actor: cancel_deploy(db, job_id, actor, now))
            except InvalidJobState as exc:
                return await run_in_threadpool(_refused, request, job_id, {"state": str(exc)})
            return _redirect(request, f"/deploy/{job_id}", "Cancel accepted: no further host will be started.")
        finally:
            await form.close()

    @app.post("/deploy/{job_id}/hosts/{server_id:int}/retry")
    async def deploy_retry(request: Request, job_id: UUID, server_id: int):
        form = await request.form(max_files=0, max_fields=6)
        try:
            _only(form, _RETRY_FIELDS)
            reason, override = _text(form.get("reason")), _text(form.get("override_reason"))
            try:
                job = await run_in_threadpool(
                    _run,
                    request,
                    lambda db, now, actor: retry_host(
                        db, job_id, server_id, reason, actor, now, override_reason=override or None
                    ),
                )
            except DeployBlocked as exc:
                return await run_in_threadpool(_refused, request, job_id, exc.reasons)
            except InvalidJobState as exc:
                return await run_in_threadpool(_refused, request, job_id, {"state": str(exc)})
            return _redirect(
                request,
                f"/deploy/{job.id}",
                f"Retry of server {server_id} queued as a new job; the reason is in the audit log.",
            )
        finally:
            await form.close()
