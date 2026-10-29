"""Deploy screens (spec §8.7): the live job screen, its htmx progress fragment and the JSON report.

Every route here only reads rows the worker already wrote; the web process never runs Ansible, git or SSH.
Operator controls delegate to ``app.services.deploy``, which owns the state machine, the audit rows and the
guardrails, so the screen cannot invent a transition: a refused control comes back as a 422 fragment (htmx)
or as the page itself (no JavaScript) with the reason inline.
"""

from datetime import datetime
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from app.jobs.queue import InvalidJobState
from app.services.deploy import DeployBlocked, cancel_deploy, continue_deploy, retry_host
from app.services.deploy_views import DeployJobNotFound, DeployJobView, deploy_job_view, deploy_report
from app.web.common import (
    _render,
    _transact,
    display_timezone,
    install_template_helpers,
    render_block,
    set_flash,
)

_CONTROL_FIELDS = frozenset({"csrf_token"})
_RETRY_FIELDS = frozenset({"csrf_token", "reason", "override_reason"})


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


def _refused(request: Request, job_id: UUID, errors: dict[str, str], status: int = 422) -> HTMLResponse:
    """A refused control: the controls fragment for htmx, the whole page without JavaScript."""
    view, timezone_name = _view(request, job_id)
    context = _context(request, view, timezone_name, errors)
    if _is_htmx(request):
        return render_block(request, "deploy/job.html.j2", "controls", status, **context)
    return _render(request, "deploy/job.html.j2", status, **context)


def _redirect(request: Request, location: str, note: str) -> RedirectResponse:
    """POST→303 with a one-shot note, so a reload never posts again."""
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


def register_deploy_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/deploy/{job_id}")
    def deploy_job(request: Request, job_id: UUID):
        return _job_page(request, job_id)

    @app.get("/jobs/{job_id}/progress")
    def deploy_progress(request: Request, job_id: UUID):
        view, timezone_name = _view(request, job_id)
        return _render(request, "deploy/_progress.html.j2", view=view, tz=timezone_name)

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
