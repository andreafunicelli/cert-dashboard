"""Scan results screen (spec 8.8): list, JSON export, endpoint detail, history drawer, on-demand scans."""

import math
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from app.models import Endpoint
from app.models.enums import JobType, ScanStatus
from app.services.endpoints import (
    EXPORT_LIMIT,
    SORTS,
    EndpointFilters,
    EndpointNotFound,
    endpoint_detail,
    export_endpoints,
    list_endpoints,
    server_choices,
)
from app.services.scans import request_scan
from app.web.certificates import LIST_DEFAULT_PAGE_SIZE, LIST_MAX_PAGE_SIZE, _query_int
from app.web.common import (
    _render,
    _transact,
    display_timezone,
    install_template_helpers,
    render_block,
    set_flash,
    unsupported_reason,
)

_ACTIVE = {"true": True, "false": False, "all": None}
_ID_LIMIT = 10**9 - 1


class _Query:
    """Validated query-string state of the list and its export; ``params`` are the non-default values."""

    def __init__(self, filters: EndpointFilters, params: dict[str, str], sort: str, page: int, size: int):
        self.filters, self.params, self.sort, self.page, self.page_size = filters, params, sort, page, size


def _query(request: Request) -> _Query:
    def raw(name: str) -> str | None:
        value = request.query_params.get(name)
        return value.strip() or None if isinstance(value, str) else None

    try:
        status, active = raw("status"), raw("active") or "true"
        if active not in _ACTIVE:
            raise ValueError("unsupported active filter")
        ids = {name: _query_int(raw(name), 0, 1, _ID_LIMIT) or None for name in ("server_id", "certificate_id")}
        text = {name: (raw(name) or "")[:200] or None for name in ("group", "search")}
        filters = EndpointFilters(
            status=ScanStatus(status) if status else None, **ids, **text, active=_ACTIVE[active]
        )
        sort = raw("sort") or "status"
        if sort not in SORTS:
            raise ValueError("unsupported sort")
        page = _query_int(raw("page"), 1, 1, 10**9)
        size = _query_int(raw("page_size"), LIST_DEFAULT_PAGE_SIZE, 1, LIST_MAX_PAGE_SIZE)
    except ValueError:
        raise HTTPException(422) from None
    params = {name: str(value) for name, value in {**ids, **text, "status": status}.items() if value}
    if active != "true":
        params["active"] = active
    if sort != "status":
        params["sort"] = sort
    if size != LIST_DEFAULT_PAGE_SIZE:
        params["page_size"] = str(size)
    return _Query(filters, params, sort, page, size)


def _url(path: str, params: dict[str, str]) -> str:
    return f"{path}?{urlencode(params)}" if params else path


def _sort_url(query: _Query, column: str) -> str:
    """Header link: toggles ascending/descending where the whitelist has both."""
    target = f"-{column}" if query.sort == column and f"-{column}" in SORTS else column
    params = {k: v for k, v in query.params.items() if k not in ("sort", "page")}
    return _url("/scans", {**params, "sort": target} if target != "status" else params)


def _scan_context(request: Request) -> dict:
    registry = request.app.state.job_registry
    return {
        "scan_supported": registry.supports(JobType.SCAN, "default"),
        "scan_reason": unsupported_reason(registry, "Plan 2", (JobType.SCAN, "default")),
        "csrf_token": request.state.session.csrf_token,
    }


def _list_page(request: Request):
    query = _query(request)
    with request.app.state.factory() as db:
        page = list_endpoints(db, query.filters, query.page, query.page_size, query.sort)
        servers = server_choices(db)
        timezone_name = display_timezone(db)
    pages = max(1, math.ceil(page.total / page.page_size))
    paging = {k: v for k, v in query.params.items() if k != "page"}
    export = {k: v for k, v in query.params.items() if k not in ("page_size", "sort")}
    return _render(
        request,
        "scans/list.html.j2",
        page=page,
        pages=pages,
        values=query.params,
        sort_state=query.sort,
        tz=timezone_name,
        servers=servers,
        statuses=[item.value for item in ScanStatus],
        page_url=lambda number: _url("/scans", {**paging, "page": str(number)} if number > 1 else paging),
        sort_url=lambda column: _sort_url(query, column),
        export_url=_url("/scans/export.json", export),
        **_scan_context(request),
    )


def _export_json(request: Request) -> JSONResponse:
    query = _query(request)  # validated like the list; paging and sort do not apply
    with request.app.state.factory() as db:
        rows = export_endpoints(db, query.filters, EXPORT_LIMIT + 1)
    return JSONResponse(
        rows[:EXPORT_LIMIT],
        headers={
            "Content-Disposition": 'attachment; filename="scans.json"',
            "Cache-Control": "no-store",
            "X-Truncated": "true" if len(rows) > EXPORT_LIMIT else "false",
        },
    )


def _detail(request: Request, endpoint_id: int) -> dict:
    with request.app.state.factory() as db:
        try:
            detail = endpoint_detail(db, endpoint_id)
        except EndpointNotFound:
            raise HTTPException(404) from None
        timezone_name = display_timezone(db)
    row = detail.row
    target = {"host": row.host, "port": str(row.port), **({"sni": row.sni} if row.sni else {})}
    return {
        "detail": detail,
        "row": row,
        "tz": timezone_name,
        "import_url": _url("/certificates/import", target) + "#pull-panel",
        **_scan_context(request),
    }


def _run(request: Request, scope: object, endpoint_id: object) -> RedirectResponse:
    """Enqueue a scan job (never connects out): every active endpoint, or one active endpoint."""
    if scope not in ("all", "endpoint"):
        raise HTTPException(422)
    target = None
    if scope == "endpoint":
        try:
            target = _query_int(endpoint_id if isinstance(endpoint_id, str) else None, 0, 1, _ID_LIMIT)
        except ValueError:
            raise HTTPException(422) from None
        if not target:
            raise HTTPException(422)
    if not request.app.state.job_registry.supports(JobType.SCAN, "default"):
        raise HTTPException(409)

    def enqueue_scan(db, now, actor):
        if target is not None:
            endpoint = db.get(Endpoint, target)
            if endpoint is None:
                raise HTTPException(404)
            if not endpoint.is_active:
                raise HTTPException(422)
        request_scan(db, {} if target is None else {"endpoint_ids": [target]}, actor, now)

    _transact(request, enqueue_scan)
    response = RedirectResponse("/scans" if target is None else f"/scans/{target}", status_code=303)
    set_flash(response, request.app.state.settings.session_secret, ["Scan queued; results appear here when the worker finishes."])
    return response


def register_scan_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/scans")
    def scan_list(request: Request):
        return _list_page(request)

    @app.get("/scans/export.json")
    def scan_export(request: Request):
        return _export_json(request)

    @app.post("/scans/run")
    async def scan_run(request: Request):
        form = await request.form(max_files=0, max_fields=10)
        try:
            return await run_in_threadpool(_run, request, form.get("scope"), form.get("endpoint_id"))
        finally:
            await form.close()

    @app.get("/scans/{endpoint_id:int}")
    def scan_detail(request: Request, endpoint_id: int):
        return _render(request, "scans/detail.html.j2", **_detail(request, endpoint_id))

    @app.get("/scans/{endpoint_id:int}/history")
    def scan_history(request: Request, endpoint_id: int):
        context = _detail(request, endpoint_id)
        if request.headers.get("HX-Request", "").lower() != "true":
            return RedirectResponse(f"/scans/{endpoint_id}#history", status_code=303)
        return render_block(request, "scans/detail.html.j2", "history", **context)
