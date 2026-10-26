"""Servers screens (spec 8.6): list, JSON export and server detail. Read-only: discovery arrives with Plan 3."""

import math
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from app.models.enums import JobType
from app.services.servers import (
    EXPORT_LIMIT,
    SORTS,
    ServerFilters,
    ServerNotFound,
    export_servers,
    list_servers,
    server_detail,
)
from app.web.certificates import LIST_DEFAULT_PAGE_SIZE, LIST_MAX_PAGE_SIZE, _query_int
from app.web.common import _render, display_timezone, install_template_helpers, unsupported_reason

_ACTIVE = {"true": True, "false": False, "all": None}


class _Query:
    """Validated query-string state of the list and its export; ``params`` are the non-default values."""

    def __init__(self, filters: ServerFilters, params: dict[str, str], sort: str, page: int, size: int):
        self.filters, self.params, self.sort, self.page, self.page_size = filters, params, sort, page, size


def _query(request: Request) -> _Query:
    def raw(name: str) -> str | None:
        value = request.query_params.get(name)
        return value.strip() or None if isinstance(value, str) else None

    try:
        active = raw("active") or "true"
        if active not in _ACTIVE:
            raise ValueError("unsupported active filter")
        text = {name: (raw(name) or "")[:200] or None for name in ("search", "group")}
        sort = raw("sort") or "hostname"
        if sort not in SORTS:
            raise ValueError("unsupported sort")
        page = _query_int(raw("page"), 1, 1, 10**9)
        size = _query_int(raw("page_size"), LIST_DEFAULT_PAGE_SIZE, 1, LIST_MAX_PAGE_SIZE)
    except ValueError:
        raise HTTPException(422) from None
    params = {name: value for name, value in text.items() if value}
    if active != "true":
        params["active"] = active
    if sort != "hostname":
        params["sort"] = sort
    if size != LIST_DEFAULT_PAGE_SIZE:
        params["page_size"] = str(size)
    return _Query(ServerFilters(**text, active=_ACTIVE[active]), params, sort, page, size)


def _url(path: str, params: dict[str, str]) -> str:
    return f"{path}?{urlencode(params)}" if params else path


def _sort_url(query: _Query, column: str) -> str:
    """Header link: ascending first, descending on the second click."""
    target = f"-{column}" if query.sort == column else column
    params = {k: v for k, v in query.params.items() if k not in ("sort", "page")}
    return _url("/servers", {**params, "sort": target} if target != "hostname" else params)


def register_server_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/servers")
    def server_list(request: Request):
        query = _query(request)
        with request.app.state.factory() as db:
            page = list_servers(db, query.filters, query.page, query.page_size, query.sort)
            timezone_name = display_timezone(db)
        pages = max(1, math.ceil(page.total / page.page_size))
        paging = {k: v for k, v in query.params.items() if k != "page"}
        return _render(
            request,
            "servers/list.html.j2",
            page=page,
            pages=pages,
            values=query.params,
            sort_state=query.sort,
            tz=timezone_name,
            page_url=lambda number: _url(
                "/servers", {**paging, "page": str(number)} if number > 1 else paging
            ),
            sort_url=lambda column: _sort_url(query, column),
            export_url=_url(
                "/servers/export.json", {k: v for k, v in paging.items() if k not in ("page_size", "sort")}
            ),
        )

    @app.get("/servers/export.json")
    def server_export(request: Request):
        query = _query(request)  # validated like the list; paging and sort do not apply
        with request.app.state.factory() as db:
            rows = export_servers(db, query.filters, EXPORT_LIMIT + 1)
        return JSONResponse(
            rows[:EXPORT_LIMIT],
            headers={
                "Content-Disposition": 'attachment; filename="servers.json"',
                "Cache-Control": "no-store",
                "X-Truncated": "true" if len(rows) > EXPORT_LIMIT else "false",
            },
        )

    @app.get("/servers/{server_id:int}")
    def server_page(request: Request, server_id: int):
        with request.app.state.factory() as db:
            try:
                detail = server_detail(db, server_id)
            except ServerNotFound:
                raise HTTPException(404) from None
            timezone_name = display_timezone(db)
        return _render(
            request,
            "servers/detail.html.j2",
            detail=detail,
            server=detail.server,
            tz=timezone_name,
            discovery_reason=unsupported_reason(
                request.app.state.job_registry, "Plan 3", (JobType.DISCOVER, "default")
            ),
        )
