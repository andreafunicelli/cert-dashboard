"""Servers screens (spec 8.6): list, JSON export, server detail and the discovery actions.

The actions only enqueue ``discover/default`` jobs (``request_discovery``); the web process never runs Ansible.
"""

import math
from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import ARRAY, Text, func, literal, select
from starlette.concurrency import run_in_threadpool

from app.jobs.handlers.discover import request_discovery, validate_discover_payload
from app.models import Server
from app.models.enums import JobType, WebserverType
from app.services.servers import (
    BINDING_SORTS,
    EXPORT_LIMIT,
    SORTS,
    BindingFilters,
    ServerFilters,
    ServerNotFound,
    export_bindings,
    export_servers,
    list_bindings,
    list_servers,
    server_detail,
)
from app.web.certificates import LIST_DEFAULT_PAGE_SIZE, LIST_MAX_PAGE_SIZE, _query_int
from app.web.common import (
    _render,
    _transact,
    display_timezone,
    install_template_helpers,
    set_flash,
    unsupported_reason,
)

_ACTIVE = {"true": True, "false": False, "all": None}
_DISCOVERY = (JobType.DISCOVER, "default")
_DISCOVER_FIELDS = frozenset({"csrf_token", "scope", "group", "hostname"})
_QUEUED = "Discovery queued; the worker runs it and the servers and bindings update when it finishes."


class _Query:
    """Validated query-string state of the list and its export; ``params`` are the non-default values."""

    def __init__(self, filters: Any, params: dict[str, str], sort: str, page: int, size: int):
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


MATCH_STATES = ("matched", "unknown", "key_mismatch", "missing_file")


def _binding_query(request: Request) -> _Query:
    """Validated query-string state of the bindings list and its export (anything unknown is a 422)."""

    def raw(name: str) -> str | None:
        value = request.query_params.get(name)
        return value.strip() or None if isinstance(value, str) else None

    try:
        active = raw("active") or "true"
        webserver, state, sort = raw("webserver"), raw("match_state"), raw("sort") or "server"
        if active not in _ACTIVE or sort not in BINDING_SORTS or (state and state not in MATCH_STATES):
            raise ValueError("unsupported filter or sort")
        numbers = {name: raw(name) for name in ("certificate_id", "server_id")}
        ids = {name: _query_int(value, 0, 1, 10**9) if value else None for name, value in numbers.items()}
        text = {name: (raw(name) or "")[:200] or None for name in ("group", "vhost")}
        filters = BindingFilters(
            **ids,
            **text,
            webserver=WebserverType(webserver) if webserver else None,
            match_state=state,
            active=_ACTIVE[active],
        )
        page = _query_int(raw("page"), 1, 1, 10**9)
        size = _query_int(raw("page_size"), LIST_DEFAULT_PAGE_SIZE, 1, LIST_MAX_PAGE_SIZE)
    except ValueError:
        raise HTTPException(422) from None
    params = {
        name: str(value)
        for name, value in {**ids, **text, "webserver": webserver, "match_state": state}.items()
        if value
    }
    for name, value, default in (("active", active, "true"), ("sort", sort, "server")):
        if value != default:
            params[name] = value
    if size != LIST_DEFAULT_PAGE_SIZE:
        params["page_size"] = str(size)
    return _Query(filters, params, sort, page, size)


def _register_binding_routes(app: FastAPI) -> None:
    @app.get("/bindings")
    def binding_list(request: Request):
        query = _binding_query(request)
        with request.app.state.factory() as db:
            page = list_bindings(db, query.filters, query.page, query.page_size, query.sort)
            timezone_name = display_timezone(db)
        paging = {k: v for k, v in query.params.items() if k != "page"}
        sortless = {k: v for k, v in paging.items() if k not in ("page_size", "sort")}

        def sort_url(column: str) -> str:
            target = f"-{column}" if query.sort == column else column
            return _url("/bindings", {**sortless, "sort": target})

        return _render(
            request,
            "bindings/list.html.j2",
            page=page,
            pages=max(1, math.ceil(page.total / page.page_size)),
            values=query.params,
            sort_state=query.sort,
            tz=timezone_name,
            match_states=MATCH_STATES,
            webservers=[item.value for item in WebserverType],
            page_url=lambda number: _url("/bindings", {**paging, "page": str(number)} if number > 1 else paging),
            sort_url=sort_url,
            export_url=_url("/bindings/export.json", sortless),
        )

    @app.get("/bindings/export.json")
    def binding_export(request: Request):
        query = _binding_query(request)  # validated like the list; paging and sort do not apply
        with request.app.state.factory() as db:
            rows = export_bindings(db, query.filters, EXPORT_LIMIT + 1)
        return JSONResponse(
            rows[:EXPORT_LIMIT],
            headers={
                "Content-Disposition": 'attachment; filename="bindings.json"',
                "Cache-Control": "no-store",
                "X-Truncated": "true" if len(rows) > EXPORT_LIMIT else "false",
            },
        )

    @app.get("/bindings/help")
    def binding_help(request: Request):
        return _render(request, "bindings/help.html.j2")


def _discovery_context(request: Request) -> dict[str, Any]:
    return {
        "discovery_reason": unsupported_reason(request.app.state.job_registry, "Plan 3", _DISCOVERY),
        "csrf_token": request.state.session.csrf_token,
    }


def _queued(request: Request, location: str) -> RedirectResponse:
    response = RedirectResponse(location, status_code=303)
    set_flash(response, request.app.state.settings.session_secret, [_QUEUED])
    return response


def _require_discovery(request: Request) -> None:
    if not request.app.state.job_registry.supports(*_DISCOVERY):
        raise HTTPException(409)


def _discover_payload(db, form) -> dict:
    """The job payload for the submitted scope; a name that is not an inventory server or group is a 404."""
    scope = form.get("scope")
    if scope == "all":
        return {}
    if scope == "group":
        group = form.get("group")
        payload = _validated({"groups": [group]})
        known = db.scalar(
            select(Server.id)
            .where(Server.is_active, Server.ansible_groups.op("@>")(literal([group], ARRAY(Text))))
            .limit(1)
        )
        if known is None:
            raise HTTPException(404)
        return payload
    if scope == "host":
        hostname = form.get("hostname")
        payload = _validated({"hosts": [hostname]})
        server = db.scalars(select(Server).where(Server.hostname == hostname)).first()
        if server is None:
            raise HTTPException(404)
        if not server.is_active:
            raise HTTPException(422)
        return payload
    raise HTTPException(422)


def _validated(payload: dict) -> dict:
    try:
        return validate_discover_payload(payload)
    except ValueError:
        raise HTTPException(422) from None


def _discover_scope(request: Request, form) -> RedirectResponse:
    """Enqueue discovery of everything, one group or one host (never connects out)."""
    _require_discovery(request)
    if set(form.keys()) - _DISCOVER_FIELDS:
        raise HTTPException(422)
    _transact(request, lambda db, now, actor: request_discovery(db, _discover_payload(db, form), actor, now))
    return _queued(request, "/servers")


def _discover_server(request: Request, server_id: int) -> RedirectResponse:
    _require_discovery(request)

    def enqueue_one(db, now, actor):
        server = db.get(Server, server_id)
        if server is None:
            raise HTTPException(404)
        if not server.is_active:
            raise HTTPException(422)
        request_discovery(db, {"hosts": [server.hostname]}, actor, now)

    _transact(request, enqueue_one)
    return _queued(request, f"/servers/{server_id}")


def _group_names(db) -> list[str]:
    name = func.unnest(Server.ansible_groups).label("name")
    return list(db.scalars(select(name).where(Server.is_active).distinct().order_by("name")))


def register_server_routes(app: FastAPI) -> None:
    install_template_helpers(app)
    _register_binding_routes(app)

    @app.post("/servers/discover")
    async def server_discover(request: Request):
        form = await request.form(max_files=0, max_fields=10)
        try:
            return await run_in_threadpool(_discover_scope, request, form)
        finally:
            await form.close()

    @app.post("/servers/{server_id:int}/discover")
    async def server_discover_one(request: Request, server_id: int):
        form = await request.form(max_files=0, max_fields=10)  # only the CSRF token is expected
        try:
            if set(form.keys()) - {"csrf_token"}:
                raise HTTPException(422)
            return await run_in_threadpool(_discover_server, request, server_id)
        finally:
            await form.close()

    @app.get("/servers")
    def server_list(request: Request):
        query = _query(request)
        with request.app.state.factory() as db:
            page = list_servers(db, query.filters, query.page, query.page_size, query.sort)
            timezone_name = display_timezone(db)
            groups = _group_names(db)
        pages = max(1, math.ceil(page.total / page.page_size))
        paging = {k: v for k, v in query.params.items() if k != "page"}
        return _render(
            request,
            "servers/list.html.j2",
            page=page,
            pages=pages,
            groups=groups,
            values=query.params,
            sort_state=query.sort,
            tz=timezone_name,
            **_discovery_context(request),
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
            **_discovery_context(request),
        )
