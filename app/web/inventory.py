"""Inventory management (``/inventory``): the hosts Ansible manages, edited inside the dashboard.

The screen is the manual half of the source model in spec 6.1: hosts typed here are marked
``inventory_source = "manual"`` (``services.inventory_entries``), work with no repository configured at all,
and are never deactivated by reconciliation. The repository stays available as *one optional source*: the
"Import from repository" action enqueues the existing discovery job, which pulls the checkout (any git URL,
GitHub included) and reconciles hosts — it is never a redirect and never required for a basic task.

Every state change is a POST with the shared CSRF check, runs in one transaction, is audited, and answers
with a 303 plus a flash note (or the panel re-rendered with 422 and inline errors). Forms are HTMX-enhanced
with ``hx-post``/``hx-select`` against ``#inventory-panel`` and keep a working native POST without JavaScript.
"""

import math
from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from app.jobs.handlers.discover import request_discovery
from app.models.enums import JobType, WebserverType
from app.services.inventory_entries import (
    SORTS,
    EntryFields,
    InventoryEntryError,
    InventoryEntryNotFound,
    InventoryFilters,
    create_entry,
    delete_entry,
    group_names,
    list_entries,
    parse_entry,
    set_entry_active,
    update_entry,
)
from app.services.settings import get_setting
from app.web.certificates import LIST_DEFAULT_PAGE_SIZE, LIST_MAX_PAGE_SIZE, _query_int
from app.web.common import (
    _render,
    _transact,
    ansible_unavailable_reason,
    display_timezone,
    install_template_helpers,
    inventory_unconfigured_reason,
    set_flash,
    unsupported_reason,
)

_ACTIVE = {"true": True, "false": False, "all": None}
_SOURCES = ("manual", "repository")
_WEBSERVERS = {"nginx": WebserverType.NGINX, "apache": WebserverType.APACHE}
_DISCOVERY = (JobType.DISCOVER, "default")
_FORM_KEYS = ("hostname", "display_name", "connection_address", "webserver", "ansible_groups", "notes")
_FORM_LIMITS = {
    "hostname": 300,
    "display_name": 240,
    "connection_address": 300,
    "webserver": 20,
    "ansible_groups": 2000,
    "notes": 2200,
}


class _Query:
    """Validated query-string state of the list; ``params`` keeps only the non-default values."""

    def __init__(self, filters: InventoryFilters, params: dict[str, str], sort: str, page: int, size: int):
        self.filters, self.params, self.sort, self.page, self.page_size = filters, params, sort, page, size

    @property
    def values(self) -> dict[str, str]:
        """What the filter form and the applied-filter chips render."""
        active = "true" if self.filters.active is True else "false" if self.filters.active is False else "all"
        return {**self.params, "active": active}


def _raw(request: Request, name: str) -> str | None:
    value = request.query_params.get(name)
    return (value.strip()[:200] or None) if isinstance(value, str) else None


def _query(request: Request) -> _Query:
    try:
        active = _raw(request, "active") or "true"
        if active not in _ACTIVE:
            raise ValueError("unsupported active filter")
        source = _raw(request, "source")
        if source and source not in _SOURCES:
            raise ValueError("unsupported source filter")
        webserver = _raw(request, "webserver")
        if webserver and webserver not in _WEBSERVERS:
            raise ValueError("unsupported webserver filter")
        sort = _raw(request, "sort") or "hostname"
        if sort not in SORTS:
            raise ValueError("unsupported sort")
        page = _query_int(request.query_params.get("page"), 1, 1, 10**9)
        size = _query_int(request.query_params.get("page_size"), LIST_DEFAULT_PAGE_SIZE, 1, LIST_MAX_PAGE_SIZE)
        text = {name: _raw(request, name) for name in ("search", "group")}
    except ValueError:
        raise HTTPException(422) from None
    params = {name: value for name, value in text.items() if value}
    if source:
        params["source"] = source
    if webserver:
        params["webserver"] = webserver
    if active != "true":
        params["active"] = active
    if sort != "hostname":
        params["sort"] = sort
    if size != LIST_DEFAULT_PAGE_SIZE:
        params["page_size"] = str(size)
    filters = InventoryFilters(
        search=text["search"],
        group=text["group"],
        source=source,
        webserver=_WEBSERVERS[webserver] if webserver else None,
        active=_ACTIVE[active],
    )
    return _Query(filters, params, sort, page, size)


def _url(path: str, params: dict[str, str]) -> str:
    return f"{path}?{urlencode(params)}" if params else path


def _sort_url(query: _Query, column: str) -> str:
    """Header link: ascending first, descending on the second click."""
    target = f"-{column}" if query.sort == column else column
    params = {k: v for k, v in query.params.items() if k not in ("sort", "page")}
    if target != "hostname":
        params["sort"] = target
    return _url("/inventory", params)


def _page_url(query: _Query, number: int) -> str:
    params = {k: v for k, v in query.params.items() if k != "page"}
    if number > 1:
        params["page"] = str(number)
    return _url("/inventory", params)


def _import_context(request: Request, db) -> dict[str, Any]:
    """Why "Import from repository" is disabled (first applicable reason), or "" when it works."""
    reason = (
        unsupported_reason(request.app.state.job_registry, "Plan 3", _DISCOVERY)
        or ansible_unavailable_reason(db, request.app.state.clock())
        or inventory_unconfigured_reason(db)
    )
    repository = get_setting(db, "inventory.repo_url")
    return {"import_reason": reason, "repository": repository if isinstance(repository, str) else ""}


def _page(
    request: Request,
    status: int = 200,
    errors: dict[str, str] | None = None,
    values: dict[str, str] | None = None,
    *,
    query: _Query | None = None,
):
    """Render the list and the panel. ``values`` is the submitted form when one is being re-rendered."""
    query = query or _query(request)
    with request.app.state.factory() as db:
        page = list_entries(db, query.filters, query.page, query.page_size, query.sort)
        timezone_name = display_timezone(db)
        groups = group_names(db)
        extra = _import_context(request, db)
    pages = max(1, math.ceil(page.total / page.page_size))
    return _render(
        request,
        "inventory/list.html.j2",
        status,
        page=page,
        pages=pages,
        tz=timezone_name,
        groups=groups,
        values=query.values,
        query=query,
        sort_url=lambda column: _sort_url(query, column),
        page_url=lambda number: _page_url(query, number),
        csrf_token=request.state.session.csrf_token,
        errors=errors or {},
        form=values if values is not None else {name: "" for name in _FORM_KEYS},
        create_open=values is not None or request.query_params.get("create") == "1",
        **extra,
    )


def _submitted(**values: str) -> dict[str, str]:
    """The values to re-render after a refusal, capped per field so nothing huge is echoed back."""
    return {name: value[: _FORM_LIMITS[name]] for name, value in values.items()}


def _done(request: Request, note: str) -> RedirectResponse:
    response = RedirectResponse("/inventory", status_code=303)
    set_flash(response, request.app.state.settings.session_secret, [note])
    return response


def _apply(request: Request, work, note: str, values: dict[str, str] | None = None):
    """Run ``work(db, actor)`` in one transaction; a typed refusal re-renders the panel with 422."""
    try:
        _transact(request, work)
    except InventoryEntryError as error:
        return _page(request, 422, {error.field: error.message}, values)
    except InventoryEntryNotFound:
        raise HTTPException(404) from None
    return _done(request, note)


def register_inventory_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/inventory")
    def inventory_list(request: Request):
        return _page(request)

    @app.post("/inventory")
    def inventory_create(
        request: Request,
        hostname: str = Form(""),
        display_name: str = Form(""),
        connection_address: str = Form(""),
        webserver: str = Form(""),
        ansible_groups: str = Form(""),
        notes: str = Form(""),
    ):
        submitted = _submitted(
            hostname=hostname,
            display_name=display_name,
            connection_address=connection_address,
            webserver=webserver,
            ansible_groups=ansible_groups,
            notes=notes,
        )
        try:
            fields: EntryFields = parse_entry(submitted)
        except InventoryEntryError as error:
            return _page(request, 422, {error.field: error.message}, submitted)
        return _apply(
            request,
            lambda db, now, actor: create_entry(db, fields, actor),
            f"“{fields.hostname}” added to the inventory.",
        )

    @app.post("/inventory/{server_id:int}/edit")
    def inventory_edit(
        request: Request,
        server_id: int,
        hostname: str = Form(""),
        display_name: str = Form(""),
        connection_address: str = Form(""),
        webserver: str = Form(""),
        ansible_groups: str = Form(""),
        notes: str = Form(""),
    ):
        submitted = _submitted(
            hostname=hostname,
            display_name=display_name,
            connection_address=connection_address,
            webserver=webserver,
            ansible_groups=ansible_groups,
            notes=notes,
        )
        try:
            fields: EntryFields = parse_entry(submitted)
        except InventoryEntryError as error:
            return _page(request, 422, {error.field: error.message}, submitted)
        return _apply(
            request,
            lambda db, now, actor: update_entry(db, server_id, fields, actor),
            f"“{fields.hostname}” updated.",
        )

    @app.post("/inventory/{server_id:int}/active")
    def inventory_active(request: Request, server_id: int, active: str = Form("")):
        if active not in ("true", "false"):
            raise HTTPException(422)
        wanted = active == "true"
        return _apply(
            request,
            lambda db, now, actor: set_entry_active(db, server_id, wanted, actor),
            f"Host {'activated' if wanted else 'deactivated'}.",
        )

    @app.post("/inventory/{server_id:int}/delete")
    def inventory_delete(request: Request, server_id: int):
        return _apply(
            request,
            lambda db, now, actor: delete_entry(db, server_id, actor),
            "Host deleted from the inventory.",
        )

    @app.post("/inventory/import")
    def inventory_import(request: Request):
        """Optional repository source: enqueue the discovery job that pulls and reconciles the checkout."""
        with request.app.state.factory() as db:
            reason = _import_context(request, db)["import_reason"]
        if reason:
            return _page(request, 422, {"form": reason}, None)
        _transact(request, lambda db, now, actor: request_discovery(db, {}, actor, now))
        return _done(
            request,
            "Discovery queued: the worker pulls the inventory repository and reconciles the hosts.",
        )
