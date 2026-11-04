"""Inventory management (Slice B INV): manual hosts, the optional repository source, connection defaults.

Manual hosts are first-class (decision D1): every route here works with no Git repository configured and
nothing redirects outside the dashboard (C10). The repository appears only as a source panel, a link to
``/settings?tab=inventory`` and an optional "Import from repository" action.

Forms are native first (C1) and carry the htmx attributes of C4, so the same server render serves both.
Success is one flash note through ``done()`` (C2); refusals are 422 full pages with the shared error
summary and field errors (C3), and the edited row is shown even when the current filter or page hides it.
"""

import math
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app.jobs.handlers.discover import request_discovery
from app.models.enums import JobType
from app.services.digest import inventory_revision_result, parse_inventory_revision
from app.services.managed_hosts import (
    SSH_PORT_KEY,
    SSH_USER_KEY,
    HostError,
    HostNotFound,
    count_hosts,
    count_manual_hosts,
    create_host,
    delete_host,
    filter_params,
    get_host_row,
    groups_in_use,
    list_hosts,
    parse_connection_form,
    parse_filters,
    parse_host_form,
    parse_repository_form,
    set_active,
    update_manual_host,
    update_repository_host,
)
from app.services.settings import SettingsValidationError, get_setting, update_settings
from app.web.certificates import LIST_DEFAULT_PAGE_SIZE, LIST_MAX_PAGE_SIZE
from app.web.common import (
    _render,
    _transact,
    ansible_unavailable_reason,
    display_timezone,
    install_template_helpers,
    inventory_unconfigured_reason,
    unsupported_reason,
)
from app.web.management import done, install_management_helpers

_DISCOVERY = (JobType.DISCOVER, "default")
IMPORT_QUEUED = "Discovery queued; repository hosts appear here when the worker finishes."
CONFIRMATION_REQUIRED = "Confirm the action to continue."
_FORM_FIELDS = ("hostname", "display_name", "connection_address", "webserver", "groups", "notes")
_MAX_FIELD = 4000


def _url(path: str, params: dict[str, str]) -> str:
    return f"{path}?{urlencode(params)}" if params else path


def _bounded_int(raw: object, default: int, low: int, high: int) -> int:
    """A query-string integer; anything malformed or out of range falls back (contract §4: never a 422)."""
    if not isinstance(raw, str):
        return default
    value = raw.strip()
    if not value.isdigit() or len(value) > 9:
        return default
    return min(max(int(value), low), high)


def _return_to(form) -> str:
    """The validated ``return_to``: only this page, never a second host and never a control character."""
    value = form.get("return_to")
    if not isinstance(value, str) or len(value) > 1000:
        return "/inventory"
    if not value.startswith("/inventory") or value.startswith("//"):
        return "/inventory"
    if any(character < " " or character in "\x7f\\" for character in value):
        return "/inventory"
    return value


def _submitted(form) -> dict[str, str]:
    values = {}
    for name in _FORM_FIELDS:
        raw = form.get(name)
        values[name] = raw[:_MAX_FIELD] if isinstance(raw, str) else ""
    return values


def _repository_url(url: str) -> str:
    """The stored repository URL with any userinfo removed (settings refuse credentials, so no token leaks)."""
    if "://" not in url:
        return url.rpartition("@")[2] if "@" in url else url
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None:
        host = f"{host}:{port}"
    return f"{parts.scheme}://{host}{parts.path}"


def _source_status(db) -> dict:
    url = get_setting(db, "inventory.repo_url")
    configured = isinstance(url, str) and bool(url)
    ref = get_setting(db, "inventory.ref")
    revision = last_pull = None
    if configured:
        revision, last_pull = parse_inventory_revision(db.scalar(inventory_revision_result()))
    return {
        "configured": configured,
        "url": _repository_url(url) if configured else "",
        "ref": ref if isinstance(ref, str) else "",
        "revision": revision,
        "last_pull": last_pull,
    }


def _import_reason(request: Request, db) -> str:
    """Why "Import from repository" is unavailable: the same reason ``/servers`` disables discovery."""
    return (
        unsupported_reason(request.app.state.job_registry, "Plan 3", _DISCOVERY)
        or ansible_unavailable_reason(db, request.app.state.clock())
        or inventory_unconfigured_reason(db)
    )


def _page(
    request: Request,
    status: int = 200,
    form_values: dict[str, str] | None = None,
    errors: dict[str, list[str]] | None = None,
    edit: dict | None = None,
    action_error: str | None = None,
    connection_values: dict[str, str] | None = None,
    connection_errors: dict[str, list[str]] | None = None,
):
    filters = parse_filters(request.query_params)
    page_number = _bounded_int(request.query_params.get("page"), 1, 1, 10**9)
    page_size = _bounded_int(request.query_params.get("page_size"), LIST_DEFAULT_PAGE_SIZE, 1, LIST_MAX_PAGE_SIZE)
    with request.app.state.factory() as db:
        page = list_hosts(db, filters, page_number, page_size)
        total_hosts = count_hosts(db)
        manual_hosts = count_manual_hosts(db)
        groups = groups_in_use(db)
        source = _source_status(db)
        import_reason = _import_reason(request, db)
        timezone_name = display_timezone(db)
        manual_ssh_user = get_setting(db, SSH_USER_KEY)
        manual_ssh_port = get_setting(db, SSH_PORT_KEY)
        extra_row = None
        if edit and edit.get("id") and all(item.id != edit["id"] for item in page.items):
            extra_row = get_host_row(db, edit["id"])
    selected = filter_params(filters)
    pages = max(1, math.ceil(page.total / page.page_size)) if page.total else 1
    paging = dict(selected)
    if page_size != LIST_DEFAULT_PAGE_SIZE:
        paging["page_size"] = str(page_size)
    ssh_user = manual_ssh_user if isinstance(manual_ssh_user, str) else ""
    return _render(
        request,
        "inventory/list.html.j2",
        status,
        csrf_token=request.state.session.csrf_token,
        page=page,
        pages=pages,
        values=selected,
        groups=groups,
        source=source,
        import_reason=import_reason,
        manual_ssh_user=ssh_user,
        manual_ssh_port=manual_ssh_port,
        total_hosts=total_hosts,
        connection_warning=bool(manual_hosts) and not ssh_user,
        form_values=form_values or {name: "" for name in _FORM_FIELDS},
        errors=errors or {},
        edit=edit,
        extra_row=extra_row,
        action_error=action_error,
        connection_values=connection_values or {"ssh_user": ssh_user, "ssh_port": str(manual_ssh_port)},
        connection_errors=connection_errors or {},
        add_open=not total_hosts or bool(errors) or request.query_params.get("create") == "1",
        tz=timezone_name,
        page_url=lambda number: _url("/inventory", {**paging, "page": str(number)} if number > 1 else paging),
    )


def _create(request: Request, form):
    values = _submitted(form)
    fields, errors = parse_host_form(form)
    if errors:
        return _page(request, 422, form_values=values, errors=errors)
    try:
        server, _ = _transact(request, lambda db, now, actor: create_host(db, fields, actor, now))
    except HostError as exc:
        return _page(request, 422, form_values=values, errors={exc.field: [exc.message]})
    return done(request, "/inventory", f"Host {server.hostname} added.")


def _edit(request: Request, server_id: int, form):
    values = _submitted(form)
    with request.app.state.factory() as db:
        row = get_host_row(db, server_id)
    if row is None:
        raise HTTPException(404)
    if row.manual:
        manual_fields, errors = parse_host_form(form)
        if manual_fields is None:
            return _page(request, 422, edit={"id": server_id, "values": values, "errors": errors})
        work = lambda db, now, actor: update_manual_host(db, server_id, manual_fields, actor, now)
    else:
        repository_fields, errors = parse_repository_form(form)
        if repository_fields is None:
            return _page(request, 422, edit={"id": server_id, "values": values, "errors": errors})
        work = lambda db, now, actor: update_repository_host(
            db, server_id, repository_fields, actor, now
        )
    try:
        server, _ = _transact(request, work)
    except HostNotFound:
        raise HTTPException(404) from None
    except HostError as exc:
        if exc.field == "action":
            return _page(request, 422, action_error=exc.message)
        return _page(request, 422, edit={"id": server_id, "values": values, "errors": {exc.field: [exc.message]}})
    return done(request, _return_to(form), f"Host {server.hostname} updated.")


def _set_active(request: Request, server_id: int, active: bool, form):
    try:
        server, _ = _transact(request, lambda db, now, actor: set_active(db, server_id, active, actor, now))
    except HostNotFound:
        raise HTTPException(404) from None
    except HostError as exc:
        return _page(request, 422, action_error=exc.message)
    if active:
        return done(request, _return_to(form), f"Host {server.hostname} reactivated.")
    return done(
        request,
        _return_to(form),
        f"Host {server.hostname} deactivated. It is no longer discovered or deployed to.",
    )


def _delete(request: Request, server_id: int, form):
    if form.get("confirm") != "1":
        return _page(request, 422, action_error=CONFIRMATION_REQUIRED)
    try:
        hostname, _ = _transact(request, lambda db, now, actor: delete_host(db, server_id, actor, now))
    except HostNotFound:
        raise HTTPException(404) from None
    except HostError as exc:
        return _page(request, 422, action_error=exc.message)
    return done(request, "/inventory", f"Host {hostname} deleted.")


def _connection(request: Request, form):
    values = {
        "ssh_user": form.get("ssh_user") if isinstance(form.get("ssh_user"), str) else "",
        "ssh_port": form.get("ssh_port") if isinstance(form.get("ssh_port"), str) else "",
    }
    changes, errors = parse_connection_form(form)
    if errors:
        return _page(request, 422, connection_values=values, connection_errors=errors)
    try:
        _transact(request, lambda db, now, actor: update_settings(db, changes, actor))
    except SettingsValidationError as exc:
        renamed = {
            ("ssh_user" if key == SSH_USER_KEY else "ssh_port"): list(messages)
            for key, messages in exc.errors.items()
        }
        return _page(request, 422, connection_values=values, connection_errors=renamed)
    return done(request, "/inventory", "Connection defaults saved.")


def _import(request: Request):
    with request.app.state.factory() as db:
        reason = _import_reason(request, db)
    if reason:
        raise HTTPException(409)
    _transact(request, lambda db, now, actor: request_discovery(db, {}, actor, now))
    return done(request, "/inventory", IMPORT_QUEUED)


async def _form(request: Request):
    return await request.form(max_files=0, max_fields=20)


def register_inventory_routes(app: FastAPI) -> None:
    install_template_helpers(app)
    install_management_helpers(app)

    @app.get("/inventory")
    def inventory_list(request: Request):
        return _page(request)

    @app.post("/inventory")
    async def inventory_create(request: Request):
        form = await _form(request)
        try:
            return await run_in_threadpool(_create, request, form)
        finally:
            await form.close()

    @app.post("/inventory/connection")
    async def inventory_connection(request: Request):
        form = await _form(request)
        try:
            return await run_in_threadpool(_connection, request, form)
        finally:
            await form.close()

    @app.post("/inventory/import")
    async def inventory_import(request: Request):
        form = await _form(request)
        try:
            if set(form.keys()) - {"csrf_token"}:
                raise HTTPException(422)
            return await run_in_threadpool(_import, request)
        finally:
            await form.close()

    @app.post("/inventory/{server_id:int}/edit")
    async def inventory_edit(request: Request, server_id: int):
        form = await _form(request)
        try:
            return await run_in_threadpool(_edit, request, server_id, form)
        finally:
            await form.close()

    @app.post("/inventory/{server_id:int}/deactivate")
    async def inventory_deactivate(request: Request, server_id: int):
        form = await _form(request)
        try:
            return await run_in_threadpool(_set_active, request, server_id, False, form)
        finally:
            await form.close()

    @app.post("/inventory/{server_id:int}/activate")
    async def inventory_activate(request: Request, server_id: int):
        form = await _form(request)
        try:
            return await run_in_threadpool(_set_active, request, server_id, True, form)
        finally:
            await form.close()

    @app.post("/inventory/{server_id:int}/delete")
    async def inventory_delete(request: Request, server_id: int):
        form = await _form(request)
        try:
            return await run_in_threadpool(_delete, request, server_id, form)
        finally:
            await form.close()
