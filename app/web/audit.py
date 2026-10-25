"""Read-only audit browser (``/audit``) and metadata-only JSON export (Task 21).

Only GET routes exist. Audit rows are never updated or deleted here; the browser and the
export are authenticated reads and are not themselves audited.
"""

import json
import math
from datetime import UTC, datetime
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from app.models import AuditLog
from app.services.audit import AuditFilters, export_audit, list_audit
from app.web.common import _render, display_timezone, format_datetime, install_template_helpers

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
EXPORT_LIMIT = 5_000
_DATE_CHARS = 64
_FILTER_NAMES = ("actor", "action_prefix", "target_type", "target_id", "start", "end", "ip")


def _iso(value: datetime) -> str:
    """UTC ISO-8601; sub-second precision is kept (microseconds, only when non-zero)."""
    moment = value.astimezone(UTC)
    fraction = f".{moment.microsecond:06d}" if moment.microsecond else ""
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + fraction + "Z"


def _parse_moment(raw: str) -> datetime:
    if len(raw) > _DATE_CHARS:
        raise ValueError("date is too long")
    moment = datetime.fromisoformat(raw)  # YYYY-MM-DD or a full ISO-8601 timestamp
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment


def _query_int(raw: str | None, default: int, low: int, high: int | None = None) -> int:
    if raw is None:
        return default
    if not (raw.isascii() and raw.isdigit()):
        raise ValueError("not a number")
    value = int(raw)
    if value < low or (high is not None and value > high):
        raise ValueError("out of range")
    return value


class _Query:
    """Validated query-string state shared by the page and the export."""

    def __init__(self, filters: AuditFilters, params: dict[str, str], page: int, page_size: int):
        self.filters, self.params, self.page, self.page_size = filters, params, page, page_size


def _parse_query(request: Request) -> _Query:
    """Blank values (an untouched GET form) mean "no filter". Anything invalid is a 422."""

    def raw(name: str) -> str | None:
        value = request.query_params.get(name)
        return value.strip() or None if isinstance(value, str) else None

    try:
        values = {name: raw(name) for name in _FILTER_NAMES}
        filters = AuditFilters(
            **{
                **values,
                "start": _parse_moment(values["start"]) if values["start"] else None,
                "end": _parse_moment(values["end"]) if values["end"] else None,
            }
        )
        page = _query_int(raw("page"), 1, 1)
        page_size = _query_int(raw("page_size"), DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE)
    except ValueError:
        raise HTTPException(422) from None
    params = {name: value for name, value in values.items() if value}
    if page_size != DEFAULT_PAGE_SIZE:
        params["page_size"] = str(page_size)
    return _Query(filters, params, page, page_size)


def _ip_text(value) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text.removesuffix("/32" if "." in text else "/128")


def _export_row(row: AuditLog) -> dict:
    """The public allowlist: exactly these fields, nothing else from the row."""
    return {
        "id": str(row.id),
        "created_at": _iso(row.created_at),
        "actor_label": row.actor_label,
        "actor_user_id": row.actor_user_id,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "details": row.details,
        "ip": _ip_text(row.ip),
        "user_agent": row.user_agent,
    }


def _list_page(request: Request):
    query = _parse_query(request)
    with request.app.state.factory() as db:
        rows, total = list_audit(db, query.filters, query.page, query.page_size)
        timezone_name = display_timezone(db)
    pages = max(1, math.ceil(total / query.page_size))
    filter_params = {k: v for k, v in query.params.items() if k != "page_size"}

    def page_url(number: int) -> str:
        params = {**query.params, "page": number} if number > 1 else query.params
        return f"/audit?{urlencode(params)}" if params else "/audit"

    items = [
        {
            "row": row,
            "utc": _iso(row.created_at),
            "local": format_datetime(row.created_at, timezone_name),
            "ip": _ip_text(row.ip),
            "details_json": json.dumps(row.details, indent=2, sort_keys=True, ensure_ascii=False),
        }
        for row in rows
    ]
    return _render(
        request,
        "audit.html.j2",
        items=items,
        total=total,
        page=query.page,
        pages=pages,
        values=query.params,
        page_size=query.page_size,
        default_page_size=DEFAULT_PAGE_SIZE,
        tz=timezone_name,
        page_url=page_url,
        export_url="/audit/export.json" + (f"?{urlencode(filter_params)}" if filter_params else ""),
    )


def _export_json(request: Request) -> JSONResponse:
    query = _parse_query(request)  # validated like the page; paging is ignored
    with request.app.state.factory() as db:
        rows, total = export_audit(db, query.filters, EXPORT_LIMIT)
        body = [_export_row(row) for row in rows]
    return JSONResponse(
        body,
        headers={
            "Content-Disposition": 'attachment; filename="audit.json"',
            "Cache-Control": "no-store",
            "X-Total-Count": str(total),
            "X-Truncated": "true" if total > len(body) else "false",
        },
    )


def register_audit_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/audit")
    def audit_page(request: Request):
        return _list_page(request)

    @app.get("/audit/export.json")
    def audit_export(request: Request):
        return _export_json(request)
