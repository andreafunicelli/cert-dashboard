"""Certificate inventory web routes: upload import (Task 15)."""

import base64
import binascii
import math
import re
from collections.abc import Mapping
from datetime import UTC
from urllib.parse import urlencode
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import FormData, UploadFile

from app.auth.local import PasswordChangeError, reauthenticate
from app.crypto.chain import ChainError, fullchain_pem
from app.crypto.parse import MAX_INPUT_BYTES
from app.jobs.queue import enqueue
from app.models import Binding, Certificate, Job, PrivateKey, Server
from app.models.enums import CertificateStatus, JobStatus, JobType, RenewalState
from app.services.certificates import (
    EXPIRY_BUCKETS,
    EXPORT_LIMIT,
    PFX_PASSWORD_MAX,
    PFX_PASSWORD_MIN,
    SORTS,
    CertificateFilters,
    CertificateMetadata,
    ImportResult,
    ImportValidationError,
    InventoryError,
    UploadInput,
    allowed_status_changes,
    attach_chain,
    certificate_detail,
    export_certificates,
    export_pfx,
    import_upload,
    list_certificates,
    record_download,
    record_export_failure,
    set_status,
    update_certificate,
    validate_upload,
)
from app.services.scans import (
    PULL_ACTION,
    PullPayloadError,
    ScanRequestError,
    format_hostport,
    request_scan,
    scan_targets,
    validate_pull_payload,
)
from app.web.common import (
    _actor,
    _render,
    _transact,
    display_timezone,
    install_template_helpers,
    read_flash,
    render_block,
    set_flash,
    unsupported_reason,
)

_TEMPLATE = "import.html.j2"
_CHUNK = 64 * 1024
# The ASGI layer already caps request bodies at 4 MiB; each object is capped at 1 MiB below.
_MAX_PART = 4 * 1024 * 1024
_FORMATS = ("pem", "crt", "pfx")
_METADATA_FIELDS = ("owner_name", "owner_email", "team", "notes")
_NOTES = {
    "duplicate": None,
    "issuer_serial_collision": "Another certificate with the same issuer and serial number is already stored.",
    "expired": "The certificate has expired.",
}
_NOTE_PREFIXES = {
    "missing_issuer:": "The issuer certificate is missing from the chain: ",
    "chain:": "Chain note: ",
    "issuer:": "Issuer: ",
    "root:": "Root: ",
    "intermediate:": "Intermediate: ",
}


def _describe_warning(code: str) -> str | None:
    if code in _NOTES:
        return _NOTES[code]
    for prefix, text in _NOTE_PREFIXES.items():
        if code.startswith(prefix):
            return text + code[len(prefix) :]
    return code.replace("_", " ").capitalize()


def _notes(result: ImportResult) -> tuple[str, ...]:
    return tuple(note for note in (_describe_warning(code) for code in result.warnings) if note)


def _read_file(upload: UploadFile) -> bytes:
    """Chunked read that stops one byte past the cap, so oversized input is cheap to reject."""
    chunks, total = [], 0
    while chunk := upload.file.read(_CHUNK):
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_INPUT_BYTES:
            break
    return b"".join(chunks)[: MAX_INPUT_BYTES + 1]


def _read_object(
    form: FormData, file_field: str, text_field: str, *, base64_text: bool = False
) -> bytes | None:
    """One uploaded object: the file if one was chosen, else the pasted text; at most cap+1 bytes."""
    upload = form.get(file_field)
    if isinstance(upload, UploadFile) and upload.filename:
        data = _read_file(upload)
        if data:
            return data
    text = form.get(text_field)
    if not isinstance(text, str) or not text.strip():
        return None
    if base64_text:
        # Cap the raw pasted text first: base64 inflates by a third, so a decoded size check is not enough.
        raw = text.encode("utf-8")
        if len(raw) > MAX_INPUT_BYTES:
            return raw[: MAX_INPUT_BYTES + 1]
        try:
            return base64.b64decode("".join(text.split()), validate=True)
        except (binascii.Error, ValueError):
            raise _BadBase64 from None
    return text.encode("utf-8")[: MAX_INPUT_BYTES + 1]


class _BadBase64(Exception):
    pass


def _value(form: FormData, name: str, limit: int = 20_000) -> str:
    value = form.get(name)
    return value[:limit] if isinstance(value, str) else ""


def _secret(form: FormData, name: str) -> str | None:
    value = form.get(name)
    return value if isinstance(value, str) and value else None


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request", "").lower() == "true"


def _page(request: Request, status: int = 200, *, block: str = "upload_panel", **context) -> HTMLResponse:
    context.setdefault("form", {"format": "pem", **dict.fromkeys(_METADATA_FIELDS, "")})
    context.setdefault("errors", {})
    context.setdefault("duplicate", None)
    context.setdefault("pull_form", {"host": "", "port": "443", "sni": "", **dict.fromkeys(_METADATA_FIELDS, "")})
    context.setdefault("pull_errors", {})
    context["csrf_token"] = request.state.session.csrf_token
    if not _is_htmx(request):
        return _render(request, _TEMPLATE, status, **context)
    # htmx swaps only the panel of the form that was submitted: render just that block.
    template = request.app.state.templates.env.get_template(_TEMPLATE)
    scope = {"request": request, "user": request.state.user, **context}
    html = "".join(template.blocks[block](template.new_context(scope)))
    return HTMLResponse(html, status, headers={"Cache-Control": "no-store"})


def _binding_hint(request: Request) -> dict:
    """Context for ``?from_binding=<id>``: the binding the operator wants to import the certificate of.

    Only the owner notes are pre-filled (matching happens at the next discovery); an unknown, retired or
    malformed id is ignored and the plain form is shown.
    """
    raw = request.query_params.get("from_binding", "")
    if not (raw.isascii() and raw.isdigit() and 0 < int(raw) < 2**31):
        return {}
    with request.app.state.factory() as db:
        row = db.execute(
            select(Binding, Server.hostname)
            .join(Server, Server.id == Binding.server_id)
            .where(Binding.id == int(raw), Binding.is_active)
        ).first()
    if row is None:
        return {}
    binding, hostname = row
    hint = {
        "server": hostname,
        "vhost": binding.vhost_name,
        "port": binding.port,
        "fingerprint": binding.on_disk_fingerprint,
    }
    notes = f"Found on {hostname} ({binding.vhost_name}:{binding.port})"
    if binding.on_disk_fingerprint:
        notes += f"; on-disk SHA-256 {binding.on_disk_fingerprint}"
    form = {"format": "pem", **dict.fromkeys(_METADATA_FIELDS, ""), "notes": notes}
    return {"form": form, "from_binding": hint}


def _failure(
    request: Request, form: Mapping[str, str], errors: Mapping[str, tuple[str, ...]]
) -> HTMLResponse:
    return _page(request, 422, form=form, errors=errors)


def _handle_upload(request: Request, form: FormData) -> Response:
    values = {name: _value(form, name, 20_000) for name in _METADATA_FIELDS}
    chosen = _value(form, "format", 16)
    values["format"] = chosen if chosen in _FORMATS else "pem"
    errors: dict[str, tuple[str, ...]] = {}
    try:
        data = _read_object(form, "file", "file_text", base64_text=values["format"] == "pfx")
    except _BadBase64:
        data = None
        errors["file"] = ("The pasted PFX is not valid base64.",)
    chain = _read_object(form, "chain_file", "chain_text")
    key = _read_object(form, "key_file", "key_text")
    upload = UploadInput(
        data=data or b"",
        format=values["format"],
        password=_secret(form, "password"),
        chain_data=chain,
        key_data=key,
        key_password=_secret(form, "key_password"),
    )
    try:
        metadata = CertificateMetadata(**{name: values[name] for name in _METADATA_FIELDS})
    except InventoryError as exc:
        metadata = None
        errors["metadata"] = (exc.message,)
    prepared = None
    try:
        prepared = validate_upload(upload)
    except ImportValidationError as exc:
        for name, messages in exc.errors.items():
            errors.setdefault(name, messages)  # a base64 failure already explained the file problem
    if errors or metadata is None or prepared is None:
        return _failure(request, values, errors)

    keyring = request.app.state.settings.keyring
    confirm = _value(form, "attach_key", 16) == "confirm"
    try:
        result: ImportResult | None
        result, _ = _transact(
            request,
            lambda db, now, actor: import_upload(
                db, keyring, upload, metadata, actor, confirm_key=confirm, prepared=prepared
            ),
        )
    except ImportValidationError as exc:
        return _failure(request, values, exc.errors)
    except InventoryError:
        return _failure(request, values, {"file": ("The certificate could not be imported.",)})
    assert result is not None
    location = f"/certificates/{result.certificate.id}"
    if result.created or result.key_attached:
        notes = _notes(result)
        secret = request.app.state.settings.session_secret
        if _is_htmx(request):
            # A 303 would be followed by XHR itself; HX-Redirect makes htmx navigate the browser.
            response = Response(status_code=200, headers={"HX-Redirect": location})
        else:
            response = RedirectResponse(location, status_code=303)
        # Non-blocking trust warnings ride a one-shot signed cookie to the next full page.
        set_flash(response, secret, notes)
        return response
    duplicate = {"id": result.certificate.id, "notes": _notes(result), "key_attachable": result.key_attachable}
    return _page(request, 200, form=values, duplicate=duplicate)


PULL_ROUTE = "/certificates/import/pull"
PULL_PRIORITY = 200  # on-demand scan/discovery
_PULL_ERROR_FIELDS = ("host", "port", "sni", "metadata")
_SECRET_LIKE = "Remove anything that looks like a secret (passwords, tokens, keys) from the details."


def _pull_failure(request: Request, values: Mapping[str, str], errors: Mapping[str, str]) -> HTMLResponse:
    return _page(request, 422, block="pull_panel", pull_form=values, pull_errors=errors)


def _handle_pull(request: Request, form: FormData) -> Response:
    values = {name: _value(form, name, 20_000) for name in _METADATA_FIELDS}
    # Host and SNI go to the shared validator exactly as typed: no trimming, no truncation, so the
    # web form and the job registry accept and reject the same input.
    raw_host, raw_sni = form.get("host"), form.get("sni")
    host = raw_host if isinstance(raw_host, str) else ""
    sni = raw_sni if isinstance(raw_sni, str) else ""
    values["host"], values["sni"] = host, sni
    values["port"] = _value(form, "port", 16).strip() or "443"
    port: int | str = values["port"]
    if port.isascii() and port.isdigit() and len(port) <= 6:
        port = int(port)
    payload = {
        "action": PULL_ACTION,
        "host": host,
        "port": port,
        "sni": sni or None,
        "metadata": {name: values[name] or None for name in _METADATA_FIELDS},
    }
    try:
        clean = validate_pull_payload(payload)
    except PullPayloadError as exc:
        # Echo a bounded copy of the rejected input back into the form.
        shown = {**values, "host": host[:300], "sni": sni[:300]}
        return _pull_failure(request, shown, {k: v for k, v in exc.errors.items() if k in _PULL_ERROR_FIELDS})
    try:
        job_id, _ = _transact(
            request,
            lambda db, now, actor: enqueue(
                db,
                JobType.SCAN,
                clean,
                actor,
                priority=PULL_PRIORITY,
                run_after=now,
                max_attempts=3,
                scheduled_reason="manual",
            ).id,
        )
    except ValueError:
        # The queue refuses payloads the audit redaction would alter (secret-like free text).
        return _pull_failure(request, values, {"metadata": _SECRET_LIKE})
    location = f"/imports/{job_id}"
    if _is_htmx(request):
        return Response(status_code=200, headers={"HX-Redirect": location})
    return RedirectResponse(location, status_code=303)


def _import_job(request: Request, raw_id: str) -> dict:
    """The view model of a pull-import job; anything else (bad id, other job kinds) is a 404."""
    try:
        parsed = UUID(raw_id)
    except ValueError:
        raise HTTPException(404) from None
    if str(parsed) != raw_id.lower():
        raise HTTPException(404)
    with request.app.state.factory() as db:
        job = db.get(Job, parsed)
        if job is None:
            raise HTTPException(404)
        payload = job.payload if isinstance(job.payload, dict) else {}
        if job.type != JobType.SCAN or payload.get("action") != PULL_ACTION:
            raise HTTPException(404)
        result = job.result if isinstance(job.result, dict) else {}
        status = JobStatus(job.status)
        # A failed attempt with attempts left (and a retryable class) goes back to the queue.
        retrying = (
            status == JobStatus.FAILED
            and job.error_class == "transient_network"
            and job.attempt < job.max_attempts
            and result.get("retryable") is not False
        )
        certificate_id = result.get("certificate_id")
        raw_host, raw_port = payload.get("host"), payload.get("port")
        # A job the registry rejected (poison payload) keeps its sanitized failure; never trust the shape.
        if isinstance(raw_host, str) and type(raw_port) is int and 1 <= raw_port <= 65535:
            endpoint = format_hostport(raw_host, raw_port)
        else:
            endpoint = "(invalid request)"
        raw_sni = payload.get("sni")
        return {
            "id": str(job.id),
            "status": "retrying" if retrying else status.value,
            "polling": retrying or status in (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.PAUSED),
            "endpoint": endpoint,
            "sni": raw_sni if isinstance(raw_sni, str) else None,
            "attempt": job.attempt,
            "max_attempts": job.max_attempts,
            "error_message": job.error_message,
            "certificate_id": certificate_id if type(certificate_id) is int else None,
            "created": result.get("created") is True,
        }


LIST_DEFAULT_PAGE_SIZE = 50
LIST_MAX_PAGE_SIZE = 100
_TRUE = frozenset({"true", "1", "yes", "on"})
_FALSE = frozenset({"false", "0", "no", "off"})
_CHAIN_TOO_LARGE = "Input is too large: the chain is limited to 1 MiB (1,048,576 bytes)."
_CHAIN_EMPTY = "Choose a chain file or paste the intermediate certificates."
_CHAIN_UNREADABLE = "The chain could not be parsed or ordered. Provide PEM or DER certificates that belong to this one."
_CHAIN_MESSAGES = {
    "missing_issuer": "The issuer certificate is missing from the chain.",
    "expired_intermediate": "An intermediate certificate in the chain has expired.",
    "not_yet_valid_intermediate": "An intermediate certificate in the chain is not yet valid.",
    "untrusted_root": "The chain ends at a root certificate that is not a configured trust anchor.",
    "leaf_not_valid": "The certificate is outside its validity period.",
    "forged_issuer": "The chain claims an issuer whose signature does not verify.",
    "missing_identity": "The certificate has no DNS or IP subject alternative name to validate against.",
    "chain_truncated": "The chain was cut short while being ordered.",
    "unparseable_certificate": "The stored certificate could not be parsed.",
    "unparseable_chain": "The stored chain could not be parsed.",
}
_CHAIN_PREFIXES = {
    "issuer:": "Missing issuer: ",
    "intermediate:": "Intermediate: ",
    "root:": "Root: ",
    "policy_failure:": "Path validation failed: ",
}


def describe_chain_message(code: str) -> str:
    if code in _CHAIN_MESSAGES:
        return _CHAIN_MESSAGES[code]
    for prefix, text in _CHAIN_PREFIXES.items():
        if code.startswith(prefix):
            return text + code[len(prefix) :].replace("_", " ")
    return code.replace("_", " ").capitalize()


class _ListQuery:
    """Validated query-string state of the list (and its JSON export)."""

    def __init__(self, filters: CertificateFilters, params: dict[str, str], sort: str, page: int, size: int):
        self.filters, self.params, self.sort, self.page, self.page_size = filters, params, sort, page, size


def _query_bool(raw: str | None) -> bool | None:
    if raw is None:
        return None
    value = raw.lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError("not a boolean")


def _query_int(raw: str | None, default: int, low: int, high: int) -> int:
    if raw is None:
        return default
    if not (raw.isascii() and raw.isdigit()) or len(raw) > 9:
        raise ValueError("not a number")
    value = int(raw)
    if not low <= value <= high:
        raise ValueError("out of range")
    return value


def _list_query(request: Request) -> _ListQuery:
    """Parse filters, sort and paging. Blank values (an untouched GET form) mean "no filter"."""

    def raw(name: str) -> str | None:
        value = request.query_params.get(name)
        return value.strip() or None if isinstance(value, str) else None

    try:
        text = {name: raw(name) for name in ("search", "issuer", "team", "owner")}
        status, state = raw("status"), raw("renewal_state")
        has_key, has_bindings = _query_bool(raw("has_key")), _query_bool(raw("has_bindings"))
        filters = CertificateFilters(
            **text,
            status=CertificateStatus(status) if status else None,
            expiry=raw("expiry"),
            has_key=has_key,
            has_bindings=has_bindings,
            renewal_state=RenewalState(state) if state else None,
        )
        sort = raw("sort") or "not_after"
        if sort not in SORTS:
            raise ValueError("unsupported sort")
        page = _query_int(raw("page"), 1, 1, 10**9)
        size = _query_int(raw("page_size"), LIST_DEFAULT_PAGE_SIZE, 1, LIST_MAX_PAGE_SIZE)
    except ValueError:
        raise HTTPException(422) from None
    params = {name: value for name, value in text.items() if value}
    for name, value in (("status", status), ("expiry", raw("expiry")), ("renewal_state", state)):
        if value:
            params[name] = value
    for name, flag in (("has_key", has_key), ("has_bindings", has_bindings)):
        if flag is not None:
            params[name] = "true" if flag else "false"
    if sort != "not_after":
        params["sort"] = sort
    if size != LIST_DEFAULT_PAGE_SIZE:
        params["page_size"] = str(size)
    return _ListQuery(filters, params, sort, page, size)


def _iso(value) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _export_row(row: Certificate) -> dict:
    """The public allowlist: never PEM, key references or free-text notes."""
    return {
        "id": row.id,
        "common_name": row.common_name,
        "sans": list(row.sans),
        "issuer_cn": row.issuer_cn,
        "serial": row.serial,
        "not_before": _iso(row.not_before),
        "not_after": _iso(row.not_after),
        "sha256_fingerprint": row.sha256_fingerprint,
        "status": row.status.value,
        "chain_status": row.chain_status.value,
        "owner_name": row.owner_name,
        "owner_email": row.owner_email,
        "team": row.team,
        "imported_from": row.imported_from,
        "renews_id": row.renews_id,
        "has_key": row.key_id is not None,
        "binding_count": row.binding_count,
    }


def _sort_url(query: _ListQuery, column: str) -> str:
    """Header link: toggles ascending/descending where the whitelist allows it."""
    descending = f"-{column}"
    if query.sort == column and descending in SORTS:
        target = descending
    elif query.sort == descending:
        target = column
    else:
        target = column
    params = {k: v for k, v in query.params.items() if k not in ("sort", "page")}
    if target != "not_after":
        params["sort"] = target
    return f"/certificates?{urlencode(params)}" if params else "/certificates"


def _list_page(request: Request):
    query = _list_query(request)
    now = request.app.state.clock()
    with request.app.state.factory() as db:
        page = list_certificates(db, query.filters, query.page, query.page_size, query.sort, now)
        timezone_name = display_timezone(db)
    pages = max(1, math.ceil(page.total / page.page_size))
    page_params = {k: v for k, v in query.params.items() if k != "page"}

    def page_url(number: int) -> str:
        params = {**page_params, "page": number} if number > 1 else page_params
        return f"/certificates?{urlencode(params)}" if params else "/certificates"

    export_params = {k: v for k, v in query.params.items() if k != "page_size"}
    return _render(
        request,
        "certificates/list.html.j2",
        page=page,
        pages=pages,
        query=query,
        values=query.params,
        now=now,
        tz=timezone_name,
        page_url=page_url,
        sort_url=lambda column: _sort_url(query, column),
        sort_state=query.sort,
        export_url="/certificates/export.json" + (f"?{urlencode(export_params)}" if export_params else ""),
        statuses=[item.value for item in CertificateStatus],
        buckets=EXPIRY_BUCKETS,
        renewal_states=[item.value for item in RenewalState],
    )


def _export_json(request: Request) -> JSONResponse:
    query = _list_query(request)  # validated like the list; paging is ignored
    now = request.app.state.clock()
    with request.app.state.factory() as db:
        page = export_certificates(db, query.filters, query.sort, now, EXPORT_LIMIT)
    body = {
        "total": page.total,
        "truncated": page.total > len(page.items),
        "certificates": [_export_row(row) for row in page.items],
    }
    return JSONResponse(
        body,
        headers={"Content-Disposition": 'attachment; filename="certificates.json"', "Cache-Control": "no-store"},
    )


def _base_context(request: Request, certificate_id: int) -> dict:
    """What every inventory form fragment needs; 404 when the certificate does not exist."""
    with request.app.state.factory() as db:
        row = db.get(Certificate, certificate_id)
        if row is None:
            raise HTTPException(404)
        current = {name: getattr(row, name) or "" for name in _METADATA_FIELDS}
        return {
            "cert_id": row.id,
            "common_name": row.common_name,
            "cert_status": row.status,
            "status_options": [item.value for item in allowed_status_changes(row.status)],
            "edit_form": current,
            "edit_errors": {},
            "status_form": {"status": "", "reason": ""},
            "status_errors": {},
            "chain_errors": {},
            "csrf_token": request.state.session.csrf_token,
        }


def _detail_page(request: Request, certificate_id: int, status: int = 200, **forms):
    context = _base_context(request, certificate_id)
    now = request.app.state.clock()
    with request.app.state.factory() as db:
        try:
            detail = certificate_detail(db, certificate_id, now)
        except InventoryError:
            raise HTTPException(404) from None
        timezone_name = display_timezone(db)
    registry = request.app.state.job_registry
    diagnostics = detail.diagnostics
    context["scan_error"] = None  # a rejected "Scan now" passes its reason through ``forms``
    warnings = [describe_chain_message(code) for code in diagnostics.messages]
    cached = detail.certificate.chain_status.value
    context.update(
        detail=detail,
        c=detail.certificate,
        tz=timezone_name,
        now=now,
        warnings=warnings,
        recheck_failed=diagnostics.status is None,
        recheck_differs=diagnostics.status is not None and diagnostics.status.value != cached,
        trust_warning=cached != "trusted" or diagnostics.status is None or diagnostics.status.value != "trusted",
        deploy_supported=registry.supports(JobType.DEPLOY),
        scan_supported=registry.supports(JobType.SCAN),
        deploy_reason=unsupported_reason(registry, "Plan 3", (JobType.DEPLOY, "default")),
        scan_reason=unsupported_reason(registry, "Plan 2", (JobType.SCAN, "default")),
        missing_key_versions=_missing_key_versions(request),
        key_unavailable=KEY_UNAVAILABLE,
        **forms,
    )
    return _render(request, "certificates/detail.html.j2", status, **context)


def _edit_page(request: Request, certificate_id: int, status: int = 200, **forms):
    context = _base_context(request, certificate_id)
    context.update(forms)
    if status == 422 and _is_htmx(request):
        return render_block(request, "certificates/detail.html.j2", "metadata_panel", status, **context)
    return _render(request, "certificates/edit.html.j2", status, **context)


def _panel_failure(request: Request, certificate_id: int, block: str, **forms):
    """An inline 422: the panel fragment for htmx, otherwise the whole detail page."""
    if _is_htmx(request):
        context = {**_base_context(request, certificate_id), **forms}
        return render_block(request, "certificates/detail.html.j2", block, 422, **context)
    return _detail_page(request, certificate_id, 422, **forms)


def _redirect(request: Request, location: str) -> Response:
    if _is_htmx(request):
        return Response(status_code=200, headers={"HX-Redirect": location})
    return RedirectResponse(location, status_code=303)


def _handle_edit(request: Request, certificate_id: int, form: FormData) -> Response:
    values = {name: _value(form, name, 20_000) for name in _METADATA_FIELDS}
    try:
        metadata = CertificateMetadata(**values)
        _transact(request, lambda db, now, actor: update_certificate(db, certificate_id, metadata, actor))
    except InventoryError as exc:
        if exc.code == "not_found":
            raise HTTPException(404) from None
        return _edit_page(request, certificate_id, 422, edit_form=values, edit_errors={"metadata": exc.message})
    return _redirect(request, f"/certificates/{certificate_id}")


def _handle_status(request: Request, certificate_id: int, form: FormData) -> Response:
    values = {"status": _value(form, "status", 32), "reason": _value(form, "reason", 5_000)}
    try:
        try:
            target = CertificateStatus(values["status"])
        except ValueError:
            raise InventoryError("invalid_status", "Choose a valid new status.") from None
        _transact(request, lambda db, now, actor: set_status(db, certificate_id, target, values["reason"], actor))
    except InventoryError as exc:
        if exc.code == "not_found":
            raise HTTPException(404) from None
        return _panel_failure(
            request, certificate_id, "status_panel", status_form=values, status_errors={"form": exc.message}
        )
    return _redirect(request, f"/certificates/{certificate_id}")


def _handle_scan(request: Request, certificate_id: int) -> Response:
    """Enqueue an on-demand scan of the endpoints expecting this certificate; never connects out."""
    payload = {"certificate_id": certificate_id}

    def enqueue_scan(db, now, actor):
        if db.get(Certificate, certificate_id) is None:
            raise HTTPException(404)
        targets, _ = scan_targets(db, payload)
        if not targets:
            raise ScanRequestError("No active endpoint expects this certificate, so there is nothing to scan.")
        request_scan(db, payload, actor, now)

    try:
        _transact(request, enqueue_scan)
    except ScanRequestError as exc:
        return _detail_page(request, certificate_id, 422, scan_error=str(exc))
    response = _redirect(request, f"/certificates/{certificate_id}#endpoints-panel")
    set_flash(response, request.app.state.settings.session_secret, ["Scan queued; results appear in the endpoints panel."])
    return response


def _handle_chain(request: Request, certificate_id: int, form: FormData) -> Response:
    data = _read_object(form, "chain_file", "chain_text")
    message = None
    if not data:
        message = _CHAIN_EMPTY
    elif len(data) > MAX_INPUT_BYTES:
        message = _CHAIN_TOO_LARGE
    else:
        try:
            _transact(
                request,
                lambda db, now, actor: attach_chain(db, certificate_id, data, actor, validation_time=now),
            )
        except InventoryError as exc:
            if exc.code == "not_found":
                raise HTTPException(404) from None
            message = _CHAIN_UNREADABLE
    if message is not None:
        return _panel_failure(request, certificate_id, "chain_panel", chain_errors={"chain": message})
    return _redirect(request, f"/certificates/{certificate_id}")


# --------------------------------------------------------------------------
# Audited downloads (Task 20)
# --------------------------------------------------------------------------

KEY_UNAVAILABLE = "key material cannot be decrypted with the configured master key"
_PEM_MEDIA = "application/x-pem-file"
_PFX_MEDIA = "application/x-pkcs12"
_FILENAME_LIMIT = 100
_NO_CHAIN = "No intermediate chain is stored for this certificate. Import the chain from the certificate page first."
_REAUTH_ERRORS = {
    "invalid_current_password": (422, "Your password is incorrect."),
    "locked": (423, "This account is temporarily locked. Try again later or contact another admin."),
    "not_supported": (422, "Your password is managed by your directory; this action is not available here."),
}
_REAUTH_FALLBACK = (422, "Request could not be completed.")
_PFX_FIELD_LIMIT = 1024


def safe_filename(common_name: str, certificate_id: int, suffix: str) -> str:
    """``<safe-cn><suffix>``: ``[A-Za-z0-9._-]`` only, ``*`` spelled out, at most 100 characters of name."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", common_name.replace("*", "wildcard")).lstrip(".")[:_FILENAME_LIMIT]
    if not re.search(r"[A-Za-z0-9]", name):
        name = f"certificate-{certificate_id}"
    return name + suffix


def _attachment(filename: str) -> dict[str, str]:
    return {"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"}


def _missing_key_versions(request: Request) -> frozenset[int]:
    return frozenset(getattr(request.app.state, "missing_key_versions", ()) or ())


def _message_page(request: Request, status: int, message: str) -> HTMLResponse:
    app = request.app
    return app.state.templates.TemplateResponse(
        request=request,
        name="error.html.j2",
        status_code=status,
        context={
            "status": status,
            "message": message,
            "request_id": request.state.request_id,
            "user": request.state.user,
            "navigation": app.state.navigation,
            "status_banner": app.state.status_banner,
            "flash": read_flash(request),
        },
        headers={"Cache-Control": "no-store"},
    )


def _public_download(request: Request, certificate_id: int, kind: str) -> Response:
    def work(db, now, actor):
        row = db.get(Certificate, certificate_id)
        if row is None:
            raise HTTPException(404)
        if kind == "leaf":
            body, suffix = row.pem, ".crt"
        elif kind == "chain":
            if not row.chain_pem.strip():
                raise InventoryError("no_chain", _NO_CHAIN)
            body, suffix = row.chain_pem, ".chain.pem"
        else:
            try:
                body = fullchain_pem(row.pem, row.chain_pem)
            except ChainError:
                raise InventoryError("invalid_chain", "The stored certificate or chain could not be read.") from None
            suffix = ".fullchain.pem"
        record_download(db, certificate_id, kind, actor)
        return body, safe_filename(row.common_name, row.id, suffix)

    try:
        (body, filename), _ = _transact(request, work)
    except InventoryError as exc:
        return _message_page(request, 422, exc.message)
    return Response(body, media_type=_PEM_MEDIA, headers=_attachment(filename))


def _export_blocker(request: Request, row: Certificate) -> str | None:
    """Why the PFX export cannot even be offered for this certificate (None = it can)."""
    if row.key_id is None:
        return "No private key is stored for this certificate."
    with request.app.state.factory() as db:
        key = db.get(PrivateKey, row.key_id)
    if key is not None and key.master_key_version in _missing_key_versions(request):
        return f"PFX export is unavailable: {KEY_UNAVAILABLE}."
    return None


def _export_page(request: Request, certificate_id: int, status: int = 200, *, error: str | None = None, check=True):
    with request.app.state.factory() as db:
        row = db.get(Certificate, certificate_id)
        if row is None:
            raise HTTPException(404)
        cert = {"cert_id": row.id, "common_name": row.common_name}
        blocked = _export_blocker(request, row) if check else None
    return _render(
        request,
        "certificates/export_pfx.html.j2",
        status,
        csrf_token=request.state.session.csrf_token,
        blocked=blocked,
        error=error,
        **cert,
    )


def _pfx_form_error(form: FormData) -> str | None:
    pfx, confirm, password = form.get("pfx_password"), form.get("pfx_password_confirm"), form.get("password")
    if not isinstance(pfx, str) or len(pfx) < PFX_PASSWORD_MIN:
        return f"The PFX password must contain at least {PFX_PASSWORD_MIN} characters."
    if len(pfx) > PFX_PASSWORD_MAX:
        return f"The PFX password must contain at most {PFX_PASSWORD_MAX:,} characters."
    # Both fields are mandatory: an absent confirmation is refused exactly like a different one.
    if confirm != pfx:
        return "The PFX passwords do not match."
    if not isinstance(password, str) or not password or len(password) > _PFX_FIELD_LIMIT:
        return "Enter your current password to confirm it is you."
    return None


def _export_outcome(request: Request, certificate_id: int, password: str, pfx_password: str):
    """Re-authenticate, then export, in this order and these transactions.

    A refused re-authentication commits its counter/lockout/audit effects. A failed export after a
    successful re-authentication rolls back and then commits ``key.export_failed`` on its own.
    Returns ``bytes`` on success or ``(status, message)``.
    """
    app = request.app
    db = app.state.factory()
    try:
        now, actor = app.state.clock(), _actor(request)
        try:
            reauthenticate(db, request.state.session.user_id, password, actor, now)
        except PasswordChangeError as exc:
            db.commit()
            return _REAUTH_ERRORS.get(exc.code, _REAUTH_FALLBACK)
        try:
            data = export_pfx(db, certificate_id, app.state.settings.keyring, pfx_password, actor)
        except InventoryError as exc:
            db.rollback()
            if exc.code == "not_found":
                raise HTTPException(404) from None
            record_export_failure(db, certificate_id, exc.code, actor)
            db.commit()
            return 422, exc.message
        db.commit()
        return data
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _handle_export(request: Request, certificate_id: int, form: FormData) -> Response:
    with request.app.state.factory() as db:
        row = db.get(Certificate, certificate_id)
        if row is None:
            raise HTTPException(404)
        common_name = row.common_name
    problem = _pfx_form_error(form)
    if problem is not None:
        return _export_page(request, certificate_id, 422, error=problem, check=False)
    outcome = _export_outcome(request, certificate_id, str(form["password"]), str(form["pfx_password"]))
    if isinstance(outcome, tuple):
        status, message = outcome
        return _export_page(request, certificate_id, status, error=message, check=False)
    return Response(
        content=outcome, media_type=_PFX_MEDIA, headers=_attachment(safe_filename(common_name, certificate_id, ".pfx"))
    )


def register_certificate_routes(app: FastAPI) -> None:
    from app.jobs.handlers import build_registry  # late: handlers import the worker module

    install_template_helpers(app)
    app.state.job_registry = build_registry()  # capability checks only; the worker owns execution

    @app.get("/certificates")
    def certificate_list(request: Request):
        return _list_page(request)

    @app.get("/certificates/export.json")
    def certificate_export(request: Request):
        return _export_json(request)

    @app.get("/certificates/{certificate_id:int}")
    def certificate_detail_page(request: Request, certificate_id: int):
        return _detail_page(request, certificate_id)

    @app.get("/certificates/{certificate_id:int}/edit")
    def certificate_edit_form(request: Request, certificate_id: int):
        return _edit_page(request, certificate_id)

    @app.get("/certificates/{certificate_id:int}/leaf.pem")
    def certificate_leaf_pem(request: Request, certificate_id: int):
        return _public_download(request, certificate_id, "leaf")

    @app.get("/certificates/{certificate_id:int}/chain.pem")
    def certificate_chain_pem(request: Request, certificate_id: int):
        return _public_download(request, certificate_id, "chain")

    @app.get("/certificates/{certificate_id:int}/fullchain.pem")
    def certificate_fullchain_pem(request: Request, certificate_id: int):
        return _public_download(request, certificate_id, "fullchain")

    @app.get("/certificates/{certificate_id:int}/export.pfx")
    def certificate_export_form(request: Request, certificate_id: int):
        return _export_page(request, certificate_id)

    @app.post("/certificates/{certificate_id:int}/export.pfx")
    async def certificate_export_submit(request: Request, certificate_id: int):
        form = await request.form(max_files=0, max_fields=10, max_part_size=_MAX_PART)
        try:
            return await run_in_threadpool(_handle_export, request, certificate_id, form)
        finally:
            await form.close()

    @app.post("/certificates/{certificate_id:int}/edit")
    async def certificate_edit_submit(request: Request, certificate_id: int):
        form = await request.form(max_files=0, max_fields=50, max_part_size=_MAX_PART)
        try:
            return await run_in_threadpool(_handle_edit, request, certificate_id, form)
        finally:
            await form.close()

    @app.post("/certificates/{certificate_id:int}/status")
    async def certificate_status_submit(request: Request, certificate_id: int):
        form = await request.form(max_files=0, max_fields=50, max_part_size=_MAX_PART)
        try:
            return await run_in_threadpool(_handle_status, request, certificate_id, form)
        finally:
            await form.close()

    @app.post("/certificates/{certificate_id:int}/scan")
    async def certificate_scan_submit(request: Request, certificate_id: int):
        return await run_in_threadpool(_handle_scan, request, certificate_id)

    @app.post("/certificates/{certificate_id:int}/chain")
    async def certificate_chain_submit(request: Request, certificate_id: int):
        form = await request.form(max_files=2, max_fields=50, max_part_size=_MAX_PART)
        try:
            return await run_in_threadpool(_handle_chain, request, certificate_id, form)
        finally:
            await form.close()

    @app.get("/certificates/import")
    def import_form(request: Request):
        # The Scans mismatch page links here with the endpoint's host, port and SNI prefilled.
        target = {name: request.query_params.get(name, "")[:300] for name in ("host", "port", "sni")}
        if not target["host"]:
            return _page(request, **_binding_hint(request))
        blank = dict.fromkeys(_METADATA_FIELDS, "")
        return _page(request, pull_form={**blank, **target, "port": target["port"] or "443"})

    @app.post(PULL_ROUTE)
    async def import_pull_submit(request: Request):
        form = await request.form(max_files=0, max_fields=50, max_part_size=_MAX_PART)
        try:
            return await run_in_threadpool(_handle_pull, request, form)
        finally:
            await form.close()

    @app.get("/imports/{job_id}")
    def import_progress(request: Request, job_id: str):
        job = _import_job(request, job_id)
        return _render(request, "import_progress.html.j2", job=job)

    @app.get("/imports/{job_id}/progress")
    def import_progress_status(request: Request, job_id: str):
        job = _import_job(request, job_id)
        template = request.app.state.templates.env.get_template("import_progress.html.j2")
        scope = {"request": request, "user": request.state.user, "job": job}
        html = "".join(template.blocks["status"](template.new_context(scope)))
        return HTMLResponse(html, headers={"Cache-Control": "no-store"})

    @app.post("/certificates/import/upload")
    async def import_upload_submit(request: Request):
        form = await request.form(max_files=8, max_fields=50, max_part_size=_MAX_PART)
        try:
            return await run_in_threadpool(_handle_upload, request, form)
        finally:
            await form.close()
