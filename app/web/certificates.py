"""Certificate inventory web routes: upload import (Task 15)."""

import base64
import binascii
from collections.abc import Mapping
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import FormData, UploadFile

from app.crypto.parse import MAX_INPUT_BYTES
from app.jobs.queue import enqueue
from app.models import Job
from app.models.enums import JobStatus, JobType
from app.services.certificates import (
    CertificateMetadata,
    ImportResult,
    ImportValidationError,
    InventoryError,
    UploadInput,
    import_upload,
    validate_upload,
)
from app.services.scans import PULL_ACTION, PullPayloadError, format_hostport, validate_pull_payload
from app.web.common import _render, _transact, set_flash

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


def register_certificate_routes(app: FastAPI) -> None:
    @app.get("/certificates/import")
    def import_form(request: Request):
        return _page(request)

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
