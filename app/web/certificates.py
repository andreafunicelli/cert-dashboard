"""Certificate inventory web routes: upload import (Task 15)."""

import base64
import binascii
from collections.abc import Mapping

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import FormData, UploadFile

from app.crypto.parse import MAX_INPUT_BYTES
from app.services.certificates import (
    CertificateMetadata,
    ImportResult,
    ImportValidationError,
    InventoryError,
    UploadInput,
    import_upload,
    validate_upload,
)
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


def _page(request: Request, status: int = 200, **context) -> HTMLResponse:
    context.setdefault("form", {"format": "pem", **dict.fromkeys(_METADATA_FIELDS, "")})
    context.setdefault("errors", {})
    context.setdefault("duplicate", None)
    context["csrf_token"] = request.state.session.csrf_token
    if not _is_htmx(request):
        return _render(request, _TEMPLATE, status, **context)
    # htmx swaps only the form panel: render just the content block of the same template.
    template = request.app.state.templates.env.get_template(_TEMPLATE)
    scope = {"request": request, "user": request.state.user, **context}
    html = "".join(template.blocks["content"](template.new_context(scope)))
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


def register_certificate_routes(app: FastAPI) -> None:
    @app.get("/certificates/import")
    def import_form(request: Request):
        return _page(request)

    @app.post("/certificates/import/upload")
    async def import_upload_submit(request: Request):
        form = await request.form(max_files=8, max_fields=50, max_part_size=_MAX_PART)
        try:
            return await run_in_threadpool(_handle_upload, request, form)
        finally:
            await form.close()
