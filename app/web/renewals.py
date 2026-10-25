"""Resumable manual-CA renewal wizard (Task 19).

Every POST performs exactly one Task 18 transition in one transaction and answers 303 to the step
of the *new* state (``HX-Redirect`` for htmx, which cannot observe a 303). Typed service failures
become a 422 page, or the panel fragment for htmx, with the renewal left untouched. Nothing here
can mark a renewal ``deployed``: that transition belongs to the Plan 3 deploy handler.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import FormData

from app.crypto.csr import canonical_sans
from app.crypto.keys import KeySpec
from app.crypto.parse import MAX_INPUT_BYTES
from app.models import Certificate, Renewal
from app.models.enums import CertificateStatus, JobType, RenewalState
from app.services.audit import Actor, record
from app.services.renewals import (
    InvalidTransition,
    IssuedValidationError,
    RenewalBasics,
    RenewalError,
    RenewalValidationError,
    attach_issued,
    cancel,
    create_draft,
    edit_draft,
    finalize,
    generate_csr,
    issued_warnings,
    mark_submitted,
)
from app.web.certificates import _MAX_PART, _is_htmx, _read_object, _redirect, describe_chain_message
from app.web.common import _render, _transact, display_timezone, install_template_helpers, render_block

STEPS = ("basics", "csr", "submitted", "upload", "ready", "done")
_STEP_LABELS = {
    "basics": "Basics",
    "csr": "CSR",
    "submitted": "Order",
    "upload": "Upload",
    "ready": "Ready",
    "done": "Done",
}
# Steps a renewal can show per state; the first one is the default. Anything else falls back to it.
_STATE_STEPS: dict[RenewalState, tuple[str, ...]] = {
    RenewalState.DRAFT: ("basics",),
    RenewalState.CSR_GENERATED: ("csr",),
    RenewalState.SUBMITTED: ("submitted", "upload"),
    RenewalState.ISSUED: ("ready",),
    RenewalState.DEPLOYED: ("done",),
    RenewalState.DONE: ("done",),
    RenewalState.CANCELLED: ("basics",),
}
# One non-terminal renewal per previous certificate (deployed still awaits its confirmation).
NON_TERMINAL = (
    RenewalState.DRAFT,
    RenewalState.CSR_GENERATED,
    RenewalState.SUBMITTED,
    RenewalState.ISSUED,
    RenewalState.DEPLOYED,
)
_CANCELLABLE = frozenset(
    {RenewalState.DRAFT, RenewalState.CSR_GENERATED, RenewalState.SUBMITTED, RenewalState.ISSUED}
)

DEFAULT_ALGORITHM = "rsa-2048"


@dataclass(frozen=True)
class Algorithm:
    value: str
    label: str
    spec: KeySpec
    note: str


ALGORITHMS = (
    Algorithm(
        "rsa-2048",
        "RSA 2048 (default)",
        KeySpec(kind="rsa", size=2048),
        "Most compatible: accepted by virtually every CA, client and appliance.",
    ),
    Algorithm(
        "rsa-3072",
        "RSA 3072",
        KeySpec(kind="rsa", size=3072),
        "Larger security margin; slightly slower handshakes, accepted by all current clients and CAs.",
    ),
    Algorithm(
        "rsa-4096",
        "RSA 4096",
        KeySpec(kind="rsa", size=4096),
        "Largest RSA key: slowest handshakes and bigger certificates; some older appliances reject it.",
    ),
    Algorithm(
        "ecdsa-p256",
        "ECDSA P-256",
        KeySpec(kind="ecdsa", curve="secp256r1"),
        "Small and fast; compatibility is good with current software but some older clients and CAs lack ECDSA.",
    ),
    Algorithm(
        "ecdsa-p384",
        "ECDSA P-384",
        KeySpec(kind="ecdsa", curve="secp384r1"),
        "Higher margin than P-256 with the same ECDSA compatibility caveats; some clients reject P-384.",
    ),
)
_ALGORITHMS = {item.value: item for item in ALGORITHMS}

_CHECKS = {
    "parse": ("Certificate file", "Re-download the certificate from the CA as PEM or DER (never a PFX/PKCS#12 bundle)."),
    "key_match": (
        "Private key match",
        "The CA issued a certificate for a different key. Submit exactly the CSR from step 2 (compare its SHA-256) and download again.",
    ),
    "csr_match": ("CSR public key", "The certificate does not belong to the CSR of this renewal; re-download it from the right order."),
    "csr_signature": ("CSR signature", "The stored CSR could not be verified; cancel this renewal and start a new one."),
    "csr_hash": ("CSR hash", "The stored CSR no longer matches its frozen hash; cancel this renewal and start a new one."),
    "csr_identity": ("CSR names", "The stored CSR no longer matches the renewal names; cancel this renewal and start a new one."),
    "common_name": ("Common name", "The CA changed the common name. Re-order with the right name or start a new renewal."),
    "sans": ("Subject alternative names", "The CA changed the requested SANs. Re-order with the right names or start a new renewal."),
    "validity": ("Validity period", "The certificate is outside its validity window; download the current certificate from the CA."),
    "self_signed": ("Issuer", "A self-signed certificate was uploaded; upload the one signed by the CA."),
    "duplicate": ("Inventory", "This certificate already exists in the inventory; open it there instead."),
    "chain": ("Chain", "Download the intermediate certificate(s) from the CA again, or leave the chain empty to reuse the previous certificate's chain."),
    "certificate": ("Inventory", "The certificate could not be stored; check the details and try again."),
}
_TOO_LARGE = "Input is too large: at most 1 MiB (1,048,576 bytes) per field is accepted."
_ISSUED_WARNINGS = {"expired": "The issued certificate has already expired."}
_FILENAME_LIMIT = 100


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def csr_filename(common_name: str) -> str:
    """``<safe-cn>.csr``: ``[A-Za-z0-9._-]`` only, ``*`` spelled out, at most 100 characters of name."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", common_name.replace("*", "wildcard"))
    return (name.lstrip(".")[:_FILENAME_LIMIT] or "renewal") + ".csr"


def _uuid_or_404(raw: str) -> UUID:
    try:
        parsed = UUID(raw)
    except ValueError:
        raise HTTPException(404) from None
    if str(parsed) != raw.lower():
        raise HTTPException(404)
    return parsed


def _source_id(request: Request) -> int | None:
    raw = request.query_params.get("from")
    if raw is None or raw == "":
        return None
    if not (raw.isascii() and raw.isdigit()) or len(raw) > 15:
        raise HTTPException(422)
    return int(raw)


def _text(form: FormData, name: str, cap: int) -> str:
    value = form.get(name)
    return value[:cap] if isinstance(value, str) else ""


def _lines(text: str) -> tuple[str, ...]:
    return tuple(line.strip() for line in text.splitlines() if line.strip())


def _display_sans(sans: list[str] | tuple[str, ...]) -> str:
    # A DNS name can never parse as an IP, so the "DNS:" tag is redundant for display.
    return "\n".join(item.removeprefix("DNS:") for item in sans)


def _form_values(form: FormData) -> dict[str, str]:
    return {
        "common_name": _text(form, "common_name", 300),
        "sans": _text(form, "sans", 20_000),
        "ca_name": _text(form, "ca_name", 201),
        "notes": _text(form, "notes", 10_001),
        "key_algorithm": _text(form, "key_algorithm", 32) or DEFAULT_ALGORITHM,
    }


def _basics(values: Mapping[str, str]) -> RenewalBasics:
    return RenewalBasics(
        common_name=values["common_name"],
        sans=_lines(values["sans"]),
        ca_name=values["ca_name"] or None,
        notes=values["notes"] or None,
    )


def _prefill(previous: Certificate) -> RenewalBasics:
    return RenewalBasics(
        common_name=previous.common_name,
        sans=tuple(previous.sans) or (previous.common_name,),
        ca_name=previous.issuer_cn,
        notes=None,
    )


def _values_from_basics(basics: RenewalBasics) -> dict[str, str]:
    return {
        "common_name": basics.common_name,
        "sans": _display_sans(basics.sans),
        "ca_name": basics.ca_name or "",
        "notes": basics.notes or "",
        "key_algorithm": DEFAULT_ALGORITHM,
    }


def _values_from_row(row: Renewal) -> dict[str, str]:
    return {
        "common_name": row.common_name,
        "sans": _display_sans(row.sans),
        "ca_name": row.ca_name or "",
        "notes": row.notes or "",
        "key_algorithm": DEFAULT_ALGORITHM,
    }


def _location(renewal_id: UUID | str, state: RenewalState) -> str:
    return f"/renewals/{renewal_id}?step={_STATE_STEPS[state][0]}"


def _errors(exc: RenewalValidationError | IssuedValidationError) -> dict[str, list[str]]:
    return {key: list(messages) for key, messages in exc.errors.items()}


def in_flight(db: Session, previous_id: int) -> Renewal | None:
    return db.scalar(
        select(Renewal)
        .where(Renewal.previous_certificate_id == previous_id, Renewal.state.in_(NON_TERMINAL))
        .order_by(Renewal.created_at, Renewal.id)
        .limit(1)
    )


def start_renewal(
    db: Session, previous_id: int | None, basics: RenewalBasics | None, actor: Actor, now: datetime
) -> tuple[Renewal, bool]:
    """Create the draft, or return the in-flight renewal of the same certificate.

    The previous certificate row is locked first, so two concurrent starts serialise and the
    second one sees (and returns) the renewal the first one committed. There is no DB constraint.
    """
    if previous_id is None:
        if basics is None:
            raise RenewalValidationError({"common_name": ("common_name is required",)})
        return create_draft(db, None, basics, actor, now), True
    previous = db.scalar(select(Certificate).where(Certificate.id == previous_id).with_for_update())
    if previous is None:
        raise RenewalError("not_found", "certificate not found")
    existing = in_flight(db, previous_id)
    if existing is not None:
        return existing, False
    return create_draft(db, previous_id, basics or _prefill(previous), actor, now), True


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _steps(renewal_id: UUID | None) -> list[dict[str, str | None]]:
    return [
        {
            "name": name,
            "label": _STEP_LABELS[name],
            "url": f"/renewals/{renewal_id}?step={name}" if renewal_id else None,
        }
        for name in STEPS
    ]


def _render_panel(request: Request, template: str, status: int, context: dict) -> HTMLResponse:
    context["csrf_token"] = request.state.session.csrf_token
    context["algorithms"] = ALGORITHMS
    context["checks"] = _CHECKS
    if status == 422 and _is_htmx(request):
        return render_block(request, template, "panel", status, **context)
    return _render(request, template, status, **context)


def _new_page(
    request: Request,
    previous_id: int | None,
    status: int = 200,
    *,
    values: Mapping[str, str],
    errors: Mapping[str, list[str]] | None = None,
) -> HTMLResponse:
    context = {
        "r": None,
        "state": "new",
        "step": "basics",
        "steps": _steps(None),
        "source_id": previous_id,
        "previous": None,
        "certificate": None,
        "warnings": [],
        "form": dict(values),
        "errors": errors or {},
        "can_cancel": False,
        "editable": True,
        "deploy_supported": False,
        "tz": "UTC",
    }
    if previous_id is not None:
        with request.app.state.factory() as db:
            context["previous"] = db.get(Certificate, previous_id)
            context["tz"] = display_timezone(db)
    return _render_panel(request, "renewals/basics.html.j2", status, context)


def _step_page(
    request: Request,
    renewal_id: str,
    step: str | None,
    status: int = 200,
    *,
    errors: Mapping[str, list[str]] | None = None,
    form: Mapping[str, str] | None = None,
) -> HTMLResponse:
    key = _uuid_or_404(renewal_id)
    now = request.app.state.clock()
    with request.app.state.factory() as db:
        row = db.get(Renewal, key)
        if row is None:
            raise HTTPException(404)
        allowed = _STATE_STEPS[row.state]
        shown = step if step in allowed else allowed[0]
        previous = db.get(Certificate, row.previous_certificate_id) if row.previous_certificate_id else None
        certificate = db.get(Certificate, row.certificate_id) if row.certificate_id else None
        warnings: list[str] = []
        if shown == "ready":
            warnings = [
                _ISSUED_WARNINGS.get(code) or describe_chain_message(code) for code in issued_warnings(db, key, now)
            ]
        timezone_name = display_timezone(db)
    context = {
        "r": row,
        "state": row.state.value,
        "step": shown,
        "steps": _steps(key),
        "source_id": row.previous_certificate_id,
        "previous": previous,
        "certificate": certificate,
        "warnings": warnings,
        "form": dict(form or _values_from_row(row)),
        "errors": errors or {},
        "can_cancel": row.state in _CANCELLABLE,
        "editable": row.state == RenewalState.DRAFT,
        "deploy_supported": request.app.state.job_registry.supports(JobType.DEPLOY),
        "tz": timezone_name,
    }
    return _render_panel(request, f"renewals/{shown}.html.j2", status, context)


def _failure(
    request: Request,
    renewal_id: str,
    step: str | None,
    errors: Mapping[str, list[str]],
    form: Mapping[str, str] | None = None,
) -> HTMLResponse:
    return _step_page(request, renewal_id, step, 422, errors=errors, form=form)


def _perform(request: Request, renewal_id: str, work, *, step: str | None, form: Mapping[str, str] | None = None):
    """Run one transition; 303 to the new state's step, or a 422 page leaving the state untouched."""
    key = _uuid_or_404(renewal_id)
    try:
        state, _ = _transact(request, lambda db, now, actor: work(db, key, now, actor).state)
    except (RenewalValidationError, IssuedValidationError) as exc:
        return _failure(request, renewal_id, step, _errors(exc), form)
    except InvalidTransition as exc:
        return _failure(request, renewal_id, step, {"form": [exc.message]}, form)
    except RenewalError as exc:
        if exc.code == "not_found":
            raise HTTPException(404) from None
        return _failure(request, renewal_id, step, {"form": [exc.message]}, form)
    return _redirect(request, _location(key, state))


# --------------------------------------------------------------------------
# Handlers (run in the threadpool)
# --------------------------------------------------------------------------


def _handle_new_form(request: Request) -> Response:
    previous_id = _source_id(request)
    if previous_id is None:
        return _new_page(request, None, values=_values_from_basics(RenewalBasics("", ())))
    with request.app.state.factory() as db:
        previous = db.get(Certificate, previous_id)
        if previous is None:
            raise HTTPException(404)
        existing = in_flight(db, previous_id)
        if existing is not None:
            return RedirectResponse(_location(existing.id, existing.state), status_code=303)
        basics = _prefill(previous)
        active = previous.status == CertificateStatus.ACTIVE
    errors = {} if active else {"form": ["Only an active certificate can be renewed."]}
    return _new_page(
        request, previous_id, 200 if active else 422, values=_values_from_basics(basics), errors=errors
    )


def _handle_new(request: Request, form: FormData) -> Response:
    previous_id = _source_id(request)
    # An empty submission renews the source certificate as-is; a filled one carries the operator's edits.
    values = _form_values(form) if "common_name" in form else None
    basics = _basics(values) if values is not None else None

    def work(db: Session, now: datetime, actor: Actor) -> str:
        row, _created = start_renewal(db, previous_id, basics, actor, now)
        return _location(row.id, row.state)

    try:
        location, _ = _transact(request, work)
    except RenewalValidationError as exc:
        return _new_page(request, previous_id, 422, values=values or _form_values(form), errors=_errors(exc))
    except RenewalError as exc:
        if exc.code == "not_found":
            raise HTTPException(404) from None
        return _new_page(
            request, previous_id, 422, values=values or _form_values(form), errors={"form": [exc.message]}
        )
    return _redirect(request, location)


def _handle_edit(request: Request, renewal_id: str, form: FormData) -> Response:
    values = _form_values(form)
    return _perform(
        request,
        renewal_id,
        lambda db, key, now, actor: edit_draft(db, key, _basics(values), actor, now),
        step="basics",
        form=values,
    )


def _names_match(row: Renewal, form: FormData) -> bool:
    """False when the posted names differ from the saved draft (unsaved edits next to Generate)."""
    if "common_name" not in form:
        return True
    posted_cn, posted_sans = _text(form, "common_name", 300).strip(), _lines(_text(form, "sans", 20_000))
    try:
        same_cn = canonical_sans([posted_cn])[0] == canonical_sans([row.common_name])[0]
        same_sans = set(canonical_sans([*posted_sans, posted_cn])) == set(row.sans)
    except ValueError:
        return False
    return same_cn and same_sans


def _handle_generate(request: Request, renewal_id: str, form: FormData) -> Response:
    values = _form_values(form)
    algorithm = _ALGORITHMS.get(values["key_algorithm"])
    keyring = request.app.state.settings.keyring

    def work(db: Session, key: UUID, now: datetime, actor: Actor) -> Renewal:
        row = db.scalar(select(Renewal).where(Renewal.id == key).with_for_update())
        if row is None:
            raise RenewalError("not_found", "renewal not found")
        if row.state == RenewalState.DRAFT:
            if algorithm is None:
                raise RenewalValidationError({"key_algorithm": ("Choose one of the listed key algorithms.",)})
            if not _names_match(row, form):
                raise RenewalValidationError(
                    {"form": ("The names on the form differ from the saved draft: save them first, then generate the CSR.",)}
                )
        return generate_csr(db, key, algorithm.spec if algorithm else _ALGORITHMS[DEFAULT_ALGORITHM].spec, keyring, actor, now)

    return _perform(request, renewal_id, work, step="basics", form=values)


def _handle_submit(request: Request, renewal_id: str, form: FormData) -> Response:
    reference = _text(form, "order_reference", 201)
    return _perform(
        request,
        renewal_id,
        lambda db, key, now, actor: mark_submitted(db, key, reference, actor, now),
        step="csr",
    )


def _handle_issued(request: Request, renewal_id: str, form: FormData) -> Response:
    leaf = _read_object(form, "leaf_file", "leaf_text")
    chain = _read_object(form, "chain_file", "chain_text")
    oversized: dict[str, list[str]] = {}
    if leaf is not None and len(leaf) > MAX_INPUT_BYTES:
        oversized["parse"] = [_TOO_LARGE]
    if chain is not None and len(chain) > MAX_INPUT_BYTES:
        oversized["chain"] = [_TOO_LARGE]
    echo = {name: _text(form, name, 20_000) for name in ("leaf_text", "chain_text")}
    if oversized:
        return _failure(request, renewal_id, "upload", oversized, echo)
    return _perform(
        request,
        renewal_id,
        lambda db, key, now, actor: attach_issued(db, key, leaf or b"", chain, actor, now),
        step="upload",
        form=echo,
    )


def _handle_finalize(request: Request, renewal_id: str, form: FormData) -> Response:
    previous_status = _text(form, "previous_status", 16) or "superseded"
    reason = _text(form, "reason", 1_001)
    confirmed = _text(form, "confirm", 8) == "yes"

    def work(db: Session, key: UUID, now: datetime, actor: Actor) -> Renewal:
        if not confirmed:
            raise RenewalValidationError(
                {"confirm": ("Confirm that the new certificate is deployed and in use before finishing.",)}
            )
        return finalize(db, key, previous_status, reason, actor, now)  # type: ignore[arg-type]

    return _perform(request, renewal_id, work, step="done", form={"previous_status": previous_status, "reason": reason})


def _handle_cancel(request: Request, renewal_id: str, form: FormData) -> Response:
    reason = _text(form, "reason", 1_001)
    return _perform(
        request,
        renewal_id,
        lambda db, key, now, actor: cancel(db, key, reason, actor, now),
        step=None,
        form=None,
    )


def _download_csr(request: Request, renewal_id: str) -> Response:
    key = _uuid_or_404(renewal_id)

    def work(db: Session, now: datetime, actor: Actor) -> tuple[str, str]:
        row = db.get(Renewal, key)
        if row is None or not row.csr_pem:
            raise HTTPException(404)
        filename = csr_filename(row.common_name)
        # Public material only; the audit names the CSR by hash, never by content.
        record(db, actor, "renewal.csr_download", "renewal", str(key), {"csr_sha256": row.csr_sha256, "filename": filename})
        return row.csr_pem, filename

    (pem, filename), _ = _transact(request, work)
    return Response(
        pem,
        media_type="application/pkcs10",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


async def _run(request: Request, handler, *args, files: int = 0) -> Response:
    """Parse the (bounded) form, run the blocking handler in the threadpool, always close uploads."""
    form = await request.form(max_files=files, max_fields=50, max_part_size=_MAX_PART)
    try:
        return await run_in_threadpool(handler, request, *args, form)
    finally:
        await form.close()


def register_renewal_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/renewals/new")
    def renewal_new_form(request: Request):
        return _handle_new_form(request)

    @app.post("/renewals/new")
    async def renewal_new_submit(request: Request):
        return await _run(request, _handle_new)

    @app.get("/renewals/{renewal_id}")
    def renewal_page(request: Request, renewal_id: str):
        step = request.query_params.get("step")
        if step is not None and step not in STEPS:
            raise HTTPException(422)
        return _step_page(request, renewal_id, step)

    @app.get("/renewals/{renewal_id}/csr.pem")
    def renewal_csr(request: Request, renewal_id: str):
        return _download_csr(request, renewal_id)

    @app.post("/renewals/{renewal_id}/edit")
    async def renewal_edit(request: Request, renewal_id: str):
        return await _run(request, _handle_edit, renewal_id)

    @app.post("/renewals/{renewal_id}/generate-csr")
    async def renewal_generate_csr(request: Request, renewal_id: str):
        return await _run(request, _handle_generate, renewal_id)

    @app.post("/renewals/{renewal_id}/submit")
    async def renewal_submit(request: Request, renewal_id: str):
        return await _run(request, _handle_submit, renewal_id)

    @app.post("/renewals/{renewal_id}/issued")
    async def renewal_issued(request: Request, renewal_id: str):
        return await _run(request, _handle_issued, renewal_id, files=2)

    @app.post("/renewals/{renewal_id}/finalize")
    async def renewal_finalize(request: Request, renewal_id: str):
        return await _run(request, _handle_finalize, renewal_id)

    @app.post("/renewals/{renewal_id}/cancel")
    async def renewal_cancel(request: Request, renewal_id: str):
        return await _run(request, _handle_cancel, renewal_id)
