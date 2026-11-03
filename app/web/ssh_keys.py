"""SSH keys screen (``/ssh-keys``): the public keys to authorize on managed servers.

Two cards, one screen:

* **Worker key** — read-only metadata for the private key Ansible uses. The value never leaves its sealed
  row (``services.worker_credentials``); this screen shows presence, type and public fingerprint and links
  to Settings → Worker for replacing or removing the private key. Nothing here can read it.
* **Registered public keys** — labelled public keys an operator pastes in, each with a ``SHA256:…``
  fingerprint comparable with ``ssh-keygen -lf``. A private key is refused with a message that says so, and a
  key already registered is refused by fingerprint under its existing label.

Add and delete are POSTs with the shared CSRF check, one transaction each, audited. Forms are HTMX-enhanced
against ``#ssh-key-panel`` and keep working without JavaScript.
"""

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from app.jobs.worker import worker_capabilities
from app.services.ssh_keys import (
    SSHKeyError,
    SSHKeyNotFound,
    add_key,
    delete_key,
    list_keys,
    parse_label,
    parse_public_key,
)
from app.services.worker_credentials import SSH_PRIVATE_KEY, credential_state
from app.web.common import _render, _transact, display_timezone, install_template_helpers, set_flash

_MAX_LABEL = 200


def _page(
    request: Request,
    status: int = 200,
    errors: dict[str, str] | None = None,
    values: dict[str, str] | None = None,
):
    with request.app.state.factory() as db:
        keys = list_keys(db)
        worker_key = credential_state(
            db,
            request.app.state.settings,
            SSH_PRIVATE_KEY,
            worker=worker_capabilities(db, request.app.state.clock()),
        )
        timezone_name = display_timezone(db)
    return _render(
        request,
        "ssh_keys/list.html.j2",
        status,
        keys=keys,
        worker_key=worker_key,
        tz=timezone_name,
        csrf_token=request.state.session.csrf_token,
        errors=errors or {},
        form=values if values is not None else {"label": "", "public_key": ""},
        add_open=values is not None,
    )


def _done(request: Request, note: str) -> RedirectResponse:
    response = RedirectResponse("/ssh-keys", status_code=303)
    set_flash(response, request.app.state.settings.session_secret, [note])
    return response


def register_ssh_key_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/ssh-keys")
    def ssh_keys_list(request: Request):
        return _page(request)

    @app.post("/ssh-keys")
    def ssh_keys_create(
        request: Request,
        label: str = Form(""),
        public_key: str = Form(""),
    ):
        submitted = {
            "label": label[:_MAX_LABEL],
            # Never re-render the pasted value: it may be a private key, and a refused secret is not echoed.
            "public_key": "",
        }
        # Validate before the transaction so a refusal never leaves a half-written row to roll back.
        try:
            parse_label(label)
            parse_public_key(public_key)
        except SSHKeyError as error:
            return _page(request, 422, {error.field: error.message}, submitted)
        created: dict[str, str] = {}

        def work(db, now, actor):
            created["label"] = add_key(db, label, public_key, actor).label

        try:
            _transact(request, work)
        except SSHKeyError as error:
            return _page(request, 422, {error.field: error.message}, submitted)
        return _done(request, f"“{created['label']}” registered. Authorize it on the managed servers.")

    @app.post("/ssh-keys/{key_id:int}/delete")
    def ssh_keys_delete(request: Request, key_id: int):
        try:
            _transact(request, lambda db, now, actor: delete_key(db, key_id, actor))
        except SSHKeyNotFound:
            raise HTTPException(404) from None
        return _done(request, "Key deleted. Remove it from the servers' authorized_keys as well.")
