"""SSH keys (Slice B contract §6): the worker client key plus the trusted host key store.

The worker's private key is managed in Settings → Worker and this page only ever shows its
presence, provenance, type and public fingerprint (``credential_states`` never returns the value).
What this area owns is host trust: an administrator pastes a host public key, attests that the
fingerprint was compared with the server through an independent channel, and the dashboard lists,
fingerprints and can remove it. The store works with no Git repository configured (D1/D2): no
route here reads the inventory repository.

Add and delete are CSRF-checked POSTs, one transaction each, audited. Native forms get a ``303``
and htmx gets ``200`` + ``HX-Redirect`` (both with the signed flash); refusals re-render the full
page with ``422`` and the shared error summary, and never echo a pasted private key.
"""

from fastapi import FastAPI, Form, HTTPException, Request
from sqlalchemy import select

from app.jobs.worker import worker_capabilities
from app.models import SshHostKey, User
from app.services.ssh_host_keys import (
    HostKeyNotFound,
    HostKeyValidationError,
    add_host_keys,
    remove_host_key,
    short_host,
)
from app.services.worker_credentials import SSH_PRIVATE_KEY, credential_state
from app.web.common import _render, _transact, display_timezone, install_template_helpers
from app.web.management import done, install_management_helpers

_DELETE_CONSEQUENCE = (
    "The dashboard stops trusting this key. Keys for this host in the mounted known_hosts file "
    "are not changed and still apply."
)
_CONFIRM_MESSAGE = "Confirm the action to continue."


def _page(request: Request, status: int = 200, errors=None, values=None):
    """Render the whole page; htmx swaps the ``ssh-host-keys-panel`` panel out of it (C4)."""
    with request.app.state.factory() as db:
        rows = db.execute(
            select(
                SshHostKey.id,
                SshHostKey.host,
                SshHostKey.key_type,
                SshHostKey.fingerprint_sha256,
                SshHostKey.comment,
                SshHostKey.created_at,
                User.username.label("created_by"),
            )
            .outerjoin(User, User.id == SshHostKey.created_by)
            .order_by(SshHostKey.host, SshHostKey.key_type)
        ).all()
        worker = worker_capabilities(db, request.app.state.clock())
        worker_key = credential_state(db, request.app.state.settings, SSH_PRIVATE_KEY, worker=worker)
        timezone_name = display_timezone(db)
    return _render(
        request,
        "ssh_keys/list.html.j2",
        status,
        csrf_token=request.state.session.csrf_token,
        host_keys=rows,
        worker_key=worker_key,
        known_hosts_present=None if worker is None else worker.known_hosts_present,
        tz=timezone_name,
        errors=errors or {},
        form=values or {"entries": "", "hosts": "", "comment": ""},
        delete_consequence=_DELETE_CONSEQUENCE,
    )


def register_ssh_key_routes(app: FastAPI) -> None:
    install_template_helpers(app)
    install_management_helpers(app)

    @app.get("/ssh-keys")
    def ssh_keys_page(request: Request):
        return _page(request)

    @app.post("/ssh-keys/host-keys")
    def ssh_keys_add(
        request: Request,
        entries: str = Form(""),
        hosts: str = Form(""),
        comment: str = Form(""),
        verified: str = Form(""),
    ):
        values = {"entries": entries, "hosts": hosts, "comment": comment}

        def work(db, now, actor):
            return add_host_keys(
                db,
                entries=entries,
                hosts=hosts,
                comment=comment,
                verified=verified,
                actor=actor,
            )

        try:
            stored, _ = _transact(request, work)
        except HostKeyValidationError as exc:
            if exc.discard_paste:
                values["entries"] = ""
            return _page(request, 422, exc.errors, values)
        return done(request, "/ssh-keys", f"Trusted {len(stored)} host key(s).")

    @app.post("/ssh-keys/host-keys/{key_id}/delete")
    def ssh_keys_delete(request: Request, key_id: int, confirm: str = Form("")):
        if confirm != "1":
            return _page(request, 422, {"confirm": [_CONFIRM_MESSAGE]})

        def work(db, now, actor):
            return remove_host_key(db, key_id, actor)

        try:
            removed, _ = _transact(request, work)
        except HostKeyNotFound:
            raise HTTPException(404) from None
        note = (
            f"Removed the dashboard-trusted {removed.key_type} key for {short_host(removed.host)}. "
            "The mounted known_hosts file and other trusted keys still apply."
        )
        return done(request, "/ssh-keys", note)
