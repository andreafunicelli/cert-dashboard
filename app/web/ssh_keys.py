"""SSH keys (Slice B): the worker client key lives in Settings → Worker; this page owns host trust.

The foundation card renders the trust-store shell and its empty state; the SSH keys card adds the
add/delete forms. Only public host keys are ever stored here (decision D2).
"""

from fastapi import FastAPI, Request
from sqlalchemy import select

from app.models import SshHostKey, User
from app.web.common import _render, display_timezone, install_template_helpers
from app.web.management import install_management_helpers


def _ssh_keys_page(request: Request):
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
        timezone_name = display_timezone(db)
    return _render(
        request,
        "ssh_keys/list.html.j2",
        csrf_token=request.state.session.csrf_token,
        host_keys=rows,
        tz=timezone_name,
    )


def register_ssh_key_routes(app: FastAPI) -> None:
    install_template_helpers(app)
    install_management_helpers(app)

    @app.get("/ssh-keys")
    def ssh_keys_page(request: Request):
        return _ssh_keys_page(request)
