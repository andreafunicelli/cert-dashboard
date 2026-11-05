"""Inventory management (Slice B): manual hosts, the optional repository source, connection defaults.

This foundation card owns the page shell, the panel id and the empty states; the inventory
management card fills in the create/edit/actions forms. Nothing here requires a Git repository:
manual hosts are first-class (decision D1).
"""

from fastapi import FastAPI, Request
from sqlalchemy import func, select

from app.models import Server
from app.services.inventory_sources import MANUAL_SOURCE
from app.services.settings import get_setting
from app.web.common import _render, display_timezone, install_template_helpers
from app.web.management import install_management_helpers


def _inventory_page(request: Request):
    with request.app.state.factory() as db:
        rows = db.execute(
            select(
                Server.id,
                Server.hostname,
                Server.display_name,
                Server.inventory_source,
                Server.is_active,
            ).order_by(Server.hostname, Server.id)
        ).all()
        manual = db.scalar(
            select(func.count())
            .select_from(Server)
            .where(Server.inventory_source == MANUAL_SOURCE)
        )
        repository_configured = bool(get_setting(db, "inventory.repo_url"))
        manual_ssh_user = get_setting(db, "inventory.manual_ssh_user")
        manual_ssh_port = get_setting(db, "inventory.manual_ssh_port")
        timezone_name = display_timezone(db)
    return _render(
        request,
        "inventory/list.html.j2",
        csrf_token=request.state.session.csrf_token,
        hosts=rows,
        manual_hosts=manual or 0,
        repository_configured=repository_configured,
        manual_ssh_user=manual_ssh_user,
        manual_ssh_port=manual_ssh_port,
        tz=timezone_name,
    )


def register_inventory_routes(app: FastAPI) -> None:
    install_template_helpers(app)
    install_management_helpers(app)

    @app.get("/inventory")
    def inventory_list(request: Request):
        return _inventory_page(request)
