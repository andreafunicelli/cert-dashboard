"""Inventory management screen (real Postgres, real HTTP stack).

Covers the manual source model end to end: create/edit/delete/deactivate without any repository, the
repository row staying read-only here, the optional import action, filters, inline errors and audit rows.
Discovery reconciliation keeps manual hosts active — that half is exercised through
``sync_inventory_servers`` so a future change to the exemption fails here.
"""

import re

import pytest
from sqlalchemy import select

from app.models import AuditLog, Job, Server
from app.models.enums import WebserverType
from app.services.audit import Actor
from app.services.discovery import sync_inventory_servers
from app.services.inventory import InventoryHost
from tests.integration.conftest import create_login_user, set_setting

HOST = "web01.example.internal"
REPOSITORY_SOURCE = "main:inventory/hosts.yml@" + "a" * 40
FORM = {
    "hostname": HOST,
    "display_name": "Web 01",
    "connection_address": "",
    "webserver": "nginx",
    "ansible_groups": "web, tls",
    "notes": "rack 4",
}


@pytest.fixture
def web_factory(queue_factory):
    """A private, migrated database per test: these routes commit by design."""
    return queue_factory


@pytest.fixture
def web_user(web_factory):
    return create_login_user(web_factory, "admin")


@pytest.fixture
def csrf(signed_in):
    return signed_in.fixture_csrf


def _servers(factory):
    with factory() as db:
        return list(db.scalars(select(Server).order_by(Server.id)))


def _server(factory, hostname=HOST) -> Server | None:
    with factory() as db:
        return db.scalar(select(Server).where(Server.hostname == hostname))


def _audit(factory, action):
    with factory() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


def _fields(payload: dict | None = None) -> dict:
    return {**FORM, **(payload or {})}


def _create(signed_in, csrf, payload: dict | None = None):
    return signed_in.post("/inventory", data={"csrf_token": csrf, **_fields(payload)}, follow_redirects=False)


# --- the screen itself -----------------------------------------------------------------------------


def test_empty_inventory_shows_a_manual_path_and_does_not_require_a_repository(signed_in):
    page = signed_in.get("/inventory")
    assert page.status_code == 200
    assert 'data-empty="inventory"' in page.text
    assert "No hosts in the inventory yet" in page.text
    assert "Add your first host" in page.text
    # No repository configured: the import action is present but disabled with the reason, never a redirect.
    assert "No inventory repository is configured" in page.text
    assert 'href="/settings?tab=inventory"' in page.text
    # The onboarding call to action opens the create form, so a manual host needs no repository.
    assert 'href="/inventory?create=1#add-host"' in page.text


def test_create_host_works_with_no_repository_configured(signed_in, csrf, web_factory):
    response = _create(signed_in, csrf)
    assert response.status_code == 303 and response.headers["location"] == "/inventory"
    server = _server(web_factory)
    assert server is not None
    assert server.inventory_source == "manual" and server.is_active
    assert list(server.ansible_groups) == ["web", "tls"]
    assert str(server.webserver) == "nginx" and server.display_name == "Web 01" and server.notes == "rack 4"
    created = _audit(web_factory, "server.create")
    assert len(created) == 1 and created[0].details["source"] == "manual"
    # The flash note and the row are visible on the next page.
    page = signed_in.get("/inventory")
    assert "added to the inventory" in page.text
    assert f'data-server-id="{server.id}"' in page.text
    assert "Added here" in page.text


def test_duplicate_hostname_is_refused_case_insensitively(signed_in, csrf, web_factory):
    assert _create(signed_in, csrf).status_code == 303
    duplicate = _create(signed_in, csrf, {"hostname": HOST.upper()})
    assert duplicate.status_code == 422
    assert 'data-field="hostname"' in duplicate.text
    assert "already in the inventory" in duplicate.text
    assert len(_servers(web_factory)) == 1


def test_invalid_hostname_is_an_inline_error_and_writes_nothing(signed_in, csrf, web_factory):
    response = _create(signed_in, csrf, {"hostname": "web 01"})
    assert response.status_code == 422
    assert 'data-field="hostname"' in response.text
    assert "hostname or IP address" in response.text
    assert _servers(web_factory) == [] and _audit(web_factory, "server.create") == []


def test_htmx_post_returns_the_fragment_it_would_swap(signed_in, csrf):
    response = signed_in.post(
        "/inventory",
        data={"csrf_token": csrf, **_fields({"hostname": "-nope"})},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 422
    assert 'id="inventory-panel"' in response.text and "data-inventory-errors" in response.text


@pytest.mark.parametrize("headers", [{}, {"HX-Request": "true"}], ids=["native", "htmx"])
def test_edit_error_reopens_that_rows_form_with_the_attempted_values(signed_in, csrf, web_factory, headers):
    """A refused edit belongs to the row's Edit host form, not to the Add host form above it."""
    _create(signed_in, csrf)
    server = _server(web_factory)
    assert server is not None
    response = signed_in.post(
        f"/inventory/{server.id}/edit",
        data={"csrf_token": csrf, **_fields({"hostname": "-bad", "display_name": "Attempted"})},
        headers=headers,
        follow_redirects=False,
    )
    assert response.status_code == 422
    assert 'data-inventory-errors="true"' in response.text
    row = re.search(rf'<tr data-server-id="{server.id}".*?</tr>', response.text, re.DOTALL)
    assert row is not None
    row_html = row.group(0)
    assert '<details class="inventory-row-actions" open>' in row_html
    assert f'id="edit-{server.id}-hostname" name="hostname" value="-bad"' in row_html
    assert f'id="edit-{server.id}-display_name" name="display_name" value="Attempted"' in row_html
    assert '<p class="form-error" data-field="hostname" role="alert">' in row_html
    # The create form is not the one that was refused: it stays closed and shows neither the input nor the error.
    create = re.search(r'<details class="inventory-create" id="add-host".*?</details>', response.text, re.DOTALL)
    assert create is not None
    create_html = create.group(0)
    assert "open" not in create_html.split(">", 1)[0]
    assert "-bad" not in create_html
    assert 'data-field="hostname"' not in create_html


def test_edit_refusal_from_the_service_reopens_the_row_form_with_its_error(signed_in, csrf, web_factory):
    """A uniqueness refusal from ``update_entry`` is rendered on the row that was being edited too."""
    _create(signed_in, csrf)
    assert _create(signed_in, csrf, {"hostname": "web02.example.internal"}).status_code == 303
    server = _server(web_factory)
    assert server is not None
    response = signed_in.post(
        f"/inventory/{server.id}/edit",
        data={"csrf_token": csrf, **_fields({"hostname": "WEB02.example.internal", "display_name": "Attempted"})},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 422
    row = re.search(rf'<tr data-server-id="{server.id}".*?</tr>', response.text, re.DOTALL)
    assert row is not None
    assert f'id="edit-{server.id}-hostname" name="hostname" value="WEB02.example.internal"' in row.group(0)
    assert '<p class="form-error" data-field="hostname" role="alert">' in row.group(0)
    assert "already in the inventory" in row.group(0)


def test_htmx_create_navigates_and_shows_the_success_note(signed_in, csrf, web_factory):
    """htmx cannot observe a 303: success answers HX-Redirect so the browser lands on the list and its flash."""
    response = signed_in.post(
        "/inventory",
        data={"csrf_token": csrf, **_fields()},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert response.headers["HX-Redirect"] == "/inventory"
    assert response.cookies.get("cd_flash")
    page = signed_in.get("/inventory")
    assert 'data-banner="flash"' in page.text
    assert "added to the inventory" in page.text


def test_htmx_edit_navigates_and_shows_the_success_note(signed_in, csrf, web_factory):
    _create(signed_in, csrf)
    server = _server(web_factory)
    assert server is not None
    response = signed_in.post(
        f"/inventory/{server.id}/edit",
        data={"csrf_token": csrf, **_fields({"display_name": "Web primary"})},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 200 and response.headers["HX-Redirect"] == "/inventory"
    page = signed_in.get("/inventory")
    assert 'data-banner="flash"' in page.text
    assert "updated" in page.text


def test_edit_updates_and_audits_the_before_and_after(signed_in, csrf, web_factory):
    _create(signed_in, csrf)
    server = _server(web_factory)
    response = signed_in.post(
        f"/inventory/{server.id}/edit",
        data={
            "csrf_token": csrf,
            "hostname": HOST,
            "display_name": "Web primary",
            "connection_address": "10.0.0.11",
            "webserver": "apache",
            "ansible_groups": "web,edge",
            "notes": "",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    updated = _server(web_factory)
    assert updated.display_name == "Web primary" and str(updated.webserver) == "apache"
    assert list(updated.ansible_groups) == ["web", "edge"] and updated.connection_address == "10.0.0.11"
    audits = _audit(web_factory, "server.update")
    assert len(audits) == 1
    changes = audits[0].details["changes"]
    assert changes["display_name"] == {"from": "Web 01", "to": "Web primary"}
    assert changes["webserver"] == {"from": "nginx", "to": "apache"}


def test_edit_refuses_an_unknown_host_with_404(signed_in, csrf):
    response = signed_in.post("/inventory/999999/edit", data={"csrf_token": csrf, **FORM})
    assert response.status_code == 404


# --- the repository stays the other source, read-only here -----------------------------------------


def _repository_host(factory, hostname="repo01.example.internal") -> Server:
    from app.models import Server as Model

    with factory.begin() as db:
        server = Model(hostname=hostname, inventory_source=REPOSITORY_SOURCE, is_active=True)
        db.add(server)
        db.flush()
        return server


def test_repository_rows_are_listed_but_not_edited_or_deleted_here(signed_in, csrf, web_factory):
    server = _repository_host(web_factory)
    page = signed_in.get("/inventory")
    assert f'data-server-id="{server.id}"' in page.text and "Repository" in page.text
    assert "Managed by the repository" in page.text

    edit = signed_in.post(f"/inventory/{server.id}/edit", data={"csrf_token": csrf, **FORM})
    delete = signed_in.post(f"/inventory/{server.id}/delete", data={"csrf_token": csrf})
    active = signed_in.post(f"/inventory/{server.id}/active", data={"csrf_token": csrf, "active": "false"})
    for response in (edit, delete, active):
        assert response.status_code == 422
        assert "comes from the inventory repository" in response.text
    stored = _server(web_factory, "repo01.example.internal")
    assert stored.hostname == "repo01.example.internal" and stored.is_active


def test_import_without_a_repository_explains_itself_and_queues_nothing(signed_in, csrf, web_factory):
    response = signed_in.post("/inventory/import", data={"csrf_token": csrf}, follow_redirects=False)
    assert response.status_code == 422
    assert "No inventory repository is configured" in response.text
    with web_factory() as db:
        assert list(db.scalars(select(Job))) == []


def test_import_with_a_repository_queues_discovery(signed_in, csrf, web_factory):
    set_setting(web_factory, "inventory.repo_url", "https://git.example.test/inventory.git")
    response = signed_in.post("/inventory/import", data={"csrf_token": csrf}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/inventory"
    with web_factory() as db:
        jobs = list(db.scalars(select(Job)))
    assert len(jobs) == 1 and str(jobs[0].type) == "discover" and str(jobs[0].status) == "queued"


# --- delete, deactivate and the history rule -------------------------------------------------------


def test_delete_removes_a_manual_host_without_history(signed_in, csrf, web_factory):
    _create(signed_in, csrf)
    server = _server(web_factory)
    response = signed_in.post(f"/inventory/{server.id}/delete", data={"csrf_token": csrf}, follow_redirects=False)
    assert response.status_code == 303
    assert _server(web_factory) is None
    deleted = _audit(web_factory, "server.delete")
    assert len(deleted) == 1 and deleted[0].details["hostname"] == HOST


def test_delete_is_refused_when_discovery_history_exists_and_deactivation_is_offered(
    signed_in, csrf, web_factory, now
):
    from tests.integration.conftest import add_binding

    _create(signed_in, csrf)
    server = _server(web_factory)
    with web_factory.begin() as db:
        row = db.get(Server, server.id)
        add_binding(db, row, "shop.example.internal", match_state="matched", fingerprint="a" * 64, at=now)
    response = signed_in.post(f"/inventory/{server.id}/delete", data={"csrf_token": csrf})
    assert response.status_code == 422
    assert "deactivate it instead" in response.text and "1 bindings" in response.text
    assert _server(web_factory) is not None
    # The deactivation path the message points at works and keeps the row.
    assert signed_in.post(
        f"/inventory/{server.id}/active", data={"csrf_token": csrf, "active": "false"}, follow_redirects=False
    ).status_code == 303
    assert _server(web_factory).is_active is False
    assert _audit(web_factory, "server.deactivate")


def test_inactive_manual_hosts_stay_out_of_the_default_view_but_can_be_filtered(signed_in, csrf, web_factory):
    _create(signed_in, csrf)
    server = _server(web_factory)
    signed_in.post(f"/inventory/{server.id}/active", data={"csrf_token": csrf, "active": "false"})
    assert f'data-server-id="{server.id}"' not in signed_in.get("/inventory").text
    inactive = signed_in.get("/inventory?active=false")
    assert f'data-server-id="{server.id}"' in inactive.text and "Inactive" in inactive.text
    assert f'data-server-id="{server.id}"' in signed_in.get("/inventory?active=all").text


# --- discovery reconciliation keeps manual hosts ------------------------------------------------


def test_discovery_reconciliation_leaves_manual_hosts_active_and_adopts_them_when_listed(web_factory, clock):
    actor = Actor(None, "fixture", "192.0.2.10")
    with web_factory.begin() as db:
        manual = Server(hostname="manual.example.test", inventory_source="manual", is_active=True)
        repository = Server(hostname="repo.example.test", inventory_source="old@rev", is_active=True)
        db.add_all([manual, repository])
        db.flush()
        sync_inventory_servers(db, [], "new@rev", actor, clock())
        assert manual.is_active is True  # never expected in the checkout: absence is not a removal
        assert repository.is_active is False  # a repository row that disappeared is deactivated
        assert manual.inventory_source == "manual"
        # A manual host the repository now lists is adopted by it, keeping its id and history.
        sync_inventory_servers(
            db,
            [InventoryHost("manual.example.test", ("web",), None, WebserverType.NGINX)],
            "new@rev",
            actor,
            clock(),
        )
        assert manual.is_active is True and manual.inventory_source == "new@rev"
        assert list(manual.ansible_groups) == ["web"]


# --- filters, paging and CSRF ---------------------------------------------------------------------


def test_filters_search_and_failing_filters(signed_in, csrf, web_factory):
    _create(signed_in, csrf)
    _repository_host(web_factory, "repo02.example.internal")
    manual = _server(web_factory)
    manual_only = signed_in.get("/inventory?source=manual")
    assert f'data-server-id="{manual.id}"' in manual_only.text
    assert "repo02.example.internal" not in manual_only.text
    assert "repo02.example.internal" in signed_in.get("/inventory?source=repository").text
    assert f'data-server-id="{manual.id}"' in signed_in.get("/inventory?search=web01").text
    assert f'data-server-id="{manual.id}"' not in signed_in.get("/inventory?search=nothing-matches").text
    for broken in ("source=nope", "webserver=iis", "sort=notes", "page_size=0", "active=maybe", "page=0"):
        assert signed_in.get(f"/inventory?{broken}").status_code == 422, broken


def test_a_post_without_the_csrf_token_is_refused(signed_in, web_factory):
    response = signed_in.post("/inventory", data=FORM, follow_redirects=False)
    assert response.status_code == 403
    assert _servers(web_factory) == []


def test_the_management_screens_are_reachable_from_the_screens_that_exist_today(signed_in):
    """The shell owns the final navigation; until it lands, the new screens are linked from the existing ones."""
    assert 'href="/inventory"' in signed_in.get("/servers").text
    assert 'href="/ssh-keys"' in signed_in.get("/settings?tab=worker").text
    assert signed_in.get("/inventory").status_code == 200
    assert signed_in.get("/ssh-keys").status_code == 200
