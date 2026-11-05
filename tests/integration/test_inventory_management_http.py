"""Inventory management HTTP routes (Slice B INV): CRUD, validation, filters, empty states.

Real PostgreSQL through the module's private ``web_factory`` database and the real HTTP stack. Every test
runs with ``inventory.repo_url`` unset unless it says otherwise: manual hosts must work with no repository
configured (D1), and no response may redirect outside the dashboard (C10).
"""

import base64
import html
import json
from datetime import UTC, datetime
from http.cookies import SimpleCookie

import pytest
from sqlalchemy import func, select, text

from app.models import AuditLog, Binding, Job, Server
from app.models.enums import JobType, WebserverType
from app.services.settings import get_setting
from app.web.common import FLASH_COOKIE

URL = "/inventory"
MANUAL = "manual"
REPOSITORY = "main:inventory.yml@abc1234"


@pytest.fixture
def clean_inventory(web_factory):
    """The module database is shared by every test here; each one starts and ends with no hosts or settings."""

    def clear():
        with web_factory.begin() as db:
            db.execute(text("DELETE FROM scan_result"))
            db.execute(text("DELETE FROM endpoint"))
            db.execute(text("DELETE FROM binding"))
            db.execute(text("DELETE FROM job_host"))
            db.execute(text("DELETE FROM job"))
            db.execute(text("DELETE FROM server"))
            db.execute(text("DELETE FROM app_setting WHERE key LIKE 'inventory.%'"))

    clear()
    yield clear
    clear()


def _post(client, url, **data):
    return client.post(url, data={"csrf_token": client.fixture_csrf, **data}, follow_redirects=False)


def _flash(response) -> list[str]:
    raw = response.headers.get("set-cookie")
    assert raw is not None, "the mutation must carry the signed flash cookie"
    value = SimpleCookie(raw)[FLASH_COOKIE].value
    payload = value.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))


def _form(**overrides) -> dict[str, str]:
    data = {
        "hostname": "web01.example.test",
        "display_name": "",
        "connection_address": "",
        "webserver": "",
        "groups": "",
        "notes": "",
    }
    data.update(overrides)
    return data


def _seed(
    factory,
    hostname="web01.example.test",
    *,
    source=MANUAL,
    active=True,
    groups=(),
    **extra,
) -> int:
    with factory.begin() as db:
        server = Server(
            hostname=hostname,
            inventory_source=source,
            is_active=active,
            ansible_groups=list(groups),
            **extra,
        )
        db.add(server)
        db.flush()
        return server.id


def _stored(factory, server_id) -> dict | None:
    with factory.begin() as db:
        server = db.get(Server, server_id)
        if server is None:
            return None
        return {
            "hostname": server.hostname,
            "display_name": server.display_name,
            "connection_address": server.connection_address,
            "groups": list(server.ansible_groups),
            "webserver": server.webserver,
            "source": server.inventory_source,
            "is_active": server.is_active,
            "notes": server.notes,
        }


def _audits(factory, action, target_id) -> list[AuditLog]:
    """Audit rows are append-only and outlive the fixture cleanup, so always scope by the target id."""
    target = AuditLog.target_id.is_(None) if target_id is None else AuditLog.target_id == str(target_id)
    with factory.begin() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.action == action, target).order_by(AuditLog.id)))


def _add_binding(factory, server_id) -> None:
    with factory.begin() as db:
        db.add(
            Binding(
                server_id=server_id,
                webserver=WebserverType.NGINX,
                vhost_name="web01.example.test",
                vhost_names=["web01.example.test"],
                port=443,
                config_file="/etc/nginx/conf.d/web01.conf",
                cert_path="/etc/ssl/web01.pem",
                key_path="/etc/ssl/web01.key",
                match_state="matched",
                last_seen_at=datetime.now(UTC),
            )
        )


def _configure_repository(factory, url="https://git.example.test/inventory.git") -> None:
    with factory.begin() as db:
        db.execute(
            text(
                "INSERT INTO app_setting (key, value, updated_at) VALUES ('inventory.repo_url', :value, now())"
            ),
            {"value": json.dumps(url)},
        )


def _host_ids(page: str) -> list[int]:
    import re

    return [int(value) for value in re.findall(r'data-server-id="(\d+)"', page)]


# --- create ----------------------------------------------------------------------------------------


def test_create_manual_host_without_a_repository_flashes_and_audits(signed_in, web_factory, clean_inventory):
    response = _post(
        signed_in,
        URL,
        hostname="WEB01.Example.TEST",
        display_name="Web 01",
        groups="web, prod",
        webserver="nginx",
        notes="primary",
    )
    assert response.status_code == 303
    assert response.headers["location"] == URL
    assert _flash(response) == ["Host web01.example.test added."]
    with web_factory.begin() as db:
        server = db.scalars(select(Server)).one()
        server_id = server.id
        assert server.hostname == "web01.example.test"
        assert server.inventory_source == MANUAL
        assert server.is_active is True
        assert list(server.ansible_groups) == ["web", "prod"]
        assert server.webserver is WebserverType.NGINX
    [audit] = _audits(web_factory, "server.create", server_id)
    assert (audit.target_type, audit.details["hostname"], audit.details["source"]) == (
        "server",
        "web01.example.test",
        MANUAL,
    )


def test_create_htmx_navigates_and_shows_the_flash_on_the_next_page(signed_in, web_factory, clean_inventory):
    response = signed_in.post(
        URL, data={"csrf_token": signed_in.fixture_csrf, **_form()}, headers={"HX-Request": "true"}
    )
    assert response.status_code == 200
    assert response.headers["HX-Redirect"] == URL
    signed_in.cookies.set(FLASH_COOKIE, SimpleCookie(response.headers["set-cookie"])[FLASH_COOKIE].value)
    page = signed_in.get(URL).text
    assert 'data-banner="flash"' in page and "Host web01.example.test added." in page


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"hostname": ""}, "Enter a hostname."),
        ({"hostname": "-bad"}, "Use letters, digits, dots, hyphens or underscores (or an IP address)"),
        (
            {"hostname": "fe80::1%x y"},
            "Use letters, digits, dots, hyphens or underscores (or an IP address)",
        ),
        ({"display_name": "x" * 201}, "Display name must be at most 200 characters"),
        ({"connection_address": "user@web01"}, "Enter a hostname or IP address without a user or port."),
        (
            {"connection_address": "::1%-oProxyCommand=id"},
            "Enter a hostname or IP address without a user or port.",
        ),
        ({"groups": "web-prod"}, "Group names use letters, digits and underscores"),
        ({"groups": "all"}, '"all" and "ungrouped" are reserved by Ansible.'),
        ({"groups": " ".join(f"g{index}" for index in range(65))}, "At most 64 groups."),
        ({"notes": "x" * 2001}, "Notes must be at most 2000 characters."),
    ],
)
def test_create_refuses_invalid_input_inline_with_the_previous_values(
    signed_in, web_factory, clean_inventory, data, message
):
    response = _post(signed_in, URL, **{**_form(), **data})
    assert response.status_code == 422
    body = html.unescape(response.text)
    assert message in body
    assert 'aria-invalid="true"' in response.text
    assert 'id="main-content"' in response.text
    for value in data.values():
        if len(value) < 250:
            assert value in body
    with web_factory.begin() as db:
        assert db.scalar(select(func.count()).select_from(Server)) == 0


def test_create_refuses_a_duplicate_of_a_manual_host_naming_source_and_state(
    signed_in, web_factory, clean_inventory
):
    _seed(web_factory, "web01.example.test")
    response = _post(signed_in, URL, **_form())
    assert response.status_code == 422
    assert "A host named web01.example.test already exists (Manual, active)." in response.text


def test_create_refuses_a_duplicate_of_an_inactive_repository_host(signed_in, web_factory, clean_inventory):
    _seed(web_factory, "web01.example.test", source=REPOSITORY, active=False)
    response = _post(signed_in, URL, **_form())
    assert response.status_code == 422
    assert "A host named web01.example.test already exists (Repository, inactive)." in response.text


def test_create_requires_csrf(signed_in, web_factory, clean_inventory):
    response = signed_in.post(URL, data=_form(), follow_redirects=False)
    assert response.status_code == 403
    with web_factory.begin() as db:
        assert db.scalar(select(func.count()).select_from(Server)) == 0


# --- edit ------------------------------------------------------------------------------------------


def test_edit_manual_host_updates_every_field_and_audits_the_changes(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "web01.example.test", groups=["web"], notes="old")
    response = _post(
        signed_in,
        f"/inventory/{server_id}/edit",
        **_form(
            hostname="web01.example.test",
            display_name="Web 01",
            connection_address="192.0.2.10",
            webserver="apache",
            groups="web prod",
            notes="new",
        ),
    )
    assert response.status_code == 303
    assert response.headers["location"] == URL
    assert _flash(response) == ["Host web01.example.test updated."]
    stored = _stored(web_factory, server_id)
    assert stored["display_name"] == "Web 01"
    assert stored["connection_address"] == "192.0.2.10"
    assert stored["groups"] == ["web", "prod"]
    assert stored["webserver"] is WebserverType.APACHE
    assert stored["notes"] == "new"
    [audit] = _audits(web_factory, "server.update", server_id)
    assert audit.details["source"] == MANUAL
    assert audit.details["changes"]["notes"] == {"before": "old", "after": "new"}
    assert audit.details["changes"]["webserver"] == {"before": None, "after": "apache"}


def test_edit_keeps_the_filters_through_a_validated_return_to(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "web01.example.test")
    response = _post(signed_in, f"/inventory/{server_id}/edit", **_form(notes="kept"), return_to="/inventory?q=web")
    assert response.status_code == 303
    assert response.headers["location"] == "/inventory?q=web"


def test_edit_ignores_a_return_to_that_leaves_the_page(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "web01.example.test")
    response = _post(
        signed_in, f"/inventory/{server_id}/edit", **_form(), return_to="https://github.com/elsewhere"
    )
    assert response.status_code == 303
    assert response.headers["location"] == URL


def test_edit_error_reopens_that_rows_form_even_when_a_filter_hides_it(
    signed_in, web_factory, clean_inventory
):
    server_id = _seed(web_factory, "inactive01.example.test", active=False)
    _seed(web_factory, "web01.example.test")
    response = _post(signed_in, f"/inventory/{server_id}/edit?q=web01", **_form(hostname="-bad"))
    assert response.status_code == 422
    assert "Editing <code>inactive01.example.test</code>" in response.text
    assert "Use letters, digits, dots, hyphens or underscores" in response.text
    assert 'id="field-hostname-' + str(server_id) + '"' in response.text
    assert 'aria-describedby="error-hostname-' + str(server_id) + '"' in response.text
    assert 'id="error-hostname-' + str(server_id) + '"' in response.text
    # The create form is untouched: no error on its own field ids.
    assert 'id="error-hostname"' not in response.text
    assert 'value="-bad"' in response.text
    assert _stored(web_factory, server_id)["hostname"] == "inactive01.example.test"


def test_edit_error_reopens_a_row_that_lives_on_a_later_page(signed_in, web_factory, clean_inventory):
    for index in range(55):
        _seed(web_factory, f"host{index:02d}.example.test")
    target = _seed(web_factory, "zz-target.example.test")
    response = _post(signed_in, f"/inventory/{target}/edit", **_form(hostname="bad..name"))
    assert response.status_code == 422
    assert "Editing <code>zz-target.example.test</code>" in response.text
    assert 'id="error-hostname-' + str(target) + '"' in response.text


def test_edit_refuses_unknown_ids(signed_in, clean_inventory):
    response = _post(signed_in, "/inventory/999999/edit", **_form())
    assert response.status_code == 404


def test_hostname_cannot_change_once_the_host_has_history(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "web01.example.test")
    _add_binding(web_factory, server_id)
    response = _post(signed_in, f"/inventory/{server_id}/edit", **_form(hostname="renamed.example.test"))
    assert response.status_code == 422
    assert "A hostname cannot be changed once the host has discovery or deploy history." in response.text
    assert _stored(web_factory, server_id)["hostname"] == "web01.example.test"
    changed = _post(signed_in, f"/inventory/{server_id}/edit", **_form(notes="history kept"))
    assert changed.status_code == 303
    assert _stored(web_factory, server_id)["notes"] == "history kept"


def test_repository_row_edits_only_display_name_and_notes(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "repo01.example.test", source=REPOSITORY, groups=["web"])
    response = _post(
        signed_in,
        f"/inventory/{server_id}/edit",
        hostname="changed.example.test",
        display_name="Repo host",
        connection_address="192.0.2.55",
        webserver="apache",
        groups="db",
        notes="note",
        csrf_token=signed_in.fixture_csrf,
    )
    assert response.status_code == 303
    assert _flash(response) == ["Host repo01.example.test updated."]
    stored = _stored(web_factory, server_id)
    assert stored["hostname"] == "repo01.example.test"
    assert stored["connection_address"] is None
    assert stored["groups"] == ["web"]
    assert stored["webserver"] is None
    assert stored["display_name"] == "Repo host"
    assert stored["notes"] == "note"
    [audit] = _audits(web_factory, "server.update", server_id)
    assert audit.details["source"] == "repository"


def test_repository_row_offers_no_delete_or_state_actions(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "repo01.example.test", source=REPOSITORY)
    page = signed_in.get(URL).text
    assert f'action="/inventory/{server_id}/deactivate"' not in page
    assert f'action="/inventory/{server_id}/delete"' not in page
    assert f'action="/inventory/{server_id}/edit"' in page


# --- deactivate / reactivate -----------------------------------------------------------------------


def test_deactivate_then_reactivate_a_manual_host(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "web01.example.test")
    response = _post(signed_in, f"/inventory/{server_id}/deactivate")
    assert response.status_code == 303
    assert _flash(response) == [
        "Host web01.example.test deactivated. It is no longer discovered or deployed to."
    ]
    assert _stored(web_factory, server_id)["is_active"] is False
    [audit] = _audits(web_factory, "server.deactivate", server_id)
    assert audit.details == {"hostname": "web01.example.test", "source": MANUAL}

    again = _post(signed_in, f"/inventory/{server_id}/deactivate")
    assert again.status_code == 422
    assert "This host is already inactive." in again.text

    reactivated = _post(signed_in, f"/inventory/{server_id}/activate")
    assert reactivated.status_code == 303
    assert _flash(reactivated) == ["Host web01.example.test reactivated."]
    assert _stored(web_factory, server_id)["is_active"] is True
    assert _audits(web_factory, "server.activate", server_id)


def test_deactivate_htmx_answers_with_hx_redirect(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "web01.example.test")
    response = signed_in.post(
        f"/inventory/{server_id}/deactivate",
        data={"csrf_token": signed_in.fixture_csrf},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert response.headers["HX-Redirect"] == URL
    assert _flash(response) == [
        "Host web01.example.test deactivated. It is no longer discovered or deployed to."
    ]


def test_repository_rows_cannot_be_deactivated_or_reactivated(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "repo01.example.test", source=REPOSITORY)
    for action in ("deactivate", "activate"):
        response = _post(signed_in, f"/inventory/{server_id}/{action}")
        assert response.status_code == 422
        assert "Repository hosts are managed in Git." in response.text
    assert _audits(web_factory, "server.deactivate", server_id) == []


# --- delete ----------------------------------------------------------------------------------------


def test_delete_requires_the_confirmation_step(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "web01.example.test")
    response = _post(signed_in, f"/inventory/{server_id}/delete")
    assert response.status_code == 422
    assert "Confirm the action to continue." in response.text
    assert _stored(web_factory, server_id) is not None
    assert _audits(web_factory, "server.delete", server_id) == []


def test_delete_removes_a_manual_host_without_history(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "web01.example.test")
    response = _post(signed_in, f"/inventory/{server_id}/delete", confirm="1")
    assert response.status_code == 303
    assert response.headers["location"] == URL
    assert _flash(response) == ["Host web01.example.test deleted."]
    assert _stored(web_factory, server_id) is None
    [audit] = _audits(web_factory, "server.delete", server_id)
    assert audit.target_id == str(server_id)


def test_delete_is_refused_with_history_and_the_page_offers_deactivation(
    signed_in, web_factory, clean_inventory
):
    server_id = _seed(web_factory, "web01.example.test")
    _add_binding(web_factory, server_id)
    response = _post(signed_in, f"/inventory/{server_id}/delete", confirm="1")
    assert response.status_code == 422
    assert "web01.example.test has discovery or deploy history; deactivate it instead." in response.text
    assert f'action="/inventory/{server_id}/deactivate"' in response.text
    assert _stored(web_factory, server_id) is not None
    assert _audits(web_factory, "server.delete", server_id) == []


def test_every_mutation_answers_htmx_with_hx_redirect(signed_in, web_factory, clean_inventory):
    """C2: htmx gets 200 + HX-Redirect + the flash cookie, so the browser navigates and reads the banner."""
    server_id = _seed(web_factory, "web01.example.test")
    steps = [
        (
            f"/inventory/{server_id}/edit",
            _form(notes="htmx"),
            "Host web01.example.test updated.",
            "server.update",
        ),
        (
            f"/inventory/{server_id}/deactivate",
            {},
            "Host web01.example.test deactivated. It is no longer discovered or deployed to.",
            "server.deactivate",
        ),
        (
            f"/inventory/{server_id}/activate",
            {},
            "Host web01.example.test reactivated.",
            "server.activate",
        ),
        (f"/inventory/{server_id}/delete", {"confirm": "1"}, "Host web01.example.test deleted.", "server.delete"),
    ]
    for url, data, note, action in steps:
        response = signed_in.post(
            url,
            data={"csrf_token": signed_in.fixture_csrf, **data},
            headers={"HX-Request": "true"},
            follow_redirects=False,
        )
        assert response.status_code == 200, url
        assert response.headers["HX-Redirect"].startswith(URL), url
        assert _flash(response) == [note], url
        assert _audits(web_factory, action, server_id), url


def test_refusal_of_an_htmx_request_still_carries_the_panel_to_swap(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "web01.example.test")
    response = signed_in.post(
        f"/inventory/{server_id}/edit",
        data={"csrf_token": signed_in.fixture_csrf, **_form(hostname="-bad")},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 422
    assert 'id="inventory-panel"' in response.text
    assert "Use letters, digits, dots, hyphens or underscores" in response.text


def test_repository_rows_cannot_be_deleted(signed_in, web_factory, clean_inventory):
    server_id = _seed(web_factory, "repo01.example.test", source=REPOSITORY)
    response = _post(signed_in, f"/inventory/{server_id}/delete", confirm="1")
    assert response.status_code == 422
    assert "Repository hosts are managed in Git." in response.text
    assert _stored(web_factory, server_id) is not None


def test_delete_refuses_unknown_ids(signed_in, clean_inventory):
    response = _post(signed_in, "/inventory/999999/delete", confirm="1")
    assert response.status_code == 404


# --- connection defaults ---------------------------------------------------------------------------


def test_connection_defaults_save_and_are_audited(signed_in, web_factory, clean_inventory):
    response = _post(signed_in, "/inventory/connection", ssh_user="deploy_user", ssh_port="2222")
    assert response.status_code == 303
    assert _flash(response) == ["Connection defaults saved."]
    with web_factory.begin() as db:
        assert get_setting(db, "inventory.manual_ssh_user") == "deploy_user"
        assert get_setting(db, "inventory.manual_ssh_port") == 2222
    [audit] = _audits(web_factory, "settings.update", None)
    assert audit.details["changes"]["inventory.manual_ssh_port"] == {"before": 22, "after": 2222}


def test_connection_defaults_refuse_an_invalid_user_and_port(signed_in, web_factory, clean_inventory):
    response = _post(signed_in, "/inventory/connection", ssh_user="Deploy", ssh_port="0")
    assert response.status_code == 422
    assert "Use a POSIX user name (lower-case letters, digits, _ . -)." in response.text
    assert "Enter a port between 1 and 65535." in response.text
    with web_factory.begin() as db:
        assert get_setting(db, "inventory.manual_ssh_user") == ""
        assert get_setting(db, "inventory.manual_ssh_port") == 22


# --- import ----------------------------------------------------------------------------------------


def _discover_jobs(factory) -> int:
    with factory.begin() as db:
        return db.scalar(select(func.count()).select_from(Job).where(Job.type == JobType.DISCOVER))


def test_import_is_disabled_without_a_repository_and_a_forced_post_changes_nothing(
    signed_in, web_factory, clean_inventory
):
    page = signed_in.get(URL).text
    assert "Import from repository" in page
    assert "No inventory repository is configured: set the repository URL first." in page
    forced = _post(signed_in, "/inventory/import")
    assert forced.status_code == 409
    assert _discover_jobs(web_factory) == 0


def test_import_still_needs_a_repository_while_manual_hosts_make_discovery_possible(
    signed_in, web_factory, clean_inventory
):
    """Manual hosts (D1) make `/servers` runnable; import reads Git, so it still needs the repository."""
    _seed(web_factory, "web01.example.test")
    page = signed_in.get(URL).text
    assert "No inventory repository is configured: set the repository URL first." in page
    forced = _post(signed_in, "/inventory/import")
    assert forced.status_code == 409
    assert _discover_jobs(web_factory) == 0


def test_import_with_a_repository_queues_one_discovery(signed_in, web_factory, clean_inventory):
    _configure_repository(web_factory)
    response = _post(signed_in, "/inventory/import")
    assert response.status_code == 303
    assert _flash(response) == [
        "Discovery queued; repository hosts appear here when the worker finishes."
    ]
    assert _discover_jobs(web_factory) == 1


# --- filters, paging and states --------------------------------------------------------------------


def _seed_fixture_set(factory) -> dict[str, int]:
    return {
        "web": _seed(
            factory, "web01.example.test", groups=["web"], webserver=WebserverType.NGINX, display_name="Front end"
        ),
        "db": _seed(factory, "db01.example.test", groups=["db"], webserver=WebserverType.APACHE),
        "repo": _seed(factory, "repo01.example.test", source=REPOSITORY),
        "off": _seed(factory, "off01.example.test", active=False),
    }


def test_filters_search_cover_hostname_display_name_and_address(signed_in, web_factory, clean_inventory):
    ids = _seed_fixture_set(web_factory)
    with web_factory.begin() as db:
        db.execute(
            text("UPDATE server SET connection_address = '192.0.2.77' WHERE id = :id"), {"id": ids["db"]}
        )
    assert _host_ids(signed_in.get(URL + "?q=front").text) == [ids["web"]]
    assert _host_ids(signed_in.get(URL + "?q=db01").text) == [ids["db"]]
    assert _host_ids(signed_in.get(URL + "?q=192.0.2.77").text) == [ids["db"]]


def test_filters_group_source_webserver_and_state(signed_in, web_factory, clean_inventory):
    ids = _seed_fixture_set(web_factory)
    assert _host_ids(signed_in.get(URL + "?group=db").text) == [ids["db"]]
    assert _host_ids(signed_in.get(URL + "?source=repository").text) == [ids["repo"]]
    assert _host_ids(signed_in.get(URL + "?webserver=auto").text) == [ids["repo"]]
    assert _host_ids(signed_in.get(URL + "?state=inactive").text) == [ids["off"]]
    assert set(_host_ids(signed_in.get(URL + "?state=all").text)) == set(ids.values())


def test_invalid_filter_values_fall_back_instead_of_refusing_the_page(signed_in, web_factory, clean_inventory):
    ids = _seed_fixture_set(web_factory)
    page = signed_in.get(URL + "?source=git&webserver=caddy&state=bogus&page=abc&page_size=999")
    assert page.status_code == 200
    assert ids["web"] in _host_ids(page.text)


def test_paging_keeps_the_filters(signed_in, web_factory, clean_inventory):
    for index in range(3):
        _seed(web_factory, f"host{index}.example.test", groups=["web"])
    first = signed_in.get(URL + "?q=host&page_size=2").text
    second = signed_in.get(URL + "?q=host&page_size=2&page=2").text
    assert len(_host_ids(first)) == 2
    assert len(_host_ids(second)) == 1
    assert "page=2" in first


def test_empty_state_offers_adding_a_host_and_the_optional_repository(signed_in, clean_inventory):
    page = signed_in.get(URL).text
    assert "No hosts yet" in page
    assert 'href="#add-host">Add a host' in page
    assert "Configure a repository (optional)" in page
    assert "No inventory repository is configured: set the repository URL first." in page
    assert page.count('action="/inventory/import"') == 0


def test_empty_state_with_a_repository_offers_the_import_action(signed_in, web_factory, clean_inventory):
    _configure_repository(web_factory)
    page = signed_in.get(URL).text
    assert "No hosts yet" in page
    assert page.count('action="/inventory/import"') == 2  # source panel and the empty state


def test_filtered_empty_state_is_distinct_from_the_empty_inventory(signed_in, web_factory, clean_inventory):
    _seed(web_factory, "web01.example.test")
    page = signed_in.get(URL + "?q=nothing-matches").text
    assert "No hosts match these filters" in page
    assert "No hosts yet" not in page
    assert 'href="/inventory">Clear filters' in page


def test_connection_warning_only_appears_for_manual_hosts_without_an_ssh_user(
    signed_in, web_factory, clean_inventory
):
    warning = "Manual hosts connect as the worker's default SSH user. Set the SSH user used on your servers."
    assert warning not in signed_in.get(URL).text
    server_id = _seed(web_factory, "web01.example.test")
    assert warning in signed_in.get(URL).text
    _post(signed_in, "/inventory/connection", ssh_user="deploy_user", ssh_port="22")
    assert warning not in signed_in.get(URL).text
    with web_factory.begin() as db:
        db.execute(text("UPDATE server SET inventory_source = :source WHERE id = :id"), {"source": REPOSITORY, "id": server_id})
    assert warning not in signed_in.get(URL).text
