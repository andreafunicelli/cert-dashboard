"""Slice B management pages serve with no Git repository, SSH key or known_hosts configured.

The database is the module's private ``web_factory`` database; rows a test inserts are removed by
``clean_management_rows`` so the page-level assertions stay order-independent.
"""

import re
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
from fastapi import Request
from sqlalchemy import text

from app.models import Server, SshHostKey
from app.web.common import FLASH_COOKIE
from app.web.management import done

PAGES = ("/inventory", "/ssh-keys", "/users")


def _done_request(secret: bytes, **headers: str) -> Request:
    app = SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(session_secret=secret)))
    raw = [(name.lower().encode("ascii"), value.encode("ascii")) for name, value in headers.items()]
    return Request({"type": "http", "method": "POST", "path": "/inventory", "headers": raw, "app": app})


@pytest.fixture
def clean_management_rows(web_factory):
    def clear():
        with web_factory.begin() as db:
            db.execute(text("DELETE FROM ssh_host_key"))
            db.execute(text("DELETE FROM server"))

    clear()
    yield clear
    clear()


def test_management_pages_render_with_no_repository_ssh_key_or_known_hosts(
    signed_in, clean_management_rows
):
    for path in PAGES:
        response = signed_in.get(path)
        assert response.status_code == 200, path
        assert 'id="main-content"' in response.text, path
    for path in ("/inventory", "/ssh-keys"):
        page = signed_in.get(path).text
        assert 'href="/static/pages/management.css"' in page, path
        assert 'name="htmx-config"' in page, path


def test_inventory_page_states_the_optional_source_and_connection_defaults(
    signed_in, clean_management_rows
):
    page = signed_in.get("/inventory").text
    assert "No hosts yet" in page
    assert "Repository: not configured" in page
    assert 'href="/settings?tab=inventory"' in page
    assert "Connection defaults" in page
    assert "worker&#39;s default SSH user" in page
    assert ">22<" in page or "22" in page


def test_ssh_keys_page_shows_the_empty_trust_store_and_links_the_worker_key(
    signed_in, clean_management_rows
):
    page = signed_in.get("/ssh-keys").text
    assert "No host keys trusted in the dashboard yet." in page
    assert 'href="/settings?tab=worker"' in page


def test_management_pages_redirect_anonymous_users_to_login(client):
    for path in PAGES:
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303, path
        assert response.headers["location"] == "/login", path


def test_manual_hosts_and_trusted_keys_are_stored_without_a_repository(
    signed_in, web_factory, clean_management_rows
):
    with web_factory.begin() as db:
        db.add(Server(hostname="web01.example.test", inventory_source="manual", ansible_groups=["web"]))
        db.add(
            SshHostKey(
                host="web01.example.test",
                key_type="ssh-ed25519",
                public_key="AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnly",
                fingerprint_sha256="SHA256:fixture-only",
                comment="lab host",
            )
        )
    inventory = signed_in.get("/inventory")
    assert inventory.status_code == 200
    assert "web01.example.test" in inventory.text
    assert 'data-source="manual"' in inventory.text
    keys = signed_in.get("/ssh-keys")
    assert keys.status_code == 200
    assert "web01.example.test" in keys.text
    assert "ssh-ed25519" in keys.text and "SHA256:fixture-only" in keys.text


def test_navigation_puts_inventory_first_and_ssh_keys_last_under_infrastructure(signed_in):
    page = signed_in.get("/inventory").text
    start = page.index('class="area-navigation"')
    area = page[start : page.index("</nav>", start)]
    labels = re.findall(r'<a href="(/[^"]*)">([^<]+)</a>', area)
    assert labels[0] == ("/inventory", "Inventory")
    assert labels[-1] == ("/ssh-keys", "SSH keys")


def _flash_value(response) -> str:
    return SimpleCookie(response.headers["set-cookie"])[FLASH_COOKIE].value


def test_done_flash_is_rendered_on_the_next_full_page(signed_in, web_settings):
    response = done(_done_request(web_settings.session_secret), "/inventory", "Host web01 added.")
    signed_in.cookies.set(FLASH_COOKIE, _flash_value(response))
    page = signed_in.get("/inventory")
    assert 'data-banner="flash"' in page.text and "Host web01 added." in page.text


def test_done_htmx_flash_survives_the_redirect(signed_in, web_settings):
    response = done(
        _done_request(web_settings.session_secret, **{"HX-Request": "true"}),
        "/ssh-keys",
        "Trusted 1 host key.",
    )
    assert response.status_code == 200 and response.headers["HX-Redirect"] == "/ssh-keys"
    signed_in.cookies.set(FLASH_COOKIE, _flash_value(response))
    page = signed_in.get(response.headers["HX-Redirect"])
    assert 'data-banner="flash"' in page.text and "Trusted 1 host key." in page.text
