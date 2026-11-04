"""Shared Slice B management conventions (contract §8) and the manual-first defaults (§3.3, D6).

Database-free: the macros, the success channel and the settings validators are exercised directly.
"""

import html
import json
import re
from http.cookies import SimpleCookie
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Request
from jinja2 import Environment, FileSystemLoader

from app.services.audit import Actor
from app.services.inventory_sources import MANUAL_SOURCE, is_manual
from app.services.settings import (
    SettingsValidationError,
    get_setting,
    is_valid_setting,
    update_settings,
)
from app.web.common import FLASH_COOKIE, read_flash
from app.web.management import done, management_head

ROOT = Path(__file__).resolve().parents[2]
SECRET = b"fixture-management-flash-secret"


def environment() -> Environment:
    env = Environment(loader=FileSystemLoader(str(ROOT / "app/templates")), autoescape=True)
    env.globals["management_head"] = management_head
    return env


def render(source: str, **context) -> str:
    return environment().from_string(source).render(**context)


def _request(**headers: str) -> Request:
    app = SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(session_secret=SECRET)))
    raw = [(name.lower().encode("ascii"), value.encode("ascii")) for name, value in headers.items()]
    return Request({"type": "http", "method": "POST", "path": "/inventory", "headers": raw, "app": app})


def _flash_notes(response) -> tuple[str, ...]:
    value = SimpleCookie(response.headers["set-cookie"])[FLASH_COOKIE].value
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/inventory",
            "headers": [(b"cookie", f"{FLASH_COOKIE}={value}".encode("ascii"))],
            "app": SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(session_secret=SECRET))),
        }
    )
    return read_flash(request)


class _NoRows:
    """A session whose setting lookup finds no stored row: only the code defaults apply."""

    def execute(self, *_args, **_kwargs):
        return self

    def first(self):
        return None


def test_manual_connection_defaults_need_no_seed_row():
    db = _NoRows()
    assert get_setting(db, "inventory.manual_ssh_user") == ""
    assert get_setting(db, "inventory.manual_ssh_port") == 22


def test_manual_connection_defaults_are_validated():
    for value in ("", "deploy", "deploy_1.x-y"):
        assert is_valid_setting("inventory.manual_ssh_user", value), value
    for value in ("Deploy", "-deploy", "deploy user", "a" * 33):
        assert not is_valid_setting("inventory.manual_ssh_user", value), value
    for value in (1, 22, 65535):
        assert is_valid_setting("inventory.manual_ssh_port", value), value
    for value in (0, 65536, "22", True):
        assert not is_valid_setting("inventory.manual_ssh_port", value), value


def test_update_settings_refuses_invalid_manual_defaults_before_writing():
    with pytest.raises(SettingsValidationError) as caught:
        update_settings(
            _NoRows(),
            {"inventory.manual_ssh_user": "Deploy user", "inventory.manual_ssh_port": 0},
            Actor(None, "fixture"),
        )
    assert set(caught.value.errors) == {"inventory.manual_ssh_user", "inventory.manual_ssh_port"}


def test_manual_source_is_the_only_manual_marker():
    assert MANUAL_SOURCE == "manual"
    assert is_manual("manual")
    for value in (None, "", "main:inventory/hosts.yml@0123456", "Manual"):
        assert not is_manual(value), value


def test_done_redirects_natively_and_carries_the_flash():
    response = done(_request(), "/inventory", "Host web01 added.")
    assert response.status_code == 303
    assert response.headers["location"] == "/inventory"
    assert _flash_notes(response) == ("Host web01 added.",)


def test_done_answers_htmx_with_hx_redirect_and_the_same_flash():
    response = done(_request(**{"HX-Request": "true"}), "/ssh-keys", "Trusted 1 host key.")
    assert response.status_code == 200
    assert response.headers["HX-Redirect"] == "/ssh-keys"
    assert response.body == b""
    assert _flash_notes(response) == ("Trusted 1 host key.",)


def test_done_only_treats_the_exact_htmx_header_as_htmx():
    assert done(_request(**{"HX-Request": "false"}), "/inventory", "Host web01 added.").status_code == 303


def test_error_summary_and_field_error_link_and_describe_each_field():
    html = render(
        """
{% from "_management_ui.html.j2" import error_summary, field_error, field_attrs %}
{{ error_summary(errors) }}
<label for="field-hostname">Hostname</label>
<input id="field-hostname" name="hostname"{{ field_attrs(errors, "hostname") }}>
{{ field_error(errors, "hostname") }}
""",
        errors={
            "hostname": ["Enter a hostname.", "Use letters."],
            "notes": "Notes must be at most 2000 characters.",
        },
    )
    assert 'class="error-summary"' in html and 'role="alert"' in html and 'tabindex="-1"' in html
    assert 'href="#field-hostname"' in html and "Enter a hostname." in html and "Use letters." in html
    assert 'href="#field-notes"' in html and "Notes must be at most 2000 characters." in html
    assert '<p class="field-error" id="error-hostname">' in html
    assert 'aria-invalid="true"' in html and 'aria-describedby="error-hostname"' in html
    assert 'id="error-notes"' not in html


def test_error_partials_escape_messages_and_field_names():
    html = render(
        """
{% from "_management_ui.html.j2" import error_summary, field_error %}
{{ error_summary(errors) }}{{ field_error(errors, "hostname") }}
""",
        errors={"hostname": '<script>alert("x")</script>'},
    )
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_confirm_action_discloses_consequence_and_posts_confirm_one():
    html = render(
        '{% from "_management_ui.html.j2" import confirm_action %}'
        '{{ confirm_action("/inventory/7/delete", "Delete host web01", '
        '"Deletion removes the host from the dashboard.", "csrf-value") }}'
    )
    assert '<details class="confirmation">' in html
    assert "<summary>Delete host web01</summary>" in html
    assert "Deletion removes the host from the dashboard." in html
    assert '<form method="post" action="/inventory/7/delete">' in html
    assert 'name="confirm" value="1"' in html
    assert 'name="csrf_token" value="csrf-value"' in html
    assert ">Delete host web01</button>" in html


def test_empty_state_badges_and_the_repository_source_hook():
    html = render(
        """
{% from "_management_ui.html.j2" import empty_state, source_badge, state_badge %}
{% call empty_state("No hosts yet", "Add one, or import from a repository.") %}<a href="#inventory-create">Add a host</a>{% endcall %}
{{ source_badge("manual") }}
{{ source_badge("main:inventory/hosts.yml@0123456789abcdef") }}
{{ source_badge("<script>alert(1)</script>") }}
{{ state_badge(true) }}{{ state_badge(false) }}
"""
    )
    assert "No hosts yet" in html and 'class="empty-state-actions"' in html
    assert '<a href="#inventory-create">Add a host</a>' in html
    assert "Manual" in html
    assert "Repository · <code>main:inventory/hosts.yml@0123456</code>" in html
    assert "0123456789abcdef" not in html  # the badge only shows the short revision
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "Active" in html and "Inactive" in html


def test_management_head_links_management_styles_and_configures_htmx():
    markup = str(management_head("/static/pages/inventory-hosts.css"))
    assert '<link rel="stylesheet" href="/static/pages/management.css">' in markup
    assert '<link rel="stylesheet" href="/static/pages/inventory-hosts.css">' in markup
    meta = re.search(r'<meta name="htmx-config" content="([^"]+)">', markup)
    assert meta is not None
    config = json.loads(html.unescape(meta.group(1)))
    rules = {rule["code"]: rule for rule in config["responseHandling"]}
    assert rules["422"]["swap"] is True
    # A 422 must keep the form's hx-select panel filter (C4) so the panel is re-rendered in place.
    assert "select" not in rules["422"]
    assert rules["403"]["swap"] is True and rules["403"]["target"] == "#main-content"
    # A 403 leaves the form's hx-select("#inventory-panel"/"#ssh-host-keys-panel") in force unless the
    # rule overrides it, but the error page has no management panel; select the main region instead.
    assert rules["403"]["select"] == "#main-content"
    assert rules["403"]["swapOverride"] == "outerHTML"
    assert rules["[45].."]["swap"] is False and rules["[45].."]["error"] is True
    assert "<script>" not in str(management_head('"><script>alert(1)</script>'))


def _page_context(path: str) -> dict:
    return {
        "request": SimpleNamespace(url=SimpleNamespace(path=path), state=SimpleNamespace(worker_stale=False)),
        "user": SimpleNamespace(display_name="Fixture operator"),
        "navigation": [],
        "status_banner": "",
        "capability_banner": "",
        "flash": (),
        "csrf_token": "preview-only-not-a-valid-token",
        "tz": "UTC",
    }


def test_csrf_error_page_offers_the_main_region_selected_by_the_403_rule():
    page = environment().get_template("error.html.j2").render(
        **(
            _page_context("/inventory")
            | {
                "status": 403,
                "message": "Your form expired. Reload the page and try again.",
                "request_id": "fixture-request-id",
            }
        )
    )
    region = re.search(r'<main id="main-content"[^>]*>(.*?)</main>', page, re.DOTALL)
    assert region is not None
    assert "Your form expired. Reload the page and try again." in region.group(1)


def test_inventory_skeleton_renders_the_empty_state_without_a_repository():
    html = environment().get_template("inventory/list.html.j2").render(
        **(
            _page_context("/inventory")
            | {
                "hosts": [],
                "manual_hosts": 0,
                "repository_configured": False,
                "manual_ssh_user": "",
                "manual_ssh_port": 22,
            }
        )
    )
    assert "No hosts yet" in html and "Repository: not configured" in html
    assert 'href="/settings?tab=inventory"' in html and "Connection defaults" in html


def test_ssh_keys_skeleton_renders_the_empty_trust_store():
    html = environment().get_template("ssh_keys/list.html.j2").render(
        **(_page_context("/ssh-keys") | {"host_keys": []})
    )
    assert "No host keys trusted in the dashboard yet." in html
    assert 'href="/settings?tab=worker"' in html
