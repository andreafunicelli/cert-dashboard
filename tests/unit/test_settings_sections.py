"""Database-free contracts for the consolidated settings read context (UX 3/3 backend support).

The canonical navigation groups Scanning inside Schedule and General inside Maintenance. The legacy
tabs, routes and panel contracts must keep working; these tests pin the additive context schema and the
422 precedence rule without a database or a rendered template.
"""

from types import SimpleNamespace

import pytest
from fastapi.responses import HTMLResponse
from starlette.datastructures import FormData

from app.web import settings as settings_web

STORED = {
    "scan.timeout_seconds": 15,
    "scan.daily_at": "01:30",
    "scan.enabled": False,
    "discovery.nightly_at": "02:10",
    "discovery.enabled": True,
    "expiry_check.daily_at": "06:00",
    "digest.daily_at": "06:30",
    "cleanup.daily_at": "05:00",
    "cleanup.enabled": False,
    "ui.timezone": "Europe/Rome",
    "retention.days": 180,
}


class _Session:
    def __enter__(self):
        return object()

    def __exit__(self, *exc_info):
        return False


def _request(headers=None, query=None):
    state = SimpleNamespace(
        session=SimpleNamespace(csrf_token="fixture-csrf"),
        factory=_Session,
        clock=lambda: None,
    )
    return SimpleNamespace(
        app=SimpleNamespace(state=state), state=state, headers=headers or {}, query_params=query or {}
    )


@pytest.fixture
def rendered(monkeypatch):
    """Capture the template context ``_page`` produces, whichever render path it takes."""
    captured: dict = {"context": {}, "status": None, "block": None}

    def render_page(request, name, status=200, **context):
        captured.update(context=context, status=status, block=None)
        return HTMLResponse("page", status)

    def render_fragment(request, name, block, status=200, **context):
        captured.update(context=context, status=status, block=block)
        return HTMLResponse("panel", status)

    monkeypatch.setattr(settings_web, "get_setting", lambda db, key: STORED.get(key, ""))
    monkeypatch.setattr(settings_web, "display_timezone", lambda db: "UTC")
    monkeypatch.setattr(settings_web, "latest_smtp_test", lambda db: None)
    monkeypatch.setattr(settings_web, "notification_failures", lambda db: [])
    monkeypatch.setattr(
        settings_web,
        "inventory_status",
        lambda db, now: {
            "configured": False,
            "last_test": None,
            "worker": {"reporting": False, "ssh_key_present": None, "known_hosts_present": None},
        },
    )
    monkeypatch.setattr(settings_web, "_trust_context", lambda db: {"anchor": "stub"})
    monkeypatch.setattr(settings_web, "_status_context", lambda request, db: {"snapshot": "stub"})
    monkeypatch.setattr(settings_web, "_render", render_page)
    monkeypatch.setattr(settings_web, "render_block", render_fragment)
    return captured


def _page(rendered, tab, status=200, values=None, errors=None, headers=None, query=None):
    response = settings_web._page(_request(headers, query), tab, status, values, errors)
    assert response.status_code == status
    return rendered["context"]


def test_canonical_section_tabs_omit_the_legacy_tabs_and_carry_the_group_labels():
    assert settings_web._SECTION_TABS == [
        {"name": "smtp", "label": "SMTP"},
        {"name": "alerts", "label": "Alerts"},
        {"name": "inventory", "label": "Inventory repository"},
        {"name": "deployment", "label": "Deployment"},
        {"name": "schedule", "label": "Schedule and scans"},
        {"name": "trust", "label": "Trust anchors"},
        {"name": "status", "label": "Status"},
        {"name": "maintenance", "label": "System and maintenance"},
        {"name": "branding", "label": "Branding"},
        {"name": "worker", "label": "Worker"},
    ]


def test_inventory_repository_copy_and_the_shared_no_inventory_sentence():
    from app.services.inventory_sources import NO_INVENTORY

    assert settings_web._TAB_LABELS["inventory"] == "Inventory repository"
    assert settings_web._NO_INVENTORY == NO_INVENTORY
    assert settings_web._WARNINGS["inventory_not_configured"] == NO_INVENTORY
    assert NO_INVENTORY == "No inventory: add a host in Inventory or configure a repository."


def test_legacy_tabs_keep_every_entry_scanning_and_general_included():
    assert [item["name"] for item in settings_web._TAB_LINKS] == [
        "smtp",
        "alerts",
        "inventory",
        "deployment",
        "scanning",
        "schedule",
        "general",
        "trust",
        "status",
        "maintenance",
        "branding",
        "worker",
    ]


def test_schedule_exposes_scanning_as_its_related_section(rendered):
    context = _page(rendered, "schedule", query={"saved": "1"})

    assert context["tab"] == "schedule"
    assert context["tab_label"] == "Schedule"
    assert context["section_tab"] == "schedule"
    assert context["section_label"] == "Schedule and scans"
    assert context["section_tabs"] is settings_web._SECTION_TABS
    assert context["tabs"] is settings_web._TAB_LINKS
    assert context["saved"] is True
    assert context["fields"] is settings_web._TAB_FIELDS["schedule"]
    [related] = context["related_sections"]
    assert set(related) == {"tab", "label", "fields", "values", "errors", "saved"}
    assert related["tab"] == "scanning"
    assert related["label"] == "Scanning"
    assert related["fields"] is settings_web._TAB_FIELDS["scanning"]
    assert related["values"] == {"timeout_seconds": 15, "daily_at": "01:30", "enabled": False}
    assert related["errors"] == {}
    assert related["saved"] is False


def test_scanning_keeps_its_own_contract_and_selects_schedule_in_the_canonical_nav(rendered):
    context = _page(rendered, "scanning")

    assert context["tab"] == "scanning"
    assert context["tab_label"] == "Scanning"
    assert context["fields"] is settings_web._TAB_FIELDS["scanning"]
    assert context["values"] == {"timeout_seconds": 15, "daily_at": "01:30", "enabled": False}
    assert context["errors"] == {}
    assert context["section_tab"] == "schedule"
    assert context["section_label"] == "Schedule and scans"
    [related] = context["related_sections"]
    assert related["tab"] == "schedule"
    assert related["label"] == "Schedule"
    assert related["values"]["discovery_nightly_at"] == "02:10"


def test_maintenance_exposes_general_as_its_related_section(rendered):
    context = _page(rendered, "maintenance")

    assert context["tab"] == "maintenance"
    assert context["section_tab"] == "maintenance"
    assert context["section_label"] == "System and maintenance"
    [related] = context["related_sections"]
    assert related["tab"] == "general"
    assert related["label"] == "General"
    assert related["fields"] is settings_web._TAB_FIELDS["general"]
    assert related["values"] == {"timezone": "Europe/Rome", "retention_days": 180}
    assert related["errors"] == {} and related["saved"] is False


def test_general_keeps_its_own_contract_and_gets_the_maintenance_panel_context(rendered):
    context = _page(rendered, "general")

    assert context["tab"] == "general"
    assert context["tab_label"] == "General"
    assert context["values"] == {"timezone": "Europe/Rome", "retention_days": 180}
    assert context["section_tab"] == "maintenance"
    assert context["section_label"] == "System and maintenance"
    assert context["snapshot"] == "stub"  # the related Maintenance panel renders on this page
    [related] = context["related_sections"]
    assert related == {
        "tab": "maintenance",
        "label": "Maintenance",
        "fields": (),
        "values": {},
        "errors": {},
        "saved": False,
    }


@pytest.mark.parametrize("tab", ["smtp", "alerts", "inventory", "deployment", "trust", "status"])
def test_non_grouped_tabs_have_no_related_sections(rendered, tab):
    context = _page(rendered, tab)

    assert context["tab"] == tab
    assert context["section_tab"] == tab
    assert context["section_label"] == settings_web._SECTION_LABELS[tab]
    assert context["related_sections"] == []


def test_htmx_422_keeps_refused_values_and_errors_only_in_the_original_section(rendered):
    response = settings_web._refuse(
        _request(headers={"HX-Request": "true"}),
        "scanning",
        FormData([("daily_at", "25:00"), ("timeout_seconds", "15")]),
        {"daily_at": ["must be HH:MM"]},
    )

    assert response.status_code == 422
    assert rendered["status"] == 422 and rendered["block"] == "panel"
    context = rendered["context"]
    assert context["tab"] == "scanning"
    assert context["values"]["daily_at"] == "25:00"
    assert context["values"]["timeout_seconds"] == "15"
    assert context["errors"] == {"daily_at": ["must be HH:MM"]}
    [related] = context["related_sections"]
    assert related["tab"] == "schedule"
    assert related["values"]["discovery_nightly_at"] == "02:10"  # stored value, never the refused text
    assert related["errors"] == {} and related["saved"] is False


def test_native_422_for_scanning_returns_the_whole_page_context(rendered):
    response = settings_web._refuse(
        _request(), "scanning", FormData([("timeout_seconds", "0")]), {"timeout_seconds": ["is too small"]}
    )

    assert response.status_code == 422
    assert rendered["status"] == 422 and rendered["block"] is None
    assert rendered["context"]["values"]["timeout_seconds"] == "0"
    assert rendered["context"]["related_sections"][0]["tab"] == "schedule"


def test_native_422_for_general_includes_the_related_maintenance_section(rendered):
    response = settings_web._refuse(
        _request(), "general", FormData([("timezone", "Mars/Olympus")]), {"timezone": ["is not a valid time zone"]}
    )

    assert response.status_code == 422
    assert rendered["status"] == 422 and rendered["block"] is None
    context = rendered["context"]
    assert context["tab"] == "general"
    assert context["values"]["timezone"] == "Mars/Olympus"
    assert context["errors"] == {"timezone": ["is not a valid time zone"]}
    [related] = context["related_sections"]
    assert related["tab"] == "maintenance" and related["values"] == {} and related["errors"] == {}


def test_unknown_field_is_refused_without_leaking_into_the_related_section(rendered):
    response = settings_web._handle_post(
        _request(headers={"HX-Request": "true"}),
        "scanning",
        FormData([("discovery_nightly_at", "value-that-must-not-persist-77")]),
    )

    assert response.status_code == 422
    context = rendered["context"]
    assert context["errors"] == {"form": [settings_web._UNRECOGNISED]}
    assert "value-that-must-not-persist-77" not in repr(context["values"])
    assert "value-that-must-not-persist-77" not in repr(context["related_sections"])
