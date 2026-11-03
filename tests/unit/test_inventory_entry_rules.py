"""Manual inventory entries: the field rules, before any database or HTTP layer (spec 4.7, 6.1).

The database half (uniqueness, delete protection, discovery reconciliation) needs PostgreSQL and lives
in ``tests/integration/test_inventory_management_http.py``. Everything here is pure.
"""

import pytest

from app.models.enums import WebserverType
from app.services.inventory_entries import (
    MANUAL_SOURCE,
    InventoryEntryError,
    parse_entry,
)


def _error(field_expected, form):
    with pytest.raises(InventoryEntryError) as raised:
        parse_entry(form)
    assert raised.value.field == field_expected
    assert raised.value.message
    return raised.value


def test_parse_entry_trims_and_normalizes_every_field():
    fields = parse_entry(
        {
            "hostname": "  web01.example.internal ",
            "display_name": "  Web  01 ",
            "connection_address": "",
            "webserver": "nginx",
            "ansible_groups": "web, tls  web ,,",
            "notes": " Rack 4 ",
        }
    )
    assert fields.hostname == "web01.example.internal"
    assert fields.display_name == "Web  01"
    assert fields.connection_address is None
    assert fields.webserver is WebserverType.NGINX
    assert fields.ansible_groups == ("web", "tls")
    assert fields.notes == "Rack 4"


def test_parse_entry_leaves_optional_fields_empty_without_echoing_blank_strings():
    fields = parse_entry({"hostname": "db01"})
    assert fields.display_name is None
    assert fields.connection_address is None
    assert fields.webserver is None
    assert fields.ansible_groups == ()
    assert fields.notes is None


def test_parse_entry_keeps_a_connection_address_that_differs_from_the_hostname():
    fields = parse_entry({"hostname": "web01.example.internal", "connection_address": "10.0.0.11"})
    assert fields.connection_address == "10.0.0.11"


def test_parse_entry_accepts_ipv4_ipv6_and_underscore_names_ansible_actually_accepts():
    for hostname in ("10.0.0.11", "2001:db8::11", "web_01.example.internal", "a", "3scale-gateway"):
        assert parse_entry({"hostname": hostname}).hostname == hostname


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "   ",
        "web 01",
        "-web.example",
        "web-.example",
        "web..example",
        "web.example.",
        ".web.example",
        "web01/example",
        "web01\nexample",
        "wéb01.example",
        "a" * 254,
    ],
)
def test_parse_entry_rejects_hostnames_ansible_cannot_address(hostname):
    _error("hostname", {"hostname": hostname})


def test_parse_entry_rejects_an_unknown_webserver_value():
    error = _error("webserver", {"hostname": "web01", "webserver": "iis"})
    assert "nginx" in error.message and "Apache" in error.message


def test_parse_entry_treats_auto_as_no_webserver_choice():
    assert parse_entry({"hostname": "web01", "webserver": ""}).webserver is None
    assert parse_entry({"hostname": "web01", "webserver": "apache"}).webserver is WebserverType.APACHE


@pytest.mark.parametrize("group", ["all", "ungrouped", "a" * 65, "wéb", "wéb,web"])
def test_parse_entry_rejects_groups_that_are_reserved_or_not_a_single_token(group):
    error = _error("ansible_groups", {"hostname": "web01", "ansible_groups": group})
    assert "group" in error.message.lower()


def test_parse_entry_rejects_more_groups_than_a_host_can_reasonably_carry():
    _error("ansible_groups", {"hostname": "web01", "ansible_groups": ",".join(f"g{n}" for n in range(65))})


@pytest.mark.parametrize(
    ("field", "value", "limit"),
    [
        ("display_name", "x" * 201, 200),
        ("connection_address", "x" * 254, 253),
        ("notes", "x" * 2001, 2000),
    ],
)
def test_parse_entry_rejects_text_beyond_the_column_limits(field, value, limit):
    error = _error(field, {"hostname": "web01", field: value})
    assert str(limit) in error.message


def test_parse_entry_rejects_a_connection_address_that_is_not_a_host():
    _error("connection_address", {"hostname": "web01", "connection_address": "10.0.0.11:22"})


def test_parse_entry_rejects_control_characters_in_free_text():
    _error("display_name", {"hostname": "web01", "display_name": "web\x00one"})
    _error("notes", {"hostname": "web01", "notes": "rack 4\x00cabinet 2"})


def test_parse_entry_keeps_line_breaks_in_notes_but_normalizes_them():
    fields = parse_entry({"hostname": "web01", "notes": "rack 4\r\ncabinet 2\ttop"})
    assert fields.notes == "rack 4\ncabinet 2\ttop"


def test_manual_source_is_a_stable_marker_distinct_from_a_repository_revision():
    # ``inventory_source`` holds "<ref>:<path>@<rev>" for repository rows (spec 6.1); a manual row must
    # never look like one, so reconciliation can tell them apart without a new column.
    assert MANUAL_SOURCE == "manual"
    assert "@" not in MANUAL_SOURCE and ":" not in MANUAL_SOURCE
