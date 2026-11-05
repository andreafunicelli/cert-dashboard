"""Validation rules for manual inventory hosts (Slice B contract §3.1, §4 INV).

Pure functions only: no database, no HTTP. The route behaviour is covered by
``tests/integration/test_inventory_management_http.py``.
"""

from types import SimpleNamespace

import pytest

from app.models.enums import WebserverType
from app.services.managed_hosts import (
    CONNECTION_SYNTAX,
    DISPLAY_NAME_MAX,
    DISPLAY_NAME_RULE,
    GROUPS_MAX_MESSAGE,
    GROUPS_RESERVED,
    GROUPS_SYNTAX,
    HOSTNAME_EMPTY,
    HOSTNAME_SYNTAX,
    NOTES_MAX,
    NOTES_RULE,
    SSH_PORT_RULE,
    SSH_USER_RULE,
    WEBSERVER_CHOICE,
    HostError,
    HostFilters,
    duplicate_message,
    filter_params,
    normalize_connection_address,
    normalize_display_name,
    normalize_groups,
    normalize_hostname,
    normalize_notes,
    normalize_webserver,
    parse_connection_form,
    parse_filters,
    parse_host_form,
)


def _message(call, field):
    with pytest.raises(HostError) as caught:
        call()
    assert caught.value.field == field
    return caught.value.message


# --- hostname --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("web01.example.test", "web01.example.test"),
        ("WEB01.Example.TEST", "web01.example.test"),
        ("web_01", "web_01"),
        ("  web01  ", "web01"),
        ("192.0.2.10", "192.0.2.10"),
        ("2001:DB8::1", "2001:db8::1"),
        ("::1", "::1"),
        ("fe80::1", "fe80::1"),
    ],
)
def test_hostname_normalizes_to_lower_case_and_keeps_ip_literals(raw, expected):
    assert normalize_hostname(raw) == expected


@pytest.mark.parametrize("raw", ["fe80::1%eth0", "fe80::1%x y", "fe80::1%a\nb", "::1%-oProxyCommand=id"])
def test_hostname_refuses_ipv6_scope_ids(raw):
    """Contract §3.1 allows an IP literal, not a scoped literal: the scope id is free text (CVE-shaped)."""
    assert _message(lambda: normalize_hostname(raw), "hostname") == HOSTNAME_SYNTAX


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "-bad",
        "bad-",
        "bad..name",
        "web01.",
        "a" * 64,
        "web 01",
        "web/01",
        "user@web01",
        "https://web01",
        "web01:22",
        ".".join(["a" * 63] * 5)[:254],
    ],
)
def test_hostname_refuses_invalid_values(raw):
    assert _message(lambda: normalize_hostname(raw), "hostname") in (HOSTNAME_EMPTY, HOSTNAME_SYNTAX)


def test_empty_hostname_has_its_own_message():
    assert _message(lambda: normalize_hostname("  "), "hostname") == HOSTNAME_EMPTY
    assert _message(lambda: normalize_hostname("-bad"), "hostname") == HOSTNAME_SYNTAX


# --- connection address ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "hostname", "expected"),
    [
        ("", "web01", None),
        ("web01", "web01", None),
        ("WEB01.Example.TEST", "web01.example.test", None),
        ("web01.example.test", "web01", "web01.example.test"),
        ("192.0.2.10", "web01", "192.0.2.10"),
        ("2001:DB8::2", "web01", "2001:db8::2"),
        ("fe80::1", "web01", "fe80::1"),
    ],
)
def test_connection_address_is_normalized_and_dropped_when_equal_to_hostname(raw, hostname, expected):
    assert normalize_connection_address(raw, hostname) == expected


@pytest.mark.parametrize("raw", ["fe80::1%eth0", "fe80::1%x y", "fe80::1%a\nb", "::1%-oProxyCommand=id"])
def test_connection_address_refuses_ipv6_scope_ids(raw):
    assert _message(lambda: normalize_connection_address(raw, "web01"), "connection_address") == CONNECTION_SYNTAX


@pytest.mark.parametrize("raw", ["user@web01", "web01:22", "https://web01/x", "-bad", "web 01", "web01/path"])
def test_connection_address_refuses_users_ports_and_paths(raw):
    assert _message(lambda: normalize_connection_address(raw, "web01"), "connection_address") == CONNECTION_SYNTAX


# --- display name and notes ------------------------------------------------------------------------


def test_display_name_blank_becomes_none_and_limits_apply():
    assert normalize_display_name("") is None
    assert normalize_display_name("  ") is None
    assert normalize_display_name("  Web front end  ") == "Web front end"
    assert normalize_display_name("x" * DISPLAY_NAME_MAX) == "x" * DISPLAY_NAME_MAX
    assert _message(lambda: normalize_display_name("x" * (DISPLAY_NAME_MAX + 1)), "display_name") == DISPLAY_NAME_RULE
    assert _message(lambda: normalize_display_name("two\nlines"), "display_name") == DISPLAY_NAME_RULE
    assert _message(lambda: normalize_display_name("carriage\rreturn"), "display_name") == DISPLAY_NAME_RULE


def test_notes_blank_becomes_none_and_the_limit_applies():
    assert normalize_notes("") is None
    assert normalize_notes("  ") is None
    assert normalize_notes("first line\nsecond line") == "first line\nsecond line"
    assert normalize_notes("x" * NOTES_MAX) == "x" * NOTES_MAX
    assert _message(lambda: normalize_notes("x" * (NOTES_MAX + 1)), "notes") == NOTES_RULE


# --- groups ----------------------------------------------------------------------------------------


def test_groups_split_on_commas_and_whitespace_keeping_order_and_deduping():
    assert normalize_groups("web, prod") == ("web", "prod")
    assert normalize_groups("web prod,web") == ("web", "prod")
    assert normalize_groups("") == ()
    assert normalize_groups("   ") == ()
    assert normalize_groups("db_1, DB2") == ("db_1", "DB2")


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("1web", GROUPS_SYNTAX),
        ("web-prod", GROUPS_SYNTAX),
        ("all", GROUPS_RESERVED),
        ("ungrouped", GROUPS_RESERVED),
        ("web, all", GROUPS_RESERVED),
        ("a" * 65, GROUPS_SYNTAX),
    ],
)
def test_groups_refuse_invalid_and_reserved_names(raw, message):
    assert _message(lambda: normalize_groups(raw), "groups") == message


def test_groups_refuse_more_than_sixty_four_names():
    raw = " ".join(f"g{index}" for index in range(65))
    assert _message(lambda: normalize_groups(raw), "groups") == GROUPS_MAX_MESSAGE
    assert len(normalize_groups(" ".join(f"g{index}" for index in range(64)))) == 64


# --- webserver -------------------------------------------------------------------------------------


def test_webserver_accepts_blank_nginx_and_apache_only():
    assert normalize_webserver("") is None
    assert normalize_webserver("nginx") is WebserverType.NGINX
    assert normalize_webserver("Apache") is WebserverType.APACHE
    assert _message(lambda: normalize_webserver("caddy"), "webserver") == WEBSERVER_CHOICE


# --- whole form ------------------------------------------------------------------------------------


def test_parse_host_form_returns_normalized_fields():
    fields, errors = parse_host_form(
        {
            "hostname": "WEB01.Example.TEST",
            "display_name": " Web 01 ",
            "connection_address": "192.0.2.10",
            "webserver": "nginx",
            "groups": "web, prod",
            "notes": "note",
        }
    )
    assert errors == {}
    assert fields.hostname == "web01.example.test"
    assert fields.display_name == "Web 01"
    assert fields.connection_address == "192.0.2.10"
    assert fields.webserver is WebserverType.NGINX
    assert fields.groups == ("web", "prod")
    assert fields.notes == "note"


def test_parse_host_form_reports_every_invalid_field_at_once():
    fields, errors = parse_host_form(
        {
            "hostname": "-bad",
            "display_name": "x" * 201,
            "connection_address": "user@web01",
            "webserver": "caddy",
            "groups": "all",
            "notes": "x" * 2001,
        }
    )
    assert fields is None
    assert set(errors) == {"hostname", "display_name", "connection_address", "webserver", "groups", "notes"}
    assert all(len(messages) >= 1 for messages in errors.values())


def test_parse_host_form_reports_a_missing_hostname():
    fields, errors = parse_host_form({"hostname": "", "display_name": "", "groups": "", "notes": ""})
    assert fields is None
    assert errors == {"hostname": [HOSTNAME_EMPTY]}


# --- duplicate message -----------------------------------------------------------------------------


def test_duplicate_message_names_the_existing_source_and_state():
    manual = SimpleNamespace(inventory_source="manual", is_active=True)
    repository = SimpleNamespace(inventory_source="main:inventory.yml@abc1234", is_active=False)
    assert duplicate_message(manual, "web01") == "A host named web01 already exists (Manual, active)."
    assert duplicate_message(repository, "web01") == "A host named web01 already exists (Repository, inactive)."


# --- connection defaults ---------------------------------------------------------------------------


def test_connection_form_accepts_empty_user_and_defaults_the_port():
    changes, errors = parse_connection_form({"ssh_user": "", "ssh_port": ""})
    assert errors == {}
    assert changes == {"inventory.manual_ssh_user": "", "inventory.manual_ssh_port": 22}


def test_connection_form_normalizes_user_and_port():
    changes, errors = parse_connection_form({"ssh_user": "deploy_user", "ssh_port": "2222"})
    assert errors == {}
    assert changes == {"inventory.manual_ssh_user": "deploy_user", "inventory.manual_ssh_port": 2222}


@pytest.mark.parametrize(
    ("form", "field", "message"),
    [
        ({"ssh_user": "Deploy", "ssh_port": "22"}, "ssh_user", SSH_USER_RULE),
        ({"ssh_user": "-deploy", "ssh_port": "22"}, "ssh_user", SSH_USER_RULE),
        ({"ssh_user": "u" * 33, "ssh_port": "22"}, "ssh_user", SSH_USER_RULE),
        ({"ssh_user": "", "ssh_port": "0"}, "ssh_port", SSH_PORT_RULE),
        ({"ssh_user": "", "ssh_port": "65536"}, "ssh_port", SSH_PORT_RULE),
        ({"ssh_user": "", "ssh_port": "ssh"}, "ssh_port", SSH_PORT_RULE),
        ({"ssh_user": "", "ssh_port": "-1"}, "ssh_port", SSH_PORT_RULE),
    ],
)
def test_connection_form_refuses_invalid_user_and_port(form, field, message):
    changes, errors = parse_connection_form(form)
    assert changes is None
    assert errors == {field: [message]}


def test_connection_form_reports_user_and_port_together():
    changes, errors = parse_connection_form({"ssh_user": "Deploy", "ssh_port": "0"})
    assert changes is None
    assert set(errors) == {"ssh_user", "ssh_port"}


# --- filters ---------------------------------------------------------------------------------------


def test_filters_default_and_fall_back_on_invalid_values():
    assert parse_filters({}) == HostFilters()
    assert parse_filters({"state": "bogus", "source": "git", "webserver": "caddy"}).state == "active"
    assert parse_filters({"source": "git"}).source is None
    assert parse_filters({"webserver": "caddy"}).webserver is None


def test_filters_keep_valid_values_and_bound_the_search_text():
    filters = parse_filters(
        {"q": "  web  ", "group": "web", "source": "repository", "webserver": "auto", "state": "all"}
    )
    assert filters == HostFilters(q="web", group="web", source="repository", webserver="auto", state="all")
    assert len(parse_filters({"q": "x" * 500}).q) == 200


def test_filter_params_omit_defaults_so_urls_stay_short():
    assert filter_params(HostFilters()) == {}
    assert filter_params(HostFilters(q="web", state="inactive")) == {"q": "web", "state": "inactive"}
