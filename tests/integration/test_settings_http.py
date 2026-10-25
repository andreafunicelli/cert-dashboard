"""Task 23 (part A): typed settings service and the seven configuration tabs (real Postgres, real HTTP)."""

import importlib
import json

import pytest
from sqlalchemy import select

from app.models import AppSetting, AuditLog
from app.services.audit import Actor
from app.services.settings import SettingsValidationError, get_setting, update_settings
from tests.integration.conftest import create_login_user

SCHEMA = importlib.import_module("app.migrations.versions.0001_v1_schema")
DEFAULTS = SCHEMA.DEFAULT_SETTINGS


# --- fixtures --------------------------------------------------------------------------------------


@pytest.fixture
def web_factory(queue_factory):
    """A private, migrated database per test: settings and audit rows are committed by design."""
    return queue_factory


@pytest.fixture
def web_user(web_factory):
    return create_login_user(web_factory, "admin")


@pytest.fixture
def csrf(signed_in):
    return signed_in.fixture_csrf


@pytest.fixture
def db(web_factory):
    with web_factory() as session:
        yield session


@pytest.fixture
def admin(web_user):
    return Actor(web_user.id, web_user.username, "192.0.2.10", "fixture-browser")


def _audits(factory):
    with factory() as session:
        return list(
            session.scalars(select(AuditLog).where(AuditLog.action == "settings.update").order_by(AuditLog.id))
        )


def _stored(factory, key):
    with factory() as session:
        row = session.get(AppSetting, key)
        return None if row is None else row.value


def _save(factory, changes, actor):
    with factory.begin() as session:
        update_settings(session, changes, actor)


def _post(client, csrf, tab, **data):
    return client.post(f"/settings/{tab}", data={**data, "csrf_token": csrf}, follow_redirects=False)


TABS = ("smtp", "alerts", "inventory", "deployment", "scanning", "schedule", "general")


# --- plan test -------------------------------------------------------------------------------------


# Placeholder values only: these URLs model credential-bearing forms, never real credentials.
SECRET_BEARING_REPO_URLS = [
    "https://git.example.test/team/repo.git/access_token=EXAMPLE",
    "https://git.example.test/team/repo.git;token=EXAMPLE",
    "https://git.example.test/team/repo.git/%61ccess_token=EXAMPLE",
    "https://git.example.test/team/repo.git/%2561ccess%255Ftoken%253DEXAMPLE",
    "https://git.example.test/team/token/EXAMPLE/repo.git",
    "https://git.example.test/team/repo.git/password=EXAMPLE",
    "https://git.example.test/team/repo.git/api_key=EXAMPLE",
    "https://git.example.test/team/repo.git;sig=EXAMPLE",
    "https://git.example.test/ghp_EXAMPLEEXAMPLEEXAMPLE/repo.git",
    "https://git.example.test/glpat-EXAMPLEEXAMPLE/repo.git",
    "ssh://git@git.example.test/team/repo.git/token=EXAMPLE",
    "ssh://git@git.example.test/team/secret/repo.git",
    "git@git.example.test:team/repo.git/access_token=EXAMPLE",
    "git@git.example.test:team/token/repo.git",
    "git@git.example.test:team/%74oken/repo.git",
]


def test_settings_secrets_and_ranges(signed_in, csrf, db):
    bad = signed_in.post("/settings/smtp", data={"smtp_password": "***", "csrf_token": csrf})
    assert bad.status_code == 422
    assert db.get(AppSetting, "smtp_password") is None
    good = signed_in.post(
        "/settings/deployment",
        data={
            "batch_percent": "10",
            "concurrency": "5",
            "pause_timeout_hours": "24",
            "backup_retention_days": "0",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert good.status_code == 303
    assert get_setting(db, "deploy.backup_retention_days") == 0


# --- service: allowlist and defaults ---------------------------------------------------------------


def test_every_seeded_key_round_trips_through_get_setting(db, web_factory, admin):
    assert len(DEFAULTS) == 32
    for key, default in DEFAULTS.items():
        assert get_setting(db, key) == default, key
    _save(web_factory, dict(DEFAULTS), admin)  # re-submitting every default is valid and a no-op
    assert _audits(web_factory) == []


def test_service_defaults_match_the_seeded_migration_defaults():
    from app.services import settings as service

    assert {key: spec.default for key, spec in service._SETTINGS.items()} == DEFAULTS
    assert service.SETTING_KEYS == set(DEFAULTS)


def test_get_setting_of_unknown_key_raises_key_error(db):
    with pytest.raises(KeyError):
        get_setting(db, "nope.key")
    with pytest.raises(KeyError):
        get_setting(db, "smtp_password")


def test_missing_row_falls_back_to_the_seeded_default(web_factory, db):
    from sqlalchemy import delete

    with web_factory.begin() as session:
        session.execute(delete(AppSetting).where(AppSetting.key == "scan.timeout_seconds"))
    assert get_setting(db, "scan.timeout_seconds") == 10


def test_thresholds_default_and_stored_sorted_descending(db, web_factory, admin):
    assert get_setting(db, "alert.thresholds_days") == [60, 30, 14, 7, 1, 0]
    _save(web_factory, {"alert.thresholds_days": [3, 90, 0, 30]}, admin)
    assert _stored(web_factory, "alert.thresholds_days") == [90, 30, 3, 0]


@pytest.mark.parametrize(
    "key",
    ["smtp_password", "smtp.password", "x.secret", "api.token", "nope", "ui.timezone.extra", ""],
)
def test_unknown_and_secret_keys_are_rejected(web_factory, admin, key):
    with pytest.raises(SettingsValidationError) as caught:
        _save(web_factory, {key: "x"}, admin)
    assert caught.value.errors == {key: ("unknown setting",)}
    assert _stored(web_factory, key) is None


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("scan.daily_at", "24:00"),
        ("scan.daily_at", "7:30"),
        ("scan.daily_at", "07:60"),
        ("scan.daily_at", "07:30:00"),
        ("scan.daily_at", 730),
        ("discovery.nightly_at", "midnight"),
        ("digest.daily_at", ""),
        ("cleanup.daily_at", None),
        ("scan.enabled", "true"),
        ("scan.enabled", 1),
        ("smtp.tls_verify", None),
        ("alert.thresholds_days", []),
        ("alert.thresholds_days", [1, 1]),
        ("alert.thresholds_days", [-1]),
        ("alert.thresholds_days", [366]),
        ("alert.thresholds_days", list(range(11))),
        ("alert.thresholds_days", [True]),
        ("alert.thresholds_days", "30"),
        ("alert.recipients", ["not-an-email"]),
        ("alert.recipients", ["a@example.test", "a@example.test"]),
        ("alert.recipients", [f"u{i}@example.test" for i in range(51)]),
        ("alert.recipients", ["a" * 250 + "@example.test"]),
        ("alert.recipients", "a@example.test"),
        ("smtp.host", "bad host"),
        ("smtp.host", "a" * 254),
        ("smtp.host", "-bad.example"),
        ("smtp.port", 0),
        ("smtp.port", 65536),
        ("smtp.port", "25"),
        ("smtp.port", True),
        ("smtp.security", "tls"),
        ("smtp.security", "STARTTLS"),
        ("smtp.from", "not-an-email"),
        ("smtp.from", "a" * 250 + "@example.test"),
        ("smtp.username", "u" * 255),
        ("inventory.repo_url", "file:///etc"),
        ("inventory.repo_url", "http://git.example.test/r.git"),
        ("inventory.repo_url", "ftp://git.example.test/r.git"),
        ("inventory.repo_url", "https://user:pass@git.example.test/r.git"),
        ("inventory.repo_url", "https://user@git.example.test/r.git"),
        ("inventory.repo_url", "https://git.example.test/r.git?token=abc"),
        ("inventory.repo_url", "https://git.example.test/r.git?access_token=abc"),
        ("inventory.repo_url", "https://git.example.test/r.git#frag"),
        ("inventory.repo_url", "ssh://user:pass@git.example.test/r.git"),
        ("inventory.repo_url", "ssh://git.example.test"),
        ("inventory.repo_url", "git@git.example.test:team/r.git?password=x"),
        ("inventory.repo_url", "just-words"),
        *[("inventory.repo_url", url) for url in SECRET_BEARING_REPO_URLS],
        ("inventory.ref", "a..b"),
        ("inventory.ref", "has space"),
        ("inventory.ref", "x" * 201),
        ("inventory.path", "/abs/path"),
        ("inventory.path", "../escape"),
        ("inventory.path", "a/../../escape"),
        ("inventory.path", "a\\b"),
        ("inventory.path", "x" * 256),
        ("inventory.webserver_var", "1bad"),
        ("inventory.webserver_var", "has space"),
        ("inventory.webserver_var", ""),
        ("inventory.webserver_var", "v" * 65),
        ("deploy.batch_percent", 0),
        ("deploy.batch_percent", 101),
        ("deploy.concurrency", 0),
        ("deploy.concurrency", 51),
        ("deploy.pause_timeout_hours", 0),
        ("deploy.pause_timeout_hours", 169),
        ("deploy.host_timeout_seconds", 59),
        ("deploy.host_timeout_seconds", 7201),
        ("deploy.backup_retention_days", -1),
        ("deploy.backup_retention_days", 3651),
        ("scan.timeout_seconds", 0),
        ("scan.timeout_seconds", 61),
        ("retention.days", 0),
        ("retention.days", 3651),
        ("retention.days", 1.5),
        ("ui.timezone", "Mars/Olympus"),
        ("ui.timezone", ""),
        ("ui.timezone", "../etc/passwd"),
        ("trust.include_public_bundle", "yes"),
    ],
)
def test_invalid_values_are_rejected_and_nothing_is_written(web_factory, admin, key, value):
    with pytest.raises(SettingsValidationError) as caught:
        _save(web_factory, {key: value}, admin)
    assert list(caught.value.errors) == [key]
    assert caught.value.errors[key]
    assert get_setting_value(web_factory, key) == DEFAULTS[key]
    assert _audits(web_factory) == []


def get_setting_value(factory, key):
    with factory() as session:
        return get_setting(session, key)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("scan.daily_at", "00:00"),
        ("scan.daily_at", "23:59"),
        ("discovery.nightly_at", "03:15"),
        ("smtp.host", "mail.example.test"),
        ("smtp.host", "192.0.2.25"),
        ("smtp.host", "2001:db8::25"),
        ("smtp.port", 587),
        ("smtp.port", None),
        ("smtp.security", "starttls"),
        ("smtp.security", "ssl"),
        ("smtp.security", "none"),
        ("smtp.from", "certs@example.test"),
        ("smtp.username", "mailer"),
        ("alert.recipients", ["ops@example.test", "sec@example.test"]),
        ("inventory.repo_url", "https://git.example.test/team/inv.git"),
        ("inventory.repo_url", "ssh://git@git.example.test/team/inv.git"),
        ("inventory.repo_url", "ssh://git.example.test:2222/team/inv.git"),
        ("inventory.repo_url", "git@git.example.test:team/inv.git"),
        ("inventory.ref", "release/2026.10-rc1"),
        ("inventory.path", "inventories/prod"),
        ("inventory.webserver_var", "web_server"),
        ("deploy.backup_retention_days", 0),
        ("deploy.backup_retention_days", 3650),
        ("deploy.host_timeout_seconds", 60),
        ("deploy.host_timeout_seconds", 7200),
        ("scan.timeout_seconds", 60),
        ("retention.days", 1),
        ("retention.days", 3650),
        ("ui.timezone", "Europe/Rome"),
        ("smtp.tls_verify", False),
        ("trust.include_public_bundle", False),
    ],
)
def test_valid_values_are_stored(web_factory, db, admin, key, value):
    _save(web_factory, {key: value}, admin)
    assert get_setting_value(web_factory, key) == value


# --- service: patch semantics and audit ------------------------------------------------------------


def test_invalid_multi_field_patch_changes_nothing_and_aggregates_errors(web_factory, admin):
    with pytest.raises(SettingsValidationError) as caught:
        _save(
            web_factory,
            {"deploy.batch_percent": 50, "deploy.concurrency": 0, "scan.timeout_seconds": 999, "nope": 1},
            admin,
        )
    assert set(caught.value.errors) == {"deploy.concurrency", "scan.timeout_seconds", "nope"}
    assert get_setting_value(web_factory, "deploy.batch_percent") == 10
    assert _audits(web_factory) == []


def test_effective_patch_writes_one_audit_with_before_and_after(web_factory, admin):
    _save(web_factory, {"deploy.batch_percent": 25, "deploy.concurrency": 5, "smtp.tls_verify": False}, admin)
    [audit] = _audits(web_factory)
    assert audit.actor_user_id == admin.user_id
    assert audit.target_type == "settings"
    assert audit.details == {
        "changes": {
            "deploy.batch_percent": {"before": 10, "after": 25},
            "smtp.tls_verify": {"before": True, "after": False},
        }
    }
    with web_factory() as session:
        row = session.get(AppSetting, "deploy.batch_percent")
        assert row.updated_by == admin.user_id
        assert session.get(AppSetting, "deploy.concurrency").updated_by is None  # unchanged: not rewritten


def test_unchanged_patch_writes_no_audit(web_factory, admin):
    _save(web_factory, {"deploy.batch_percent": 10}, admin)
    assert _audits(web_factory) == []
    _save(web_factory, {"alert.thresholds_days": [0, 1, 7, 14, 30, 60]}, admin)  # same set, normalised
    assert _audits(web_factory) == []


def test_empty_patch_is_a_noop(web_factory, admin):
    _save(web_factory, {}, admin)
    assert _audits(web_factory) == []


def test_audit_details_never_contain_secret_material(web_factory, admin):
    _save(web_factory, {"smtp.username": "mailer", "smtp.host": "mail.example.test"}, admin)
    with pytest.raises(SettingsValidationError):
        _save(web_factory, {"smtp.password": "hunter2-hunter2"}, admin)
    with web_factory() as session:
        text = json.dumps([row.details for row in session.scalars(select(AuditLog))], default=str)
    assert "hunter2" not in text and "password" not in text.lower()


# --- HTTP: pages -----------------------------------------------------------------------------------


@pytest.mark.parametrize("tab", TABS)
def test_every_configuration_tab_renders(signed_in, tab):
    page = signed_in.get(f"/settings?tab={tab}")
    assert page.status_code == 200
    assert f'action="/settings/{tab}"' in page.text
    for other in ("smtp", "alerts", "inventory", "deployment", "scanning", "schedule", "general"):
        assert f"/settings?tab={other}" in page.text


def test_default_tab_is_smtp_and_unknown_tab_is_404(signed_in):
    assert 'action="/settings/smtp"' in signed_in.get("/settings").text
    assert signed_in.get("/settings?tab=nope").status_code == 404


def test_settings_navigation_is_enabled(signed_in):
    assert '<a href="/settings">Settings</a>' in signed_in.get("/settings").text


@pytest.mark.parametrize("tab", ["trust", "status", "maintenance"])
def test_part_b_tabs_are_placeholders(signed_in, tab):
    page = signed_in.get(f"/settings?tab={tab}")
    assert page.status_code == 200
    assert "coming in the next task" in page.text


def test_settings_requires_sign_in(client):
    assert client.get("/settings", follow_redirects=False).status_code == 303


def test_defaults_are_shown_in_forms(signed_in):
    alerts = signed_in.get("/settings?tab=alerts").text
    assert 'value="60, 30, 14, 7, 1, 0"' in alerts
    assert 'value="07:30"' in signed_in.get("/settings?tab=schedule").text
    assert 'value="webserver_type"' in signed_in.get("/settings?tab=inventory").text


def test_smtp_tab_explains_password_and_disables_test_send(signed_in, web_factory, admin):
    page = signed_in.get("/settings?tab=smtp").text
    assert "provided only via the worker secret file" in page
    assert "smtp_password" in page and 'name="smtp_password"' not in page
    assert "unsafe: TLS certificate verification disabled" not in page
    assert "Send test email" in page and "requires the alert/digest handler (Plan 2)" in page
    assert "disabled" in page
    _save(web_factory, {"smtp.tls_verify": False}, admin)
    assert "unsafe: TLS certificate verification disabled" in signed_in.get("/settings?tab=smtp").text


def test_inventory_tab_disables_test_pull(signed_in):
    page = signed_in.get("/settings?tab=inventory").text
    assert "Test pull" in page and "requires the discovery handler (Plan 3)" in page


# --- HTTP: posts -----------------------------------------------------------------------------------

GOOD_FORMS = {
    "smtp": {
        "host": "mail.example.test",
        "port": "587",
        "security": "starttls",
        "from": "certs@example.test",
        "username": "mailer",
        "tls_verify": "true",
    },
    "alerts": {
        "thresholds_days": "7, 30,1",
        "recipients": "ops@example.test\r\nsec@example.test\r\n",
        "digest_enabled": "false",
        "expiry_check_enabled": "true",
    },
    "inventory": {
        "repo_url": "ssh://git@git.example.test/team/inv.git",
        "ref": "main",
        "path": "inventories/prod",
        "webserver_var": "web_server",
    },
    "deployment": {
        "batch_percent": "20",
        "concurrency": "4",
        "pause_after_canary": "false",
        "pause_timeout_hours": "12",
        "backup_retention_days": "14",
        "host_timeout_seconds": "900",
    },
    "scanning": {"timeout_seconds": "15", "daily_at": "01:30", "enabled": "false"},
    "schedule": {
        "discovery_nightly_at": "02:10",
        "discovery_enabled": "false",
        "expiry_check_daily_at": "06:00",
        "digest_daily_at": "06:30",
        "cleanup_daily_at": "05:00",
        "cleanup_enabled": "false",
    },
    "general": {"timezone": "Europe/Rome", "retention_days": "180"},
}
EXPECTED = {
    "smtp": {
        "smtp.host": "mail.example.test",
        "smtp.port": 587,
        "smtp.security": "starttls",
        "smtp.from": "certs@example.test",
        "smtp.username": "mailer",
        "smtp.tls_verify": True,
    },
    "alerts": {
        "alert.thresholds_days": [30, 7, 1],
        "alert.recipients": ["ops@example.test", "sec@example.test"],
        "alert.digest_enabled": False,
        "expiry_check.enabled": True,
    },
    "inventory": {
        "inventory.repo_url": "ssh://git@git.example.test/team/inv.git",
        "inventory.ref": "main",
        "inventory.path": "inventories/prod",
        "inventory.webserver_var": "web_server",
    },
    "deployment": {
        "deploy.batch_percent": 20,
        "deploy.concurrency": 4,
        "deploy.pause_after_canary": False,
        "deploy.pause_timeout_hours": 12,
        "deploy.backup_retention_days": 14,
        "deploy.host_timeout_seconds": 900,
    },
    "scanning": {"scan.timeout_seconds": 15, "scan.daily_at": "01:30", "scan.enabled": False},
    "schedule": {
        "discovery.nightly_at": "02:10",
        "discovery.enabled": False,
        "expiry_check.daily_at": "06:00",
        "digest.daily_at": "06:30",
        "cleanup.daily_at": "05:00",
        "cleanup.enabled": False,
    },
    "general": {"ui.timezone": "Europe/Rome", "retention.days": 180},
}


@pytest.mark.parametrize("tab", TABS)
def test_each_tab_saves_audits_and_redirects(signed_in, csrf, web_factory, tab):
    response = _post(signed_in, csrf, tab, **GOOD_FORMS[tab])
    assert response.status_code == 303
    assert response.headers["location"] == f"/settings?tab={tab}&saved=1"
    for key, value in EXPECTED[tab].items():
        assert _stored(web_factory, key) == value, key
    assert len(_audits(web_factory)) == 1
    assert "Settings saved" in signed_in.get(response.headers["location"]).text


def test_patch_semantics_only_submitted_fields_change(signed_in, csrf, web_factory):
    response = _post(signed_in, csrf, "deployment", batch_percent="40")
    assert response.status_code == 303
    assert _stored(web_factory, "deploy.batch_percent") == 40
    assert _stored(web_factory, "deploy.concurrency") == 5  # seeded value untouched
    [audit] = _audits(web_factory)
    assert audit.details == {"changes": {"deploy.batch_percent": {"before": 10, "after": 40}}}


def test_ui_booleans_hidden_false_plus_checkbox_true_last_value_wins(signed_in, csrf, web_factory):
    response = signed_in.post(
        "/settings/scanning",
        content=f"csrf_token={csrf}&enabled=false&enabled=true&timeout_seconds=10".encode(),
        headers={"content-type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert _stored(web_factory, "scan.enabled") is True
    response = _post(signed_in, csrf, "scanning", enabled="false")
    assert response.status_code == 303 and _stored(web_factory, "scan.enabled") is False


def test_unchanged_post_redirects_without_audit(signed_in, csrf, web_factory):
    assert _post(signed_in, csrf, "deployment", batch_percent="10").status_code == 303
    assert _audits(web_factory) == []


def test_empty_port_means_unset(signed_in, csrf, web_factory, admin):
    _save(web_factory, {"smtp.port": 25}, admin)
    assert _post(signed_in, csrf, "smtp", port="").status_code == 303
    assert _stored(web_factory, "smtp.port") is None


@pytest.mark.parametrize(
    ("tab", "field", "value", "message"),
    [
        ("deployment", "batch_percent", "0", "between 1 and 100"),
        ("deployment", "batch_percent", "abc", "whole number"),
        ("deployment", "concurrency", "51", "between 1 and 50"),
        ("deployment", "backup_retention_days", "-1", "between 0 and 3650"),
        ("scanning", "daily_at", "25:00", "HH:MM"),
        ("scanning", "timeout_seconds", "0", "between 1 and 60"),
        ("schedule", "digest_daily_at", "7:30", "HH:MM"),
        ("general", "timezone", "Mars/Olympus", "time zone"),
        ("general", "retention_days", "0", "between 1 and 3650"),
        ("smtp", "security", "tls", "one of"),
        ("smtp", "port", "70000", "between 1 and 65535"),
        ("smtp", "from", "not-an-email", "email"),
        ("alerts", "thresholds_days", "7,7", "distinct"),
        ("alerts", "thresholds_days", "x", "whole number"),
        ("alerts", "recipients", "nope", "email"),
        ("inventory", "repo_url", "https://u:p@git.example.test/r.git", "credentials"),
        ("inventory", "repo_url", "file:///etc", "https"),
        ("inventory", "path", "../x", "relative"),
        ("inventory", "ref", "a..b", "git ref"),
    ],
)
def test_invalid_field_renders_422_with_message_and_keeps_submitted_value(
    signed_in, csrf, web_factory, tab, field, value, message
):
    response = _post(signed_in, csrf, tab, **{field: value})
    assert response.status_code == 422
    assert message in response.text
    assert f'action="/settings/{tab}"' in response.text
    assert _audits(web_factory) == []
    if field == "repo_url":  # a rejected URL may carry a credential: it is never echoed
        assert "u:p@" not in response.text
    elif field != "recipients":
        assert value in response.text.replace("&#34;", '"')


def test_invalid_multi_field_post_writes_nothing(signed_in, csrf, web_factory):
    response = _post(signed_in, csrf, "deployment", batch_percent="50", concurrency="0")
    assert response.status_code == 422
    assert _stored(web_factory, "deploy.batch_percent") == 10
    assert _audits(web_factory) == []


@pytest.mark.parametrize(
    ("tab", "field"),
    [
        ("smtp", "smtp_password"),
        ("smtp", "password"),
        ("smtp", "smtp.host"),
        ("smtp", "bogus"),
        ("alerts", "api_token"),
        ("general", "secret"),
        ("deployment", "host"),  # a smtp field posted to the wrong tab
    ],
)
def test_fields_outside_the_tab_map_are_422_and_nothing_is_written(signed_in, csrf, web_factory, tab, field):
    response = _post(signed_in, csrf, tab, **{field: "value-that-must-not-persist-77"})
    assert response.status_code == 422
    assert "value-that-must-not-persist-77" not in response.text
    assert _audits(web_factory) == []
    with web_factory() as session:
        stored = json.dumps([row.value for row in session.scalars(select(AppSetting))], default=str)
    assert "value-that-must-not-persist-77" not in stored


def test_valid_field_next_to_unknown_field_is_not_written(signed_in, csrf, web_factory):
    response = _post(signed_in, csrf, "smtp", host="mail.example.test", smtp_password="hunter2-hunter2")
    assert response.status_code == 422
    assert "hunter2" not in response.text
    assert _stored(web_factory, "smtp.host") == ""
    assert _audits(web_factory) == []


def test_htmx_validation_error_returns_a_fragment(signed_in, csrf):
    response = signed_in.post(
        "/settings/deployment",
        data={"batch_percent": "0", "csrf_token": csrf},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 422
    assert "between 1 and 100" in response.text
    assert "<html" not in response.text and "<nav" not in response.text


@pytest.mark.parametrize("tab", TABS)
def test_every_post_requires_csrf(signed_in, web_factory, tab):
    response = signed_in.post(f"/settings/{tab}", data=GOOD_FORMS[tab], follow_redirects=False)
    assert response.status_code == 403
    response = signed_in.post(
        f"/settings/{tab}", data={**GOOD_FORMS[tab], "csrf_token": "wrong"}, follow_redirects=False
    )
    assert response.status_code == 403
    assert _audits(web_factory) == []


def test_trust_is_not_posted_here(signed_in, csrf):
    assert _post(signed_in, csrf, "trust", include_public_bundle="false").status_code in (404, 405)


def test_saved_timezone_drives_display_helper(signed_in, csrf, web_factory):
    from app.web.common import display_timezone

    with web_factory() as session:
        assert display_timezone(session) == "UTC"
    assert _post(signed_in, csrf, "general", timezone="Europe/Rome").status_code == 303
    with web_factory() as session:
        assert display_timezone(session) == "Europe/Rome"


@pytest.mark.parametrize("url", SECRET_BEARING_REPO_URLS)
def test_secret_bearing_repo_url_is_422_unwritten_unaudited_and_not_echoed(
    signed_in, csrf, web_factory, url
):
    before = _stored(web_factory, "inventory.repo_url")
    response = _post(signed_in, csrf, "inventory", repo_url=url)
    assert response.status_code == 422
    assert "credentials" in response.text
    assert "EXAMPLE" not in response.text and "access_token" not in response.text
    assert _stored(web_factory, "inventory.repo_url") == before
    assert _audits(web_factory) == []
