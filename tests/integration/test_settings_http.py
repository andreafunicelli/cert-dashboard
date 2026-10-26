"""Task 23 (part A): typed settings service and the seven configuration tabs (real Postgres, real HTTP)."""

import html
import importlib
import inspect
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from importlib.metadata import version as package_version

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from app import cli
from app.crypto.keyring import Keyring
from app.models import (
    AppSetting,
    AuditLog,
    Certificate,
    Job,
    PrivateKey,
    SchedulerState,
    TrustAnchor,
    WorkerHeartbeat,
)
from app.models.enums import ChainStatus, JobStatus, JobType
from app.services.audit import Actor
from app.services.settings import SettingsValidationError, get_setting, status_snapshot, update_settings
from app.services.trust_anchors import add_anchor, public_bundle_anchors
from tests.integration.conftest import create_login_user
from tests.integration.test_trust_anchors import _certificate_row

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
def test_part_b_tabs_render_real_panels(signed_in, tab):
    page = signed_in.get(f"/settings?tab={tab}")
    assert page.status_code == 200
    assert "coming in the next task" not in page.text
    for other in ("trust", "status", "maintenance"):
        assert f"/settings?tab={other}" in page.text


def test_settings_requires_sign_in(client):
    assert client.get("/settings", follow_redirects=False).status_code == 303


def test_defaults_are_shown_in_forms(signed_in):
    alerts = signed_in.get("/settings?tab=alerts").text
    assert 'value="60, 30, 14, 7, 1, 0"' in alerts
    assert 'value="07:30"' in signed_in.get("/settings?tab=schedule").text
    assert 'value="webserver_type"' in signed_in.get("/settings?tab=inventory").text


def test_smtp_tab_explains_password_and_enables_test_send(signed_in, web_factory, admin):
    page = signed_in.get("/settings?tab=smtp").text
    assert "provided only via the worker secret file" in page
    assert "smtp_password" in page and 'name="smtp_password"' not in page
    assert "unsafe: TLS certificate verification disabled" not in page
    assert 'action="/settings/smtp/test"' in page
    assert '<button type="submit">Send test email</button>' in page  # enabled: alert_expiry/smtp_test is registered
    assert "alert_expiry/smtp_test not registered" not in page
    assert "digest/default not registered" not in page
    assert "No test e-mail has been sent yet." in page
    _save(web_factory, {"smtp.tls_verify": False}, admin)
    assert "unsafe: TLS certificate verification disabled" in signed_in.get("/settings?tab=smtp").text


def test_inventory_tab_disables_test_pull(signed_in):
    page = signed_in.get("/settings?tab=inventory").text
    assert "Test pull" in page and "handler discover/default not registered (Plan 3)" in page


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


_SECRET_URL = "https://git.example.test/team/repo.git/access_token=EXAMPLE"
_MIXED_INVALID = [
    {"bogus": "x"},  # unknown field
    {"smtp_password": "x"},  # secret-looking unknown field
    {"ref": "a" * 5000},  # parse-level invalid second field (over-long)
    {"path": "../escape"},  # service-level invalid second field
    {"ref": "bad..ref"},
]


@pytest.mark.parametrize("htmx", [False, True])
@pytest.mark.parametrize("extra", _MIXED_INVALID)
@pytest.mark.parametrize("url", [_SECRET_URL, *SECRET_BEARING_REPO_URLS[:6]])
def test_secret_repo_url_with_another_invalid_field_is_never_echoed(
    signed_in, csrf, web_factory, url, extra, htmx
):
    before = _stored(web_factory, "inventory.repo_url")
    response = signed_in.post(
        "/settings/inventory",
        data={"repo_url": url, "csrf_token": csrf, **extra},
        headers={"HX-Request": "true"} if htmx else {},
        follow_redirects=False,
    )
    assert response.status_code == 422
    assert "EXAMPLE" not in response.text and "access_token" not in response.text
    assert "token=" not in response.text and "%61ccess" not in response.text
    assert _stored(web_factory, "inventory.repo_url") == before
    assert _audits(web_factory) == []


def test_valid_repo_url_is_kept_in_form_when_another_field_is_invalid(signed_in, csrf):
    response = _post(
        signed_in, csrf, "inventory", repo_url="https://git.example.test/team/inv.git", bogus="x"
    )
    assert response.status_code == 422
    assert "https://git.example.test/team/inv.git" in response.text


# --- Part B: trust anchors ---------------------------------------------------------------------

UPLOAD = "/settings/trust-anchors"
PRUNE = "/settings/maintenance/prune"


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def _self_signed(now, *, ca):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture Self Signed")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def _anchors(factory):
    with factory() as session:
        return list(session.scalars(select(TrustAnchor).order_by(TrustAnchor.id)))


def _actions(factory, action):
    with factory() as session:
        return list(session.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


def _audit_ids(factory):
    with factory() as session:
        return set(session.scalars(select(AuditLog.id)))


def _add_certificate(factory, certs):
    with factory.begin() as session:
        return _certificate_row(session, certs.leaf_pem, certs.chain_pem).id


def _chain_status(factory, certificate_id):
    with factory() as session:
        return session.get(Certificate, certificate_id).chain_status


def _seed_anchor(factory, certs, now):
    with factory.begin() as session:
        return add_anchor(session, _pem(certs.root), "seed", Actor(None, "fixture"), now).id


def _upload(client, csrf, pem=None, *, paste=None, notes="", headers=None):
    data = {"csrf_token": csrf, "notes": notes}
    if paste is not None:
        data["pem"] = paste
    files = {"file": ("root.pem", pem, "application/x-pem-file")} if pem is not None else None
    return client.post(UPLOAD, data=data, files=files, headers=headers, follow_redirects=False)


def _flat(text):
    return " ".join(html.unescape(text).split())


def test_trust_tab_shows_public_bundle_line_and_no_public_rows(signed_in):
    page = signed_in.get("/settings?tab=trust")
    roots = len(public_bundle_anchors())
    assert roots > 0
    expected = f"Public bundle: certifi {package_version('certifi')}, {roots} roots, include-public-bundle = true"
    assert expected in _flat(page.text)
    assert 'action="/settings/trust"' in page.text and f'action="{UPLOAD}"' in page.text
    assert "No uploaded trust anchors" in page.text
    assert "<tbody" not in page.text  # public roots are never listed as rows


def test_upload_root_adds_anchor_audits_and_rechecks_synchronously(signed_in, csrf, web_factory, certs):
    certificate_id = _add_certificate(web_factory, certs)
    assert _chain_status(web_factory, certificate_id) == ChainStatus.UNCHECKED
    response = _upload(signed_in, csrf, _pem(certs.root), notes="Internal root CA")
    assert response.status_code == 303 and response.headers["location"] == "/settings?tab=trust"
    [anchor] = _anchors(web_factory)
    assert anchor.source == "uploaded" and anchor.notes == "Internal root CA" and anchor.created_by is not None
    assert _chain_status(web_factory, certificate_id) == ChainStatus.TRUSTED  # no worker involved
    assert len(_actions(web_factory, "trust_anchor.add")) == 1
    page = _flat(signed_in.get("/settings?tab=trust").text)
    for shown in (anchor.subject, anchor.sha256_fingerprint, "uploaded", "Internal root CA", "admin"):
        assert shown in page
    assert "Chain statuses rechecked: trusted 1" in page
    assert "Chain statuses rechecked" not in _flat(signed_in.get("/settings?tab=trust").text)  # one-shot


def test_upload_accepts_a_pasted_pem(signed_in, csrf, web_factory, certs):
    response = _upload(signed_in, csrf, paste=_pem(certs.root).decode("ascii"))
    assert response.status_code == 303
    [anchor] = _anchors(web_factory)
    assert anchor.notes is None


@pytest.mark.parametrize(
    ("pem_of", "message"),
    [
        (lambda certs, now: certs.leaf_pem, "CA:TRUE"),
        (lambda certs, now: _pem(certs.intermediate2), "self-signed"),
        (lambda certs, now: _pem(_self_signed(now, ca=False)), "CA:TRUE"),
        (lambda certs, now: _pem(certs.root) + _pem(certs.root), "single"),
        (lambda certs, now: b"not a certificate", "PEM"),
    ],
    ids=["leaf", "intermediate", "self-signed-non-ca", "two-certificates", "garbage"],
)
def test_upload_of_non_root_material_is_422_and_changes_nothing(
    signed_in, csrf, web_factory, certs, now, pem_of, message
):
    before = _audit_ids(web_factory)
    response = _upload(signed_in, csrf, pem_of(certs, now))
    assert response.status_code == 422 and message in response.text
    assert "PRIVATE KEY" not in response.text and "BEGIN CERTIFICATE" not in response.text
    assert _anchors(web_factory) == [] and _audit_ids(web_factory) == before


def test_upload_rejection_is_an_htmx_fragment(signed_in, csrf, certs):
    response = _upload(signed_in, csrf, certs.leaf_pem, headers={"HX-Request": "true"})
    assert response.status_code == 422 and "CA:TRUE" in response.text
    assert "<html" not in response.text and "<nav" not in response.text


def test_upload_requires_input_and_bounds_notes_and_size(signed_in, csrf, web_factory, certs):
    assert _upload(signed_in, csrf).status_code == 422
    assert _upload(signed_in, csrf, _pem(certs.root), notes="x" * 1001).status_code == 422
    assert _upload(signed_in, csrf, b"A" * 1_048_577).status_code == 422
    assert _anchors(web_factory) == []
    assert _upload(signed_in, csrf, _pem(certs.root), notes="x" * 1000).status_code == 303


def test_duplicate_upload_is_422(signed_in, csrf, web_factory, certs):
    assert _upload(signed_in, csrf, _pem(certs.root)).status_code == 303
    response = _upload(signed_in, csrf, _pem(certs.root))
    assert response.status_code == 422 and "already exists" in response.text
    assert len(_anchors(web_factory)) == 1


@pytest.mark.parametrize("confirm", [None, "", "delete", "DELETE ", "DELETE!"])
def test_delete_without_exact_confirmation_is_422_and_keeps_the_anchor(
    signed_in, csrf, web_factory, certs, now, confirm
):
    certificate_id = _add_certificate(web_factory, certs)
    anchor_id = _seed_anchor(web_factory, certs, now)
    assert _chain_status(web_factory, certificate_id) == ChainStatus.TRUSTED
    data = {"csrf_token": csrf} | ({} if confirm is None else {"confirm": confirm})
    response = signed_in.post(f"{UPLOAD}/{anchor_id}/delete", data=data, follow_redirects=False)
    assert response.status_code == 422 and "DELETE" in response.text
    assert [row.id for row in _anchors(web_factory)] == [anchor_id]
    assert _actions(web_factory, "trust_anchor.remove") == []
    assert _chain_status(web_factory, certificate_id) == ChainStatus.TRUSTED


def test_delete_removes_audits_and_rechecks_synchronously(signed_in, csrf, web_factory, certs, now):
    certificate_id = _add_certificate(web_factory, certs)
    anchor_id = _seed_anchor(web_factory, certs, now)
    response = signed_in.post(
        f"{UPLOAD}/{anchor_id}/delete", data={"csrf_token": csrf, "confirm": "DELETE"}, follow_redirects=False
    )
    assert response.status_code == 303 and response.headers["location"] == "/settings?tab=trust"
    assert _anchors(web_factory) == []
    assert len(_actions(web_factory, "trust_anchor.remove")) == 1
    assert _chain_status(web_factory, certificate_id) == ChainStatus.UNTRUSTED_ROOT
    assert "Chain statuses rechecked: untrusted_root 1" in _flat(signed_in.get("/settings?tab=trust").text)


def test_delete_of_unknown_anchor_is_404(signed_in, csrf):
    data = {"csrf_token": csrf, "confirm": "DELETE"}
    assert signed_in.post(f"{UPLOAD}/9999/delete", data=data, follow_redirects=False).status_code == 404
    assert signed_in.post(f"{UPLOAD}/abc/delete", data=data, follow_redirects=False).status_code == 404


def test_public_bundle_toggle_rechecks_audits_and_never_persists_roots(
    signed_in, csrf, web_factory, certs, monkeypatch
):
    from app.services import trust_anchors as service

    monkeypatch.setattr(service, "public_bundle_anchors", lambda: (certs.root,))
    certificate_id = _add_certificate(web_factory, certs)
    off = _post(signed_in, csrf, "trust", include_public_bundle="false")
    assert off.status_code == 303 and off.headers["location"] == "/settings?tab=trust"
    assert _stored(web_factory, "trust.include_public_bundle") is False
    assert _chain_status(web_factory, certificate_id) != ChainStatus.TRUSTED
    assert _audits(web_factory)[-1].details["changes"] == {
        "trust.include_public_bundle": {"before": True, "after": False}
    }
    page = _flat(signed_in.get("/settings?tab=trust").text)
    assert "include-public-bundle = false" in page and "Chain statuses rechecked" in page

    on = _post(signed_in, csrf, "trust", include_public_bundle="true")
    assert on.status_code == 303
    assert _stored(web_factory, "trust.include_public_bundle") is True
    assert _chain_status(web_factory, certificate_id) == ChainStatus.TRUSTED
    assert _anchors(web_factory) == []


@pytest.mark.parametrize("data", [{}, {"include_public_bundle": "maybe"}, {"include_public_bundle": "true", "x": "1"}])
def test_invalid_toggle_is_422_and_changes_nothing(signed_in, csrf, web_factory, data):
    response = _post(signed_in, csrf, "trust", **data)
    assert response.status_code == 422
    assert _stored(web_factory, "trust.include_public_bundle") is True  # the seeded default is untouched
    assert _audits(web_factory) == []


def test_part_b_posts_require_csrf(signed_in, web_factory):
    forms = [
        ("/settings/trust", {"include_public_bundle": "false"}),
        (UPLOAD, {"pem": "x"}),
        (f"{UPLOAD}/1/delete", {"confirm": "DELETE"}),
        (PRUNE, {"confirm": "PRUNE OLD JOBS"}),
    ]
    for path, data in forms:
        assert signed_in.post(path, data=data, follow_redirects=False).status_code == 403
        wrong = signed_in.post(path, data=data | {"csrf_token": "wrong"}, follow_redirects=False)
        assert wrong.status_code == 403
    assert _audits(web_factory) == [] and _actions(web_factory, "job.enqueue") == []


# --- Part B: status ----------------------------------------------------------------------------

SHA = "ab" * 32


def _snapshot(db, keyring, now):
    return status_snapshot(db, keyring, now, keyring_sha256=SHA)


def _heartbeat(db, now, age_seconds, worker_id="worker-1"):
    db.add(
        WorkerHeartbeat(
            worker_id=worker_id,
            started_at=now - timedelta(hours=1),
            last_seen_at=now - timedelta(seconds=age_seconds),
        )
    )
    db.commit()


def _job(db, status, finished_at=None, job_type=JobType.SCAN):
    db.add(
        Job(
            type=job_type,
            status=status,
            priority=100,
            payload={},
            run_after=finished_at or datetime(2026, 10, 19, tzinfo=UTC),
            finished_at=finished_at,
        )
    )
    db.commit()


def _key_row(db, version):
    db.add(
        PrivateKey(
            key_type="rsa",
            key_size=2048,
            ciphertext=b"fixture-ciphertext-bytes",
            nonce=b"123456789012",
            aad=f"private_key:0:{version}:{uuid.uuid4().hex}",
            master_key_version=version,
            public_key_sha256=uuid.uuid4().hex + uuid.uuid4().hex,
            public_key_pem="-----BEGIN PUBLIC KEY-----\nZml4dHVyZQ==\n-----END PUBLIC KEY-----\n",
            origin="imported_pem",
        )
    )
    db.commit()


def _active_certificate(db, now, owner_email=None, status="active"):
    token = uuid.uuid4().hex
    db.add(
        Certificate(
            common_name=f"{token}.example.test",
            subject_dn=f"CN={token}.example.test",
            sans=[],
            issuer_dn="CN=Fixture CA",
            issuer_cn="Fixture CA",
            serial=token,
            not_before=now - timedelta(days=30),
            not_after=now + timedelta(days=30),
            sha256_fingerprint=token + token,
            pem="-----BEGIN CERTIFICATE-----\nZml4dHVyZQ==\n-----END CERTIFICATE-----\n",
            owner_email=owner_email,
            status=status,
            imported_from="upload_pem",
        )
    )
    db.commit()


def test_status_snapshot_pins_liveness_constants_and_is_json_native(db, keyring, now):
    snapshot = _snapshot(db, keyring, now)
    assert json.loads(json.dumps(snapshot)) == snapshot
    assert snapshot["worker"] == {
        "state": "stale",
        "last_seen_at": None,
        "heartbeat_interval_seconds": 30,
        "stale_after_seconds": 300,
        "workers": 0,
    }
    assert snapshot["queue"] == {"queued": 0, "running": 0, "paused": 0, "failed_24h": 0}
    assert snapshot["keyring"] == {
        "active_version": 1,
        "file_sha256": SHA,
        "loaded_versions": [1],
        "missing_versions": [],
        "stale_rows": 0,
    }
    assert isinstance(snapshot["db_size_bytes"], int) and snapshot["db_size_bytes"] > 0
    assert snapshot["last_jobs"] == {}
    assert snapshot["smtp"] == {
        "consecutive_failures": 0,
        "last_error": None,
        "last_success_at": None,
        "last_test": None,
    }


def test_status_snapshot_never_contains_secret_material(db, keyring, now):
    text = json.dumps(_snapshot(db, keyring, now))
    assert bytes(range(32)).hex() not in text and "base64" not in text.lower()
    assert "password" not in text.lower() and "BEGIN" not in text


def test_worker_is_ok_up_to_exactly_five_minutes_and_stale_after(db, keyring, now):
    _heartbeat(db, now, 300)
    snapshot = _snapshot(db, keyring, now)
    assert snapshot["worker"]["state"] == "ok" and snapshot["worker"]["workers"] == 1
    assert snapshot["worker"]["last_seen_at"] == (now - timedelta(seconds=300)).isoformat()
    assert "worker_stale" not in snapshot["warnings"]
    stale = _snapshot(db, keyring, now + timedelta(seconds=1))
    assert stale["worker"]["state"] == "stale" and stale["worker"]["workers"] == 0
    assert stale["worker"]["last_seen_at"] == (now - timedelta(seconds=300)).isoformat()
    assert "worker_stale" in stale["warnings"]


def test_queue_depth_counts_open_jobs_and_failures_of_the_last_24_hours(db, keyring, now):
    for status in (JobStatus.QUEUED, JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.PAUSED):
        _job(db, status)
    _job(db, JobStatus.FAILED, now - timedelta(hours=23))
    _job(db, JobStatus.FAILED, now - timedelta(hours=25))
    _job(db, JobStatus.SUCCEEDED, now - timedelta(hours=1))
    assert _snapshot(db, keyring, now)["queue"] == {"queued": 2, "running": 1, "paused": 1, "failed_24h": 1}


def test_last_runs_and_last_finished_job_per_type(db, keyring, now):
    db.add(SchedulerState(key="expiry_check", last_run_at=now - timedelta(hours=5)))
    db.add(SchedulerState(key="digest", last_run_at=None))
    db.commit()
    _job(db, JobStatus.SUCCEEDED, now - timedelta(hours=2), JobType.CLEANUP)
    _job(db, JobStatus.FAILED, now - timedelta(hours=1), JobType.CLEANUP)
    _job(db, JobStatus.QUEUED, None, JobType.CLEANUP)
    snapshot = _snapshot(db, keyring, now)
    assert snapshot["last_runs"] == {"digest": None, "expiry_check": (now - timedelta(hours=5)).isoformat()}
    assert snapshot["last_jobs"] == {
        "cleanup": {"status": "failed", "finished_at": (now - timedelta(hours=1)).isoformat()}
    }


def test_keyring_state_reports_missing_and_stale_versions(db, now):
    _key_row(db, 1)
    _key_row(db, 7)
    ring = Keyring(2, {1: bytes(range(32)), 2: bytes(range(1, 33))})
    keyring_state = _snapshot(db, ring, now)["keyring"]
    assert keyring_state["active_version"] == 2 and keyring_state["loaded_versions"] == [1, 2]
    assert keyring_state["missing_versions"] == [7] and keyring_state["stale_rows"] == 2
    assert "missing_key_versions" in _snapshot(db, ring, now)["warnings"]
    complete = Keyring(2, {1: bytes(range(32)), 2: bytes(range(1, 33)), 7: bytes(range(2, 34))})
    assert "missing_key_versions" not in _snapshot(db, complete, now)["warnings"]


def test_configuration_warnings_follow_the_settings(db, keyring, now, admin):
    warnings = _snapshot(db, keyring, now)["warnings"]
    assert warnings == ["smtp_not_configured", "inventory_not_configured", "worker_stale"]
    with db.begin_nested():
        update_settings(
            db,
            {"smtp.host": "mail.example.test", "inventory.repo_url": "https://git.example.test/team/inventory.git"},
            admin,
        )
    db.commit()
    assert _snapshot(db, keyring, now)["warnings"] == ["worker_stale"]
    update_settings(db, {"smtp.tls_verify": False}, admin)
    db.commit()
    assert _snapshot(db, keyring, now)["warnings"] == ["smtp_tls_unverified", "worker_stale"]


def test_no_alert_recipients_warns_only_when_an_active_certificate_lacks_an_owner(db, keyring, now, admin):
    _active_certificate(db, now, owner_email="owner@example.test")
    _active_certificate(db, now, owner_email=None, status="superseded")
    assert "no_alert_recipients" not in _snapshot(db, keyring, now)["warnings"]
    _active_certificate(db, now, owner_email="")
    assert "no_alert_recipients" in _snapshot(db, keyring, now)["warnings"]
    update_settings(db, {"alert.recipients": ["ops@example.test"]}, admin)
    db.commit()
    assert "no_alert_recipients" not in _snapshot(db, keyring, now)["warnings"]


def test_status_tab_renders_the_snapshot(signed_in, web_factory):
    with web_factory() as session:
        _job(session, JobStatus.QUEUED)
    page = _flat(signed_in.get("/settings?tab=status").text)
    assert signed_in.app.state.settings.keyring_sha256 in page
    for expected in ("Active version", "30 seconds", "5 minutes", "Queued 1", "Database size"):
        assert expected in page
    for code in ("smtp_not_configured", "inventory_not_configured", "worker_stale"):
        assert f'data-warning="{code}"' in signed_in.get("/settings?tab=status").text
    assert "smtp_password" not in page


def test_status_banner_links_worker_and_key_warnings_to_the_status_tab(signed_in):
    signed_in.app.state.status_banner = "key material cannot be decrypted with the configured master key"
    text = signed_in.get("/settings?tab=general").text
    assert re.search(r'data-banner="worker".*?href="/settings\?tab=status"', text, re.DOTALL)
    assert re.search(r"key material cannot be decrypted.*?href=\"/settings\?tab=status\"", text, re.DOTALL)


# --- Part B: maintenance -----------------------------------------------------------------------


def _jobs(factory):
    with factory() as session:
        return list(session.scalars(select(Job).order_by(Job.created_at)))


def test_maintenance_shows_cli_rotation_instructions_and_keyring_state_only(signed_in):
    text = signed_in.get("/settings?tab=maintenance").text
    flat = _flat(text)
    assert "python -m app.cli rotate-master-key" in flat
    assert "python -m app.cli verify-key --certificate-id" in flat
    assert "Active version" in flat and "PRUNE OLD JOBS" in flat
    # the instructions name commands and arguments that really exist in app/cli.py
    source = inspect.getsource(cli)
    for token in ('"rotate-master-key"', '"verify-key"', '"--certificate-id"'):
        assert token in source
    # the displayed invocation runs the generator inside a container whose /secrets and /out mounts it
    # creates itself, from a 0700 temp dir owned by the container user; a bare host command would fail
    assert (
        'docker run --rm -v /etc/cert-dashboard/secrets:/secrets:ro -v "$tmp":/out cert-dashboard:local \\ '
        "python -m app.cli generate-master-key --version 2 --merge /secrets/master_key "
        "--output /out/master_key.v2.new"
    ) in flat
    assert 'install -d -m 0700 -o 10001 -g 10001 "$tmp"' in flat
    assert "docs/operations.md" in flat and "as root" in flat
    assert "from the repository checkout" not in flat
    # no keyring edit or rotation control: the only form is the typed-confirmed prune
    assert re.findall(r'<form[^>]*\saction="([^"]+)"', text) == [PRUNE]
    assert "<textarea" not in text and 'type="file"' not in text


def test_prune_with_exact_confirmation_enqueues_one_cleanup_job_and_audits(signed_in, csrf, web_factory, web_user):
    before = _audit_ids(web_factory)
    response = signed_in.post(PRUNE, data={"csrf_token": csrf, "confirm": "PRUNE OLD JOBS"}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/settings?tab=maintenance"
    [job] = _jobs(web_factory)
    assert job.type == JobType.CLEANUP and job.status == JobStatus.QUEUED
    assert job.payload == {"reason": "manual_prune"} and job.priority == 10
    assert job.requested_by == web_user.id
    assert len(_actions(web_factory, "job.enqueue")) == 1
    [requested] = _actions(web_factory, "maintenance.prune_requested")
    assert requested.actor_user_id == web_user.id and requested.details == {"reason": "manual_prune"}
    assert before <= _audit_ids(web_factory)  # nothing in the audit log is ever removed
    assert "Retention cleanup queued" in _flat(signed_in.get("/settings?tab=maintenance").text)


@pytest.mark.parametrize(
    "confirm", [None, "", "prune old jobs", "PRUNE OLD JOBS ", " PRUNE OLD JOBS", "PRUNE", "DELETE"]
)
def test_prune_without_the_exact_confirmation_is_422_and_enqueues_nothing(signed_in, csrf, web_factory, confirm):
    data = {"csrf_token": csrf} | ({} if confirm is None else {"confirm": confirm})
    response = signed_in.post(PRUNE, data=data, follow_redirects=False)
    assert response.status_code == 422 and "PRUNE OLD JOBS" in response.text
    assert _jobs(web_factory) == []
    assert _actions(web_factory, "maintenance.prune_requested") == []
    assert _actions(web_factory, "job.enqueue") == []
