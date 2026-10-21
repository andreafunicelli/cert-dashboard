"""Independent v1 catalog and privilege contract, exercised on PostgreSQL 16."""

import uuid
from datetime import UTC, datetime

import pytest
from alembic import command
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError

# ! = NOT NULL; unspecified fields are nullable. Includes table-specific timestamps.
COLUMNS = {
    "certificate": "id:bigint! common_name:text! subject_dn:text! sans:text[]! issuer_dn:text! issuer_cn:text! serial:text! not_before:timestamptz! not_after:timestamptz! sha256_fingerprint:char(64)! pem:text! chain_pem:text! chain_status:chain_status! key_id:bigint owner_name:text owner_email:text team:text notes:text status:certificate_status! renews_id:bigint imported_from:text! created_by:bigint",
    "private_key": "id:bigint! key_type:private_key_type! key_size:integer! curve:text ciphertext:bytea! nonce:bytea! aad:text! master_key_version:integer! public_key_sha256:char(64)! public_key_pem:text! created_by:bigint origin:text!",
    "renewal": "id:uuid! certificate_id:bigint previous_certificate_id:bigint state:renewal_state! common_name:text! sans:text[]! key_id:bigint csr_pem:text csr_sha256:char(64) ca_name:text ca_order_reference:text issued_chain_pem:text state_changed_at:timestamptz! created_by:bigint submitted_by:bigint issued_by:bigint deployed_by:bigint notes:text",
    "server": "id:bigint! hostname:text! display_name:text ansible_groups:text[]! webserver:webserver_type connection_address:text inventory_source:text! last_discovery_at:timestamptz last_discovery_status:text is_active:boolean! notes:text",
    "binding": "id:bigint! server_id:bigint! webserver:webserver_type! vhost_name:text! vhost_names:text[]! port:integer! config_file:text! cert_path:text! chain_path:text key_path:text! cert_owner:text cert_group:text cert_mode:integer key_owner:text key_group:text key_mode:integer on_disk_fingerprint:char(64) on_disk_key_public_sha256:char(64) certificate_id:bigint match_state:text! last_seen_at:timestamptz! is_active:boolean! notes:text",
    "endpoint": "id:bigint! host:text! port:integer! sni:text source:endpoint_source! server_id:bigint binding_id:bigint expected_certificate_id:bigint is_active:boolean! last_scan_at:timestamptz last_scan_status:scan_status",
    "scan_result": "id:bigint! endpoint_id:bigint! status:scan_status! observed_fingerprint:char(64) observed_common_name:text observed_issuer_cn:text observed_not_after:timestamptz observed_chain_length:integer expected_certificate_id:bigint tls_version:text error:text source:text! checked_at:timestamptz! elapsed_ms:integer",
    "job": "id:uuid! type:job_type! status:job_status! priority:integer! payload:jsonb! requested_by:bigint scheduled_reason:text attempt:integer! max_attempts:integer! run_after:timestamptz! timeout_at:timestamptz locked_by:text locked_at:timestamptz started_at:timestamptz finished_at:timestamptz error_class:text error_message:text result:jsonb resume_from_batch:integer! paused_at:timestamptz ansible_artifact_dir:text",
    "job_host": "id:uuid! job_id:uuid! server_id:bigint! binding_id:bigint batch_no:integer! status:job_host_status! started_at:timestamptz finished_at:timestamptz old_fingerprint:char(64) new_fingerprint:char(64) ansible_return_code:integer log_excerpt:text error_message:text rolled_back:boolean! rollback_error:text precheck:jsonb",
    "user": "id:bigint! username:citext! email:citext! display_name:text auth_backend:auth_backend! password_hash:text totp_secret_ciphertext:bytea totp_secret_nonce:bytea totp_secret_version:integer totp_enabled:boolean! totp_confirmed_at:timestamptz totp_last_used_step:bigint recovery_codes:text[]! is_active:boolean! failed_attempts:integer! locked_until:timestamptz last_login_at:timestamptz must_change_password:boolean!",
    "user_session": "id:char(64)! user_id:bigint! csrf_token:char(64)! last_seen_at:timestamptz! expires_at:timestamptz! ip:text user_agent:text revoked_at:timestamptz authenticated_at:timestamptz",
    "app_setting": "key:text! value:jsonb! updated_by:bigint",
    "notification_log": "id:bigint! certificate_id:bigint kind:text! threshold_days:integer recipients:text[]! status:notification_status! error:text sent_at:timestamptz dedupe_key:text! attempts:integer! next_attempt_at:timestamptz last_attempt_at:timestamptz",
    "audit_log": "id:uuid! actor_user_id:bigint actor_label:text! action:text! target_type:text! target_id:text details:jsonb! ip:inet user_agent:text",
    "worker_heartbeat": "worker_id:text! started_at:timestamptz! last_seen_at:timestamptz! current_job_id:uuid",
    "scheduler_state": "key:text! last_run_at:timestamptz",
    "login_rate_limit": "ip:inet! window_start:timestamptz! attempts:integer!",
    "trust_anchor": "id:bigint! subject:text! sha256_fingerprint:char(64)! pem:text! source:trust_anchor_source! notes:text created_by:bigint",
}
IMMUTABLE = {"audit_log", "scan_result", "trust_anchor"}
ENUMS = {
    "certificate_status": ["active", "superseded", "revoked"],
    "chain_status": ["trusted", "incomplete", "untrusted_root", "unchecked"],
    "trust_anchor_source": ["public_bundle", "uploaded"],
    "private_key_type": ["rsa", "ecdsa"],
    "renewal_state": ["draft", "csr_generated", "submitted", "issued", "deployed", "done", "cancelled"],
    "webserver_type": ["nginx", "apache"],
    "job_type": ["discover", "deploy", "scan", "alert_expiry", "digest", "cleanup"],
    "job_status": ["queued", "running", "paused", "succeeded", "failed", "cancelled"],
    "job_host_status": ["pending", "running", "succeeded", "failed", "rolled_back", "skipped"],
    "scan_status": ["ok", "mismatch", "expired", "unreachable", "error"],
    "endpoint_source": ["manual", "discovery"],
    "notification_status": ["sent", "failed"],
    "auth_backend": ["local", "ldap"],
}
DEFAULTS = {
    "certificate": {"sans": "{}", "chain_pem": "''", "chain_status": "unchecked", "status": "active"},
    "server": {"ansible_groups": "{}", "is_active": "true"},
    "binding": {"is_active": "true"},
    "endpoint": {"port": "443", "is_active": "true"},
    "renewal": {"state": "draft"},
    "job": {"status": "queued", "attempt": "0", "max_attempts": "3", "resume_from_batch": "0"},
    "job_host": {"batch_no": "0", "status": "pending", "rolled_back": "false"},
    "user": {
        "auth_backend": "local",
        "totp_enabled": "false",
        "recovery_codes": "{}",
        "is_active": "true",
        "failed_attempts": "0",
        "must_change_password": "false",
    },
    "notification_log": {"attempts": "0"},
    "scan_result": {"checked_at": "now()"},
    "audit_log": {"details": "{}"},
    "trust_anchor": {"source": "uploaded"},
}
SETTINGS = {
    "trust.include_public_bundle": True,
    "smtp.host": "",
    "smtp.port": None,
    "smtp.security": "",
    "smtp.from": "",
    "smtp.username": "",
    "smtp.tls_verify": True,
    "alert.thresholds_days": [60, 30, 14, 7, 1, 0],
    "alert.recipients": [],
    "alert.digest_enabled": True,
    "inventory.repo_url": "",
    "inventory.ref": "",
    "inventory.path": "",
    "inventory.webserver_var": "webserver_type",
    "deploy.batch_percent": 10,
    "deploy.pause_after_canary": True,
    "deploy.pause_timeout_hours": 24,
    "deploy.backup_retention_days": 30,
    "deploy.concurrency": 5,
    "deploy.host_timeout_seconds": 600,
    "scan.timeout_seconds": 10,
    "scan.daily_at": "02:00",
    "scan.enabled": True,
    "discovery.nightly_at": "03:00",
    "discovery.enabled": True,
    "digest.daily_at": "07:30",
    "expiry_check.daily_at": "07:00",
    "expiry_check.enabled": True,
    "cleanup.daily_at": "04:00",
    "cleanup.enabled": True,
    "ui.timezone": "UTC",
    "retention.days": 90,
}
FK = {
    "certificate": {
        "key_id": ("private_key", "id"),
        "renews_id": ("certificate", "id"),
        "created_by": ("user", "id"),
    },
    "private_key": {"created_by": ("user", "id")},
    "renewal": {
        **{c: ("certificate", "id") for c in ["certificate_id", "previous_certificate_id"]},
        "key_id": ("private_key", "id"),
        **{c: ("user", "id") for c in ["created_by", "submitted_by", "issued_by", "deployed_by"]},
    },
    "binding": {"server_id": ("server", "id"), "certificate_id": ("certificate", "id")},
    "endpoint": {
        "server_id": ("server", "id"),
        "binding_id": ("binding", "id"),
        "expected_certificate_id": ("certificate", "id"),
    },
    "scan_result": {"endpoint_id": ("endpoint", "id"), "expected_certificate_id": ("certificate", "id")},
    "job": {"requested_by": ("user", "id")},
    "job_host": {"job_id": ("job", "id"), "server_id": ("server", "id"), "binding_id": ("binding", "id")},
    "user_session": {"user_id": ("user", "id")},
    "app_setting": {"updated_by": ("user", "id")},
    "notification_log": {"certificate_id": ("certificate", "id")},
    "audit_log": {"actor_user_id": ("user", "id")},
    "worker_heartbeat": {"current_job_id": ("job", "id")},
    "trust_anchor": {"created_by": ("user", "id")},
}
UNIQUE = {
    "certificate": {("sha256_fingerprint",), ("issuer_dn", "serial")},
    "private_key": {("public_key_sha256",)},
    "server": {("hostname",)},
    "binding": {("server_id", "webserver", "config_file", "port", "vhost_name", "cert_path")},
    "job_host": {("job_id", "server_id", "binding_id")},
    "user": {("username",)},
    "notification_log": {("dedupe_key",)},
    "trust_anchor": {("sha256_fingerprint",)},
}


def test_entire_v1_schema(engine):
    assert set(inspect(engine).get_table_names()) == set(COLUMNS) | {"alembic_version"}
    with engine.connect() as conn:
        assert conn.scalar(text("SHOW server_version_num")).startswith("16")
        assert dict(conn.execute(text("SELECT key,value FROM app_setting")).all()) == SETTINGS
        assert conn.scalar(text('SELECT count(*) FROM "user"')) == 0
        assert conn.scalar(text("SELECT count(*) FROM trust_anchor")) == 0


@pytest.mark.parametrize("table", COLUMNS)
def test_all_column_types_nullability_timestamps_and_keys(engine, table):
    with engine.connect() as conn:
        actual = {
            name: (typ, nullable)
            for name, typ, nullable in conn.execute(
                text("""
            SELECT a.attname, format_type(a.atttypid,a.atttypmod), NOT a.attnotnull
            FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=:table AND a.attnum>0 AND NOT a.attisdropped
        """),
                {"table": table},
            )
        }
    expected = {}
    for field in (
        COLUMNS[table]
        + " created_at:timestamptz!"
        + ("" if table in IMMUTABLE else " updated_at:timestamptz!")
    ).split():
        name, typ = field.split(":")
        nullable = not typ.endswith("!")
        typ = (
            typ.rstrip("!")
            .replace("timestamptz", "timestamp with time zone")
            .replace("char(64)", "character(64)")
        )
        expected[name] = (typ, nullable)
    assert actual == expected
    pk = {
        "app_setting": ["key"],
        "worker_heartbeat": ["worker_id"],
        "scheduler_state": ["key"],
        "login_rate_limit": ["ip", "window_start"],
    }.get(table, ["id"])
    assert inspect(engine).get_pk_constraint(table)["constrained_columns"] == pk
    columns = {c["name"]: c for c in inspect(engine).get_columns(table)}
    for column, value in {
        "created_at": "now()",
        **({"updated_at": "now()"} if table not in IMMUTABLE else {}),
        **DEFAULTS.get(table, {}),
    }.items():
        assert value in columns[column]["default"], (table, column)
    actual_fks = {
        f["constrained_columns"][0]: (f["referred_table"], f["referred_columns"][0])
        for f in inspect(engine).get_foreign_keys(table)
    }
    assert actual_fks == FK.get(table, {})
    if "id" in columns and str(columns["id"]["type"]) == "BIGINT":
        assert "nextval(" in columns["id"]["default"]
    expected_checks = {
        "certificate": {"ck_certificate_validity", "ck_certificate_required_key"},
        "private_key": {
            "ck_private_key_nonce_length",
            "ck_private_key_master_key_version",
            "ck_private_key_origin",
        },
        "renewal": {"ck_renewal_required_key"},
    }
    assert {c["name"] for c in inspect(engine).get_check_constraints(table)} == expected_checks.get(
        table, set()
    )
    for f in inspect(engine).get_foreign_keys(table):
        expected_delete = {
            ("job_host", "job_id"): "CASCADE",
            ("user_session", "user_id"): "CASCADE",
            ("worker_heartbeat", "current_job_id"): "SET NULL",
        }.get((table, f["constrained_columns"][0]))
        assert f["options"].get("ondelete") == expected_delete
    assert {tuple(x["column_names"]) for x in inspect(engine).get_unique_constraints(table)} == UNIQUE.get(
        table, set()
    )


def test_enum_values_and_indexes(engine):
    inspector = inspect(engine)
    assert {e["name"]: e["labels"] for e in inspector.get_enums()} == ENUMS
    expected = {
        "certificate": {("not_after",), ("status", "not_after"), ("sans",)},
        "private_key": {("master_key_version",)},
        "binding": {("certificate_id",), ("server_id", "is_active"), ("match_state",)},
        "job_host": {("job_id", "status"), ("job_id", "batch_no")},
        "scan_result": {("endpoint_id", "checked_at"), ("status", "checked_at")},
    }
    for table, indexes in expected.items():
        actual = inspector.get_indexes(table)
        assert indexes <= {tuple(i["column_names"]) for i in actual}
        if table == "scan_result":
            assert all(i["column_sorting"]["checked_at"] == ("desc",) for i in actual)
    gin = next(i for i in inspector.get_indexes("certificate") if i["column_names"] == ["sans"])
    assert gin["dialect_options"]["postgresql_using"] == "gin"
    endpoint = next(i for i in inspector.get_indexes("endpoint") if i["unique"])
    assert "COALESCE(sni, host)".lower() in " ".join(endpoint["expressions"]).lower()
    claim = next(
        i
        for i in inspector.get_indexes("job")
        if i["column_names"] == ["priority", "run_after", "created_at"]
    )
    assert claim["column_sorting"]["priority"] == ("desc",)
    assert "queued" in claim["dialect_options"]["postgresql_where"]


def test_audit_permissions_cannot_be_bypassed_by_noop_rules(db, engine, owner_engine):
    audit_id = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO audit_log(id,actor_label,action,target_type) VALUES (:id,'test','test.write','test')"
        ),
        {"id": audit_id},
    )
    for sql in ["UPDATE audit_log SET actor_label='changed'", "DELETE FROM audit_log", "TRUNCATE audit_log"]:
        with pytest.raises(DBAPIError) as exc, db.begin_nested():
            db.execute(text(sql))
        assert exc.value.orig.sqlstate == "42501"
    assert db.scalar(text("SELECT actor_label FROM audit_log WHERE id=:id"), {"id": audit_id}) == "test"
    with engine.connect() as conn:
        assert conn.execute(
            text(
                "SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication FROM pg_roles WHERE rolname=current_user"
            )
        ).one() == (False, False, False, False)
        for sql in [
            "SET ROLE db_owner",
            "CREATE TABLE forbidden(id int)",
            "ALTER TABLE server ADD COLUMN forbidden int",
        ]:
            with pytest.raises(DBAPIError), conn.begin_nested():
                conn.execute(text(sql))
    with owner_engine.connect() as conn:
        assert not list(conn.scalars(text("SELECT rulename FROM pg_rules WHERE tablename='audit_log'")))
        assert set(
            conn.scalars(
                text("SELECT tgname FROM pg_trigger WHERE tgrelid='audit_log'::regclass AND NOT tgisinternal")
            )
        ) == {"audit_log_no_mutation", "audit_log_no_truncate"}


def cert_values(**overrides):
    values = {
        "common_name": "example.test",
        "subject_dn": "CN=example.test",
        "issuer_dn": "CN=CA",
        "issuer_cn": "CA",
        "serial": uuid.uuid4().hex,
        "not_before": datetime(2026, 1, 1, tzinfo=UTC),
        "not_after": datetime(2027, 1, 1, tzinfo=UTC),
        "sha256_fingerprint": uuid.uuid4().hex * 2,
        "pem": "test-only-public",
        "imported_from": "upload_pem",
    }
    return values | overrides


def test_certificate_uniqueness_checks_and_default_trust(db):
    from app.models import Certificate

    a = Certificate(**cert_values())
    db.add(a)
    db.flush()
    assert a.chain_status == "unchecked" and a.chain_pem == "" and a.sans == []
    for overrides in [
        {"sha256_fingerprint": a.sha256_fingerprint},
        {"issuer_dn": a.issuer_dn, "serial": a.serial},
        {"not_after": a.not_before},
        {"imported_from": "renewal"},
    ]:
        with pytest.raises(IntegrityError), db.begin_nested():
            db.add(Certificate(**cert_values(**overrides)))
            db.flush()


def test_key_constraints_and_renewal_draft_exception(db):
    from app.models import PrivateKey, Renewal

    values = {
        "key_type": "rsa",
        "key_size": 2048,
        "ciphertext": b"encrypted",
        "nonce": b"n" * 12,
        "aad": "private_key:1:1",
        "master_key_version": 1,
        "public_key_sha256": "a" * 64,
        "public_key_pem": "public",
        "origin": "generated",
    }
    key = PrivateKey(**values)
    db.add(key)
    db.flush()
    for changes in [
        {"nonce": b"n" * 11},
        {"master_key_version": 0},
        {"public_key_sha256": key.public_key_sha256},
    ]:
        with pytest.raises(IntegrityError), db.begin_nested():
            db.add(PrivateKey(**(values | {"public_key_sha256": "b" * 64} | changes)))
            db.flush()
    for state in ["draft", "cancelled"]:
        db.add(Renewal(common_name="example.test", sans=[], state=state, state_changed_at=datetime.now(UTC)))
    db.flush()
    for state in ["csr_generated", "submitted", "issued", "deployed", "done"]:
        with pytest.raises(IntegrityError), db.begin_nested():
            db.add(
                Renewal(common_name="example.test", sans=[], state=state, state_changed_at=datetime.now(UTC))
            )
            db.flush()


def test_citext_and_coalesced_endpoint_uniqueness(db):
    from app.models import Endpoint, User

    db.add(User(username="Admin", email="admin@example.test"))
    db.flush()
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(User(username="admin", email="other@example.test"))
        db.flush()
    db.add(Endpoint(host="example.test", source="manual"))
    db.flush()
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(Endpoint(host="example.test", sni="example.test", source="manual"))
        db.flush()
    db.add(Endpoint(host="example.test", sni="different.test", source="manual"))
    db.flush()


def test_trigger_updates_timestamp_even_on_raw_sql(db):
    before = db.scalar(text("SELECT updated_at FROM app_setting WHERE key='ui.timezone'"))
    db.execute(
        text(
            "UPDATE app_setting SET updated_at='2000-01-01',value='\"Europe/Rome\"'::jsonb WHERE key='ui.timezone'"
        )
    )
    after = db.scalar(text("SELECT updated_at FROM app_setting WHERE key='ui.timezone'"))
    assert after > before
    assert db.scalar(text("SELECT created_at <= updated_at FROM app_setting LIMIT 1")) is True


def test_migration_matches_models_without_drift(alembic_config, owner_engine):
    command.check(alembic_config)


def test_database_readiness_and_transaction_contract(engine, database_urls):
    from app.config import DatabaseSettings
    from app.db import assert_database_ready, create_session_factory, transaction
    from app.models import Server

    app_url = database_urls[1]
    settings = DatabaseSettings(
        db_host=app_url.host,
        db_port=app_url.port,
        db_name=app_url.database,
        db_user=app_url.username,
        db_password=app_url.password.encode(),
    )
    factory = create_session_factory(settings)
    try:
        assert_database_ready(engine, timeout_seconds=1)
        with transaction(factory) as session:
            session.add(Server(hostname="committed.test", inventory_source="fixture"))
        with pytest.raises(RuntimeError), transaction(factory) as session:
            session.add(Server(hostname="rolled-back.test", inventory_source="fixture"))
            session.flush()
            raise RuntimeError("rollback")
        with engine.connect() as conn:
            assert conn.scalar(text("SELECT count(*) FROM server WHERE hostname='committed.test'")) == 1
            assert conn.scalar(text("SELECT count(*) FROM server WHERE hostname='rolled-back.test'")) == 0
    finally:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM server WHERE hostname='committed.test'"))
        factory.kw["bind"].dispose()


def test_database_readiness_rejects_wrong_head(owner_engine, engine):
    from app.config import ConfigurationError
    from app.db import assert_database_ready

    with owner_engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num='wrong_head'"))
    try:
        with pytest.raises(ConfigurationError, match="migration"):
            assert_database_ready(engine, timeout_seconds=0)
    finally:
        with owner_engine.begin() as conn:
            conn.execute(text("UPDATE alembic_version SET version_num='0001_v1_schema'"))


def test_real_compose_migrate_service_reaches_head_without_app_secrets(tmp_path):
    import json
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    for name in ["db_password", "db_owner_password"]:
        (tmp_path / name).write_text(uuid.uuid4().hex)
        (tmp_path / name).chmod(0o444)
    override = tmp_path / "migration-test.yml"
    override.write_text(
        json.dumps(
            {
                "secrets": {
                    name: {"file": str(tmp_path / name)} for name in ["db_password", "db_owner_password"]
                }
            }
        )
    )
    compose = [
        "docker",
        "compose",
        "--profile",
        "migrate",
        "-p",
        "certdash-migrate-" + uuid.uuid4().hex[:10],
        "-f",
        "docker-compose.yml",
        "-f",
        "docker-compose.migrate.yml",
        "-f",
        str(override),
    ]
    try:
        subprocess.run(
            compose + ["up", "-d", "--wait", "--pull", "never", "db"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=90,
        )
        result = subprocess.run(
            compose + ["run", "--rm", "--no-deps", "migrate"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=90,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        head = subprocess.run(
            compose
            + [
                "exec",
                "-T",
                "db",
                "psql",
                "-U",
                "db_owner",
                "-d",
                "cert_dashboard",
                "-Atc",
                "SELECT version_num FROM alembic_version",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        assert head.stdout.strip() == "0001_v1_schema"
        # Exercise the actual Alembic CLI, rather than only its Python API.
        checked = subprocess.run(
            compose + ["run", "--rm", "--no-deps", "migrate", "alembic", "check"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=90,
        )
        assert checked.returncode == 0, checked.stdout + checked.stderr
        assert "No new upgrade operations detected" in checked.stdout
    finally:
        subprocess.run(
            compose + ["down", "--volumes", "--remove-orphans"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )


def test_owner_also_gets_loud_append_only_failure(owner_engine):
    with owner_engine.connect() as conn, conn.begin():
        conn.execute(
            text(
                "INSERT INTO audit_log(actor_label,action,target_type) VALUES ('owner-test','test.write','test')"
            )
        )
        for sql in [
            "UPDATE audit_log SET actor_label='changed'",
            "DELETE FROM audit_log",
            "TRUNCATE audit_log",
        ]:
            with pytest.raises(DBAPIError) as exc, conn.begin_nested():
                conn.execute(text(sql))
            assert exc.value.orig.sqlstate == "P0001"
            assert "audit_log is append-only" in str(exc.value.orig)
        conn.rollback()


@pytest.mark.parametrize("timeout", [0, 1])
def test_database_readiness_bounds_connection_retries_without_leaking_credentials(database_urls, timeout):
    import time

    from sqlalchemy import create_engine

    from app.config import ConfigurationError
    from app.db import assert_database_ready

    wrong_password = "confidential-wrong-password"
    engine = create_engine(database_urls[1].set(password=wrong_password), connect_args={"connect_timeout": 1})
    started = time.monotonic()
    try:
        with pytest.raises(ConfigurationError, match="database: unavailable") as exc:
            assert_database_ready(engine, timeout_seconds=timeout)
        assert wrong_password not in str(exc.value)
        assert timeout <= time.monotonic() - started < timeout + 2
    finally:
        engine.dispose()


def test_test_compose_migrates_with_owner_before_container_unit_smoke():
    from pathlib import Path

    import yaml

    root = Path(__file__).resolve().parents[2]
    services = yaml.safe_load((root / "docker-compose.test.yml").read_text())["services"]
    assert "migrate" in services
    migrate = services["migrate"]
    assert migrate["command"] == ["alembic", "upgrade", "head"]
    assert migrate["environment"]["DB_USER"] == "db_owner"
    assert migrate["secrets"] == [{"source": "db_owner_password", "target": "db_password"}]
    assert services["app"]["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
    assert services["app"]["command"] == ["pytest", "-q", "tests/unit", "-p", "no:cacheprovider"]


def test_ci_builds_runtime_image_before_real_compose_integration():
    from pathlib import Path

    import yaml

    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    commands = [step.get("run", "") for step in workflow["jobs"]["verify"]["steps"]]
    suite = next(i for i, cmd in enumerate(commands) if cmd.startswith("uv run pytest -q --cov"))
    assert any(
        cmd.startswith("docker build ") and "-t cert-dashboard:local" in cmd for cmd in commands[:suite]
    )


def test_binding_job_host_uniqueness_and_worker_cascade(db, now):
    from app.models import Binding, Job, JobHost, Server, WorkerHeartbeat

    server = Server(hostname="fixture.example.test", inventory_source="test")
    db.add(server)
    db.flush()
    fields = {
        "server_id": server.id,
        "webserver": "nginx",
        "vhost_name": "example.test",
        "vhost_names": ["example.test"],
        "config_file": "/etc/nginx/example.test.conf",
        "cert_path": "/etc/certs/example.test.pem",
        "key_path": "/etc/certs/example.test.key",
        "match_state": "unknown",
        "last_seen_at": now,
    }
    binding = Binding(**fields)
    db.add(binding)
    db.flush()
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(Binding(**fields))
        db.flush()
    job = Job(type="deploy", priority=300, payload={}, run_after=now, max_attempts=1)
    db.add(job)
    db.flush()
    host = {"job_id": job.id, "server_id": server.id, "binding_id": binding.id}
    db.add(JobHost(**host))
    db.add(
        WorkerHeartbeat(worker_id="fixture-worker", started_at=now, last_seen_at=now, current_job_id=job.id)
    )
    db.flush()
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(JobHost(**host))
        db.flush()
    db.execute(text("DELETE FROM job WHERE id=:id"), {"id": job.id})
    assert db.scalar(text("SELECT count(*) FROM job_host WHERE job_id=:id"), {"id": job.id}) == 0
    assert (
        db.scalar(text("SELECT current_job_id FROM worker_heartbeat WHERE worker_id='fixture-worker'"))
        is None
    )


def test_trust_anchor_uniqueness_defaults_and_session_cascade(db, now):
    from app.models import TrustAnchor, User, UserSession

    user = User(username="fixture-admin", email="fixture@example.test")
    db.add(user)
    db.flush()
    anchor = TrustAnchor(
        subject="CN=Fixture CA",
        sha256_fingerprint="f" * 64,
        pem="fixture-public-certificate",
        created_by=user.id,
    )
    db.add(anchor)
    db.flush()
    assert anchor.source == "uploaded"
    created = anchor.created_at
    db.execute(text("UPDATE trust_anchor SET notes='test' WHERE id=:id"), {"id": anchor.id})
    db.refresh(anchor)
    assert anchor.created_at == created
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(TrustAnchor(subject="CN=Duplicate", sha256_fingerprint="f" * 64, pem="fixture-public"))
        db.flush()
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(UserSession(id="b" * 64, user_id=-1, csrf_token="c" * 64, last_seen_at=now, expires_at=now))
        db.flush()
    db.add(UserSession(id="a" * 64, user_id=user.id, csrf_token="c" * 64, last_seen_at=now, expires_at=now))
    db.flush()
    # Anchor attribution intentionally prevents deleting an attributed admin.
    with pytest.raises(IntegrityError), db.begin_nested():
        db.execute(text('DELETE FROM "user" WHERE id=:id'), {"id": user.id})
    db.delete(anchor)
    db.flush()
    db.execute(text('DELETE FROM "user" WHERE id=:id'), {"id": user.id})
    assert db.scalar(text("SELECT count(*) FROM user_session WHERE id=:id"), {"id": "a" * 64}) == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"vhost_name": "other.example.test"},
        {"config_file": "/etc/nginx/other.conf"},
        {"port": 8443},
        {"webserver": "apache"},
    ],
)
def test_binding_identity_keeps_distinct_directives_sharing_cert_path(db, now, changes):
    from app.models import Binding, Server

    server = Server(hostname="shared.example.test", inventory_source="fixture")
    db.add(server)
    db.flush()
    fields = {
        "server_id": server.id,
        "webserver": "nginx",
        "config_file": "/etc/nginx/shared.conf",
        "port": 443,
        "vhost_name": "first.example.test",
        "vhost_names": ["first.example.test"],
        "cert_path": "/etc/certs/shared.pem",
        "key_path": "/etc/certs/shared.key",
        "match_state": "unknown",
        "last_seen_at": now,
    }
    first = Binding(**fields)
    db.add(first)
    db.flush()
    other = Binding(**(fields | changes))
    db.add(other)
    db.flush()
    assert first.id != other.id and first.cert_path == other.cert_path
    with pytest.raises(IntegrityError) as exc, db.begin_nested():
        db.add(Binding(**fields))
        db.flush()
    assert exc.value.orig.sqlstate == "23505"


def test_job_host_null_binding_is_part_of_unique_identity(db, now):
    from app.models import Job, JobHost, Server

    server = Server(hostname="discovery.example.test", inventory_source="fixture")
    job = Job(type="discover", priority=200, payload={}, run_after=now)
    db.add_all([server, job])
    db.flush()
    fields = {"job_id": job.id, "server_id": server.id, "binding_id": None}
    db.add(JobHost(**fields))
    db.flush()
    with pytest.raises(IntegrityError) as exc, db.begin_nested():
        db.add(JobHost(**fields))
        db.flush()
    assert exc.value.orig.sqlstate == "23505"


def test_failed_notification_records_attempt_without_claiming_send(db, now, engine):
    from app.models import NotificationLog

    row = NotificationLog(
        kind="digest",
        recipients=["fixture@example.test"],
        status="failed",
        attempts=1,
        error="fixture SMTP failure",
        dedupe_key="fixture:" + uuid.uuid4().hex,
    )
    db.add(row)
    db.flush()
    assert row.sent_at is None
    row.last_attempt_at = now
    db.flush()
    saved = db.execute(
        text("SELECT sent_at,last_attempt_at FROM notification_log WHERE id=:id"), {"id": row.id}
    ).one()
    assert saved == (None, now)
    columns = {c["name"]: c for c in inspect(engine).get_columns("notification_log")}
    assert columns["sent_at"]["nullable"] is True and columns["sent_at"]["default"] is None
    assert columns["last_attempt_at"]["nullable"] is True and columns["last_attempt_at"]["default"] is None


@pytest.mark.parametrize("table", ["job_host", "binding"])
def test_nullable_uniqueness_is_explicit_in_postgres_catalog(engine, table):
    with engine.connect() as conn:
        assert (
            conn.scalar(
                text("""
            SELECT i.indnullsnotdistinct FROM pg_constraint c
            JOIN pg_index i ON i.indexrelid=c.conindid
            WHERE c.conrelid=to_regclass(:table) AND c.contype='u'
        """),
                {"table": "public." + table},
            )
            is True
        )


def test_app_role_cannot_disable_owner_audit_triggers(db):
    assert (
        db.scalar(
            text("SELECT tableowner FROM pg_tables WHERE schemaname='public' AND tablename='audit_log'")
        )
        == "db_owner"
    )
    with pytest.raises(DBAPIError) as exc, db.begin_nested():
        db.execute(text("ALTER TABLE audit_log DISABLE TRIGGER ALL"))
    assert exc.value.orig.sqlstate == "42501"
    assert "must be owner" in str(exc.value.orig)


MUTABLE_TABLES = sorted(set(COLUMNS) - IMMUTABLE)


def test_updated_at_trigger_matrix_covers_every_catalog_table(engine):
    with engine.connect() as conn:
        catalog = conn.scalars(
            text("""
            SELECT table_name FROM information_schema.columns
            WHERE table_schema='public' AND column_name='updated_at'
            ORDER BY table_name
        """)
        ).all()
    assert MUTABLE_TABLES == catalog


@pytest.mark.parametrize("table", MUTABLE_TABLES)
def test_every_mutable_table_has_enabled_before_update_timestamp_trigger(engine, table):
    with engine.connect() as conn:
        triggers = conn.execute(
            text("""
            SELECT t.tgenabled, (t.tgtype & 2)=2 AS is_before,
                   (t.tgtype & 16)=16 AS is_update, (t.tgtype & 1)=1 AS is_row,
                   p.proname
            FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
            WHERE t.tgrelid=to_regclass(:table) AND NOT t.tgisinternal
        """),
            {"table": "public." + table},
        ).all()
    assert ("O", True, True, True, "touch_updated_at") in triggers
