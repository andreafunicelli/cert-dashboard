import base64
import json
import logging
import os
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from threading import Barrier

import pytest
from alembic import command
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db import transaction
from app.models import AuditLog, Certificate, PrivateKey, User
from app.services.audit import Actor


@pytest.fixture
def keyrings():
    from app.crypto.keyring import Keyring

    return Keyring(1, {1: bytes(range(32))}), Keyring(2, {1: bytes(range(32)), 2: bytes(reversed(range(32)))})


@pytest.fixture
def isolated_database(owner_engine, database_urls):
    name = "fixture_keys_" + uuid.uuid4().hex
    owner_url = owner_engine.url.set(database=name)
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.exec_driver_sql(f'CREATE DATABASE "{name}"')
    cfg = Config("alembic.ini")
    cfg.attributes["database_url"] = owner_url
    command.upgrade(cfg, "head")
    owner = create_engine(owner_url)
    app = create_engine(database_urls[1].set(database=name))
    yield owner, app
    app.dispose()
    owner.dispose()
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.exec_driver_sql(f'DROP DATABASE "{name}" WITH (FORCE)')


@pytest.fixture
def isolated_factory(isolated_database):
    _, engine = isolated_database
    factory = sessionmaker(engine, expire_on_commit=False)
    yield factory
    engine.dispose()


def test_complete_reserved_id_insert_dedup_and_no_plaintext_sql(db, actor, keyrings):
    from app.crypto.keys import public_key_sha256
    from app.services.certificates import store_key, unwrap_key

    key = ec.generate_private_key(ec.SECP256R1())
    statements = []

    def capture(conn, cursor, statement, parameters, context, many):
        statements.append((statement, parameters))

    bind = db.get_bind()
    event.listen(bind, "before_cursor_execute", capture)
    try:
        row = store_key(db, keyrings[0], key, "generated", actor)
        db.flush()
        duplicate = store_key(db, keyrings[0], key, "imported_pem", actor)
        db.flush()
    finally:
        event.remove(bind, "before_cursor_execute", capture)
    assert duplicate.id == row.id and row.aad == f"private_key:{row.id}:1"
    assert row.key_type == "ecdsa" and row.key_size == 256 and row.curve == "prime256v1"
    assert (
        row.public_key_sha256
        == public_key_sha256(key.public_key())
        == public_key_sha256(unwrap_key(row, keyrings[0]).public_key())
    )
    assert row.ciphertext and len(row.nonce) == 12 and row.master_key_version == 1
    assert any("nextval" in sql.lower() for sql, _ in statements)
    assert "PRIVATE KEY" not in repr(statements)
    audits = db.scalars(select(AuditLog).where(AuditLog.target_type == "private_key")).all()
    assert len(audits) == 1 and "PRIVATE KEY" not in json.dumps(audits[0].details)


@pytest.mark.parametrize("fix_aad", [False, True])
def test_moving_encrypted_payload_to_another_row_fails(db, actor, keyrings, fix_aad):
    from app.crypto.keyring import KeyUnwrapError
    from app.services.certificates import store_key, unwrap_key

    row = store_key(db, keyrings[0], ec.generate_private_key(ec.SECP256R1()), "generated", actor)
    db.flush()
    moved = PrivateKey(
        id=row.id + 1000,
        ciphertext=row.ciphertext,
        nonce=row.nonce,
        aad=row.aad,
        master_key_version=row.master_key_version,
        key_type=row.key_type,
        key_size=row.key_size,
        curve=row.curve,
        public_key_sha256=row.public_key_sha256,
        public_key_pem=row.public_key_pem,
    )
    if fix_aad:
        moved.aad = f"private_key:{moved.id}:1"
    with pytest.raises(KeyUnwrapError):
        unwrap_key(moved, keyrings[0])


def test_missing_version_is_metadata_and_only_blocks_dependent_actions(db, actor, keyrings):
    from app.crypto.keyring import Keyring, KeyUnwrapError
    from app.services.certificates import missing_master_key_versions, store_key, unwrap_key

    row = store_key(db, keyrings[0], ec.generate_private_key(ec.SECP256R1()), "generated", actor)
    db.flush()
    current = Keyring(2, {2: keyrings[1].keys[2]})
    assert missing_master_key_versions(db, current) == {1}
    assert db.get(PrivateKey, row.id).public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
    with pytest.raises(KeyUnwrapError):
        unwrap_key(row, current)
    fresh = store_key(db, current, ec.generate_private_key(ec.SECP256R1()), "generated", actor)
    assert unwrap_key(fresh, current).key_size == 256


def test_rotation_caps_total_rows_and_is_idempotent_across_keys_and_totp(db, actor, keyrings, caplog):
    from app.crypto.keyring import Keyring, WrappedSecret, unwrap, wrap
    from app.services.certificates import rotate_master_key, store_key, unwrap_key

    old, new = keyrings
    for _ in range(101):
        store_key(db, old, ec.generate_private_key(ec.SECP256R1()), "generated", actor)
    user = db.get(User, actor.user_id)
    seed = b"fixture-totp-seed"
    wrapped = wrap(old, seed, f"user:{user.id}:totp:1")
    user.totp_secret_ciphertext = wrapped.ciphertext
    user.totp_secret_nonce = wrapped.nonce
    user.totp_secret_version = 1
    db.flush()
    sql_parameters = []

    def capture_sql(conn, cursor, statement, parameters, context, many):
        sql_parameters.append(repr(parameters))

    bind = db.get_bind()
    event.listen(bind, "before_cursor_execute", capture_sql)
    with caplog.at_level(logging.DEBUG, logger="app"):
        assert rotate_master_key(db, new, actor) == 2
        assert (
            db.scalar(select(func.count()).select_from(PrivateKey).where(PrivateKey.master_key_version == 2))
            == 100
        )
        assert rotate_master_key(db, new, actor) == 0
        before = db.scalar(select(func.count()).select_from(AuditLog))
        assert rotate_master_key(db, new, actor) == 0
        db.flush()
        assert db.scalar(select(func.count()).select_from(AuditLog)) == before
    event.remove(bind, "before_cursor_execute", capture_sql)
    assert "fixture-totp-seed" not in "".join(sql_parameters)
    assert "PRIVATE KEY" not in "".join(sql_parameters)
    only = Keyring(2, {2: new.keys[2]})
    for row in db.scalars(select(PrivateKey)):
        assert row.aad == f"private_key:{row.id}:2" and unwrap_key(row, only).key_size == 256
    db.refresh(user)
    assert user.totp_secret_version == 2
    assert (
        unwrap(
            only,
            WrappedSecret(user.totp_secret_ciphertext, user.totp_secret_nonce, 2),
            f"user:{user.id}:totp:2",
        )
        == seed
    )
    assert "fixture-totp-seed" not in caplog.text and "PRIVATE KEY" not in caplog.text
    rotations = db.scalars(select(AuditLog).where(AuditLog.action == "master_key.rotate")).all()
    assert [r.details["keys_rotated"] for r in rotations] == [100, 1]
    assert [r.details["users_rotated"] for r in rotations] == [0, 1]


def test_rotation_restarts_after_committed_batch_and_mid_batch_crash(isolated_factory, keyrings, monkeypatch):
    from app.crypto.keyring import Keyring
    from app.services import certificates as service

    actor = Actor(None, "system")
    with transaction(isolated_factory) as db:
        for _ in range(3):
            service.store_key(db, keyrings[0], ec.generate_private_key(ec.SECP256R1()), "generated", actor)
    with transaction(isolated_factory) as db:
        assert service.rotate_master_key(db, keyrings[1], actor, batch_size=1) == 2
    original = service.wrap
    calls = 0

    def crash(ring, plaintext, aad):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("fixture interrupted rotation")
        return original(ring, plaintext, aad)

    monkeypatch.setattr(service, "wrap", crash)
    with pytest.raises(RuntimeError), transaction(isolated_factory) as db:
        service.rotate_master_key(db, keyrings[1], actor)
    monkeypatch.setattr(service, "wrap", original)
    with transaction(isolated_factory) as db:
        assert [x.master_key_version for x in db.scalars(select(PrivateKey).order_by(PrivateKey.id))] == [
            2,
            1,
            1,
        ]
        assert service.rotate_master_key(db, keyrings[1], actor) == 0
    with transaction(isolated_factory) as db:
        assert service.rotate_master_key(db, keyrings[1], actor) == 0
        for row in db.scalars(select(PrivateKey)):
            assert service.unwrap_key(row, Keyring(2, {2: keyrings[1].keys[2]})).key_size == 256


def test_concurrent_public_hash_dedup_is_race_safe(isolated_factory, keyrings):
    from app.services.certificates import store_key

    key = ec.generate_private_key(ec.SECP256R1())
    barrier = Barrier(2)

    def capture(conn, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO private_key"):
            barrier.wait(timeout=10)

    engine = isolated_factory.kw["bind"]
    event.listen(engine, "before_cursor_execute", capture)

    def insert():
        with transaction(isolated_factory) as db:
            return store_key(db, keyrings[0], key, "generated", Actor(None, "system")).id

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: insert(), range(2)))
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert results[0] == results[1]
    with transaction(isolated_factory) as db:
        assert len(db.scalars(select(PrivateKey)).all()) == 1
        assert len(db.scalars(select(AuditLog)).all()) == 1


def test_rotation_releases_previous_plaintext_before_next_row(db, actor, keyrings, monkeypatch):
    import inspect

    from app.services import certificates as service

    for _ in range(3):
        service.store_key(db, keyrings[0], ec.generate_private_key(ec.SECP256R1()), "generated", actor)
    real = service.unwrap
    calls = 0

    def checked(ring, wrapped, aad):
        nonlocal calls
        calls += 1
        for frame in inspect.stack():
            if frame.function == "rotate_master_key":
                assert not any(
                    isinstance(v, bytes) and b"PRIVATE KEY" in v for v in frame.frame.f_locals.values()
                )
        return real(ring, wrapped, aad)

    monkeypatch.setattr(service, "unwrap", checked)
    assert service.rotate_master_key(db, keyrings[1], actor) == 0 and calls == 3


def test_cli_rotation_commits_batches_and_verify_outputs_only_metadata(
    isolated_factory, keyrings, tmp_path, now, monkeypatch, capsys
):
    from app.services.certificates import store_key

    engine = isolated_factory.kw["bind"]
    old, new = keyrings
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with transaction(isolated_factory) as db:
        row = store_key(db, old, key, "generated", Actor(None, "system"))
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.example.test")])
        leaf = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256())
        )
        cert = Certificate(
            common_name="fixture.example.test",
            subject_dn="CN=fixture.example.test",
            issuer_dn="CN=fixture.example.test",
            issuer_cn="fixture.example.test",
            sans=[],
            serial=format(leaf.serial_number, "x"),
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=30),
            sha256_fingerprint=leaf.fingerprint(hashes.SHA256()).hex(),
            pem=leaf.public_bytes(serialization.Encoding.PEM).decode(),
            key_id=row.id,
            imported_from="upload_pem",
        )
        db.add(cert)
        db.flush()
        cert_id = cert.id
    keyfile = {"active": 2, "keys": {str(k): base64.b64encode(v).decode() for k, v in new.keys.items()}}
    (tmp_path / "master_key").write_text(json.dumps(keyfile))
    (tmp_path / "db_password").write_text(engine.url.password)
    env = {
        **os.environ,
        "SECRETS_DIR": str(tmp_path),
        "DB_HOST": engine.url.host,
        "DB_PORT": str(engine.url.port),
        "DB_NAME": engine.url.database,
        "DB_USER": "app_role",
    }

    def run(*args):
        return subprocess.run(
            [sys.executable, "-m", "app.cli", *args], env=env, capture_output=True, text=True, check=False
        )

    from app.cli import main

    for name, value in env.items():
        if name in {"SECRETS_DIR", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER"}:
            monkeypatch.setenv(name, value)
    assert main(["rotate-master-key"]) == 0
    out, err = capsys.readouterr()
    assert "remaining=0" in out and not err
    assert main(["verify-key", "--certificate-id", str(cert_id)]) == 0
    out, err = capsys.readouterr()
    assert "verified" in out and not err
    assert main(["verify-key", "--certificate-id", "999999999"]) == 1
    out, err = capsys.readouterr()
    assert not out and "certificate not found" in err
    rotated = run("rotate-master-key")
    assert rotated.returncode == 0, rotated.stderr
    assert "remaining=0" in rotated.stdout
    verified = run("verify-key", "--certificate-id", str(cert_id))
    assert verified.returncode == 0 and "verified" in verified.stdout
    for value in [
        "PRIVATE KEY",
        leaf.public_bytes(serialization.Encoding.PEM).decode(),
        *keyfile["keys"].values(),
    ]:
        assert value not in rotated.stdout + rotated.stderr + verified.stdout + verified.stderr
    with transaction(isolated_factory) as db:
        assert db.scalar(select(PrivateKey.master_key_version)) == 2


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "public_key_sha256"])
def test_persisted_key_tamper_fails_closed(db, actor, keyrings, field):
    from app.crypto.keyring import KeyUnwrapError
    from app.services.certificates import store_key, unwrap_key

    row = store_key(db, keyrings[0], ec.generate_private_key(ec.SECP256R1()), "generated", actor)
    if field == "ciphertext":
        row.ciphertext = row.ciphertext[:-1] + bytes([row.ciphertext[-1] ^ 1])
    elif field == "nonce":
        row.nonce = b"n" * 12
    else:
        row.public_key_sha256 = "0" * 64
    with pytest.raises(KeyUnwrapError):
        unwrap_key(row, keyrings[0])


@pytest.mark.parametrize("size", [0, -1, True])
def test_rotation_refuses_invalid_batch_size(db, keyrings, size):
    from app.services.certificates import rotate_master_key

    with pytest.raises(ValueError, match="batch_size"):
        rotate_master_key(db, keyrings[1], Actor(None, "system"), size)


def test_two_rotators_and_legacy_writer_finish_without_deadlock(isolated_factory, keyrings):
    from app.crypto.keyring import Keyring
    from app.services.certificates import rotate_master_key, store_key, unwrap_key

    actor = Actor(None, "system")
    with transaction(isolated_factory) as db:
        for _ in range(120):
            store_key(db, keyrings[0], ec.generate_private_key(ec.SECP256R1()), "generated", actor)
    start = Barrier(3)

    def rotate():
        start.wait(timeout=10)
        for _ in range(20):
            with transaction(isolated_factory) as db:
                db.execute(text("SET LOCAL lock_timeout = '5s'"))
                db.execute(text("SET LOCAL statement_timeout = '10s'"))
                remaining = rotate_master_key(db, keyrings[1], actor, batch_size=25)
            if remaining == 0:
                return
        raise AssertionError("rotation did not converge")

    def legacy_write():
        start.wait(timeout=10)
        for _ in range(12):
            with transaction(isolated_factory) as db:
                db.execute(text("SET LOCAL statement_timeout = '10s'"))
                store_key(db, keyrings[0], ec.generate_private_key(ec.SECP256R1()), "generated", actor)

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(rotate), pool.submit(rotate), pool.submit(legacy_write)]
        for future in futures:
            future.result(timeout=30)
    # A legacy writer can finish after either rotator's snapshot; final pass is required.
    for _ in range(10):
        with transaction(isolated_factory) as db:
            remaining = rotate_master_key(db, keyrings[1], actor, batch_size=25)
        if remaining == 0:
            break
    assert remaining == 0
    with transaction(isolated_factory) as db:
        rows = db.scalars(select(PrivateKey)).all()
        assert len(rows) == 132 and {row.master_key_version for row in rows} == {2}
        for row in rows:
            assert unwrap_key(row, Keyring(2, {2: keyrings[1].keys[2]})).key_size == 256


def test_store_key_rollback_after_id_reservation_leaves_no_half_row(isolated_factory, keyrings, monkeypatch):
    from app.services import certificates as service

    actor = Actor(None, "system")
    original = service.wrap

    def fail_after_nextval(*args):
        raise RuntimeError("fixture encryption failure")

    with transaction(isolated_factory) as db:
        before = db.scalar(text("SELECT last_value FROM private_key_id_seq"))
    monkeypatch.setattr(service, "wrap", fail_after_nextval)
    with pytest.raises(RuntimeError, match="fixture encryption failure"), transaction(isolated_factory) as db:
        service.store_key(db, keyrings[0], ec.generate_private_key(ec.SECP256R1()), "generated", actor)
    with transaction(isolated_factory) as db:
        assert db.scalar(select(func.count()).select_from(PrivateKey)) == 0
        assert db.scalar(select(func.count()).select_from(AuditLog)) == 0
    monkeypatch.setattr(service, "wrap", original)
    with transaction(isolated_factory) as db:
        row = service.store_key(db, keyrings[0], ec.generate_private_key(ec.SECP256R1()), "generated", actor)
        assert row.id > before and row.ciphertext and len(row.nonce) == 12


@pytest.mark.parametrize("late_version", [1, 3])
def test_cli_rechecks_committed_late_legacy_rows(
    isolated_factory, keyrings, monkeypatch, capsys, late_version
):
    from types import SimpleNamespace

    from app import cli
    from app.crypto.keyring import Keyring
    from app.services.certificates import store_key

    actor = Actor(None, "system")
    with transaction(isolated_factory) as db:
        store_key(db, keyrings[0], ec.generate_private_key(ec.SECP256R1()), "generated", actor)
    monkeypatch.setattr(cli, "load_settings", lambda *args: SimpleNamespace(keyring=keyrings[1]))
    monkeypatch.setattr(cli, "create_session_factory", lambda _: isolated_factory)
    completed = 0

    @contextmanager
    def with_late_writer(factory):
        nonlocal completed
        with transaction(factory) as db:
            yield db
        completed += 1
        if completed == 2:  # preflight, then last batch has committed.
            ring = Keyring(late_version, {late_version: bytes([late_version]) * 32})
            with transaction(isolated_factory) as writer:
                store_key(writer, ring, ec.generate_private_key(ec.SECP256R1()), "generated", actor)

    monkeypatch.setattr(cli, "transaction", with_late_writer)
    assert cli.main(["rotate-master-key"]) == 1
    out, err = capsys.readouterr()
    assert "remaining=0" in out and "rotation incomplete" in err and "remaining=1" in err
    if late_version == 3:
        assert "missing_versions=3" in err
    assert "PRIVATE KEY" not in out + err
    assert completed == 3  # fresh final transaction, not a reused identity-map snapshot.


def test_database_rejects_unknown_private_key_origin(db, actor, keyrings):
    from app.services.certificates import store_key

    with pytest.raises(IntegrityError) as exc, db.begin_nested():
        store_key(db, keyrings[0], ec.generate_private_key(ec.SECP256R1()), "fixture-invalid-origin", actor)
    assert exc.value.orig.sqlstate == "23514"
