import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier

import pytest
from alembic import command
from alembic.config import Config
from argon2 import PasswordHasher, Type, extract_parameters
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import sessionmaker

from app.models import AuditLog, LoginRateLimit, User

PASSWORD = "fixture-strong-passphrase!"


@pytest.fixture(scope="module")
def engine(owner_engine, database_urls):
    # Authentication commits failures/audit in independent transactions. Isolate
    # the database rather than deleting append-only audit history for cleanup.
    name = "fixture_auth_" + uuid.uuid4().hex
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.exec_driver_sql(f'CREATE DATABASE "{name}"')
    cfg = Config("alembic.ini")
    cfg.attributes["database_url"] = owner_engine.url.set(database=name)
    command.upgrade(cfg, "head")
    app = create_engine(database_urls[1].set(database=name))
    yield app
    app.dispose()
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.exec_driver_sql(f'DROP DATABASE "{name}" WITH (FORCE)')


@pytest.fixture
def auth_context(engine, now):
    from app.auth.local import LocalAuthBackend, hash_password

    factory = sessionmaker(engine, expire_on_commit=False)
    username = "fixture-auth-" + uuid.uuid4().hex
    with factory.begin() as db:
        user = User(
            username=username,
            email="fixture@example.test",
            display_name="Fixture",
            password_hash=hash_password(PASSWORD),
        )
        db.add(user)
        db.flush()
        user_id = user.id
    clock = [now]
    backend = LocalAuthBackend(factory, lambda: clock[0])
    return backend, factory, username, user_id, clock


def test_password_policy_parameters_roundtrip_and_unique_salts():
    from app.auth.local import hash_password, verify_password

    first, second = hash_password(PASSWORD), hash_password(PASSWORD)
    params = extract_parameters(first)
    assert (params.type, params.time_cost, params.memory_cost, params.parallelism, params.salt_len) == (
        Type.ID,
        3,
        65536,
        4,
        16,
    )
    assert first != second
    assert verify_password(first, PASSWORD)
    assert not verify_password(first, "fixture-wrong-password")
    assert not verify_password("not-an-argon2-hash", PASSWORD)


@pytest.mark.parametrize(
    "password, hint",
    [("X!bad", "12"), ("PASSWORD", "common"), ("x" * 1_048_576, "1024")],
    ids=["short", "common", "megabyte"],
)
def test_creation_policy_rejects_before_hashing(password, hint, monkeypatch):
    from app.auth.local import hash_password

    def must_not_hash(*args, **kwargs):
        pytest.fail("rejected password reached Argon2")

    monkeypatch.setattr(PasswordHasher, "hash", must_not_hash)
    with pytest.raises(ValueError, match=hint):
        hash_password(password)


def test_vendored_denylist_is_exactly_one_thousand_known_passwords():
    entries = (
        (Path(__file__).resolve().parents[2] / "app/static/common-passwords.txt").read_text().splitlines()
    )
    assert len(entries) == len(set(entries)) == 1000
    assert "password" in entries and "123456" in entries and "qwerty" in entries


def test_lockout_is_persistent_expires_and_resets_failures(auth_context):
    from app.auth.base import Failure, Success
    from app.auth.local import LocalAuthBackend

    backend, factory, username, user_id, clock = auth_context
    for _ in range(10):
        assert isinstance(backend.authenticate(username, "wrong"), Failure)
    restarted = LocalAuthBackend(factory, lambda: clock[0])
    assert restarted.authenticate(username, PASSWORD) == Failure("locked")
    with factory() as db:
        user = db.get(User, user_id)
        assert user.failed_attempts == 10 and user.locked_until == clock[0] + timedelta(minutes=15)
        actions = list(db.scalars(select(AuditLog.action).where(AuditLog.actor_user_id == user_id)))
        assert actions.count("auth.login_failed") == 11 and actions.count("auth.lockout") == 1
    clock[0] += timedelta(minutes=15)
    assert restarted.authenticate(username.upper(), PASSWORD) == Success(
        str(user_id), "Fixture", "fixture@example.test"
    )
    with factory() as db:
        user = db.get(User, user_id)
        assert user.failed_attempts == 0 and user.locked_until is None
    assert isinstance(restarted.authenticate(username, "wrong"), Failure)
    assert isinstance(restarted.authenticate(username, PASSWORD), Success)
    with factory() as db:
        assert db.get(User, user_id).failed_attempts == 0


def test_expired_lockout_wrong_password_starts_a_new_failure_streak(auth_context):
    from app.auth.base import Failure

    backend, factory, username, user_id, clock = auth_context
    with factory.begin() as db:
        user = db.get(User, user_id)
        user.failed_attempts, user.locked_until = 10, clock[0]
    assert backend.authenticate(username, "wrong") == Failure("invalid_credentials")
    with factory() as db:
        user = db.get(User, user_id)
        assert user.failed_attempts == 1 and user.locked_until is None


def test_unknown_and_inactive_accounts_do_real_dummy_work_and_have_generic_messages(
    auth_context, monkeypatch
):
    from app.auth.base import Failure

    backend, factory, username, user_id, _ = auth_context
    original = PasswordHasher.verify
    calls = []

    def spy(self, encoded, password):
        calls.append(encoded)
        return original(self, encoded, password)

    monkeypatch.setattr(PasswordHasher, "verify", spy)
    unknown = backend.authenticate("absent-" + uuid.uuid4().hex, PASSWORD)
    wrong = backend.authenticate(username, "wrong")
    with factory.begin() as db:
        user = db.get(User, user_id)
        encoded = user.password_hash
        user.is_active = False
    inactive = backend.authenticate(username, PASSWORD)
    assert len(calls) == 3 and calls[0] != encoded and calls[1] == encoded and calls[2] != encoded
    assert unknown == wrong == Failure("invalid_credentials") and inactive == Failure("inactive")
    assert unknown.message == wrong.message == inactive.message == Failure("locked").message
    assert username not in unknown.message


def test_login_rehashes_an_outdated_hash(auth_context):
    from app.auth.base import Success

    backend, factory, username, user_id, _ = auth_context
    old = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(PASSWORD)
    with factory.begin() as db:
        db.get(User, user_id).password_hash = old
    assert isinstance(backend.authenticate(username, PASSWORD), Success)
    with factory() as db:
        current = db.get(User, user_id).password_hash
        params = extract_parameters(current)
        assert current != old and (params.time_cost, params.memory_cost, params.parallelism) == (3, 65536, 4)


def test_missing_password_hash_can_never_authenticate_against_dummy(auth_context, monkeypatch):
    from app.auth import local
    from app.auth.base import Failure

    backend, factory, username, user_id, _ = auth_context
    with factory.begin() as db:
        db.get(User, user_id).password_hash = None
    # Even if a submitted password verifies against the dummy, it grants no identity.
    monkeypatch.setattr(local, "_DUMMY_HASH", PasswordHasher().hash(PASSWORD))
    assert backend.authenticate(username, PASSWORD) == Failure("invalid_credentials")


def test_concurrent_failures_are_not_lost(auth_context):
    from app.auth.base import Failure

    backend, factory, username, user_id, _ = auth_context
    barrier = Barrier(10)

    def fail(_):
        barrier.wait(timeout=20)
        return backend.authenticate(username, "wrong")

    with ThreadPoolExecutor(max_workers=10) as pool:
        assert all(isinstance(result, Failure) for result in pool.map(fail, range(10)))
    with factory() as db:
        assert db.get(User, user_id).failed_attempts == 10
        assert db.get(User, user_id).locked_until is not None


def test_password_and_hash_never_reach_logs_or_audit(auth_context, caplog):
    backend, factory, username, user_id, _ = auth_context
    submitted = "fixture-secret-password=never-audit-this"
    with caplog.at_level(logging.DEBUG):
        backend.authenticate(username, submitted)
        backend.authenticate(username, PASSWORD)
    with factory() as db:
        rows = list(db.scalars(select(AuditLog).where(AuditLog.actor_user_id == user_id)))
        assert {row.action for row in rows} == {"auth.login_failed", "auth.login_success"}
        text = json.dumps([row.details for row in rows]) + caplog.text
        assert submitted not in text and PASSWORD not in text and "$argon2" not in text
        assert all(set(row.details) <= {"reason"} for row in rows)


def test_megabyte_login_password_is_rejected_before_verify_or_rehash(auth_context, monkeypatch):
    from app.auth.base import Failure

    backend, _, username, _, _ = auth_context

    def forbidden(*args, **kwargs):
        pytest.fail("unbounded input reached Argon2")

    monkeypatch.setattr(PasswordHasher, "verify", forbidden)
    monkeypatch.setattr(PasswordHasher, "hash", forbidden)
    assert backend.authenticate(username, "x" * 1_048_576) == Failure("invalid_credentials")
    assert backend.authenticate("absent", "x" * 1_048_576) == Failure("invalid_credentials")


@pytest.mark.parametrize("flavor", ["local", "fake"])
def test_auth_backend_contract_supports_local_and_nonlocal_identities(auth_context, flavor):
    from app.auth.base import AuthBackend, Failure, Success, UserRecord

    local, _, username, user_id, _ = auth_context

    class Fake:
        name = "fake-directory"

        def authenticate(self, username, password):
            return (
                Success("directory:one", "Directory User", "fixture@example.test")
                if (username == "fixture" and password == PASSWORD)
                else Failure("invalid_credentials")
            )

        def lookup(self, username):
            return (
                UserRecord(
                    "directory:one", "fixture", "Directory User", "fixture@example.test", self.name, True
                )
                if username == "fixture"
                else None
            )

        def supports_password_change(self):
            return False

    backend = local if flavor == "local" else Fake()
    name = username if flavor == "local" else "fixture"
    assert isinstance(backend, AuthBackend)
    result = backend.authenticate(name, PASSWORD)
    assert isinstance(result, Success)
    user = backend.lookup(name.upper() if flavor == "local" else name)
    assert user.user_key == result.user_key == (str(user_id) if flavor == "local" else "directory:one")
    assert user.backend == backend.name and user.is_active
    assert not hasattr(user, "password_hash")
    assert backend.lookup("absent") is None
    assert isinstance(backend.authenticate(name, "wrong"), Failure)
    assert backend.supports_password_change() == (flavor == "local")


def test_ldap_stub_never_falls_back_to_local(auth_context):
    from app.auth.base import AuthBackend, Failure
    from app.auth.ldap import LDAPAuthBackend

    _, _, username, _, _ = auth_context
    backend = LDAPAuthBackend()
    assert isinstance(backend, AuthBackend) and backend.name == "ldap"
    assert backend.authenticate(username, PASSWORD) == Failure("not_supported")
    assert backend.lookup(username) is None and not backend.supports_password_change()


def test_database_outage_fails_closed_without_exception_details(auth_context, monkeypatch):
    from sqlalchemy.exc import OperationalError

    from app.auth.base import Failure

    backend, factory, username, _, _ = auth_context

    def unavailable():
        raise OperationalError("fixture-sensitive-query", {}, Exception("fixture-private-details"))

    with monkeypatch.context() as patch:
        patch.setattr(factory, "begin", unavailable)
        result = backend.authenticate(username, PASSWORD)
    assert result == Failure("backend_unavailable")
    assert "fixture" not in result.message


@pytest.mark.parametrize("ip", ["192.0.2.71", "2001:db8::71"])
def test_rate_limit_persists_five_attempts_per_minute(engine, now, ip):
    from app.auth.local import allow_login_attempt

    factory = sessionmaker(engine)
    try:
        assert [allow_login_attempt(factory, ip, now) for _ in range(6)] == [True] * 5 + [False]
        assert not allow_login_attempt(sessionmaker(engine), ip, now)
        assert allow_login_attempt(factory, ip, now + timedelta(minutes=1))
    finally:
        with factory.begin() as db:
            db.execute(delete(LoginRateLimit).where(LoginRateLimit.ip == ip))


def test_rate_limit_canonicalizes_ipv6_and_ipv4_mapped_addresses(engine, now):
    from app.auth.local import allow_login_attempt

    factory = sessionmaker(engine)
    try:
        for _ in range(5):
            assert allow_login_attempt(factory, "2001:0db8:0000:0000:0000:0000:0000:72/128", now)
            assert allow_login_attempt(factory, "::ffff:192.0.2.72", now)
        assert not allow_login_attempt(factory, "2001:db8::72", now)
        assert not allow_login_attempt(factory, "192.0.2.72", now)
        assert allow_login_attempt(factory, "2001:db8::73", now)  # deliberate /128, not /64
    finally:
        with factory.begin() as db:
            db.execute(
                delete(LoginRateLimit).where(
                    LoginRateLimit.ip.in_(["2001:db8::72", "192.0.2.72", "2001:db8::73"])
                )
            )


def test_concurrent_rate_limit_cannot_admit_a_sixth_request(engine, now):
    from app.auth.local import allow_login_attempt

    factory, barrier = sessionmaker(engine), Barrier(12)
    ip = "192.0.2.74"

    def attempt(_):
        barrier.wait(timeout=20)
        return allow_login_attempt(factory, ip, now)

    try:
        with ThreadPoolExecutor(max_workers=12) as pool:
            assert sum(pool.map(attempt, range(12))) == 5
        with factory() as db:
            assert db.get(LoginRateLimit, (ip, now.replace(second=0, microsecond=0))).attempts >= 6
    finally:
        with factory.begin() as db:
            db.execute(delete(LoginRateLimit).where(LoginRateLimit.ip == ip))


@pytest.mark.parametrize(
    "password",
    [None, b"fixture", "\ud800" * 12, "é" * 513],
    ids=["none", "bytes", "surrogate", "utf8-oversize"],
)
def test_invalid_passwords_fail_closed_before_argon(password, monkeypatch):
    from app.auth.local import hash_password, verify_password

    def forbidden(*args, **kwargs):
        pytest.fail("invalid input reached Argon2")

    monkeypatch.setattr(PasswordHasher, "verify", forbidden)
    monkeypatch.setattr(PasswordHasher, "hash", forbidden)
    assert not verify_password("unused", password)
    with pytest.raises(ValueError):
        hash_password(password)


def test_password_policy_accepts_twelve_characters_and_utf8_byte_boundary():
    from app.auth.local import hash_password, verify_password

    for password in ["fixture-pass", "é" * 512]:
        assert verify_password(hash_password(password), password)


@pytest.mark.parametrize("ip", ["2001:db8::/64", "192.0.2.0/24", "fe80::1%eth0", "not-an-ip", None])
def test_invalid_source_addresses_are_refused_without_consuming_attempts(engine, now, ip):
    from app.auth.local import allow_login_attempt

    with pytest.raises(ValueError, match="single IPv4 or IPv6"):
        allow_login_attempt(sessionmaker(engine), ip, now)


def test_rate_limit_normalizes_timezone_and_fails_closed_on_db_outage(engine, now, monkeypatch):
    from datetime import timezone

    from sqlalchemy.exc import OperationalError

    from app.auth.local import allow_login_attempt

    factory, ip = sessionmaker(engine), "192.0.2.75"
    try:
        other_zone = now.astimezone(timezone(timedelta(hours=5)))
        assert [allow_login_attempt(factory, ip, other_zone) for _ in range(5)] == [True] * 5
        assert not allow_login_attempt(factory, ip, now)
        with pytest.raises(ValueError, match="timezone-aware"):
            allow_login_attempt(factory, ip, now.replace(tzinfo=None))

        def unavailable():
            raise OperationalError("fixture-query", {}, Exception("fixture-private-details"))

        with monkeypatch.context() as patch:
            patch.setattr(factory, "begin", unavailable)
            assert not allow_login_attempt(factory, ip, now)
    finally:
        with factory.begin() as db:
            db.execute(delete(LoginRateLimit).where(LoginRateLimit.ip == ip))
