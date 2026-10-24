import base64
import json
import logging
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from alembic import command
from alembic.config import Config
from argon2 import PasswordHasher, Type, extract_parameters
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.crypto.keyring import Keyring, KeyUnwrapError, WrappedSecret, unwrap, wrap
from app.models import AuditLog, User, UserSession
from app.services.audit import Actor

PASSWORD = "fixture-strong-passphrase!"
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


@pytest.fixture(scope="module")
def engine(owner_engine, database_urls):
    name = "fixture_totp_" + uuid.uuid4().hex
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
def context(engine, now):
    from app.auth.local import hash_password

    factory = sessionmaker(engine, expire_on_commit=False)
    with factory.begin() as db:
        user = User(
            username="fixture-totp-" + uuid.uuid4().hex,
            email="fixture@example.test",
            password_hash=hash_password(PASSWORD),
        )
        db.add(user)
        db.flush()
        user_id, username = user.id, user.username
    return factory, user_id, Actor(user_id, username, "192.0.2.90"), Keyring(1, {1: bytes(range(32))}), now


def _begin(context):
    from app.auth.local import begin_totp

    factory, user_id, actor, keyring, _ = context
    with factory.begin() as db:
        return begin_totp(db, user_id, keyring, actor)


def _enable(context):
    from app.auth.local import confirm_totp

    enrollment = _begin(context)
    factory, user_id, actor, keyring, now = context
    with factory.begin() as db:
        assert confirm_totp(db, user_id, pyotp.TOTP(enrollment.secret).at(now), keyring, now, actor)
    return enrollment


def _sessions(db, user_id, now):
    for _ in range(2):
        db.add(
            UserSession(
                id=secrets.token_hex(32),
                user_id=user_id,
                csrf_token=secrets.token_hex(32),
                last_seen_at=now,
                expires_at=now + timedelta(hours=8),
                authenticated_at=now,
            )
        )


def test_enrollment_encrypts_with_user_aad_and_hashes_ten_recovery_codes(context):
    enrollment = _begin(context)
    factory, user_id, _, keyring, _ = context
    assert len(enrollment.recovery_codes) == len(set(enrollment.recovery_codes)) == 10
    assert all(len(code.replace("-", "")) == 32 for code in enrollment.recovery_codes)
    query = parse_qs(urlparse(enrollment.provisioning_uri).query)
    assert query["secret"] == [enrollment.secret] and query["issuer"] == ["Cert Dashboard"]
    assert enrollment.secret not in repr(enrollment)
    assert all(code not in repr(enrollment) for code in enrollment.recovery_codes)
    with factory() as db:
        user = db.get(User, user_id)
        assert not user.totp_enabled and user.totp_confirmed_at is None and user.totp_last_used_step is None
        wrapped = WrappedSecret(user.totp_secret_ciphertext, user.totp_secret_nonce, user.totp_secret_version)
        assert unwrap(keyring, wrapped, f"user:{user_id}:totp:1").decode() == enrollment.secret
        with pytest.raises(KeyUnwrapError):
            unwrap(keyring, wrapped, f"user:{user_id + 1}:totp:1")
        assert len(user.recovery_codes) == 10
        for encoded in user.recovery_codes:
            params = extract_parameters(encoded)
            assert (
                params.type,
                params.time_cost,
                params.memory_cost,
                params.parallelism,
                params.salt_len,
            ) == (Type.ID, 3, 65536, 4, 16)
        assert enrollment.secret.encode() not in user.totp_secret_ciphertext
        assert all(code not in str(user.recovery_codes) for code in enrollment.recovery_codes)


def test_rfc6238_sha1_six_digit_vector_and_single_step_replay(context, monkeypatch):
    from app.auth.local import confirm_totp, consume_second_factor

    monkeypatch.setattr(pyotp, "random_base32", lambda: RFC_SECRET)
    enrollment = _begin(context)
    assert enrollment.secret == RFC_SECRET
    factory, user_id, actor, keyring, _ = context
    instant = datetime.fromtimestamp(59, UTC)
    with factory.begin() as db:
        assert confirm_totp(db, user_id, "287082", keyring, instant, actor)  # RFC 6238 SHA-1, mod 10^6
    for moment in [instant, instant + timedelta(seconds=30)]:
        with factory.begin() as db:
            assert not consume_second_factor(db, user_id, "287082", keyring, moment, actor)
    with factory() as db:
        assert db.get(User, user_id).totp_last_used_step == 1


@pytest.mark.parametrize("offset, accepted", [(-2, False), (-1, True), (0, True), (1, True), (2, False)])
def test_confirmation_accepts_only_the_one_step_window(context, offset, accepted):
    from app.auth.local import confirm_totp

    enrollment = _begin(context)
    factory, user_id, actor, keyring, now = context
    code = pyotp.TOTP(enrollment.secret).at(now + timedelta(seconds=offset * 30))
    with factory.begin() as db:
        assert confirm_totp(db, user_id, code, keyring, now, actor) is accepted
    with factory() as db:
        user = db.get(User, user_id)
        assert user.totp_enabled is accepted
        if accepted:
            assert user.totp_last_used_step == int(now.timestamp()) // 30 + offset
            assert user.totp_confirmed_at == now


def test_pending_recovery_cannot_confirm_and_enabled_secret_cannot_be_replaced(context):
    from app.auth.local import begin_totp, confirm_totp, consume_second_factor

    enrollment = _begin(context)
    factory, user_id, actor, keyring, now = context
    with factory.begin() as db:
        assert not confirm_totp(db, user_id, enrollment.recovery_codes[0], keyring, now, actor)
        assert not consume_second_factor(db, user_id, enrollment.recovery_codes[0], keyring, now, actor)
    with factory.begin() as db:
        assert confirm_totp(db, user_id, pyotp.TOTP(enrollment.secret).at(now), keyring, now, actor)
    with factory.begin() as db, pytest.raises(ValueError, match="enabled"):
        begin_totp(db, user_id, keyring, actor)
    with factory() as db:
        assert db.get(User, user_id).totp_enabled


def test_pending_enrollment_restart_replaces_material_and_revokes_sessions(context):
    from app.auth.local import begin_totp

    first = _begin(context)
    factory, user_id, actor, keyring, now = context
    with factory.begin() as db:
        _sessions(db, user_id, now)
    with factory.begin() as db:
        second = begin_totp(db, user_id, keyring, actor)
    assert first.secret != second.secret and set(first.recovery_codes).isdisjoint(second.recovery_codes)
    with factory() as db:
        assert all(
            row.revoked_at is not None
            for row in db.scalars(select(UserSession).where(UserSession.user_id == user_id))
        )
        user = db.get(User, user_id)
        assert not user.totp_enabled
        assert (
            unwrap(
                keyring,
                WrappedSecret(user.totp_secret_ciphertext, user.totp_secret_nonce, 1),
                f"user:{user_id}:totp:1",
            ).decode()
            == second.secret
        )


def test_confirmation_and_disable_revoke_sessions_and_disable_clears_all_material(context):
    from app.auth.local import confirm_totp, disable_totp

    enrollment = _begin(context)
    factory, user_id, actor, keyring, now = context
    with factory.begin() as db:
        _sessions(db, user_id, now)
        assert confirm_totp(db, user_id, pyotp.TOTP(enrollment.secret).at(now), keyring, now, actor)
    with factory() as db:
        assert all(
            row.revoked_at == now
            for row in db.scalars(select(UserSession).where(UserSession.user_id == user_id))
        )
    with factory.begin() as db:
        _sessions(db, user_id, now)
        disable_totp(db, user_id, actor)
    with factory() as db:
        user = db.get(User, user_id)
        assert not user.totp_enabled and user.recovery_codes == []
        assert user.totp_secret_ciphertext is user.totp_secret_nonce is user.totp_secret_version is None
        assert user.totp_confirmed_at is user.totp_last_used_step is None
        assert all(
            row.revoked_at is not None
            for row in db.scalars(select(UserSession).where(UserSession.user_id == user_id))
        )


def test_recovery_is_case_dash_space_normalized_and_single_use(context):
    from app.auth.local import consume_second_factor

    enrollment = _enable(context)
    factory, user_id, actor, keyring, now = context
    code = enrollment.recovery_codes[0]
    with factory.begin() as db:
        assert consume_second_factor(
            db, user_id, "  " + code.lower().replace("-", " ") + "  ", keyring, now, actor
        )
    with factory.begin() as db:
        assert not consume_second_factor(db, user_id, code, keyring, now, actor)
    with factory() as db:
        assert len(db.get(User, user_id).recovery_codes) == 9


@pytest.mark.parametrize("kind", ["totp", "recovery"])
def test_two_requests_with_stale_loaded_rows_consume_a_code_once(context, kind):
    from app.auth.local import consume_second_factor

    enrollment = _enable(context)
    factory, user_id, actor, keyring, now = context
    moment = now + timedelta(seconds=30)
    code = pyotp.TOTP(enrollment.secret).at(moment) if kind == "totp" else enrollment.recovery_codes[0]
    barrier = Barrier(2)

    def consume(_):
        with factory.begin() as db:
            cached = db.get(User, user_id)
            barrier.wait(timeout=20)
            result = consume_second_factor(db, user_id, code, keyring, moment, actor)
            assert cached.id == user_id
            return result

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(consume, range(2))) == [False, True]
    with factory() as db:
        user = db.get(User, user_id)
        if kind == "totp":
            assert user.totp_last_used_step == int(moment.timestamp()) // 30
        else:
            assert len(user.recovery_codes) == 9


def test_password_success_cannot_reset_mfa_failures_and_lockout_expires(context):
    from app.auth.base import Success
    from app.auth.local import LocalAuthBackend, consume_second_factor

    enrollment = _enable(context)
    factory, user_id, actor, keyring, now = context
    clock = [now]
    backend = LocalAuthBackend(factory, lambda: clock[0])
    with factory.begin() as db:
        db.get(User, user_id).failed_attempts = 8
    for count in [9, 10]:
        assert isinstance(backend.authenticate(actor.label, PASSWORD), Success)
        with factory.begin() as db:
            assert not consume_second_factor(db, user_id, "invalid", keyring, clock[0], actor)
        with factory() as db:
            assert db.get(User, user_id).failed_attempts == count
    with factory.begin() as db:
        assert not consume_second_factor(db, user_id, enrollment.recovery_codes[0], keyring, now, actor)
        user = db.get(User, user_id)
        assert user.locked_until == now + timedelta(minutes=15) and len(user.recovery_codes) == 10
    clock[0] += timedelta(minutes=15)
    with factory.begin() as db:
        assert consume_second_factor(
            db, user_id, pyotp.TOTP(enrollment.secret).at(clock[0]), keyring, clock[0], actor
        )
    with factory() as db:
        user = db.get(User, user_id)
        assert user.failed_attempts == 0 and user.locked_until is None


def test_failed_confirmation_counts_and_success_resets_shared_lockout(context):
    from app.auth.base import Success
    from app.auth.local import LocalAuthBackend, confirm_totp

    enrollment = _begin(context)
    factory, user_id, actor, keyring, now = context
    with factory.begin() as db:
        db.get(User, user_id).failed_attempts = 9
    assert isinstance(LocalAuthBackend(factory, lambda: now).authenticate(actor.label, PASSWORD), Success)
    with factory.begin() as db:
        assert not confirm_totp(db, user_id, "invalid", keyring, now, actor)
    with factory.begin() as db:
        assert not confirm_totp(db, user_id, pyotp.TOTP(enrollment.secret).at(now), keyring, now, actor)
    later = now + timedelta(minutes=15)
    with factory.begin() as db:
        assert confirm_totp(db, user_id, pyotp.TOTP(enrollment.secret).at(later), keyring, later, actor)
    with factory() as db:
        user = db.get(User, user_id)
        assert user.failed_attempts == 0 and user.locked_until is None and user.totp_enabled


@pytest.mark.parametrize("failure", ["missing", "tag", "nonce", "row_binding", "invalid_secret"])
def test_missing_or_tampered_key_blocks_totp_but_recovery_is_independent(context, failure):
    from app.auth.local import consume_second_factor

    enrollment = _enable(context)
    factory, user_id, actor, keyring, now = context
    if failure == "missing":
        keyring = Keyring(2, {2: bytes(reversed(range(32)))})
    else:
        with factory.begin() as db:
            user = db.get(User, user_id)
            if failure in {"tag", "nonce"}:
                field = "totp_secret_ciphertext" if failure == "tag" else "totp_secret_nonce"
                value = getattr(user, field)
                setattr(user, field, bytes([value[0] ^ 1]) + value[1:])
            else:
                wrapped = wrap(
                    keyring,
                    b"fixture-invalid-base32" if failure == "invalid_secret" else RFC_SECRET.encode(),
                    f"user:{user_id + (failure == 'row_binding')}:totp:1",
                )
                user.totp_secret_ciphertext, user.totp_secret_nonce = wrapped.ciphertext, wrapped.nonce
    later = now + timedelta(seconds=30)
    with pytest.raises(KeyUnwrapError), factory.begin() as db:
        consume_second_factor(db, user_id, pyotp.TOTP(enrollment.secret).at(later), keyring, later, actor)
    with factory.begin() as db:
        assert consume_second_factor(db, user_id, enrollment.recovery_codes[0], keyring, later, actor)


def test_totp_and_recovery_material_never_appears_in_audit_or_logs(context, caplog):
    from app.auth.local import confirm_totp, consume_second_factor

    factory, user_id, actor, keyring, now = context
    with caplog.at_level(logging.DEBUG):
        enrollment = _begin(context)
        code = pyotp.TOTP(enrollment.secret).at(now)
        with factory.begin() as db:
            assert confirm_totp(db, user_id, code, keyring, now, actor)
        with factory.begin() as db:
            assert consume_second_factor(db, user_id, enrollment.recovery_codes[0], keyring, now, actor)
    with factory() as db:
        rows = list(
            db.scalars(
                select(AuditLog).where(AuditLog.target_id == str(user_id), AuditLog.target_type == "user")
            )
        )
        assert rows and any(row.action == "auth.recovery_used" for row in rows)
        output = caplog.text + json.dumps([row.details for row in rows])
        for sensitive in [
            enrollment.secret,
            enrollment.provisioning_uri,
            code,
            *enrollment.recovery_codes,
            *db.get(User, user_id).recovery_codes,
        ]:
            assert sensitive not in output
        assert "$argon2" not in output


def test_recovery_checks_all_ten_hash_slots_including_consumed_padding(context, monkeypatch):
    from app.auth.local import consume_second_factor

    enrollment = _enable(context)
    factory, user_id, actor, keyring, now = context
    original, calls = PasswordHasher.verify, []

    def verify(self, encoded, password):
        calls.append(1)
        return original(self, encoded, password)

    monkeypatch.setattr(PasswordHasher, "verify", verify)
    for code, expected in [
        (enrollment.recovery_codes[0], True),
        (enrollment.recovery_codes[0], False),
        (enrollment.recovery_codes[-1], True),
    ]:
        calls.clear()
        with factory.begin() as db:
            assert consume_second_factor(db, user_id, code, keyring, now, actor) is expected
        assert len(calls) == 10


def test_future_window_acceptance_never_allows_a_counter_to_move_backwards(context):
    from app.auth.local import confirm_totp, consume_second_factor

    enrollment = _begin(context)
    factory, user_id, actor, keyring, now = context
    totp = pyotp.TOTP(enrollment.secret)
    with factory.begin() as db:
        assert confirm_totp(db, user_id, totp.at(now + timedelta(seconds=30)), keyring, now, actor)
    with factory.begin() as db:
        assert not consume_second_factor(db, user_id, totp.at(now), keyring, now, actor)
        assert not consume_second_factor(
            db, user_id, totp.at(now + timedelta(seconds=30)), keyring, now, actor
        )
    with factory.begin() as db:
        moment = now + timedelta(seconds=60)
        assert consume_second_factor(db, user_id, totp.at(moment), keyring, moment, actor)


@pytest.mark.parametrize("kind", ["totp", "recovery"])
def test_caller_rollback_restores_code_and_audit_atomically(context, kind):
    from app.auth.local import consume_second_factor

    enrollment = _enable(context)
    factory, user_id, actor, keyring, now = context
    moment = now + timedelta(seconds=30)
    code = pyotp.TOTP(enrollment.secret).at(moment) if kind == "totp" else enrollment.recovery_codes[0]
    with pytest.raises(RuntimeError, match="fixture rollback"), factory.begin() as db:
        assert consume_second_factor(db, user_id, code, keyring, moment, actor)
        raise RuntimeError("fixture rollback")
    with factory.begin() as db:
        assert consume_second_factor(db, user_id, code, keyring, moment, actor)


def test_concurrent_mfa_failures_reach_one_shared_lockout(context):
    from app.auth.local import consume_second_factor

    _enable(context)
    factory, user_id, actor, keyring, now = context
    barrier = Barrier(10)

    def fail(_):
        with factory.begin() as db:
            barrier.wait(timeout=20)
            return consume_second_factor(db, user_id, "invalid", keyring, now, actor)

    with ThreadPoolExecutor(max_workers=10) as pool:
        assert list(pool.map(fail, range(10))) == [False] * 10
    with factory() as db:
        user = db.get(User, user_id)
        assert user.failed_attempts == 10 and user.locked_until == now + timedelta(minutes=15)
        actions = list(db.scalars(select(AuditLog.action).where(AuditLog.target_id == str(user_id))))
        assert actions.count("auth.mfa_failed") == 10 and actions.count("auth.lockout") == 1


def test_megabyte_factor_is_rejected_before_argon(context, monkeypatch):
    from app.auth.local import consume_second_factor

    _enable(context)
    factory, user_id, actor, keyring, now = context

    def forbidden(*args, **kwargs):
        pytest.fail("oversized factor reached Argon2")

    monkeypatch.setattr(PasswordHasher, "verify", forbidden)
    with factory.begin() as db:
        assert not consume_second_factor(db, user_id, "x" * 1_048_576, keyring, now, actor)


def test_inactive_user_cannot_enroll_or_consume_and_missing_user_fails_cleanly(context):
    from app.auth.local import begin_totp, confirm_totp, consume_second_factor, disable_totp

    enrollment = _enable(context)
    factory, user_id, actor, keyring, now = context
    with factory.begin() as db:
        db.get(User, user_id).is_active = False
    with factory.begin() as db:
        assert not consume_second_factor(db, user_id, enrollment.recovery_codes[0], keyring, now, actor)
        assert not confirm_totp(db, user_id, "123456", keyring, now, actor)
        with pytest.raises(ValueError, match="unavailable"):
            begin_totp(db, user_id, keyring, actor)
        assert not consume_second_factor(db, -1, "123456", keyring, now, actor)
        with pytest.raises(ValueError, match="unavailable"):
            disable_totp(db, -1, actor)
