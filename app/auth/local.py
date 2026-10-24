"""Local first-factor authentication; callers must still enforce MFA and sessions.

Web must call allow_login_attempt before selecting/calling ANY authentication backend.
Rate limits use UTC minute windows and IPv6 /128, not /64; IPv4-mapped IPv6 shares
the IPv4 bucket. No forwarding headers are interpreted here: web supplies its trusted
source address. Passwords are never passed to audit or logging.
"""

import binascii
import hashlib
import hmac
import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv6Address, ip_address, ip_interface
from pathlib import Path

import pyotp
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.auth.base import AuthResult, Failure, Success, UserRecord
from app.crypto.keyring import Keyring, KeyUnwrapError, WrappedSecret, unwrap, wrap
from app.models import LoginRateLimit, User, UserSession
from app.models.enums import AuthBackend as BackendName
from app.services.audit import Actor, record

_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, salt_len=16, type=Type.ID)
_DUMMY_HASH = _HASHER.hash(secrets.token_urlsafe(32))
_COMMON = frozenset(
    line.casefold()
    for line in (Path(__file__).resolve().parents[1] / "static/common-passwords.txt")
    .read_text(encoding="utf-8")
    .splitlines()
)
_MAX_PASSWORD_BYTES = 1024
_LOG = logging.getLogger(__name__)


def _bounded_password(password: str) -> bool:
    # Bound before encoding, including the large-input early return.
    if not isinstance(password, str) or len(password) > _MAX_PASSWORD_BYTES:
        return False
    try:
        return len(password.encode("utf-8")) <= _MAX_PASSWORD_BYTES
    except UnicodeError:
        return False


def hash_password(password: str) -> str:
    if not _bounded_password(password):
        raise ValueError("Password must be valid UTF-8 text of at most 1024 bytes.")
    if password.casefold() in _COMMON:
        raise ValueError("Password is too common; choose a different password.")
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    return _HASHER.hash(password)


def verify_password(encoded: str, password: str) -> bool:
    if not _bounded_password(password):
        return False
    try:
        return _HASHER.verify(encoded, password)
    except (VerificationError, InvalidHashError, TypeError):
        return False


def _audit(
    db: Session, user: User | None, action: str, reason: str | None = None, *, actor: Actor | None = None
) -> None:
    if actor is None:
        actor = Actor(user.id, user.username) if user is not None else Actor(None, "anonymous")
    record(
        db,
        actor,
        action,
        "user",
        str(user.id) if user is not None else None,
        {"reason": reason} if reason else {},
    )
    _LOG.info("Authentication event %s", action, extra={"user_id": actor.user_id})


class LocalAuthBackend:
    name = "local"

    def __init__(self, factory: sessionmaker[Session], clock: Callable[[], datetime]):
        self.factory = factory
        self.clock = clock

    def supports_password_change(self) -> bool:
        return True

    def lookup(self, username: str) -> UserRecord | None:
        with self.factory() as db:
            user = db.scalar(
                select(User).where(User.username == username, User.auth_backend == BackendName.LOCAL)
            )
            if user is None:
                return None
            return UserRecord(
                str(user.id),
                user.username,
                user.display_name or user.username,
                user.email,
                self.name,
                user.is_active,
            )

    def authenticate(self, username: str, password: str) -> AuthResult:
        try:
            # Holding the row through verify/audit prevents lost increments and success/failure races.
            with self.factory.begin() as db:
                user = db.scalar(
                    select(User)
                    .where(User.username == username, User.auth_backend == BackendName.LOCAL)
                    .with_for_update()
                )
                now = self.clock()
                reason = None
                if user is None:
                    reason = "invalid_credentials"
                elif not user.is_active:
                    reason = "inactive"
                elif user.locked_until is not None and user.locked_until > now:
                    reason = "locked"
                if reason is not None:
                    verify_password(_DUMMY_HASH, password)
                    _audit(db, user, "auth.login_failed", reason)
                    return Failure(reason)
                if user.locked_until is not None:
                    user.failed_attempts, user.locked_until = 0, None
                matches = verify_password(user.password_hash or _DUMMY_HASH, password)
                if not user.password_hash or not matches:
                    user.failed_attempts += 1
                    _audit(db, user, "auth.login_failed", "invalid_credentials")
                    if user.failed_attempts >= 10:
                        user.locked_until = now + timedelta(minutes=15)
                        _audit(db, user, "auth.lockout")
                    return Failure("invalid_credentials")
                if _HASHER.check_needs_rehash(user.password_hash):
                    # Verify enforces the input cap; creation policy does not invalidate legacy passwords.
                    user.password_hash = _HASHER.hash(password)
                if not user.totp_enabled and user.totp_secret_ciphertext is None:
                    user.failed_attempts, user.locked_until = 0, None
                _audit(db, user, "auth.login_success")
                return Success(str(user.id), user.display_name or user.username, user.email)
        except SQLAlchemyError:
            _LOG.warning("Authentication backend unavailable")
            return Failure("backend_unavailable")


def _source_ip(source_ip: str) -> str:
    try:
        if "%" in source_ip:
            raise ValueError
        address = ip_interface(source_ip) if "/" in source_ip else None
        if address is not None and address.network.prefixlen != address.max_prefixlen:
            raise ValueError
        address = address.ip if address is not None else ip_address(source_ip)
        if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return str(address)
    except (ValueError, TypeError):
        raise ValueError("Source must be a single IPv4 or IPv6 address.") from None


def allow_login_attempt(factory: sessionmaker[Session], source_ip: str, now: datetime) -> bool:
    """Consume an attempt atomically; fail closed on DB outage. Call before hashing."""
    ip = _source_ip(source_ip)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Login rate-limit time must be timezone-aware.")
    window = now.astimezone(UTC).replace(second=0, microsecond=0)
    statement = insert(LoginRateLimit).values(ip=ip, window_start=window, attempts=1)
    statement = statement.on_conflict_do_update(
        index_elements=[LoginRateLimit.ip, LoginRateLimit.window_start],
        set_={"attempts": func.least(LoginRateLimit.attempts + 1, 6)},
    ).returning(LoginRateLimit.attempts)
    try:
        with factory.begin() as db:
            return db.scalar(statement) <= 5
    except SQLAlchemyError:
        return False


@dataclass(frozen=True)
class Enrollment:
    secret: str = field(repr=False)
    provisioning_uri: str = field(repr=False)
    recovery_codes: tuple[str, ...] = field(repr=False)


def _locked_user(db: Session, user_id: int) -> User | None:
    return db.scalar(
        select(User).where(User.id == user_id).with_for_update().execution_options(populate_existing=True)
    )


def _revoke_mfa_sessions(db: Session, user_id: int, now: datetime | None = None) -> None:
    db.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now if now is not None else func.now())
    )


def begin_totp(db: Session, user_id: int, keyring: Keyring, actor: Actor) -> Enrollment:
    """Caller must require current-password reauthentication; commit before displaying once."""
    user = _locked_user(db, user_id)
    if user is None or not user.is_active:
        raise ValueError("User is unavailable.")
    if user.totp_enabled:
        raise ValueError("TOTP is already enabled; disable it before replacing enrollment.")
    secret = pyotp.random_base32()
    codes = tuple(
        "-".join(raw[index : index + 8] for index in range(0, 32, 8))
        for raw in (secrets.token_hex(16).upper() for _ in range(10))
    )
    encoded = [_HASHER.hash(code.replace("-", "")) for code in codes]
    encrypted = wrap(keyring, secret.encode("ascii"), f"user:{user.id}:totp:{keyring.active}")
    if user.totp_secret_ciphertext is not None:
        _revoke_mfa_sessions(db, user.id)
    user.totp_secret_ciphertext = encrypted.ciphertext
    user.totp_secret_nonce, user.totp_secret_version = encrypted.nonce, encrypted.version
    user.totp_enabled, user.totp_confirmed_at, user.totp_last_used_step = False, None, None
    user.recovery_codes = encoded
    _audit(db, user, "auth.totp_enroll", actor=actor)
    uri = pyotp.TOTP(secret, digest=hashlib.sha1, digits=6, interval=30).provisioning_uri(
        name=user.username, issuer_name="Cert Dashboard"
    )
    return Enrollment(secret, uri, codes)


def _mfa_ready(db: Session, user: User | None, now: datetime, actor: Actor) -> bool:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("MFA time must be timezone-aware.")
    if user is None or not user.is_active:
        _audit(db, user, "auth.mfa_failed", "invalid_credentials", actor=actor)
        return False
    if user.locked_until is not None:
        if user.locked_until > now:
            _audit(db, user, "auth.mfa_failed", "locked", actor=actor)
            return False
        user.failed_attempts, user.locked_until = 0, None
    return True


def _mfa_failure(db: Session, user: User, now: datetime, actor: Actor) -> bool:
    user.failed_attempts += 1
    _audit(db, user, "auth.mfa_failed", "invalid_code", actor=actor)
    if user.failed_attempts >= 10:
        user.locked_until = now + timedelta(minutes=15)
        _audit(db, user, "auth.lockout", actor=actor)
    return False


def _totp_step(user: User, code: str, keyring: Keyring, now: datetime) -> int | None:
    if not isinstance(code, str) or len(code) > 128:
        return None
    code = code.strip()
    if len(code) != 6 or not code.isascii() or not code.isdecimal():
        return None
    if any(
        value is None
        for value in (user.totp_secret_ciphertext, user.totp_secret_nonce, user.totp_secret_version)
    ):
        raise KeyUnwrapError()
    raw = unwrap(
        keyring,
        WrappedSecret(user.totp_secret_ciphertext, user.totp_secret_nonce, user.totp_secret_version),
        f"user:{user.id}:totp:{user.totp_secret_version}",
    )
    try:
        totp = pyotp.TOTP(raw.decode("ascii"), digest=hashlib.sha1, digits=6, interval=30)
        current = int(now.timestamp()) // 30
        matched = [
            step
            for step in range(max(0, current - 1), current + 2)
            if hmac.compare_digest(totp.generate_otp(step), code)
        ]
    except (ValueError, TypeError, UnicodeError, binascii.Error):
        raise KeyUnwrapError() from None
    finally:
        del raw
    if not matched or any(
        user.totp_last_used_step is not None and step <= user.totp_last_used_step for step in matched
    ):
        return None
    return max(matched)


def confirm_totp(db: Session, user_id: int, code: str, keyring: Keyring, now: datetime, actor: Actor) -> bool:
    """Caller commits False results too, preserving lockout counters and failure audits."""
    user = _locked_user(db, user_id)
    if not _mfa_ready(db, user, now, actor):
        return False
    if user.totp_enabled or user.totp_secret_ciphertext is None:
        return _mfa_failure(db, user, now, actor)
    step = _totp_step(user, code, keyring, now)
    if step is None:
        return _mfa_failure(db, user, now, actor)
    user.totp_enabled, user.totp_confirmed_at, user.totp_last_used_step = True, now, step
    user.failed_attempts, user.locked_until = 0, None
    _revoke_mfa_sessions(db, user.id, now)
    _audit(db, user, "auth.totp_enabled", actor=actor)
    return True


def _recovery_index(user: User, code: str) -> int | None:
    if not isinstance(code, str) or len(code) > 128:
        return None
    normalized = "".join(char for char in code.upper() if char != "-" and not char.isspace())
    if len(normalized) != 32 or any(char not in "0123456789ABCDEF" for char in normalized):
        return None
    # Check all ten positions, padding consumed slots, so neither match position nor
    # early success changes the number of constant-time Argon2 verifications.
    match = None
    for index in range(10):
        encoded = user.recovery_codes[index] if index < len(user.recovery_codes) else _DUMMY_HASH
        valid = verify_password(encoded, normalized)
        if valid and index < len(user.recovery_codes):
            match = index
    return match


def consume_second_factor(
    db: Session, user_id: int, code: str, keyring: Keyring, now: datetime, actor: Actor
) -> bool:
    """Verify under a row lock. Caller must enforce a prior password-verified session."""
    user = _locked_user(db, user_id)
    if not _mfa_ready(db, user, now, actor):
        return False
    if not user.totp_enabled:
        return _mfa_failure(db, user, now, actor)
    step = _totp_step(user, code, keyring, now)
    if step is not None:
        user.totp_last_used_step = step
        action = "auth.totp_verified"
    else:
        recovery = _recovery_index(user, code)
        if recovery is None:
            return _mfa_failure(db, user, now, actor)
        user.recovery_codes = [value for index, value in enumerate(user.recovery_codes) if index != recovery]
        action = "auth.recovery_used"
    user.failed_attempts, user.locked_until = 0, None
    _audit(db, user, action, actor=actor)
    return True


def disable_totp(db: Session, user_id: int, actor: Actor) -> None:
    """Caller authorizes self/admin reset and current-password reauthentication."""
    user = _locked_user(db, user_id)
    if user is None:
        raise ValueError("User is unavailable.")
    user.totp_enabled, user.totp_confirmed_at, user.totp_last_used_step = False, None, None
    user.totp_secret_ciphertext = user.totp_secret_nonce = user.totp_secret_version = None
    user.recovery_codes = []
    _revoke_mfa_sessions(db, user.id)
    _audit(db, user, "auth.totp_disabled", actor=actor)
