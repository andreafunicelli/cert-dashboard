"""Local first-factor authentication; callers must still enforce MFA and sessions.

Web must call allow_login_attempt before selecting/calling ANY authentication backend.
Rate limits use UTC minute windows and IPv6 /128, not /64; IPv4-mapped IPv6 shares
the IPv4 bucket. No forwarding headers are interpreted here: web supplies its trusted
source address. Passwords are never passed to audit or logging.
"""

import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv6Address, ip_address, ip_interface
from pathlib import Path

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.auth.base import AuthResult, Failure, Success, UserRecord
from app.models import LoginRateLimit, User
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


def _audit(db: Session, user: User | None, action: str, reason: str | None = None) -> None:
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
