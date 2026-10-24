from sqlalchemy import ARRAY, BigInteger, Boolean, DateTime, Integer, LargeBinary, Text, text
from sqlalchemy.dialects.postgresql import CITEXT
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps
from app.models.enums import AuthBackend, pg_enum


class User(Timestamps, Base):
    __tablename__ = "user"
    id = mapped_column(BigInteger, primary_key=True)
    username = mapped_column(CITEXT, nullable=False, unique=True)
    email = mapped_column(CITEXT, nullable=False)
    display_name = mapped_column(Text, nullable=True)
    auth_backend = mapped_column(
        pg_enum(AuthBackend, "auth_backend"), nullable=False, server_default=text("'local'")
    )
    password_hash = mapped_column(Text, nullable=True)
    totp_secret_ciphertext = mapped_column(LargeBinary, nullable=True)
    totp_secret_nonce = mapped_column(LargeBinary, nullable=True)
    totp_secret_version = mapped_column(Integer, nullable=True)
    totp_enabled = mapped_column(Boolean, nullable=False, server_default=text("false"))
    totp_confirmed_at = mapped_column(DateTime(timezone=True), nullable=True)
    totp_last_used_step = mapped_column(BigInteger, nullable=True)
    recovery_codes = mapped_column(ARRAY(Text), nullable=False, server_default=text("'{}'"))
    is_active = mapped_column(Boolean, nullable=False, server_default=text("true"))
    failed_attempts = mapped_column(Integer, nullable=False, server_default=text("0"))
    locked_until = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at = mapped_column(DateTime(timezone=True), nullable=True)
    must_change_password = mapped_column(Boolean, nullable=False, server_default=text("false"))
