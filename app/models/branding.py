"""Replaceable logo storage (``docs/ux-spec.md`` A2-D1).

A singleton ``branding_asset`` row holds only sanitized bytes and their metadata; no row means the
default logo. ``branding_draft`` is the session-owned preview: the random token is kept by the
browser, only its SHA-256 is stored, and the row expires 30 minutes after Preview. A consumed row
is a short-lived receipt so retrying Save cannot create a second asset or audit row.
"""

from sqlalchemy import (
    CHAR,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, CreatedAt, Timestamps

BRANDING_MIMES = ("image/svg+xml", "image/png")
_MIMES_SQL = ", ".join(f"'{mime}'" for mime in BRANDING_MIMES)


class BrandingAsset(Timestamps, Base):
    """The active custom logo; ``sha256`` is the revision compared by save/reset."""

    __tablename__ = "branding_asset"
    __table_args__ = (
        CheckConstraint("id = 1", name="singleton"),
        CheckConstraint(f"mime IN ({_MIMES_SQL})", name="mime"),
        CheckConstraint("octet_length(content) <= 262144", name="content_size"),
    )
    id = mapped_column(SmallInteger, primary_key=True)
    mime = mapped_column(Text, nullable=False)
    content = mapped_column(LargeBinary, nullable=False)
    width = mapped_column(Integer, nullable=False)
    height = mapped_column(Integer, nullable=False)
    sha256 = mapped_column(Text, nullable=False)
    display_filename = mapped_column(Text, nullable=False)
    updated_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)


class BrandingDraft(CreatedAt, Base):
    """One pending preview per session, addressed by the SHA-256 of a random 256-bit token."""

    __tablename__ = "branding_draft"
    __table_args__ = (
        CheckConstraint(f"mime IS NULL OR mime IN ({_MIMES_SQL})", name="mime"),
        CheckConstraint("content IS NULL OR octet_length(content) <= 262144", name="content_size"),
        Index(
            "uq_branding_draft_session_open",
            "session_id",
            unique=True,
            postgresql_where=text("consumed_at IS NULL"),
        ),
    )
    token_sha256 = mapped_column(Text, primary_key=True)
    session_id = mapped_column(
        CHAR(64), ForeignKey("user_session.id", ondelete="CASCADE"), nullable=False
    )
    content: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    mime = mapped_column(Text, nullable=True)
    width = mapped_column(Integer, nullable=True)
    height = mapped_column(Integer, nullable=True)
    sha256 = mapped_column(Text, nullable=True)
    byte_size = mapped_column(Integer, nullable=True)
    display_filename = mapped_column(Text, nullable=True)
    base_revision = mapped_column(Text, nullable=False)
    expires_at = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at = mapped_column(DateTime(timezone=True), nullable=True)
