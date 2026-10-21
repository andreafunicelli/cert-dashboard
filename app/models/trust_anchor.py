from sqlalchemy import CHAR, BigInteger, ForeignKey, Text, text
from sqlalchemy.orm import mapped_column

from app.models.base import Base, CreatedAt
from app.models.enums import TrustAnchorSource, pg_enum


class TrustAnchor(CreatedAt, Base):
    __tablename__ = "trust_anchor"
    id = mapped_column(BigInteger, primary_key=True)
    subject = mapped_column(Text, nullable=False)
    sha256_fingerprint = mapped_column(CHAR(64), nullable=False, unique=True)
    pem = mapped_column(Text, nullable=False)
    source = mapped_column(
        pg_enum(TrustAnchorSource, "trust_anchor_source"), nullable=False, server_default=text("'uploaded'")
    )
    notes = mapped_column(Text, nullable=True)
    created_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
