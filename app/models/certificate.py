from sqlalchemy import (
    ARRAY,
    CHAR,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps
from app.models.enums import CertificateStatus, ChainStatus, pg_enum


class Certificate(Timestamps, Base):
    __tablename__ = "certificate"
    id = mapped_column(BigInteger, primary_key=True)
    common_name = mapped_column(Text, nullable=False)
    subject_dn = mapped_column(Text, nullable=False)
    sans = mapped_column(ARRAY(Text), nullable=False, server_default=text("'{}'"))
    issuer_dn = mapped_column(Text, nullable=False)
    issuer_cn = mapped_column(Text, nullable=False)
    serial = mapped_column(Text, nullable=False)
    not_before = mapped_column(DateTime(timezone=True), nullable=False)
    not_after = mapped_column(DateTime(timezone=True), nullable=False)
    sha256_fingerprint = mapped_column(CHAR(64), nullable=False, unique=True)
    pem = mapped_column(Text, nullable=False)
    chain_pem = mapped_column(Text, nullable=False, server_default=text("''"))
    chain_status = mapped_column(
        pg_enum(ChainStatus, "chain_status"), nullable=False, server_default=text("'unchecked'")
    )
    key_id = mapped_column(BigInteger, ForeignKey("private_key.id"), nullable=True)
    owner_name = mapped_column(Text, nullable=True)
    owner_email = mapped_column(Text, nullable=True)
    team = mapped_column(Text, nullable=True)
    notes = mapped_column(Text, nullable=True)
    status = mapped_column(
        pg_enum(CertificateStatus, "certificate_status"), nullable=False, server_default=text("'active'")
    )
    renews_id = mapped_column(BigInteger, ForeignKey("certificate.id"), nullable=True)
    imported_from = mapped_column(Text, nullable=False)
    created_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
    __table_args__ = (
        UniqueConstraint("issuer_dn", "serial"),
        CheckConstraint("not_after > not_before", name="validity"),
        CheckConstraint(
            "key_id IS NOT NULL OR imported_from IN ('upload_pem','upload_pfx','pull_endpoint')",
            name="required_key",
        ),
        Index("ix_certificate_not_after", "not_after"),
        Index("ix_certificate_status_not_after", "status", "not_after"),
        Index("ix_certificate_sans", "sans", postgresql_using="gin"),
    )
