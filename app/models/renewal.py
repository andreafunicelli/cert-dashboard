from sqlalchemy import ARRAY, CHAR, BigInteger, CheckConstraint, DateTime, ForeignKey, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps
from app.models.enums import RenewalState, pg_enum


class Renewal(Timestamps, Base):
    __tablename__ = "renewal"
    id = mapped_column(UUID, primary_key=True, server_default=text("gen_random_uuid()"))
    certificate_id = mapped_column(BigInteger, ForeignKey("certificate.id"), nullable=True)
    previous_certificate_id = mapped_column(BigInteger, ForeignKey("certificate.id"), nullable=True)
    state = mapped_column(
        pg_enum(RenewalState, "renewal_state"), nullable=False, server_default=text("'draft'")
    )
    common_name = mapped_column(Text, nullable=False)
    sans = mapped_column(ARRAY(Text), nullable=False)
    key_id = mapped_column(BigInteger, ForeignKey("private_key.id"), nullable=True)
    csr_pem = mapped_column(Text, nullable=True)
    csr_sha256 = mapped_column(CHAR(64), nullable=True)
    ca_name = mapped_column(Text, nullable=True)
    ca_order_reference = mapped_column(Text, nullable=True)
    issued_chain_pem = mapped_column(Text, nullable=True)
    state_changed_at = mapped_column(DateTime(timezone=True), nullable=False)
    created_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
    submitted_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
    issued_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
    deployed_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
    notes = mapped_column(Text, nullable=True)
    __table_args__ = (
        CheckConstraint("key_id IS NOT NULL OR state IN ('draft','cancelled')", name="required_key"),
    )
