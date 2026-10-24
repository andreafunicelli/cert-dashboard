from sqlalchemy import CHAR, BigInteger, DateTime, ForeignKey, Index, Integer, Text, text
from sqlalchemy.orm import mapped_column

from app.models.base import Base, CreatedAt
from app.models.enums import ScanStatus, pg_enum


class ScanResult(CreatedAt, Base):
    __tablename__ = "scan_result"
    id = mapped_column(BigInteger, primary_key=True)
    endpoint_id = mapped_column(BigInteger, ForeignKey("endpoint.id"), nullable=False)
    status = mapped_column(pg_enum(ScanStatus, "scan_status"), nullable=False)
    observed_fingerprint = mapped_column(CHAR(64), nullable=True)
    observed_common_name = mapped_column(Text, nullable=True)
    observed_issuer_cn = mapped_column(Text, nullable=True)
    observed_not_after = mapped_column(DateTime(timezone=True), nullable=True)
    observed_chain_length = mapped_column(Integer, nullable=True)
    expected_certificate_id = mapped_column(BigInteger, ForeignKey("certificate.id"), nullable=True)
    tls_version = mapped_column(Text, nullable=True)
    error = mapped_column(Text, nullable=True)
    source = mapped_column(Text, nullable=False)
    checked_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    elapsed_ms = mapped_column(Integer, nullable=True)


Index("ix_scan_result_endpoint_checked", ScanResult.endpoint_id, ScanResult.checked_at.desc())
Index("ix_scan_result_status_checked", ScanResult.status, ScanResult.checked_at.desc())
