from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, Text, func, text
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps
from app.models.enums import EndpointSource, ScanStatus, pg_enum


class Endpoint(Timestamps, Base):
    __tablename__ = "endpoint"
    id = mapped_column(BigInteger, primary_key=True)
    host = mapped_column(Text, nullable=False)
    port = mapped_column(Integer, nullable=False, server_default=text("443"))
    sni = mapped_column(Text, nullable=True)
    source = mapped_column(pg_enum(EndpointSource, "endpoint_source"), nullable=False)
    server_id = mapped_column(BigInteger, ForeignKey("server.id"), nullable=True)
    binding_id = mapped_column(BigInteger, ForeignKey("binding.id"), nullable=True)
    expected_certificate_id = mapped_column(BigInteger, ForeignKey("certificate.id"), nullable=True)
    is_active = mapped_column(Boolean, nullable=False, server_default=text("true"))
    last_scan_at = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_status = mapped_column(pg_enum(ScanStatus, "scan_status"), nullable=True)


Index(
    "uq_endpoint_identity",
    Endpoint.host,
    Endpoint.port,
    func.coalesce(Endpoint.sni, Endpoint.host),
    unique=True,
)
