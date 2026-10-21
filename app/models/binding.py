from sqlalchemy import (
    ARRAY,
    CHAR,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps
from app.models.enums import WebserverType, pg_enum


class Binding(Timestamps, Base):
    __tablename__ = "binding"
    id = mapped_column(BigInteger, primary_key=True)
    server_id = mapped_column(BigInteger, ForeignKey("server.id"), nullable=False)
    webserver = mapped_column(pg_enum(WebserverType, "webserver_type"), nullable=False)
    vhost_name = mapped_column(Text, nullable=False)
    vhost_names = mapped_column(ARRAY(Text), nullable=False)
    port = mapped_column(Integer, nullable=False, server_default=text("443"))
    config_file = mapped_column(Text, nullable=False)
    cert_path = mapped_column(Text, nullable=False)
    chain_path = mapped_column(Text, nullable=True)
    key_path = mapped_column(Text, nullable=False)
    cert_owner = mapped_column(Text, nullable=True)
    cert_group = mapped_column(Text, nullable=True)
    cert_mode = mapped_column(Integer, nullable=True)
    key_owner = mapped_column(Text, nullable=True)
    key_group = mapped_column(Text, nullable=True)
    key_mode = mapped_column(Integer, nullable=True)
    on_disk_fingerprint = mapped_column(CHAR(64), nullable=True)
    on_disk_key_public_sha256 = mapped_column(CHAR(64), nullable=True)
    certificate_id = mapped_column(BigInteger, ForeignKey("certificate.id"), nullable=True)
    match_state = mapped_column(Text, nullable=False)
    last_seen_at = mapped_column(DateTime(timezone=True), nullable=False)
    is_active = mapped_column(Boolean, nullable=False, server_default=text("true"))
    notes = mapped_column(Text, nullable=True)
    __table_args__ = (
        UniqueConstraint(
            "server_id",
            "webserver",
            "config_file",
            "port",
            "vhost_name",
            "cert_path",
            postgresql_nulls_not_distinct=True,
        ),
        Index("ix_binding_certificate_id", "certificate_id"),
        Index("ix_binding_server_active", "server_id", "is_active"),
        Index("ix_binding_match_state", "match_state"),
    )
