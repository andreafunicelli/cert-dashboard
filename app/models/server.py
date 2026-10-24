from sqlalchemy import ARRAY, BigInteger, Boolean, DateTime, Text, text
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps
from app.models.enums import WebserverType, pg_enum


class Server(Timestamps, Base):
    __tablename__ = "server"
    id = mapped_column(BigInteger, primary_key=True)
    hostname = mapped_column(Text, nullable=False, unique=True)
    display_name = mapped_column(Text, nullable=True)
    ansible_groups = mapped_column(ARRAY(Text), nullable=False, server_default=text("'{}'"))
    webserver = mapped_column(pg_enum(WebserverType, "webserver_type"), nullable=True)
    connection_address = mapped_column(Text, nullable=True)
    inventory_source = mapped_column(Text, nullable=False)
    last_discovery_at = mapped_column(DateTime(timezone=True), nullable=True)
    last_discovery_status = mapped_column(Text, nullable=True)
    is_active = mapped_column(Boolean, nullable=False, server_default=text("true"))
    notes = mapped_column(Text, nullable=True)
