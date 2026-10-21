from sqlalchemy import ARRAY, BigInteger, DateTime, ForeignKey, Integer, Text, text
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps
from app.models.enums import NotificationStatus, pg_enum


class NotificationLog(Timestamps, Base):
    __tablename__ = "notification_log"
    id = mapped_column(BigInteger, primary_key=True)
    certificate_id = mapped_column(BigInteger, ForeignKey("certificate.id"), nullable=True)
    kind = mapped_column(Text, nullable=False)
    threshold_days = mapped_column(Integer, nullable=True)
    recipients = mapped_column(ARRAY(Text), nullable=False)
    status = mapped_column(pg_enum(NotificationStatus, "notification_status"), nullable=False)
    error = mapped_column(Text, nullable=True)
    sent_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    dedupe_key = mapped_column(Text, nullable=False, unique=True)
    attempts = mapped_column(Integer, nullable=False, server_default=text("0"))
    next_attempt_at = mapped_column(DateTime(timezone=True), nullable=True)
