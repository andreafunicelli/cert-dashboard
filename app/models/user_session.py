from sqlalchemy import CHAR, BigInteger, DateTime, ForeignKey, Text
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps


class UserSession(Timestamps, Base):
    __tablename__ = "user_session"
    id = mapped_column(CHAR(64), primary_key=True)
    user_id = mapped_column(BigInteger, ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    csrf_token = mapped_column(CHAR(64), nullable=False)
    last_seen_at = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at = mapped_column(DateTime(timezone=True), nullable=False)
    ip = mapped_column(Text, nullable=True)
    user_agent = mapped_column(Text, nullable=True)
    revoked_at = mapped_column(DateTime(timezone=True), nullable=True)
    authenticated_at = mapped_column(DateTime(timezone=True), nullable=True)
