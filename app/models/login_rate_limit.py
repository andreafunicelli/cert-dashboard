from sqlalchemy import DateTime, Integer
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps


class LoginRateLimit(Timestamps, Base):
    __tablename__ = "login_rate_limit"
    ip = mapped_column(INET, primary_key=True)
    window_start = mapped_column(DateTime(timezone=True), primary_key=True)
    attempts = mapped_column(Integer, nullable=False)
