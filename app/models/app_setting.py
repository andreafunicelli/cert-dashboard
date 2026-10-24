from sqlalchemy import BigInteger, ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps


class AppSetting(Timestamps, Base):
    __tablename__ = "app_setting"
    key = mapped_column(Text, primary_key=True)
    value = mapped_column(JSONB, nullable=False)
    updated_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
