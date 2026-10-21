from sqlalchemy import DateTime, Text
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps


class SchedulerState(Timestamps, Base):
    __tablename__ = "scheduler_state"
    key = mapped_column(Text, primary_key=True)
    last_run_at = mapped_column(DateTime(timezone=True), nullable=True)
