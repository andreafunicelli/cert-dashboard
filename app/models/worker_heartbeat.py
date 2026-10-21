from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps


class WorkerHeartbeat(Timestamps, Base):
    __tablename__ = "worker_heartbeat"
    worker_id = mapped_column(Text, primary_key=True)
    started_at = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at = mapped_column(DateTime(timezone=True), nullable=False)
    current_job_id = mapped_column(UUID, ForeignKey("job.id", ondelete="SET NULL"), nullable=True)
