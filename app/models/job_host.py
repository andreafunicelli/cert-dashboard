from sqlalchemy import (
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
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps
from app.models.enums import JobHostStatus, pg_enum


class JobHost(Timestamps, Base):
    __tablename__ = "job_host"
    id = mapped_column(UUID, primary_key=True, server_default=text("gen_random_uuid()"))
    job_id = mapped_column(UUID, ForeignKey("job.id", ondelete="CASCADE"), nullable=False)
    server_id = mapped_column(BigInteger, ForeignKey("server.id"), nullable=False)
    binding_id = mapped_column(BigInteger, ForeignKey("binding.id"), nullable=True)
    batch_no = mapped_column(Integer, nullable=False, server_default=text("0"))
    status = mapped_column(
        pg_enum(JobHostStatus, "job_host_status"), nullable=False, server_default=text("'pending'")
    )
    started_at = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at = mapped_column(DateTime(timezone=True), nullable=True)
    old_fingerprint = mapped_column(CHAR(64), nullable=True)
    new_fingerprint = mapped_column(CHAR(64), nullable=True)
    ansible_return_code = mapped_column(Integer, nullable=True)
    log_excerpt = mapped_column(Text, nullable=True)
    error_message = mapped_column(Text, nullable=True)
    rolled_back = mapped_column(Boolean, nullable=False, server_default=text("false"))
    rollback_error = mapped_column(Text, nullable=True)
    precheck = mapped_column(JSONB, nullable=True)
    __table_args__ = (
        UniqueConstraint("job_id", "server_id", "binding_id"),
        Index("ix_job_host_status", "job_id", "status"),
        Index("ix_job_host_batch", "job_id", "batch_no"),
    )
