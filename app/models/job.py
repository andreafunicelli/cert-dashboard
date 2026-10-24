from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps
from app.models.enums import JobStatus, JobType, pg_enum


class Job(Timestamps, Base):
    __tablename__ = "job"
    id = mapped_column(UUID, primary_key=True, server_default=text("gen_random_uuid()"))
    type = mapped_column(pg_enum(JobType, "job_type"), nullable=False)
    status = mapped_column(pg_enum(JobStatus, "job_status"), nullable=False, server_default=text("'queued'"))
    priority = mapped_column(Integer, nullable=False)
    payload = mapped_column(JSONB, nullable=False)
    requested_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
    scheduled_reason = mapped_column(Text, nullable=True)
    attempt = mapped_column(Integer, nullable=False, server_default=text("0"))
    max_attempts = mapped_column(Integer, nullable=False, server_default=text("3"))
    run_after = mapped_column(DateTime(timezone=True), nullable=False)
    timeout_at = mapped_column(DateTime(timezone=True), nullable=True)
    locked_by = mapped_column(Text, nullable=True)
    locked_at = mapped_column(DateTime(timezone=True), nullable=True)
    started_at = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at = mapped_column(DateTime(timezone=True), nullable=True)
    error_class = mapped_column(Text, nullable=True)
    error_message = mapped_column(Text, nullable=True)
    result = mapped_column(JSONB, nullable=True)
    resume_from_batch = mapped_column(Integer, nullable=False, server_default=text("0"))
    paused_at = mapped_column(DateTime(timezone=True), nullable=True)
    ansible_artifact_dir = mapped_column(Text, nullable=True)


Index(
    "ix_job_claim_queued",
    Job.priority.desc(),
    Job.run_after,
    Job.created_at,
    postgresql_where=Job.status == "queued",
)
