from sqlalchemy import BigInteger, ForeignKey, Text, text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import mapped_column

from app.models.base import Base, CreatedAt


class AuditLog(CreatedAt, Base):
    __tablename__ = "audit_log"
    id = mapped_column(UUID, primary_key=True, server_default=text("gen_random_uuid()"))
    actor_user_id = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
    actor_label = mapped_column(Text, nullable=False)
    action = mapped_column(Text, nullable=False)
    target_type = mapped_column(Text, nullable=False)
    target_id = mapped_column(Text, nullable=True)
    details = mapped_column(JSONB, nullable=False, server_default=text("'{}'"))
    ip = mapped_column(INET, nullable=True)
    user_agent = mapped_column(Text, nullable=True)
