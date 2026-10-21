from sqlalchemy import CHAR, BigInteger, CheckConstraint, ForeignKey, Index, Integer, LargeBinary, Text
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps
from app.models.enums import PrivateKeyType, pg_enum


class PrivateKey(Timestamps, Base):
    __tablename__ = "private_key"
    id = mapped_column(BigInteger, primary_key=True)
    key_type = mapped_column(pg_enum(PrivateKeyType, "private_key_type"), nullable=False)
    key_size = mapped_column(Integer, nullable=False)
    curve = mapped_column(Text, nullable=True)
    ciphertext = mapped_column(LargeBinary, nullable=False)
    nonce = mapped_column(LargeBinary, nullable=False)
    aad = mapped_column(Text, nullable=False)
    master_key_version = mapped_column(Integer, nullable=False)
    public_key_sha256 = mapped_column(CHAR(64), nullable=False, unique=True)
    public_key_pem = mapped_column(Text, nullable=False)
    created_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
    origin = mapped_column(Text, nullable=False)
    __table_args__ = (
        CheckConstraint("octet_length(nonce) = 12", name="nonce_length"),
        CheckConstraint("master_key_version >= 1", name="master_key_version"),
        Index("ix_private_key_master_key_version", "master_key_version"),
    )
