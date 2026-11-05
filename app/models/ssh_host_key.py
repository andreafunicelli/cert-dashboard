"""Trusted SSH host public keys (Slice B decision D2): public material only, immutable rows.

A row means an administrator pasted the key and attested that they compared its fingerprint with
the server through an independent channel. Nothing is auto-accepted and no key material other than
the public blob is stored. Removal is a DELETE; the audit log keeps the history.
"""

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import mapped_column

from app.models.base import Base, CreatedAt

# The key types the dashboard accepts; the CHECK constraint is the database backstop.
SSH_HOST_KEY_TYPES = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
)
_KEY_TYPES_SQL = ", ".join(f"'{key_type}'" for key_type in SSH_HOST_KEY_TYPES)


class SshHostKey(CreatedAt, Base):
    __tablename__ = "ssh_host_key"
    __table_args__ = (
        UniqueConstraint("host", "key_type"),
        CheckConstraint(f"key_type IN ({_KEY_TYPES_SQL})", name="key_type"),
    )
    id = mapped_column(BigInteger, primary_key=True)
    host = mapped_column(Text, nullable=False)
    key_type = mapped_column(Text, nullable=False)
    public_key = mapped_column(Text, nullable=False)
    fingerprint_sha256 = mapped_column(Text, nullable=False)
    comment = mapped_column(Text, nullable=True)
    created_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
