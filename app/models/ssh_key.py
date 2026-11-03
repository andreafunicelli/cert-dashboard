from sqlalchemy import CHAR, BigInteger, ForeignKey, Text
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps


class SSHPublicKey(Timestamps, Base):
    """One SSH public key registered from the dashboard.

    Only public material lives here: ``public_key`` is the normalized OpenSSH line
    (``type base64 [comment]``) and ``fingerprint_sha256`` is SHA-256 over the DER SubjectPublicKeyInfo,
    unique so the same key cannot be registered twice. Private keys never reach this table — the worker's
    private key keeps its sealed-secret contract in ``encrypted_setting`` (``services.worker_credentials``).
    """

    __tablename__ = "ssh_public_key"
    id = mapped_column(BigInteger, primary_key=True)
    label = mapped_column(Text, nullable=False, unique=True)
    public_key = mapped_column(Text, nullable=False)
    key_type = mapped_column(Text, nullable=False)
    fingerprint_sha256 = mapped_column(CHAR(64), nullable=False, unique=True)
    created_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
