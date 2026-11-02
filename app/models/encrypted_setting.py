from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Index, Integer, LargeBinary, Text
from sqlalchemy.orm import mapped_column

from app.models.base import Base, Timestamps


class EncryptedSetting(Timestamps, Base):
    """One secret setting, sealed with the certificate keyring and bound to its own name.

    The AAD is rebuilt from ``name`` and ``keyring_version`` when the row is read (never stored), so a
    ciphertext copied into another setting — or read under another key version — cannot be decrypted.
    There is no plaintext column and nothing here is rendered: the interface reads presence only.
    """

    __tablename__ = "encrypted_setting"
    name = mapped_column(Text, primary_key=True)
    ciphertext = mapped_column(LargeBinary, nullable=False)
    nonce = mapped_column(LargeBinary, nullable=False)
    keyring_version = mapped_column(Integer, nullable=False)
    updated_by = mapped_column(BigInteger, ForeignKey("user.id"), nullable=True)
    __table_args__ = (
        CheckConstraint("octet_length(nonce) = 12", name="nonce_length"),
        CheckConstraint("keyring_version >= 1", name="keyring_version"),
        CheckConstraint(
            "name IN ('worker.ssh_private_key', 'worker.vault_password', 'inventory.git_token')",
            name="known_name",
        ),
        Index("ix_encrypted_setting_keyring_version", "keyring_version"),
    )
