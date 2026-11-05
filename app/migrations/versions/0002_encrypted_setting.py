"""Encrypted worker credentials: one sealed row per setting, bound to its own name.

The AAD is rebuilt from ``name`` and ``keyring_version`` when a row is read, so no AAD column is
stored. ``app_setting`` stays JSONB and secret-free: worker credentials never live there.

Revision ID: 0002_encrypted_setting
Revises: 0001_v1_schema
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_encrypted_setting"
down_revision = "0001_v1_schema"
branch_labels = None
depends_on = None

DDL = (
    """CREATE TABLE encrypted_setting (
        name TEXT NOT NULL,
        ciphertext BYTEA NOT NULL,
        nonce BYTEA NOT NULL,
        keyring_version INTEGER NOT NULL,
        updated_by BIGINT,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
        CONSTRAINT pk_encrypted_setting PRIMARY KEY (name),
        CONSTRAINT ck_encrypted_setting_nonce_length CHECK (octet_length(nonce) = 12),
        CONSTRAINT ck_encrypted_setting_keyring_version CHECK (keyring_version >= 1),
        CONSTRAINT ck_encrypted_setting_known_name CHECK (
            name IN ('worker.ssh_private_key', 'worker.vault_password', 'inventory.git_token')
        ),
        CONSTRAINT fk_encrypted_setting_updated_by_user FOREIGN KEY(updated_by) REFERENCES "user" (id)
    )""",
    """CREATE INDEX ix_encrypted_setting_keyring_version ON encrypted_setting (keyring_version)""",
    """CREATE TRIGGER encrypted_setting_updated_at BEFORE UPDATE ON encrypted_setting FOR EACH ROW EXECUTE FUNCTION touch_updated_at()""",
    # 0001 granted DML with ON ALL TABLES: a table created afterwards needs its own grant.
    """GRANT SELECT, INSERT, UPDATE, DELETE ON encrypted_setting TO app_role""",
)


def upgrade() -> None:
    for statement in DDL:
        op.execute(sa.text(statement))


def downgrade() -> None:
    raise RuntimeError("Forward-only migration; restore the reviewed backup")
