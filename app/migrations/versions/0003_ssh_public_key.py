"""Registered SSH public keys: label, normalized OpenSSH line, unique fingerprint.

Only public material is stored. The worker's private key keeps its existing contract (one sealed row in
``encrypted_setting``, never rendered) and is not touched by this migration.

Revision ID: 0003_ssh_public_key
Revises: 0002_encrypted_setting
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_ssh_public_key"
down_revision = "0002_encrypted_setting"
branch_labels = None
depends_on = None

DDL = (
    """CREATE TABLE ssh_public_key (
        id BIGSERIAL NOT NULL,
        label TEXT NOT NULL,
        public_key TEXT NOT NULL,
        key_type TEXT NOT NULL,
        fingerprint_sha256 CHAR(64) NOT NULL,
        created_by BIGINT,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
        CONSTRAINT pk_ssh_public_key PRIMARY KEY (id),
        CONSTRAINT uq_ssh_public_key_label UNIQUE (label),
        CONSTRAINT uq_ssh_public_key_fingerprint_sha256 UNIQUE (fingerprint_sha256),
        CONSTRAINT fk_ssh_public_key_created_by_user FOREIGN KEY(created_by) REFERENCES "user" (id)
    )""",
    """CREATE TRIGGER ssh_public_key_updated_at BEFORE UPDATE ON ssh_public_key FOR EACH ROW EXECUTE FUNCTION touch_updated_at()""",
    # 0001 granted DML with ON ALL TABLES/SEQUENCES: objects created afterwards need their own grants.
    """GRANT SELECT, INSERT, UPDATE, DELETE ON ssh_public_key TO app_role""",
    """GRANT USAGE, SELECT ON SEQUENCE ssh_public_key_id_seq TO app_role""",
)


def upgrade() -> None:
    for statement in DDL:
        op.execute(sa.text(statement))


def downgrade() -> None:
    raise RuntimeError("Forward-only migration; restore the reviewed backup")
