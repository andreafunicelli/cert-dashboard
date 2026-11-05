"""Dashboard trust store for SSH host public keys (Slice B decision D2, D4).

Additive: one new table, nothing existing changes. Rows are immutable (no ``updated_at``); removal
is DELETE and the audit log keeps the history. Only public material: no secret belongs here.

Revision ID: 0003_ssh_host_key
Revises: 0002_encrypted_setting
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_ssh_host_key"
down_revision = "0002_encrypted_setting"
branch_labels = None
depends_on = None

DDL = (
    """CREATE TABLE ssh_host_key (
        id BIGSERIAL NOT NULL,
        host TEXT NOT NULL,
        key_type TEXT NOT NULL,
        public_key TEXT NOT NULL,
        fingerprint_sha256 TEXT NOT NULL,
        comment TEXT,
        created_by BIGINT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
        CONSTRAINT pk_ssh_host_key PRIMARY KEY (id),
        CONSTRAINT uq_ssh_host_key_host UNIQUE (host, key_type),
        CONSTRAINT ck_ssh_host_key_key_type CHECK (key_type IN (
            'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
            'ecdsa-sha2-nistp521', 'ssh-rsa'
        )),
        CONSTRAINT fk_ssh_host_key_created_by_user FOREIGN KEY(created_by) REFERENCES "user" (id)
    )""",
    # 0001 granted DML with ON ALL TABLES: a table created afterwards needs its own grant.
    # No UPDATE: a trusted key is deleted and re-added, never rewritten.
    """GRANT SELECT, INSERT, DELETE ON ssh_host_key TO app_role""",
    """GRANT USAGE, SELECT ON SEQUENCE ssh_host_key_id_seq TO app_role""",
)


def upgrade() -> None:
    for statement in DDL:
        op.execute(sa.text(statement))


def downgrade() -> None:
    raise RuntimeError("Forward-only migration; restore the reviewed backup")
