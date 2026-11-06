"""Replaceable branding storage (docs/ux-spec.md A2-D1).

Additive: two new tables and their grants. ``branding_asset`` is a singleton (no row = default);
``branding_draft`` is the session-owned preview with a 30-minute expiry and a partial unique index
that allows only one unconsumed draft per session. 0001's grants do not cover new tables.

Revision ID: 0004_branding
Revises: 0003_ssh_host_key
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_branding"
down_revision = "0003_ssh_host_key"
branch_labels = None
depends_on = None

DDL = (
    """CREATE TABLE branding_asset (
        id SMALLINT NOT NULL,
        mime TEXT NOT NULL,
        content BYTEA NOT NULL,
        width INTEGER NOT NULL,
        height INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        display_filename TEXT NOT NULL,
        updated_by BIGINT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
        CONSTRAINT pk_branding_asset PRIMARY KEY (id),
        CONSTRAINT ck_branding_asset_singleton CHECK (id = 1),
        CONSTRAINT ck_branding_asset_mime CHECK (mime IN ('image/svg+xml', 'image/png')),
        CONSTRAINT ck_branding_asset_content_size CHECK (octet_length(content) <= 262144),
        CONSTRAINT fk_branding_asset_updated_by_user FOREIGN KEY(updated_by) REFERENCES "user" (id)
    )""",
    """CREATE TABLE branding_draft (
        token_sha256 TEXT NOT NULL,
        session_id CHAR(64) NOT NULL,
        content BYTEA,
        mime TEXT,
        width INTEGER,
        height INTEGER,
        sha256 TEXT,
        byte_size INTEGER,
        display_filename TEXT,
        base_revision TEXT NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        consumed_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
        CONSTRAINT pk_branding_draft PRIMARY KEY (token_sha256),
        CONSTRAINT ck_branding_draft_mime CHECK (
            mime IS NULL OR mime IN ('image/svg+xml', 'image/png')
        ),
        CONSTRAINT ck_branding_draft_content_size CHECK (
            content IS NULL OR octet_length(content) <= 262144
        ),
        CONSTRAINT fk_branding_draft_session_id_user_session FOREIGN KEY(session_id)
            REFERENCES user_session (id) ON DELETE CASCADE
    )""",
    """CREATE UNIQUE INDEX uq_branding_draft_session_open ON branding_draft (session_id)
        WHERE consumed_at IS NULL""",
    """CREATE TRIGGER branding_asset_updated_at BEFORE UPDATE ON branding_asset
        FOR EACH ROW EXECUTE FUNCTION touch_updated_at()""",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON branding_asset TO app_role",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON branding_draft TO app_role",
)


def upgrade() -> None:
    for statement in DDL:
        op.execute(sa.text(statement))


def downgrade() -> None:
    raise RuntimeError("Forward-only migration; restore the reviewed backup")
