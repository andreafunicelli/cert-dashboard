"""Owner-only Alembic entry point; deliberately loads no application secrets."""

import os
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from app.config import load_database_settings
from app.db import database_url
from app.models import Base

config = context.config
url = config.attributes.get("database_url")
if url is None:
    url = database_url(
        load_database_settings(os.environ, Path(os.environ.get("SECRETS_DIR", "/run/secrets")))
    )


def configure(connection=None):
    context.configure(
        connection=connection,
        url=url,
        target_metadata=Base.metadata,
        compare_type=True,
        compare_server_default=True,
        literal_binds=context.is_offline_mode(),
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    configure()
elif config.attributes.get("connection") is not None:
    configure(config.attributes["connection"])
else:
    with create_engine(url, poolclass=NullPool).connect() as connection:
        configure(connection)
