"""Database sessions and readiness; runtime never applies migrations."""

import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.config import ConfigurationError, DatabaseSettings


def database_url(settings: DatabaseSettings) -> URL:
    return URL.create(
        "postgresql+psycopg",
        username=settings.db_user,
        password=settings.db_password.decode("utf-8"),
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
    )


def create_session_factory(settings: DatabaseSettings) -> sessionmaker[Session]:
    engine = create_engine(database_url(settings), pool_pre_ping=True, connect_args={"connect_timeout": 5})
    return sessionmaker(engine, expire_on_commit=False)


@contextmanager
def transaction(factory: sessionmaker[Session]) -> Iterator[Session]:
    with factory.begin() as session:
        yield session


def assert_database_ready(engine: Engine, timeout_seconds: int = 60) -> None:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    expected = set(ScriptDirectory.from_config(cfg).get_heads())
    deadline = time.monotonic() + timeout_seconds
    delay = 1.0
    while True:
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
                actual = set(MigrationContext.configure(connection).get_current_heads())
        except SQLAlchemyError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConfigurationError("database: unavailable; check DB credentials/connectivity") from None
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, 5)
        else:
            if actual != expected:
                raise ConfigurationError(
                    "database: migration head mismatch; run the dedicated migrate service"
                )
            return
