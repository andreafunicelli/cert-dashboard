import secrets
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from testcontainers.community.postgres import PostgresContainer

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "postgres:16-bookworm@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4"


@pytest.fixture(scope="session")
def database_urls():
    password = secrets.token_urlsafe(32)
    with PostgresContainer(
        IMAGE,
        username="db_owner",
        password=secrets.token_urlsafe(32),
        dbname="cert_dashboard",
        driver="psycopg",
    ) as postgres:
        owner = create_engine(postgres.get_connection_url())
        with owner.begin() as conn:
            conn.exec_driver_sql(
                f"CREATE ROLE app_role LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION"
            )
            conn.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
            conn.execute(text("GRANT USAGE ON SCHEMA public TO app_role"))
        app_url = owner.url.set(username="app_role", password=password)
        yield owner.url, app_url
        owner.dispose()


@pytest.fixture(scope="session")
def alembic_config(database_urls):
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "app/migrations"))
    cfg.attributes["database_url"] = database_urls[0]
    return cfg


@pytest.fixture(scope="session")
def owner_engine(database_urls, alembic_config):
    # Migration must succeed without application/master/session secrets.
    assert (ROOT / "app/migrations/versions/0001_v1_schema.py").exists(), "Missing initial v1 migration"
    command.upgrade(alembic_config, "head")
    engine = create_engine(database_urls[0])
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def engine(database_urls, owner_engine):
    engine = create_engine(database_urls[1])
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine):
    with engine.connect() as connection:
        outer = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        outer.rollback()
