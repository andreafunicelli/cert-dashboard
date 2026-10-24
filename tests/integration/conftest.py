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


@pytest.fixture
def actor(db):
    from app.models import User
    from app.services.audit import Actor

    user = User(username="fixture-admin", email="fixture@example.test")
    db.add(user)
    db.flush()
    return Actor(user.id, user.username, "192.0.2.10", "fixture-browser")


@pytest.fixture(scope="module")
def web_factory(owner_engine, database_urls):
    import uuid

    from sqlalchemy.orm import sessionmaker

    name = "fixture_web_" + uuid.uuid4().hex
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql(f'CREATE DATABASE "{name}"')
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["database_url"] = owner_engine.url.set(database=name)
    command.upgrade(config, "head")
    engine = create_engine(database_urls[1].set(database=name))
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql(f'DROP DATABASE "{name}" WITH (FORCE)')


@pytest.fixture
def web_user(web_factory):
    import uuid

    from app.models import User

    with web_factory.begin() as db:
        user = User(
            username="fixture-web-" + uuid.uuid4().hex,
            email="fixture@example.test",
            display_name="<script>fixture</script>",
        )
        db.add(user)
        db.flush()
        return user


@pytest.fixture
def clock(now):
    from datetime import timedelta

    class Clock:
        value = now

        def __call__(self):
            return self.value

        def advance(self, **delta):
            self.value += timedelta(**delta)

    return Clock()


@pytest.fixture
def web_settings(web_factory):
    from app.config import Settings
    from app.crypto.keyring import Keyring

    url = web_factory.kw["bind"].url
    return Settings(
        profile="web",
        db_password=url.password.encode(),
        db_host=url.host,
        db_port=url.port,
        db_user=url.username,
        db_name=url.database,
        keyring=Keyring(1, {1: bytes(range(32))}),
        keyring_sha256="0" * 64,
        session_secret=b"fixture-session-signing-secret-32-bytes",
    )


@pytest.fixture
def web_app(web_settings, web_factory, web_user, clock):
    # These routes exercise infrastructure only. Real account/login forms are Task 11.
    from fastapi import Depends, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse

    from app.auth.sessions import (
        clear_session_cookie,
        issue_login_csrf,
        revoke_sessions,
        rotate_session,
        set_session_cookie,
    )
    from app.main import create_app, enforce_login_rate_limit, require_user

    app = create_app(web_settings)
    app.state.factory, app.state.clock = web_factory, clock
    app.state.public_paths.update({"/_test/login-form", "/_test/login", "/_test/mfa"})
    app.state.calls = 0
    authentication = Depends(require_user)

    @app.get("/_test/login-form")
    def login_form(request: Request):
        response = HTMLResponse("")
        token = issue_login_csrf(response, web_settings.session_secret, clock())
        response.body = f'<form><input name="csrf_token" value="{token}"></form>'.encode()
        response.headers["content-length"] = str(len(response.body))
        return response

    @app.post("/_test/login")
    async def login(request: Request):
        enforce_login_rate_limit(request)
        # Test-only successful first factor; no password/session policy is duplicated here.
        with web_factory.begin() as db:
            from app.models import User

            pending = db.get(User, web_user.id).totp_enabled
            session = rotate_session(
                db,
                request.state.session,
                web_user.id,
                clock(),
                request.state.client_ip,
                "fixture-browser",
                authenticated=not pending,
            )
        response = JSONResponse({"pending": pending, "csrf_token": session.csrf_token})
        set_session_cookie(response, session)
        return response

    @app.post("/_test/mfa")
    def mfa(request: Request):
        previous = request.state.session
        if previous is None or previous.authenticated_at is not None:
            raise HTTPException(401)
        with web_factory.begin() as db:
            session = rotate_session(
                db, previous, previous.user_id, clock(), request.state.client_ip, "fixture-browser"
            )
        response = JSONResponse({"csrf_token": session.csrf_token})
        set_session_cookie(response, session)
        return response

    @app.api_route("/_test/protected", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def protected(request: Request, user=authentication):
        app.state.calls += 1
        form = await request.form() if request.method != "GET" else {}
        return {"user_key": user.user_key, "echo": form.get("echo"), "ip": request.state.client_ip}

    @app.post("/_test/logout")
    def logout(request: Request, user=authentication):
        with web_factory.begin() as db:
            revoke_sessions(db, request.state.session.user_id, clock())
        response = JSONResponse({"ok": True})
        clear_session_cookie(response)
        return response

    @app.get("/_test/error/{status}")
    def error(status: int):
        raise HTTPException(status, "password=fixture-should-never-be-shown")

    @app.get("/_test/boom")
    def boom(request: Request):
        raise RuntimeError("password=fixture-internal " + request.cookies.get("cd_session", ""))

    @app.get("/_test/validation")
    def validation(number: int):
        return {"number": number}

    @app.post("/_test/db-mutation")
    def broken_mutation(request: Request):
        from sqlalchemy.exc import OperationalError

        from app.models import User

        app.state.calls += 1
        with web_factory.begin() as db:
            db.add(User(username="fixture-rollback-" + web_user.username, email="fixture@example.test"))
            db.flush()
            raise OperationalError(
                "fixture-sensitive-query",
                {"session": request.state.session.id},
                Exception("fixture-private-details"),
            )

    @app.get("/_test/page")
    def page(request: Request):
        return app.state.templates.TemplateResponse(
            request=request,
            name="base.html.j2",
            context={"user": request.state.user, "navigation": app.state.navigation, "status_banner": ""},
        )

    return app


@pytest.fixture
def client(web_app, web_user):
    from fastapi.testclient import TestClient

    with TestClient(
        web_app,
        base_url="https://testserver",
        client=(f"192.0.2.{10 + web_user.id % 200}", 4000),
        raise_server_exceptions=False,
    ) as client:
        yield client


@pytest.fixture
def signed_in(client, web_factory, web_user, clock):
    from app.auth.sessions import issue_session

    with web_factory.begin() as db:
        session = issue_session(db, web_user.id, clock(), "192.0.2.101", "fixture-browser")
    client.cookies.set("cd_session", session.id, domain="testserver.local", path="/")
    client.fixture_csrf = session.csrf_token
    return client


LOGIN_PASSWORD = "correct-long-pass"


def create_login_user(factory, username="admin", password=LOGIN_PASSWORD, backend="local", **extra):
    """Persist a user row; non-local (fake directory) users carry no password hash."""
    from types import SimpleNamespace

    from app.auth.local import hash_password
    from app.models import User

    with factory.begin() as db:
        user = User(
            username=username,
            email=f"{username}@example.test",
            display_name=username,
            auth_backend=backend,
            password_hash=hash_password(password) if backend == "local" else None,
            **extra,
        )
        db.add(user)
        db.flush()
        return SimpleNamespace(id=user.id, username=username, password=password)


@pytest.fixture
def plain_user(web_factory):
    return create_login_user(web_factory)


@pytest.fixture
def totp_user(web_factory, web_settings, clock):
    import pyotp

    from app.auth.local import begin_totp, confirm_totp
    from app.services.audit import Actor

    user = create_login_user(web_factory)
    actor = Actor(user.id, user.username, "192.0.2.90")
    with web_factory.begin() as db:
        enrollment = begin_totp(db, user.id, web_settings.keyring, actor)
    with web_factory.begin() as db:
        code = pyotp.TOTP(enrollment.secret).at(clock())
        assert confirm_totp(db, user.id, code, web_settings.keyring, clock(), actor)
    user.secret, user.recovery_codes = enrollment.secret, enrollment.recovery_codes
    return user


@pytest.fixture
def csrf(client):
    """Pre-auth double-submit token taken from the real login form."""
    import re

    response = client.get("/login")
    assert response.status_code == 200
    return re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)


@pytest.fixture(scope="session")
def queue_template(owner_engine):
    """Migrated template database; each queue test gets a cheap private copy of it."""
    import uuid

    name = "fixture_queue_template_" + uuid.uuid4().hex
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql(f'CREATE DATABASE "{name}"')
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["database_url"] = owner_engine.url.set(database=name)
    command.upgrade(config, "head")
    yield name
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql(f'DROP DATABASE "{name}" WITH (FORCE)')


@pytest.fixture
def queue_factory(owner_engine, database_urls, queue_template):
    """App-role sessionmaker on a private database.

    Queue tests commit real data over several connections; the private database keeps that
    away from the rollback-per-test ``db`` fixture and from every other test's rows.
    """
    import uuid

    from sqlalchemy.orm import sessionmaker

    name = "fixture_queue_" + uuid.uuid4().hex
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql(f'CREATE DATABASE "{name}" TEMPLATE "{queue_template}"')
    engine = create_engine(database_urls[1].set(database=name), pool_size=12)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql(f'DROP DATABASE "{name}" WITH (FORCE)')


@pytest.fixture
def seeded_jobs(queue_factory, now):
    """Eight committed, immediately claimable ``scan`` jobs (ids in creation order)."""
    from datetime import timedelta

    from app.models import Job
    from app.models.enums import JobType

    ids = []
    with queue_factory.begin() as db:
        for index in range(8):
            job = Job(
                type=JobType.SCAN,
                priority=100,
                payload={"index": index},
                run_after=now - timedelta(minutes=1),
                max_attempts=3,
            )
            db.add(job)
            db.flush()
            ids.append(job.id)
    return ids


# --- worker runtime ---------------------------------------------------------------------------


def _worker_settings(tmp_path, **overrides):
    from app.config import Settings
    from app.crypto.keyring import Keyring

    values = {
        "profile": "worker",
        "db_password": b"fixture-not-used",
        "keyring": Keyring(1, {1: bytes(range(32))}),
        "keyring_sha256": "0" * 64,
        "artifacts_root": tmp_path / "artifacts",
        "key_staging_dir": tmp_path / "keys",
    }
    return Settings(**(values | overrides))


@pytest.fixture
def make_worker(tmp_path, clock):
    """Build worker runtimes on any session factory; every one is closed (lock released) at teardown."""
    from app.jobs.handlers import build_registry
    from app.jobs.worker import Worker

    built = []

    def build(factory, *, registry=None, settings=None, **settings_overrides):
        runtime = Worker(
            settings or _worker_settings(tmp_path, **settings_overrides),
            registry or build_registry(),
            factory,
            clock=clock,
        )
        built.append(runtime)
        return runtime

    yield build
    for runtime in built:
        runtime.close(grace_seconds=0)


@pytest.fixture
def worker_harness(web_factory, make_worker):
    """A worker bound to the same database and clock as the ``client`` fixture."""
    from app.models import WorkerHeartbeat

    runtime = make_worker(web_factory)
    yield runtime
    runtime.close(grace_seconds=0)
    with web_factory.begin() as db:
        for row in db.query(WorkerHeartbeat):
            db.delete(row)
