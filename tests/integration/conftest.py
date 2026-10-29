import contextlib
import functools
import itertools
import json
import secrets
import uuid
from pathlib import Path
from typing import ClassVar

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from testcontainers.community.postgres import PostgresContainer

from app.crypto.keys import public_key_sha256
from tests.fixtures.git_inventory import InventoryRepo, make_bare_repo, write_vaulted
from tests.fixtures.ssh_targets import VHOSTS

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
def ansible_worker(tmp_path, make_worker):
    """``ansible_worker(factory, **overrides)``: ``make_worker`` with an SSH key and the Ansible directories.

    The key is a real, freshly generated ed25519 key in OpenSSH format (never a secret anywhere else),
    ``known_hosts_file`` an existing file, and ``inventory_root`` / ``key_staging_dir`` private temporary
    directories. Tests that really connect to the SSH targets override ``ansible_ssh_key`` and
    ``known_hosts_file`` with the ``ssh_targets`` values.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    )
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")

    def build(factory, **overrides):
        values = {
            "ansible_ssh_key": key,
            "known_hosts_file": known_hosts,
            "inventory_root": tmp_path / "inventory",
            "key_staging_dir": tmp_path / "keys",
        }
        return make_worker(factory, **(values | overrides))

    return build


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


# --- local TLS listener (Task 16) -------------------------------------------------------------


class TLSServer:
    """A 127.0.0.1 listener that counts accepted connections and records the SNI it receives.

    ``mode``: ``tls`` completes handshakes and serves ``cert`` + ``intermediates``; ``silent``
    accepts and never answers; ``garbage`` answers the ClientHello with non-TLS bytes.
    """

    host = "127.0.0.1"

    def __init__(self, cert, key, intermediates=(), mode="tls"):
        import socket
        import threading

        from OpenSSL import SSL

        self.mode = mode
        self.connections = 0
        self.server_names: list[bytes | None] = []
        self._lock = threading.Lock()
        self._held: list[socket.socket] = []
        self._closing = False
        self._stop = threading.Event()
        self._context = SSL.Context(SSL.TLS_SERVER_METHOD)
        self._context.use_certificate(cert)
        self._context.use_privatekey(key)
        for extra in intermediates:
            self._context.add_extra_chain_cert(extra)
        self._context.set_tlsext_servername_callback(self._on_server_name)
        self._listener = socket.socket()
        self._listener.bind((self.host, 0))
        self._listener.listen(16)
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _on_server_name(self, connection):
        with self._lock:
            self.server_names.append(connection.get_servername())

    @property
    def seen_server_names(self) -> list[str]:
        with self._lock:
            return [name.decode("ascii") for name in self.server_names if name]

    def _accept_loop(self):
        import threading

        while not self._closing:
            try:
                sock, _ = self._listener.accept()
            except OSError:
                return
            with self._lock:
                self.connections += 1
                self._held.append(sock)
            threading.Thread(target=self._serve, args=(sock,), daemon=True).start()

    def _serve(self, sock):
        from OpenSSL import SSL

        with contextlib.suppress(Exception):  # the client may disconnect at any point
            if self.mode == "silent":
                self._stop.wait(30)
            elif self.mode == "garbage":
                sock.settimeout(10)
                sock.recv(4096)
                sock.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            else:
                # Blocking socket on purpose: with a timeout the fd is non-blocking and
                # pyOpenSSL would raise WantReadError instead of waiting for the client.
                connection = SSL.Connection(self._context, sock)
                connection.set_accept_state()
                connection.do_handshake()
                connection.recv(1)  # returns/raises once the client closes
        sock.close()

    def close(self):
        self._closing = True
        self._stop.set()
        self._listener.close()
        with self._lock:
            for sock in self._held:
                try:
                    sock.close()
                except OSError:
                    pass


@pytest.fixture
def tls_servers():
    """Factory for listeners; every one is closed at teardown."""
    started = []

    def start(cert, key, intermediates=(), mode="tls"):
        server = TLSServer(cert, key, intermediates, mode)
        started.append(server)
        return server

    yield start
    for server in started:
        server.close()


@pytest.fixture
def pull_certs(now):
    """Unique certificates per test: the web database is shared by the whole test module."""
    from tests.fixtures.certificates import generate_certificates

    return generate_certificates(now)


@pytest.fixture
def tls_server(tls_servers, pull_certs):
    """A listener serving the leaf plus both intermediates (never the root)."""
    return tls_servers(pull_certs.leaf, pull_certs.leaf_key, pull_certs.intermediates)


# --- Renewal state-machine fixtures (Task 18) ---------------------------------


@functools.cache
def _fixture_ca():
    from datetime import UTC, datetime

    from tests.fixtures.ca import FixtureCA

    return FixtureCA(datetime(2026, 10, 19, 12, 0, tzinfo=UTC))


@pytest.fixture(scope="session")
def ca():
    return _fixture_ca()


@pytest.fixture
def keyring():
    from app.crypto.keyring import Keyring

    return Keyring(1, {1: bytes(range(32))})


@pytest.fixture
def previous_certificate(db, ca, actor, now):
    """An active, key-less inventory certificate (with chain and ownership) that gets renewed."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

    from app.crypto.chain import order_chain
    from app.crypto.parse import parse_certificates
    from app.services.certificates import CertificateMetadata, save_certificate

    key = ec.generate_private_key(ec.SECP256R1())
    pem = ca.issue(
        public_key=key.public_key(),
        common_name="www.example.internal",
        sans=["www.example.internal", "api.example.internal"],
        not_before=now.replace(year=2025),
        not_after=now.replace(year=2027),
    )
    leaf = parse_certificates(pem)[0]
    chain = order_chain(leaf.cert, [x509.load_pem_x509_certificate(ca.chain_pem)])
    metadata = CertificateMetadata(owner_name="Ada", owner_email="ada@example.test", team="web")
    return save_certificate(
        db, leaf, chain, metadata, actor, source="upload_pem", validation_time=now
    ).certificate


@pytest.fixture
def submitted_renewal(db, ca, keyring, previous_certificate, actor, now):
    """A renewal of ``previous_certificate`` waiting for the CA's issued certificate."""
    from app.crypto.keys import KeySpec
    from app.services.renewals import (
        RenewalBasics,
        create_draft,
        generate_csr,
        mark_submitted,
    )

    basics = RenewalBasics("www.example.internal", ("www.example.internal", "api.example.internal"), "TestCA")
    renewal = create_draft(db, previous_certificate.id, basics, actor, now)
    generate_csr(db, renewal.id, KeySpec(kind="ecdsa"), keyring, actor, now)
    return mark_submitted(db, renewal.id, "ORDER-1", actor, now)


# --- shared helpers for worker/scan tests (Plan 2) ---------------------------------------------


def closed_port() -> int:
    """A loopback TCP port with nothing listening (connections are refused)."""
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def set_setting(factory, key, value) -> None:
    from app.models import AppSetting

    with factory.begin() as db:
        row = db.get(AppSetting, key)
        if row is None:
            db.add(AppSetting(key=key, value=value))
        else:
            row.value = value


# Schedule keys whose enabled flag is not ``<key>.enabled``. ``trust_recheck`` shares ``scan.enabled``
# (Plan 2 contract decision 5); ``trust_recheck.enabled`` is not an allowlisted setting.
_ENABLED_SETTINGS = {"digest": "alert.digest_enabled", "trust_recheck": "scan.enabled"}


def disable_schedules(factory, *keys) -> None:
    """Switch the named schedules off so ticks in a test enqueue only what the test queues itself."""
    for key in keys:
        set_setting(factory, _ENABLED_SETTINGS.get(key, f"{key}.enabled"), False)


def configure_smtp(factory, capture, *, security="none", recipients=(), tls_verify=True, username="") -> None:
    """Point the SMTP settings at a loopback ``CaptureServer`` (reused by the alert and digest tests)."""
    for key, value in {
        "smtp.host": "127.0.0.1",
        "smtp.port": capture.port,
        "smtp.security": security,
        "smtp.from": "dashboard@example.test",
        "smtp.username": username,
        "smtp.tls_verify": tls_verify,
        "alert.recipients": list(recipients),
    }.items():
        set_setting(factory, key, value)


_expiring_counter = itertools.count(1)


def expiring(factory, days, **metadata):
    """Commit an active certificate (issued by the session ``ca``) expiring ``days`` after the fixture ``now``.

    ``metadata`` sets ownership columns (``owner_email``, ``owner_name``, ``team``, ``notes``); the
    common name is unique per call. Returns the detached ``Certificate``.
    """
    from datetime import UTC, datetime, timedelta

    from cryptography.hazmat.primitives.asymmetric import ec

    from app.crypto.parse import parse_certificates
    from app.models import Certificate
    from app.models.enums import ChainStatus

    base = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
    name = f"expiring{next(_expiring_counter)}-{secrets.token_hex(3)}.example.test"
    pem = _fixture_ca().issue(
        public_key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        common_name=name,
        sans=[name],
        not_before=base - timedelta(days=300),
        not_after=base + timedelta(days=days),
    )
    parsed = parse_certificates(pem)[0]
    with factory.begin() as db:
        row = Certificate(
            common_name=parsed.common_name,
            subject_dn=parsed.subject_dn,
            sans=list(parsed.sans),
            issuer_dn=parsed.issuer_dn,
            issuer_cn=parsed.issuer_cn,
            serial=parsed.serial,
            not_before=parsed.not_before,
            not_after=parsed.not_after,
            sha256_fingerprint=parsed.sha256_fingerprint,
            pem=parsed.pem,
            chain_status=ChainStatus.UNCHECKED,
            imported_from="upload_pem",
            **metadata,
        )
        db.add(row)
        db.flush()
        return row


_KEEP = object()


def add_endpoint(db, host, port=443, *, sni=None, expected_certificate_id=None, is_active=True) -> int:
    """Flush a manual endpoint on the caller's session and return its id (reused by the digest tests)."""
    from app.models import Endpoint
    from app.models.enums import EndpointSource

    endpoint = Endpoint(
        host=host,
        port=port,
        sni=sni,
        source=EndpointSource.MANUAL,
        expected_certificate_id=expected_certificate_id,
        is_active=is_active,
    )
    db.add(endpoint)
    db.flush()
    return endpoint.id


def add_results(db, endpoint_id, results) -> None:
    """Insert ``scan_result`` rows ``[(checked_at, status), ...]``; ``last_scan_*`` follows the newest."""
    from app.models import Endpoint, ScanResult
    from app.models.enums import ScanStatus

    endpoint = db.get(Endpoint, endpoint_id)
    for checked_at, status in results:
        db.add(
            ScanResult(
                endpoint_id=endpoint_id,
                status=ScanStatus(status),
                observed_fingerprint=None if status in ("unreachable", "error") else secrets.token_hex(32),
                observed_common_name=None if status in ("unreachable", "error") else f"seen-{endpoint_id}.example.test",
                expected_certificate_id=endpoint.expected_certificate_id,
                source="scheduled",
                checked_at=checked_at,
            )
        )
    newest_at, newest_status = max(results, key=lambda item: item[0])
    endpoint.last_scan_at = newest_at
    endpoint.last_scan_status = ScanStatus(newest_status)
    db.flush()


def add_server(db, hostname, **columns):
    from app.models import Server

    server = Server(hostname=hostname, inventory_source="fixture", **columns)
    db.add(server)
    db.flush()
    return server


def add_binding(db, server, vhost, *, match_state, fingerprint, at):
    """Insert an active binding created at ``at`` and audit the insertion like Plan 3 reconciliation."""
    from app.jobs.queue import SYSTEM_ACTOR
    from app.models import Binding
    from app.models.enums import WebserverType
    from app.services.bindings import audit_binding_state

    binding = Binding(
        server_id=server.id,
        webserver=WebserverType.NGINX,
        vhost_name=vhost,
        vhost_names=[vhost],
        config_file=f"/etc/nginx/conf.d/{vhost}.conf",
        cert_path=f"/etc/ssl/{vhost}.pem",
        key_path=f"/etc/ssl/{vhost}.key",
        on_disk_fingerprint=fingerprint,
        match_state=match_state,
        is_active=True,
        created_at=at,
        last_seen_at=at,
    )
    db.add(binding)
    db.flush()
    audit_binding_state(db, binding, None, SYSTEM_ACTOR, job_id=None, now=at)
    db.flush()
    return binding


def reconcile(db, binding, *, at, match_state=_KEEP, fingerprint=_KEEP, is_active=_KEEP):
    """Change a binding's audited triple the way Plan 3 reconciliation will; returns the audit row or ``None``."""
    from app.jobs.queue import SYSTEM_ACTOR
    from app.services.bindings import audit_binding_state, binding_state

    previous = binding_state(binding)
    if match_state is not _KEEP:
        binding.match_state = match_state
    if fingerprint is not _KEEP:
        binding.on_disk_fingerprint = fingerprint
    if is_active is not _KEEP:
        binding.is_active = is_active
    binding.last_seen_at = at
    db.flush()
    row = audit_binding_state(db, binding, previous, SYSTEM_ACTOR, job_id=None, now=at)
    db.flush()
    return row


@pytest.fixture
def count_statements(web_factory):
    """``with count_statements() as counter:`` counts SQL statements sent through ``engine`` (default: the web bind)."""
    from types import SimpleNamespace

    from sqlalchemy import event

    @contextlib.contextmanager
    def counting(engine=None):
        bind = engine or web_factory.kw["bind"]
        counter = SimpleNamespace(count=0)

        def capture(*_args):
            counter.count += 1

        event.listen(bind, "before_cursor_execute", capture)
        try:
            yield counter
        finally:
            event.remove(bind, "before_cursor_execute", capture)

    return counting


@pytest.fixture
def scan_world(web_factory, now):
    """Committed endpoints in every scan state on one server (names are unique per use).

    The mismatch endpoint expects ``expected_certificate_id`` but serves ``served_certificate_id``
    (also in inventory) and carries 25 history rows; ``token`` is a search term matching every host.
    """
    from datetime import timedelta
    from types import SimpleNamespace

    from app.models import Endpoint, ScanResult
    from app.models.enums import EndpointSource, ScanStatus

    token = "sw" + secrets.token_hex(4)
    expected, served, other = (expiring(web_factory, days) for days in (90, 60, 30))
    group = f"grp-{token}"
    hosts = {name: f"{name}-{token}.example.test" for name in ("mismatch", "ok", "expired", "down", "broken", "never", "off")}
    ids = {}
    with web_factory.begin() as db:
        server = add_server(db, f"srv-{token}.example.test", ansible_groups=[group, "web"])
        specs = {  # name -> (expected certificate, newest status, served certificate)
            "mismatch": (expected, "mismatch", served),
            "ok": (other, "ok", other),
            "expired": (expected, "expired", expected),
            "down": (expected, "unreachable", None),
            "broken": (expected, "error", None),
            "never": (None, None, None),
            "off": (expected, "ok", expected),
        }
        for name, (cert, status, seen) in specs.items():
            endpoint = Endpoint(
                host=hosts[name],
                port=443,
                sni=f"sni-{name}-{token}.example.test" if name == "ok" else None,
                source=EndpointSource.MANUAL,
                server_id=server.id,
                expected_certificate_id=cert.id if cert else None,
                is_active=name != "off",
            )
            db.add(endpoint)
            db.flush()
            ids[name] = endpoint.id
            if status is None:
                continue
            for age in range(25 if name == "mismatch" else 1):  # age 0 is the newest result
                failed = status in ("unreachable", "error")
                db.add(
                    ScanResult(
                        endpoint_id=endpoint.id,
                        status=ScanStatus(status if age == 0 else "ok"),
                        observed_fingerprint=None if failed else (seen.sha256_fingerprint if age == 0 else secrets.token_hex(32)),
                        observed_common_name=None if failed else seen.common_name,
                        observed_issuer_cn=None if failed else "Fixture Issuing CA",
                        observed_not_after=None if failed else seen.not_after,
                        observed_chain_length=None if failed else 2,
                        tls_version=None if failed else "TLSv1.3",
                        error=None if not failed else f"{hosts[name]}:443 unreachable: refused",
                        expected_certificate_id=endpoint.expected_certificate_id,
                        source="scheduled",
                        checked_at=now - timedelta(hours=age),
                    )
                )
            endpoint.last_scan_at, endpoint.last_scan_status = now, ScanStatus(status)
    return SimpleNamespace(
        token=token,
        group=group,
        server_id=server.id,
        mismatch_id=ids["mismatch"],
        mismatch_host=hosts["mismatch"],
        ok_id=ids["ok"],
        ok_host=hosts["ok"],
        ok_sni=f"sni-ok-{token}.example.test",
        hosts=hosts,
        ids=ids,
        expected_certificate_id=expected.id,
        expected_fingerprint=expected.sha256_fingerprint,
        served_certificate_id=served.id,
        served_fingerprint=served.sha256_fingerprint,
    )


@pytest.fixture
def server_map(web_factory, now):
    """Committed servers, bindings in every ``match_state``, endpoints and discover jobs (Plan 3 will write them for real).

    Hostnames carry a per-use ``token`` (the database outlives a test); ``server("web01.example.internal")`` takes
    the short name and returns an object with the real ``hostname`` and ``id``. ``group`` holds web01, web02 and the
    inactive old01. web01: three active bindings (matched, key_mismatch, missing_file) plus one inactive, one active
    mismatching endpoint (and an inactive one), three discover runs. web02: one unknown and one matched binding.
    ``certificate_id`` is used by web01's matched and key_mismatch bindings and by web02's matched one.
    """
    from datetime import timedelta
    from types import SimpleNamespace

    from app.models import Binding, Endpoint, Job, JobHost
    from app.models.enums import EndpointSource, JobHostStatus, JobStatus, JobType, ScanStatus, WebserverType

    token = "sm" + secrets.token_hex(4)
    group = f"grp-{token}"
    certificate = expiring(web_factory, 90)
    other = expiring(web_factory, 45)
    fingerprint = certificate.sha256_fingerprint
    servers: dict[str, SimpleNamespace] = {}

    def binding(server, vhost, state, **columns):
        values = {
            "server_id": server.id,
            "webserver": WebserverType.NGINX,
            "vhost_name": vhost,
            "vhost_names": [vhost],
            "port": 443,
            "config_file": f"/etc/nginx/conf.d/{vhost}.conf",
            "cert_path": f"/etc/ssl/{vhost}/fullchain.pem",
            "chain_path": f"/etc/ssl/{vhost}/chain.pem",
            "key_path": f"/etc/ssl/{vhost}/privkey.pem",
            "cert_owner": "root",
            "cert_group": "ssl-cert",
            "cert_mode": 0o644,
            "key_owner": "root",
            "key_group": "ssl-cert",
            "key_mode": 0o640,
            "match_state": state,
            "last_seen_at": now,
            "is_active": True,
        }
        return Binding(**{**values, **columns})

    def endpoint(server, host, status, *, active=True):
        return Endpoint(
            host=host,
            port=443,
            source=EndpointSource.DISCOVERY,
            server_id=server.id,
            is_active=active,
            last_scan_at=now,
            last_scan_status=ScanStatus(status),
        )

    with web_factory.begin() as db:
        specs = {
            "web01.example.internal": {"ansible_groups": [group, "web"], "webserver": WebserverType.NGINX,
                                           "last_discovery_at": now - timedelta(hours=1), "last_discovery_status": "ok",
                                           "connection_address": "10.20.0.11", "notes": "web01 note"},
            "web02.example.internal": {"ansible_groups": [group], "webserver": WebserverType.APACHE,
                                           "last_discovery_at": now - timedelta(days=2), "last_discovery_status": "failed"},
            "db01.example.internal": {"ansible_groups": ["db"]},
            "old01.example.internal": {"ansible_groups": [group], "is_active": False},
        }
        for short, columns in specs.items():
            row = add_server(db, short.replace(".", f"-{token}.", 1), **columns)
            servers[short] = SimpleNamespace(id=row.id, hostname=row.hostname)
        web01, web02 = (SimpleNamespace(id=servers[name].id) for name in list(specs)[:2])
        db.add_all(
            [
                binding(web01, f"www-{token}.example.test", "matched", certificate_id=certificate.id,
                        on_disk_fingerprint=fingerprint, on_disk_key_public_sha256="a" * 64),
                binding(web01, f"api-{token}.example.test", "key_mismatch", certificate_id=certificate.id,
                        on_disk_fingerprint=fingerprint, on_disk_key_public_sha256="b" * 64, key_mode=0o600),
                binding(web01, f"gone-{token}.example.test", "missing_file", cert_owner=None, cert_group=None,
                        cert_mode=None),
                binding(web01, f"retired-{token}.example.test", "matched", certificate_id=other.id,
                        on_disk_fingerprint=other.sha256_fingerprint, is_active=False),
                binding(web02, f"shop-{token}.example.test", "unknown", on_disk_fingerprint="c" * 64,
                        webserver=WebserverType.APACHE),
                binding(web02, f"blog-{token}.example.test", "matched", certificate_id=certificate.id,
                        on_disk_fingerprint=fingerprint, webserver=WebserverType.APACHE),
            ]
        )
        db.add_all(
            [
                endpoint(web01, f"www-{token}.example.test", "mismatch"),
                endpoint(web01, f"api-{token}.example.test", "ok"),
                endpoint(web01, f"retired-{token}.example.test", "mismatch", active=False),
                endpoint(web02, f"shop-{token}.example.test", "expired"),
            ]
        )
        # (age in hours, host status, job status, inventory_rev, error): newest first is "ok".
        for age, host_status, job_status, rev, error in [
            (1, JobHostStatus.SUCCEEDED, JobStatus.SUCCEEDED, "1f3c9a7", None),
            (25, JobHostStatus.FAILED, JobStatus.FAILED, None, "ssh: connect to host failed password=fixture-leaked-secret"),
            (49, JobHostStatus.SUCCEEDED, JobStatus.SUCCEEDED, "0d4e5b2", None),
        ]:
            started = now - timedelta(hours=age)
            job = Job(type=JobType.DISCOVER, status=job_status, priority=100, payload={}, run_after=started,
                      started_at=started, finished_at=started + timedelta(seconds=95),
                      result={"inventory_rev": rev} if rev else None)
            db.add(job)
            db.flush()
            db.add(JobHost(job_id=job.id, server_id=web01.id, status=host_status, started_at=started,
                           finished_at=started + timedelta(seconds=95), error_message=error))
        deploy = Job(type=JobType.DEPLOY, status=JobStatus.SUCCEEDED, priority=100, payload={}, run_after=now,
                     started_at=now, finished_at=now)
        db.add(deploy)
        db.flush()
        db.add(JobHost(job_id=deploy.id, server_id=web01.id, status=JobHostStatus.SUCCEEDED, started_at=now,
                       finished_at=now))
    return SimpleNamespace(
        token=token,
        group=group,
        server=lambda short: servers[short],
        certificate_id=certificate.id,
        certificate_fingerprint=fingerprint,
        other_certificate_id=other.id,
        hosts_using_certificate={servers["web01.example.internal"].hostname, servers["web02.example.internal"].hostname},
        discovery_age_hours=(1, 25, 49),
    )


# --- Compose TLS/SMTP targets (Plan 2 Task 17) -------------------------------------------------


class ComposeTargets:
    """The ``targets`` profile of ``docker-compose.test.yml``: nginx and Apache TLS servers plus an SMTP capture.

    Only throwaway material lives in the session temp directory: a fixture CA, its leaves (key files 0600)
    and a dummy file for every secret the compose file declares.
    """

    WEB_SERVERS = ("tls-nginx", "tls-apache")
    RELOAD: ClassVar[dict[str, list[str]]] = {
        "tls-nginx": ["nginx", "-s", "reload"],
        "tls-apache": ["httpd", "-k", "graceful"],
    }
    STABLE_POLLS = 10
    CONTAINER_PORTS: ClassVar[dict[str, int]] = {"tls-nginx": 8443, "tls-apache": 8443, "smtp": 1025}

    def __init__(self, directory: Path):
        import os
        import uuid

        self.directory = directory
        self.project = "certdash-targets-" + uuid.uuid4().hex[:10]
        self.env = {
            **os.environ,
            "TLS_TARGET_DIR": str(directory / "tls-targets"),
            "TEST_SECRETS_DIR": str(directory / "secrets"),
        }
        self._stopped: set[str] = set()
        self._prepare()

    def _prepare(self):
        from datetime import UTC, datetime

        import yaml
        from cryptography.hazmat.primitives.asymmetric import ec

        from tests.fixtures.ca import FixtureCA

        (self.directory / "secrets").mkdir()
        for name in yaml.safe_load((ROOT / "docker-compose.test.yml").read_text())["secrets"]:
            (self.directory / "secrets" / name).write_text("dummy-target-secret")
        ca = FixtureCA(datetime.now(UTC))
        for service in self.WEB_SERVERS:  # the servers refuse to start without a certificate
            key = ec.generate_private_key(ec.SECP256R1())
            pem = ca.issue(public_key=key.public_key(), common_name="initial.example.internal", sans=["initial.example.internal"])
            self._write(service, x509_load(pem), key, [ca.intermediate])

    def _write(self, service, cert, key, chain):
        import os

        from cryptography.hazmat.primitives import serialization

        folder = self.directory / "tls-targets" / service
        folder.mkdir(parents=True, exist_ok=True)
        chain_pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in [cert, *chain])
        key_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        for name, data, mode in (("fullchain.pem", chain_pem, 0o644), ("key.pem", key_pem, 0o600)):
            # Replace the file (new inode) instead of rewriting it: nginx caches a loaded certificate by
            # path, inode and mtime in whole seconds, so a same-size in-place rewrite within one second
            # of the previous write would survive a reload.
            temporary = folder / f".{name}.tmp"
            temporary.unlink(missing_ok=True)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.chmod(temporary, mode)  # the umask must not widen a key file
            os.replace(temporary, folder / name)

    def _compose(self, *args, check=True, timeout=120):
        import subprocess

        command = ["docker", "compose", "-p", self.project, "-f", "docker-compose.test.yml", "--profile", "targets", *args]
        return subprocess.run(command, cwd=ROOT, env=self.env, capture_output=True, text=True, check=check, timeout=timeout)

    def up(self):
        import subprocess

        try:
            self._compose("up", "-d", "--wait", "--pull", "never", "tls-nginx", "tls-apache", "smtp", timeout=300)
        except subprocess.CalledProcessError as error:
            logs = self._compose("logs", "--no-color", check=False).stdout[-4000:]
            self.down()
            raise RuntimeError(f"compose targets failed to start: {error.stderr[-2000:]}\n{logs}") from None

    def down(self):
        import shutil

        self._compose("down", "-v", "--remove-orphans", "-t", "2", check=False)
        shutil.rmtree(self.directory, ignore_errors=True)

    def address(self, service) -> tuple[str, int]:
        """The published loopback ``(host, port)``; asked each time because a restart may change the port."""
        output = self._compose("port", service, str(self.CONTAINER_PORTS[service])).stdout.strip()
        return "127.0.0.1", int(output.rpartition(":")[2])

    def _served_der(self, service) -> bytes:
        """The leaf the target serves on a fresh connection, read with the scanner's own TLS primitive."""
        from app.services.scans import pull_chain

        host, port = self.address(service)
        return pull_chain(host, port, "target.example.internal", 3).der_chain[0]

    def _draining(self, service) -> bool:
        """True while a previous server generation is still alive and may answer a new connection.

        nginx marks old workers ``worker process is shutting down`` in the process title; during that window
        the old and the new worker share the listening socket, so one new-certificate answer proves nothing.
        """
        if service != "tls-nginx":
            return False
        listing = self._compose("exec", "-T", service, "ps", "-o", "args").stdout
        return "shutting down" in listing

    def serve(self, service, cert, key, chain) -> None:
        """Serve ``cert`` + ``chain``: rewrite the files, start the service if stopped, reload, await the swap.

        Ready means: no old server generation is draining and ``STABLE_POLLS`` consecutive fresh connections
        all get the new leaf. A single new-certificate answer is not enough: during a graceful reload the old
        worker keeps accepting connections until it processes the quit signal.
        """
        import time

        from cryptography.hazmat.primitives.serialization import Encoding

        from app.jobs.queue import JobFailure

        self._write(service, cert, key, chain)
        if service in self._stopped:
            self._compose("start", service)
            self._stopped.discard(service)
        self._compose("exec", "-T", service, *self.RELOAD[service])
        wanted, deadline, last, streak = cert.public_bytes(Encoding.DER), time.monotonic() + 30, "no answer yet", 0
        while time.monotonic() < deadline:
            try:
                if self._served_der(service) == wanted:
                    streak += 1
                    if streak >= self.STABLE_POLLS and not self._draining(service):
                        return
                else:
                    streak, last = 0, "still serving another certificate"
            except (OSError, JobFailure) as error:  # still (re)starting
                streak, last = 0, type(error).__name__
            time.sleep(0.1)
        logs = self._compose("logs", "--no-color", "--tail", "20", service, check=False).stdout
        raise TimeoutError(
            f"{service} did not settle on the new certificate within 30 s: expected {self.STABLE_POLLS} "
            f"consecutive fresh connections serving it and no draining old generation ({last})\n{logs}"
        )

    def stop(self, service) -> None:
        self._compose("stop", "-t", "2", service)
        self._stopped.add(service)

    def messages(self) -> list:
        """Every message captured by the ``smtp`` service, read from its spool."""
        import json
        from email import message_from_string, policy

        output = self._compose("exec", "-T", "smtp", "python", "-m", "tests.fixtures.smtp_capture", "--dump", "/spool").stdout
        return [message_from_string(raw, policy=policy.default) for raw in json.loads(output)]


def x509_load(pem: bytes):
    from cryptography import x509

    return x509.load_pem_x509_certificate(pem)


@pytest.fixture(scope="session")
def compose_targets(tmp_path_factory):
    targets = ComposeTargets(tmp_path_factory.mktemp("targets"))
    targets.up()
    yield targets
    targets.down()


# --- SSH-enabled nginx/Apache targets (Plan 3 Task 3) -----------------------------------------


@pytest.fixture(scope="session")
def ssh_targets(tmp_path_factory, ca):
    """The ``ssh-targets`` compose profile: three real sshd + webserver containers with pinned host keys."""
    from tests.fixtures.ssh_targets import TargetStack

    stack = TargetStack(tmp_path_factory.mktemp("ssh-targets"), ca)
    stack.up()
    yield stack
    stack.down()


@pytest.fixture
def fresh_targets(ssh_targets):
    """``ssh_targets`` with all three reset to their initial state; request it in any test that reads or mutates them."""
    ssh_targets.reset_all()
    return ssh_targets


@pytest.fixture
def runner_secrets(tmp_path, ssh_targets):
    """The test ``ansible_ssh_key`` (a 0600 file) and the pinned ``known_hosts`` for the SSH targets."""
    from app.ansible.runner import RunnerSecrets

    key = tmp_path / "ansible_ssh_key"
    key.write_bytes(ssh_targets.client_key)
    key.chmod(0o600)
    return RunnerSecrets(key, ssh_targets.known_hosts)


# --- job control helpers (Plan 3 Task 1) -------------------------------------------------------


def fetch(factory, model, row_id):
    """Reload one committed row in a fresh session."""
    with factory() as db:
        return db.get(model, row_id)


def enqueue_one(factory, job_type, payload, *, priority, max_attempts=3, run_after=None):
    """Commit one job through ``enqueue`` (with its audit row); due immediately unless ``run_after``."""
    from datetime import UTC, datetime

    from app.jobs.queue import SYSTEM_ACTOR, enqueue

    with factory.begin() as db:
        job = enqueue(
            db,
            job_type,
            payload,
            SYSTEM_ACTOR,
            priority=priority,
            run_after=run_after or datetime(2020, 1, 1, tzinfo=UTC),
            max_attempts=max_attempts,
        )
        return job.id


def audit_actions(factory, target_id):
    """Audit actions recorded for one target, oldest first."""
    from sqlalchemy import select

    from app.models import AuditLog

    with factory() as db:
        return list(
            db.scalars(
                select(AuditLog.action)
                .where(AuditLog.target_id == target_id)
                .order_by(AuditLog.created_at, AuditLog.id)
            )
        )


# --- Git inventory helpers (Plan 3 Task 4) -----------------------------------------------------



@pytest.fixture
def inventory_repo(tmp_path_factory):
    """``inventory_repo(factory, *, hosts, groups=None, vault=None) -> InventoryRepo``.

    Builds a bare ``file://`` inventory repository in a fresh temporary directory and writes the
    ``inventory.*`` rows pointing at it. ``hosts`` maps hostname -> host variables, ``groups`` maps
    group -> hostnames, ``vault`` is ``(password, mapping)`` for an encrypted
    ``group_vars/all/vault.yml``. The rows are written directly: the settings validator accepts only
    ``https``/``ssh``/scp URLs, so this is a test-only shortcut.
    """
    import json

    def build(factory, *, hosts, groups=None, vault=None, ref="main") -> InventoryRepo:
        root = tmp_path_factory.mktemp("inventory-repo")
        document = {
            "all": {
                "hosts": {name: dict(variables) for name, variables in hosts.items()},
                "children": {
                    group: {"hosts": {name: {} for name in names}} for group, names in (groups or {}).items()
                },
            }
        }
        repo = make_bare_repo(root / "inventory.git", {"inventory/hosts.yml": json.dumps(document)})
        if vault is not None:
            password, mapping = vault
            staging = root / "vault-staging"
            (staging / "group_vars/all").mkdir(parents=True)
            write_vaulted(staging / "group_vars/all/vault.yml", mapping, password)
            repo.commit({"inventory/group_vars/all/vault.yml": (staging / "group_vars/all/vault.yml").read_text()})
        for key, value in (
            ("inventory.repo_url", repo.url),
            ("inventory.ref", ref),
            ("inventory.path", "inventory"),
            ("inventory.webserver_var", "webserver_type"),
        ):
            set_setting(factory, key, value)
        return repo

    return build


# --- discovery reconciliation helpers (Plan 3 Task 9) --------------------------------------------

JOB_ID = uuid.UUID("5d0c6f0e-6f0a-4a0e-9d58-3c1f0b7a2e11")


def binding_doc(
    vhost,
    *,
    fp=None,
    key=None,
    exists=True,
    key_unreadable=False,
    port=443,
    cert_path=None,
    key_path=None,
    chain_path=None,
    chain_diagnostic=None,
    config_file=None,
    vhost_names=None,
    webserver="nginx",
):
    """One §6.2 binding as Task 8A emits it; ``exists=False`` is a certificate and key missing on the host."""
    return {
        "webserver": webserver,
        "vhost_name": vhost,
        "vhost_names": list(vhost_names) if vhost_names is not None else [vhost],
        "port": port,
        "config_file": config_file or f"/etc/nginx/conf.d/{vhost}.conf",
        "cert_path": cert_path or f"/etc/ssl/{vhost}.pem",
        "chain_path": chain_path,
        "key_path": key_path or f"/etc/ssl/{vhost}.key",
        "cert_owner": "root" if exists else None,
        "cert_group": "root" if exists else None,
        "cert_mode": "0644" if exists else None,
        "key_owner": "root" if exists else None,
        "key_group": "root" if exists else None,
        "key_mode": "0600" if exists else None,
        "cert_exists": exists,
        "cert_fingerprint": (fp or "c" * 64) if exists else None,
        "key_exists": exists,
        "key_public_sha256": (key or "b" * 64) if exists and not key_unreadable else None,
        "key_unreadable": key_unreadable,
        "chain_diagnostic": chain_diagnostic,
    }


def host_document(hostname, at, bindings, *, webserver="nginx"):
    return {
        "hostname": hostname,
        "webserver": webserver,
        "collected_at": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "bindings": list(bindings),
        "errors": [],
    }


def issue_leaf(ca, now, common_name="www.example.internal"):
    """A fresh EC key and the leaf the session ``ca`` issues for it, parsed, not yet imported."""
    from types import SimpleNamespace

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

    from app.crypto.chain import order_chain
    from app.crypto.parse import parse_certificates

    key = ec.generate_private_key(ec.SECP256R1())
    pem = ca.issue(
        public_key=key.public_key(),
        common_name=common_name,
        sans=[common_name],
        not_before=now.replace(year=2025),
        not_after=now.replace(year=2027),
    )
    leaf = parse_certificates(pem)[0]
    chain = order_chain(leaf.cert, [x509.load_pem_x509_certificate(ca.chain_pem)])
    return SimpleNamespace(
        key=key, leaf=leaf, chain=chain, fingerprint=leaf.sha256_fingerprint, spki=leaf.public_key_sha256
    )


def import_leaf(db, issued, keyring, actor, now):
    """Store the key and import the leaf; returns ``(id, sha256_fingerprint, spki)`` as an object."""
    from types import SimpleNamespace

    from app.services.certificates import CertificateMetadata, save_certificate, store_key

    row = store_key(db, keyring, issued.key, "generated", actor)
    metadata = CertificateMetadata(owner_name="Ada", owner_email="ada@example.test", team="web")
    saved = save_certificate(
        db, issued.leaf, issued.chain, metadata, actor, source="upload_pem", key_id=row.id, validation_time=now
    ).certificate
    return SimpleNamespace(
        id=saved.id, sha256_fingerprint=saved.sha256_fingerprint, spki=issued.spki, certificate=saved
    )


@pytest.fixture
def keyed_certificate(db, ca, keyring, actor, now):
    """An active certificate with a stored key issued by the session ``ca``; ``.spki`` = its SPKI SHA-256."""
    return import_leaf(db, issue_leaf(ca, now), keyring, actor, now)


# --- Deploy world (Plan 3 Task 13) -------------------------------------------------------------


def _world_certificate(db, ca, keyring, actor, now, *, days_before, days_after, renews_id=None):
    """A keyed leaf the session ``ca`` issues for the deploy names, imported with its key."""
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

    from app.crypto.chain import order_chain
    from app.crypto.parse import parse_certificates
    from app.services.certificates import CertificateMetadata, save_certificate, store_key

    names = ("www.example.internal", "legacy.example.internal")
    key = ec.generate_private_key(ec.SECP256R1())
    pem = ca.issue(
        public_key=key.public_key(),
        common_name=names[0],
        sans=list(names),
        not_before=now - timedelta(days=days_before),
        not_after=now + timedelta(days=days_after),
    )
    leaf = parse_certificates(pem)[0]
    chain = order_chain(leaf.cert, [x509.load_pem_x509_certificate(ca.chain_pem)])
    key_row = store_key(db, keyring, key, "generated", actor)
    saved = save_certificate(
        db,
        leaf,
        chain,
        CertificateMetadata(owner_name="Ada", owner_email="ada@example.test", team="web"),
        actor,
        source="upload_pem",
        key_id=key_row.id,
        renews_id=renews_id,
        validation_time=now,
    )
    return saved.certificate, key_row


@pytest.fixture
def deploy_world_factory(ca, keyring, now):
    """``build(db, actor)``: the database-only deploy world of Plan 3 Task 13.

    Three servers (``canary_ring``/``ring_a``/``ring_a``), four active ``matched`` bindings of the
    previous certificate -- ``web01`` www + legacy sharing ``/etc/nginx/ssl/www.crt``, ``web02`` www,
    ``web03`` www with a chain file -- an issued renewal whose new (keyed) certificate replaces it, and
    the fixture root uploaded as a trust anchor so both chains are ``trusted``.
    """

    def build(db, actor):
        from datetime import timedelta
        from types import SimpleNamespace

        from app.models import Binding, Renewal, Server
        from app.models.enums import RenewalState, WebserverType
        from app.services.deploy import configure_keyring
        from app.services.trust_anchors import add_anchor

        configure_keyring(keyring)
        anchor = add_anchor(db, ca.root_pem, "deploy fixture root", actor, now)
        old, old_key = _world_certificate(db, ca, keyring, actor, now, days_before=400, days_after=400)
        new_certificate, new_key = _world_certificate(
            db, ca, keyring, actor, now, days_before=380, days_after=200, renews_id=old.id
        )
        renewal = Renewal(
            certificate_id=new_certificate.id,
            previous_certificate_id=old.id,
            state=RenewalState.ISSUED,
            common_name="www.example.internal",
            sans=["www.example.internal", "legacy.example.internal"],
            key_id=new_key.id,
            state_changed_at=now,
        )
        db.add(renewal)
        servers = {}
        for hostname, group, webserver in (
            ("web01.example.internal", "canary_ring", WebserverType.NGINX),
            ("web02.example.internal", "ring_a", WebserverType.NGINX),
            ("web03.example.internal", "ring_a", WebserverType.APACHE),
        ):
            servers[hostname] = Server(
                hostname=hostname,
                ansible_groups=[group],
                webserver=webserver,
                inventory_source="main:inventory/hosts.yml@cafebabe",
                last_discovery_at=now - timedelta(hours=1),
                last_discovery_status="ok",
            )
            db.add(servers[hostname])
        db.flush()

        def binding(hostname, vhost, *, cert_path, key_path, config_file, chain_path=None):
            server = servers[hostname]
            row = Binding(
                server_id=server.id,
                webserver=server.webserver,
                vhost_name=vhost,
                vhost_names=[vhost],
                port=443,
                config_file=config_file,
                cert_path=cert_path,
                chain_path=chain_path,
                key_path=key_path,
                cert_owner="root",
                cert_group="root",
                cert_mode=0o644,
                key_owner="root",
                key_group="root",
                key_mode=0o600,
                on_disk_fingerprint=old.sha256_fingerprint,
                on_disk_key_public_sha256=old_key.public_key_sha256,
                certificate_id=old.id,
                match_state="matched",
                last_seen_at=now - timedelta(hours=1),
            )
            db.add(row)
            db.flush()
            return row

        target_bindings = (
            binding(
                "web01.example.internal",
                "www.example.internal",
                cert_path="/etc/nginx/ssl/www.crt",
                key_path="/etc/nginx/ssl/www.key",
                config_file="/etc/nginx/conf.d/www.conf",
            ),
            binding(
                "web01.example.internal",
                "legacy.example.internal",
                cert_path="/etc/nginx/ssl/www.crt",
                key_path="/etc/nginx/ssl/legacy.key",
                config_file="/etc/nginx/conf.d/legacy.conf",
            ),
            binding(
                "web02.example.internal",
                "www.example.internal",
                cert_path="/etc/nginx/ssl/www.crt",
                key_path="/etc/nginx/ssl/www.key",
                config_file="/etc/nginx/conf.d/www.conf",
            ),
            binding(
                "web03.example.internal",
                "www.example.internal",
                cert_path="/etc/apache2/ssl/www.crt",
                key_path="/etc/apache2/ssl/www.key",
                chain_path="/etc/apache2/ssl/www.chain.pem",
                config_file="/etc/apache2/sites-enabled/www.conf",
            ),
        )
        db.flush()
        return SimpleNamespace(
            old=old,
            old_key=old_key,
            new_certificate=new_certificate,
            new_key=new_key,
            renewal=renewal,
            anchor=anchor,
            servers=servers,
            target_bindings=target_bindings,
            batch_of={
                servers["web01.example.internal"].id: 0,
                servers["web02.example.internal"].id: 1,
                servers["web03.example.internal"].id: 2,
            },
        )

    return build


@pytest.fixture
def deploy_world(db, actor, deploy_world_factory):
    """The Plan 3 Task 13 deploy world inside the per-test rollback transaction."""
    return deploy_world_factory(db, actor)


# --- Deploy material (Plan 3 Task 14) -----------------------------------------------------------


def spki_of(pem: bytes | str) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo of a private-key or certificate PEM (the D2 identity)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    data = pem.encode() if isinstance(pem, str) else pem
    if b"PRIVATE KEY" in data:
        return public_key_sha256(serialization.load_pem_private_key(data, password=None).public_key())
    return public_key_sha256(x509.load_pem_x509_certificate(data).public_key())


def writes_of(outcome, path: str) -> int:
    """How many write operations the host reported for ``path`` (0 when it was not written)."""
    files = outcome.precheck.get("files")
    entry = files.get(path) if isinstance(files, dict) else None
    if not isinstance(entry, dict):
        return 0
    return int(entry.get("writes", 1 if entry.get("written") else 0))


def task_starts(run_dir: Path) -> list[str]:
    """The task names ``ansible-runner`` recorded under ``run_dir``, in execution order.

    The events on disk are the only trustworthy evidence of *which* tasks ran and how often: the playbook's
    own published facts cannot prove that a rollback did not run twice (Task 15).
    """
    events = sorted(Path(run_dir).rglob("job_events/*.json"), key=lambda path: int(path.name.split("-", 1)[0]))
    names: list[str] = []
    for path in events:
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("event") == "playbook_on_task_start":
            names.append(document["event_data"]["task"])
    return names


def new_deploy_leaf(ca, names=VHOSTS):
    """A fresh leaf for ``names`` with its own key, the session CA's chain and the D2 identities."""
    from types import SimpleNamespace

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    cert_pem = ca.issue(public_key=key.public_key(), common_name=names[0], sans=list(names))
    chain_pem = ca.chain_pem
    return SimpleNamespace(
        key=key,
        cert_pem=cert_pem,
        chain_pem=chain_pem,
        fullchain_pem=cert_pem + chain_pem,
        key_pem=key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        fingerprint=x509.load_pem_x509_certificate(cert_pem).fingerprint(hashes.SHA256()).hex(),
        spki_sha256=public_key_sha256(key.public_key()),
        served_chain_length=1 + len(x509.load_pem_x509_certificates(chain_pem)),
    )


class DeployMaterial:
    """The staged material of one host deploy plus the helpers ``tests/integration/test_deploy_*.py`` use."""

    def __init__(self, *, directory, ssh_targets, secrets, material, staged, artifact_dir, run_dir, mismatched):
        self.directory = directory
        self.ssh_targets = ssh_targets
        self.secrets = secrets
        self.material = material
        self.staged = staged
        self.artifact_dir = artifact_dir
        self.run_dir = run_dir
        self.mismatched_staged = mismatched
        self.other = new_deploy_leaf(ca=material.ca, names=("other.example.internal",))

    # the new material, as the tests assert it on the target
    @property
    def cert_pem(self) -> bytes:
        return self.material.cert_pem

    @property
    def chain_pem(self) -> bytes:
        return self.material.chain_pem

    @property
    def fullchain_pem(self) -> bytes:
        return self.material.fullchain_pem

    @property
    def fingerprint(self) -> str:
        return self.material.fingerprint

    @property
    def spki_sha256(self) -> str:
        return self.material.spki_sha256

    @property
    def served_chain_length(self) -> int:
        return self.material.served_chain_length

    @property
    def other_fullchain_pem(self) -> bytes:
        """An unrelated certificate, for the drift and conflict cases."""
        return self.other.fullchain_pem

    def target(self, *, binding_id, cert_path, key_path, port, sni, expected, chain_path=None):
        """One ``DeployTarget`` of this host, expected to still carry ``expected`` on disk."""
        from app.services.deploy import DeployTarget

        return DeployTarget(
            binding_id=binding_id,
            cert_path=cert_path,
            chain_path=chain_path,
            key_path=key_path,
            expected_fingerprint=expected,
            new_fingerprint=self.fingerprint,
            port=port,
            sni=sni,
        )

    def runner(self, directory):
        """A ``RunnerContext`` whose inventory is the SSH target stack and whose run directory is fresh."""
        from pathlib import Path

        from app.ansible.runner import RunnerContext

        base = Path(directory)
        (base / "inventory").mkdir(parents=True, exist_ok=True)
        return RunnerContext(
            secrets=self.secrets,
            inventory=self.ssh_targets.inventory_file(base / "inventory"),
            run_dir=base / "run",
            artifact_dir=self.artifact_dir,
        )


@pytest.fixture
def deploy_material(ca, ssh_targets, runner_secrets, tmp_path):
    """``deploy_material``: a new leaf for ``www``+``legacy`` and its key, staged like a real deploy.

    The public PEMs live in ``<tmp>/artifacts/files`` and the key only in the ``StagingArea``
    (``<tmp>/keys/<job_id>/tls_key.pem``), which is removed when the fixture ends. A second staging area
    holds the same leaf with an unrelated private key (``mismatched_staged``) for the D2 refusal case.
    """
    from types import SimpleNamespace

    from app.ansible.deploy import stage_material
    from app.ansible.staging import StagingArea

    material = new_deploy_leaf(ca)
    material.ca = ca
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    other = new_deploy_leaf(ca, names=("other.example.internal",))
    staging = StagingArea(tmp_path / "keys", JOB_ID)
    mismatched_staging = StagingArea(tmp_path / "keys", uuid.UUID(int=99))
    staging.__enter__()
    mismatched_staging.__enter__()
    staged = stage_material(
        SimpleNamespace(pem=material.cert_pem.decode(), chain_pem=material.chain_pem.decode()),
        material.key,
        artifact_dir,
        staging,
    )
    mismatched = stage_material(
        SimpleNamespace(pem=material.cert_pem.decode(), chain_pem=material.chain_pem.decode()),
        other.key,
        tmp_path / "mismatched-artifacts",
        mismatched_staging,
    )
    try:
        yield DeployMaterial(
            directory=tmp_path,
            ssh_targets=ssh_targets,
            secrets=runner_secrets,
            material=material,
            staged=staged,
            artifact_dir=artifact_dir,
            run_dir=tmp_path / "run",
            mismatched=mismatched,
        )
    finally:
        mismatched_staging.__exit__(None, None, None)
        staging.__exit__(None, None, None)


# --- Deploy runtime (Plan 3 Task 16) -------------------------------------------------------------


def _import_target_certificate(factory, material, actor, now) -> int:
    """Import the certificate the SSH targets serve (public part only), as an inventory entry would be."""
    from cryptography import x509

    from app.crypto.chain import order_chain
    from app.crypto.parse import parse_certificates
    from app.services.certificates import CertificateMetadata, save_certificate

    leaf = parse_certificates(material.cert_pem)[0]
    chain = order_chain(leaf.cert, list(x509.load_pem_x509_certificates(material.chain_pem)))
    with factory.begin() as db:
        saved = save_certificate(
            db,
            leaf,
            chain,
            CertificateMetadata(owner_name="Ada", owner_email="ada@example.test", team="web"),
            actor,
            source="upload_pem",
            validation_time=now,
        )
        return saved.certificate.id


@pytest.fixture
def deploy_ready(ssh_targets, fresh_targets, queue_factory, ansible_worker, inventory_repo, keyring, ca, clock, tmp_path):
    """``deploy_ready``: the Plan 3 Task 16 deploy world, discovered from the real SSH targets.

    A real discovery of all three targets runs once, after importing the certificate they serve, so every
    binding is ``matched`` and every server knows its webserver. The renewal's new certificate (same vhost
    names, a new key, issued by the session ``ca``) is stored with its key, the fixture root is uploaded as a
    trust anchor, and ``start(**options)`` previews and enqueues one deploy job for it with ``confirmed=True``.
    ``worker`` runs ``deploy/default``; ``build_worker(**overrides)`` builds another worker on the same
    database (the key-unwrap case needs a keyring without the key version).

    Artifacts go to a short ``/tmp`` directory: ssh refuses a multiplexing socket path of 108+ bytes and a
    pytest ``tmp_path`` is too deep for ``<artifacts>/<job_id>/run/cp/<40-hex hash>``.
    """
    import shutil
    import tempfile
    from types import SimpleNamespace

    from cryptography import x509

    from app.crypto.chain import order_chain
    from app.crypto.parse import parse_certificates
    from app.jobs.handlers import build_registry
    from app.jobs.handlers.deploy import deploy_handler_registration
    from app.jobs.handlers.discover import request_discovery
    from app.models import Job, Renewal
    from app.models.enums import RenewalState
    from app.services.audit import Actor
    from app.services.certificates import CertificateMetadata, save_certificate, store_key
    from app.services.deploy import DeployOptions, configure_keyring, preview_deploy, start_deploy
    from app.services.trust_anchors import add_anchor

    actor = Actor(None, "tester")
    artifacts = Path(tempfile.mkdtemp(prefix="cd-", dir="/tmp"))
    configure_keyring(keyring)
    repo = inventory_repo(queue_factory, hosts=ssh_targets.inventory_hosts())
    registry = build_registry()
    deploy_handler_registration(registry)

    def build_worker(**overrides):
        values = {
            "ansible_ssh_key": ssh_targets.client_key,
            "known_hosts_file": ssh_targets.known_hosts,
            "artifacts_root": artifacts,
            "keyring": keyring,
            "key_staging_dir": tmp_path / "keys",
            # ``build_registry()`` registers ``deploy/default`` in Task 19; until then the fixture wires it.
            "registry": registry,
        }
        return ansible_worker(queue_factory, **{**values, **overrides})

    worker = build_worker()

    def discover() -> None:
        with queue_factory.begin() as db:
            job_id = request_discovery(db, {}, actor, clock()).id
        worker.run_queued(timeout=900)
        with queue_factory() as db:
            job = db.get(Job, job_id)
            if job.status != "succeeded":
                raise RuntimeError(
                    f"deploy_ready discovery failed: {job.error_class} {job.error_message} {job.result}"
                )

    try:
        with queue_factory.begin() as db:
            anchor = add_anchor(db, ca.root_pem, "deploy fixture root", actor, clock())
        # The certificate the targets serve is imported first: one discovery then yields four ``matched``
        # bindings (importing it afterwards would need a second run of the whole inventory).
        old_id = _import_target_certificate(queue_factory, ssh_targets.old, actor, clock())
        discover()

        material = new_deploy_leaf(ca, names=VHOSTS)
        leaf = parse_certificates(material.cert_pem)[0]
        chain = order_chain(leaf.cert, list(x509.load_pem_x509_certificates(material.chain_pem)))
        with queue_factory.begin() as db:
            key_row = store_key(db, keyring, material.key, "generated", actor)
            saved = save_certificate(
                db,
                leaf,
                chain,
                CertificateMetadata(owner_name="Ada", owner_email="ada@example.test", team="web"),
                actor,
                source="upload_pem",
                key_id=key_row.id,
                renews_id=old_id,
                validation_time=clock(),
            ).certificate
            renewal = Renewal(
                certificate_id=saved.id,
                previous_certificate_id=old_id,
                state=RenewalState.ISSUED,
                common_name=leaf.common_name,
                sans=list(leaf.sans),
                key_id=key_row.id,
                state_changed_at=clock(),
            )
            db.add(renewal)
            new = SimpleNamespace(
                id=saved.id,
                sha256_fingerprint=saved.sha256_fingerprint,
                key_public_sha256=key_row.public_key_sha256,
                key_pem=material.key_pem,
                cert_pem=material.cert_pem,
            )

        def start(**options):
            """Preview and enqueue the deploy exactly as the screen does (plan hash echoed, confirmed)."""
            moment = clock()
            with queue_factory.begin() as db:
                deploy_options = DeployOptions(certificate_id=new.id, **options)
                preview = preview_deploy(db, deploy_options, moment, keyring=keyring)
                if preview.blocked:
                    raise RuntimeError(f"deploy refused: {preview.blocked}")
                return start_deploy(
                    db,
                    deploy_options,
                    plan_sha256=preview.plan_sha256,
                    confirmed=True,
                    override_reason=None,
                    actor=actor,
                    now=moment,
                    keyring=keyring,
                ).id

        yield SimpleNamespace(
            repo=repo,
            renewal=renewal,
            new=new,
            other_cert_pem=new_deploy_leaf(ca, names=("other.example.internal",)).fullchain_pem,
            worker=worker,
            build_worker=build_worker,
            start=start,
            anchor=anchor,
            clock=clock,
            key_staging_dir=tmp_path / "keys",
            artifacts_root=artifacts,
        )
    finally:
        shutil.rmtree(artifacts, ignore_errors=True)
