import base64
import json

import pytest


@pytest.fixture
def secret_files(tmp_path):
    key = base64.b64encode(bytes(range(32))).decode()
    (tmp_path / "master_key").write_text(json.dumps({"active": 1, "keys": {"1": key}}))
    (tmp_path / "db_password").write_bytes(b"file-value\n")
    (tmp_path / "session_secret").write_bytes(b"session-test-only-32-random-bytes!!")
    return tmp_path


@pytest.fixture
def now():
    from datetime import UTC, datetime

    return datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="session")
def certs():
    from datetime import UTC, datetime

    from tests.fixtures.certificates import generate_certificates

    return generate_certificates(datetime(2026, 10, 19, 12, 0, tzinfo=UTC))


@pytest.fixture
def tls_material():
    """A 127.0.0.1 leaf from a wall-clock-dated fixture CA with ``server_context()``/``client_context()``."""
    from tests.fixtures.smtp_capture import make_tls_material

    return make_tls_material()


@pytest.fixture
def smtp_server():
    """Factory for loopback ``CaptureServer`` instances; every one is closed at teardown."""
    from tests.fixtures.smtp_capture import CaptureServer

    started = []

    def start(**options):
        server = CaptureServer(**options)
        started.append(server)
        return server

    yield start
    for server in started:
        server.close()
