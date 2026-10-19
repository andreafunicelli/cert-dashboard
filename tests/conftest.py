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
