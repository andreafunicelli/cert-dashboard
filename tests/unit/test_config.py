import base64
import json

import pytest


def test_secret_file_wins_and_settings_keep_startup_snapshot(secret_files):
    from app.config import load_settings

    settings = load_settings("web", {"DB_PASSWORD": "env-value"}, secret_files)
    assert settings.db_password == b"file-value"
    assert settings.worker_concurrency == 4
    (secret_files / "db_password").write_bytes(b"rotated")
    assert settings.db_password == b"file-value"
    assert "file-value" not in repr(settings)


def test_env_fallback_when_secret_file_absent(secret_files):
    from app.config import load_settings

    (secret_files / "db_password").unlink()
    assert load_settings("web", {"DB_PASSWORD": "env-fallback"}, secret_files).db_password == b"env-fallback"


def test_startup_metadata_only_reports_presence_and_keyring_fingerprint(secret_files):
    import hashlib

    from app.config import load_settings

    settings = load_settings("web", {}, secret_files)
    metadata = settings.startup_metadata()
    assert metadata["master_key_active"] == 1
    assert metadata["master_key_sha256"] == hashlib.sha256((secret_files / "master_key").read_bytes()).hexdigest()
    assert metadata["db_password_present"] is True
    assert metadata["ansible_ssh_key_present"] is False
    assert "file-value" not in json.dumps(metadata)


def test_session_secret_trims_crlf_before_accepting_32_bytes(secret_files):
    from app.config import load_settings

    raw = b"r" * 32 + b"\r\n"
    (secret_files / "session_secret").write_bytes(raw)
    assert load_settings("web", {}, secret_files).session_secret == b"r" * 32


def test_migrations_can_load_database_only_credentials(secret_files):
    from app.config import load_database_settings

    (secret_files / "master_key").unlink()
    (secret_files / "session_secret").unlink()
    settings = load_database_settings({"DB_USER": "db_owner"}, secret_files)
    assert settings.db_user == "db_owner" and settings.db_password == b"file-value"
    assert "file-value" not in repr(settings)


@pytest.mark.parametrize("name", ["master_key", "db_password", "session_secret"])
@pytest.mark.parametrize("contents", [None, b"", b"\n"])
def test_web_refuses_missing_or_empty_secret(secret_files, name, contents):
    from app.config import ConfigurationError, load_settings

    target = secret_files / name
    if contents is None:
        target.unlink()
    else:
        target.write_bytes(contents)
    with pytest.raises(ConfigurationError, match=name):
        load_settings("web", {}, secret_files)


def test_empty_file_never_falls_back_to_env(secret_files):
    from app.config import ConfigurationError, load_settings

    (secret_files / "db_password").write_bytes(b"")
    with pytest.raises(ConfigurationError, match="db_password"):
        load_settings("web", {"DB_PASSWORD": "fallback"}, secret_files)


def test_worker_and_cli_do_not_require_session_secret(secret_files):
    from app.config import load_settings

    (secret_files / "session_secret").unlink()
    worker = load_settings("worker", {}, secret_files)
    assert worker.ssh_available is False
    assert worker.session_secret is None
    assert load_settings("cli", {}, secret_files).session_secret is None


def test_worker_ssh_capability_and_optional_secret_snapshot(secret_files):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from app.config import load_settings

    key = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    (secret_files / "ansible_ssh_key").write_bytes(key)
    (secret_files / "smtp_password").write_bytes(b"smtp-test-only")
    settings = load_settings("worker", {}, secret_files)
    assert settings.ssh_available
    assert settings.smtp_password == b"smtp-test-only"
    assert "smtp-test-only" not in repr(settings)


def test_web_ignores_worker_secrets(secret_files):
    from app.config import load_settings

    (secret_files / "ansible_ssh_key").write_bytes(b"bad-worker-key")
    (secret_files / "smtp_password").write_bytes(b"smtp-secret")
    web = load_settings("web", {}, secret_files)
    assert web.ansible_ssh_key is None and web.smtp_password is None


def test_malformed_optional_ssh_key_names_secret_not_contents(secret_files):
    from app.config import ConfigurationError, load_settings

    (secret_files / "ansible_ssh_key").write_bytes(b"confidential-invalid-key")
    with pytest.raises(ConfigurationError) as exc:
        load_settings("worker", {}, secret_files)
    assert "ansible_ssh_key" in str(exc.value)
    assert "confidential-invalid-key" not in str(exc.value)


@pytest.mark.parametrize("value", [b"short", b"x" * 31, b"x" * 31 + b"\n"])
def test_session_secret_requires_32_bytes(secret_files, value):
    from app.config import ConfigurationError, load_settings

    (secret_files / "session_secret").write_bytes(value)
    with pytest.raises(ConfigurationError, match="session_secret"):
        load_settings("web", {}, secret_files)


@pytest.mark.parametrize("name,value", [
    ("WORKER_CONCURRENCY", "0"), ("WORKER_CONCURRENCY", "bad"),
    ("MAX_PARALLEL_JOBS", "-1"), ("DB_PORT", "65536"), ("DB_PORT", "0"),
])
def test_invalid_numeric_configuration_is_actionable(secret_files, name, value):
    from app.config import ConfigurationError, load_settings

    with pytest.raises(ConfigurationError, match=name):
        load_settings("worker", {name: value}, secret_files)


@pytest.mark.parametrize("active", [1, 2])
def test_keyring_valid_versions_are_immutable_and_do_not_leak(active):
    from app.crypto.keyring import load_keyring

    a, b = bytes(range(32)), bytes(reversed(range(32)))
    raw = json.dumps({"active": active, "keys": {"1": base64.b64encode(a).decode(), "2": base64.b64encode(b).decode()}}).encode()
    ring = load_keyring(raw)
    assert ring.active == active and ring.keys[1] == a and ring.keys[2] == b
    assert base64.b64encode(a).decode() not in repr(ring)
    with pytest.raises(TypeError):
        ring.keys[3] = a


@pytest.mark.parametrize("count,limit", [(17, "hard limit of 16"), (3, "live limit of 2")])
def test_keyring_limits_reject_before_base64_decoding(monkeypatch, count, limit):
    from app.config import ConfigurationError
    from app.crypto.keyring import load_keyring

    def forbidden_decode(*args, **kwargs):
        pytest.fail("over-limit keyrings must be rejected before decoding any key")

    monkeypatch.setattr(base64, "b64decode", forbidden_decode)
    raw = json.dumps({"active": 1, "keys": {str(i): "invalid" for i in range(1, count + 1)}}).encode()
    with pytest.raises(ConfigurationError, match=f"master_key:.*{limit}"):
        load_keyring(raw)


def test_unsupported_openssh_key_names_secret_without_leaking_blob(secret_files):
    import struct

    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.serialization import load_ssh_private_key

    from app.config import ConfigurationError, load_settings

    def ssh_string(value):
        return struct.pack(">I", len(value)) + value

    public = ssh_string(b"ssh-confidential-unsupported")
    blob = (b"openssh-key-v1\0" + ssh_string(b"none") + ssh_string(b"none")
            + ssh_string(b"") + struct.pack(">I", 1) + ssh_string(public) + ssh_string(b"x" * 16))
    key = b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.b64encode(blob) + b"\n-----END OPENSSH PRIVATE KEY-----\n"
    with pytest.raises(UnsupportedAlgorithm):
        load_ssh_private_key(key, password=None)
    (secret_files / "ansible_ssh_key").write_bytes(key)
    with pytest.raises(ConfigurationError, match="ansible_ssh_key") as exc:
        load_settings("worker", {}, secret_files)
    assert "confidential" not in str(exc.value)


def test_unexpected_ssh_parser_error_is_safe_configuration_failure(secret_files, monkeypatch):
    from cryptography.hazmat.primitives import serialization

    from app.config import ConfigurationError, load_settings

    def failing_parser(*args, **kwargs):
        raise RuntimeError("confidential parser details")

    monkeypatch.setattr(serialization, "load_pem_private_key", failing_parser)
    (secret_files / "ansible_ssh_key").write_bytes(b"private-key-input")
    with pytest.raises(ConfigurationError, match="ansible_ssh_key") as exc:
        load_settings("worker", {}, secret_files)
    assert "confidential" not in str(exc.value)


def test_duplicate_json_keys_are_rejected_before_values_decoded():
    from app.config import ConfigurationError
    from app.crypto.keyring import load_keyring

    with pytest.raises(ConfigurationError, match="duplicate"):
        load_keyring(b'{"active":1,"keys":{"1":"x","1":"y"}}')


@pytest.mark.parametrize("document", [
    None, [], {}, {"active": 1, "keys": []},
    {"active": True, "keys": {"1": "x"}},
    {"active": 0, "keys": {"0": "x"}},
    {"active": 1.0, "keys": {"1": "x"}},
    {"active": 2, "keys": {"1": "x"}},
    {"active": 1, "keys": {"01": "x"}},
    {"active": 1, "keys": {"-1": "x"}},
    {"active": 1, "keys": {"1": "%%%"}},
    {"active": 1, "keys": {"1": base64.b64encode(b"x" * 16).decode()}},
    {"active": 3, "keys": {str(i): base64.b64encode(b"x" * 32).decode() for i in range(1,4)}},
    {"active": 17, "keys": {str(i): "invalid" for i in range(1,18)}},
    {"active": 1, "keys": {"1": base64.b64encode(b"x" * 32).decode()}, "unexpected": 1},
])
def test_invalid_keyrings_fail_closed(document):
    from app.config import ConfigurationError
    from app.crypto.keyring import load_keyring

    with pytest.raises(ConfigurationError, match="master_key"):
        load_keyring(json.dumps(document).encode())


def test_malformed_keyring_does_not_echo_input():
    from app.config import ConfigurationError
    from app.crypto.keyring import load_keyring

    with pytest.raises(ConfigurationError) as exc:
        load_keyring(b"confidential-json-not-valid")
    assert "confidential-json-not-valid" not in str(exc.value)
