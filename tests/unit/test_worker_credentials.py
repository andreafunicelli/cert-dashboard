"""Worker credentials: sealed round-trip, name-bound AAD, resolution order and write validation.

The database half of this contract (upsert, audit, rotation, banner) needs PostgreSQL and lives in
``tests/integration/test_worker_credentials.py``; everything here runs without a database.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from app.config import Settings
from app.crypto.keyring import Keyring, KeyUnwrapError
from app.models import EncryptedSetting, User
from app.services import worker_credentials as credentials

KEYRING = Keyring(1, {1: bytes(range(32))})
TWO_VERSIONS = Keyring(2, {1: bytes(range(32)), 2: bytes(reversed(range(32)))})


class _Session:
    """The read paths ``credential_state`` and ``resolve_worker_settings`` use: ``get`` by primary key."""

    def __init__(self, rows=(), users=None):
        self.rows = {row.name: row for row in rows}
        self.users = users or {}

    def get(self, model, key, **kwargs):
        if model is EncryptedSetting:
            return self.rows.get(key)
        if model is User:
            return self.users.get(key)
        raise AssertionError(f"unexpected model {model!r}")


def _settings(directory, keyring: Keyring = KEYRING) -> Settings:
    return Settings(
        profile="worker",
        keyring=keyring,
        keyring_sha256="0" * 64,
        db_password=b"fixture-db-password",
        secrets_dir=directory,
    )


def _ssh_key() -> tuple[ed25519.Ed25519PrivateKey, bytes, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return key, pem, hashlib.sha256(der).hexdigest()


def _row(keyring: Keyring, name: str, value: bytes, updated_by: int | None = None) -> EncryptedSetting:
    wrapped = credentials._seal(keyring, name, value)
    return EncryptedSetting(
        name=name,
        ciphertext=wrapped.ciphertext,
        nonce=wrapped.nonce,
        keyring_version=wrapped.version,
        updated_by=updated_by,
    )


def test_sealed_value_round_trips_and_cannot_move_to_another_setting():
    _, pem, _ = _ssh_key()
    sealed = credentials._seal(TWO_VERSIONS, credentials.SSH_PRIVATE_KEY, pem)

    assert credentials._open(
        TWO_VERSIONS, credentials.SSH_PRIVATE_KEY, sealed.ciphertext, sealed.nonce, sealed.version
    ) == bytes(pem)
    assert sealed.ciphertext != pem and len(sealed.nonce) == 12 and sealed.version == 2
    # The AAD binds the ciphertext to the setting name: the same bytes under another name fail.
    with pytest.raises(KeyUnwrapError):
        credentials._open(
            TWO_VERSIONS, credentials.VAULT_PASSWORD, sealed.ciphertext, sealed.nonce, sealed.version
        )
    # ... and to the keyring version the row was written with.
    with pytest.raises(KeyUnwrapError):
        credentials._open(TWO_VERSIONS, credentials.SSH_PRIVATE_KEY, sealed.ciphertext, sealed.nonce, 1)


def test_resolution_is_absent_when_neither_the_database_nor_a_file_has_a_value(tmp_path):
    resolved = credentials.resolve_worker_settings(_Session(), _settings(tmp_path))

    assert resolved.ansible_ssh_key is None
    assert resolved.ansible_vault_password is None
    assert resolved.inventory_git_token is None
    assert resolved.ssh_available is False


def test_a_mounted_file_wins_when_the_database_is_empty(tmp_path):
    _, pem, _ = _ssh_key()
    (tmp_path / "ansible_ssh_key").write_bytes(pem + b"\n")
    (tmp_path / "ansible_vault_password").write_bytes(b"file-vault-password\n")
    (tmp_path / "inventory_git_token").write_bytes(b"file-github-token")

    resolved = credentials.resolve_worker_settings(_Session(), _settings(tmp_path))

    # Read exactly like the startup loader read files: trailing newlines removed, nothing else changed.
    assert resolved.ansible_ssh_key == pem.rstrip(b"\r\n")
    assert resolved.ansible_vault_password == b"file-vault-password"
    assert resolved.inventory_git_token == b"file-github-token"
    assert resolved.ssh_available is True


def test_the_startup_snapshot_is_the_file_level_when_the_file_is_not_readable(tmp_path):
    """Backwards compatibility: an installation with only the mounted files behaves exactly as before."""
    settings = Settings(
        profile="worker",
        keyring=KEYRING,
        keyring_sha256="0" * 64,
        db_password=b"fixture-db-password",
        secrets_dir=tmp_path,
        ansible_ssh_key=b"snapshot-ssh-key",
        ansible_vault_password=b"snapshot-vault-password",
        inventory_git_token=b"snapshot-git-token",
    )

    resolved = credentials.resolve_worker_settings(_Session(), settings)

    assert resolved.ansible_ssh_key == b"snapshot-ssh-key"
    assert resolved.ansible_vault_password == b"snapshot-vault-password"
    assert resolved.inventory_git_token == b"snapshot-git-token"
    assert resolved.ssh_available is True
    assert credentials.credential_state(_Session(), settings, credentials.SSH_PRIVATE_KEY).source == "file"


def test_a_file_replaced_after_startup_is_read_again_before_the_snapshot_is_used(tmp_path):
    (tmp_path / "ansible_vault_password").write_bytes(b"replaced-vault-password\n")
    settings = Settings(
        profile="worker",
        keyring=KEYRING,
        keyring_sha256="0" * 64,
        db_password=b"fixture-db-password",
        secrets_dir=tmp_path,
        ansible_vault_password=b"startup-vault-password",
    )

    resolved = credentials.resolve_worker_settings(_Session(), settings)

    assert resolved.ansible_vault_password == b"replaced-vault-password"


def test_the_database_wins_over_the_file_when_both_are_set(tmp_path):
    _, pem, _ = _ssh_key()
    (tmp_path / "ansible_ssh_key").write_bytes(pem)
    (tmp_path / "ansible_vault_password").write_bytes(b"file-vault-password")
    (tmp_path / "inventory_git_token").write_bytes(b"file-github-token")
    rows = [
        _row(KEYRING, credentials.SSH_PRIVATE_KEY, b"database-ssh-key"),
        _row(KEYRING, credentials.VAULT_PASSWORD, b"database-vault-password"),
        _row(KEYRING, credentials.INVENTORY_GIT_TOKEN, b"database-github-token"),
    ]

    resolved = credentials.resolve_worker_settings(_Session(rows), _settings(tmp_path))

    assert resolved.ansible_ssh_key == b"database-ssh-key"
    assert resolved.ansible_vault_password == b"database-vault-password"
    assert resolved.inventory_git_token == b"database-github-token"


def test_ssh_available_becomes_true_when_the_key_only_lives_in_the_database(tmp_path):
    """The banner condition: no mounted file, one database row, discovery and deploy become possible."""
    _, pem, fingerprint = _ssh_key()
    rows = [_row(KEYRING, credentials.SSH_PRIVATE_KEY, pem)]
    settings = _settings(tmp_path)

    assert settings.ssh_available is False
    resolved = credentials.resolve_worker_settings(_Session(rows), settings)

    assert resolved.ssh_available is True
    assert resolved.ansible_ssh_key == pem
    state = credentials.credential_state(_Session(rows), settings, credentials.SSH_PRIVATE_KEY)
    assert state.configured is True
    assert state.source == "database"
    assert state.key_type == "Ed25519"
    assert state.fingerprint_sha256 == fingerprint


def test_credential_state_carries_metadata_and_never_the_value(tmp_path):
    _, pem, fingerprint = _ssh_key()
    row = _row(KEYRING, credentials.SSH_PRIVATE_KEY, pem, updated_by=7)
    users = {7: User(id=7, username="fixture-admin", email="admin@example.test")}

    state = credentials.credential_state(_Session([row], users), _settings(tmp_path), credentials.SSH_PRIVATE_KEY)

    assert asdict(state) == {
        "name": credentials.SSH_PRIVATE_KEY,
        "label": "SSH private key",
        "configured": True,
        "source": "database",
        "updated_at": None,
        "updated_by": "fixture-admin",
        "key_type": "Ed25519",
        "fingerprint_sha256": fingerprint,
    }
    assert "PRIVATE KEY" not in repr(state) and pem.decode() not in repr(state)


def test_a_file_backed_credential_is_reported_as_configured_by_its_file(tmp_path):
    _, pem, _ = _ssh_key()
    (tmp_path / "ansible_ssh_key").write_bytes(pem)

    state = credentials.credential_state(_Session(), _settings(tmp_path), credentials.SSH_PRIVATE_KEY)

    assert state.configured is True
    assert state.source == "file"
    assert state.updated_at is None and state.updated_by is None


def test_worker_capabilities_can_report_a_file_credential_the_web_process_cannot_see(tmp_path):
    class Capabilities:
        ssh_key_present = True
        vault_password_present = False
        inventory_token_present = False

    state = credentials.credential_state(
        _Session(), _settings(tmp_path), credentials.SSH_PRIVATE_KEY, worker=Capabilities()
    )

    assert state.configured is True and state.source == "file"
    states = credentials.credential_states(_Session(), _settings(tmp_path), worker=Capabilities())
    assert [spec.name for spec in credentials.WORKER_CREDENTIALS] == [
        credentials.SSH_PRIVATE_KEY,
        credentials.VAULT_PASSWORD,
        credentials.INVENTORY_GIT_TOKEN,
    ]
    assert states[credentials.SSH_PRIVATE_KEY].configured is True
    assert states[credentials.VAULT_PASSWORD].configured is False


def test_an_undecryptable_row_is_configured_but_states_no_metadata(tmp_path):
    _, pem, _ = _ssh_key()
    row = _row(KEYRING, credentials.SSH_PRIVATE_KEY, pem)
    only_the_new_version = Keyring(2, {2: bytes(reversed(range(32)))})

    state = credentials.credential_state(
        _Session([row]), _settings(tmp_path, only_the_new_version), credentials.SSH_PRIVATE_KEY
    )

    assert state.configured is True and state.source == "database"
    assert state.key_type is None and state.fingerprint_sha256 is None


def test_a_present_but_undecryptable_row_never_falls_back_to_the_file(tmp_path):
    _, pem, _ = _ssh_key()
    (tmp_path / "ansible_ssh_key").write_bytes(b"file-ssh-key")
    row = _row(KEYRING, credentials.SSH_PRIVATE_KEY, pem)

    with pytest.raises(KeyUnwrapError):
        credentials.resolve_worker_settings(
            _Session([row]), _settings(tmp_path, Keyring(2, {2: bytes(reversed(range(32)))}))
        )


def test_valid_ssh_keys_report_their_type_and_public_fingerprint():
    _, pem, fingerprint = _ssh_key()
    metadata = credentials.validate_credential(credentials.SSH_PRIVATE_KEY, pem)

    assert metadata.key_type == "Ed25519"
    assert metadata.fingerprint_sha256 == fingerprint

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    rsa_pem = rsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    assert credentials.validate_credential(credentials.SSH_PRIVATE_KEY, rsa_pem).key_type == "RSA 3072"


@pytest.mark.parametrize(
    ("value", "message", "canary"),
    [
        (b"", "must not be empty", b""),
        (b"x" * 20_000, "at most 16384 bytes", b"xxxxxxxx"),
        (b"not a key at all\n", "not a private key", b"not a key at all"),
    ],
    ids=["empty", "too-large", "garbage"],
)
def test_invalid_ssh_keys_are_refused_with_a_safe_message(value, message, canary):
    with pytest.raises(credentials.CredentialError) as excinfo:
        credentials.validate_credential(credentials.SSH_PRIVATE_KEY, value)

    assert message in str(excinfo.value)
    assert excinfo.value.name == credentials.SSH_PRIVATE_KEY
    if canary:
        assert canary.decode() not in str(excinfo.value)


def test_a_public_key_is_refused_and_named_as_such():
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    line = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)

    for value in (pem, line):
        with pytest.raises(credentials.CredentialError, match="public key"):
            credentials.validate_credential(credentials.SSH_PRIVATE_KEY, value)


def test_a_passphrase_protected_key_is_refused_instead_of_stored_without_its_passphrase():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"fixture-passphrase"),
    )

    with pytest.raises(credentials.CredentialError, match="passphrase") as excinfo:
        credentials.validate_credential(credentials.SSH_PRIVATE_KEY, pem)

    assert "fixture-passphrase" not in str(excinfo.value)


@pytest.mark.parametrize("name", [credentials.VAULT_PASSWORD, credentials.INVENTORY_GIT_TOKEN])
@pytest.mark.parametrize(
    ("value", "message"),
    [
        (b"", "must not be empty"),
        (b"line-one\nline-two", "line breaks"),
        (b"carriage\rreturn", "line breaks"),
        (b"bell\x07", "control characters"),
        (b"x" * 513, "at most 512 bytes"),
    ],
    ids=["empty", "newline", "carriage-return", "control", "too-long"],
)
def test_password_shaped_credentials_have_a_small_safe_alphabet(name, value, message):
    with pytest.raises(credentials.CredentialError, match=message) as excinfo:
        credentials.validate_credential(name, value)
    assert excinfo.value.name == name


@pytest.mark.parametrize("name", [credentials.VAULT_PASSWORD, credentials.INVENTORY_GIT_TOKEN])
def test_password_shaped_credentials_accept_text_and_bytes(name):
    assert credentials.validate_credential(name, "a passphrase with spaces").key_type is None
    assert credentials.validate_credential(name, b"opaque-bytes").fingerprint_sha256 is None


def test_an_unknown_name_is_a_programming_error_not_a_user_error(tmp_path):
    with pytest.raises(KeyError):
        credentials.credential_state(_Session(), _settings(tmp_path), "worker.smtp_password")
    with pytest.raises(KeyError):
        credentials.validate_credential("worker.smtp_password", b"x")
