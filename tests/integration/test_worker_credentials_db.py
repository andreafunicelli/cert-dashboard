"""Worker credentials against PostgreSQL: upsert, audit, AAD binding, rotation, resolution and banner."""

import hashlib
import json
from dataclasses import asdict, replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.config import Settings
from app.crypto.keyring import Keyring, KeyUnwrapError
from app.jobs.handlers import build_registry
from app.jobs.worker import Worker, record_worker_start
from app.models import AuditLog, EncryptedSetting, WorkerHeartbeat
from app.models.enums import JobType
from app.services import worker_credentials as credentials
from app.services.audit import Actor, record
from app.services.certificates import rotate_master_key, stale_master_key_rows
from app.web.common import NO_SSH_KEY, ansible_unavailable_reason

SSH = credentials.SSH_PRIVATE_KEY
VAULT = credentials.VAULT_PASSWORD
TOKEN = credentials.INVENTORY_GIT_TOKEN


def ssh_key() -> tuple[bytes, str]:
    """An unencrypted Ed25519 private key in OpenSSH form, and its public fingerprint."""
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    )
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem, hashlib.sha256(der).hexdigest()


@pytest.fixture
def keyring() -> Keyring:
    return Keyring(1, {1: bytes(range(32))})


@pytest.fixture
def credentials_settings(tmp_path, keyring) -> Settings:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fixture-host ssh-ed25519 AAAA\n")
    return Settings(
        profile="worker",
        keyring=keyring,
        keyring_sha256="0" * 64,
        db_password=b"fixture-db-password",
        secrets_dir=tmp_path,
        known_hosts_file=known_hosts,
    )


@pytest.fixture
def same_connection_factory(db):
    """A sessionmaker on the test's own connection, for functions that open their own session."""
    return sessionmaker(db.get_bind(), join_transaction_mode="create_savepoint", expire_on_commit=False)


def credential_audits(db):
    return db.scalars(select(AuditLog).where(AuditLog.target_type == "credential")).all()


def test_set_replace_remove_is_one_audited_change_per_action(db, actor, credentials_settings):
    pem, fingerprint = ssh_key()
    state = credentials.set_credential(db, credentials_settings, SSH, pem, actor)

    assert state.configured is True and state.source == "database"
    assert state.key_type == "Ed25519" and state.fingerprint_sha256 == fingerprint
    assert state.updated_by == actor.label and state.updated_at is not None
    row = db.get(EncryptedSetting, SSH)
    assert row is not None and row.ciphertext != pem and len(row.nonce) == 12
    assert row.keyring_version == 1 and row.updated_by == actor.user_id

    replacement, replacement_fingerprint = ssh_key()
    state = credentials.set_credential(db, credentials_settings, SSH, replacement, actor)
    assert state.fingerprint_sha256 == replacement_fingerprint
    assert db.scalar(select(func.count()).select_from(EncryptedSetting)) == 1

    events = {event.action: event for event in credential_audits(db)}
    assert set(events) == {"credential.set", "credential.replaced"}
    assert events["credential.set"].details == {
        "name": SSH,
        "action": "set",
        "key_type": "Ed25519",
        "fingerprint_sha256": fingerprint,
    }
    assert events["credential.replaced"].details["action"] == "replaced"
    assert events["credential.set"].actor_user_id == actor.user_id
    assert events["credential.set"].actor_label == actor.label

    state = credentials.remove_credential(db, credentials_settings, SSH, actor)
    assert state.configured is False and state.source is None
    assert db.get(EncryptedSetting, SSH) is None
    removed = db.scalars(select(AuditLog).where(AuditLog.action == "credential.removed")).one()
    # Removing the key says which key it was, and never what it was: the public fingerprint only.
    assert removed.details == {
        "name": SSH,
        "action": "removed",
        "key_type": "Ed25519",
        "fingerprint_sha256": replacement_fingerprint,
    }
    payload = json.dumps(removed.details, default=str)
    assert "PRIVATE KEY" not in payload
    assert replacement.decode().splitlines()[1] not in payload


def test_an_undecryptable_row_can_still_be_removed_without_a_fingerprint(db, actor, credentials_settings):
    """Explicit removal is the recovery path for a broken row: it must not raise, and it says less."""
    pem, _ = ssh_key()
    credentials.set_credential(db, credentials_settings, SSH, pem, actor)
    row = db.get(EncryptedSetting, SSH)
    row.ciphertext = b"not a wrapped secret"
    db.flush()

    state = credentials.remove_credential(db, credentials_settings, SSH, actor)
    assert state.configured is False
    assert db.get(EncryptedSetting, SSH) is None
    removed = db.scalars(select(AuditLog).where(AuditLog.action == "credential.removed")).one()
    assert removed.details == {"name": SSH, "action": "removed"}


def test_removing_a_credential_that_is_not_stored_changes_nothing_and_writes_no_event(db, actor, credentials_settings):
    before = db.scalar(select(func.count()).select_from(AuditLog))
    state = credentials.remove_credential(db, credentials_settings, VAULT, actor)
    assert state.configured is False
    assert db.scalar(select(func.count()).select_from(AuditLog)) == before


def test_no_audit_row_or_credential_state_carries_the_value(db, actor, credentials_settings):
    vault = "vault-canary-3f9c2a"
    token = "ghp_canary5a1b2c3d4e5f6g7h8i9j0"
    credentials.set_credential(db, credentials_settings, VAULT, vault, actor)
    credentials.set_credential(db, credentials_settings, TOKEN, token, actor)

    states = credentials.credential_states(db, credentials_settings)
    exposed = json.dumps([event.details for event in credential_audits(db)], default=str)
    exposed += "".join(json.dumps(asdict(state), default=str) + repr(state) for state in states.values())
    assert vault not in exposed and token not in exposed
    for name, secret in ((VAULT, vault), (TOKEN, token)):
        row = db.get(EncryptedSetting, name)
        assert secret.encode() not in row.ciphertext
        assert row.ciphertext != secret.encode()


def test_an_invalid_key_is_refused_and_leaves_no_row_and_no_event(db, actor, credentials_settings):
    public_pem = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(credentials.CredentialError, match="public key") as excinfo:
        credentials.set_credential(db, credentials_settings, SSH, public_pem, actor)

    assert "-----BEGIN" not in str(excinfo.value)
    assert db.get(EncryptedSetting, SSH) is None
    assert credential_audits(db) == []


def test_a_ciphertext_cannot_be_moved_between_settings(db, actor, credentials_settings):
    pem, _ = ssh_key()
    credentials.set_credential(db, credentials_settings, SSH, pem, actor)
    credentials.set_credential(db, credentials_settings, VAULT, b"vault-value", actor)
    ssh_row, vault_row = db.get(EncryptedSetting, SSH), db.get(EncryptedSetting, VAULT)
    vault_row.ciphertext, vault_row.nonce = ssh_row.ciphertext, ssh_row.nonce
    vault_row.keyring_version = ssh_row.keyring_version
    db.flush()

    with pytest.raises(KeyUnwrapError):
        credentials.resolve_worker_settings(db, credentials_settings)
    # The screen still reports the row as configured, it just cannot vouch for its metadata.
    assert credentials.credential_state(db, credentials_settings, VAULT).configured is True


def test_resolution_prefers_the_database_row_over_the_mounted_file(db, actor, credentials_settings):
    (credentials_settings.secrets_dir / "ansible_vault_password").write_bytes(b"file-vault-password\n")
    assert credentials.resolve_worker_settings(db, credentials_settings).ansible_vault_password == (
        b"file-vault-password"
    )

    credentials.set_credential(db, credentials_settings, VAULT, b"database-vault-password", actor)

    resolved = credentials.resolve_worker_settings(db, credentials_settings)
    assert resolved.ansible_vault_password == b"database-vault-password"
    # Removing it falls back to the file, exactly as before the setting existed.
    credentials.remove_credential(db, credentials_settings, VAULT, actor)
    assert credentials.resolve_worker_settings(db, credentials_settings).ansible_vault_password == (
        b"file-vault-password"
    )


def test_rotation_rewraps_the_credentials_and_preserves_their_value(db, actor, credentials_settings):
    pem, fingerprint = ssh_key()
    credentials.set_credential(db, credentials_settings, SSH, pem, actor)
    credentials.set_credential(db, credentials_settings, VAULT, b"vault-value", actor)
    rotated = Keyring(2, {1: credentials_settings.keyring.keys[1], 2: bytes(reversed(range(32)))})
    newer = replace(credentials_settings, keyring=rotated)

    assert stale_master_key_rows(db, rotated) == 2
    assert rotate_master_key(db, rotated, actor) == 0
    rows = db.scalars(select(EncryptedSetting)).all()
    assert {row.keyring_version for row in rows} == {2}

    resolved = credentials.resolve_worker_settings(db, newer)
    assert resolved.ansible_ssh_key == pem and resolved.ansible_vault_password == b"vault-value"
    assert credentials.credential_state(db, newer, SSH).fingerprint_sha256 == fingerprint
    # The retired version alone can no longer read them.
    with pytest.raises(KeyUnwrapError):
        credentials.resolve_worker_settings(db, credentials_settings)
    rotation = db.scalars(select(AuditLog).where(AuditLog.action == "master_key.rotate")).one()
    assert rotation.details["credentials_rotated"] == 2


def test_the_banner_clears_when_the_key_is_stored_in_the_database(db, actor, credentials_settings):
    now = datetime.now(UTC)
    db.add(WorkerHeartbeat(worker_id="fixture-worker", started_at=now, last_seen_at=now))
    record(
        db,
        Actor(None, "worker:fixture-worker"),
        "worker.start",
        "worker",
        "fixture-worker",
        {
            "worker_id": "fixture-worker",
            "ssh_key_present": False,
            "known_hosts_present": True,
            "vault_password_present": False,
            "inventory_token_present": False,
        },
    )
    db.flush()

    assert ansible_unavailable_reason(db, now) == NO_SSH_KEY

    pem, _ = ssh_key()
    credentials.set_credential(db, credentials_settings, SSH, pem, actor)

    # No restart, no new worker.start row: the next page load sees the stored key.
    assert ansible_unavailable_reason(db, now) == ""


def test_the_worker_reports_and_claims_ssh_jobs_from_a_database_credential(
    db, actor, credentials_settings, same_connection_factory
):
    worker = Worker(credentials_settings, build_registry(), same_connection_factory)
    assert JobType.DISCOVER not in worker.eligible_types()

    pem, _ = ssh_key()
    credentials.set_credential(db, credentials_settings, SSH, pem, actor)

    assert JobType.DISCOVER in worker.eligible_types()
    record_worker_start(same_connection_factory, credentials_settings, "fixture-worker", datetime.now(UTC))
    startup = db.scalars(select(AuditLog).where(AuditLog.action == "worker.start")).one()
    assert startup.details["ssh_key_present"] is True


def test_resolved_credentials_are_still_resolved_per_job(db, actor, credentials_settings, same_connection_factory):
    """The bytes handed to the runner are the stored ones: staging writes exactly those."""
    from app.ansible.runner import stage_runner_secrets
    from app.ansible.staging import StagingArea

    pem, _ = ssh_key()
    credentials.set_credential(db, credentials_settings, SSH, pem, actor)
    settings = credentials.resolve_worker_settings(db, credentials_settings)

    job_id = uuid4()
    with StagingArea(credentials_settings.secrets_dir / "staging", job_id) as area:
        staged = stage_runner_secrets(settings, area)
        assert staged.ssh_key.read_bytes() == pem + (b"" if pem.endswith(b"\n") else b"\n")
        assert settings.ansible_ssh_key == pem
    assert not (credentials_settings.secrets_dir / "staging" / str(job_id)).exists()
