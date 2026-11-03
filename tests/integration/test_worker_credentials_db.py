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
from app.jobs.worker import Worker, record_worker_start, worker_capabilities
from app.models import AuditLog, EncryptedSetting, JSONValue, WorkerHeartbeat
from app.models.enums import JobType
from app.services import worker_credentials as credentials
from app.services.audit import Actor, record
from app.services.certificates import rotate_master_key, stale_master_key_rows
from app.web.common import NO_SSH_KEY, ansible_unavailable_reason
from app.web.settings import inventory_status

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


def _heartbeat(db, worker_id: str, now: datetime) -> None:
    """A fresh heartbeat, so ``worker_capabilities`` accepts that worker's newest start row."""
    db.add(WorkerHeartbeat(worker_id=worker_id, started_at=now, last_seen_at=now))
    db.flush()


def _start_report(db) -> dict[str, JSONValue]:
    details = db.scalars(select(AuditLog.details).where(AuditLog.action == "worker.start")).one()
    assert isinstance(details, dict)
    return details


def test_removing_a_database_only_credential_hides_it_and_restores_the_banner(
    db, actor, credentials_settings, same_connection_factory
):
    """Start with database-only credentials, remove them without restarting the worker.

    The startup row says the worker *had* the three credentials (effective flags), but no mounted file
    supplied them, so after the removal every state is absent, the SSH banner is back and the next job
    resolves no key at all.
    """
    now = datetime.now(UTC)
    worker_id = "worker-db-only"
    _heartbeat(db, worker_id, now)
    pem, fingerprint = ssh_key()
    credentials.set_credential(db, credentials_settings, SSH, pem, actor)
    credentials.set_credential(db, credentials_settings, VAULT, b"vault-value", actor)
    credentials.set_credential(db, credentials_settings, TOKEN, b"token-value", actor)
    record_worker_start(same_connection_factory, credentials_settings, worker_id, now)

    startup = _start_report(db)
    assert startup["ssh_key_present"] is True  # effective: the database held it at startup
    assert startup["ssh_key_file_present"] is False  # but no mounted file did
    assert startup["vault_password_file_present"] is False
    assert startup["inventory_token_file_present"] is False
    assert ansible_unavailable_reason(db, now) == ""
    stored = credentials.credential_state(db, credentials_settings, SSH, worker=worker_capabilities(db, now))
    assert (stored.configured, stored.source, stored.fingerprint_sha256) == (True, "database", fingerprint)

    for name in (SSH, VAULT, TOKEN):
        credentials.remove_credential(db, credentials_settings, name, actor)

    worker = worker_capabilities(db, now)
    states = credentials.credential_states(db, credentials_settings, worker=worker)
    assert [(state.configured, state.source, state.key_type, state.fingerprint_sha256) for state in states.values()] == [
        (False, None, None, None)
    ] * 3
    assert ansible_unavailable_reason(db, now) == NO_SSH_KEY
    assert inventory_status(db, now)["worker"]["ssh_key_present"] is False
    assert credentials.resolve_worker_settings(db, credentials_settings).ansible_ssh_key is None
    # The startup report is append-only evidence: the removal is its own credential.removed event,
    # never an edit of the row that recorded the startup.
    assert _start_report(db) == startup
    removed = db.scalars(select(AuditLog).where(AuditLog.action == "credential.removed")).all()
    assert {event.details["name"] for event in removed} == {SSH, VAULT, TOKEN}


def test_removing_a_database_credential_keeps_the_mounted_fallback_configured(
    db, actor, credentials_settings, same_connection_factory
):
    """The file level still answers after the row is gone: configured, source=file, no banner."""
    now = datetime.now(UTC)
    worker_id = "worker-with-files"
    pem, _ = ssh_key()
    mounted_key = (pem + b"\n").rstrip(b"\r\n")
    (credentials_settings.secrets_dir / "ansible_ssh_key").write_bytes(pem + b"\n")
    (credentials_settings.secrets_dir / "ansible_vault_password").write_bytes(b"file-vault-password\n")
    _heartbeat(db, worker_id, now)
    credentials.set_credential(db, credentials_settings, SSH, pem, actor)
    credentials.set_credential(db, credentials_settings, VAULT, b"database-vault-password", actor)
    record_worker_start(same_connection_factory, credentials_settings, worker_id, now)

    startup = _start_report(db)
    assert (startup["ssh_key_present"], startup["ssh_key_file_present"]) == (True, True)
    assert (startup["vault_password_present"], startup["vault_password_file_present"]) == (True, True)
    assert (startup["inventory_token_present"], startup["inventory_token_file_present"]) == (False, False)

    ssh_state = credentials.remove_credential(db, credentials_settings, SSH, actor)
    vault_state = credentials.remove_credential(db, credentials_settings, VAULT, actor)

    assert (ssh_state.configured, ssh_state.source) == (True, "file")
    assert (vault_state.configured, vault_state.source) == (True, "file")
    assert ansible_unavailable_reason(db, now) == ""
    assert inventory_status(db, now)["worker"]["ssh_key_present"] is True
    resolved = credentials.resolve_worker_settings(db, credentials_settings)
    assert resolved.ansible_ssh_key == mounted_key
    assert resolved.ansible_vault_password == b"file-vault-password"


def test_a_worker_started_before_the_save_reports_the_saved_credential_and_its_removal(
    db, actor, credentials_settings, same_connection_factory
):
    """No restart between the three steps: absent, then database, then absent again."""
    now = datetime.now(UTC)
    worker_id = "worker-before-save"
    _heartbeat(db, worker_id, now)
    record_worker_start(same_connection_factory, credentials_settings, worker_id, now)

    startup = _start_report(db)
    assert (startup["ssh_key_present"], startup["ssh_key_file_present"]) == (False, False)
    assert ansible_unavailable_reason(db, now) == NO_SSH_KEY

    pem, _ = ssh_key()
    credentials.set_credential(db, credentials_settings, SSH, pem, actor)
    state = credentials.credential_state(db, credentials_settings, SSH, worker=worker_capabilities(db, now))
    assert (state.configured, state.source) == (True, "database")
    assert ansible_unavailable_reason(db, now) == ""
    assert _start_report(db) == startup  # the save did not rewrite the startup row

    credentials.remove_credential(db, credentials_settings, SSH, actor)
    state = credentials.credential_state(db, credentials_settings, SSH, worker=worker_capabilities(db, now))
    assert (state.configured, state.source) == (False, None)
    assert ansible_unavailable_reason(db, now) == NO_SSH_KEY


def test_a_legacy_start_report_is_not_read_as_a_mounted_file(db, actor, credentials_settings):
    """A row written before this fix has no provenance: unknown, never "mounted".

    The effective flags stay intact for readers that only ask whether the worker can run jobs, but no
    consumer may turn them into a file claim. The documented consequence is a degraded window until
    the worker restarts and writes a report with provenance; job resolution is untouched, so mounted
    files still work and nothing is lost.
    """
    now = datetime.now(UTC)
    worker_id = "worker-legacy"
    _heartbeat(db, worker_id, now)
    record(
        db,
        Actor(None, f"worker:{worker_id}"),
        "worker.start",
        "worker",
        worker_id,
        {
            "worker_id": worker_id,
            "ssh_key_present": True,
            "known_hosts_present": True,
            "vault_password_present": True,
            "inventory_token_present": True,
        },
    )
    db.flush()

    capabilities = worker_capabilities(db, now)
    assert capabilities is not None
    assert capabilities.ssh_key_present is True  # compatibility field, unchanged meaning
    assert capabilities.ssh_key_file_present is None
    assert capabilities.vault_password_file_present is None
    assert capabilities.inventory_token_file_present is None

    states = credentials.credential_states(db, credentials_settings, worker=capabilities)
    assert [(state.configured, state.source) for state in states.values()] == [(False, None)] * 3
    assert ansible_unavailable_reason(db, now) == NO_SSH_KEY

    # A mounted-only installation keeps working: the file is still resolved for the next job, and a
    # value saved in the database is reported from the live row even while the worker is old.
    pem, _ = ssh_key()
    (credentials_settings.secrets_dir / "ansible_ssh_key").write_bytes(pem + b"\n")
    assert credentials.resolve_worker_settings(db, credentials_settings).ansible_ssh_key == (
        pem + b"\n"
    ).rstrip(b"\r\n")
    credentials.set_credential(db, credentials_settings, VAULT, b"database-vault-password", actor)
    state = credentials.credential_state(db, credentials_settings, VAULT, worker=capabilities)
    assert (state.configured, state.source) == (True, "database")


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
            "ssh_key_file_present": False,
            "vault_password_file_present": False,
            "inventory_token_file_present": False,
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
    assert startup.details["ssh_key_file_present"] is False  # the database held it, not a file


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
