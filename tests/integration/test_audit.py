import json
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.db import transaction
from app.models import AuditLog, User


def test_audit_is_append_only(db, actor):
    from app.services.audit import record

    row = record(db, actor, "certificate.update", "certificate", "42", {"notes": "renew"})
    db.flush()
    for sql in ["UPDATE audit_log SET action='bad'", "DELETE FROM audit_log", "TRUNCATE audit_log"]:
        with pytest.raises(DBAPIError) as exc, db.begin_nested():
            db.execute(text(sql))
        assert exc.value.orig.sqlstate == "42501"
    assert db.get(AuditLog, row.id).action == "certificate.update"
    assert row.details == {"notes": "renew"}


def test_actor_snapshot_and_system_actor(db, actor):
    from app.services.audit import Actor, record

    row = record(db, actor, "user.update", "user", str(actor.user_id), {})
    system = record(db, Actor(None, "worker:fixture"), "job.finished", "job", None, {"count": 2})
    db.flush()
    db.get(User, actor.user_id).username = "fixture-renamed"
    db.flush()
    db.expire(row)
    assert row.actor_label == "fixture-admin" and row.actor_user_id == actor.user_id
    assert str(row.ip) == "192.0.2.10" and row.user_agent == "fixture-browser"
    assert row.id is not None and row.created_at.tzinfo is not None
    assert system.actor_user_id is None and system.actor_label == "worker:fixture"
    assert system.ip is None and system.user_agent is None and system.target_id is None
    with pytest.raises(AttributeError):
        actor.label = "mutated"


def test_redaction_is_a_defensive_snapshot_before_persistence(db, actor):
    from app.services.audit import record

    details = {
        "password": "fixture-password",
        "nested": [{"totp_secret": "fixture-seed", "key_id": 42}],
        "notes": "-----BEGIN CERTIFICATE-----\nfixture-public\n-----END CERTIFICATE-----",
        "sha256_fingerprint": "f" * 64,
    }
    row = record(db, actor, "certificate.import", "certificate", "42", details)
    details["nested"][0]["key_id"] = 99
    db.flush()
    db.expire(row)
    assert row.details == {
        "password": "[REDACTED]",
        "nested": [{"totp_secret": "[REDACTED]", "key_id": 42}],
        "notes": "[REDACTED]",
        "sha256_fingerprint": "f" * 64,
    }
    assert "fixture-password" not in json.dumps(row.details) and "fixture-seed" not in json.dumps(row.details)


def test_untrusted_actor_metadata_is_scrubbed(db):
    from app.services.audit import Actor, record

    row = record(
        db,
        Actor(None, "password=fixture-label", user_agent="token=fixture-agent"),
        "certificate.import",
        "certificate",
        None,
        {},
    )
    db.flush()
    assert "fixture-label" not in row.actor_label and "fixture-agent" not in row.user_agent


def test_caller_commit_persists_audit_and_mutation_together(engine):
    from app.services.audit import Actor, record

    name = "fixture-" + uuid.uuid4().hex
    with engine.connect() as connection:
        outer = connection.begin()
        factory = sessionmaker(
            bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False
        )
        try:
            with transaction(factory) as db:
                user = User(username=name, email="fixture@example.test")
                db.add(user)
                db.flush()
                row = record(db, Actor(user.id, name), "user.create", "user", str(user.id), {})
            assert connection.scalar(select(User.id).where(User.username == name)) == user.id
            assert connection.scalar(select(AuditLog.id).where(AuditLog.actor_user_id == user.id)) == row.id
        finally:
            outer.rollback()


def test_record_never_commits_or_rolls_back_callers_transaction(engine):
    from app.services.audit import Actor, record

    name = "fixture-" + uuid.uuid4().hex
    audit_id = None
    try:
        with transaction(sessionmaker(engine)) as db:
            user = User(username=name, email="fixture@example.test")
            db.add(user)
            db.flush()
            row = record(db, Actor(user.id, name), "user.create", "user", str(user.id), {})
            db.flush()
            audit_id = row.id
            with engine.connect() as observer:
                assert observer.scalar(select(User.id).where(User.username == name)) is None
                assert observer.scalar(select(AuditLog.id).where(AuditLog.id == audit_id)) is None
            raise RuntimeError("fixture rollback")
    except RuntimeError as exc:
        assert str(exc) == "fixture rollback"
    with engine.connect() as observer:
        assert observer.scalar(select(User.id).where(User.username == name)) is None
        assert observer.scalar(select(AuditLog.id).where(AuditLog.id == audit_id)) is None
