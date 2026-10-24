import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Barrier

import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.crypto.chain import order_chain
from app.crypto.keyring import Keyring
from app.crypto.parse import parse_certificates
from app.db import transaction
from app.models import AuditLog, Certificate
from app.models.enums import CertificateStatus, ChainStatus
from app.services.audit import Actor
from app.services.certificates import (
    CertificateMetadata,
    ImportResult,
    InventoryError,
    attach_chain,
    save_certificate,
    set_lineage,
    set_status,
    store_key,
    update_certificate,
)
from app.services.trust_anchors import add_anchor


@pytest.fixture
def keyring():
    return Keyring(1, {1: bytes(range(32))})


def _parse(cert):
    return parse_certificates(cert.public_bytes(serialization.Encoding.PEM))[0]


def _save(db, actor, cert, chain_certs=(), **kwargs):
    leaf = _parse(cert)
    chain = order_chain(leaf.cert, chain_certs)
    kwargs.setdefault("source", "upload_pem")
    return save_certificate(db, leaf, chain, CertificateMetadata(), actor, **kwargs)


def _audits(db, action, target_id=None):
    # Audit ids are random UUIDs and created_at is the transaction start, so
    # callers must not depend on row order.
    stmt = select(AuditLog).where(AuditLog.action == action)
    if target_id is not None:
        stmt = stmt.where(AuditLog.target_id == str(target_id))
    return db.scalars(stmt).all()


def _count(db, model=Certificate):
    return db.scalar(select(func.count()).select_from(model))


def test_import_deduplicates(db, certs, actor):
    leaf = parse_certificates(certs.leaf_pem)[0]
    chain = order_chain(certs.leaf, certs.intermediates)
    first = save_certificate(db, leaf, chain, CertificateMetadata(), actor, source="upload_pem")
    again = save_certificate(
        db, leaf, chain, CertificateMetadata(notes="overwrite?"), actor, source="upload_pem"
    )
    assert first.created and not again.created
    assert again.certificate.id == first.certificate.id
    assert again.certificate.notes is None


def test_import_persists_identity_chain_and_one_audit(db, certs, actor, now):
    result = _save(db, actor, certs.leaf, certs.intermediates, validation_time=now)
    cert = result.certificate
    assert isinstance(result, ImportResult) and result.created
    assert cert.sha256_fingerprint == _parse(certs.leaf).sha256_fingerprint
    assert cert.imported_from == "upload_pem" and cert.key_id is None
    assert cert.status == CertificateStatus.ACTIVE and cert.created_by == actor.user_id
    assert [p.sha256_fingerprint for p in parse_certificates(cert.chain_pem.encode())] == [
        certs.intermediate2_fp,
        certs.intermediate1_fp,
    ]
    audits = _audits(db, "certificate.import", cert.id)
    assert len(audits) == 1
    details = audits[0].details
    assert details["source"] == "upload_pem" and details["sha256_fingerprint"] == cert.sha256_fingerprint
    assert details["chain_status"] == cert.chain_status.value
    assert "BEGIN" not in json.dumps(details)


def test_result_and_metadata_are_frozen(db, certs, actor):
    result = _save(db, actor, certs.leaf, certs.intermediates)
    with pytest.raises(AttributeError):
        result.created = False
    with pytest.raises(AttributeError):
        CertificateMetadata().notes = "x"


def test_invalid_source_is_rejected_without_rows(db, certs, actor):
    with pytest.raises(InventoryError) as exc:
        _save(db, actor, certs.leaf, source="upload_zip")
    assert exc.value.code == "invalid_source"
    assert _count(db) == 0 and not _audits(db, "certificate.import")


def test_issuer_serial_collision_returns_existing_row(db, certs, actor):
    first = _save(db, actor, certs.leaf, certs.intermediates)
    colliding = replace(_parse(certs.leaf), sha256_fingerprint="f" * 64)
    chain = order_chain(colliding.cert, certs.intermediates)
    again = save_certificate(
        db, colliding, chain, CertificateMetadata(team="other"), actor, source="upload_pem"
    )
    assert not again.created and again.certificate.id == first.certificate.id
    assert "issuer_serial_collision" in again.warnings and "duplicate" in again.warnings
    assert again.certificate.team is None
    assert _count(db) == 1


def test_duplicate_is_audited_with_fingerprint_and_source_only(db, certs, actor):
    first = _save(db, actor, certs.leaf, certs.intermediates)
    again = _save(db, actor, certs.leaf, certs.intermediates, source="pull_endpoint")
    assert again.warnings[-1] == "duplicate"
    assert len(_audits(db, "certificate.import")) == 1
    duplicates = _audits(db, "certificate.import_duplicate", first.certificate.id)
    assert len(duplicates) == 1
    assert duplicates[0].details == {
        "sha256_fingerprint": first.certificate.sha256_fingerprint,
        "source": "pull_endpoint",
    }
    assert again.certificate.imported_from == "upload_pem"


@pytest.fixture
def isolated_factory(owner_engine, database_urls):
    name = "fixture_inventory_" + uuid.uuid4().hex
    owner_url = owner_engine.url.set(database=name)
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.exec_driver_sql(f'CREATE DATABASE "{name}"')
    cfg = Config("alembic.ini")
    cfg.attributes["database_url"] = owner_url
    command.upgrade(cfg, "head")
    app = create_engine(database_urls[1].set(database=name))
    yield sessionmaker(app, expire_on_commit=False)
    app.dispose()
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.exec_driver_sql(f'DROP DATABASE "{name}" WITH (FORCE)')


def _rendezvous(factory, prefix, parties=2):
    barrier = Barrier(parties)

    def capture(conn, cursor, statement, parameters, context, many):
        if statement.lstrip().startswith(prefix):
            barrier.wait(timeout=20)

    engine = factory.kw["bind"]
    event.listen(engine, "before_cursor_execute", capture)
    return lambda: event.remove(engine, "before_cursor_execute", capture)


def test_concurrent_identical_imports_converge(isolated_factory, certs):
    leaf = _parse(certs.leaf)
    chain = order_chain(leaf.cert, certs.intermediates)
    release = _rendezvous(isolated_factory, "INSERT INTO certificate", 2)

    def run(_):
        with transaction(isolated_factory) as db:
            return save_certificate(
                db, leaf, chain, CertificateMetadata(), Actor(None, "system"), source="upload_pem"
            )

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, range(2)))
    finally:
        release()
    assert sorted(r.created for r in results) == [False, True]
    assert len({r.certificate.id for r in results}) == 1
    with transaction(isolated_factory) as db:
        assert _count(db) == 1
        assert len(_audits(db, "certificate.import")) == 1
        assert len(_audits(db, "certificate.import_duplicate")) == 1


def test_mismatched_key_is_rejected_and_nothing_persists(db, certs, actor, keyring):
    key = store_key(db, keyring, certs.ecdsa_key, "generated", actor)
    with pytest.raises(InventoryError) as exc:
        _save(db, actor, certs.leaf, certs.intermediates, key_id=key.id)
    assert exc.value.code == "key_mismatch"
    assert _count(db) == 0 and not _audits(db, "certificate.import")


def test_unknown_key_id_is_not_found(db, certs, actor):
    with pytest.raises(InventoryError) as exc:
        _save(db, actor, certs.leaf, key_id=999_999)
    assert exc.value.code == "not_found"


def test_matching_key_is_stored_with_the_new_certificate(db, certs, actor, keyring):
    key = store_key(db, keyring, certs.leaf_key, "generated", actor)
    result = _save(db, actor, certs.leaf, certs.intermediates, key_id=key.id)
    assert result.created and result.certificate.key_id == key.id
    assert len(_audits(db, "certificate.key_attach")) == 0


def test_matching_key_attaches_to_public_only_duplicate_with_own_audit(db, certs, actor, keyring):
    first = _save(db, actor, certs.leaf, certs.intermediates)
    first.certificate.notes = "keep me"
    key = store_key(db, keyring, certs.leaf_key, "imported_pem", actor)
    again = save_certificate(
        db,
        _parse(certs.leaf),
        order_chain(certs.leaf, certs.intermediates),
        CertificateMetadata(notes="overwrite?", owner_name="mallory"),
        actor,
        source="upload_pem",
        key_id=key.id,
    )
    assert not again.created and again.certificate.key_id == key.id
    assert again.certificate.notes == "keep me" and again.certificate.owner_name is None
    attach = _audits(db, "certificate.key_attach", first.certificate.id)
    assert len(attach) == 1 and attach[0].details["key_id"] == key.id
    assert len(_audits(db, "certificate.import_duplicate")) == 1
    # A repeat with the same key is a plain duplicate: no second attach.
    _save(db, actor, certs.leaf, certs.intermediates, key_id=key.id)
    assert len(_audits(db, "certificate.key_attach")) == 1


def test_duplicate_with_other_key_attached_is_key_mismatch(db, certs, actor, keyring):
    key = store_key(db, keyring, certs.leaf_key, "generated", actor)
    other = store_key(db, keyring, certs.ecdsa_key, "generated", actor)
    _save(db, actor, certs.leaf, certs.intermediates, key_id=key.id)
    with pytest.raises(InventoryError) as exc:
        _save(db, actor, certs.leaf, certs.intermediates, key_id=other.id)
    assert exc.value.code == "key_mismatch"
    # A mismatching key is rejected before any duplicate audit.
    assert not _audits(db, "certificate.import_duplicate")


@pytest.mark.parametrize("source", ["renewal", "discovery"])
def test_keyless_renewal_and_discovery_hit_the_check_constraint(db, certs, actor, source):
    with pytest.raises(IntegrityError) as exc:
        _save(db, actor, certs.leaf, certs.intermediates, source=source)
    assert getattr(exc.value.orig, "sqlstate", None) == "23514"
    assert "required_key" in str(exc.value.orig)


@pytest.mark.parametrize("source", ["renewal", "discovery"])
def test_renewal_and_discovery_with_key_are_accepted(db, certs, actor, keyring, source):
    key = store_key(db, keyring, certs.leaf_key, "generated", actor)
    result = _save(db, actor, certs.leaf, certs.intermediates, source=source, key_id=key.id)
    assert result.created and result.certificate.imported_from == source


def test_lineage_self_link_and_two_node_cycle_are_rejected(db, certs, actor):
    a = _save(db, actor, certs.leaf).certificate
    b = _save(db, actor, certs.wildcard).certificate
    with pytest.raises(InventoryError) as exc:
        set_lineage(db, a.id, a.id, actor)
    assert exc.value.code == "lineage_cycle"
    set_lineage(db, b.id, a.id, actor)
    assert db.get(Certificate, b.id).renews_id == a.id
    with pytest.raises(InventoryError) as exc:
        set_lineage(db, a.id, b.id, actor)
    assert exc.value.code == "lineage_cycle"
    assert db.get(Certificate, a.id).renews_id is None
    assert len(_audits(db, "certificate.lineage")) == 1


def test_lineage_longer_cycle_and_audit_details(db, certs, actor):
    a = _save(db, actor, certs.leaf).certificate
    b = _save(db, actor, certs.wildcard).certificate
    c = _save(db, actor, certs.ip_leaf).certificate
    set_lineage(db, b.id, a.id, actor)
    set_lineage(db, c.id, b.id, actor)
    with pytest.raises(InventoryError) as exc:
        set_lineage(db, a.id, c.id, actor)
    assert exc.value.code == "lineage_cycle"
    audit = _audits(db, "certificate.lineage", c.id)
    assert len(audit) == 1 and audit[0].details == {"previous_id": b.id}


def test_lineage_unknown_ids_are_not_found(db, certs, actor):
    a = _save(db, actor, certs.leaf).certificate
    for args in ((a.id, 999_999), (999_999, a.id)):
        with pytest.raises(InventoryError) as exc:
            set_lineage(db, *args, actor)
        assert exc.value.code == "not_found"


def test_save_with_renews_id_links_and_unknown_renews_id_is_not_found(db, certs, actor, keyring):
    old = _save(db, actor, certs.leaf).certificate
    key = store_key(db, keyring, certs.ecdsa_key, "generated", actor)
    new = _save(db, actor, certs.ecdsa_leaf, source="renewal", key_id=key.id, renews_id=old.id)
    assert new.certificate.renews_id == old.id
    with pytest.raises(InventoryError) as exc:
        _save(db, actor, certs.wildcard, renews_id=999_999)
    assert exc.value.code == "not_found"


def test_concurrent_reverse_lineage_edges_cannot_both_succeed(isolated_factory, certs):
    actor = Actor(None, "system")
    with transaction(isolated_factory) as db:
        a = _save(db, actor, certs.leaf).certificate.id
        b = _save(db, actor, certs.wildcard).certificate.id
    release = _rendezvous(isolated_factory, "SELECT pg_advisory_xact_lock", 2)

    def link(edge):
        child, parent = edge
        try:
            with transaction(isolated_factory) as db:
                set_lineage(db, child, parent, actor)
        except InventoryError as exc:
            return exc.code
        return "ok"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(link, [(a, b), (b, a)]))
    finally:
        release()
    assert sorted(outcomes) == ["lineage_cycle", "ok"]
    with transaction(isolated_factory) as db:
        rows = db.scalars(select(Certificate).where(Certificate.id.in_([a, b]))).all()
        assert sum(r.renews_id is not None for r in rows) == 1
        assert len(_audits(db, "certificate.lineage")) == 1


def test_metadata_is_normalised_and_validated():
    meta = CertificateMetadata(owner_name="  Ada ", owner_email=" ada@example.test ", team="  ", notes="")
    assert (meta.owner_name, meta.owner_email, meta.team, meta.notes) == (
        "Ada",
        "ada@example.test",
        None,
        None,
    )
    for kwargs in (
        {"owner_name": "x" * 201},
        {"team": "x" * 201},
        {"owner_email": "x" * 243 + "@example.test"},
        {"owner_email": "not-an-address"},
        {"owner_email": "@example.test"},
        {"notes": "x" * 10_001},
    ):
        with pytest.raises(InventoryError) as exc:
            CertificateMetadata(**kwargs)
        assert exc.value.code == "invalid_metadata"
    assert CertificateMetadata(owner_name="x" * 200, notes="x" * 10_000)


def test_update_certificate_audits_changed_fields_once(db, certs, actor):
    row = _save(db, actor, certs.leaf).certificate
    updated = update_certificate(
        db, row.id, CertificateMetadata(owner_name="Ada", team="infra", notes="n"), actor
    )
    assert (updated.owner_name, updated.team, updated.notes) == ("Ada", "infra", "n")
    audits = _audits(db, "certificate.update", row.id)
    assert len(audits) == 1
    assert audits[0].details == {
        "before": {"owner_name": None, "team": None, "notes": None},
        "after": {"owner_name": "Ada", "team": "infra", "notes": "n"},
    }
    update_certificate(db, row.id, CertificateMetadata(owner_name="Ada", team="infra", notes="n"), actor)
    assert len(_audits(db, "certificate.update", row.id)) == 1
    update_certificate(db, row.id, CertificateMetadata(owner_name="Ada", team="infra"), actor)
    details = [a.details for a in _audits(db, "certificate.update", row.id)]
    assert len(details) == 2
    assert {"before": {"notes": "n"}, "after": {"notes": None}} in details


def test_update_unknown_certificate_is_not_found(db, actor):
    with pytest.raises(InventoryError) as exc:
        update_certificate(db, 999_999, CertificateMetadata(), actor)
    assert exc.value.code == "not_found"


def test_status_transitions_are_audited_with_reason(db, certs, actor):
    row = _save(db, actor, certs.leaf).certificate
    set_status(db, row.id, CertificateStatus.SUPERSEDED, "replaced by renewal", actor)
    assert db.get(Certificate, row.id).status == CertificateStatus.SUPERSEDED
    set_status(db, row.id, CertificateStatus.REVOKED, "key compromised", actor)
    audits = _audits(db, "certificate.status_change", row.id)
    assert sorted((a.details for a in audits), key=lambda d: d["to"]) == [
        {"from": "superseded", "to": "revoked", "reason": "key compromised"},
        {"from": "active", "to": "superseded", "reason": "replaced by renewal"},
    ]


@pytest.mark.parametrize(
    ("start", "target"),
    [
        (CertificateStatus.ACTIVE, CertificateStatus.ACTIVE),
        (CertificateStatus.SUPERSEDED, CertificateStatus.ACTIVE),
        (CertificateStatus.SUPERSEDED, CertificateStatus.SUPERSEDED),
        (CertificateStatus.REVOKED, CertificateStatus.ACTIVE),
        (CertificateStatus.REVOKED, CertificateStatus.SUPERSEDED),
        (CertificateStatus.REVOKED, CertificateStatus.REVOKED),
    ],
)
def test_illegal_status_transitions_leave_no_audit(db, certs, actor, start, target):
    row = _save(db, actor, certs.leaf).certificate
    if start != CertificateStatus.ACTIVE:
        set_status(db, row.id, start, "setup", actor)
    before = len(_audits(db, "certificate.status_change"))
    with pytest.raises(InventoryError) as exc:
        set_status(db, row.id, target, "why", actor)
    assert exc.value.code == "invalid_status"
    assert db.get(Certificate, row.id).status == start
    assert len(_audits(db, "certificate.status_change")) == before


def test_unknown_status_value_is_invalid_status(db, certs, actor):
    row = _save(db, actor, certs.leaf).certificate
    with pytest.raises(InventoryError) as exc:
        set_status(db, row.id, "deleted", "why", actor)
    assert exc.value.code == "invalid_status"


@pytest.mark.parametrize("reason", ["", "   ", "x" * 1001])
def test_status_change_requires_bounded_reason(db, certs, actor, reason):
    row = _save(db, actor, certs.leaf).certificate
    with pytest.raises(InventoryError) as exc:
        set_status(db, row.id, CertificateStatus.REVOKED, reason, actor)
    assert exc.value.code == "reason_required"
    assert db.get(Certificate, row.id).status == CertificateStatus.ACTIVE
    assert not _audits(db, "certificate.status_change")
    set_status(db, row.id, CertificateStatus.REVOKED, "x" * 1000, actor)


def test_set_status_unknown_certificate_is_not_found(db, actor):
    with pytest.raises(InventoryError) as exc:
        set_status(db, 999_999, CertificateStatus.REVOKED, "why", actor)
    assert exc.value.code == "not_found"


def test_incomplete_chain_keeps_missing_issuer_and_persists_incomplete(db, certs, actor, now):
    result = _save(db, actor, certs.leaf, (), validation_time=now)
    assert result.certificate.chain_status == ChainStatus.INCOMPLETE
    issuer = certs.intermediate2.subject.rfc4514_string()
    assert f"missing_issuer:{issuer}" in result.warnings
    audit = _audits(db, "certificate.import")[0]
    assert audit.details["chain_status"] == "incomplete"
    assert f"missing_issuer:{issuer}" in audit.details["warnings"]
    assert result.certificate.chain_pem == ""


def test_expired_leaf_imports_with_expired_warning(db, certs, actor, now):
    result = _save(db, actor, certs.expired, certs.intermediates, validation_time=now)
    assert result.created and "expired" in result.warnings
    assert result.certificate.not_after < now


def test_valid_leaf_has_no_expired_warning_and_default_time_is_now(db, certs, actor):
    # Fixture certificates are valid around 2026-10-19; only assert the non-expired path.
    result = _save(
        db,
        actor,
        certs.leaf,
        certs.intermediates,
        validation_time=certs.leaf.not_valid_before_utc + timedelta(hours=1),
    )
    assert "expired" not in result.warnings


def test_trusted_chain_is_persisted_and_untrusted_root_is_a_warning(db, certs, actor, now):
    untrusted = _save(db, actor, certs.leaf, (*certs.intermediates, certs.root), validation_time=now)
    assert untrusted.certificate.chain_status == ChainStatus.UNTRUSTED_ROOT
    assert "untrusted_root" in untrusted.warnings
    assert "chain:root" in untrusted.warnings
    add_anchor(db, certs.root.public_bytes(serialization.Encoding.PEM), None, actor, now)
    trusted = _save(db, actor, certs.wildcard, (*certs.intermediates, certs.root), validation_time=now)
    assert trusted.certificate.chain_status == ChainStatus.TRUSTED
    assert not any(w.startswith(("untrusted", "missing")) for w in trusted.warnings)


def test_attach_chain_stores_normalised_chain_status_and_one_audit(db, certs, actor, now):
    row = _save(db, actor, certs.leaf, (), validation_time=now).certificate
    assert row.chain_status == ChainStatus.INCOMPLETE
    add_anchor(db, certs.root.public_bytes(serialization.Encoding.PEM), None, actor, now)
    data = certs.chain_pem + certs.root.public_bytes(serialization.Encoding.PEM) + certs.leaf_pem
    updated = attach_chain(db, row.id, data, actor, validation_time=now)
    assert updated.chain_status == ChainStatus.TRUSTED
    stored = [p.sha256_fingerprint for p in parse_certificates(updated.chain_pem.encode())]
    assert stored == [certs.intermediate2_fp, certs.intermediate1_fp]
    audits = _audits(db, "certificate.chain_upload", row.id)
    assert len(audits) == 1
    assert audits[0].details["chain_fingerprints"] == stored
    assert audits[0].details["chain_status"] == "trusted"
    assert "BEGIN" not in json.dumps(audits[0].details)


def test_attach_chain_accepts_der(db, certs, actor, now):
    row = _save(db, actor, certs.leaf, (), validation_time=now).certificate
    der = certs.intermediate2.public_bytes(serialization.Encoding.DER)
    updated = attach_chain(db, row.id, der, actor, validation_time=now)
    assert [p.sha256_fingerprint for p in parse_certificates(updated.chain_pem.encode())] == [
        certs.intermediate2_fp
    ]


@pytest.mark.parametrize(
    "data",
    [b"not a certificate", b"", b"x" * 1_048_577],
    ids=["garbage", "empty", "oversize"],
)
def test_attach_chain_rejects_invalid_input_without_audit(db, certs, actor, data):
    row = _save(db, actor, certs.leaf, certs.intermediates).certificate
    before = row.chain_pem
    with pytest.raises(InventoryError) as exc:
        attach_chain(db, row.id, data, actor)
    assert exc.value.code == "invalid_chain"
    assert db.get(Certificate, row.id).chain_pem == before
    assert not _audits(db, "certificate.chain_upload")


def test_attach_chain_unknown_certificate_is_not_found(db, certs, actor):
    with pytest.raises(InventoryError) as exc:
        attach_chain(db, 999_999, certs.chain_pem, actor)
    assert exc.value.code == "not_found"


def test_no_pem_or_key_material_in_any_inventory_audit(db, certs, actor, keyring):
    key = store_key(db, keyring, certs.leaf_key, "generated", actor)
    row = _save(db, actor, certs.leaf, certs.intermediates, key_id=key.id).certificate
    _save(db, actor, certs.leaf, certs.intermediates)
    update_certificate(db, row.id, CertificateMetadata(notes="n"), actor)
    attach_chain(db, row.id, certs.chain_pem, actor)
    set_status(db, row.id, CertificateStatus.REVOKED, "r", actor)
    text = json.dumps(
        [a.details for a in db.scalars(select(AuditLog).where(AuditLog.action.like("certificate.%")))]
    )
    assert "BEGIN" not in text and "PRIVATE" not in text
