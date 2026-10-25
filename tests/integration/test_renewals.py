import base64
import hashlib
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, local

import pytest
from alembic import command
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

from app.crypto.csr import build_csr, validate_csr
from app.crypto.keys import KeySpec, generate_key
from app.crypto.parse import parse_certificates
from app.db import transaction
from app.models import (
    AuditLog,
    Binding,
    Certificate,
    Job,
    JobHost,
    PrivateKey,
    Renewal,
    Server,
)
from app.models.enums import (
    CertificateStatus,
    ChainStatus,
    JobHostStatus,
    JobStatus,
    JobType,
    RenewalState,
    WebserverType,
)
from app.services.audit import Actor
from app.services.certificates import unwrap_key
from app.services.renewals import (
    InvalidTransition,
    IssuedValidationError,
    RenewalBasics,
    RenewalError,
    RenewalValidationError,
    attach_issued,
    cancel,
    create_draft,
    edit_draft,
    finalize,
    generate_csr,
    issued_warnings,
    mark_deployed,
    mark_submitted,
)
from app.services.trust_anchors import add_anchor

NAMES = ("www.example.internal", "api.example.internal")
ECDSA = KeySpec(kind="ecdsa")


# --- helpers ----------------------------------------------------------------


def _count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def _audit_count(db):
    return _count(db, AuditLog)


def _renewal_audits(db, renewal_id, action=None):
    stmt = select(AuditLog).where(AuditLog.target_type == "renewal", AuditLog.target_id == str(renewal_id))
    if action is not None:
        stmt = stmt.where(AuditLog.action == action)
    return list(db.scalars(stmt))


def _basics(**overrides):
    values = {"common_name": NAMES[0], "sans": NAMES, "ca_name": "TestCA", "notes": None}
    values.update(overrides)
    return RenewalBasics(**values)


def _draft(db, actor, now, previous_id=None, **overrides):
    return create_draft(db, previous_id, _basics(**overrides), actor, now)


def _csr_generated(db, keyring, actor, now, previous_id=None, spec=ECDSA, **overrides):
    renewal = _draft(db, actor, now, previous_id, **overrides)
    return generate_csr(db, renewal.id, spec, keyring, actor, now)


def _submitted(db, keyring, actor, now, previous_id=None, **overrides):
    renewal = _csr_generated(db, keyring, actor, now, previous_id, **overrides)
    return mark_submitted(db, renewal.id, "ORDER-9", actor, now)


def _deploy_evidence(
    db,
    renewal,
    now,
    *,
    job_status=JobStatus.SUCCEEDED,
    job_type=JobType.DEPLOY,
    host_status=JobHostStatus.SUCCEEDED,
    with_binding=True,
    fingerprint=None,
    payload_certificate_id=None,
    with_host=True,
):
    certificate = db.get(Certificate, renewal.certificate_id)
    job = Job(
        type=job_type,
        status=job_status,
        priority=300,
        payload={
            "certificate_id": renewal.certificate_id
            if payload_certificate_id is None
            else payload_certificate_id
        },
        run_after=now,
    )
    server = Server(hostname=f"h-{uuid.uuid4().hex[:10]}.example.test", inventory_source="manual")
    db.add_all([job, server])
    db.flush()
    binding_id = None
    if with_binding:
        binding = Binding(
            server_id=server.id,
            webserver=WebserverType.NGINX,
            vhost_name="www",
            vhost_names=["www"],
            port=443,
            config_file="/etc/nginx/www.conf",
            cert_path="/etc/ssl/www.pem",
            key_path="/etc/ssl/www.key",
            certificate_id=certificate.id,
            match_state="match",
            last_seen_at=now,
        )
        db.add(binding)
        db.flush()
        binding_id = binding.id
    if with_host:
        db.add(
            JobHost(
                job_id=job.id,
                server_id=server.id,
                binding_id=binding_id,
                status=host_status,
                new_fingerprint=fingerprint or certificate.sha256_fingerprint,
            )
        )
    db.flush()
    return job


def _issued(db, ca, keyring, actor, now, previous_id=None, chain=True):
    renewal = _submitted(db, keyring, actor, now, previous_id)
    return attach_issued(db, renewal.id, ca.issue(renewal.csr_pem), ca.chain_pem if chain else None, actor, now)


def _deployed(db, ca, keyring, actor, now, previous_id=None):
    renewal = _issued(db, ca, keyring, actor, now, previous_id)
    job = _deploy_evidence(db, renewal, now)
    return mark_deployed(db, renewal.id, job.id, actor, now)


def _renewal_in_state(db, ca, keyring, actor, now, state, previous_id=None):
    if state == RenewalState.DRAFT:
        return _draft(db, actor, now, previous_id)
    if state == RenewalState.CANCELLED:
        renewal = _draft(db, actor, now, previous_id)
        return cancel(db, renewal.id, "abandoned", actor, now)
    if state == RenewalState.CSR_GENERATED:
        return _csr_generated(db, keyring, actor, now, previous_id)
    if state == RenewalState.SUBMITTED:
        return _submitted(db, keyring, actor, now, previous_id)
    if state == RenewalState.ISSUED:
        return _issued(db, ca, keyring, actor, now, previous_id)
    renewal = _deployed(db, ca, keyring, actor, now, previous_id)
    if state == RenewalState.DEPLOYED:
        return renewal
    return finalize(db, renewal.id, "superseded", "", actor, now)


def _assert_blocked(db, renewal, before_certificates, before_audits):
    db.refresh(renewal)
    assert renewal.state == RenewalState.SUBMITTED
    assert renewal.certificate_id is None and renewal.issued_chain_pem is None
    assert _count(db, Certificate) == before_certificates
    assert _audit_count(db) == before_audits


def _attach_expecting_errors(db, renewal, leaf, chain, actor, now):
    certificates, audits = _count(db, Certificate), _audit_count(db)
    with pytest.raises(IssuedValidationError) as exc:
        attach_issued(db, renewal.id, leaf, chain, actor, now)
    _assert_blocked(db, renewal, certificates, audits)
    return exc.value.errors


# --- plan test ---------------------------------------------------------------


def test_wrong_issued_key_is_atomic(db, submitted_renewal, ca, actor, now):
    rid = submitted_renewal.id
    before = db.scalar(select(func.count()).select_from(Certificate))
    other_leaf_pem = ca.issue(
        public_key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        common_name=submitted_renewal.common_name,
        sans=list(submitted_renewal.sans),
    )
    with pytest.raises(IssuedValidationError) as exc:
        attach_issued(db, rid, other_leaf_pem, ca.chain_pem, actor, now)
    assert "key_match" in exc.value.errors
    assert db.get(Renewal, rid).state == RenewalState.SUBMITTED
    assert db.scalar(select(func.count()).select_from(Certificate)) == before


# --- create / edit -----------------------------------------------------------


def test_create_draft_canonicalizes_and_audits_once(db, actor, now, previous_certificate):
    renewal = create_draft(
        db,
        previous_certificate.id,
        RenewalBasics(" WWW.Example.Internal ", ("API.example.internal", "api.example.internal"), "  Sectigo ", " n "),
        actor,
        now,
    )
    assert renewal.state == RenewalState.DRAFT
    assert renewal.common_name == "www.example.internal"
    # CN is included exactly once; duplicates collapse after canonicalization.
    assert sorted(renewal.sans) == ["api.example.internal", "www.example.internal"]
    assert renewal.ca_name == "Sectigo" and renewal.notes == "n"
    assert renewal.previous_certificate_id == previous_certificate.id
    assert renewal.key_id is None and renewal.csr_pem is None
    assert renewal.created_by == actor.user_id and renewal.state_changed_at == now
    audits = _renewal_audits(db, renewal.id)
    assert [a.action for a in audits] == ["renewal.create"]
    assert audits[0].details["previous_certificate_id"] == previous_certificate.id


def test_create_draft_without_previous(db, actor, now):
    renewal = _draft(db, actor, now)
    assert renewal.previous_certificate_id is None


@pytest.mark.parametrize("which", ["missing", "superseded", "revoked"])
def test_create_draft_requires_active_previous(db, actor, now, previous_certificate, which):
    before = _audit_count(db)
    previous_id = 10**9
    if which != "missing":
        previous_certificate.status = CertificateStatus(which)
        db.flush()
        previous_id = previous_certificate.id
        before = _audit_count(db)
    with pytest.raises(RenewalError) as exc:
        create_draft(db, previous_id, _basics(), actor, now)
    assert exc.value.code == "previous_not_active"
    assert _count(db, Renewal) == 0 and _audit_count(db) == before


@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"common_name": "not a name"}, "common_name"),
        ({"common_name": ""}, "common_name"),
        ({"common_name": "a" * 64 + ".example.test"}, "common_name"),
        ({"sans": ()}, "sans"),
        ({"sans": ("bad_name.example.test",)}, "sans"),
        ({"sans": tuple(f"h{i}.example.test" for i in range(101))}, "sans"),
        ({"ca_name": "x" * 201}, "ca_name"),
        ({"notes": "x" * 10_001}, "notes"),
    ],
)
def test_create_draft_reports_field_errors(db, actor, now, overrides, field):
    with pytest.raises(RenewalValidationError) as exc:
        _draft(db, actor, now, **overrides)
    assert field in exc.value.errors
    assert _count(db, Renewal) == 0 and _audit_count(db) == 0


def test_create_draft_limits_identities_after_cn_inclusion(db, actor, now):
    sans = tuple(f"h{i}.example.test" for i in range(100))
    with pytest.raises(RenewalValidationError) as exc:
        _draft(db, actor, now, sans=sans)
    assert "sans" in exc.value.errors


def test_edit_draft_changes_names_and_audits_once(db, actor, now):
    renewal = _draft(db, actor, now)
    edited = edit_draft(
        db, renewal.id, _basics(common_name="new.example.internal", sans=("new.example.internal",), notes="n"), actor, now
    )
    assert edited.common_name == "new.example.internal" and edited.sans == ["new.example.internal"]
    assert edited.state == RenewalState.DRAFT and edited.notes == "n"
    assert [a.action for a in _renewal_audits(db, renewal.id)] == ["renewal.create", "renewal.edit"]


def test_edit_draft_validates(db, actor, now):
    renewal = _draft(db, actor, now)
    audits = _audit_count(db)
    with pytest.raises(RenewalValidationError):
        edit_draft(db, renewal.id, _basics(common_name="bad name"), actor, now)
    assert _audit_count(db) == audits and renewal.common_name == NAMES[0]


# --- CSR generation ----------------------------------------------------------


def test_generate_csr_stores_key_csr_and_hash_atomically(db, actor, now, keyring):
    renewal = _draft(db, actor, now)
    keys_before = _count(db, PrivateKey)
    generated = generate_csr(db, renewal.id, ECDSA, keyring, actor, now + timedelta(minutes=1))
    assert generated.state == RenewalState.CSR_GENERATED
    assert generated.state_changed_at == now + timedelta(minutes=1)
    key = db.get(PrivateKey, generated.key_id)
    assert _count(db, PrivateKey) == keys_before + 1 and key.origin == "generated"
    csr = x509.load_pem_x509_csr(generated.csr_pem.encode())
    assert generated.csr_sha256 == hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest()
    assert generated.csr_sha256 == generated.csr_sha256.lower() and len(generated.csr_sha256) == 64
    assert validate_csr(generated.csr_pem, generated.common_name, generated.sans, key.public_key_sha256) == []
    assert unwrap_key(key, keyring).public_key().public_numbers() == csr.public_key().public_numbers()


def test_generate_csr_defaults_to_rsa_2048(db, actor, now, keyring):
    renewal = _draft(db, actor, now)
    generated = generate_csr(db, renewal.id, KeySpec(), keyring, actor, now)
    key = db.get(PrivateKey, generated.key_id)
    assert (key.key_type.value, key.key_size) == ("rsa", 2048)


def test_generate_csr_audit_has_metadata_only(db, actor, now, keyring):
    renewal = _draft(db, actor, now)
    generated = generate_csr(db, renewal.id, ECDSA, keyring, actor, now)
    (audit,) = _renewal_audits(db, renewal.id, "renewal.csr_generated")
    assert audit.details == {
        "csr_sha256": generated.csr_sha256,
        "key_type": "ecdsa",
        "key_size": 256,
        "curve": "prime256v1",
        "key_id": generated.key_id,
    }
    assert "BEGIN" not in json.dumps(audit.details)
    assert len(_renewal_audits(db, renewal.id)) == 2


def test_generate_csr_bad_spec_leaves_draft_untouched(db, actor, now, keyring):
    renewal = _draft(db, actor, now)
    audits, keys = _audit_count(db), _count(db, PrivateKey)
    with pytest.raises(RenewalValidationError) as exc:
        generate_csr(db, renewal.id, KeySpec(kind="rsa", size=1024), keyring, actor, now)
    assert "key" in exc.value.errors
    assert renewal.state == RenewalState.DRAFT and renewal.key_id is None
    assert _audit_count(db) == audits and _count(db, PrivateKey) == keys


def test_names_are_frozen_after_csr(db, actor, now, keyring):
    renewal = _csr_generated(db, keyring, actor, now)
    audits = _audit_count(db)
    with pytest.raises(InvalidTransition) as exc:
        edit_draft(db, renewal.id, _basics(common_name="other.example.internal"), actor, now)
    assert exc.value.from_state == RenewalState.CSR_GENERATED and exc.value.action == "edit_draft"
    assert renewal.common_name == NAMES[0] and _audit_count(db) == audits


# --- submit ------------------------------------------------------------------


def test_mark_submitted_strips_reference_and_audits(db, actor, now, keyring):
    renewal = _csr_generated(db, keyring, actor, now)
    submitted = mark_submitted(db, renewal.id, "  ORDER 42  ", actor, now + timedelta(hours=1))
    assert submitted.state == RenewalState.SUBMITTED and submitted.ca_order_reference == "ORDER 42"
    assert submitted.submitted_by == actor.user_id and submitted.state_changed_at == now + timedelta(hours=1)
    (audit,) = _renewal_audits(db, renewal.id, "renewal.submitted")
    assert audit.details == {"order_reference": "ORDER 42"}


@pytest.mark.parametrize("reference", ["", "   ", "x" * 201])
def test_mark_submitted_requires_reference(db, actor, now, keyring, reference):
    renewal = _csr_generated(db, keyring, actor, now)
    audits = _audit_count(db)
    with pytest.raises(RenewalValidationError) as exc:
        mark_submitted(db, renewal.id, reference, actor, now)
    assert "order_reference" in exc.value.errors
    assert renewal.state == RenewalState.CSR_GENERATED and _audit_count(db) == audits


def test_mark_submitted_accepts_200_characters(db, actor, now, keyring):
    renewal = _csr_generated(db, keyring, actor, now)
    assert len(mark_submitted(db, renewal.id, "x" * 200, actor, now).ca_order_reference) == 200


# --- attach_issued: success --------------------------------------------------


def test_attach_issued_creates_linked_certificate(db, submitted_renewal, previous_certificate, ca, actor, now):
    rid = submitted_renewal.id
    leaf_pem = ca.issue(submitted_renewal.csr_pem)
    later = now + timedelta(minutes=5)
    renewal = attach_issued(db, rid, leaf_pem, ca.chain_pem, actor, later)
    certificate = db.get(Certificate, renewal.certificate_id)
    assert renewal.state == RenewalState.ISSUED and renewal.issued_by == actor.user_id
    assert renewal.state_changed_at == later
    assert certificate.key_id == renewal.key_id and certificate.renews_id == previous_certificate.id
    assert certificate.imported_from == "renewal" and certificate.status == CertificateStatus.ACTIVE
    assert (certificate.owner_name, certificate.owner_email, certificate.team) == ("Ada", "ada@example.test", "web")
    assert certificate.notes is None
    assert renewal.issued_chain_pem == certificate.chain_pem == ca.chain_pem.decode()
    # One renewal audit per transition, plus the inventory import it caused.
    assert [a.action for a in _renewal_audits(db, rid, "renewal.issued")] == ["renewal.issued"]
    (imported,) = db.scalars(
        select(AuditLog).where(AuditLog.action == "certificate.import", AuditLog.target_id == str(certificate.id))
    )
    assert imported.details["source"] == "renewal"
    issued = _renewal_audits(db, rid, "renewal.issued")[0]
    assert issued.details["certificate_id"] == certificate.id
    assert issued.details["fingerprint"] == certificate.sha256_fingerprint
    assert issued.details["chain_status"] == certificate.chain_status.value
    assert isinstance(issued.details["warnings"], list)
    assert "BEGIN" not in json.dumps(issued.details)


def test_attach_issued_accepts_der_leaf(db, submitted_renewal, ca, actor, now):
    der = x509.load_pem_x509_certificate(ca.issue(submitted_renewal.csr_pem)).public_bytes(
        serialization.Encoding.DER
    )
    assert attach_issued(db, submitted_renewal.id, der, None, actor, now).state == RenewalState.ISSUED


def test_attach_issued_without_previous_copies_no_metadata(db, ca, keyring, actor, now):
    renewal = _submitted(db, keyring, actor, now)
    issued = attach_issued(db, renewal.id, ca.issue(renewal.csr_pem), None, actor, now)
    certificate = db.get(Certificate, issued.certificate_id)
    assert certificate.renews_id is None and certificate.team is None
    assert issued.issued_chain_pem == "" and certificate.chain_pem == ""


def test_attach_issued_trusted_chain_has_no_warnings(db, submitted_renewal, ca, actor, now):
    add_anchor(db, ca.root_pem, None, actor, now)
    renewal = attach_issued(
        db, submitted_renewal.id, ca.issue(submitted_renewal.csr_pem), ca.chain_pem, actor, now
    )
    assert db.get(Certificate, renewal.certificate_id).chain_status == ChainStatus.TRUSTED
    assert issued_warnings(db, renewal.id, now) == ()


def test_missing_intermediate_is_accepted_as_incomplete(db, submitted_renewal, ca, actor, now):
    add_anchor(db, ca.root_pem, None, actor, now)
    # Previous certificate's stored chain is deliberately not reused: supply an unrelated chain.
    renewal = attach_issued(
        db, submitted_renewal.id, ca.issue(submitted_renewal.csr_pem), ca.expired_chain_pem, actor, now
    )
    certificate = db.get(Certificate, renewal.certificate_id)
    assert renewal.state == RenewalState.ISSUED
    assert certificate.chain_status == ChainStatus.INCOMPLETE
    assert certificate.chain_pem == ""
    assert issued_warnings(db, renewal.id, now)


def test_missing_intermediate_without_any_chain_is_incomplete(db, ca, keyring, actor, now):
    add_anchor(db, ca.root_pem, None, actor, now)
    renewal = _submitted(db, keyring, actor, now)
    issued = attach_issued(db, renewal.id, ca.issue(renewal.csr_pem), None, actor, now)
    assert db.get(Certificate, issued.certificate_id).chain_status == ChainStatus.INCOMPLETE
    warnings = issued_warnings(db, issued.id, now)
    assert any(w.startswith(("missing_issuer", "issuer:")) for w in warnings)


def test_expired_intermediate_is_accepted_as_incomplete(db, ca, keyring, actor, now):
    add_anchor(db, ca.root_pem, None, actor, now)
    renewal = _submitted(db, keyring, actor, now)
    leaf = ca.issue(renewal.csr_pem, issuer="expired_intermediate")
    issued = attach_issued(db, renewal.id, leaf, ca.expired_chain_pem, actor, now)
    assert issued.state == RenewalState.ISSUED
    assert db.get(Certificate, issued.certificate_id).chain_status == ChainStatus.INCOMPLETE
    assert "expired_intermediate" in issued_warnings(db, issued.id, now)
    (audit,) = _renewal_audits(db, issued.id, "renewal.issued")
    assert "expired_intermediate" in audit.details["warnings"]


def test_untrusted_root_is_accepted_with_warning(db, submitted_renewal, ca, actor, now):
    renewal = attach_issued(
        db, submitted_renewal.id, ca.issue(submitted_renewal.csr_pem), ca.chain_with_root_pem, actor, now
    )
    certificate = db.get(Certificate, renewal.certificate_id)
    assert certificate.chain_status == ChainStatus.UNTRUSTED_ROOT
    assert "untrusted_root" in issued_warnings(db, renewal.id, now)
    # Roots are never stored in the chain.
    assert renewal.issued_chain_pem == ca.chain_pem.decode()
    (audit,) = _renewal_audits(db, renewal.id, "renewal.issued")
    assert audit.details["chain_status"] == "untrusted_root" and "untrusted_root" in audit.details["warnings"]


def test_previously_stored_chain_is_reused(db, submitted_renewal, previous_certificate, ca, actor, now):
    add_anchor(db, ca.root_pem, None, actor, now)
    assert previous_certificate.chain_pem == ca.chain_pem.decode()
    renewal = attach_issued(db, submitted_renewal.id, ca.issue(submitted_renewal.csr_pem), None, actor, now)
    certificate = db.get(Certificate, renewal.certificate_id)
    assert certificate.chain_pem == previous_certificate.chain_pem == renewal.issued_chain_pem
    assert certificate.chain_status == ChainStatus.TRUSTED


def test_unlinked_stored_chain_is_not_reused(db, submitted_renewal, previous_certificate, ca, actor, now):
    leaf = ca.issue(submitted_renewal.csr_pem, issuer="expired_intermediate")
    renewal = attach_issued(db, submitted_renewal.id, leaf, None, actor, now)
    assert renewal.issued_chain_pem == "" and previous_certificate.chain_pem != ""


# --- attach_issued: blocking errors -------------------------------------------


def test_wrong_cn_is_blocking(db, submitted_renewal, ca, actor, now):
    leaf = ca.issue(submitted_renewal.csr_pem, common_name="other.example.internal")
    errors = _attach_expecting_errors(db, submitted_renewal, leaf, ca.chain_pem, actor, now)
    assert set(errors) == {"common_name"}


def test_missing_cn_is_blocking(db, submitted_renewal, ca, actor, now):
    leaf = ca.issue(submitted_renewal.csr_pem, common_name=None)
    errors = _attach_expecting_errors(db, submitted_renewal, leaf, ca.chain_pem, actor, now)
    assert set(errors) == {"common_name"}


@pytest.mark.parametrize(
    "sans",
    [
        ["www.example.internal"],
        ["www.example.internal", "api.example.internal", "extra.example.internal"],
        ["www.example.internal", "other.example.internal"],
        [],
    ],
)
def test_wrong_san_set_is_blocking(db, submitted_renewal, ca, actor, now, sans):
    leaf = ca.issue(submitted_renewal.csr_pem, sans=sans)
    errors = _attach_expecting_errors(db, submitted_renewal, leaf, ca.chain_pem, actor, now)
    assert set(errors) == {"sans"}


def test_san_types_are_compared_exactly(db, submitted_renewal, ca, actor, now):
    sans = [x509.DNSName(n) for n in NAMES] + [x509.RFC822Name("ops@example.internal")]
    errors = _attach_expecting_errors(
        db, submitted_renewal, ca.issue(submitted_renewal.csr_pem, sans=sans), ca.chain_pem, actor, now
    )
    assert set(errors) == {"sans"}


def test_san_order_and_case_do_not_matter(db, submitted_renewal, ca, actor, now):
    leaf = ca.issue(submitted_renewal.csr_pem, sans=["API.example.internal", "WWW.example.internal"])
    assert attach_issued(db, submitted_renewal.id, leaf, ca.chain_pem, actor, now).state == RenewalState.ISSUED


@pytest.mark.parametrize("flavor", ["rsa", "ec"])
def test_key_mismatch_shows_both_public_hashes(db, submitted_renewal, ca, actor, now, flavor):
    other = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if flavor == "rsa"
        else ec.generate_private_key(ec.SECP384R1())
    )
    leaf = ca.issue(submitted_renewal.csr_pem, public_key=other.public_key())
    errors = _attach_expecting_errors(db, submitted_renewal, leaf, ca.chain_pem, actor, now)
    assert set(errors) == {"key_match", "csr_match"}
    expected = db.get(PrivateKey, submitted_renewal.key_id).public_key_sha256
    actual = parse_certificates(leaf)[0].public_key_sha256
    message = " ".join(errors["key_match"])
    assert expected in message and actual in message


@pytest.mark.parametrize(
    ("window", "word"),
    [
        (lambda now: (now - timedelta(days=30), now - timedelta(days=1)), "expired"),
        (lambda now: (now + timedelta(days=1), now + timedelta(days=30)), "not yet valid"),
        (lambda now: (now - timedelta(days=30), now), "expired"),  # not_after == now is already invalid
    ],
)
def test_leaf_validity_window_is_blocking(db, submitted_renewal, ca, actor, now, window, word):
    before, after = window(now)
    leaf = ca.issue(submitted_renewal.csr_pem, not_before=before, not_after=after)
    errors = _attach_expecting_errors(db, submitted_renewal, leaf, ca.chain_pem, actor, now)
    assert set(errors) == {"validity"} and word in errors["validity"][0]


def test_not_before_equal_to_now_is_valid(db, submitted_renewal, ca, actor, now):
    leaf = ca.issue(submitted_renewal.csr_pem, not_before=now)
    assert attach_issued(db, submitted_renewal.id, leaf, ca.chain_pem, actor, now).state == RenewalState.ISSUED


def test_invalid_stored_csr_signature_is_blocking(db, submitted_renewal, ca, actor, now):
    csr = x509.load_pem_x509_csr(submitted_renewal.csr_pem.encode())
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0xFF  # corrupt the signature value only
    pem = (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + base64.encodebytes(bytes(der)).decode()
        + "-----END CERTIFICATE REQUEST-----\n"
    )
    submitted_renewal.csr_pem = pem
    db.flush()
    leaf = ca.issue(csr.public_bytes(serialization.Encoding.PEM).decode())
    errors = _attach_expecting_errors(db, submitted_renewal, leaf, ca.chain_pem, actor, now)
    assert set(errors) == {"csr_signature"}


def test_unparseable_stored_csr_is_blocking(db, submitted_renewal, ca, actor, now):
    leaf = ca.issue(submitted_renewal.csr_pem)
    submitted_renewal.csr_pem = "not a csr"
    db.flush()
    errors = _attach_expecting_errors(db, submitted_renewal, leaf, ca.chain_pem, actor, now)
    assert set(errors) == {"csr_signature"}


def test_pfx_is_rejected_by_content(db, submitted_renewal, ca, actor, now):
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = x509.load_pem_x509_certificate(ca.issue(public_key=key.public_key(), common_name="pfx.example.test", sans=["pfx.example.test"]))
    pfx = pkcs12.serialize_key_and_certificates(
        b"x", key, leaf, None, serialization.BestAvailableEncryption(b"correct-horse-battery")
    )
    errors = _attach_expecting_errors(db, submitted_renewal, pfx, None, actor, now)
    assert set(errors) == {"parse"} and "pfx_not_accepted" in errors["parse"][0]


@pytest.mark.parametrize(
    "data",
    [
        b"hello",
        b"",
        b"-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----",
        b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
    ],
)
def test_non_certificate_leaf_data_is_a_parse_error(db, submitted_renewal, ca, actor, now, data):
    errors = _attach_expecting_errors(db, submitted_renewal, data, ca.chain_pem, actor, now)
    assert set(errors) == {"parse"}


def test_leaf_data_must_contain_exactly_one_certificate(db, submitted_renewal, ca, actor, now):
    leaf = ca.issue(submitted_renewal.csr_pem)
    errors = _attach_expecting_errors(db, submitted_renewal, leaf + ca.chain_pem, None, actor, now)
    assert set(errors) == {"parse"} and "exactly one" in errors["parse"][0]


def test_self_signed_leaf_is_blocking(db, submitted_renewal, ca, keyring, actor, now):
    key = unwrap_key(db.get(PrivateKey, submitted_renewal.key_id), keyring)
    leaf = ca.issue(submitted_renewal.csr_pem, issuer=key)
    errors = _attach_expecting_errors(db, submitted_renewal, leaf, None, actor, now)
    assert set(errors) == {"self_signed"}


def test_duplicate_fingerprint_is_rejected_unlike_import(db, submitted_renewal, ca, actor, now):
    from app.crypto.chain import order_chain
    from app.services.certificates import CertificateMetadata, save_certificate

    leaf_pem = ca.issue(submitted_renewal.csr_pem)
    parsed = parse_certificates(leaf_pem)[0]
    save_certificate(
        db, parsed, order_chain(parsed.cert, []), CertificateMetadata(), actor, source="upload_pem", validation_time=now
    )
    errors = _attach_expecting_errors(db, submitted_renewal, leaf_pem, ca.chain_pem, actor, now)
    assert set(errors) == {"duplicate"}


def test_duplicate_issuer_and_serial_is_rejected(db, submitted_renewal, ca, actor, now):
    from app.crypto.chain import order_chain
    from app.services.certificates import CertificateMetadata, save_certificate

    first = ca.issue(submitted_renewal.csr_pem, serial=0xABCDEF, not_after=now + timedelta(days=100))
    parsed = parse_certificates(first)[0]
    save_certificate(
        db, parsed, order_chain(parsed.cert, []), CertificateMetadata(), actor, source="upload_pem", validation_time=now
    )
    second = ca.issue(submitted_renewal.csr_pem, serial=0xABCDEF, not_after=now + timedelta(days=200))
    assert parse_certificates(second)[0].sha256_fingerprint != parsed.sha256_fingerprint
    errors = _attach_expecting_errors(db, submitted_renewal, second, ca.chain_pem, actor, now)
    assert set(errors) == {"duplicate"}


def test_malformed_chain_is_blocking(db, submitted_renewal, ca, actor, now):
    leaf = ca.issue(submitted_renewal.csr_pem)
    errors = _attach_expecting_errors(
        db, submitted_renewal, leaf, b"-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----", actor, now
    )
    assert set(errors) == {"chain"}


def test_forged_issuer_link_in_chain_is_blocking(db, submitted_renewal, ca, actor, now):
    leaf = ca.issue(submitted_renewal.csr_pem)
    errors = _attach_expecting_errors(db, submitted_renewal, leaf, ca.forged_intermediate_pem, actor, now)
    assert set(errors) == {"chain"}


def test_independent_errors_are_reported_together(db, submitted_renewal, ca, actor, now):
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    leaf = ca.issue(
        public_key=other,
        common_name="other.example.internal",
        sans=["other.example.internal"],
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1),
    )
    errors = _attach_expecting_errors(db, submitted_renewal, leaf, ca.forged_intermediate_pem, actor, now)
    assert set(errors) == {"key_match", "csr_match", "common_name", "sans", "validity", "chain"}
    assert all(isinstance(messages, tuple) and messages for messages in errors.values())


def test_parse_failure_still_reports_chain_errors(db, submitted_renewal, ca, actor, now):
    errors = _attach_expecting_errors(db, submitted_renewal, b"garbage", b"also garbage", actor, now)
    assert set(errors) == {"parse", "chain"}


def test_rejected_upload_can_be_retried(db, submitted_renewal, ca, actor, now):
    _attach_expecting_errors(db, submitted_renewal, b"garbage", None, actor, now)
    leaf = ca.issue(submitted_renewal.csr_pem)
    assert attach_issued(db, submitted_renewal.id, leaf, ca.chain_pem, actor, now).state == RenewalState.ISSUED


# --- mark_deployed -----------------------------------------------------------


def test_mark_deployed_requires_real_succeeded_deploy_evidence(db, ca, keyring, actor, now):
    renewal = _issued(db, ca, keyring, actor, now)
    job = _deploy_evidence(db, renewal, now)
    later = now + timedelta(hours=2)
    deployed = mark_deployed(db, renewal.id, job.id, actor, later)
    assert deployed.state == RenewalState.DEPLOYED and deployed.deployed_by == actor.user_id
    assert deployed.state_changed_at == later
    (audit,) = _renewal_audits(db, renewal.id, "renewal.deployed")
    assert audit.details == {"job_id": str(job.id)}


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"job_status": JobStatus.QUEUED}, "job_not_succeeded"),
        ({"job_status": JobStatus.RUNNING}, "job_not_succeeded"),
        ({"job_status": JobStatus.FAILED}, "job_not_succeeded"),
        ({"job_status": JobStatus.CANCELLED}, "job_not_succeeded"),
        ({"job_type": JobType.SCAN}, "job_unrelated"),
        ({"payload_certificate_id": 10**9}, "job_unrelated"),
        ({"with_host": False}, "no_succeeded_binding"),
        ({"host_status": JobHostStatus.FAILED}, "no_succeeded_binding"),
        ({"host_status": JobHostStatus.ROLLED_BACK}, "no_succeeded_binding"),
        ({"with_binding": False}, "no_succeeded_binding"),
        ({"fingerprint": "0" * 64}, "no_succeeded_binding"),
    ],
)
def test_mark_deployed_rejects_insufficient_evidence(db, ca, keyring, actor, now, kwargs, reason):
    renewal = _issued(db, ca, keyring, actor, now)
    job = _deploy_evidence(db, renewal, now, **kwargs)
    audits = _audit_count(db)
    with pytest.raises(InvalidTransition) as exc:
        mark_deployed(db, renewal.id, job.id, actor, now)
    assert exc.value.reason == reason and exc.value.from_state == RenewalState.ISSUED
    assert renewal.state == RenewalState.ISSUED and renewal.deployed_by is None
    assert _audit_count(db) == audits


def test_mark_deployed_rejects_unknown_job(db, ca, keyring, actor, now):
    renewal = _issued(db, ca, keyring, actor, now)
    with pytest.raises(InvalidTransition) as exc:
        mark_deployed(db, renewal.id, uuid.uuid4(), actor, now)
    assert exc.value.reason == "job_unrelated"


def test_mark_deployed_ignores_evidence_for_other_certificate(db, ca, keyring, actor, now):
    renewal = _issued(db, ca, keyring, actor, now)
    other = _issued(db, ca, keyring, actor, now)
    job = _deploy_evidence(db, other, now)
    with pytest.raises(InvalidTransition) as exc:
        mark_deployed(db, renewal.id, job.id, actor, now)
    assert exc.value.reason == "job_unrelated"


# --- finalize ----------------------------------------------------------------


def test_finalize_supersedes_previous_by_default(db, ca, keyring, actor, now, previous_certificate):
    renewal = _deployed(db, ca, keyring, actor, now, previous_certificate.id)
    done = finalize(db, renewal.id, "superseded", "", actor, now + timedelta(days=1))
    assert done.state == RenewalState.DONE and done.state_changed_at == now + timedelta(days=1)
    assert db.get(Certificate, previous_certificate.id).status == CertificateStatus.SUPERSEDED
    assert db.get(Certificate, done.certificate_id).status == CertificateStatus.ACTIVE
    (audit,) = _renewal_audits(db, renewal.id, "renewal.done")
    assert audit.details["previous_status"] == "superseded" and "reason" in audit.details
    (change,) = db.scalars(
        select(AuditLog).where(
            AuditLog.action == "certificate.status_change", AuditLog.target_id == str(previous_certificate.id)
        )
    )
    assert change.details["to"] == "superseded"


def test_finalize_superseded_keeps_optional_note_as_reason(db, ca, keyring, actor, now, previous_certificate):
    renewal = _deployed(db, ca, keyring, actor, now, previous_certificate.id)
    finalize(db, renewal.id, "superseded", "  replaced by ops  ", actor, now)
    (audit,) = _renewal_audits(db, renewal.id, "renewal.done")
    assert audit.details["reason"] == "replaced by ops"
    (change,) = db.scalars(select(AuditLog).where(AuditLog.action == "certificate.status_change"))
    assert change.details["reason"] == "replaced by ops"


def test_finalize_can_revoke_previous_with_reason(db, ca, keyring, actor, now, previous_certificate):
    renewal = _deployed(db, ca, keyring, actor, now, previous_certificate.id)
    finalize(db, renewal.id, "revoked", "key compromised", actor, now)
    assert db.get(Certificate, previous_certificate.id).status == CertificateStatus.REVOKED
    assert db.get(Renewal, renewal.id).state == RenewalState.DONE


@pytest.mark.parametrize(
    ("previous_status", "reason", "field"),
    [("revoked", "", "reason"), ("revoked", "   ", "reason"), ("superseded", "x" * 1001, "reason"), ("revoked", "x" * 1001, "reason"), ("active", "", "previous_status"), ("gone", "r", "previous_status")],
)
def test_finalize_validates_input(db, ca, keyring, actor, now, previous_certificate, previous_status, reason, field):
    renewal = _deployed(db, ca, keyring, actor, now, previous_certificate.id)
    audits = _audit_count(db)
    with pytest.raises(RenewalValidationError) as exc:
        finalize(db, renewal.id, previous_status, reason, actor, now)
    assert field in exc.value.errors
    assert renewal.state == RenewalState.DEPLOYED and _audit_count(db) == audits
    assert db.get(Certificate, previous_certificate.id).status == CertificateStatus.ACTIVE


def test_finalize_tolerates_previous_already_superseded(db, ca, keyring, actor, now, previous_certificate):
    from app.services.certificates import set_status

    renewal = _deployed(db, ca, keyring, actor, now, previous_certificate.id)
    set_status(db, previous_certificate.id, CertificateStatus.SUPERSEDED, "manual", actor)
    changes = _count(db, AuditLog)
    done = finalize(db, renewal.id, "superseded", "", actor, now)
    assert done.state == RenewalState.DONE
    assert _count(db, AuditLog) == changes + 1  # only renewal.done
    (audit,) = _renewal_audits(db, renewal.id, "renewal.done")
    assert audit.details["previous_changed"] is False


def test_finalize_without_previous_certificate(db, ca, keyring, actor, now):
    renewal = _deployed(db, ca, keyring, actor, now)
    done = finalize(db, renewal.id, "superseded", "", actor, now)
    assert done.state == RenewalState.DONE
    (audit,) = _renewal_audits(db, renewal.id, "renewal.done")
    assert audit.details["previous_changed"] is False


# --- cancel ------------------------------------------------------------------


@pytest.mark.parametrize(
    "state",
    [RenewalState.DRAFT, RenewalState.CSR_GENERATED, RenewalState.SUBMITTED, RenewalState.ISSUED],
)
def test_cancel_keeps_key_history_and_issued_certificate(db, ca, keyring, actor, now, state):
    renewal = _renewal_in_state(db, ca, keyring, actor, now, state)
    key_id, certificate_id = renewal.key_id, renewal.certificate_id
    keys, certificates = _count(db, PrivateKey), _count(db, Certificate)
    cancelled = cancel(db, renewal.id, "  wrong CA  ", actor, now + timedelta(minutes=3))
    assert cancelled.state == RenewalState.CANCELLED and cancelled.state_changed_at == now + timedelta(minutes=3)
    assert (cancelled.key_id, cancelled.certificate_id) == (key_id, certificate_id)
    assert _count(db, PrivateKey) == keys and _count(db, Certificate) == certificates
    if key_id is not None:
        assert db.get(PrivateKey, key_id) is not None
    (audit,) = _renewal_audits(db, renewal.id, "renewal.cancelled")
    assert audit.details == {"from_state": state.value, "reason": "wrong CA"}


@pytest.mark.parametrize("reason", ["", "   ", "x" * 1001])
def test_cancel_requires_a_reason(db, actor, now, reason):
    renewal = _draft(db, actor, now)
    audits = _audit_count(db)
    with pytest.raises(RenewalValidationError) as exc:
        cancel(db, renewal.id, reason, actor, now)
    assert "reason" in exc.value.errors
    assert renewal.state == RenewalState.DRAFT and _audit_count(db) == audits


def test_cancel_accepts_1000_character_reason(db, actor, now):
    renewal = _draft(db, actor, now)
    assert cancel(db, renewal.id, "r" * 1000, actor, now).state == RenewalState.CANCELLED


# --- transition matrix ---------------------------------------------------------

ALL_STATES = list(RenewalState)
LEGAL = {
    "edit_draft": {RenewalState.DRAFT},
    "generate_csr": {RenewalState.DRAFT},
    "mark_submitted": {RenewalState.CSR_GENERATED},
    "attach_issued": {RenewalState.SUBMITTED},
    "mark_deployed": {RenewalState.ISSUED},
    "finalize": {RenewalState.DEPLOYED},
    "cancel": {RenewalState.DRAFT, RenewalState.CSR_GENERATED, RenewalState.SUBMITTED, RenewalState.ISSUED},
}
TARGET = {
    "edit_draft": RenewalState.DRAFT,
    "generate_csr": RenewalState.CSR_GENERATED,
    "mark_submitted": RenewalState.SUBMITTED,
    "attach_issued": RenewalState.ISSUED,
    "mark_deployed": RenewalState.DEPLOYED,
    "finalize": RenewalState.DONE,
    "cancel": RenewalState.CANCELLED,
}
AUDIT = {
    "edit_draft": "renewal.edit",
    "generate_csr": "renewal.csr_generated",
    "mark_submitted": "renewal.submitted",
    "attach_issued": "renewal.issued",
    "mark_deployed": "renewal.deployed",
    "finalize": "renewal.done",
    "cancel": "renewal.cancelled",
}


_SPARE_CSR = build_csr(generate_key(ECDSA), NAMES[0], NAMES).pem


def _invoke(action, db, renewal, ca, keyring, actor, now):
    rid = renewal.id
    if action == "edit_draft":
        return edit_draft(db, rid, _basics(notes="edited"), actor, now)
    if action == "generate_csr":
        return generate_csr(db, rid, ECDSA, keyring, actor, now)
    if action == "mark_submitted":
        return mark_submitted(db, rid, "ORDER-X", actor, now)
    if action == "attach_issued":
        return attach_issued(db, rid, ca.issue(renewal.csr_pem or _SPARE_CSR), ca.chain_pem, actor, now)
    if action == "mark_deployed":
        job_id = _deploy_evidence(db, renewal, now).id if renewal.certificate_id else uuid.uuid4()
        return mark_deployed(db, rid, job_id, actor, now)
    if action == "finalize":
        return finalize(db, rid, "superseded", "", actor, now)
    return cancel(db, rid, "because", actor, now)


@pytest.mark.parametrize("action", list(LEGAL))
@pytest.mark.parametrize("state", ALL_STATES, ids=lambda s: s.value)
def test_transition_matrix(db, ca, keyring, actor, now, state, action):
    renewal = _renewal_in_state(db, ca, keyring, actor, now, state)
    rid = renewal.id
    before_audits = _audit_count(db)
    if state in LEGAL[action]:
        result = _invoke(action, db, renewal, ca, keyring, actor, now)
        assert result.state == TARGET[action]
        assert db.get(Renewal, rid).state == TARGET[action]
        assert len(_renewal_audits(db, rid, AUDIT[action])) == 1
    else:
        with pytest.raises(InvalidTransition) as exc:
            _invoke(action, db, renewal, ca, keyring, actor, now)
        assert exc.value.from_state == state and exc.value.action == action
        assert db.get(Renewal, rid).state == state
        assert _audit_count(db) == before_audits


def test_terminal_states_never_change(db, ca, keyring, actor, now):
    for state in (RenewalState.DONE, RenewalState.CANCELLED):
        renewal = _renewal_in_state(db, ca, keyring, actor, now, state)
        snapshot = (renewal.state, renewal.state_changed_at, renewal.key_id, renewal.certificate_id)
        for action in LEGAL:
            with pytest.raises(InvalidTransition):
                _invoke(action, db, renewal, ca, keyring, actor, now)
        assert snapshot == (renewal.state, renewal.state_changed_at, renewal.key_id, renewal.certificate_id)


@pytest.mark.parametrize("action", list(LEGAL))
def test_unknown_renewal_is_not_found(db, ca, keyring, actor, now, action):
    ghost = Renewal(id=uuid.uuid4(), csr_pem=_SPARE_CSR, certificate_id=None)
    with pytest.raises(RenewalError) as exc:
        _invoke(action, db, ghost, ca, keyring, actor, now)
    assert exc.value.code == "not_found"


def test_full_lifecycle_writes_one_renewal_audit_per_transition(db, ca, keyring, actor, now, previous_certificate):
    renewal = _draft(db, actor, now, previous_certificate.id)
    edit_draft(db, renewal.id, _basics(notes="x"), actor, now)
    generate_csr(db, renewal.id, ECDSA, keyring, actor, now)
    mark_submitted(db, renewal.id, "ORDER-1", actor, now)
    attach_issued(db, renewal.id, ca.issue(renewal.csr_pem), ca.chain_pem, actor, now)
    mark_deployed(db, renewal.id, _deploy_evidence(db, renewal, now).id, actor, now)
    finalize(db, renewal.id, "superseded", "", actor, now)
    actions = sorted(a.action for a in _renewal_audits(db, renewal.id))
    assert actions == sorted(
        [
            "renewal.create",
            "renewal.edit",
            "renewal.csr_generated",
            "renewal.submitted",
            "renewal.issued",
            "renewal.deployed",
            "renewal.done",
        ]
    )
    for audit in _renewal_audits(db, renewal.id):
        assert audit.actor_user_id == actor.user_id


def test_audits_never_contain_key_material(db, ca, keyring, actor, now, previous_certificate):
    _deployed(db, ca, keyring, actor, now, previous_certificate.id)
    dump = json.dumps([a.details for a in db.scalars(select(AuditLog))])
    assert "PRIVATE KEY" not in dump and "BEGIN" not in dump


# --- issued_warnings -----------------------------------------------------------


def test_issued_warnings_without_certificate_is_empty(db, actor, now):
    renewal = _draft(db, actor, now)
    assert issued_warnings(db, renewal.id, now) == ()


def test_issued_warnings_unknown_renewal(db, now):
    with pytest.raises(RenewalError) as exc:
        issued_warnings(db, uuid.uuid4(), now)
    assert exc.value.code == "not_found"


def test_issued_warnings_flags_leaf_that_expired_later(db, ca, keyring, actor, now):
    renewal = _issued(db, ca, keyring, actor, now)
    certificate = db.get(Certificate, renewal.certificate_id)
    assert "expired" in issued_warnings(db, renewal.id, certificate.not_after + timedelta(seconds=1))


# --- concurrency ---------------------------------------------------------------


@pytest.fixture
def isolated_factory(owner_engine, database_urls):
    name = "fixture_renewal_" + uuid.uuid4().hex
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


def _rendezvous_once(factory, prefix, parties=2):
    """Make each connection pause once at the first statement starting with ``prefix``."""
    barrier, seen = Barrier(parties), local()

    def capture(conn, cursor, statement, parameters, context, many):
        if statement.lstrip().startswith(prefix) and not getattr(seen, "done", False):
            seen.done = True
            barrier.wait(timeout=20)

    engine = factory.kw["bind"]
    event.listen(engine, "before_cursor_execute", capture)
    return lambda: event.remove(engine, "before_cursor_execute", capture)


@pytest.mark.parametrize("duplicate", ["cancel", "mark_submitted"])
def test_concurrent_duplicate_transition_produces_one_change(isolated_factory, keyring, now, duplicate):
    from app.models import User

    with transaction(isolated_factory) as db:
        user = User(username="concurrent-admin", email="c@example.test")
        db.add(user)
        db.flush()
        actor = Actor(user.id, user.username)
        renewal = _csr_generated(db, keyring, actor, now)
        rid = renewal.id

    release = _rendezvous_once(isolated_factory, "SELECT renewal.id")

    def run(_):
        with transaction(isolated_factory) as db:
            try:
                if duplicate == "cancel":
                    cancel(db, rid, "double click", actor, now)
                else:
                    mark_submitted(db, rid, "ORDER-DUP", actor, now)
            except InvalidTransition as exc:
                return ("rejected", exc.from_state)
            return ("changed", None)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, range(2)))
    finally:
        release()
    assert sorted(kind for kind, _ in results) == ["changed", "rejected"]
    rejected_from = next(state for kind, state in results if kind == "rejected")
    expected = RenewalState.CANCELLED if duplicate == "cancel" else RenewalState.SUBMITTED
    assert rejected_from == expected
    with transaction(isolated_factory) as db:
        assert db.get(Renewal, rid).state == expected
        action = "renewal.cancelled" if duplicate == "cancel" else "renewal.submitted"
        assert len(_renewal_audits(db, rid, action)) == 1
