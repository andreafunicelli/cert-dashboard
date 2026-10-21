from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import func, select

from app.crypto.parse import parse_certificates
from app.crypto.trust import assess_chain
from app.models import AppSetting, AuditLog, Certificate, TrustAnchor
from app.models.enums import ChainStatus
from app.services.trust_anchors import (
    AnchorValidationError,
    add_anchor,
    load_anchors,
    recheck_chain_statuses,
    remove_anchor,
)


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _certificate_row(db, leaf_pem: bytes, chain_pem: bytes = b"") -> Certificate:
    parsed = parse_certificates(leaf_pem)[0]
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
        chain_pem=chain_pem.decode("ascii"),
        chain_status=ChainStatus.UNCHECKED,
        imported_from="upload_pem",
    )
    db.add(row)
    db.flush()
    return row


def test_expired_intermediate_and_non_ca_anchor(db, certs, actor, now):
    expired = assess_chain(
        certs.expired_intermediate_leaf, certs.expired_intermediate_chain, [certs.root], now
    )
    assert expired.status == ChainStatus.INCOMPLETE
    assert "expired_intermediate" in expired.messages
    with pytest.raises(AnchorValidationError, match="CA:TRUE"):
        add_anchor(db, certs.leaf_pem, None, actor, now)
    assert db.scalar(select(func.count()).select_from(TrustAnchor)) == 0


def test_add_anchor_trusts_then_remove_rechecks(db, certs, actor, now):
    cert = _certificate_row(db, certs.leaf_pem, certs.chain_pem)
    anchor = add_anchor(db, _pem(certs.root), "internal root", actor, now)
    db.flush()
    db.refresh(cert)
    assert cert.chain_status == ChainStatus.TRUSTED
    assert len(load_anchors(db)) == 1
    actions = set(db.scalars(select(AuditLog.action)).all())
    assert {"trust_anchor.add", "certificate.chain_check"} <= actions

    remove_anchor(db, anchor.id, actor, now)
    db.flush()
    db.refresh(cert)
    assert cert.chain_status == ChainStatus.UNTRUSTED_ROOT
    assert load_anchors(db) == ()
    assert "trust_anchor.remove" in set(db.scalars(select(AuditLog.action)).all())


def test_public_bundle_toggle_rechecks_without_persisting(monkeypatch, db, certs, actor, now):
    from app.services import trust_anchors as service

    monkeypatch.setattr(service, "public_bundle_anchors", lambda: (certs.root,))
    cert = _certificate_row(db, certs.leaf_pem, certs.chain_pem)
    setting = db.scalar(select(AppSetting).where(AppSetting.key == "trust.include_public_bundle"))
    setting.value = False
    db.flush()
    recheck_chain_statuses(db, now)
    db.refresh(cert)
    assert cert.chain_status != ChainStatus.TRUSTED

    setting.value = True
    db.flush()
    counts = recheck_chain_statuses(db, now)
    db.refresh(cert)
    assert cert.chain_status == ChainStatus.TRUSTED
    assert counts.get("trusted") == 1
    assert db.scalar(select(func.count()).select_from(TrustAnchor)) == 0


def test_default_unchecked_becomes_incomplete_and_is_audited(monkeypatch, db, certs, now):
    from app.services import trust_anchors as service

    monkeypatch.setattr(service, "public_bundle_anchors", lambda: ())
    cert = _certificate_row(db, certs.leaf_pem, certs.chain_pem)
    assert cert.chain_status == ChainStatus.UNCHECKED
    counts = recheck_chain_statuses(db, now)
    db.refresh(cert)
    assert cert.chain_status == ChainStatus.INCOMPLETE
    assert counts.get("incomplete") == 1
    audit = db.scalar(select(AuditLog).where(AuditLog.action == "certificate.chain_check"))
    assert audit is not None and audit.target_id == str(cert.id)
    assert "PRIVATE KEY" not in str(audit.details)


def test_anchor_validation_rejections(db, certs, actor, now):
    with pytest.raises(AnchorValidationError, match="CA:TRUE"):
        add_anchor(db, certs.leaf_pem, None, actor, now)
    with pytest.raises(AnchorValidationError, match="self-signed"):
        add_anchor(db, _pem(certs.intermediate2), None, actor, now)
    with pytest.raises(AnchorValidationError, match="single"):
        add_anchor(db, _pem(certs.root) + _pem(certs.root), None, actor, now)
    with pytest.raises(AnchorValidationError, match="PEM"):
        add_anchor(db, certs.root.public_bytes(serialization.Encoding.DER), None, actor, now)
    with pytest.raises(AnchorValidationError):
        add_anchor(db, b"x" * 1_048_577, None, actor, now)
    assert db.scalar(select(func.count()).select_from(TrustAnchor)) == 0

    root = add_anchor(db, _pem(certs.root), None, actor, now)
    assert root.source == "uploaded"
    with pytest.raises(AnchorValidationError, match="already"):
        add_anchor(db, _pem(certs.root), None, actor, now)

    no_sign_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No Sign Root")])
    no_sign = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(no_sign_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(no_sign_key, hashes.SHA256())
    )
    with pytest.raises(AnchorValidationError, match="signing"):
        add_anchor(db, _pem(no_sign), None, actor, now)

    forged_key = ec.generate_private_key(ec.SECP256R1())
    signing_key = ec.generate_private_key(ec.SECP256R1())
    forged = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(forged_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(signing_key, hashes.SHA256())
    )
    with pytest.raises(AnchorValidationError, match="signature"):
        add_anchor(db, _pem(forged), None, actor, now)

    assert db.scalar(select(func.count()).select_from(TrustAnchor)) == 1


def test_load_anchors_skips_malformed_rows(db, certs, actor, now):
    db.add(
        TrustAnchor(
            subject="CN=Broken",
            sha256_fingerprint="a" * 64,
            pem="not a certificate",
            source="uploaded",
        )
    )
    db.flush()
    assert load_anchors(db) == ()
    add_anchor(db, _pem(certs.root), None, actor, now)
    assert len(load_anchors(db)) == 1
