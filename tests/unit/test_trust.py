from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.crypto.trust import ChainAssessment, assess_chain
from app.models.enums import ChainStatus


def _issue(
    subject_cn,
    key,
    issuer,
    issuer_key,
    *,
    sans=(),
    ca=False,
    key_usage=False,
    before=None,
    after=None,
):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(list(sans)), critical=False)
    return builder.sign(issuer_key if issuer_key is not None else key, hashes.SHA256())


def test_internal_anchor_and_missing_paths(certs, now):
    trusted = assess_chain(certs.leaf, certs.intermediates, [certs.root], now)
    assert trusted.status == ChainStatus.TRUSTED
    absent = assess_chain(certs.leaf, certs.intermediates, [], now, [certs.root])
    assert absent.status == ChainStatus.UNTRUSTED_ROOT
    missing = assess_chain(certs.leaf, [certs.intermediate1], [certs.root], now)
    assert missing.status == ChainStatus.INCOMPLETE


def test_expired_intermediate_is_incomplete(certs, now):
    expired = assess_chain(
        certs.expired_intermediate_leaf, certs.expired_intermediate_chain, [certs.root], now
    )
    assert expired.status == ChainStatus.INCOMPLETE
    assert "expired_intermediate" in expired.messages


def test_leaf_validity_and_validation_time_are_enforced(certs, now):
    assert (
        assess_chain(certs.expired, certs.intermediates, [certs.root], now).status
        == ChainStatus.INCOMPLETE
    )
    assert (
        assess_chain(certs.not_yet_valid, certs.intermediates, [certs.root], now).status
        == ChainStatus.INCOMPLETE
    )
    just_before = certs.leaf.not_valid_before_utc - timedelta(seconds=1)
    assert (
        assess_chain(certs.leaf, certs.intermediates, [certs.root], just_before).status
        == ChainStatus.INCOMPLETE
    )
    at_expiry = certs.leaf.not_valid_after_utc
    assert (
        assess_chain(certs.leaf, certs.intermediates, [certs.root], at_expiry).status
        == ChainStatus.INCOMPLETE
    )
    result = assess_chain(certs.leaf, certs.intermediates, [certs.root], now)
    assert isinstance(result, ChainAssessment) and result.validation_time == now


def test_wildcard_and_ip_identities_are_trusted(certs, now):
    assert (
        assess_chain(certs.wildcard, certs.intermediates, [certs.root], now).status
        == ChainStatus.TRUSTED
    )
    assert (
        assess_chain(certs.ip_leaf, certs.intermediates, [certs.root], now).status
        == ChainStatus.TRUSTED
    )


def test_certificate_without_a_tls_identity_is_incomplete(certs, now):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _issue(
        "cn-only.example.test",
        key,
        certs.intermediate2,
        certs.intermediate2_key,
        before=now - timedelta(days=1),
        after=now + timedelta(days=30),
    )
    result = assess_chain(cert, certs.intermediates, [certs.root], now)
    assert result.status == ChainStatus.INCOMPLETE
    assert "missing_identity" in result.messages


def test_no_anchors_and_no_supplied_root_is_incomplete(certs, now):
    result = assess_chain(certs.leaf, certs.intermediates, [], now)
    assert result.status == ChainStatus.INCOMPLETE
    assert "missing_issuer" in result.messages


def test_self_signed_leaf_is_an_untrusted_root(now):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _issue(
        "self.example.test",
        key,
        None,
        None,
        sans=[x509.DNSName("self.example.test")],
        before=now - timedelta(days=1),
        after=now + timedelta(days=30),
    )
    result = assess_chain(cert, [], [], now)
    assert result.status == ChainStatus.UNTRUSTED_ROOT


def test_verifier_receives_all_supplied_intermediates(certs, now):
    alternate_root_key = ec.generate_private_key(ec.SECP256R1())
    alternate_root = _issue(
        "Alternate Root",
        alternate_root_key,
        None,
        None,
        ca=True,
        key_usage=True,
        before=now - timedelta(days=1),
        after=now + timedelta(days=30),
    )
    cross_signed = _issue(
        "Fixture Intermediate 2",
        certs.intermediate2_key,
        alternate_root,
        alternate_root_key,
        ca=True,
        key_usage=True,
        before=now - timedelta(days=1),
        after=now + timedelta(days=30),
    )
    result = assess_chain(certs.leaf, [certs.intermediate2, cross_signed], [alternate_root], now)
    assert result.status == ChainStatus.TRUSTED


def test_public_bundle_is_loaded_from_the_local_package():
    from app.services.trust_anchors import public_bundle_anchors

    anchors = public_bundle_anchors()
    assert len(anchors) > 0
    assert all(isinstance(anchor, x509.Certificate) for anchor in anchors)
