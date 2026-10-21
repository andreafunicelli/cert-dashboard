from datetime import UTC, datetime, timedelta

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
    name_constraints=None,
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
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                (issuer_key if issuer_key is not None else key).public_key()
            ),
            critical=False,
        )
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
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints, critical=True)
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
        assess_chain(certs.expired, certs.intermediates, [certs.root], now).status == ChainStatus.INCOMPLETE
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
    assert assess_chain(certs.wildcard, certs.intermediates, [certs.root], now).status == ChainStatus.TRUSTED
    assert assess_chain(certs.ip_leaf, certs.intermediates, [certs.root], now).status == ChainStatus.TRUSTED


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


def test_expired_anchor_reports_a_policy_reason(certs, now):
    expired_key = ec.generate_private_key(ec.SECP256R1())
    expired_root = _issue(
        "Expired Root",
        expired_key,
        None,
        None,
        ca=True,
        key_usage=True,
        before=now - timedelta(days=90),
        after=now - timedelta(days=30),
    )
    cross = _issue(
        "Fixture Intermediate 2",
        certs.intermediate2_key,
        expired_root,
        expired_key,
        ca=True,
        key_usage=True,
        before=now - timedelta(days=1),
        after=now + timedelta(days=30),
    )
    result = assess_chain(certs.leaf, [cross], [expired_root], now)
    assert result.status == ChainStatus.INCOMPLETE
    assert "policy_failure:expired_anchor" in result.messages


def test_not_yet_valid_anchor_has_its_own_policy_reason(certs, now):
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _issue(
        "Future Root",
        root_key,
        None,
        None,
        ca=True,
        key_usage=True,
        before=now + timedelta(days=1),
        after=now + timedelta(days=90),
    )
    cross = _issue(
        "Fixture Intermediate 2",
        certs.intermediate2_key,
        root,
        root_key,
        ca=True,
        key_usage=True,
        before=now - timedelta(days=1),
        after=now + timedelta(days=30),
    )
    result = assess_chain(certs.leaf, [cross], [root], now)
    assert result.status == ChainStatus.INCOMPLETE
    assert result.messages == ("policy_failure:anchor_not_yet_valid",)


def test_name_constraints_rejection_reports_a_policy_reason(certs, now):
    constrained = _issue(
        "Fixture Intermediate 2",
        certs.intermediate2_key,
        certs.root,
        certs.root_key,
        ca=True,
        key_usage=True,
        before=now - timedelta(days=1),
        after=now + timedelta(days=30),
        name_constraints=x509.NameConstraints(
            permitted_subtrees=[x509.DNSName(".allowed.example.test")], excluded_subtrees=None
        ),
    )
    result = assess_chain(certs.leaf, [constrained], [certs.root], now)
    assert result.status == ChainStatus.INCOMPLETE
    assert result.messages == ("policy_failure:name_constraint",)


def test_intermediate_without_key_usage_reports_a_policy_reason(certs, now):
    no_usage = _issue(
        "Fixture Intermediate 2",
        certs.intermediate2_key,
        certs.root,
        certs.root_key,
        ca=True,
        key_usage=False,
        before=now - timedelta(days=1),
        after=now + timedelta(days=30),
    )
    result = assess_chain(certs.leaf, [no_usage], [certs.root], now)
    assert result.status == ChainStatus.INCOMPLETE
    assert result.messages == ("policy_failure:missing_key_usage",)


def test_leaf_without_aki_reports_a_policy_reason(certs, now):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-aki.example.test")]))
        .issuer_name(certs.intermediate2.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("no-aki.example.test")]), critical=False)
        .sign(certs.intermediate2_key, hashes.SHA256())
    )
    result = assess_chain(cert, certs.intermediates, [certs.root], now)
    assert result.status == ChainStatus.INCOMPLETE
    assert "policy_failure:missing_aki" in result.messages


def _deep_chain(length: int):
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _issue(
        "Deep Root",
        root_key,
        None,
        None,
        ca=True,
        key_usage=True,
        before=datetime(2026, 10, 19, 12, 0, tzinfo=UTC) - timedelta(days=1),
        after=datetime(2026, 10, 19, 12, 0, tzinfo=UTC) + timedelta(days=30),
    )
    intermediates = []
    previous, previous_key = root, root_key
    for index in range(1, length + 1):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _issue(
            f"Deep Intermediate {index}",
            key,
            previous,
            previous_key,
            ca=True,
            key_usage=True,
            before=datetime(2026, 10, 19, 12, 0, tzinfo=UTC) - timedelta(days=1),
            after=datetime(2026, 10, 19, 12, 0, tzinfo=UTC) + timedelta(days=30),
        )
        intermediates.append(cert)
        previous, previous_key = cert, key
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _issue(
        "deep.example.test",
        leaf_key,
        previous,
        previous_key,
        sans=[x509.DNSName("deep.example.test")],
        before=datetime(2026, 10, 19, 12, 0, tzinfo=UTC) - timedelta(days=1),
        after=datetime(2026, 10, 19, 12, 0, tzinfo=UTC) + timedelta(days=30),
    )
    return leaf, intermediates


def test_structurally_truncated_chain_reports_chain_truncated(now):
    leaf, intermediates = _deep_chain(17)
    result = assess_chain(leaf, intermediates, [], now)
    assert result.status == ChainStatus.INCOMPLETE
    assert "chain_truncated" in result.messages
