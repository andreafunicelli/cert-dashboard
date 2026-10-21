import hashlib
import os
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.crypto.chain import ChainError, fullchain_pem, order_chain
from app.crypto.parse import ParseError, parse_certificates

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _issue(
    subject_cn: str,
    key,
    issuer: x509.Certificate | None,
    issuer_key,
    *,
    sans=(),
    ca: bool = False,
) -> x509.Certificate:
    subject = _name(subject_cn)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(list(sans)), critical=False)
    return builder.sign(issuer_key if issuer_key is not None else key, hashes.SHA256())


def _fp(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _spki(cert: x509.Certificate) -> str:
    return hashlib.sha256(
        cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()


def test_parse_pem_der_leading_text_crlf_and_multiple(certs):
    leaf_pem = certs.leaf.public_bytes(serialization.Encoding.PEM)
    second_pem = certs.intermediate2.public_bytes(serialization.Encoding.PEM)
    payload = b"preamble text\r\n" + leaf_pem.replace(b"\n", b"\r\n") + second_pem
    parsed = parse_certificates(payload)
    assert [item.sha256_fingerprint for item in parsed] == [_fp(certs.leaf), _fp(certs.intermediate2)]
    der = parse_certificates(certs.leaf.public_bytes(serialization.Encoding.DER))
    assert der[0].sha256_fingerprint == _fp(certs.leaf)


def test_parsed_fields_fingerprints_and_sans(certs):
    parsed = parse_certificates(certs.leaf.public_bytes(serialization.Encoding.PEM))[0]
    assert parsed.common_name == "leaf.example.test"
    assert parsed.subject_dn == certs.leaf.subject.rfc4514_string()
    assert parsed.issuer_dn == certs.leaf.issuer.rfc4514_string()
    assert parsed.issuer_cn == "Fixture Intermediate 2"
    assert parsed.serial == format(certs.leaf.serial_number, "x")
    assert parsed.not_before == certs.leaf.not_valid_before_utc
    assert parsed.not_after == certs.leaf.not_valid_after_utc
    assert parsed.sha256_fingerprint == hashlib.sha256(
        certs.leaf.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    assert parsed.public_key_sha256 == _spki(certs.leaf)
    assert parsed.pem.startswith("-----BEGIN CERTIFICATE-----")
    assert parsed.sans == (
        "leaf.example.test",
        "fixture@example.test",
        "https://leaf.example.test/status",
    )
    wildcard = parse_certificates(certs.wildcard.public_bytes(serialization.Encoding.PEM))[0]
    assert wildcard.sans == ("*.example.test",)
    address = parse_certificates(certs.ip_leaf.public_bytes(serialization.Encoding.PEM))[0]
    assert address.sans == ("192.0.2.10", "2001:db8::10")


def test_cn_falls_back_to_first_san(certs):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "No CN")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(certs.intermediate2.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("fallback.example.test"), x509.DNSName("second.example.test")]
            ),
            critical=False,
        )
        .sign(certs.intermediate2_key, hashes.SHA256())
    )
    parsed = parse_certificates(cert.public_bytes(serialization.Encoding.PEM))[0]
    assert parsed.common_name == "fallback.example.test"


def test_serial_is_lowercase_hex_without_leading_zeros(certs):
    parsed = parse_certificates(certs.leaf.public_bytes(serialization.Encoding.PEM))[0]
    assert parsed.serial == parsed.serial.lower()
    assert not parsed.serial.startswith("0") or parsed.serial == "0"


@pytest.mark.parametrize(
    "raw",
    [
        b"hello",
        b"-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----",
        b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----",
        b"",
    ],
)
def test_garbage_is_typed(raw):
    with pytest.raises(ParseError):
        parse_certificates(raw)


def test_mixed_certificate_and_key_blocks_are_rejected(certs):
    payload = (
        certs.leaf.public_bytes(serialization.Encoding.PEM)
        + b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"
    )
    with pytest.raises(ParseError):
        parse_certificates(payload)


def test_oversized_input_is_rejected_before_parsing():
    with pytest.raises(ParseError, match="1 MiB"):
        parse_certificates(b"x" * 1_048_577)
    with pytest.raises(ParseError):
        parse_certificates(b"x" * 1_048_576)


def test_unusual_san_falls_back_to_lenient_parsing(certs):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _issue(
        "Odd San Leaf",
        key,
        certs.intermediate2,
        certs.intermediate2_key,
        sans=[x509.DNSName("bad_name.example.test")],
    )
    parsed = parse_certificates(cert.public_bytes(serialization.Encoding.PEM))[0]
    assert parsed.sans == ("bad_name.example.test",)


def test_reverse_chain_and_root_removal(certs):
    result = order_chain(
        certs.leaf, [certs.root, certs.intermediate1, certs.intermediate2, certs.root]
    )
    assert result.fingerprints == (certs.intermediate2_fp, certs.intermediate1_fp)
    assert "root" in result.dropped and "duplicate" in result.dropped
    missing = order_chain(certs.leaf, [certs.intermediate1])
    assert missing.missing_issuer == certs.intermediate2.subject.rfc4514_string()
    assert result.diagnostic_roots == (certs.root,)
    assert result.missing_issuer is None
    assert result.pem.count("-----BEGIN CERTIFICATE-----") == 2


def test_non_root_top_intermediate_may_omit_root(certs):
    result = order_chain(certs.leaf, [certs.intermediate1, certs.intermediate2])
    assert result.fingerprints == (certs.intermediate2_fp, certs.intermediate1_fp)
    assert result.missing_issuer == certs.root.subject.rfc4514_string()
    assert result.diagnostic_roots == ()


def test_unrelated_certificate_is_dropped(certs):
    other_root_key = ec.generate_private_key(ec.SECP256R1())
    other_root = _issue("Other Root", other_root_key, None, None, ca=True)
    unrelated = _issue("Unrelated Leaf", ec.generate_private_key(ec.SECP256R1()), other_root, other_root_key)
    result = order_chain(certs.leaf, [certs.intermediate2, certs.intermediate1, unrelated])
    assert result.fingerprints == (certs.intermediate2_fp, certs.intermediate1_fp)
    assert "unrelated" in result.dropped
    assert _fp(unrelated) not in result.fingerprints


def test_forged_claimed_issuer_is_rejected(certs):
    forged_key = ec.generate_private_key(ec.SECP256R1())
    forged = _issue(
        "Fixture Intermediate 2", forged_key, certs.intermediate1, certs.intermediate1_key, ca=True
    )
    with pytest.raises(ChainError):
        order_chain(certs.leaf, [forged])


def test_cross_signed_ambiguity_is_deterministic(certs):
    other_root_key = ec.generate_private_key(ec.SECP256R1())
    other_root = _issue("Other Root", other_root_key, None, None, ca=True)
    cross = _issue(
        "Fixture Intermediate 2", certs.intermediate2_key, other_root, other_root_key, ca=True
    )
    first = order_chain(certs.leaf, [certs.intermediate2, cross])
    second = order_chain(certs.leaf, [cross, certs.intermediate2])
    assert first.fingerprints == second.fingerprints
    assert first.fingerprints[0] == min(_fp(certs.intermediate2), _fp(cross))
    assert "cross-sign" in first.dropped


def test_forged_root_claiming_the_issuer_is_rejected(certs):
    fake_root_key = ec.generate_private_key(ec.SECP256R1())
    fake_root = _issue("Fixture Root", fake_root_key, None, None, ca=True)
    with pytest.raises(ChainError):
        order_chain(certs.leaf, [certs.intermediate2, certs.intermediate1, fake_root])


def test_self_signed_leaf_and_cycles_terminate(certs):
    self_key = ec.generate_private_key(ec.SECP256R1())
    self_leaf = _issue("Self Leaf", self_key, None, None)
    result = order_chain(self_leaf, [])
    assert result.fingerprints == ()
    assert result.missing_issuer is None
    assert result.diagnostic_roots == ()

    a_key = ec.generate_private_key(ec.SECP256R1())
    b_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("Cycle Leaf"))
        .issuer_name(_name("Cycle A"))
        .public_key(a_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(a_key, hashes.SHA256())
    )
    a = (
        x509.CertificateBuilder()
        .subject_name(_name("Cycle A"))
        .issuer_name(_name("Cycle B"))
        .public_key(a_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(b_key, hashes.SHA256())
    )
    b = (
        x509.CertificateBuilder()
        .subject_name(_name("Cycle B"))
        .issuer_name(_name("Cycle A"))
        .public_key(b_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(a_key, hashes.SHA256())
    )
    cycled = order_chain(leaf, [a, b])
    assert cycled.fingerprints == (_fp(a), _fp(b))
    assert "cycle" in cycled.dropped
    assert cycled.missing_issuer == "CN=Cycle A"


def test_fullchain_pem_normalizes_and_rejects_empty(certs):
    leaf_pem = parse_certificates(certs.leaf.public_bytes(serialization.Encoding.PEM))[0].pem
    chain_pem = "".join(
        item.pem
        for item in parse_certificates(
            certs.intermediate2.public_bytes(serialization.Encoding.PEM)
            + certs.intermediate1.public_bytes(serialization.Encoding.PEM)
        )
    )
    assert fullchain_pem(leaf_pem, chain_pem) == leaf_pem + chain_pem
    assert fullchain_pem(leaf_pem, "") == leaf_pem
    with pytest.raises(ChainError):
        fullchain_pem("", "")


def test_hostile_inputs_never_raise_unhandled(certs):
    der = certs.leaf.public_bytes(serialization.Encoding.DER)
    for _ in range(300):
        payload = os.urandom(1 + len(der) % 64)
        try:
            parse_certificates(payload)
        except ParseError:
            pass
    for cut in range(0, len(der), 5):
        try:
            parse_certificates(der[:cut])
        except ParseError:
            pass
    for index in range(0, len(der), 7):
        mutated = bytearray(der)
        mutated[index] ^= 0xFF
        try:
            parse_certificates(bytes(mutated))
        except ParseError:
            pass


def test_truncated_stray_or_trailing_pem_junk_is_rejected(certs):
    leaf = certs.leaf.public_bytes(serialization.Encoding.PEM)
    intermediate = certs.intermediate2.public_bytes(serialization.Encoding.PEM)
    der = certs.intermediate2.public_bytes(serialization.Encoding.DER)
    for payload in (leaf + intermediate[:120], leaf + b"-----END CERTIFICATE-----", leaf + der):
        with pytest.raises(ParseError):
            parse_certificates(payload)


def test_complete_cross_signed_path_beats_a_lower_fingerprint_dead_end(certs):
    for _ in range(50):
        root_a_key = ec.generate_private_key(ec.SECP256R1())
        root_a = _issue("Cross Root A", root_a_key, None, None, ca=True)
        root_b_key = ec.generate_private_key(ec.SECP256R1())
        root_b = _issue("Cross Root B", root_b_key, None, None, ca=True)
        intermediate_a = _issue(
            "Fixture Intermediate 2", certs.intermediate2_key, root_a, root_a_key, ca=True
        )
        intermediate_b = _issue(
            "Fixture Intermediate 2", certs.intermediate2_key, root_b, root_b_key, ca=True
        )
        if _fp(intermediate_b) < _fp(intermediate_a):
            break
    else:
        pytest.fail("could not build a lower-fingerprint dead-end candidate")

    result = order_chain(certs.leaf, [root_a, intermediate_a, intermediate_b])
    assert result.fingerprints == (_fp(intermediate_a),)
    assert result.missing_issuer is None
    assert result.alternates == (_fp(intermediate_b),)
    assert "cross-sign" in result.dropped


def test_two_supplied_roots_and_a_duplicate_leaf(certs):
    other_root_key = ec.generate_private_key(ec.SECP256R1())
    other_root = _issue("Other Root", other_root_key, None, None, ca=True)
    result = order_chain(
        certs.leaf,
        [
            certs.intermediate2,
            certs.intermediate1,
            certs.root,
            other_root,
            certs.leaf,
            certs.leaf,
        ],
    )
    assert result.fingerprints == (certs.intermediate2_fp, certs.intermediate1_fp)
    assert "root" in result.dropped
    assert "duplicate" in result.dropped
    assert {_fp(root) for root in result.diagnostic_roots} == {
        _fp(certs.root),
        _fp(other_root),
    }


def test_thirty_cross_sign_candidates_finish_quickly(certs):
    import time

    candidates = []
    for index in range(30):
        root_key = ec.generate_private_key(ec.SECP256R1())
        root = _issue(f"Fast Root {index}", root_key, None, None, ca=True)
        candidates.append(
            _issue("Fixture Intermediate 2", certs.intermediate2_key, root, root_key, ca=True)
        )
    started = time.monotonic()
    result = order_chain(certs.leaf, candidates)
    assert time.monotonic() - started < 0.5
    assert len(result.fingerprints) == 1
    assert len(result.alternates) == 29
    assert result.missing_issuer is not None


def _deep_chain(length: int):
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _issue("Deep Root", root_key, None, None, ca=True)
    intermediates = []
    previous, previous_key = root, root_key
    for index in range(1, length + 1):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _issue(f"Deep Intermediate {index}", key, previous, previous_key, ca=True)
        intermediates.append(cert)
        previous, previous_key = cert, key
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _issue(
        "deep.example.test",
        leaf_key,
        previous,
        previous_key,
        sans=[x509.DNSName("deep.example.test")],
    )
    return leaf, intermediates, root


def test_parse_rejects_more_than_32_certificates_before_decoding(certs):
    pem = certs.leaf.public_bytes(serialization.Encoding.PEM)
    with pytest.raises(ParseError, match="32"):
        parse_certificates(pem * 33)
    assert len(parse_certificates(pem * 32)) == 32


def test_thirty_two_same_subject_candidates_are_fast(certs):
    import time

    missing_key = ec.generate_private_key(ec.SECP256R1())
    missing_root = _issue("Missing Root", missing_key, None, None, ca=True)
    candidates = [
        _issue("Fixture Intermediate 2", certs.intermediate2_key, missing_root, missing_key, ca=True)
        for _ in range(32)
    ]
    started = time.monotonic()
    result = order_chain(certs.leaf, candidates)
    assert time.monotonic() - started < 0.2
    assert len(result.fingerprints) == 1
    assert len(result.alternates) == 31


def test_sixteen_hundred_direct_candidates_finish_under_a_second(certs):
    import time

    missing_key = ec.generate_private_key(ec.SECP256R1())
    missing_root = _issue("Missing Root", missing_key, None, None, ca=True)
    candidates = [
        _issue("Fixture Intermediate 2", certs.intermediate2_key, missing_root, missing_key, ca=True)
        for _ in range(1600)
    ]
    started = time.monotonic()
    result = order_chain(certs.leaf, candidates)
    assert time.monotonic() - started < 1.0
    assert len(result.fingerprints) == 1
    assert len(result.alternates) == 1599


def test_depth_limit_reports_truncation_without_a_missing_issuer():
    leaf, intermediates, root = _deep_chain(17)
    result = order_chain(leaf, [*intermediates, root])
    assert result.truncated is True
    assert result.missing_issuer is None
    assert "depth-limit" in result.dropped
    assert len(result.fingerprints) == 16


def test_twelve_intermediates_complete_without_truncation():
    leaf, intermediates, root = _deep_chain(12)
    result = order_chain(leaf, [*intermediates, root])
    assert result.truncated is False
    assert result.missing_issuer is None
    assert "root" in result.dropped
    assert len(result.fingerprints) == 12
