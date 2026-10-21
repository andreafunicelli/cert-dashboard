import logging
import warnings
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

PASSWORD = "chosen-pass-123"


def _tlv(tag, value):
    size = len(value)
    width = (size.bit_length() + 7) // 8
    length = bytes([size]) if size < 128 else bytes([128 + width]) + size.to_bytes(width, "big")
    return bytes([tag]) + length + value


def _sequence(*values):
    return _tlv(0x30, b"".join(values))


def _oid(hex_bytes):
    return _tlv(6, bytes.fromhex(hex_bytes))


def _data(value):
    return _sequence(_oid("2a864886f70d010701"), _tlv(0xA0, _tlv(4, value)))


def _raw_pfx(keys, certificates):
    """Minimal valid, unencrypted PKCS#12 bags, generated entirely in memory."""
    bags = [
        _sequence(
            _oid("2a864886f70d010c0a0101"),
            _tlv(
                0xA0,
                key.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            ),
        )
        for key in keys
    ]
    bags.extend(
        _sequence(
            _oid("2a864886f70d010c0a0103"),
            _tlv(
                0xA0,
                _sequence(
                    _oid("2a864886f70d01091601"),
                    _tlv(0xA0, _tlv(4, cert.public_bytes(serialization.Encoding.DER))),
                ),
            ),
        )
        for cert in certificates
    )
    return _sequence(_tlv(2, b"\x03"), _data(_sequence(_data(_sequence(*bags)))))


def _self_signed(key, now, cn="fixture.example.test"):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


@pytest.mark.parametrize("algorithm", ["rsa", "ecdsa"])
def test_roundtrip_normalizes_chain_excludes_root_and_preserves_key(certs, algorithm):
    from app.crypto.keys import public_key_sha256
    from app.crypto.pfx import build_pfx, read_pfx

    key, leaf = (certs.leaf_key, certs.leaf) if algorithm == "rsa" else (certs.ecdsa_key, certs.ecdsa_leaf)
    cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    data = build_pfx(
        key, leaf, [certs.root, certs.intermediate1, certs.intermediate2, certs.intermediate2], PASSWORD, cn
    )
    loaded = read_pfx(data, PASSWORD)
    assert loaded.leaf == leaf and loaded.chain == certs.intermediates
    assert public_key_sha256(loaded.key.public_key()) == public_key_sha256(key.public_key())
    with pytest.raises(ValueError):
        pkcs12.load_key_and_certificates(data, None)
    with pytest.raises(ValueError):
        pkcs12.load_key_and_certificates(data, b"wrong-password")
    assert pkcs12.load_pkcs12(data, PASSWORD.encode()).cert.friendly_name == cn.encode()
    # Defaults must retain modern export encryption even after importing legacy bundles.
    assert bytes.fromhex("60864801650304012a") in data  # aes256-CBC OID
    assert bytes.fromhex("2a864886f70d010c0103") not in data  # legacy SHA1+3DES PBE


def test_wrong_password_is_actionable_and_does_not_echo_input(certs):
    from app.crypto.pfx import PFXError, build_pfx, read_pfx

    data = build_pfx(certs.leaf_key, certs.leaf, certs.intermediates, PASSWORD, "leaf.example.test")
    with pytest.raises(PFXError, match="password") as exc:
        read_pfx(data, "fixture-wrong-password")
    assert exc.value.code == "invalid_password_or_bundle"
    assert "fixture-wrong-password" not in str(exc.value) and PASSWORD not in str(exc.value)


@pytest.mark.parametrize("password", ["", "short", "x" * 11])
def test_export_rejects_passwords_shorter_than_twelve_characters(certs, password):
    from app.crypto.pfx import PFXError, build_pfx

    with pytest.raises(PFXError) as exc:
        build_pfx(certs.leaf_key, certs.leaf, [], password, "leaf.example.test")
    assert exc.value.code == "weak_password" and "12" in str(exc.value)


def test_twelve_unicode_characters_and_utf8_cn_are_supported(certs, now):
    from app.crypto.pfx import build_pfx, read_pfx

    leaf = _self_signed(certs.leaf_key, now, "bücher.example.test")
    password = "é" * 12
    data = build_pfx(certs.leaf_key, leaf, [], password, "bücher.example.test")
    assert read_pfx(data, password).leaf == leaf
    assert pkcs12.load_pkcs12(data, password.encode()).cert.friendly_name == "bücher.example.test".encode()


@pytest.mark.parametrize("data", [b"", b"fixture-not-a-pfx", b"\x30\x82\xff", "fixture-text", None])
def test_malformed_pfx_always_raises_typed_error(data):
    from app.crypto.pfx import PFXError, read_pfx

    with pytest.raises(PFXError) as exc:
        read_pfx(data, None)
    assert exc.value.code == "invalid_password_or_bundle"
    assert "fixture-" not in str(exc.value)


def test_oversize_is_rejected_before_the_crypto_loader(monkeypatch):
    from app.crypto.pfx import PFXError, read_pfx

    def must_not_load(*args):
        pytest.fail("oversized upload reached PKCS#12 loader")

    monkeypatch.setattr(pkcs12, "load_key_and_certificates", must_not_load)
    with pytest.raises(PFXError) as exc:
        read_pfx(b"x" * 1_048_577, None)
    assert exc.value.code == "too_large"


def test_keyless_bundle_chooses_unique_end_entity_and_orders_chain(certs):
    from app.crypto.pfx import read_pfx

    data = pkcs12.serialize_key_and_certificates(
        None,
        None,
        None,
        [certs.root, certs.intermediate1, certs.leaf, certs.intermediate2],
        serialization.BestAvailableEncryption(PASSWORD.encode()),
    )
    result = read_pfx(data, PASSWORD)
    assert result.key is None and result.leaf == certs.leaf and result.chain == certs.intermediates


def test_keyless_certificate_cap_counts_the_selected_leaf_once(certs):
    from app.crypto.pfx import PFXError, read_pfx

    assert read_pfx(_raw_pfx([], [certs.leaf] + [certs.root] * 31), None).leaf == certs.leaf
    with pytest.raises(PFXError) as exc:
        read_pfx(_raw_pfx([], [certs.leaf] + [certs.root] * 32), None)
    assert exc.value.code == "invalid_chain"


@pytest.mark.parametrize("contents", ["key_only", "root_only", "two_leaves"])
def test_missing_or_ambiguous_leaf_is_rejected(certs, contents):
    from app.crypto.pfx import PFXError, read_pfx

    keys = [certs.leaf_key] if contents == "key_only" else []
    certificates = (
        []
        if contents == "key_only"
        else [certs.root]
        if contents == "root_only"
        else [certs.leaf, certs.ecdsa_leaf]
    )
    with pytest.raises(PFXError) as exc:
        read_pfx(_raw_pfx(keys, certificates), None)
    assert exc.value.code == ("ambiguous_certificate" if contents == "two_leaves" else "missing_certificate")


def test_real_mismatched_bundle_is_rejected(certs):
    from app.crypto.pfx import PFXError, read_pfx

    with pytest.raises(PFXError) as exc:
        read_pfx(_raw_pfx([certs.ecdsa_key], [certs.leaf]), None)
    assert exc.value.code == "key_mismatch"


def test_two_key_loader_selection_is_never_accepted_without_spki_match(certs):
    from app.crypto.keys import public_key_sha256
    from app.crypto.pfx import PFXError, read_pfx

    data = _raw_pfx([certs.leaf_key, certs.ecdsa_key], [certs.leaf])
    try:
        result = read_pfx(data, None)
    except PFXError as exc:
        assert exc.code in {"key_mismatch", "invalid_password_or_bundle"}
    else:
        assert result.leaf == certs.leaf
        assert public_key_sha256(result.key.public_key()) == public_key_sha256(certs.leaf.public_key())


@pytest.mark.parametrize("kind", ["rsa1024", "rsa_e3", "ec521"])
def test_import_reuses_key_size_exponent_and_curve_rules(certs, now, kind):
    from app.crypto.pfx import PFXError, read_pfx

    key = (
        ec.generate_private_key(ec.SECP521R1())
        if kind == "ec521"
        else rsa.generate_private_key(
            public_exponent=3 if kind == "rsa_e3" else 65537,
            key_size=2048 if kind == "rsa_e3" else 1024,
        )
    )
    leaf = _self_signed(key, now)
    data = pkcs12.serialize_key_and_certificates(None, key, leaf, [], serialization.NoEncryption())
    with pytest.raises(PFXError) as exc:
        read_pfx(data, None)
    assert exc.value.code == "unsupported_key" and "65537" in str(exc.value)


def test_legacy_3des_import_does_not_change_export_defaults(certs):
    from app.crypto.pfx import build_pfx, read_pfx

    legacy = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(1000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(PASSWORD.encode())
    )
    data = pkcs12.serialize_key_and_certificates(
        None, certs.leaf_key, certs.leaf, list(certs.intermediates), legacy
    )
    assert bytes.fromhex("2a864886f70d010c0103") in data
    loaded = read_pfx(data, PASSWORD)
    modern = build_pfx(loaded.key, loaded.leaf, loaded.chain, PASSWORD, "leaf.example.test")
    assert (
        bytes.fromhex("60864801650304012a") in modern and bytes.fromhex("2a864886f70d010c0103") not in modern
    )


def test_unsupported_encryption_has_offline_reexport_hint(monkeypatch):
    from app.crypto.pfx import PFXError, read_pfx

    def unsupported(*args):
        raise UnsupportedAlgorithm("fixture-backend-private-details")

    monkeypatch.setattr(pkcs12, "load_key_and_certificates", unsupported)
    with pytest.raises(PFXError) as exc:
        read_pfx(b"fixture", "fixture-password")
    assert exc.value.code == "unsupported_encryption"
    assert "offline" in str(exc.value).lower() and "AES" in str(exc.value)
    assert "fixture-" not in str(exc.value)


@pytest.mark.parametrize("failure", ["mismatch", "missing_leaf", "wrong_name", "forged_chain"])
def test_export_validation_failures_are_typed_and_never_log_secrets(certs, failure, monkeypatch, caplog):
    from app.crypto.chain import ChainError
    from app.crypto.pfx import PFXError, build_pfx

    def forged(*args):
        raise ChainError("fixture-private-chain-details")

    if failure == "forged_chain":
        monkeypatch.setattr("app.crypto.pfx.order_chain", forged)
    key = certs.ecdsa_key if failure == "mismatch" else certs.leaf_key
    leaf = None if failure == "missing_leaf" else certs.leaf
    name = "wrong.example.test" if failure == "wrong_name" else "leaf.example.test"
    with caplog.at_level(logging.DEBUG), pytest.raises(PFXError):
        build_pfx(key, leaf, certs.intermediates, PASSWORD, name)
    assert PASSWORD not in caplog.text and "PRIVATE KEY" not in caplog.text
    assert "fixture-private" not in caplog.text


@pytest.mark.parametrize("operation", ["import", "export"])
def test_ca_certificate_with_private_key_is_never_a_pfx_leaf(certs, operation):
    from app.crypto.pfx import PFXError, build_pfx, read_pfx

    with pytest.raises(PFXError) as exc:
        if operation == "import":
            data = pkcs12.serialize_key_and_certificates(
                None, certs.root_key, certs.root, [], serialization.NoEncryption()
            )
            read_pfx(data, None)
        else:
            build_pfx(certs.root_key, certs.root, [], PASSWORD, "Fixture Root")
    assert exc.value.code == "invalid_leaf"
    assert str(exc.value) == "PFX certificate must be an end-entity certificate."


@pytest.mark.parametrize("operation", ["import", "export"])
@pytest.mark.parametrize("constraints", ["ca_false", "absent"])
def test_intermediate_must_explicitly_be_a_ca(certs, now, operation, constraints):
    from app.crypto.pfx import PFXError, build_pfx, read_pfx

    mid_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture Invalid Mid")])
    mid_builder = (
        x509.CertificateBuilder()
        .subject_name(mid_name)
        .issuer_name(certs.root.subject)
        .public_key(certs.intermediate1_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
    )
    if constraints == "ca_false":
        mid_builder = mid_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
    mid = mid_builder.sign(certs.root_key, hashes.SHA256())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.example.test")]))
        .issuer_name(mid.subject)
        .public_key(certs.leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .sign(certs.intermediate1_key, hashes.SHA256())
    )
    with pytest.raises(PFXError) as exc:
        if operation == "import":
            read_pfx(_raw_pfx([certs.leaf_key], [leaf, mid, certs.root]), None)
        else:
            build_pfx(certs.leaf_key, leaf, [mid, certs.root], PASSWORD, "fixture.example.test")
    assert exc.value.code == "invalid_chain"


@pytest.mark.parametrize("password", [None, b"fixture-password"])
def test_export_nontext_password_has_invalid_password_error(certs, password):
    from app.crypto.pfx import PFXError, build_pfx

    with pytest.raises(PFXError) as exc:
        build_pfx(certs.leaf_key, certs.leaf, [], password, "leaf.example.test")
    assert exc.value.code == "invalid_password"


def test_ber_fallback_warning_is_suppressed_and_error_stays_typed(monkeypatch):
    from app.crypto.pfx import PFXError, read_pfx

    def ber_fallback(*args):
        warnings.warn("fixture-BER-fallback-backend-details", UserWarning, stacklevel=2)
        raise ValueError("fixture-private-parse-error")

    monkeypatch.setattr(pkcs12, "load_key_and_certificates", ber_fallback)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(PFXError) as exc:
            read_pfx(b"fixture-malformed", None)
    assert exc.value.code == "invalid_password_or_bundle"
    assert not caught and "fixture-" not in str(exc.value)
