import hashlib
from ipaddress import ip_address

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID


@pytest.mark.parametrize("size", [2048, 3072, 4096])
def test_rsa_generation_and_csr_signature_are_independently_verified(size):
    from app.crypto.csr import build_csr
    from app.crypto.keys import KeySpec, generate_key

    key = generate_key(KeySpec(size=size))
    result = build_csr(key, "*.Example.TEST", ["*.example.test", "192.0.2.1"])
    csr = x509.load_pem_x509_csr(result.pem.encode())
    assert key.key_size == size and key.public_key().public_numbers().e == 65537
    assert csr.is_signature_valid and csr.signature_hash_algorithm.name == "sha256"
    key.public_key().verify(csr.signature, csr.tbs_certrequest_bytes, padding.PKCS1v15(), hashes.SHA256())
    assert csr.subject == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.example.test")])
    assert result.sha256 == hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest()


def test_default_key_is_rsa2048():
    from app.crypto.keys import KeySpec, generate_key

    key = generate_key(KeySpec())
    assert isinstance(key, rsa.RSAPrivateKey) and key.key_size == 2048


@pytest.mark.parametrize(
    "curve,size",
    [
        (None, 256),
        ("prime256v1", 256),
        ("secp256r1", 256),
        ("P-256", 256),
        ("secp384r1", 384),
        ("P-384", 384),
    ],
)
def test_ecdsa_curves_and_csr_signature(curve, size):
    from app.crypto.csr import build_csr
    from app.crypto.keys import KeySpec, generate_key

    key = generate_key(KeySpec(kind="ecdsa", curve=curve))
    csr = x509.load_pem_x509_csr(build_csr(key, "ec.example.test", ["ec.example.test"]).pem.encode())
    assert isinstance(key, ec.EllipticCurvePrivateKey) and key.key_size == size
    assert csr.is_signature_valid and csr.signature_hash_algorithm.name == "sha256"
    key.public_key().verify(csr.signature, csr.tbs_certrequest_bytes, ec.ECDSA(hashes.SHA256()))
    assert generate_key(KeySpec(kind="ecdsa", size=size, curve=curve)).key_size == size


@pytest.mark.parametrize(
    "arguments",
    [
        {"size": 1024},
        {"size": 8192},
        {"size": True},
        {"kind": "ed25519"},
        {"curve": "secp256r1"},
        {"kind": "ecdsa", "curve": "secp521r1"},
        {"kind": "ecdsa", "curve": "prime256v1", "size": 384},
        {"kind": "ecdsa", "curve": "secp384r1", "size": 256},
    ],
)
def test_unsupported_or_conflicting_key_specs_are_rejected(arguments):
    from app.crypto.keys import KeySpec, generate_key

    with pytest.raises(ValueError):
        generate_key(KeySpec(**arguments))


def test_typed_sans_are_preserved_normalized_and_cn_is_added_once(certs):
    from app.crypto.csr import build_csr, canonical_sans, validate_csr
    from app.crypto.keys import public_key_sha256

    supplied = [
        "DNS:ALT.Example.TEST",
        "IP:192.0.2.1",
        "2001:0db8::1",
        "email:Operator@EXAMPLE.TEST",
        "URI:https://Example.TEST/Case",
        "alt.example.test",
    ]
    assert canonical_sans(supplied) == (
        "alt.example.test",
        "192.0.2.1",
        "2001:db8::1",
        "email:Operator@EXAMPLE.TEST",
        "URI:https://Example.TEST/Case",
    )
    result = build_csr(certs.leaf_key, "PRIMARY.EXAMPLE.TEST", supplied)
    csr = x509.load_pem_x509_csr(result.pem.encode())
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["alt.example.test", "primary.example.test"]
    assert san.get_values_for_type(x509.IPAddress) == [ip_address("192.0.2.1"), ip_address("2001:db8::1")]
    assert san.get_values_for_type(x509.RFC822Name) == ["Operator@EXAMPLE.TEST"]
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == ["https://Example.TEST/Case"]
    assert (
        validate_csr(
            result.pem,
            "primary.example.test",
            list(reversed(supplied)),
            public_key_sha256(certs.leaf_key.public_key()),
        )
        == []
    )
    again = build_csr(
        certs.leaf_key, "PRIMARY.EXAMPLE.TEST", ["primary.example.test", "DNS:PRIMARY.EXAMPLE.TEST"]
    )
    assert (
        len(
            x509.load_pem_x509_csr(again.pem.encode())
            .extensions.get_extension_for_class(x509.SubjectAlternativeName)
            .value
        )
        == 1
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ("BÜCHER.Example", "xn--bcher-kva.example"),
        ("faß.example", "xn--fa-hia.example"),
        ("XN--BCHER-KVA.EXAMPLE", "xn--bcher-kva.example"),
        ("*.BÜCHER.Example", "*.xn--bcher-kva.example"),
    ],
)
def test_dns_idna_is_nontransitional_and_canonical(value, expected):
    from app.crypto.csr import parse_san

    assert parse_san(value) == x509.DNSName(expected)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "bad name.test",
        "bad_name.test",
        "-bad.test",
        "bad-.test",
        "bad..test",
        "bad.*.test",
        "f*oo.test",
        "*.*.test",
        "*",
        "bad.test.",
        "xn--.test",
        "a" * 64 + ".test",
        ".".join(["a" * 63] * 4),
        "999.1.1.1",
        "IP:invalid",
        "DNS:192.0.2.1",
        "fe80::1%eth0",
        "email:bad",
        "URI:relative/path",
    ],
)
def test_invalid_sans_are_rejected(value):
    from app.crypto.csr import parse_san

    with pytest.raises(ValueError):
        parse_san(value)


def test_dns_label_and_total_length_boundaries(certs):
    from app.crypto.csr import build_csr, parse_san

    longest = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
    assert len(longest) == 253 and parse_san(longest).value == longest
    assert build_csr(certs.leaf_key, "primary.example.test", [longest]).pem.startswith(
        "-----BEGIN CERTIFICATE REQUEST-----"
    )
    with pytest.raises(ValueError):
        parse_san(longest + "e")


def test_empty_and_overfull_san_lists_are_rejected_before_and_after_cn_inclusion(certs):
    from app.crypto.csr import build_csr, canonical_sans

    for values in [[], [f"n{i}.example.test" for i in range(101)]]:
        with pytest.raises(ValueError):
            canonical_sans(values)
    hundred = [f"n{i}.example.test" for i in range(100)]
    assert build_csr(certs.leaf_key, hundred[0], hundred).pem
    for values in [[], hundred]:
        with pytest.raises(ValueError):
            build_csr(certs.leaf_key, "missing.example.test", values)


@pytest.mark.parametrize("common_name", ["192.0.2.5", "2001:0db8::5"])
def test_ip_common_name_is_also_an_ip_san(certs, common_name):
    from app.crypto.csr import build_csr

    csr = x509.load_pem_x509_csr(build_csr(certs.leaf_key, common_name, ["alt.example.test"]).pem.encode())
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.IPAddress) == [ip_address(common_name)]
    assert san.get_values_for_type(x509.DNSName) == ["alt.example.test"]


@pytest.mark.parametrize("kind", ["rsa", "ecdsa"])
def test_spki_identity_survives_public_and_private_encodings_and_changes_with_key(certs, kind):
    from app.crypto.keys import public_key_sha256

    key = certs.leaf_key if kind == "rsa" else certs.ecdsa_key
    pub = key.public_key()
    spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    expected = hashlib.sha256(spki).hexdigest()
    loaded = [pub, serialization.load_der_public_key(spki)]
    public_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    loaded.append(serialization.load_pem_public_key(public_pem))
    for encoding in [serialization.Encoding.DER, serialization.Encoding.PEM]:
        for form in [serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.TraditionalOpenSSL]:
            raw = key.private_bytes(encoding, form, serialization.NoEncryption())
            loader = (
                serialization.load_der_private_key
                if encoding == serialization.Encoding.DER
                else serialization.load_pem_private_key
            )
            loaded.append(loader(raw, password=None).public_key())
    assert {public_key_sha256(item) for item in loaded} == {expected}
    other = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if kind == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    assert public_key_sha256(other.public_key()) != expected


def test_validate_csr_reports_subject_san_and_key_mismatches_together(certs):
    from app.crypto.csr import build_csr, validate_csr
    from app.crypto.keys import public_key_sha256

    result = build_csr(certs.leaf_key, "leaf.example.test", ["leaf.example.test"])
    errors = validate_csr(
        result.pem,
        "other.example.test",
        ["other.example.test"],
        public_key_sha256(certs.ecdsa_key.public_key()),
    )
    assert set(errors) == {
        "CSR subject does not match CN-only identity",
        "CSR SANs do not match",
        "CSR public key does not match",
    }


@pytest.mark.parametrize("wrong", ["same_rsa", "rsa_size", "ec_curve"])
def test_validate_csr_rejects_same_algorithm_and_size_or_curve_mismatches(certs, wrong):
    from app.crypto.csr import build_csr, validate_csr
    from app.crypto.keys import public_key_sha256

    key = certs.ecdsa_key if wrong == "ec_curve" else certs.leaf_key
    other = (
        ec.generate_private_key(ec.SECP384R1())
        if wrong == "ec_curve"
        else rsa.generate_private_key(public_exponent=65537, key_size=3072 if wrong == "rsa_size" else 2048)
    )
    result = build_csr(key, "leaf.example.test", ["leaf.example.test"])
    assert validate_csr(
        result.pem, "leaf.example.test", ["leaf.example.test"], public_key_sha256(other.public_key())
    ) == ["CSR public key does not match"]


def test_validate_csr_rejects_tampered_signature_and_malformed_input(certs):
    from app.crypto.csr import build_csr, validate_csr
    from app.crypto.keys import public_key_sha256

    result = build_csr(certs.leaf_key, "leaf.example.test", ["leaf.example.test"])
    csr = x509.load_pem_x509_csr(result.pem.encode())
    der = csr.public_bytes(serialization.Encoding.DER)
    tampered = (
        x509.load_der_x509_csr(der[:-1] + bytes([der[-1] ^ 1]))
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    expected = public_key_sha256(certs.leaf_key.public_key())
    assert validate_csr(tampered, "leaf.example.test", ["leaf.example.test"], expected) == [
        "CSR signature is invalid"
    ]
    assert validate_csr("fixture-garbage", "leaf.example.test", ["leaf.example.test"], expected) == [
        "CSR could not be parsed"
    ]


def test_validate_csr_rejects_extra_subject_fields_missing_sans_and_wrong_digest(certs):
    from app.crypto.csr import validate_csr
    from app.crypto.keys import public_key_sha256

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.test"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fixture"),
                ]
            )
        )
        .sign(certs.leaf_key, hashes.SHA384())
    )
    errors = validate_csr(
        csr.public_bytes(serialization.Encoding.PEM).decode(),
        "leaf.example.test",
        ["leaf.example.test"],
        public_key_sha256(certs.leaf_key.public_key()),
    )
    assert set(errors) == {
        "CSR subject does not match CN-only identity",
        "CSR SANs do not match",
        "CSR signature must use SHA-256",
    }


def test_generated_fixture_hierarchy_and_variants_are_usable(certs, now):
    for child, issuer in [
        (certs.root, certs.root),
        (certs.intermediate1, certs.root),
        (certs.intermediate2, certs.intermediate1),
        (certs.leaf, certs.intermediate2),
    ]:
        child.verify_directly_issued_by(issuer)
    assert certs.expired.not_valid_after_utc < now < certs.not_yet_valid.not_valid_before_utc
    assert certs.wildcard.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName) == ["*.example.test"]
    assert (
        len(
            certs.ip_leaf.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.IPAddress)
        )
        == 2
    )


@pytest.mark.parametrize(
    "cn", ["", "bad_name.test", "email:user@example.test", "URI:https://example.test", "a" * 60 + ".test"]
)
def test_common_name_must_be_a_valid_host_or_ip_and_fit_x509_limit(certs, cn):
    from app.crypto.csr import build_csr

    with pytest.raises(ValueError):
        build_csr(certs.leaf_key, cn, ["leaf.example.test"])


def test_csr_validation_rejects_invalid_expected_identity_and_unsupported_public_key(certs):
    from app.crypto.csr import build_csr, canonical_sans, validate_csr
    from app.crypto.keys import public_key_sha256

    result = build_csr(certs.leaf_key, "leaf.example.test", ["leaf.example.test"])
    assert validate_csr(
        result.pem, "leaf.example.test", [], public_key_sha256(certs.leaf_key.public_key())
    ) == ["CSR expected identity is invalid"]
    with pytest.raises(ValueError):
        canonical_sans("leaf.example.test")
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.test")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("leaf.example.test")]), critical=False)
        .sign(weak, hashes.SHA256())
    )
    assert validate_csr(
        csr.public_bytes(serialization.Encoding.PEM).decode(),
        "leaf.example.test",
        ["leaf.example.test"],
        public_key_sha256(weak.public_key()),
    ) == ["CSR public key type or size is unsupported"]


def test_validation_cannot_treat_a_dns_encoded_ip_as_an_ip_san(certs):
    from app.crypto.csr import validate_csr
    from app.crypto.keys import public_key_sha256

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.test")]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("leaf.example.test"), x509.DNSName("192.0.2.1")]),
            critical=False,
        )
        .sign(certs.leaf_key, hashes.SHA256())
    )
    assert validate_csr(
        csr.public_bytes(serialization.Encoding.PEM).decode(),
        "leaf.example.test",
        ["leaf.example.test", "192.0.2.1"],
        public_key_sha256(certs.leaf_key.public_key()),
    ) == ["CSR SANs do not match"]


def test_unicode_cn_is_punycode_and_deduplicates_the_equivalent_san(certs):
    from app.crypto.csr import build_csr

    csr = x509.load_pem_x509_csr(
        build_csr(certs.leaf_key, "BÜCHER.Example", ["xn--bcher-kva.example"]).pem.encode()
    )
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "xn--bcher-kva.example"
    assert csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName
    ) == ["xn--bcher-kva.example"]
