from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class Certificates:
    root: x509.Certificate
    root_key: ec.EllipticCurvePrivateKey = field(repr=False)
    intermediate1: x509.Certificate
    intermediate1_key: ec.EllipticCurvePrivateKey = field(repr=False)
    intermediate2: x509.Certificate
    intermediate2_key: ec.EllipticCurvePrivateKey = field(repr=False)
    leaf: x509.Certificate
    leaf_key: rsa.RSAPrivateKey = field(repr=False)
    wildcard: x509.Certificate
    ip_leaf: x509.Certificate
    expired: x509.Certificate
    not_yet_valid: x509.Certificate
    ecdsa_leaf: x509.Certificate
    ecdsa_key: ec.EllipticCurvePrivateKey = field(repr=False)
    expired_intermediate: x509.Certificate
    expired_intermediate_leaf: x509.Certificate
    expired_intermediate_chain: tuple[x509.Certificate, ...]

    @property
    def intermediate1_fp(self):
        return self.intermediate1.fingerprint(hashes.SHA256()).hex()

    @property
    def intermediate2_fp(self):
        return self.intermediate2.fingerprint(hashes.SHA256()).hex()

    @property
    def intermediates(self) -> tuple[x509.Certificate, ...]:
        return (self.intermediate2, self.intermediate1)

    @property
    def leaf_pem(self) -> bytes:
        return self.leaf.public_bytes(serialization.Encoding.PEM)

    @property
    def chain_pem(self) -> bytes:
        return b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in self.intermediates)


def generate_certificates(now: datetime) -> Certificates:
    def issue(cn, key, parent, parent_key, *, ca=False, path_length=None, sans=(), before=None, after=None):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(parent.subject if parent else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(before or now - timedelta(days=1))
            .not_valid_after(after or now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=not ca and isinstance(key, rsa.RSAPrivateKey),
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=ca,
                    crl_sign=ca,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key((parent_key or key).public_key()),
                critical=False,
            )
        )
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        if not ca:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
        return builder.sign(parent_key or key, hashes.SHA256())

    root_key, one_key, two_key, ecdsa_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(4))
    root = issue("Fixture Root", root_key, None, None, ca=True, path_length=2)
    one = issue("Fixture Intermediate 1", one_key, root, root_key, ca=True, path_length=1)
    two = issue("Fixture Intermediate 2", two_key, one, one_key, ca=True, path_length=0)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = issue(
        "leaf.example.test",
        leaf_key,
        two,
        two_key,
        sans=[
            x509.DNSName("leaf.example.test"),
            x509.RFC822Name("fixture@example.test"),
            x509.UniformResourceIdentifier("https://leaf.example.test/status"),
        ],
    )
    wildcard = issue("*.example.test", leaf_key, two, two_key, sans=[x509.DNSName("*.example.test")])
    ip_leaf = issue(
        "192.0.2.10",
        leaf_key,
        two,
        two_key,
        sans=[x509.IPAddress(ip_address("192.0.2.10")), x509.IPAddress(ip_address("2001:db8::10"))],
    )
    expired = issue(
        "expired.example.test",
        leaf_key,
        two,
        two_key,
        sans=[x509.DNSName("expired.example.test")],
        before=now - timedelta(days=30),
        after=now - timedelta(days=1),
    )
    future = issue(
        "future.example.test",
        leaf_key,
        two,
        two_key,
        sans=[x509.DNSName("future.example.test")],
        before=now + timedelta(days=1),
        after=now + timedelta(days=30),
    )
    ecdsa_leaf = issue(
        "ecdsa.example.test", ecdsa_key, two, two_key, sans=[x509.DNSName("ecdsa.example.test")]
    )
    expired_intermediate_key = ec.generate_private_key(ec.SECP256R1())
    expired_intermediate = issue(
        "Fixture Expired Intermediate",
        expired_intermediate_key,
        root,
        root_key,
        ca=True,
        before=now - timedelta(days=90),
        after=now - timedelta(days=30),
    )
    expired_intermediate_leaf = issue(
        "expired-intermediate.example.test",
        leaf_key,
        expired_intermediate,
        expired_intermediate_key,
        sans=[x509.DNSName("expired-intermediate.example.test")],
    )
    return Certificates(
        root,
        root_key,
        one,
        one_key,
        two,
        two_key,
        leaf,
        leaf_key,
        wildcard,
        ip_leaf,
        expired,
        future,
        ecdsa_leaf,
        ecdsa_key,
        expired_intermediate,
        expired_intermediate_leaf,
        (expired_intermediate,),
    )
