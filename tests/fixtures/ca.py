"""In-memory fixture CA that signs CSRs for renewal tests; keys are never written to disk."""

from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_KEEP = object()


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


class FixtureCA:
    """Root -> intermediate (valid) and root -> expired intermediate, plus a leaf signer."""

    def __init__(self, now: datetime) -> None:
        self.now = now
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate_key = ec.generate_private_key(ec.SECP256R1())
        self.expired_intermediate_key = ec.generate_private_key(ec.SECP256R1())
        self.root = self._ca("Renewal Fixture Root", self.root_key, None, self.root_key, 1)
        self.intermediate = self._ca(
            "Renewal Fixture Intermediate", self.intermediate_key, self.root, self.root_key, 0
        )
        self.expired_intermediate = self._ca(
            "Renewal Fixture Expired Intermediate",
            self.expired_intermediate_key,
            self.root,
            self.root_key,
            0,
            before=now - timedelta(days=90),
            after=now - timedelta(days=30),
        )

    def _ca(self, cn, key, parent, parent_key, path_length, *, before=None, after=None):
        subject = _name(cn)
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(parent.subject if parent else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(before or self.now - timedelta(days=365))
            .not_valid_after(after or self.now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
            .add_extension(
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
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(parent_key.public_key()), critical=False
            )
            .sign(parent_key, hashes.SHA256())
        )

    @property
    def root_pem(self) -> bytes:
        return _pem(self.root)

    @property
    def chain_pem(self) -> bytes:
        """The valid issuing intermediate (root excluded)."""
        return _pem(self.intermediate)

    @property
    def chain_with_root_pem(self) -> bytes:
        return _pem(self.intermediate) + _pem(self.root)

    @property
    def expired_chain_pem(self) -> bytes:
        return _pem(self.expired_intermediate)

    @property
    def forged_intermediate_pem(self) -> bytes:
        """Claims the real intermediate's subject but is signed by another key."""
        key = ec.generate_private_key(ec.SECP256R1())
        forged = (
            x509.CertificateBuilder()
            .subject_name(self.intermediate.subject)
            .issuer_name(self.root.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self.now - timedelta(days=1))
            .not_valid_after(self.now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256())
        )
        return _pem(forged)

    def issue(
        self,
        csr_pem: str | None = None,
        *,
        public_key=None,
        common_name=_KEEP,
        sans=_KEEP,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        issuer="intermediate",
        serial: int | None = None,
    ) -> bytes:
        """Issue a leaf. Defaults copy public key, CN and SANs from the CSR.

        ``issuer`` is ``"intermediate"``, ``"expired_intermediate"`` or a private key (self-signed).
        ``sans`` entries may be DNS-name strings or ready-made GeneralName objects.
        """
        csr_names: list[x509.GeneralName] = []
        csr_cn = None
        if csr_pem is not None:
            csr = x509.load_pem_x509_csr(csr_pem.encode("ascii") if isinstance(csr_pem, str) else csr_pem)
            public_key = public_key or csr.public_key()
            csr_cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            csr_names = list(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
        cn = csr_cn if common_name is _KEEP else common_name
        names = csr_names if sans is _KEEP else [x509.DNSName(s) if isinstance(s, str) else s for s in sans]
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]) if cn is not None else x509.Name([])
        if issuer == "intermediate":
            parent, signer = self.intermediate, self.intermediate_key
        elif issuer == "expired_intermediate":
            parent, signer = self.expired_intermediate, self.expired_intermediate_key
        else:
            parent, signer = None, issuer
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(parent.subject if parent else subject)
            .public_key(public_key)
            .serial_number(serial if serial is not None else x509.random_serial_number())
            .not_valid_before(not_before or self.now - timedelta(days=1))
            .not_valid_after(not_after or self.now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        )
        if names:
            builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
        return _pem(builder.sign(signer, hashes.SHA256()))
