"""Parse certificate bytes into public identity fields; trust is decided elsewhere."""

import re
from dataclasses import dataclass, field
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from app.crypto.csr import canonical_sans
from app.crypto.keys import public_key_sha256

MAX_INPUT_BYTES = 1_048_576

_CERTIFICATE_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)
_PEM_LABEL = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")


class ParseError(ValueError):
    """Certificate input could not be parsed."""


@dataclass(frozen=True)
class ParsedCertificate:
    common_name: str
    subject_dn: str
    sans: tuple[str, ...]
    issuer_dn: str
    issuer_cn: str
    serial: str
    not_before: datetime
    not_after: datetime
    sha256_fingerprint: str
    pem: str
    public_key_sha256: str
    cert: x509.Certificate = field(repr=False, compare=False)


def parse_certificates(data: bytes) -> list[ParsedCertificate]:
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise ParseError("certificate input must be nonempty bytes")
    raw = bytes(data)
    if len(raw) > MAX_INPUT_BYTES:
        raise ParseError("certificate input exceeds 1 MiB")
    try:
        return [_parsed(cert) for cert in _load_all(raw)]
    except ParseError:
        raise
    except Exception:  # noqa: BLE001 - hostile DER/PEM must fail as ParseError.
        raise ParseError("certificate could not be parsed") from None


def _load_all(raw: bytes) -> list[x509.Certificate]:
    if b"-----BEGIN" not in raw:
        return [x509.load_der_x509_certificate(raw)]
    labels = {label.upper() for label in _PEM_LABEL.findall(raw)}
    if labels != {b"CERTIFICATE"}:
        raise ParseError("only CERTIFICATE PEM blocks are accepted")
    blocks = _CERTIFICATE_BLOCK.findall(raw)
    if not blocks:
        raise ParseError("certificate PEM block is missing")
    return [x509.load_pem_x509_certificate(block) for block in blocks]


def _parsed(cert: x509.Certificate) -> ParsedCertificate:
    sans = _san_values(cert)
    return ParsedCertificate(
        common_name=_first_cn(cert.subject) or (sans[0] if sans else ""),
        subject_dn=cert.subject.rfc4514_string(),
        sans=sans,
        issuer_dn=cert.issuer.rfc4514_string(),
        issuer_cn=_first_cn(cert.issuer),
        serial=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sha256_fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
        pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        public_key_sha256=public_key_sha256(cert.public_key()),
        cert=cert,
    )


def _first_cn(name: x509.Name) -> str:
    attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attributes[0].value if attributes else ""


def _san_values(cert: x509.Certificate) -> tuple[str, ...]:
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return ()
    typed: list[str] = []
    plain: list[str] = []
    for name in names:
        if isinstance(name, x509.DNSName):
            typed.append("DNS:" + name.value)
            plain.append(name.value.lower())
        elif isinstance(name, x509.IPAddress):
            value = str(name.value)
            typed.append("IP:" + value)
            plain.append(value)
        elif isinstance(name, (x509.RFC822Name, x509.UniformResourceIdentifier)):
            typed.append(("email:" if isinstance(name, x509.RFC822Name) else "URI:") + name.value)
            plain.append(name.value)
        else:
            continue
    if not typed:
        return ()
    try:
        canonical = canonical_sans(typed)
    except (ValueError, TypeError):
        return tuple(dict.fromkeys(plain))
    values = []
    for value in canonical:
        if value.startswith("email:"):
            value = value[len("email:") :]
        elif value.startswith("URI:"):
            value = value[len("URI:") :]
        values.append(value)
    return tuple(values)
