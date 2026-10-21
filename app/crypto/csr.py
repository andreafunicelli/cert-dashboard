"""Typed SAN normalization and CSR identity checks; no network or key persistence."""

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlsplit

import idna
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.crypto.keys import PrivateKeyObject, public_key_sha256


@dataclass(frozen=True)
class CSRMaterial:
    pem: str
    sha256: str


def _dns_name(value: str) -> str:
    wildcard = value.startswith("*.")
    name = value[2:] if wildcard else value
    if not name or "*" in name or value.endswith("."):
        raise ValueError("invalid DNS name or wildcard")
    try:
        name = idna.encode(name, uts46=True, std3_rules=True, transitional=False).decode("ascii").lower()
    except idna.IDNAError:
        raise ValueError("invalid DNS name") from None
    result = ("*." if wildcard else "") + name
    if len(result) > 253 or any(not label or len(label) > 63 for label in name.split(".")):
        raise ValueError("DNS name exceeds label or total length limit")
    return result


def _ip_name(value: str) -> x509.IPAddress:
    if "%" in value:
        raise ValueError("scoped IP SANs are not supported")
    try:
        return x509.IPAddress(ip_address(value))
    except ValueError:
        raise ValueError("invalid IP SAN") from None


def parse_san(value: str) -> x509.GeneralName:
    if (
        not isinstance(value, str)
        or not value
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("SAN must be a nonempty identity without whitespace or controls")
    prefix, separator, remainder = value.partition(":")
    kind = prefix.casefold() if separator and prefix.casefold() in {"dns", "ip", "email", "uri"} else "auto"
    payload = remainder if kind != "auto" else value
    if kind == "ip":
        return _ip_name(payload)
    if kind in {"auto", "dns"}:
        try:
            address = _ip_name(payload)
        except ValueError:
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", payload):
                raise ValueError("invalid IP SAN") from None
        else:
            if kind == "dns":
                raise ValueError("IP addresses require IP SAN type")
            return address
        return x509.DNSName(_dns_name(payload))
    if not payload.isascii():
        raise ValueError("email and URI SANs require ASCII representations")
    if kind == "email":
        if payload.count("@") != 1:
            raise ValueError("invalid email SAN")
        local, domain = payload.split("@")
        if not local or "*" in domain:
            raise ValueError("invalid email SAN")
        _dns_name(domain)
        return x509.RFC822Name(payload)
    if not re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", payload):
        raise ValueError("URI SAN must be absolute")
    try:
        urlsplit(payload)
    except ValueError:
        raise ValueError("invalid URI SAN") from None
    return x509.UniformResourceIdentifier(payload)


def _canonical(name: x509.GeneralName) -> str:
    if isinstance(name, x509.DNSName):
        # Preserve the GeneralName type: numeric DNS values cannot become IP SANs.
        return parse_san("DNS:" + name.value).value
    if isinstance(name, x509.IPAddress):
        return str(name.value)
    if isinstance(name, x509.RFC822Name):
        return "email:" + name.value
    if isinstance(name, x509.UniformResourceIdentifier):
        return "URI:" + name.value
    raise ValueError("unsupported SAN type")


def canonical_sans(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not 1 <= len(values) <= 100:
        raise ValueError("provide between 1 and 100 SANs")
    return tuple(dict.fromkeys(_canonical(parse_san(value)) for value in values))


def _identity(common_name: str, sans: Sequence[str]) -> tuple[str, tuple[str, ...]]:
    name = parse_san(common_name)
    if not isinstance(name, (x509.DNSName, x509.IPAddress)):
        raise ValueError("common_name must be a DNS name or IP address")  # noqa: TRY004 - invalid string value.
    cn = _canonical(name)
    if len(cn.encode("ascii")) > 64:
        raise ValueError("common_name exceeds the X.509 64-byte limit")
    values = canonical_sans(sans)
    if cn not in values:
        values += (cn,)
    if len(values) > 100:
        raise ValueError("CN inclusion exceeds the 100-SAN limit")
    return cn, values


def _supported_public_key(key: object) -> bool:
    return (isinstance(key, rsa.RSAPublicKey) and key.key_size in {2048, 3072, 4096}) or (
        isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1))
    )


def build_csr(key: PrivateKeyObject, common_name: str, sans: Sequence[str]) -> CSRMaterial:
    cn, values = _identity(common_name, sans)
    if not _supported_public_key(key.public_key()):
        raise ValueError("unsupported CSR key type or size")
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName([parse_san(value) for value in values]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return CSRMaterial(
        csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest(),
    )


def validate_csr(csr_pem: str, common_name: str, sans: Sequence[str], public_hash: str) -> list[str]:
    try:
        cn, values = _identity(common_name, sans)
    except (ValueError, TypeError):
        return ["CSR expected identity is invalid"]
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    except (ValueError, UnicodeError, UnsupportedAlgorithm):
        return ["CSR could not be parsed"]
    errors = []
    try:
        if not csr.is_signature_valid:
            errors.append("CSR signature is invalid")
        if csr.signature_hash_algorithm is None or csr.signature_hash_algorithm.name != "sha256":
            errors.append("CSR signature must use SHA-256")
    except (ValueError, UnsupportedAlgorithm):
        errors.append("CSR signature is invalid")
    subject = list(csr.subject)
    try:
        subject_matches = (
            len(subject) == 1
            and subject[0].oid == NameOID.COMMON_NAME
            and _canonical(parse_san(subject[0].value)) == cn
        )
    except ValueError:
        subject_matches = False
    if not subject_matches:
        errors.append("CSR subject does not match CN-only identity")
    try:
        actual = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        actual_values = canonical_sans([_canonical(name) for name in actual])
    except (ValueError, x509.ExtensionNotFound):
        actual_values = ()
    if set(actual_values) != set(values):
        errors.append("CSR SANs do not match")
    public_key = csr.public_key()
    if not _supported_public_key(public_key):
        errors.append("CSR public key type or size is unsupported")
    if public_key_sha256(public_key) != public_hash:
        errors.append("CSR public key does not match")
    return errors
