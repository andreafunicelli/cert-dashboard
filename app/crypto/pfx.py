"""In-memory PKCS#12 import/export; chain ordering does not imply trust."""

from collections.abc import Sequence
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from app.crypto.chain import ChainError, order_chain
from app.crypto.keys import PrivateKeyObject, _validate, public_key_sha256
from app.crypto.parse import MAX_INPUT_BYTES, ParseError, parse_certificates

_READ_ERROR = (
    "Could not read PFX: check the password and file. For legacy RC2/3DES bundles, "
    "re-export offline as a modern AES-protected PKCS#12 file."
)
_UNSUPPORTED = (
    "Unsupported PFX encryption. Re-export offline with a trusted tool as a modern "
    "AES-protected PKCS#12 file; do not weaken export encryption."
)


class PFXError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class PFXMaterial:
    key: PrivateKeyObject | None = field(repr=False)
    leaf: x509.Certificate
    chain: tuple[x509.Certificate, ...]


def _password_bytes(password: str | None) -> bytes | None:
    if password is None:
        return None
    if not isinstance(password, str):
        raise PFXError("invalid_password", "PFX password must be text.")
    try:
        return password.encode("utf-8")
    except UnicodeError:
        raise PFXError("invalid_password", "PFX password must be valid UTF-8 text.") from None


def _validate_key(key: PrivateKeyObject, leaf: x509.Certificate) -> None:
    try:
        _validate(key)
    except (ValueError, TypeError):
        raise PFXError(
            "unsupported_key",
            "Supported keys are RSA 2048/3072/4096 with e=65537, or ECDSA P-256/P-384.",
        ) from None
    if public_key_sha256(key.public_key()) != public_key_sha256(leaf.public_key()):
        raise PFXError("key_mismatch", "PFX private key does not match the certificate's SPKI identity.")


def _unique_leaf(certificates: Sequence[x509.Certificate]) -> x509.Certificate:
    leaves = []
    for cert in certificates:
        try:
            is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            is_ca = False
        if not is_ca and cert not in leaves:
            leaves.append(cert)
    if not leaves:
        raise PFXError("missing_certificate", "PFX contains no end-entity certificate.")
    if len(leaves) != 1:
        raise PFXError(
            "ambiguous_certificate",
            "PFX contains multiple possible leaf certificates; re-export one identity.",
        )
    return leaves[0]


def _normalize(
    leaf: x509.Certificate, candidates: Sequence[x509.Certificate]
) -> tuple[x509.Certificate, ...]:
    if len(candidates) + 1 > 32:
        raise PFXError("invalid_chain", "PFX contains too many certificates (max 32).")
    try:
        # Reuse public parsing validation before handing certificates to the chain walker.
        for cert in (leaf, *candidates):
            parse_certificates(cert.public_bytes(serialization.Encoding.DER))
        ordered = order_chain(leaf, candidates)
        if ordered.truncated:
            raise PFXError(
                "invalid_chain", "PFX chain search exceeded its safety limit; supply a simpler chain."
            )
        if not ordered.pem:
            return ()
        return tuple(part.cert for part in parse_certificates(ordered.pem.encode("ascii")))
    except (ParseError, ChainError):
        raise PFXError(
            "invalid_chain", "PFX certificate chain is invalid; re-export the correct intermediates."
        ) from None


def read_pfx(data: bytes, password: str | None) -> PFXMaterial:
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise PFXError("invalid_password_or_bundle", _READ_ERROR)
    if len(data) > MAX_INPUT_BYTES:
        raise PFXError("too_large", "PFX input exceeds 1 MiB.")
    try:
        key, leaf, additional = pkcs12.load_key_and_certificates(bytes(data), _password_bytes(password))
        candidates = list(additional)
        if leaf is None:
            leaf = _unique_leaf(candidates)
            candidates.remove(leaf)
        # The loader exposes only one key from multi-key bundles; always require its SPKI match.
        if key is not None:
            _validate_key(key, leaf)
        chain = _normalize(leaf, candidates)
        return PFXMaterial(key, leaf, chain)
    except PFXError:
        raise
    except UnsupportedAlgorithm:
        raise PFXError("unsupported_encryption", _UNSUPPORTED) from None
    except Exception:  # noqa: BLE001 - hostile PKCS#12 must fail with a sanitized typed error.
        raise PFXError("invalid_password_or_bundle", _READ_ERROR) from None


def build_pfx(
    key: PrivateKeyObject,
    leaf: x509.Certificate,
    chain: Sequence[x509.Certificate],
    password: str,
    friendly_name: str,
) -> bytes:
    if not isinstance(password, str) or len(password) < 12:
        raise PFXError("weak_password", "PFX export password must contain at least 12 characters.")
    if not isinstance(leaf, x509.Certificate):
        raise PFXError("missing_certificate", "PFX export requires a leaf certificate.")
    try:
        parsed = parse_certificates(leaf.public_bytes(serialization.Encoding.DER))[0]
        if not isinstance(friendly_name, str) or not friendly_name or friendly_name != parsed.common_name:
            raise PFXError(
                "invalid_friendly_name", "PFX friendly name must equal the certificate common name."
            )
        _validate_key(key, leaf)
        normalized = _normalize(leaf, chain)
        return pkcs12.serialize_key_and_certificates(
            friendly_name.encode("utf-8"),
            key,
            leaf,
            list(normalized),
            serialization.BestAvailableEncryption(_password_bytes(password)),
        )
    except PFXError:
        raise
    except UnsupportedAlgorithm:
        raise PFXError("unsupported_encryption", _UNSUPPORTED) from None
    except Exception:  # noqa: BLE001 - do not expose backend errors or key/password material.
        raise PFXError("export_failed", "PFX export failed; check the certificate, key and chain.") from None
