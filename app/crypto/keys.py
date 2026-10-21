"""Private key serialization stays in memory; stored identity is public SPKI."""

import hashlib

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

type PrivateKeyObject = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def _validate(key: PrivateKeyObject) -> None:
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size in {2048, 3072, 4096}:
        return
    if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1)):
        return
    raise ValueError("unsupported private key type, size or curve")


def private_key_pem(key: PrivateKeyObject) -> bytes:
    _validate(key)
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def load_private_key(pem: bytes) -> PrivateKeyObject:
    try:
        key = serialization.load_pem_private_key(pem, password=None)
        _validate(key)
        return key
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ValueError("unsupported or malformed private key") from None


def public_key_sha256(key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey) -> str:
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()
