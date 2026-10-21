"""Private key serialization stays in memory; stored identity is public SPKI."""

import hashlib
from dataclasses import dataclass
from typing import Literal

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

type PrivateKeyObject = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


@dataclass(frozen=True)
class KeySpec:
    kind: Literal["rsa", "ecdsa"] = "rsa"
    size: int = 2048
    curve: str | None = None


def generate_key(spec: KeySpec) -> PrivateKeyObject:
    if type(spec.size) is not int:
        raise ValueError("key size must be an integer")
    if spec.kind == "rsa" and spec.size in {2048, 3072, 4096} and spec.curve is None:
        return rsa.generate_private_key(public_exponent=65537, key_size=spec.size)
    curves = {
        "prime256v1": ec.SECP256R1,
        "secp256r1": ec.SECP256R1,
        "p-256": ec.SECP256R1,
        "secp384r1": ec.SECP384R1,
        "p-384": ec.SECP384R1,
    }
    if spec.kind == "ecdsa" and (spec.curve is None or isinstance(spec.curve, str)):
        constructor = curves.get((spec.curve or "secp256r1").casefold())
        if constructor is not None:
            curve = constructor()
            # The RSA-default size is unused for EC; an explicit EC bit size must match.
            if spec.size in {2048, curve.key_size}:
                return ec.generate_private_key(curve)
    raise ValueError("unsupported or conflicting key type, size or curve")


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
