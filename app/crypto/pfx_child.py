"""Child-process entrypoint: ``python -m app.crypto.pfx_child``.

Reads one framed request from stdin, parses it under CPU and address-space
rlimits, and writes one framed response to stdout. It never logs, never writes
to disk and never echoes the password or input bytes; failures are typed codes
with fixed, safe messages. See ``app.crypto.pfx_isolated`` for the protocol.
"""

import sys

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from app.crypto.keys import _validate
from app.crypto.pfx import PFXError, read_pfx
from app.crypto.pfx_isolated import (
    ADDRESS_SPACE_BYTES,
    CPU_LIMIT_SECONDS,
    ERROR,
    KIND_KEY,
    KIND_PFX,
    OK,
    pack,
    unpack,
)

_FAILED = "The PFX could not be processed. Check the file and password, or re-export the bundle."
_KEY_UNREADABLE = "Could not read the private key: check the password and file."
_KEY_UNSUPPORTED = "Supported keys are RSA 2048/3072/4096 with e=65537, or ECDSA P-256/P-384."


def apply_limits() -> None:
    """Bound this process before it touches untrusted input (Linux ``resource`` limits)."""
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_BYTES, ADDRESS_SPACE_BYTES))


def _error(code: str, message: str) -> bytes:
    return pack(ERROR, code.encode("ascii"), message.encode("utf-8"))


def _der_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _read_pfx(password: str | None, data: bytes) -> bytes:
    material = read_pfx(data, password)
    leaf_and_chain = [
        cert.public_bytes(serialization.Encoding.DER) for cert in (material.leaf, *material.chain)
    ]
    return pack(OK, _der_key(material.key) if material.key is not None else b"", *leaf_and_chain)


def _read_key(password: str | None, data: bytes) -> bytes:
    try:
        key = serialization.load_pem_private_key(data, password.encode("utf-8") if password else None)
    except UnsupportedAlgorithm:
        return _error("unsupported_key", _KEY_UNSUPPORTED)
    except (ValueError, TypeError):
        return _error("invalid_password_or_bundle", _KEY_UNREADABLE)
    try:
        _validate(key)
    except ValueError:
        return _error("unsupported_key", _KEY_UNSUPPORTED)
    return pack(OK, _der_key(key))


def serve(request: bytes) -> bytes:
    """Pure request -> response function (limits are applied by ``main`` only)."""
    try:
        kind, has_password, password_bytes, data = unpack(request)
        password = password_bytes.decode("utf-8") if has_password == b"\x01" else None
        if kind == KIND_PFX:
            return _read_pfx(password, data)
        if kind == KIND_KEY:
            return _read_key(password, data)
        return _error("pfx_failed", _FAILED)
    except PFXError as exc:
        return _error(exc.code, exc.message)
    except Exception:  # noqa: BLE001 - includes MemoryError under RLIMIT_AS; never leak details.
        return _error("pfx_failed", _FAILED)


def main() -> None:
    apply_limits()
    request = sys.stdin.buffer.read()
    sys.stdout.buffer.write(serve(request))
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
