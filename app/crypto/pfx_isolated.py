"""Parent side of the isolated PKCS#12 / encrypted-key reader.

A crafted PKCS#12 (or password-protected PKCS#8) file can fix an enormous KDF
iteration count in a few hundred bytes, so the 1 MiB input cap does not bound
the work. Parsing therefore runs in a fresh child interpreter that the parent
can kill: wall-clock timeout here, CPU and address-space rlimits inside the
child. Password and bundle travel over stdin only; the child's stderr is
discarded; only typed, sanitized error codes cross back.

Wire format (both directions): a sequence of ``uint32 big-endian length`` +
payload frames. Request: ``kind, has_password, password, data``. Response:
``b"OK", *payloads`` or ``b"ER", code, message``.
"""

import signal
import struct
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.crypto.keys import PrivateKeyObject, _validate
from app.crypto.parse import MAX_INPUT_BYTES
from app.crypto.pfx import PFXError, PFXMaterial, _password_bytes, _validate_key

# Module-level so tests can substitute a deliberately stalled or crashing child.
PFX_CHILD_MODULE = "app.crypto.pfx_child"
PFX_TIMEOUT_SECONDS = 10.0
CPU_LIMIT_SECONDS = 5
ADDRESS_SPACE_BYTES = 512 * 1024 * 1024
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_ROOT = Path(__file__).resolve().parents[2]
# The child needs no application secrets: hand it an almost empty environment.
_CHILD_ENV = {"PYTHONPATH": str(_ROOT), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "random"}

KIND_PFX, KIND_KEY = b"P", b"K"
OK, ERROR = b"OK", b"ER"

# Codes a child may report; anything else is treated as a child failure.
_CHILD_CODES = frozenset(
    {
        "invalid_password",
        "invalid_password_or_bundle",
        "unsupported_encryption",
        "unsupported_key",
        "key_mismatch",
        "invalid_leaf",
        "missing_certificate",
        "ambiguous_certificate",
        "invalid_chain",
        "too_large",
        "pfx_failed",
    }
)
_MESSAGE_LIMIT = 300
_TIMEOUT_MESSAGE = (
    "The PFX could not be processed within its time and memory budget. Re-export it with standard "
    "AES-protected PKCS#12 settings."
)
_FAILED_MESSAGE = "The PFX could not be processed. Check the file and password, or re-export the bundle."
_UNREADABLE_KEY = "Could not read the private key: check the password and file."
# Exit signals meaning the child ran out of its CPU/memory/wall-clock budget.
_BUDGET_SIGNALS = frozenset({-signal.SIGXCPU, -signal.SIGKILL})


def pack(*parts: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(part)) + part for part in parts)


def unpack(buffer: bytes) -> list[bytes]:
    """Split frames strictly; any truncation or trailing byte is a ValueError."""
    parts, offset = [], 0
    while offset < len(buffer):
        if offset + 4 > len(buffer):
            raise ValueError("truncated frame header")
        (size,) = struct.unpack_from(">I", buffer, offset)
        offset += 4
        if size > len(buffer) - offset:
            raise ValueError("truncated frame")
        parts.append(buffer[offset : offset + size])
        offset += size
    return parts


def _request(kind: bytes, password: str | None, data: bytes) -> bytes:
    encoded = _password_bytes(password)
    return pack(kind, b"\x01" if encoded is not None else b"\x00", encoded or b"", bytes(data))


def _run_child(request: bytes) -> list[bytes]:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", PFX_CHILD_MODULE],
            input=request,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=PFX_TIMEOUT_SECONDS,
            cwd=_ROOT,
            env=_CHILD_ENV,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # subprocess.run has already killed the child and waited for it.
        raise PFXError("pfx_timeout", _TIMEOUT_MESSAGE) from None
    except OSError:
        raise PFXError("pfx_failed", _FAILED_MESSAGE) from None
    if completed.returncode in _BUDGET_SIGNALS:
        raise PFXError("pfx_timeout", _TIMEOUT_MESSAGE)
    if completed.returncode != 0 or len(completed.stdout) > _MAX_RESPONSE_BYTES:
        raise PFXError("pfx_failed", _FAILED_MESSAGE)
    try:
        return unpack(completed.stdout)
    except ValueError:
        raise PFXError("pfx_failed", _FAILED_MESSAGE) from None


def _payloads(parts: list[bytes], minimum: int) -> list[bytes]:
    if not parts:
        raise PFXError("pfx_failed", _FAILED_MESSAGE)
    if parts[0] == ERROR:
        code = parts[1].decode("ascii", "replace") if len(parts) == 3 else "pfx_failed"
        message = parts[2].decode("utf-8", "replace") if len(parts) == 3 else _FAILED_MESSAGE
        if code not in _CHILD_CODES:
            raise PFXError("pfx_failed", _FAILED_MESSAGE)
        if len(message) > _MESSAGE_LIMIT or not message.isprintable():
            message = _FAILED_MESSAGE
        raise PFXError(code, message)
    if parts[0] != OK or len(parts) - 1 < minimum:
        raise PFXError("pfx_failed", _FAILED_MESSAGE)
    return parts[1:]


def read_pfx_isolated(data: bytes, password: str | None) -> PFXMaterial:
    """``read_pfx`` executed in a killable child; same result, same typed errors."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise PFXError("invalid_password_or_bundle", _FAILED_MESSAGE)
    if len(data) > MAX_INPUT_BYTES:
        raise PFXError("too_large", "PFX input exceeds 1 MiB.")
    payloads = _payloads(_run_child(_request(KIND_PFX, password, bytes(data))), 2)
    try:
        key = serialization.load_der_private_key(payloads[0], None) if payloads[0] else None
        leaf = x509.load_der_x509_certificate(payloads[1])
        chain = tuple(x509.load_der_x509_certificate(item) for item in payloads[2:])
        if key is not None:
            _validate_key(key, leaf)  # the parent does not trust the child's output blindly
    except PFXError:
        raise
    except Exception:  # noqa: BLE001 - a malformed child answer is a child failure.
        raise PFXError("pfx_failed", _FAILED_MESSAGE) from None
    return PFXMaterial(key, leaf, chain)


def read_encrypted_key_isolated(pem: bytes, password: str | None) -> PrivateKeyObject:
    """Decrypt a password-protected PEM private key in the same sandbox as PFX parsing."""
    if not isinstance(pem, (bytes, bytearray)) or not pem or len(pem) > MAX_INPUT_BYTES:
        raise PFXError("invalid_password_or_bundle", _UNREADABLE_KEY)
    (der,) = _payloads(_run_child(_request(KIND_KEY, password, bytes(pem))), 1)
    try:
        key = serialization.load_der_private_key(der, None)
        _validate(key)
    except Exception:  # noqa: BLE001
        raise PFXError("pfx_failed", _FAILED_MESSAGE) from None
    return key
