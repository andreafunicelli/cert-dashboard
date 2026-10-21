"""Strict versioned keyrings and row-bound AES-256-GCM encryption."""

import base64
import binascii
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import ConfigurationError


@dataclass(frozen=True)
class Keyring:
    active: int
    keys: Mapping[int, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))


class KeyUnwrapError(ValueError):
    def __init__(self) -> None:
        super().__init__("key material cannot be decrypted with the configured master key")


@dataclass(frozen=True)
class WrappedSecret:
    ciphertext: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    version: int


def wrap(keyring: Keyring, plaintext: bytes, aad: str) -> WrappedSecret:
    key = keyring.keys.get(keyring.active)
    if key is None or len(key) != 32:
        raise ConfigurationError("master_key: active version must contain a 32-byte AES-256 key")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad.encode("utf-8"))
    return WrappedSecret(ciphertext, nonce, keyring.active)


def unwrap(keyring: Keyring, wrapped: WrappedSecret, aad: str) -> bytes:
    try:
        if type(wrapped.version) is not int or wrapped.version < 1 or len(wrapped.nonce) != 12:
            raise ValueError
        key = keyring.keys[wrapped.version]
        if len(key) != 32:
            raise ValueError
        return AESGCM(key).decrypt(wrapped.nonce, wrapped.ciphertext, aad.encode("utf-8"))
    except (InvalidTag, KeyError, ValueError, TypeError):
        raise KeyUnwrapError() from None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("master_key: duplicate JSON key; remove duplicate entries")
        result[key] = value
    return result


def load_keyring(raw: bytes) -> Keyring:
    hint = 'master_key: expected {"active":1,"keys":{"1":"base64 of 32 bytes"}} with at most two versions'
    try:
        data = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(data, dict) or set(data) != {"active", "keys"}:
            raise ValueError
        active, keys = data["active"], data["keys"]
        if type(active) is not int or active < 1 or not isinstance(keys, dict):
            raise ValueError
        if not keys:
            raise ValueError
        if len(keys) > 16:
            raise ConfigurationError(
                "master_key: hard limit of 16 parsed versions exceeded; remove excess versions"
            )
        if len(keys) > 2:
            raise ConfigurationError(
                "master_key: live limit of 2 versions exceeded; complete rotation and retire old versions"
            )
        decoded = {}
        for version, encoded in keys.items():
            if not version.isascii() or not version.isdecimal() or str(int(version)) != version:
                raise ValueError
            number = int(version)
            if number < 1 or not isinstance(encoded, str):
                raise ValueError
            key = base64.b64decode(encoded, validate=True)
            if len(key) != 32:
                raise ValueError
            decoded[number] = key
        if active not in decoded:
            raise ValueError
        return Keyring(active=active, keys=decoded)
    except ConfigurationError:
        raise
    except (ValueError, TypeError, UnicodeError, binascii.Error):
        raise ConfigurationError(hint) from None
