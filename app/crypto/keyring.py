"""Strict versioned AES keyring parsing; encryption is added in Task 4."""

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from app.config import ConfigurationError


@dataclass(frozen=True)
class Keyring:
    active: int
    keys: Mapping[int, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))


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
            raise ConfigurationError("master_key: hard limit of 16 parsed versions exceeded; remove excess versions")
        if len(keys) > 2:
            raise ConfigurationError("master_key: live limit of 2 versions exceeded; complete rotation and retire old versions")
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
