import base64
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


def rings():
    from app.crypto.keyring import Keyring

    return Keyring(1, {1: bytes(range(32))}), Keyring(2, {1: bytes(range(32)), 2: bytes(reversed(range(32)))})


def test_row_binding_nonce_and_tag_parameters():
    from app.crypto.keyring import KeyUnwrapError, unwrap, wrap

    ring, _ = rings()
    encrypted = [wrap(ring, b"fixture-private", "private_key:7:1") for _ in range(12)]
    assert len({x.nonce for x in encrypted}) == 12
    assert len({x.ciphertext for x in encrypted}) == 12
    for item in encrypted:
        assert item.version == 1 and len(item.nonce) == 12
        assert len(item.ciphertext) == len(b"fixture-private") + 16
        assert unwrap(ring, item, "private_key:7:1") == b"fixture-private"
        assert "fixture-private" not in repr(item)
        with pytest.raises(
            KeyUnwrapError, match="key material cannot be decrypted with the configured master key"
        ):
            unwrap(ring, item, "private_key:8:1")


@pytest.mark.parametrize(
    "change", ["ciphertext", "tag", "nonce", "nonce_length", "aad", "version", "missing", "wrong_key"]
)
def test_all_unwrap_failures_are_typed_without_fallback(change):
    from app.crypto.keyring import Keyring, KeyUnwrapError, unwrap, wrap

    ring, both = rings()
    item = wrap(ring, b"fixture-private", "private_key:7:1")
    aad = "private_key:7:1"
    if change == "ciphertext":
        item = replace(item, ciphertext=bytes([item.ciphertext[0] ^ 1]) + item.ciphertext[1:])
    elif change == "tag":
        item = replace(item, ciphertext=item.ciphertext[:-1] + bytes([item.ciphertext[-1] ^ 1]))
    elif change == "nonce":
        item = replace(item, nonce=bytes([item.nonce[0] ^ 1]) + item.nonce[1:])
    elif change == "nonce_length":
        item = replace(item, nonce=b"short")
    elif change == "aad":
        aad = "user:7:totp:1"
    elif change == "version":
        item = replace(item, version=2)
        ring = both
    elif change == "missing":
        ring = Keyring(2, {2: both.keys[2]})
    elif change == "wrong_key":
        ring = Keyring(1, {1: both.keys[2]})
    with pytest.raises(KeyUnwrapError) as exc:
        unwrap(ring, item, aad)
    assert str(exc.value) == "key material cannot be decrypted with the configured master key"
    assert "fixture-private" not in str(exc.value)


@pytest.mark.parametrize(
    "key",
    [
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        ec.generate_private_key(ec.SECP256R1()),
        ec.generate_private_key(ec.SECP384R1()),
    ],
)
def test_pkcs8_memory_serialization_and_spki_hash(key):
    from app.crypto.keys import load_private_key, private_key_pem, public_key_sha256

    raw = private_key_pem(key)
    assert raw.startswith(b"-----BEGIN PRIVATE KEY-----\n")
    loaded = load_private_key(raw)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert public_key_sha256(loaded.public_key()) == hashlib.sha256(der).hexdigest()


def test_unsupported_keys_and_garbage_are_rejected_safely():
    from app.crypto.keys import load_private_key, private_key_pem

    with pytest.raises(ValueError):
        private_key_pem(ed25519.Ed25519PrivateKey.generate())
    with pytest.raises(ValueError) as exc:
        load_private_key(b"fixture-malformed-private-material")
    assert "fixture-malformed" not in str(exc.value)


def cli(*args):
    env = {k: v for k, v in os.environ.items() if k not in {"DB_PASSWORD", "MASTER_KEY", "SESSION_SECRET"}}
    return subprocess.run([sys.executable, "-m", "app.cli", *args], capture_output=True, env=env, check=False)


def test_generate_keyring_has_exact_bytes_fingerprint_and_no_db_dependency(tmp_path):
    from app.crypto.keyring import load_keyring

    result = cli("generate-master-key", "--version", "1")
    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout.endswith(b"\n") and b"\r" not in result.stdout
    ring = load_keyring(result.stdout)
    assert ring.active == 1 and len(ring.keys[1]) == 32
    assert b"--output" in result.stderr and b"warning" in result.stderr.lower()
    assert ("sha256=" + hashlib.sha256(result.stdout).hexdigest()).encode() in result.stderr
    assert (
        result.stdout
        == (json.dumps(json.loads(result.stdout), sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    path = tmp_path / "master-key-fixture"
    path.write_bytes(result.stdout)
    merged = cli("generate-master-key", "--version", "2", "--merge", str(path))
    assert merged.returncode == 0, merged.stderr.decode()
    new = load_keyring(merged.stdout)
    assert new.active == 2 and new.keys[1] == ring.keys[1] and new.keys[2] != ring.keys[1]
    assert path.read_bytes() == result.stdout
    assert ("sha256=" + hashlib.sha256(merged.stdout).hexdigest()).encode() in merged.stderr


@pytest.mark.parametrize("version", ["0", "-1", "bad", "2147483648"])
def test_generate_rejects_invalid_versions(version):
    result = cli("generate-master-key", "--version", version)
    assert result.returncode == 2 and b"version" in result.stderr and not result.stdout


@pytest.mark.parametrize("version", [1, 2, 3])
def test_generate_rejects_reuse_decrease_or_third_live_version(tmp_path, version):
    data = {"active": 2, "keys": {str(i): base64.b64encode(bytes([i]) * 32).decode() for i in [1, 2]}}
    path = tmp_path / "master-key-fixture"
    path.write_text(json.dumps(data))
    result = cli("generate-master-key", "--version", str(version), "--merge", str(path))
    assert result.returncode == 1 and b"master_key" in result.stderr and not result.stdout
    for secret in data["keys"].values():
        assert secret.encode() not in result.stderr


def test_generate_missing_merge_is_actionable(tmp_path):
    result = cli("generate-master-key", "--version", "2", "--merge", str(tmp_path / "missing"))
    assert result.returncode != 0 and b"master_key" in result.stderr and not result.stdout


@pytest.mark.parametrize("size", [16, 24])
def test_wrap_never_uses_aes128_or_aes192(size):
    from app.config import ConfigurationError
    from app.crypto.keyring import Keyring, wrap

    with pytest.raises(ConfigurationError, match="master_key"):
        wrap(Keyring(1, {1: b"x" * size}), b"fixture-private", "private_key:1:1")


@pytest.mark.parametrize("size", [16, 24])
def test_unwrap_rejects_even_valid_non_aes256_ciphertext(size):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from app.crypto.keyring import Keyring, KeyUnwrapError, WrappedSecret, unwrap

    key = b"x" * size
    nonce = b"n" * 12
    aad = "private_key:1:1"
    data = WrappedSecret(AESGCM(key).encrypt(nonce, b"fixture-private", aad.encode()), nonce, 1)
    with pytest.raises(KeyUnwrapError):
        unwrap(Keyring(1, {1: key}), data, aad)


def test_unsupported_pem_loader_error_is_safe(monkeypatch):
    from cryptography.exceptions import UnsupportedAlgorithm

    from app.crypto.keys import load_private_key

    def unsupported(*args, **kwargs):
        raise UnsupportedAlgorithm("fixture-private-details")

    monkeypatch.setattr(serialization, "load_pem_private_key", unsupported)
    with pytest.raises(ValueError) as exc:
        load_private_key(b"fixture-private")
    assert "fixture-private" not in str(exc.value)


def test_cli_in_process_generation_and_configuration_errors(tmp_path, monkeypatch, capfdbinary):
    from app.cli import main
    from app.crypto.keyring import load_keyring

    assert main(["generate-master-key", "--version", "1"]) == 0
    out, err = capfdbinary.readouterr()
    assert load_keyring(out).active == 1
    assert b"--output" in err and ("sha256=" + hashlib.sha256(out).hexdigest()).encode() in err
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    for name in ["DB_PASSWORD", "MASTER_KEY"]:
        monkeypatch.delenv(name, raising=False)
    assert main(["rotate-master-key"]) == 1
    out, err = capfdbinary.readouterr()
    assert not out and b"db_password" in err
    assert main(["generate-master-key", "--version", "2", "--merge", str(tmp_path / "missing")]) == 1
    out, err = capfdbinary.readouterr()
    assert not out and b"master_key" in err


def test_generate_output_is_exclusive_0400_and_only_reports_metadata(tmp_path, capsys):
    from app.cli import main
    from app.crypto.keyring import load_keyring

    path = tmp_path / "new-keyring"
    assert main(["generate-master-key", "--version", "2147483647", "--output", str(path)]) == 0
    raw = path.read_bytes()
    ring = load_keyring(raw)
    out, err = capsys.readouterr()
    assert ring.active == 2147483647
    assert path.stat().st_mode & 0o777 == 0o400
    assert out == f"sha256={hashlib.sha256(raw).hexdigest()} path={path}\n"
    assert not err and raw.decode() not in out
    assert all(base64.b64encode(key).decode() not in out for key in ring.keys.values())


def test_generate_output_refuses_existing_path_without_changing_it(tmp_path):
    path = tmp_path / "existing"
    path.write_bytes(b"fixture-do-not-overwrite")
    result = cli("generate-master-key", "--version", "1", "--output", str(path))
    assert result.returncode == 1 and b"exists" in result.stderr and not result.stdout
    assert path.read_bytes() == b"fixture-do-not-overwrite"


def test_generate_output_cannot_alias_merge_source(tmp_path, capsys):
    from app.cli import main

    source = tmp_path / "current"
    raw = json.dumps({"active": 1, "keys": {"1": base64.b64encode(bytes(range(32))).decode()}}).encode()
    source.write_bytes(raw)
    # A symbolic alias must compare equal by realpath before any output is opened.
    alias = tmp_path / "alias"
    alias.symlink_to(source)
    for output in [source, alias]:
        assert (
            main(["generate-master-key", "--version", "2", "--merge", str(source), "--output", str(output)])
            == 1
        )
        out, err = capsys.readouterr()
        assert not out and "merge" in err and source.read_bytes() == raw
