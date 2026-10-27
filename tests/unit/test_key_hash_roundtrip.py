"""D2: the key identity is SHA-256 of the DER SubjectPublicKeyInfo, whichever way it is computed."""

import hashlib
import shutil
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from app.ansible.discovery import CERT_KEY_HASH_COMMAND, KEY_HASH_COMMAND
from app.crypto.keys import KeySpec, generate_key, load_private_key, private_key_pem, public_key_sha256
from app.crypto.pfx import build_pfx, read_pfx

EMPTY_INPUT_SHA256 = hashlib.sha256(b"").hexdigest()
HEX64 = set("0123456789abcdef")
needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not installed")

KINDS = [pytest.param(KeySpec("rsa"), id="rsa"), pytest.param(KeySpec("ecdsa"), id="ecdsa")]


def self_issued_leaf(key) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "keyhash.example.internal")])
    now = datetime(2026, 10, 19, tzinfo=UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )


def run_template(template: str, path) -> subprocess.CompletedProcess:
    # Exactly how the playbooks run them: bash with pipefail, so a failing openssl is not hidden by sha256sum.
    return subprocess.run(
        ["bash", "-o", "pipefail", "-c", template.format(path=str(path))],
        capture_output=True,
        text=True,
        check=False,
    )


def digest_of(result: subprocess.CompletedProcess) -> str:
    assert result.returncode == 0, result.stderr
    return result.stdout.split()[0]


@pytest.mark.parametrize("spec", KINDS)
def test_pem_pfx_and_host_commands_agree_on_the_key_hash(spec, tmp_path):
    key = generate_key(spec)
    leaf = self_issued_leaf(key)

    from_pem = public_key_sha256(load_private_key(private_key_pem(key)).public_key())
    pfx = build_pfx(key, leaf, [], "correct horse battery", "keyhash.example.internal")
    from_pfx = public_key_sha256(read_pfx(pfx, "correct horse battery").key.public_key())

    assert from_pem == from_pfx
    assert len(from_pem) == 64 and set(from_pem) <= HEX64
    assert from_pem != EMPTY_INPUT_SHA256


@needs_openssl
@pytest.mark.parametrize("spec", KINDS)
def test_host_side_commands_equal_the_library_hash(spec, tmp_path):
    key = generate_key(spec)
    (tmp_path / "leaf.key").write_bytes(private_key_pem(key))
    (tmp_path / "leaf.crt").write_bytes(self_issued_leaf(key).public_bytes(serialization.Encoding.PEM))
    expected = public_key_sha256(key.public_key())

    from_key = digest_of(run_template(KEY_HASH_COMMAND, tmp_path / "leaf.key"))
    from_cert = digest_of(run_template(CERT_KEY_HASH_COMMAND, tmp_path / "leaf.crt"))

    assert from_key == from_cert == expected
    assert set(from_key) <= HEX64 and from_key != EMPTY_INPUT_SHA256


@needs_openssl
@pytest.mark.parametrize("spec", KINDS)
def test_host_command_hash_survives_a_pfx_round_trip(spec, tmp_path):
    key = generate_key(spec)
    pfx = build_pfx(key, self_issued_leaf(key), [], "correct horse battery", "keyhash.example.internal")
    restored = read_pfx(pfx, "correct horse battery").key
    (tmp_path / "restored.key").write_bytes(private_key_pem(restored))

    assert digest_of(run_template(KEY_HASH_COMMAND, tmp_path / "restored.key")) == public_key_sha256(
        key.public_key()
    )


@needs_openssl
@pytest.mark.parametrize("spec", KINDS)
def test_passphrase_protected_key_fails_instead_of_hashing_nothing(spec, tmp_path):
    key = generate_key(spec)
    protected = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"a passphrase"),
    )
    (tmp_path / "protected.key").write_bytes(protected)

    result = run_template(KEY_HASH_COMMAND, tmp_path / "protected.key")

    # sha256sum still prints the empty-input hash; only the pipeline status tells it apart (pipefail), so
    # callers must discard stdout whenever the status is non-zero.
    assert result.returncode != 0
