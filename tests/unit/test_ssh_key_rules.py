"""SSH public keys: format rules and fingerprints, before any database or HTTP layer.

The stored half (uniqueness, delete, the worker key card) needs PostgreSQL and lives in
``tests/integration/test_ssh_keys_http.py``. Everything here is pure and generates keys in memory.
"""

import re

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from app.services.ssh_keys import (
    MAX_KEY_BYTES,
    SSHKeyError,
    parse_label,
    parse_public_key,
)


def _public(key, comment="") -> str:
    line = (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode("ascii")
    )
    return f"{line} {comment}".strip()


def _error(field_expected, text):
    with pytest.raises(SSHKeyError) as raised:
        parse_public_key(text)
    assert raised.value.field == field_expected
    assert raised.value.message
    return raised.value


def test_parse_public_key_accepts_an_ed25519_key_and_keeps_its_comment():
    key = ed25519.Ed25519PrivateKey.generate()
    material = parse_public_key(_public(key, "ansible@laptop"))
    assert material.key_type == "ssh-ed25519"
    assert material.public_key.endswith(" ansible@laptop")
    assert material.comment == "ansible@laptop"
    assert re.fullmatch(r"[0-9a-f]{64}", material.fingerprint_sha256)
    assert material.fingerprint_openssh.startswith("SHA256:")
    assert "=" not in material.fingerprint_openssh  # OpenSSH base64 fingerprint has no padding


def test_parse_public_key_accepts_rsa_and_ecdsa_keys():
    assert parse_public_key(_public(rsa.generate_private_key(public_exponent=65537, key_size=3072))).key_type == "ssh-rsa"
    assert parse_public_key(_public(ec.generate_private_key(ec.SECP256R1()))).key_type == "ecdsa-sha2-nistp256"


def test_parse_public_key_strips_surrounding_whitespace_and_line_endings():
    key = ed25519.Ed25519PrivateKey.generate()
    material = parse_public_key("\n  " + _public(key) + "  \n")
    assert "\n" not in material.public_key
    assert material.public_key == _public(key)


def test_parse_public_key_collapses_repeated_whitespace_between_the_parts():
    key = ed25519.Ed25519PrivateKey.generate()
    type_field, blob = _public(key).split(" ", 1)
    material = parse_public_key(f"{type_field}    {blob}\tcomment")
    assert material.public_key == f"{type_field} {blob} comment"


def test_parse_public_key_is_idempotent_so_a_stored_key_reparses_to_the_same_fingerprint():
    key = ed25519.Ed25519PrivateKey.generate()
    first = parse_public_key(_public(key, "deploy key"))
    second = parse_public_key(first.public_key)
    assert (second.public_key, second.fingerprint_sha256) == (first.public_key, first.fingerprint_sha256)


def test_parse_public_key_fingerprint_ignores_the_comment():
    # A duplicate is the same key material even when the pasted comment differs.
    key = ed25519.Ed25519PrivateKey.generate()
    assert (
        parse_public_key(_public(key, "one")).fingerprint_sha256
        == parse_public_key(_public(key, "two")).fingerprint_sha256
    )
    assert (
        parse_public_key(_public(key, "one")).fingerprint_openssh
        == parse_public_key(_public(key, "two")).fingerprint_openssh
    )


def test_parse_public_key_accepts_a_pem_public_key_and_stores_the_openssh_form():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    material = parse_public_key(pem)
    assert material.key_type == "ssh-rsa"
    assert material.public_key.startswith("ssh-rsa AAAA")


def test_parse_public_key_accepts_a_pem_public_key_pasted_with_windows_line_endings():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    material = parse_public_key(pem.replace("\n", "\r\n"))
    assert material.key_type == "ssh-rsa"


@pytest.mark.parametrize("text", ["", "   ", "\n\t "])
def test_parse_public_key_rejects_empty_input(text):
    _error("public_key", text)


def test_parse_public_key_rejects_a_private_key_without_echoing_it():
    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode("ascii")
    error = _error("public_key", private)
    assert "private key" in error.message.lower()
    assert "BEGIN" not in error.message


def test_parse_public_key_rejects_more_than_one_key_so_nothing_is_silently_dropped():
    one = _public(ed25519.Ed25519PrivateKey.generate())
    two = _public(ed25519.Ed25519PrivateKey.generate())
    error = _error("public_key", f"{one}\n{two}")
    assert "one key" in error.message.lower()


def test_parse_public_key_rejects_oversized_input():
    key = ed25519.Ed25519PrivateKey.generate()
    _error("public_key", _public(key) + " " + "c" * MAX_KEY_BYTES)


@pytest.mark.parametrize(
    "text",
    [
        "not a key",
        "ssh-ed25519",
        "ssh-ed25519 !!!!not-base64!!!! comment",
        "ssh-unknown-42 AAAAB3NzaC1yc2E= comment",
        "ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAABAQC trunc",
    ],
)
def test_parse_public_key_rejects_garbage_with_a_message_that_names_the_expected_format(text):
    error = _error("public_key", text)
    assert "ssh-ed25519" in error.message


@pytest.mark.parametrize("label", ["", "   ", "\n", "x" * 65, "web\tkey", "web\x00key"])
def test_parse_label_rejects_empty_over_long_or_control_character_labels(label):
    with pytest.raises(SSHKeyError) as raised:
        parse_label(label)
    assert raised.value.field == "label"
    assert raised.value.message


def test_parse_label_trims_but_keeps_case_and_spaces():
    assert parse_label("  Ansible production key  ") == "Ansible production key"
