"""Task 15: atomic upload import with inline validation (real Postgres, real HTTP stack)."""

import base64
import json
import logging
import os
import re
import subprocess
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from sqlalchemy import func, select

from app.crypto import pfx_isolated
from app.crypto.keyring import Keyring
from app.crypto.keys import public_key_sha256
from app.models import AuditLog, Certificate, PrivateKey
from app.services import certificates as inventory
from app.services.certificates import (
    CertificateMetadata,
    ImportValidationError,
    InventoryError,
    UploadInput,
    import_upload,
)

LIMIT = 1_048_576
PFX_PASSWORD = "pfx-pass-ABCDEF-123"
KEY_PASSWORD = "key-pass-ABCDEF-456"
UPLOAD = "/certificates/import/upload"


@pytest.fixture
def fresh(now):
    """Unique keys and serials per test: the web database is shared by the whole module."""
    from tests.fixtures.certificates import generate_certificates

    return generate_certificates(now)


@pytest.fixture
def keyring():
    return Keyring(1, {1: bytes(range(32))})


def _counts(factory):
    with factory() as db:
        return tuple(
            db.scalar(select(func.count()).select_from(model))
            for model in (Certificate, PrivateKey, AuditLog)
        )


def _audits(factory, action):
    with factory() as db:
        return db.scalars(select(AuditLog).where(AuditLog.action == action)).all()


def _certificate(factory, certificate_id):
    with factory() as db:
        return db.get(Certificate, certificate_id)


def _post(client, *, fmt="pem", file=None, filename="cert.pem", chain=None, key=None, headers=None, **fields):
    data = {"format": fmt, "csrf_token": client.fixture_csrf, **fields}
    files = {}
    if file is not None:
        files["file"] = (filename, file)
    if chain is not None:
        files["chain_file"] = ("chain.pem", chain)
    if key is not None:
        files["key_file"] = ("key.pem", key)
    return client.post(UPLOAD, data=data, files=files or None, headers=headers, follow_redirects=False)


def _created_id(response):
    assert response.status_code == 303, response.text[:500]
    location = response.headers["location"]
    assert re.fullmatch(r"/certificates/\d+", location)
    return int(location.rsplit("/", 1)[1])


def _pfx(fresh, password=PFX_PASSWORD, *, key=True, chain=True):
    return pkcs12.serialize_key_and_certificates(
        b"leaf.example.test",
        fresh.leaf_key if key else None,
        fresh.leaf,
        list(fresh.intermediates) if chain else [],
        serialization.BestAvailableEncryption(password.encode()),
    )


def _key_pem(key, password=None):
    encryption = (
        serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    )
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


def _field_errors(html):
    return set(re.findall(r'data-field="([a-z_]+)"', html))


def test_bad_upload_has_no_partial_rows(signed_in, web_factory):
    before = _counts(web_factory)
    response = signed_in.post(
        UPLOAD,
        data={"format": "pem", "csrf_token": signed_in.fixture_csrf},
        files={"file": ("bad.crt", b"not a certificate")},
    )
    assert response.status_code == 422 and "certificate" in response.text.lower()
    assert before == _counts(web_factory)


def test_import_form_renders_with_csrf_and_multipart(signed_in):
    response = signed_in.get("/certificates/import")
    assert response.status_code == 200
    assert 'enctype="multipart/form-data"' in response.text
    assert f'name="csrf_token" value="{signed_in.fixture_csrf}"' in response.text
    assert 'action="/certificates/import/upload"' in response.text
    assert "<html" in response.text.lower()


def test_import_form_requires_a_session(client):
    response = client.get("/certificates/import", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"


@pytest.mark.parametrize(("field", "name"), [("file", "file"), ("chain", "chain_file"), ("key", "key_file")])
def test_one_byte_over_the_limit_is_rejected_before_parsing(
    signed_in, web_factory, fresh, monkeypatch, field, name
):
    real_parse, real_load = inventory.parse_certificates, inventory.serialization.load_pem_private_key

    def guard(real):
        def checked(data, *args, **kwargs):
            assert len(data) <= LIMIT, "oversized input reached a parser"
            return real(data, *args, **kwargs)

        return checked

    monkeypatch.setattr(inventory, "parse_certificates", guard(real_parse))
    monkeypatch.setattr(inventory.serialization, "load_pem_private_key", guard(real_load))
    before = _counts(web_factory)
    oversized = b"A" * (LIMIT + 1)
    files = {"file": ("cert.pem", fresh.leaf_pem)}
    files[name] = ("big.pem", oversized)
    response = signed_in.post(
        UPLOAD, data={"format": "pem", "csrf_token": signed_in.fixture_csrf}, files=files
    )
    assert response.status_code == 422
    assert field in _field_errors(response.text) and "too large" in response.text.lower()
    assert before == _counts(web_factory)


def test_pasted_text_over_the_limit_is_rejected_before_parsing(signed_in, web_factory, monkeypatch):
    monkeypatch.setattr(
        inventory, "parse_certificates", lambda *a, **k: pytest.fail("oversized paste was parsed")
    )
    before = _counts(web_factory)
    response = signed_in.post(
        UPLOAD,
        data={"format": "pem", "csrf_token": signed_in.fixture_csrf, "file_text": "A" * (LIMIT + 1)},
        follow_redirects=False,
    )
    assert response.status_code == 422 and "too large" in response.text.lower()
    assert before == _counts(web_factory)


def test_object_of_exactly_the_limit_is_parsed(signed_in, web_factory, fresh):
    pem = fresh.leaf_pem
    padded = pem + b"\n" * (LIMIT - len(pem))
    assert len(padded) == LIMIT
    certificate_id = _created_id(_post(signed_in, file=padded))
    assert (
        _certificate(web_factory, certificate_id).sha256_fingerprint
        == fresh.leaf.fingerprint(hashes.SHA256()).hex()
    )


def test_malformed_base64_is_a_field_error(signed_in, web_factory, fresh):
    before = _counts(web_factory)
    response = signed_in.post(
        UPLOAD,
        data={"format": "pfx", "csrf_token": signed_in.fixture_csrf, "file_text": "@@ not base64 @@"},
        follow_redirects=False,
    )
    assert response.status_code == 422 and "file" in _field_errors(response.text)
    assert "base64" in response.text.lower()
    assert before == _counts(web_factory)


def test_pasted_base64_pfx_is_imported(signed_in, web_factory, fresh):
    encoded = base64.b64encode(_pfx(fresh, key=False)).decode()
    response = signed_in.post(
        UPLOAD,
        data={
            "format": "pfx",
            "csrf_token": signed_in.fixture_csrf,
            "file_text": encoded,
            "password": PFX_PASSWORD,
        },
        follow_redirects=False,
    )
    assert _certificate(web_factory, _created_id(response)).imported_from == "upload_pfx"


@pytest.mark.parametrize(
    ("fmt", "encoding", "filename"),
    [
        ("pem", serialization.Encoding.PEM, "cert.pem"),
        ("crt", serialization.Encoding.PEM, "cert.crt"),
        ("crt", serialization.Encoding.DER, "cert.crt"),
        ("pem", serialization.Encoding.DER, "misnamed.pem"),
    ],
)
def test_pem_and_der_certificates_import_by_content(signed_in, web_factory, fresh, fmt, encoding, filename):
    certificate_id = _created_id(
        _post(
            signed_in,
            fmt=fmt,
            file=fresh.leaf.public_bytes(encoding),
            filename=filename,
            owner_name="Ada Lovelace",
            owner_email="ada@example.test",
            team="Platform",
            notes="imported by test",
        )
    )
    row = _certificate(web_factory, certificate_id)
    assert row.imported_from == "upload_pem" and row.key_id is None
    assert (row.owner_name, row.owner_email, row.team, row.notes) == (
        "Ada Lovelace",
        "ada@example.test",
        "Platform",
        "imported by test",
    )
    assert [a.target_id for a in _audits(web_factory, "certificate.import")].count(str(certificate_id)) == 1


def test_separate_chain_is_ordered_and_stored(signed_in, web_factory, fresh):
    certificate_id = _created_id(_post(signed_in, file=fresh.leaf_pem, chain=fresh.chain_pem))
    row = _certificate(web_factory, certificate_id)
    assert row.chain_pem.count("BEGIN CERTIFICATE") == 2


def test_leaf_first_bundle_in_one_file_uses_the_embedded_chain(signed_in, web_factory, fresh):
    bundle = fresh.leaf_pem + fresh.chain_pem
    row = _certificate(web_factory, _created_id(_post(signed_in, file=bundle)))
    assert row.chain_pem.count("BEGIN CERTIFICATE") == 2


def test_pfx_selected_for_a_pem_file_is_a_file_error(signed_in, web_factory, fresh):
    before = _counts(web_factory)
    response = _post(signed_in, fmt="pem", file=_pfx(fresh), filename="bundle.pfx")
    assert response.status_code == 422 and "file" in _field_errors(response.text)
    assert "does not look like" in response.text
    assert before == _counts(web_factory)


def test_pem_selected_for_a_pfx_file_is_a_file_error(signed_in, web_factory, fresh):
    before = _counts(web_factory)
    response = _post(signed_in, fmt="pfx", file=fresh.leaf_pem, password=PFX_PASSWORD)
    assert response.status_code == 422 and "does not look like" in response.text
    assert before == _counts(web_factory)


def test_certificate_file_with_private_key_block_is_refused_without_echo(signed_in, web_factory, fresh):
    combined = fresh.leaf_pem + _key_pem(fresh.leaf_key)
    before = _counts(web_factory)
    response = _post(signed_in, file=combined)
    assert response.status_code == 422 and "private key" in response.text.lower()
    assert "BEGIN" not in response.text and "PRIVATE KEY" not in response.text.replace("private key", "")
    assert before == _counts(web_factory)


def test_unencrypted_separate_key_is_stored_and_linked(signed_in, web_factory, fresh):
    certificate_id = _created_id(_post(signed_in, file=fresh.leaf_pem, key=_key_pem(fresh.leaf_key)))
    row = _certificate(web_factory, certificate_id)
    with web_factory() as db:
        key = db.get(PrivateKey, row.key_id)
        assert key.origin == "imported_pem" and key.public_key_sha256 == public_key_sha256(
            fresh.leaf_key.public_key()
        )


def test_encrypted_pem_key_with_right_password(signed_in, web_factory, fresh):
    certificate_id = _created_id(
        _post(
            signed_in,
            file=fresh.leaf_pem,
            key=_key_pem(fresh.leaf_key, KEY_PASSWORD),
            key_password=KEY_PASSWORD,
        )
    )
    assert _certificate(web_factory, certificate_id).key_id is not None


@pytest.mark.parametrize("password", ["wrong-key-pass-999", ""])
def test_encrypted_pem_key_with_wrong_or_missing_password(signed_in, web_factory, fresh, password):
    before = _counts(web_factory)
    response = _post(
        signed_in,
        file=fresh.leaf_pem,
        key=_key_pem(fresh.leaf_key, KEY_PASSWORD),
        key_password=password,
    )
    assert response.status_code == 422 and "key" in _field_errors(response.text)
    assert password not in response.text or not password
    assert before == _counts(web_factory)


def _unsupported_keys():
    return {
        "rsa-1024": rsa.generate_private_key(public_exponent=65537, key_size=1024),
        "ed25519": ed25519.Ed25519PrivateKey.generate(),
        "secp521r1": ec.generate_private_key(ec.SECP521R1()),
    }


@pytest.mark.parametrize("label", ["rsa-1024", "ed25519", "secp521r1"])
def test_unsupported_key_algorithm_or_size_is_an_explicit_key_error(signed_in, web_factory, fresh, label):
    before = _counts(web_factory)
    response = _post(signed_in, file=fresh.leaf_pem, key=_key_pem(_unsupported_keys()[label]))
    assert response.status_code == 422 and "key" in _field_errors(response.text)
    assert "unsupported" in response.text.lower() and "RSA 2048" in response.text
    assert before == _counts(web_factory)


def test_encrypted_unsupported_key_is_reported_after_decryption(signed_in, web_factory, fresh):
    before = _counts(web_factory)
    response = _post(
        signed_in,
        file=fresh.leaf_pem,
        key=_key_pem(ed25519.Ed25519PrivateKey.generate(), KEY_PASSWORD),
        key_password=KEY_PASSWORD,
    )
    assert response.status_code == 422 and "unsupported" in response.text.lower()
    assert before == _counts(web_factory)


def test_non_pem_key_is_a_key_error(signed_in, web_factory, fresh):
    response = _post(signed_in, file=fresh.leaf_pem, key=b"\x30\x82\x01\x00 not pem")
    assert response.status_code == 422 and "key" in _field_errors(response.text)


def test_mismatched_key_shows_public_hashes_only(signed_in, web_factory, fresh):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    before = _counts(web_factory)
    response = _post(signed_in, file=fresh.leaf_pem, key=_key_pem(other))
    assert response.status_code == 422 and "key" in _field_errors(response.text)
    assert public_key_sha256(other.public_key()) in response.text
    assert public_key_sha256(fresh.leaf_key.public_key()) in response.text
    assert "PRIVATE" not in response.text
    assert before == _counts(web_factory)


def test_matching_pfx_with_key_leaf_and_chain(signed_in, web_factory, fresh):
    certificate_id = _created_id(
        _post(signed_in, fmt="pfx", file=_pfx(fresh), filename="bundle.pfx", password=PFX_PASSWORD)
    )
    row = _certificate(web_factory, certificate_id)
    assert row.imported_from == "upload_pfx" and row.chain_pem.count("BEGIN CERTIFICATE") == 2
    with web_factory() as db:
        key = db.get(PrivateKey, row.key_id)
        assert key.origin == "imported_pfx"
        assert key.public_key_sha256 == public_key_sha256(fresh.leaf_key.public_key())
    assert any(a.target_id == str(row.key_id) for a in _audits(web_factory, "key.create"))
    assert [a.target_id for a in _audits(web_factory, "certificate.import")].count(str(certificate_id)) == 1


def test_public_only_import_creates_no_key(signed_in, web_factory, fresh):
    before = _counts(web_factory)
    certificate_id = _created_id(_post(signed_in, file=fresh.leaf_pem))
    after = _counts(web_factory)
    assert after[0] == before[0] + 1 and after[1] == before[1]
    assert _certificate(web_factory, certificate_id).key_id is None


def test_pfx_without_key_imports_public_only(signed_in, web_factory, fresh):
    certificate_id = _created_id(
        _post(signed_in, fmt="pfx", file=_pfx(fresh, key=False), password=PFX_PASSWORD)
    )
    assert _certificate(web_factory, certificate_id).key_id is None


def test_wrong_pfx_password_is_a_password_error(signed_in, web_factory, fresh):
    before = _counts(web_factory)
    response = _post(signed_in, fmt="pfx", file=_pfx(fresh), password="not-the-password-1")
    assert response.status_code == 422 and "password" in _field_errors(response.text)
    assert "not-the-password-1" not in response.text
    assert before == _counts(web_factory)


def test_pfx_plus_separate_key_is_ambiguous(signed_in, web_factory, fresh):
    before = _counts(web_factory)
    response = _post(
        signed_in, fmt="pfx", file=_pfx(fresh), password=PFX_PASSWORD, key=_key_pem(fresh.leaf_key)
    )
    assert response.status_code == 422 and "key" in _field_errors(response.text)
    assert before == _counts(web_factory)


def test_independent_errors_are_aggregated(signed_in, web_factory, fresh):
    before = _counts(web_factory)
    response = _post(
        signed_in,
        file=b"junk",
        chain=b"also junk",
        key=b"no key here",
        owner_email="not-an-email",
    )
    assert response.status_code == 422
    assert {"file", "chain", "key", "metadata"} <= _field_errors(response.text)
    assert before == _counts(web_factory)


def test_key_and_chain_errors_surface_even_when_the_certificate_is_valid(signed_in, web_factory, fresh):
    response = _post(signed_in, file=fresh.leaf_pem, chain=b"junk", key=b"junk")
    assert response.status_code == 422
    assert _field_errors(response.text) == {"chain", "key"}


def test_duplicate_links_to_the_existing_certificate(signed_in, web_factory, fresh):
    first_id = _created_id(_post(signed_in, file=fresh.leaf_pem, chain=fresh.chain_pem))
    before = _counts(web_factory)
    again = _post(signed_in, file=fresh.leaf_pem, chain=fresh.chain_pem, notes="must not overwrite")
    assert again.status_code == 200
    assert "already in inventory" in again.text and f'href="/certificates/{first_id}"' in again.text
    assert "attach_key" not in again.text
    after = _counts(web_factory)
    assert after[0] == before[0] and after[1] == before[1]
    assert _certificate(web_factory, first_id).notes is None
    assert any(a.target_id == str(first_id) for a in _audits(web_factory, "certificate.import_duplicate"))


def test_duplicate_trust_warnings_are_shown_as_notes_not_errors(signed_in, web_factory, fresh):
    _created_id(_post(signed_in, file=fresh.leaf_pem))
    again = _post(signed_in, file=fresh.leaf_pem)
    assert again.status_code == 200 and 'class="form-error"' not in again.text
    assert "missing" in again.text.lower() or "trust" in again.text.lower()


def test_supplied_key_for_public_only_duplicate_needs_explicit_confirmation(signed_in, web_factory, fresh):
    existing_id = _created_id(_post(signed_in, file=fresh.leaf_pem))
    key_pem = _key_pem(fresh.leaf_key)
    before = _counts(web_factory)
    offered = _post(signed_in, file=fresh.leaf_pem, key=key_pem)
    assert offered.status_code == 200 and 'name="attach_key" value="confirm"' in offered.text
    assert f'href="/certificates/{existing_id}"' in offered.text
    assert _counts(web_factory)[1] == before[1], "no key row without confirmation"
    assert _certificate(web_factory, existing_id).key_id is None
    assert not _audits(web_factory, "certificate.key_attach")

    confirmed = _post(signed_in, file=fresh.leaf_pem, key=key_pem, attach_key="confirm")
    assert _created_id(confirmed) == existing_id
    row = _certificate(web_factory, existing_id)
    assert row.key_id is not None
    assert [a.target_id for a in _audits(web_factory, "certificate.key_attach")] == [str(existing_id)]
    assert _counts(web_factory)[1] == before[1] + 1


def test_confirmed_attach_with_a_mismatched_key_is_refused(signed_in, web_factory, fresh):
    existing_id = _created_id(_post(signed_in, file=fresh.leaf_pem))
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    before = _counts(web_factory)
    response = _post(signed_in, file=fresh.leaf_pem, key=_key_pem(other), attach_key="confirm")
    assert response.status_code == 422 and "key" in _field_errors(response.text)
    assert _counts(web_factory)[1] == before[1] and _certificate(web_factory, existing_id).key_id is None


def test_duplicate_with_key_already_attached_offers_nothing(signed_in, web_factory, fresh):
    _created_id(_post(signed_in, file=fresh.leaf_pem, key=_key_pem(fresh.leaf_key)))
    again = _post(signed_in, file=fresh.leaf_pem, key=_key_pem(fresh.leaf_key))
    assert again.status_code == 200 and "attach_key" not in again.text


def test_htmx_failure_is_a_422_fragment_that_keeps_non_secret_fields(signed_in, web_factory, fresh):
    response = _post(
        signed_in,
        fmt="pfx",
        file=b"not a pfx",
        password=PFX_PASSWORD,
        key_password=KEY_PASSWORD,
        owner_name="Grace Hopper",
        owner_email="grace@example.test",
        team="Compilers",
        notes="keep me",
        headers={"HX-Request": "true"},
    )
    assert response.status_code == 422
    assert "<html" not in response.text.lower() and "<form" in response.text
    for kept in ("Grace Hopper", "grace@example.test", "Compilers", "keep me"):
        assert kept in response.text
    assert re.search(r'<option value="pfx"\s+selected', response.text)
    assert PFX_PASSWORD not in response.text and KEY_PASSWORD not in response.text
    assert "not a pfx" not in response.text


def test_htmx_success_redirects_with_hx_redirect(signed_in, web_factory, fresh):
    response = _post(signed_in, file=fresh.leaf_pem, headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert re.fullmatch(r"/certificates/\d+", response.headers["hx-redirect"])


def test_full_page_failure_keeps_fields_and_has_the_layout(signed_in, fresh):
    response = _post(signed_in, file=b"junk", owner_name="Linus", team="Kernel", notes="n1")
    assert response.status_code == 422 and "<html" in response.text.lower()
    assert "Linus" in response.text and "Kernel" in response.text


def test_secrets_never_reach_html_audit_or_logs(signed_in, web_factory, fresh, caplog):
    caplog.set_level(logging.DEBUG)
    private_pem = _key_pem(fresh.leaf_key).decode()
    bodies = [
        _post(signed_in, fmt="pfx", file=_pfx(fresh), password=PFX_PASSWORD),  # success
        _post(signed_in, fmt="pfx", file=_pfx(fresh), password="wrong-pfx-pass-1"),  # failure
        _post(
            signed_in,
            file=fresh.leaf_pem,
            key=_key_pem(fresh.leaf_key, KEY_PASSWORD),
            key_password=KEY_PASSWORD,
        ),
        _post(
            signed_in,
            file=fresh.leaf_pem,
            key=_key_pem(fresh.leaf_key, KEY_PASSWORD),
            key_password="oops-oops-1",
        ),
    ]
    secrets_ = (PFX_PASSWORD, KEY_PASSWORD, "wrong-pfx-pass-1", "oops-oops-1", private_pem.splitlines()[1])
    with web_factory() as db:
        audit_text = json.dumps(
            [[row.action, row.target_id, row.details] for row in db.scalars(select(AuditLog))], default=str
        )
    for secret in secrets_:
        assert secret not in audit_text and secret not in caplog.text
        assert all(secret not in body.text for body in bodies)


def test_stalled_pfx_child_is_terminated_reaped_and_leaves_no_rows(
    signed_in, web_factory, fresh, monkeypatch
):
    popen_instances = []

    class Recorder(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            popen_instances.append(self)

    monkeypatch.setattr(subprocess, "Popen", Recorder)
    monkeypatch.setattr(pfx_isolated, "PFX_CHILD_MODULE", "tests.fixtures.stalled_pfx_child")
    monkeypatch.setattr(pfx_isolated, "PFX_TIMEOUT_SECONDS", 1.0)
    before = _counts(web_factory)
    started = time.monotonic()
    response = _post(signed_in, fmt="pfx", file=_pfx(fresh), password=PFX_PASSWORD, owner_name="Keep Me")
    elapsed = time.monotonic() - started
    assert response.status_code == 422 and "file" in _field_errors(response.text)
    assert "time and memory budget" in response.text and PFX_PASSWORD not in response.text
    assert "Keep Me" in response.text
    assert elapsed < 8
    (child,) = popen_instances
    assert child.returncode is not None, "child was not reaped"
    with pytest.raises(ProcessLookupError):
        os.kill(child.pid, 0)
    assert before == _counts(web_factory)


# --- service-level atomicity -------------------------------------------------------------------


def test_upload_input_hides_secrets_in_repr():
    upload = UploadInput(
        b"data", "pfx", password="hunter2-pass", key_data=b"KEYBYTES", key_password="k-pass-9"
    )
    text = repr(upload)
    assert "hunter2-pass" not in text and "KEYBYTES" not in text and "k-pass-9" not in text


def test_validation_error_carries_immutable_per_field_tuples(db, keyring, actor):
    with pytest.raises(ImportValidationError) as exc:
        import_upload(
            db, keyring, UploadInput(b"junk", "pem", chain_data=b"junk"), CertificateMetadata(), actor
        )
    errors = exc.value.errors
    assert set(errors) == {"file", "chain"} and all(isinstance(v, tuple) and v for v in errors.values())
    assert db.scalar(select(func.count()).select_from(Certificate)) == 0


def test_certificate_failure_rolls_back_the_key_in_the_same_transaction(
    db, keyring, actor, fresh, monkeypatch
):
    def failing(*args, **kwargs):
        raise InventoryError("not_found", "simulated failure after the key was stored")

    monkeypatch.setattr(inventory, "save_certificate", failing)
    upload = UploadInput(fresh.leaf_pem, "pem", key_data=_key_pem(fresh.leaf_key))
    with pytest.raises(InventoryError):
        import_upload(db, keyring, upload, CertificateMetadata(), actor)
    assert db.scalar(select(func.count()).select_from(PrivateKey)) == 0
    assert not db.scalars(select(AuditLog).where(AuditLog.action == "key.create")).all()


def test_service_imports_pfx_with_key_in_one_call(db, keyring, actor, fresh):
    result = import_upload(
        db, keyring, UploadInput(_pfx(fresh), "pfx", password=PFX_PASSWORD), CertificateMetadata(), actor
    )
    assert result.created and result.key_attached and result.certificate.key_id is not None
    assert result.certificate.imported_from == "upload_pfx"


def test_service_accepts_a_ca_certificate_as_an_inventory_item(db, keyring, actor, fresh):
    root_pem = fresh.root.public_bytes(serialization.Encoding.PEM)
    assert import_upload(db, keyring, UploadInput(root_pem, "pem"), CertificateMetadata(), actor).created
