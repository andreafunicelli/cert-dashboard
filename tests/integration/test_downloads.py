"""Task 20: audited PEM/chain/fullchain downloads and re-authenticated, in-memory PFX export.

Real Postgres, real HTTP stack. The signed-in user is a local account with a known password so the
re-authentication path is exercised for real (hash, lockout counter, audit).
"""

import builtins
import io
import json
import os
import re
import tempfile
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import select

from app.auth.base import UserRecord
from app.auth.sessions import issue_session
from app.crypto.chain import fullchain_pem, order_chain
from app.crypto.keyring import Keyring
from app.crypto.parse import parse_certificates
from app.models import AuditLog, PrivateKey, User
from app.services.audit import Actor
from app.services.certificates import (
    CertificateMetadata,
    InventoryError,
    export_pfx,
    save_certificate,
    store_key,
)
from tests.integration.conftest import LOGIN_PASSWORD, create_login_user

ACTOR = Actor(None, "fixture", "192.0.2.1", "fixture-browser")
PFX_PASSWORD = "chosen-pass-123"
KEY_UNAVAILABLE = "key material cannot be decrypted with the configured master key"
NO_KEY = "No private key is stored for this certificate."


# --- fixtures ----------------------------------------------------------------------------------


@pytest.fixture
def account(web_factory):
    return create_login_user(web_factory, username="dl-" + uuid.uuid4().hex[:12])


def _sign_in(client, factory, clock, user_id):
    with factory.begin() as db:
        session = issue_session(db, user_id, clock(), "192.0.2.101", "fixture-browser")
    client.cookies.set("cd_session", session.id, domain="testserver.local", path="/")
    client.fixture_csrf = session.csrf_token
    return client


@pytest.fixture
def signed_in(client, web_factory, account, clock):
    """Shadows the shared fixture: this user owns a password, so re-authentication can succeed."""
    return _sign_in(client, web_factory, clock, account.id)


@pytest.fixture
def csrf(signed_in):
    return signed_in.fixture_csrf


class Factory:
    """Persists certificates through the production services, signed by the two-level fixture chain."""

    def __init__(self, factory, certs, keyring, now):
        self.factory, self.certs, self.keyring, self.now = factory, certs, keyring, now

    def leaf(self, common_name, key):
        c = self.certs
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(c.intermediate2.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self.now - timedelta(days=1))
            .not_valid_after(self.now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("san.example.test")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        )
        return builder.sign(c.intermediate2_key, hashes.SHA256())

    def make(self, common_name=None, *, with_key=True, chain=True):
        common_name = common_name or f"dl-{uuid.uuid4().hex[:10]}.example.test"
        key = ec.generate_private_key(ec.SECP256R1())
        cert = self.leaf(common_name, key)
        parsed = parse_certificates(cert.public_bytes(serialization.Encoding.PEM))[0]
        ordered = order_chain(parsed.cert, list(self.certs.intermediates) if chain else [])
        with self.factory.begin() as db:
            key_id = store_key(db, self.keyring, key, "imported_pem", ACTOR).id if with_key else None
            row = save_certificate(
                db,
                parsed,
                ordered,
                CertificateMetadata(),
                ACTOR,
                source="upload_pem",
                key_id=key_id,
                validation_time=self.now,
            ).certificate
            return SimpleNamespace(
                id=row.id,
                key_id=key_id,
                common_name=common_name,
                sha256_fingerprint=row.sha256_fingerprint,
                pem=row.pem,
                chain_pem=row.chain_pem,
            )


@pytest.fixture
def factory(web_factory, certs, web_settings, now):
    return Factory(web_factory, certs, web_settings.keyring, now)


@pytest.fixture
def cert_with_key(factory):
    return factory.make()


def export(client, certificate_id, csrf, **override):
    data = {
        "password": LOGIN_PASSWORD,
        "pfx_password": PFX_PASSWORD,
        "pfx_password_confirm": PFX_PASSWORD,
        "csrf_token": csrf,
    }
    data.update(override)
    data = {name: value for name, value in data.items() if value is not None}
    return client.post(f"/certificates/{certificate_id}/export.pfx", data=data, follow_redirects=False)


def audits(web_factory, action, certificate_id):
    with web_factory() as db:
        return list(
            db.scalars(
                select(AuditLog)
                .where(AuditLog.action == action, AuditLog.target_id == str(certificate_id))
                .order_by(AuditLog.id)
            )
        )


def user_row(web_factory, user_id):
    with web_factory() as db:
        return db.get(User, user_id)


def disposition_name(response):
    match = re.fullmatch(r'attachment; filename="([^"]*)"', response.headers["content-disposition"])
    assert match, response.headers["content-disposition"]
    return match.group(1)


# --- PFX export: success -----------------------------------------------------------------------


def test_pfx_requires_reauth_and_chosen_password(signed_in, cert_with_key, csrf, web_factory):
    response = signed_in.post(
        f"/certificates/{cert_with_key.id}/export.pfx",
        data={
            "password": "correct-long-pass",
            "pfx_password": "chosen-pass-123",
            "pfx_password_confirm": "chosen-pass-123",
            "csrf_token": csrf,
        },
    )
    assert response.status_code == 200
    key, leaf, chain = pkcs12.load_key_and_certificates(response.content, b"chosen-pass-123")
    assert leaf.fingerprint(hashes.SHA256()).hex() == cert_with_key.sha256_fingerprint
    assert key is not None and len(chain) == 2
    (audit,) = audits(web_factory, "key.export", cert_with_key.id)
    assert audit.target_id == str(cert_with_key.id)
    assert "chosen-pass-123" not in json.dumps(audit.details)
    assert "correct-long-pass" not in json.dumps(audit.details)


def test_pfx_response_headers_and_audit_details(signed_in, cert_with_key, csrf, web_factory, account):
    response = export(signed_in, cert_with_key.id, csrf)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/x-pkcs12"
    assert response.headers["cache-control"] == "no-store"
    assert disposition_name(response) == f"{cert_with_key.common_name}.pfx"
    (audit,) = audits(web_factory, "key.export", cert_with_key.id)
    assert audit.target_type == "certificate" and audit.actor_user_id == account.id
    assert audit.details == {
        "format": "pfx",
        "fingerprint": cert_with_key.sha256_fingerprint,
        "key_id": cert_with_key.key_id,
        "chain_length": 2,
    }
    assert not audits(web_factory, "key.export_failed", cert_with_key.id)


def test_pfx_export_leaves_the_key_row_untouched(signed_in, cert_with_key, csrf, web_factory):
    with web_factory() as db:
        before = db.get(PrivateKey, cert_with_key.key_id).ciphertext
    assert export(signed_in, cert_with_key.id, csrf).status_code == 200
    with web_factory() as db:
        assert db.get(PrivateKey, cert_with_key.key_id).ciphertext == before


def test_export_form_is_a_page_never_a_file(signed_in, cert_with_key, web_factory):
    page = signed_in.get(f"/certificates/{cert_with_key.id}/export.pfx")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    assert "content-disposition" not in page.headers
    for field in ("password", "pfx_password", "pfx_password_confirm", "csrf_token"):
        assert f'name="{field}"' in page.text
    assert not audits(web_factory, "key.export", cert_with_key.id)


def test_export_form_for_unknown_certificate_is_404(signed_in):
    assert signed_in.get("/certificates/999999999/export.pfx").status_code == 404


# --- PFX export: refusals ----------------------------------------------------------------------


def _refused(response, web_factory, certificate_id, status=422):
    assert response.status_code == status
    assert b"PRIVATE KEY" not in response.content and not response.content.startswith(b"0")
    assert response.headers["content-type"].startswith("text/html")
    assert not audits(web_factory, "key.export", certificate_id)


def test_wrong_password_is_refused_and_the_failure_is_persisted(signed_in, cert_with_key, csrf, web_factory, account):
    response = export(signed_in, cert_with_key.id, csrf, password="wrong-password-value")
    _refused(response, web_factory, cert_with_key.id)
    assert "incorrect" in response.text
    assert user_row(web_factory, account.id).failed_attempts == 1
    with web_factory() as db:
        failed = db.scalars(
            select(AuditLog).where(AuditLog.action == "auth.login_failed", AuditLog.actor_user_id == account.id)
        ).all()
    assert len(failed) == 1


def test_error_pages_never_echo_either_password(signed_in, cert_with_key, csrf, web_factory):
    response = export(
        signed_in,
        cert_with_key.id,
        csrf,
        password="wrong-password-value",
        pfx_password="echo-canary-pfx-1",
        pfx_password_confirm="echo-canary-pfx-1",
    )
    assert response.status_code == 422
    assert "wrong-password-value" not in response.text and "echo-canary-pfx-1" not in response.text
    assert re.search(r'name="pfx_password"(?![^>]*value=)', response.text)
    assert 'name="password"' in response.text and 'name="csrf_token"' in response.text


@pytest.mark.parametrize("password", [None, ""])
def test_missing_password_is_refused(signed_in, cert_with_key, csrf, web_factory, password):
    response = export(signed_in, cert_with_key.id, csrf, password=password)
    _refused(response, web_factory, cert_with_key.id)
    assert "password" in response.text.lower()


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"pfx_password": "short-11-pw", "pfx_password_confirm": "short-11-pw"}, "at least 12"),
        ({"pfx_password": None, "pfx_password_confirm": None}, "at least 12"),
        ({"pfx_password": "chosen-pass-123", "pfx_password_confirm": None}, "do not match"),
        ({"pfx_password": "x" * 1025, "pfx_password_confirm": "x" * 1025}, "at most 1,024"),
        ({"pfx_password": "chosen-pass-123", "pfx_password_confirm": "chosen-pass-124"}, "do not match"),
    ],
)
def test_pfx_password_policy_is_enforced(signed_in, cert_with_key, csrf, web_factory, account, fields, message):
    response = export(signed_in, cert_with_key.id, csrf, **fields)
    _refused(response, web_factory, cert_with_key.id)
    assert message in response.text
    assert user_row(web_factory, account.id).failed_attempts == 0


def test_pfx_password_of_exactly_1024_characters_is_accepted(signed_in, cert_with_key, csrf):
    long = "p" * 1024
    response = export(signed_in, cert_with_key.id, csrf, pfx_password=long, pfx_password_confirm=long)
    assert response.status_code == 200
    key, _, _ = pkcs12.load_key_and_certificates(response.content, long.encode())
    assert key is not None


def test_missing_csrf_is_refused(signed_in, cert_with_key, csrf, web_factory):
    response = export(signed_in, cert_with_key.id, csrf, csrf_token=None)
    assert response.status_code == 403
    assert not audits(web_factory, "key.export", cert_with_key.id)
    assert export(signed_in, cert_with_key.id, csrf, csrf_token="forged").status_code == 403


def test_no_session_is_refused(client, cert_with_key, web_factory):
    response = export(client, cert_with_key.id, "anything")
    assert response.status_code in (303, 401, 403)
    assert b"PRIVATE KEY" not in response.content
    assert not audits(web_factory, "key.export", cert_with_key.id)
    assert client.get(f"/certificates/{cert_with_key.id}/export.pfx", follow_redirects=False).status_code in (
        303,
        401,
    )


def test_ten_wrong_passwords_lock_the_account_for_exports(signed_in, cert_with_key, csrf, web_factory, account):
    for _ in range(10):
        assert export(signed_in, cert_with_key.id, csrf, password="wrong-password-value").status_code in (422, 423)
    response = export(signed_in, cert_with_key.id, csrf)
    _refused(response, web_factory, cert_with_key.id, 423)
    assert user_row(web_factory, account.id).locked_until is not None


def test_directory_user_is_refused_by_the_backend_contract(client, web_app, web_factory, clock, factory):
    user = create_login_user(
        web_factory, "dl-dir-" + uuid.uuid4().hex[:8], "directory-pass-123", backend="ldap"
    )

    class Directory:
        name = "ldap"

        def lookup(self, username):
            return UserRecord(str(user.id), username, username, f"{username}@example.test", "ldap", True)

    web_app.state.backends["ldap"] = Directory()
    cert = factory.make()
    session = _sign_in(client, web_factory, clock, user.id)
    response = export(session, cert.id, session.fixture_csrf, password="directory-pass-123")
    _refused(response, web_factory, cert.id)
    assert "directory" in response.text


def test_unknown_certificate_is_404(signed_in, csrf):
    assert export(signed_in, 999999999, csrf).status_code == 404


# --- PFX export: typed key failures ------------------------------------------------------------


def _failure_audit(web_factory, certificate_id, code):
    (audit,) = audits(web_factory, "key.export_failed", certificate_id)
    assert audit.target_type == "certificate"
    assert audit.details == {"certificate_id": certificate_id, "error": code}
    return audit


def test_certificate_without_a_key_gives_a_typed_error_and_failure_audit(signed_in, factory, csrf, web_factory):
    cert = factory.make(with_key=False)
    response = export(signed_in, cert.id, csrf)
    _refused(response, web_factory, cert.id)
    assert NO_KEY in response.text
    _failure_audit(web_factory, cert.id, "no_key")


def test_missing_master_key_version_gives_the_exact_unwrap_text(signed_in, cert_with_key, csrf, web_factory):
    with web_factory.begin() as db:
        db.get(PrivateKey, cert_with_key.key_id).master_key_version = 99
    response = export(signed_in, cert_with_key.id, csrf)
    _refused(response, web_factory, cert_with_key.id)
    assert KEY_UNAVAILABLE in response.text
    _failure_audit(web_factory, cert_with_key.id, "key_unwrap")


def test_tampered_ciphertext_gives_a_typed_error_without_leaking_it(signed_in, cert_with_key, csrf, web_factory):
    with web_factory.begin() as db:
        row = db.get(PrivateKey, cert_with_key.key_id)
        tampered = bytes([row.ciphertext[0] ^ 0xFF]) + row.ciphertext[1:]
        row.ciphertext = tampered
    response = export(signed_in, cert_with_key.id, csrf)
    _refused(response, web_factory, cert_with_key.id)
    assert KEY_UNAVAILABLE in response.text
    assert tampered.hex() not in response.text
    import base64

    assert base64.b64encode(tampered).decode() not in response.text
    _failure_audit(web_factory, cert_with_key.id, "key_unwrap")


def test_tampered_aad_gives_a_typed_error(signed_in, cert_with_key, csrf, web_factory):
    with web_factory.begin() as db:
        db.get(PrivateKey, cert_with_key.key_id).aad = "private_key:0:1"
    response = export(signed_in, cert_with_key.id, csrf)
    _refused(response, web_factory, cert_with_key.id)
    _failure_audit(web_factory, cert_with_key.id, "key_unwrap")


def test_failed_export_after_reauth_does_not_persist_the_export_audit(signed_in, factory, csrf, web_factory):
    cert = factory.make(with_key=False)
    export(signed_in, cert.id, csrf)
    assert len(audits(web_factory, "key.export_failed", cert.id)) == 1
    assert audits(web_factory, "key.export", cert.id) == []


# --- service contract --------------------------------------------------------------------------


def _db_certificate(db, certs, actor, now, *, key=True):
    key_object = ec.generate_private_key(ec.SECP256R1())
    builder = Factory(None, certs, Keyring(1, {1: bytes(range(32))}), now)
    cert = builder.leaf(f"svc-{uuid.uuid4().hex[:8]}.example.test", key_object)
    parsed = parse_certificates(cert.public_bytes(serialization.Encoding.PEM))[0]
    keyring = builder.keyring
    key_id = store_key(db, keyring, key_object, "imported_pem", actor).id if key else None
    row = save_certificate(
        db,
        parsed,
        order_chain(parsed.cert, list(certs.intermediates)),
        CertificateMetadata(),
        actor,
        source="upload_pem",
        key_id=key_id,
        validation_time=now,
    ).certificate
    return row, keyring


def test_export_pfx_service_returns_bytes_and_stages_one_audit(db, certs, actor, now):
    row, keyring = _db_certificate(db, certs, actor, now)
    data = export_pfx(db, row.id, keyring, PFX_PASSWORD, actor)
    key, leaf, chain = pkcs12.load_key_and_certificates(data, PFX_PASSWORD.encode())
    assert key is not None and leaf.fingerprint(hashes.SHA256()).hex() == row.sha256_fingerprint
    assert len(chain) == 2
    db.flush()
    (audit,) = db.scalars(select(AuditLog).where(AuditLog.action == "key.export")).all()
    assert audit.details["chain_length"] == 2 and PFX_PASSWORD not in json.dumps(audit.details)


def test_export_pfx_service_typed_errors(db, certs, actor, now):
    keyless, keyring = _db_certificate(db, certs, actor, now, key=False)
    with pytest.raises(InventoryError) as no_key:
        export_pfx(db, keyless.id, keyring, PFX_PASSWORD, actor)
    assert no_key.value.code == "no_key"
    with pytest.raises(InventoryError) as missing:
        export_pfx(db, 999999999, keyring, PFX_PASSWORD, actor)
    assert missing.value.code == "not_found"
    keyed, keyring = _db_certificate(db, certs, actor, now)
    with pytest.raises(InventoryError) as other_key:
        export_pfx(db, keyed.id, Keyring(2, {2: bytes(range(1, 33))}), PFX_PASSWORD, actor)
    assert other_key.value.code == "key_unwrap" and other_key.value.message == KEY_UNAVAILABLE
    with pytest.raises(InventoryError) as weak:
        export_pfx(db, keyed.id, keyring, "short", actor)
    assert weak.value.code == "weak_password"
    assert db.scalar(select(AuditLog).where(AuditLog.action == "key.export")) is None


# --- no temporary files ------------------------------------------------------------------------


def test_export_never_touches_the_filesystem(signed_in, cert_with_key, csrf, monkeypatch):
    # Warm every lazily loaded template and import first: the guard is about the export itself.
    assert signed_in.get(f"/certificates/{cert_with_key.id}/export.pfx").status_code == 200
    assert export(signed_in, cert_with_key.id, csrf, password="wrong-password-value").status_code == 422
    assert export(signed_in, cert_with_key.id, csrf).status_code == 200

    def forbidden(*args, **kwargs):
        raise AssertionError("filesystem access during PFX export")

    for owner, names in (
        (builtins, ("open",)),
        (io, ("open",)),
        (os, ("open",)),
        (
            tempfile,
            (
                "TemporaryFile",
                "NamedTemporaryFile",
                "SpooledTemporaryFile",
                "TemporaryDirectory",
                "mkstemp",
                "mkdtemp",
            ),
        ),
    ):
        for name in names:
            monkeypatch.setattr(owner, name, forbidden)
    response = export(signed_in, cert_with_key.id, csrf)
    assert response.status_code == 200
    key, _, _ = pkcs12.load_key_and_certificates(response.content, PFX_PASSWORD.encode())
    assert key is not None


# --- public downloads --------------------------------------------------------------------------


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_leaf_chain_and_fullchain_are_exact_normalized_pem(signed_in, factory, certs):
    cert = factory.make()
    leaf = signed_in.get(f"/certificates/{cert.id}/leaf.pem")
    chain = signed_in.get(f"/certificates/{cert.id}/chain.pem")
    full = signed_in.get(f"/certificates/{cert.id}/fullchain.pem")
    expected_chain = "".join(_pem(item) for item in certs.intermediates)
    assert leaf.status_code == chain.status_code == full.status_code == 200
    assert leaf.text == cert.pem
    assert chain.text == expected_chain == cert.chain_pem
    assert full.text == cert.pem + expected_chain == fullchain_pem(cert.pem, cert.chain_pem)
    assert certs.root.subject.rfc4514_string() not in full.text and _pem(certs.root) not in full.text
    for response, suffix in ((leaf, ".crt"), (chain, ".chain.pem"), (full, ".fullchain.pem")):
        assert response.headers["content-type"] == "application/x-pem-file"
        assert response.headers["cache-control"] == "no-store"
        assert disposition_name(response) == cert.common_name + suffix
        assert "PRIVATE KEY" not in response.text


def test_every_download_kind_is_audited_with_its_format(signed_in, factory, csrf, web_factory):
    cert = factory.make()
    for kind in ("leaf", "chain", "fullchain"):
        assert signed_in.get(f"/certificates/{cert.id}/{kind}.pem").status_code == 200
    assert export(signed_in, cert.id, csrf).status_code == 200
    downloads = audits(web_factory, "certificate.download", cert.id)
    assert sorted(item.details["format"] for item in downloads) == ["chain", "fullchain", "leaf"]
    assert all(item.details == {"format": item.details["format"]} for item in downloads)
    assert all(item.target_type == "certificate" for item in downloads)
    (pfx,) = audits(web_factory, "key.export", cert.id)
    assert pfx.details["format"] == "pfx"


def test_downloads_work_for_a_certificate_without_a_key(signed_in, factory, web_factory):
    cert = factory.make(with_key=False)
    assert signed_in.get(f"/certificates/{cert.id}/leaf.pem").status_code == 200
    assert len(audits(web_factory, "certificate.download", cert.id)) == 1


def test_empty_chain_is_a_422_page_and_fullchain_is_the_leaf_alone(signed_in, factory, web_factory):
    cert = factory.make(chain=False)
    response = signed_in.get(f"/certificates/{cert.id}/chain.pem")
    assert response.status_code == 422 and "No intermediate chain" in response.text
    assert "content-disposition" not in response.headers
    assert [item.details["format"] for item in audits(web_factory, "certificate.download", cert.id)] == []
    full = signed_in.get(f"/certificates/{cert.id}/fullchain.pem")
    assert full.status_code == 200 and full.text == cert.pem


def test_unknown_certificate_downloads_are_404(signed_in):
    for kind in ("leaf", "chain", "fullchain"):
        assert signed_in.get(f"/certificates/999999999/{kind}.pem").status_code == 404


def test_downloads_require_a_session(client, factory):
    cert = factory.make()
    for kind in ("leaf", "chain", "fullchain"):
        response = client.get(f"/certificates/{cert.id}/{kind}.pem", follow_redirects=False)
        assert response.status_code in (303, 401) and cert.pem not in response.text


@pytest.mark.parametrize(
    ("common_name", "stem"),
    [
        ("*.example.test", "wildcard.example.test"),
        ("日本語.example.test", "___.example.test"),
        ('a"b;c.example.test', "a_b_c.example.test"),
        ("../../etc/passwd", "_.._etc_passwd"),
        ("*" * 64, ("wildcard" * 64)[:100]),
        ("///", None),
    ],
    ids=["wildcard", "unicode", "quotes", "path", "truncated", "fallback"],
)
def test_filenames_are_sanitized_for_every_download(signed_in, factory, csrf, common_name, stem):
    cert = factory.make(common_name)
    stem = stem or f"certificate-{cert.id}"
    expected = {"leaf.pem": ".crt", "chain.pem": ".chain.pem", "fullchain.pem": ".fullchain.pem"}
    for route, suffix in expected.items():
        name = disposition_name(signed_in.get(f"/certificates/{cert.id}/{route}"))
        assert name == stem + suffix
        assert re.fullmatch(r"[A-Za-z0-9._-]+", name) and "/" not in name
    pfx = export(signed_in, cert.id, csrf)
    assert pfx.status_code == 200 and disposition_name(pfx) == stem + ".pfx"


# --- detail page -------------------------------------------------------------------------------


def test_detail_enables_downloads_and_the_pfx_export(signed_in, factory):
    cert = factory.make()
    page = signed_in.get(f"/certificates/{cert.id}").text
    for kind in ("leaf", "chain", "fullchain"):
        assert f'href="/certificates/{cert.id}/{kind}.pem"' in page
    assert f'href="/certificates/{cert.id}/export.pfx"' in page
    assert "Available after Task 20" not in page and "Downloads arrive with Task 20" not in page


def test_detail_without_key_or_chain_disables_only_what_is_unavailable(signed_in, factory):
    cert = factory.make(with_key=False, chain=False)
    page = signed_in.get(f"/certificates/{cert.id}").text
    assert f'href="/certificates/{cert.id}/leaf.pem"' in page
    assert f'href="/certificates/{cert.id}/chain.pem"' not in page
    assert f'href="/certificates/{cert.id}/export.pfx"' not in page
    assert re.search(r'<button[^>]*disabled[^>]*>[^<]*PFX', page)
    assert NO_KEY in page


def test_missing_master_key_version_disables_only_the_pfx_button(signed_in, factory, web_app, monkeypatch):
    affected, other = factory.make(), factory.make()
    with factory.factory.begin() as db:
        db.get(PrivateKey, affected.key_id).master_key_version = 99
    monkeypatch.setattr(web_app.state, "missing_key_versions", {99}, raising=False)
    page = signed_in.get(f"/certificates/{affected.id}").text
    assert f'href="/certificates/{affected.id}/export.pfx"' not in page
    assert re.search(r'<button[^>]*disabled[^>]*>[^<]*PFX', page) and KEY_UNAVAILABLE in page
    for kind in ("leaf", "chain", "fullchain"):
        assert f'href="/certificates/{affected.id}/{kind}.pem"' in page
        assert signed_in.get(f"/certificates/{affected.id}/{kind}.pem").status_code == 200
    unaffected = signed_in.get(f"/certificates/{other.id}").text
    assert f'href="/certificates/{other.id}/export.pfx"' in unaffected
    form = signed_in.get(f"/certificates/{affected.id}/export.pfx")
    assert form.status_code == 200 and KEY_UNAVAILABLE in form.text and 'name="pfx_password"' not in form.text
