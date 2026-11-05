"""Thin Worker web adapters: safe errors, bounded input and service-only mutations."""
from io import BytesIO
from types import SimpleNamespace

import pytest
from starlette.datastructures import FormData, UploadFile

from app.services.worker_credentials import SSH_PRIVATE_KEY, VAULT_PASSWORD, CredentialError
from app.web import settings as web


@pytest.fixture
def adapter(monkeypatch):
    calls = []
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=object())))
    monkeypatch.setattr(web, "_transact", lambda request, work: (work("db", None, "actor"), None))
    monkeypatch.setattr(web, "_done", lambda request, tab, *notes: (tab, notes))
    monkeypatch.setattr(web, "_refused", lambda request, tab, *notes: (422, notes))
    def save(db, settings, name, value, actor):
        calls.append((name, value))
        return SimpleNamespace(label="SSH private key", fingerprint_sha256="a" * 64)
    monkeypatch.setattr(web, "set_credential", save)
    return request, calls


def test_pasted_key_is_passed_to_service_and_only_public_metadata_is_returned(adapter):
    request, calls = adapter
    result = web._handle_worker_save(request, "ssh", FormData({"private_key": "private-input"}))
    assert calls == [(SSH_PRIVATE_KEY, "private-input")]
    assert "private-input" not in repr(result)
    assert "a" * 64 in repr(result)


def test_optional_key_file_is_bounded_and_ambiguous_input_is_refused(adapter):
    request, calls = adapter
    upload = UploadFile(BytesIO(b"file-input"), filename="key.pem")
    web._handle_worker_save(request, "ssh", FormData({"private_key_file": upload}))
    assert calls == [(SSH_PRIVATE_KEY, b"file-input")]
    result = web._handle_worker_save(request, "ssh", FormData({"private_key": "paste", "private_key_file": upload}))
    assert result[0] == 422 and len(calls) == 1
    large = UploadFile(BytesIO(b"x" * 17000), filename="key.pem")
    result = web._handle_worker_save(request, "ssh", FormData({"private_key_file": large}))
    assert result[0] == 422 and len(calls) == 1


def test_secret_errors_never_refill_values(adapter, monkeypatch):
    request, _calls = adapter
    def refuse(*args):
        raise CredentialError(SSH_PRIVATE_KEY, "this is a public key: paste the private key instead")
    monkeypatch.setattr(web, "set_credential", refuse)
    result = web._handle_worker_save(request, "ssh", FormData({"private_key": "sensitive-invalid-input"}))
    assert result[0] == 422 and "this is a public key" in repr(result)
    assert "sensitive-invalid-input" not in repr(result)


@pytest.mark.parametrize("form", [FormData({"unexpected": "secret"}), FormData([("vault_password", "a"), ("vault_password", "b")])])
def test_unknown_and_duplicate_fields_refuse_without_write(adapter, form):
    request, calls = adapter
    assert web._handle_worker_save(request, "vault", form)[0] == 422
    assert not calls


def test_password_is_not_trimmed(adapter):
    request, calls = adapter
    web._handle_worker_save(request, "vault", FormData({"vault_password": " spaced "}))
    assert calls == [(VAULT_PASSWORD, " spaced ")]


def test_remove_requires_explicit_confirmation_and_calls_service(adapter, monkeypatch):
    request, calls = adapter
    monkeypatch.setattr(web, "remove_credential", lambda db, settings, name, actor: calls.append(name))
    assert web._handle_worker_remove(request, "ssh", FormData({"confirm": "no"}))[0] == 422
    assert not calls
    result = web._handle_worker_remove(request, "ssh", FormData({"confirm": "REMOVE"}))
    assert calls == [SSH_PRIVATE_KEY] and result[0] == "worker"
    assert "mounted" in repr(result)
