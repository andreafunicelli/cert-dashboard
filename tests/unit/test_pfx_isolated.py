"""Task 15: PKCS#12 parsing runs in a killable, resource-limited child process."""

import os
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from typing import ClassVar

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from app.crypto import pfx_isolated
from app.crypto.keys import public_key_sha256
from app.crypto.pfx import PFXError, read_pfx
from app.crypto.pfx_isolated import read_encrypted_key_isolated, read_pfx_isolated

PASSWORD = "isolated-pass-123"


def _pfx(certs, password=PASSWORD, *, key=True):
    encryption = (
        serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    )
    return pkcs12.serialize_key_and_certificates(
        b"leaf.example.test",
        certs.leaf_key if key else None,
        certs.leaf,
        list(certs.intermediates),
        encryption,
    )


class _Recorder(subprocess.Popen):
    instances: ClassVar[list] = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        type(self).instances.append(self)


@pytest.fixture
def popen_log(monkeypatch):
    _Recorder.instances = []
    monkeypatch.setattr(subprocess, "Popen", _Recorder)
    return _Recorder.instances


def test_isolated_read_matches_in_process_read(certs):
    data = _pfx(certs)
    isolated, direct = read_pfx_isolated(data, PASSWORD), read_pfx(data, PASSWORD)
    assert isolated.leaf == direct.leaf and isolated.chain == direct.chain
    assert public_key_sha256(isolated.key.public_key()) == public_key_sha256(direct.key.public_key())


def test_isolated_read_of_certificate_only_bundle_has_no_key(certs):
    material = read_pfx_isolated(_pfx(certs, password="", key=False), None)
    assert material.key is None and material.leaf == certs.leaf


def test_isolated_read_preserves_ecdsa_keys(certs):
    data = pkcs12.serialize_key_and_certificates(
        b"ecdsa",
        certs.ecdsa_key,
        certs.ecdsa_leaf,
        [],
        serialization.BestAvailableEncryption(b"ec-pass-1234"),
    )
    material = read_pfx_isolated(data, "ec-pass-1234")
    assert isinstance(material.key, ec.EllipticCurvePrivateKey)


def test_wrong_password_is_a_typed_error(certs):
    with pytest.raises(PFXError) as exc:
        read_pfx_isolated(_pfx(certs), "not-the-password")
    assert exc.value.code == "invalid_password_or_bundle"
    assert "not-the-password" not in str(exc.value)


def test_unsupported_key_inside_bundle_keeps_its_code(certs):
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak.example.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(weak.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 10, 18, tzinfo=UTC))
        .not_valid_after(datetime(2026, 11, 18, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(weak, hashes.SHA256())
    )
    data = pkcs12.serialize_key_and_certificates(
        b"weak", weak, cert, [], serialization.BestAvailableEncryption(b"weak-pass-1234")
    )
    with pytest.raises(PFXError) as exc:
        read_pfx_isolated(data, "weak-pass-1234")
    assert exc.value.code == "unsupported_key"


def test_oversized_and_empty_input_never_spawn_a_child(popen_log):
    for blob, code in ((b"x" * 1_048_577, "too_large"), (b"", "invalid_password_or_bundle")):
        with pytest.raises(PFXError) as exc:
            read_pfx_isolated(blob, None)
        assert exc.value.code == code
    assert popen_log == []


def test_secrets_travel_over_stdin_only(certs, monkeypatch):
    seen = {}
    real_run = subprocess.run

    def spy(args, **kwargs):
        seen.update(args=list(args), kwargs=dict(kwargs))
        return real_run(args, **kwargs)

    monkeypatch.setattr(pfx_isolated.subprocess, "run", spy)
    data = _pfx(certs)
    read_pfx_isolated(data, PASSWORD)
    assert PASSWORD.encode() in seen["kwargs"]["input"] and data in seen["kwargs"]["input"]
    assert PASSWORD not in repr(seen["args"]) and PASSWORD not in repr(seen["kwargs"].get("env"))
    assert seen["args"][:2] == [sys.executable, "-m"]
    assert seen["kwargs"]["stderr"] == subprocess.DEVNULL
    assert seen["kwargs"]["timeout"] == pfx_isolated.PFX_TIMEOUT_SECONDS


def test_stalled_child_is_killed_and_reaped(certs, monkeypatch, popen_log):
    monkeypatch.setattr(pfx_isolated, "PFX_CHILD_MODULE", "tests.fixtures.stalled_pfx_child")
    monkeypatch.setattr(pfx_isolated, "PFX_TIMEOUT_SECONDS", 1.0)
    started = time.monotonic()
    with pytest.raises(PFXError) as exc:
        read_pfx_isolated(_pfx(certs), PASSWORD)
    assert time.monotonic() - started < 6
    assert exc.value.code == "pfx_timeout" and PASSWORD not in exc.value.message
    (child,) = popen_log
    assert child.returncode == -signal.SIGKILL  # killed, and wait() collected the status
    with pytest.raises(ProcessLookupError):
        os.kill(child.pid, 0)  # no zombie left behind


def test_crashing_child_is_a_sanitized_failure(certs, monkeypatch):
    monkeypatch.setattr(pfx_isolated, "PFX_CHILD_MODULE", "tests.fixtures.crashing_pfx_child")
    with pytest.raises(PFXError) as exc:
        read_pfx_isolated(_pfx(certs), PASSWORD)
    assert exc.value.code == "pfx_failed" and "secret-in-stderr" not in exc.value.message


def test_cpu_budget_signal_is_reported_as_timeout(certs, monkeypatch):
    monkeypatch.setattr(pfx_isolated, "PFX_CHILD_MODULE", "tests.fixtures.cpu_limited_pfx_child")
    with pytest.raises(PFXError) as exc:
        read_pfx_isolated(_pfx(certs), PASSWORD)
    assert exc.value.code == "pfx_timeout"


def test_garbage_from_child_is_a_sanitized_failure(certs, monkeypatch):
    monkeypatch.setattr(pfx_isolated, "PFX_CHILD_MODULE", "tests.fixtures.garbage_pfx_child")
    with pytest.raises(PFXError) as exc:
        read_pfx_isolated(_pfx(certs), PASSWORD)
    assert exc.value.code == "pfx_failed"


def test_child_limits_are_applied_before_parsing():
    code = (
        "import resource;from app.crypto import pfx_child;pfx_child.apply_limits();"
        "print(resource.getrlimit(resource.RLIMIT_CPU), resource.getrlimit(resource.RLIMIT_AS))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=30)
    assert out.stdout.strip() == f"(5, 5) ({512 * 1024 * 1024}, {512 * 1024 * 1024})"


def test_serve_rejects_malformed_requests_without_raising():
    from app.crypto import pfx_child

    for request in (b"", b"garbage", b"\x00\x00\x00\x05ab"):
        kind, *parts = pfx_isolated.unpack(pfx_child.serve(request))
        assert kind == b"ER" and parts[0] == b"pfx_failed"


def test_encrypted_key_round_trip_and_wrong_password(certs):
    pem = certs.leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"key-pass-1234"),
    )
    key = read_encrypted_key_isolated(pem, "key-pass-1234")
    assert public_key_sha256(key.public_key()) == public_key_sha256(certs.leaf_key.public_key())
    for password in ("wrong-pass-1234", None):
        with pytest.raises(PFXError) as exc:
            read_encrypted_key_isolated(pem, password)
        assert exc.value.code == "invalid_password_or_bundle"


def _serve(kind, password, data):
    from app.crypto import pfx_child

    return pfx_isolated.unpack(pfx_child.serve(pfx_isolated._request(kind, password, data)))


def test_serve_answers_a_valid_bundle_with_der_frames(certs):
    status, key_der, leaf_der, *chain = _serve(pfx_isolated.KIND_PFX, PASSWORD, _pfx(certs))
    assert status == pfx_isolated.OK and key_der and len(chain) == 2
    assert leaf_der == certs.leaf.public_bytes(serialization.Encoding.DER)


def test_serve_reports_typed_errors_not_exceptions(certs):
    status, code, message = _serve(pfx_isolated.KIND_PFX, "wrong-password-1", _pfx(certs))
    assert (status, code) == (pfx_isolated.ERROR, b"invalid_password_or_bundle")
    assert b"wrong-password-1" not in message
    assert _serve(b"?", None, b"x")[:2] == [pfx_isolated.ERROR, b"pfx_failed"]


def test_serve_decrypts_keys_and_classifies_unsupported_ones():
    from cryptography.hazmat.primitives.asymmetric import ed25519

    def pem(key, password):
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password.encode()),
        )

    good = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert _serve(pfx_isolated.KIND_KEY, "key-pass-1234", pem(good, "key-pass-1234"))[0] == pfx_isolated.OK
    assert _serve(pfx_isolated.KIND_KEY, "bad-pass-12345", pem(good, "key-pass-1234"))[:2] == [
        pfx_isolated.ERROR,
        b"invalid_password_or_bundle",
    ]
    assert _serve(
        pfx_isolated.KIND_KEY, "key-pass-1234", pem(ed25519.Ed25519PrivateKey.generate(), "key-pass-1234")
    )[:2] == [pfx_isolated.ERROR, b"unsupported_key"]


def test_main_applies_limits_before_reading_and_writes_one_frame(certs, monkeypatch):
    import io
    from types import SimpleNamespace

    from app.crypto import pfx_child

    order = []
    out = io.BytesIO()
    request = pfx_isolated._request(pfx_isolated.KIND_PFX, PASSWORD, _pfx(certs))
    monkeypatch.setattr(pfx_child, "apply_limits", lambda: order.append("limits"))
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(request)))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=out))
    pfx_child.main()
    assert order == ["limits"] and pfx_isolated.unpack(out.getvalue())[0] == pfx_isolated.OK


def test_apply_limits_sets_cpu_and_address_space(monkeypatch):
    import resource

    from app.crypto import pfx_child

    calls = []
    monkeypatch.setattr(resource, "setrlimit", lambda which, limits: calls.append((which, limits)))
    pfx_child.apply_limits()
    assert calls == [
        (resource.RLIMIT_CPU, (5, 5)),
        (resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024)),
    ]
