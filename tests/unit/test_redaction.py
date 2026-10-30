import base64
import io
import json
import logging
import subprocess
import sys

import pytest

HASH = "0123456789abcdef" * 4
BLOB = base64.b64encode(bytes(range(96))).decode()
JOB_ID = "fb04310c-2a61-4b7e-9f2e-6d3c1a5e8b40"
PRIVATE_PEM = "-----BEGIN PRIVATE KEY-----\nfixture-private-material\n-----END PRIVATE KEY-----"
CERT_PEM = "-----BEGIN CERTIFICATE-----\nfixture-public-material\n-----END CERTIFICATE-----"


def test_nested_sensitive_fields_are_redacted_without_mutating_input():
    from app.services.audit import redact

    original = {
        "safe": [None, True, 3, 1.5, {"name": "fixture"}],
        "nested": [
            {"Password": "fixture-password", "pfxPassword": "fixture-export", "csrf_token": "fixture-csrf"},
            {
                "master_key": {"active": 1, "keys": {"1": "fixture-master"}},
                "totp_seed": "fixture-seed",
                "recovery_codes": ["fixture-recovery"],
            },
            {
                "private_key": "fixture-key",
                "Authorization": "Bearer fixture-token",
                "Cookie": "cd_session=fixture-session",
            },
        ],
        "form_body": {"notes": "fixture-form"},
        "request_body": "fixture-request",
        "certificate_pem": CERT_PEM,
    }
    before = json.dumps(original)
    result = redact(original)
    assert json.dumps(original) == before
    assert result["safe"] == original["safe"]
    for group in result["nested"]:
        assert set(group.values()) == {"[REDACTED]"}
    assert result["form_body"] == result["request_body"] == result["certificate_pem"] == "[REDACTED]"
    assert "fixture-password" not in json.dumps(result)
    assert redact(result) == result


@pytest.mark.parametrize(
    "name",
    [
        "password",
        "passwd",
        "passphrase",
        "api_key",
        "apiKey",
        "access_token",
        "refreshToken",
        "session_secret",
        "session_id",
        "keyring",
        "keys",
        "ciphertext",
        "totp",
        "recoveryCodes",
        "csr_pem",
        "public_key_pem",
        "form",
        "form_data",
        "body",
    ],
)
def test_sensitive_field_aliases_fail_closed(name):
    from app.services.audit import redact

    assert redact({name: "fixture-sensitive"}) == {name: "[REDACTED]"}


def test_safe_crypto_metadata_and_sha256_fingerprints_survive():
    from app.services.audit import redact

    metadata = {
        "sha256_fingerprint": HASH,
        "public_key_sha256": HASH,
        "master_key_sha256": HASH,
        "master_key_version": 2,
        "private_key_id": 42,
        "key_id": 42,
        "key_type": "rsa",
        "key_size": 2048,
        "master_key_active": 2,
        "master_key_present": True,
        "session_secret_present": False,
        "db_password_present": True,
        "totp_enabled": True,
        "format": "pfx",
        "chain_status": "trusted",
    }
    assert redact(metadata) == metadata
    assert redact("sha256=" + HASH) == "sha256=" + HASH
    assert redact({"password_present": "fixture-password"}) == {"password_present": "[REDACTED]"}


@pytest.mark.parametrize(
    "value",
    [
        PRIVATE_PEM,
        CERT_PEM,
        "-----BEGIN RSA PRIVATE KEY-----\ntruncated-private-fixture",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture-private-material\n-----END OPENSSH PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE REQUEST-----\nfixture-csr\n-----END CERTIFICATE REQUEST-----",
        BLOB,
    ],
)
def test_pem_and_long_base64_are_redacted_even_under_safe_keys(value):
    from app.services.audit import redact

    assert redact({"notes": value}) == {"notes": "[REDACTED]"}
    assert redact("prefix " + value + " suffix").startswith("prefix [REDACTED]")


@pytest.mark.parametrize(
    "value,secret",
    [
        ("password=fixture-password", "fixture-password"),
        ('password="fixture password with spaces" event=failed', "fixture password with spaces"),
        ("pfx_password='fixture-export'", "fixture-export"),
        ('{"access_token":"fixture-token"}', "fixture-token"),
        ("authorization: Bearer fixture-bearer", "fixture-bearer"),
        ("Basic fixture-basic==", "fixture-basic"),
        ("postgresql://fixture:fixture-url-password@localhost/database", "fixture-url-password"),
        ("password=fixture password with spaces; event=failed", "fixture password with spaces"),
    ],
)
def test_inline_secret_values_are_removed(value, secret):
    from app.services.audit import redact

    clean = redact(value)
    assert secret not in clean
    assert "[REDACTED]" in clean
    assert redact(clean) == clean


def render_log(message, args=(), *, extra=None, exc_info=None, stack_info=None):
    from app.services.audit import SecretRedactionFilter

    record = logging.LogRecord("fixture-audit", logging.ERROR, __file__, 1, message, args, exc_info)
    record.stack_info = stack_info
    for name, value in (extra or {}).items():
        setattr(record, name, value)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(SecretRedactionFilter())
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    handler.handle(record)
    return stream.getvalue(), record


def test_logging_filter_formats_args_and_scrubs_structured_extras():
    details = {
        "password": "fixture-password",
        "nested": [{"token": "fixture-token"}],
        "sha256_fingerprint": HASH,
    }
    output, record = render_log(
        "failure %s count=%d sha256=%s",
        (PRIVATE_PEM, 3, HASH),
        extra={"details": details, "authorization": "Bearer fixture-header", "form_body": "fixture-form"},
    )
    assert "fixture-private-material" not in output and "[REDACTED]" in output
    assert "count=3" in output and HASH in output
    assert record.details == {
        "password": "[REDACTED]",
        "nested": [{"token": "[REDACTED]"}],
        "sha256_fingerprint": HASH,
    }
    assert record.authorization == record.form_body == "[REDACTED]"
    assert details["password"] == "fixture-password"
    assert record.args == ()


def test_logging_filter_handles_mapping_args_structured_messages_and_bytes():
    output, _ = render_log(
        "password=%(password)s count=%(count)d", ({"password": "fixture-password", "count": 2},)
    )
    assert "fixture-password" not in output and "count=2" in output
    output, _ = render_log({"password": "fixture-dict-password", "sha256_fingerprint": HASH})
    assert "fixture-dict-password" not in output and HASH in output
    output, _ = render_log("key %s", (PRIVATE_PEM.encode(),))
    assert "fixture-private-material" not in output


def test_logging_filter_scrubs_chained_exceptions_cached_traceback_and_stack_info():
    try:
        try:
            raise ValueError("password=fixture-exception-password")
        except ValueError as cause:
            raise RuntimeError(PRIVATE_PEM + "\n" + BLOB) from cause
    except RuntimeError:
        output, record = render_log(
            "failed", exc_info=sys.exc_info(), stack_info="password=fixture-stack-password"
        )
    for forbidden in [
        "fixture-exception-password",
        "fixture-private-material",
        BLOB,
        "fixture-stack-password",
    ]:
        assert forbidden not in output
    assert "ValueError" in output and "RuntimeError" in output and "Traceback" in output
    assert record.exc_info is None
    from app.services.audit import SecretRedactionFilter

    record.exc_text = "password=fixture-cached-password"
    assert SecretRedactionFilter().filter(record) is True
    assert "fixture-cached-password" not in record.exc_text


def test_logging_filter_preserves_record_without_exception_and_fails_closed_on_bad_format():
    output, record = render_log("normal status=%s", ("trusted",))
    assert output == "ERROR normal status=trusted\n" and record.exc_info is None
    output, _ = render_log("password=%d", ("fixture-sensitive",))
    assert "fixture-sensitive" not in output and "[REDACTED]" in output


@pytest.mark.parametrize(
    "body",
    [
        "form_body={'notes':'fixture-form', 'other':'fixture-other'}",
        'request_body="fixture-request"',
        "body=fixture-body",
    ],
)
def test_unstructured_form_bodies_are_not_logged(body):
    from app.services.audit import redact

    assert redact("failed " + body) == "[REDACTED]"
    output, _ = render_log("failed %s", (body,))
    assert "fixture-" not in output
    assert redact({"form_body": "[REDACTED]", "sha256_fingerprint": HASH})["sha256_fingerprint"] == HASH


def test_logging_filter_accepts_none_args_and_replaces_cached_message():
    from app.services.audit import SecretRedactionFilter

    record = logging.LogRecord("fixture", logging.INFO, __file__, 1, "safe event", None, None)
    record.message = "password=fixture-cached-message"
    assert SecretRedactionFilter().filter(record) is True
    assert record.getMessage() == record.message == "safe event"


@pytest.mark.parametrize("mixed", [False, True])
def test_megabyte_text_is_bounded_and_scrubbed_without_catastrophic_backtracking(mixed):
    # Isolate the known ReDoS in a child process: the 10 s subprocess deadline is the
    # real guard (pathological backtracking cannot finish inside it), while the in-child
    # wall clock below is only a coarse smoke alarm on an unpredictable runner.
    script = """
from time import perf_counter
from app.services.audit import redact
import sys
mixed = sys.argv[1] == "True"
value = ("password=fixture-start event=safe " + "ordinary text! " * 75_000
         + " password=fixture-end") if mixed else "A" * 1_000_000
assert len(value) >= 1_000_000
start = perf_counter()
clean = redact(value)
elapsed = perf_counter() - start
# Not the contract: redact() truncates to 64 KiB before any regex runs, so baseline
# speed is machine-bound; a backtracking regression blows far past this ceiling.
assert elapsed < 4.0, elapsed
assert clean.endswith("…[TRUNCATED]")
assert "fixture-start" not in clean and "fixture-end" not in clean
assert "[REDACTED]" in clean
assert len(clean) <= 65_536 + len("…[TRUNCATED]")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(mixed)], check=False, capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, result.stderr


def test_text_limit_retains_exactly_64_kib_before_appending_marker():
    from app.services.audit import redact

    assert redact(" " * 65_536) == " " * 65_536
    assert redact(" " * 65_536 + "discarded") == " " * 65_536 + "…[TRUNCATED]"


def test_nested_tuples_and_sets_are_scrubbed_into_json_lists():
    from app.services.audit import redact

    source = {
        "items": ({"password": "fixture-tuple"}, ({"token": "fixture-nested"},)),
        "tags": {"password=fixture-set"},
    }
    assert redact(source) == {
        "items": [{"password": "[REDACTED]"}, [{"token": "[REDACTED]"}]],
        "tags": ["password=[REDACTED]"],
    }
    assert source["items"][0]["password"] == "fixture-tuple"


@pytest.mark.parametrize(
    "template,args",
    [
        ("user=%s password=%s", ("alice", "hunter2")),
        ("user=%r password=%r", ("alice", "hunter2")),
        ("user=%(user)s password=%(password)s", ({"user": "alice", "password": "hunter2"},)),
        ("user=%(user)r password=%(password)r", ({"user": "alice", "password": "hunter2"},)),
    ],
)
def test_log_secret_arguments_preserve_user_and_formatting(template, args):
    output, _ = render_log(template, args)
    assert "alice" in output and "password=[REDACTED]" in output
    assert "hunter2" not in output and "invalid log formatting" not in output
    if "%s" in template or ")s" in template:
        assert "user=alice" in output
    else:
        assert "user='alice'" in output


def test_bare_key_metadata_is_preserved():
    from app.services.audit import redact

    assert redact({"key": "smtp.host", "api_key": "fixture-api"}) == {
        "key": "smtp.host",
        "api_key": "[REDACTED]",
    }


def test_non_string_mapping_keys_are_normalized():
    from app.services.audit import redact

    assert redact({1: "v"}) == {"1": "v"}


@pytest.mark.parametrize("value", [PRIVATE_PEM.lower(), CERT_PEM.swapcase()])
def test_pem_matching_is_case_insensitive(value):
    from app.services.audit import redact

    assert redact("prefix " + value + " suffix") == "prefix [REDACTED] suffix"


def test_record_rejects_non_json_values_before_staging_an_audit():
    from sqlalchemy.orm import Session

    from app.services.audit import Actor, record

    with Session() as db:
        with pytest.raises(TypeError, match="JSON"):
            record(db, Actor(None, "fixture"), "fixture.event", "fixture", None, {"nested": [object()]})
        assert not db.new


def test_record_stages_normalized_and_redacted_nested_containers():
    from sqlalchemy.orm import Session

    from app.services.audit import Actor, record

    with Session() as db:
        row = record(
            db,
            Actor(None, "fixture"),
            "fixture.event",
            "fixture",
            None,
            {"nested": ({"password": "fixture-password"},), "tags": {"password=fixture-tag"}},
        )
        assert row.details == {
            "nested": [{"password": "[REDACTED]"}],
            "tags": ["password=[REDACTED]"],
        }
        assert list(db.new) == [row]


@pytest.mark.parametrize(
    "shape",
    ["a.", "password.", "a:", "a=", "a@", "x://", "-", "password=a.", "Bearer ", "αβЖé漢.", "A"],
)
def test_every_adversarial_shape_at_cap_is_bounded_and_still_redacts_real_secrets(shape):
    script = """
from time import perf_counter
from app.services.audit import redact
import sys
shape = sys.argv[1]
prefix = "password=" if shape == "password=a." else ""
shape = "a." if prefix else shape
for tail in ["", "\\npassword=fixture-adversarial-secret event=safe"]:
    size = 65_536 - len(prefix) - len(tail)
    value = prefix + (shape * (size // len(shape) + 1))[:size] + tail
    assert len(value) == 65_536
    start = perf_counter()
    clean = redact(value)
    elapsed = perf_counter() - start
    # Smoke alarm, not a contract: the worst shape takes ~80 ms locally, so this only
    # catches a catastrophic regression; the 10 s subprocess deadline is the real guard.
    assert elapsed < 4.0, (sys.argv[1], elapsed)
    assert "fixture-adversarial-secret" not in clean
    if tail:
        assert "password=[REDACTED]" in clean and "event=safe" in clean
"""
    result = subprocess.run(
        [sys.executable, "-c", script, shape],
        check=False,
        capture_output=True,
        text=True,
        # This watchdog includes interpreter/model imports from the Windows mount.
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("failure", ["mapping_key", "index", "message_str", "arg_str"])
def test_log_rendering_exceptions_fail_closed_without_escaping(failure):
    class BadString:
        def __str__(self):
            raise RuntimeError("fixture-secret-from-str")

    class BadIndexRecord(logging.LogRecord):
        def getMessage(self):
            raise IndexError("fixture-secret-from-index")

    from app.services.audit import SecretRedactionFilter

    if failure == "mapping_key":
        record = logging.LogRecord(
            "fixture",
            logging.ERROR,
            __file__,
            1,
            "token %(password)s user %(user)s",
            ({"user": "alice"},),
            None,
        )
    elif failure == "index":
        record = BadIndexRecord("fixture", logging.ERROR, __file__, 1, "fixture event", (), None)
    elif failure == "message_str":
        record = logging.LogRecord("fixture", logging.ERROR, __file__, 1, BadString(), (), None)
    else:
        record = logging.LogRecord("fixture", logging.ERROR, __file__, 1, "%s", (BadString(),), None)
    assert SecretRedactionFilter().filter(record) is True
    assert record.msg == "[REDACTED] invalid log formatting"
    assert record.args == ()


@pytest.mark.parametrize("secret", ["fixture=value", "fixture@token=value", "fixture:token=value"])
def test_assignment_punctuation_inside_a_secret_cannot_end_redaction(secret):
    from app.services.audit import redact

    assert redact(f"password={secret} event=safe") == "password=[REDACTED] event=safe"


def test_inline_label_after_a_message_prefix_is_still_redacted():
    from app.services.audit import redact

    assert redact("error:password=fixture-value event=safe") == "error:password=[REDACTED] event=safe"


def test_unquoted_secret_consumes_punctuation_until_whitespace():
    from app.services.audit import redact

    assert redact("password=a,b") == "password=[REDACTED]"
    assert redact("password=a;b}c]d") == "password=[REDACTED]"
    assert redact("password=x,user=alice") == "password=[REDACTED]"
    assert redact("password=x user=alice") == "password=[REDACTED] user=alice"
    assert redact("authorization: Bearer fixture.token") == "authorization: [REDACTED]"


def test_json_quoted_value_keeps_following_fields():
    from app.services.audit import redact

    assert redact('{"password": "x", "user": "alice"}') == '{"password": [REDACTED], "user": "alice"}'
    assert redact('{"password": "x,y", "user": "alice"}') == '{"password": [REDACTED], "user": "alice"}'


def test_unrenderable_extra_fields_fail_closed_without_raising():
    from app.services.audit import SecretRedactionFilter

    class BadString:
        def __str__(self):
            raise RuntimeError("fixture-secret-detail")

    record = logging.LogRecord("fixture", logging.ERROR, __file__, 1, "safe event", (), None)
    record.direct = BadString()
    record.nested = {"token": "fixture-token", "bad": BadString()}
    assert SecretRedactionFilter().filter(record) is True
    assert record.direct == "[REDACTED] unrenderable"
    assert record.nested == "[REDACTED] unrenderable"
    assert record.msg == "safe event"

    good = logging.LogRecord("fixture", logging.ERROR, __file__, 1, "safe", (), None)
    good.details = {"count": 2, "password": "fixture-password"}
    assert SecretRedactionFilter().filter(good) is True
    assert good.details == {"count": 2, "password": "[REDACTED]"}


@pytest.mark.parametrize(
    "value,secret",
    [
        ("authorization: Bearer fixture-bearer", "fixture-bearer"),
        ("authorization: Basic fixture-basic==", "fixture-basic"),
        ('authorization: Digest username="u", response="fixture-response"', "fixture-response"),
        ("authorization: Token ghp_fixtureToken", "ghp_fixtureToken"),
        ("authorization: Negotiate fixtureNegotiateBlob==", "fixtureNegotiateBlob"),
        ("authorization: NTLM fixture-ntlm", "fixture-ntlm"),
        (
            "authorization: AWS4-HMAC-SHA256 Credential=fixture/20260101, SignedHeaders=host",
            "fixture/20260101",
        ),
        ("authorization: CustomScheme fixture-unknown", "fixture-unknown"),
        ("proxy-authorization: Token fixture-proxy", "fixture-proxy"),
        ('www-authenticate: Digest realm="fixture-realm", nonce="fixture-nonce"', "fixture-nonce"),
    ],
)
def test_authorization_schemes_hide_credentials(value, secret):
    from app.services.audit import redact

    clean = redact(value)
    assert secret not in clean
    assert "[REDACTED]" in clean
    assert redact(clean) == clean


def test_bare_scheme_prose_fails_closed():
    from app.services.audit import redact

    # Without a header label a scheme word cannot be told apart from prose safely;
    # the barrier redacts the rest of the line rather than risk a credential.
    assert redact("Bearer token invalid for user alice") == "[REDACTED]"


def test_url_password_with_empty_username_is_redacted():
    from app.services.audit import redact

    assert redact("redis://:s3cret@cache:6379") == "redis://:[REDACTED]@cache:6379"
    assert redact("postgresql://:s3cret@db/app") == "postgresql://:[REDACTED]@db/app"
    assert redact("http://host:8080/path") == "http://host:8080/path"


@pytest.mark.parametrize(
    "value",
    ['password="s3cret hunter2', "password='s3cret hunter2", 'password="s3cret hunter2 user=alice'],
)
def test_unterminated_quoted_value_consumes_to_line_end(value):
    from app.services.audit import redact

    assert redact(value) == "password=[REDACTED]"


@pytest.mark.parametrize(
    "value,secret",
    [
        ("X-Auth:Basic dXNlci1zZWNyZXQ=", "dXNlci1zZWNyZXQ="),
        ("authentication:Bearer header-token", "header-token"),
        ('hdr:Digest username="u", response=r', "response=r"),
        ("password:Basic password-basic", "password-basic"),
        ("secret:Token abc123", "abc123"),
    ],
)
def test_scheme_word_after_colon_hides_credentials(value, secret):
    from app.services.audit import redact

    clean = redact(value)
    assert secret not in clean
    assert "[REDACTED]" in clean
    assert redact(clean) == clean


def test_scheme_word_inside_a_secret_value_keeps_the_following_field():
    from app.services.audit import redact

    assert redact("password=fixture:token=value event=safe") == "password=[REDACTED] event=safe"


def test_schemeless_url_credentials_are_redacted():
    from app.services.audit import redact

    assert redact("//alice:p4ss@host") == "//alice:[REDACTED]@host"
    assert redact("//:p4ss@host") == "//:[REDACTED]@host"
    assert redact("user:pass@host") == "user:pass@host"
    assert redact("http://host:8080/path") == "http://host:8080/path"


def test_job_type_structured_log_field_survives_redaction_for_every_member():
    from app.models.enums import JobType
    from app.services.audit import SecretRedactionFilter

    for job_type in JobType:
        record = logging.LogRecord("app.jobs.worker", logging.INFO, __file__, 1, "job started", (), None)
        record.job_id = JOB_ID  # type: ignore[attr-defined] - extra fields are how the worker logs
        record.job_type = job_type.value  # type: ignore[attr-defined]
        assert SecretRedactionFilter().filter(record) is True
        assert record.job_type == job_type.value  # type: ignore[attr-defined]
        assert record.job_id == JOB_ID  # type: ignore[attr-defined]


@pytest.mark.parametrize("key", ["job_type", "type"])
def test_every_job_type_value_survives_redaction_as_a_bare_value(key):
    from app.models.enums import JobType
    from app.services.audit import redact

    for job_type in JobType:
        assert redact({key: job_type.value}) == {key: job_type.value}
        assert redact(job_type.value) == job_type.value


@pytest.mark.parametrize(
    "value,secret",
    [
        ("Bearer fixture-token", "fixture-token"),
        ("password=fixture-password", "fixture-password"),
        (PRIVATE_PEM, "fixture-private-material"),
        ("Digest username=\"fixture-user\", response=\"fixture-response\"", "fixture-response"),
    ],
)
def test_credential_shaped_job_type_values_are_still_redacted(value, secret):
    from app.services.audit import SecretRedactionFilter, redact

    cleaned = redact({"job_type": value})
    assert isinstance(cleaned, dict)
    assert secret not in str(cleaned["job_type"]) and "[REDACTED]" in str(cleaned["job_type"])
    record = logging.LogRecord("app.jobs.worker", logging.INFO, __file__, 1, "job started", (), None)
    record.job_type = value  # type: ignore[attr-defined] - mirrors the worker's extra field
    assert SecretRedactionFilter().filter(record) is True
    scrubbed = str(record.job_type)  # type: ignore[attr-defined]
    assert secret not in scrubbed and "[REDACTED]" in scrubbed
