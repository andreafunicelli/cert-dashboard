"""SMTP transport: typed, code-only outcomes against the loopback aiosmtpd capture server."""

import re
import socket
import ssl
import typing
from dataclasses import fields, replace

import pytest

from app.services import smtp as smtp_module
from app.services.smtp import (
    SmtpConfig,
    SmtpStep,
    SmtpStepName,
    build_message,
    job_error_class,
    load_smtp_config,
    open_smtp,
    outcome_message,
    smtp_tls_context,
)

SECRET = "fixture-smtp-password-123"
TLS_TEMPLATE = re.compile(r"TLS handshake or certificate verification failed( \(verify code \d+\))?")


def make_config(capture, security="none", username="", **changes):
    config = SmtpConfig("127.0.0.1", capture.port, security, "dashboard@example.test", username, True, ())
    return replace(config, **changes)


def send_one(config, now, recipient="team@example.test", password=None, **session_args):
    with open_smtp(config, password, **session_args) as session:
        outcome = session.send(build_message(config, [recipient], "s", "body", None, now))
        return outcome, session.steps


def test_tempfail_is_transient_and_reject_is_permanent(smtp_server, now):
    capture = smtp_server()
    config = SmtpConfig("127.0.0.1", capture.port, "none", "dashboard@example.test", "", True, ())
    with open_smtp(config, None) as session:
        ok = session.send(build_message(config, ["team@example.test"], "s", "body", None, now))
        soft = session.send(build_message(config, ["tempfail@example.test"], "s", "body", None, now))
        hard = session.send(build_message(config, ["reject@example.test"], "s", "body", None, now))
    assert ok.delivered and ok.code == "sent"
    assert (soft.code, soft.retryable, soft.message) == ("smtp_transient", True, "451 at rcpt")
    assert (hard.code, hard.retryable, hard.message) == ("smtp_rejected", False, "550 at rcpt")
    assert [message["To"] for message in capture.messages] == ["team@example.test"]


def test_relay_echoing_the_password_never_leaks_it(smtp_server, tls_material, now, caplog):
    secret = "fixture-smtp-password-123"  # unlabeled, short: redact() alone would not catch it
    capture = smtp_server(
        tls=tls_material,
        password="another-password",
        replies={"AUTH": "535 5.7.8 PEER-TEXT-CANARY incorrect credential {password}"},
    )
    config = SmtpConfig("127.0.0.1", capture.port, "starttls", "dashboard@example.test", "mailer", True, ())
    with open_smtp(config, secret.encode(), context=tls_material.client_context()) as session:
        denied = session.send(build_message(config, ["team@example.test"], "s", "b", None, now))
        steps = session.steps
    plain = replace(config, security="none")
    with open_smtp(plain, secret.encode()) as session:
        refused = session.send(build_message(plain, ["team@example.test"], "s", "b", None, now))
    assert (denied.code, denied.retryable, denied.message) == ("smtp_auth", False, "535 at auth")
    assert refused.code == "smtp_not_configured" and capture.connections == 1
    assert [(step.step, step.code) for step in steps][-1] == ("auth", 535)
    leaked = repr(denied) + repr(refused) + repr(steps) + caplog.text
    assert secret not in leaked and "PEER-TEXT-CANARY" not in leaked and "incorrect credential" not in leaked


def test_auth_over_plaintext_is_refused_without_connecting(smtp_server, now):
    capture = smtp_server()
    config = make_config(capture, username="mailer")
    outcome, steps = send_one(config, now, password=SECRET.encode())
    assert (outcome.code, outcome.retryable) == ("smtp_not_configured", False)
    assert outcome.message == "AUTH requires starttls or ssl"
    assert capture.connections == 0 and steps == ()


def test_starttls_delivery_with_a_verified_fixture_ca(smtp_server, tls_material, now):
    capture = smtp_server(tls=tls_material, password=SECRET)
    config = make_config(capture, "starttls", username="mailer")
    outcome, steps = send_one(config, now, password=SECRET.encode(), context=tls_material.client_context())
    assert outcome.delivered and outcome.code == "sent"
    assert [(step.step, step.code) for step in steps] == [
        ("connect", 220), ("ehlo", 250), ("starttls", 220), ("ehlo", 250),
        ("auth", 235), ("mail", 250), ("rcpt", 250), ("data", 250),
    ]  # fmt: skip
    assert outcome.steps == steps
    assert [message["To"] for message in capture.messages] == ["team@example.test"]


def test_untrusted_server_certificate_is_smtp_tls_and_not_retried(smtp_server, tls_material, now, caplog):
    capture = smtp_server(tls=tls_material)
    config = make_config(capture, "starttls")
    outcome, _ = send_one(config, now, context=smtp_tls_context(True))
    assert (outcome.code, outcome.retryable) == ("smtp_tls", False)
    assert TLS_TEMPLATE.fullmatch(outcome.message)  # no certificate subject, no OpenSSL reason
    assert "Fixture" not in outcome.message and "127.0.0.1" not in outcome.message
    assert "certificate verify failed" not in caplog.text


def test_missing_starttls_never_downgrades(smtp_server, now):
    capture = smtp_server()
    config = make_config(capture, "starttls", username="mailer")
    outcome, steps = send_one(config, now, password=SECRET.encode())
    assert (outcome.code, outcome.retryable) == ("smtp_tls", False)
    assert outcome.message == "STARTTLS not offered by the server"
    assert capture.messages == [] and "mail" not in [step.step for step in steps]


def test_server_without_auth_support_is_smtp_auth(smtp_server, tls_material, now):
    capture = smtp_server(tls=tls_material)
    config = make_config(capture, "starttls", username="mailer")
    outcome, _ = send_one(config, now, password=SECRET.encode(), context=tls_material.client_context())
    assert (outcome.code, outcome.retryable) == ("smtp_auth", False)
    assert outcome.message == "AUTH not offered by the server"


def test_implicit_tls_on_ssl_security(smtp_server, tls_material, now):
    capture = smtp_server(tls=tls_material, implicit_tls=True, password=SECRET)
    config = make_config(capture, "ssl", username="mailer")
    outcome, steps = send_one(config, now, password=SECRET.encode(), context=tls_material.client_context())
    assert outcome.delivered
    assert [step.step for step in steps][:3] == ["connect", "ehlo", "auth"]
    assert len(capture.messages) == 1


def test_unverified_context_is_explicit(smtp_server, tls_material, now):
    verified, unverified = smtp_tls_context(True), smtp_tls_context(False)
    assert verified.verify_mode == ssl.CERT_REQUIRED and verified.check_hostname is True
    assert unverified.verify_mode == ssl.CERT_NONE and unverified.check_hostname is False
    capture = smtp_server(tls=tls_material)
    outcome, _ = send_one(make_config(capture, "starttls", tls_verify=False), now, context=unverified)
    assert outcome.delivered


def test_unreachable_server_is_transient(now):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = SmtpConfig("127.0.0.1", port, "none", "dashboard@example.test", "", True, ())
    outcome, steps = send_one(config, now)
    assert (outcome.code, outcome.retryable) == ("smtp_transient", True)
    assert outcome.message == "connection failed (ECONNREFUSED)"
    assert [(step.step, step.code) for step in steps] == [("connect", None)]


def test_silent_server_times_out_at_connect(now):
    with socket.socket() as silent:
        silent.bind(("127.0.0.1", 0))
        silent.listen(1)
        config = SmtpConfig(
            "127.0.0.1", silent.getsockname()[1], "none", "dashboard@example.test", "", True, ()
        )
        outcome, _ = send_one(config, now, timeout_seconds=1)
    assert (outcome.code, outcome.retryable, outcome.message) == (
        "smtp_transient",
        True,
        "timed out at connect",
    )


def test_server_disconnect_reconnects_once(smtp_server, now):
    capture = smtp_server()
    config = make_config(capture)
    with open_smtp(config, None) as session:
        first = session.send(build_message(config, ["team@example.test"], "s", "b", None, now))
        capture.drop_connections()
        second = session.send(build_message(config, ["team@example.test"], "s", "b", None, now))
        hangup = session.send(build_message(config, ["hangup@example.test"], "s", "b", None, now))
    assert first.delivered and second.delivered and len(capture.messages) == 2
    assert (hangup.code, hangup.retryable) == ("smtp_transient", True)
    assert hangup.message == "server closed the connection at rcpt"
    assert capture.connections == 3  # initial, the reconnect after the drop, the one retry after the hangup


def test_message_headers(smtp_server, now):
    capture = smtp_server()
    config = make_config(capture, reply_to=("team@example.test", "ops@example.test"))
    message = build_message(
        config, ["a@example.test", "b@example.test"], "Expiry", "plain", "<p>html</p>", now
    )
    assert message["From"] == "dashboard@example.test"
    assert message["To"] == "a@example.test, b@example.test"
    assert message["Reply-To"] == "team@example.test, ops@example.test"
    assert message["Date"].datetime == now
    assert re.fullmatch(r"<.+@example\.test>", message["Message-ID"])
    assert message.get_content_type() == "multipart/alternative"
    assert [part.get_content_type() for part in message.iter_parts()] == ["text/plain", "text/html"]
    with open_smtp(config, None) as session:
        assert session.send(message).delivered
    [received] = capture.messages
    assert received["Subject"] == "Expiry" and received["Message-ID"] == message["Message-ID"]
    assert "Reply-To" not in build_message(
        replace(config, reply_to=()), ["a@example.test"], "s", "t", None, now
    )


def test_non_ascii_text_is_delivered_intact(smtp_server, now):
    capture = smtp_server()
    config = make_config(capture)
    message = build_message(
        config, ["team@example.test"], "Scadenza è vicina", "Certificato è in scadenza", None, now
    )
    with open_smtp(config, None) as session:
        assert session.send(message).delivered
    assert capture.messages[0].get_content().strip() == "Certificato è in scadenza"
    assert capture.messages[0]["Subject"] == "Scadenza è vicina"


@pytest.mark.parametrize(("verb", "code", "kind", "retryable"), [
    ("MAIL", 554, "smtp_rejected", False),
    ("RCPT", 451, "smtp_transient", True),
    ("DATA", 554, "smtp_rejected", False),
    ("DATA", 452, "smtp_transient", True),
])  # fmt: skip
def test_peer_text_in_every_reply_position_is_discarded(
    smtp_server, now, caplog, verb, code, kind, retryable
):
    capture = smtp_server(replies={verb: f"{code} 5.7.1 PEER-TEXT-CANARY {SECRET} {{password}}"})
    outcome, steps = send_one(make_config(capture), now)
    assert (outcome.code, outcome.retryable) == (kind, retryable)
    assert outcome.message == f"{code} at {verb.lower()}"
    assert (steps[-1].step, steps[-1].code) == (verb.lower(), code)
    leaked = repr(outcome) + repr(steps) + caplog.text
    assert "PEER-TEXT-CANARY" not in leaked and SECRET not in leaked
    assert capture.messages == []


def test_failed_transaction_is_reset_for_the_next_message(smtp_server, now):
    capture = smtp_server()
    config = make_config(capture)
    with open_smtp(config, None) as session:
        refused = session.send(
            build_message(config, ["reject@example.test", "tempfail@example.test"], "s", "b", None, now)
        )
        partial = session.send(
            build_message(config, ["reject@example.test", "team@example.test"], "s", "b", None, now)
        )
    assert (refused.code, refused.message) == ("smtp_rejected", "550 at rcpt")  # the first refusal wins
    assert partial.delivered and len(capture.messages) == 1


def test_message_without_recipients_never_connects(smtp_server, now):
    capture = smtp_server()
    config = make_config(capture)
    with open_smtp(config, None) as session:
        outcome = session.send(build_message(config, [], "s", "b", None, now))
    assert (outcome.code, outcome.retryable, outcome.message) == ("no_recipients", False, "no recipients")
    assert capture.connections == 0


def test_steps_are_fixed_names_and_reply_codes_only(smtp_server, tls_material, now):
    capture = smtp_server(tls=tls_material, password=SECRET)
    config = make_config(capture, "starttls", username="mailer")
    with open_smtp(config, SECRET.encode(), context=tls_material.client_context()) as session:
        session.send(build_message(config, ["team@example.test", "reject@example.test"], "s", "b", None, now))
        session.send(build_message(config, ["tempfail@example.test"], "s", "b", None, now))
        steps = session.steps
    assert {field.name for field in fields(SmtpStep)} == {"step", "code"}
    names = set(typing.get_args(SmtpStepName))
    assert names == {"connect", "ehlo", "starttls", "auth", "mail", "rcpt", "data", "quit"}
    assert len(steps) > 8
    for step in steps:
        assert type(step) is SmtpStep and step.step in names
        assert step.code is None or (type(step.code) is int and 200 <= step.code <= 599)


def test_outcome_messages_come_from_the_fixed_table():
    assert outcome_message("reply", step="rcpt", code=451) == "451 at rcpt"
    assert outcome_message("reply", step="data") == "unexpected reply at data"
    assert outcome_message("connect", errno_value=111) == "connection failed (ECONNREFUSED)"
    assert outcome_message("connect", errno_value=-99999) == "connection failed"
    assert outcome_message("connect") == "connection failed"
    assert outcome_message("timeout", step="connect") == "timed out at connect"
    assert outcome_message("closed", step="mail") == "server closed the connection at mail"
    assert outcome_message("no_starttls") == "STARTTLS not offered by the server"
    assert outcome_message("tls") == "TLS handshake or certificate verification failed"
    assert (
        outcome_message("tls", verify_code=20)
        == "TLS handshake or certificate verification failed (verify code 20)"
    )
    assert outcome_message("no_auth") == "AUTH not offered by the server"
    assert outcome_message("auth_needs_tls") == "AUTH requires starttls or ssl"
    assert outcome_message("not_configured") == "smtp.host, smtp.from or smtp.security is not set"
    assert outcome_message("no_recipients") == "no recipients"
    assert outcome_message("sent") == "sent"
    for bad in ("", "reply2", "PEER-TEXT-CANARY"):
        with pytest.raises(ValueError):
            outcome_message(bad)


def test_job_error_class_maps_codes():
    assert job_error_class("smtp_transient") == "smtp_transient"
    assert job_error_class("smtp_auth") == "auth"
    for code in ("smtp_rejected", "smtp_tls", "smtp_not_configured", "no_recipients"):
        assert job_error_class(code) == "config_invalid"


def test_load_smtp_config_defaults_ports_and_reports_unconfigured(monkeypatch):
    base = {
        "smtp.host": "mail.example.test", "smtp.port": None, "smtp.security": "starttls",
        "smtp.from": "dashboard@example.test", "smtp.username": "", "smtp.tls_verify": True,
        "alert.recipients": ["team@example.test"],
    }  # fmt: skip

    def load(**changes):
        values = {**base, **changes}
        monkeypatch.setattr(smtp_module, "get_setting", lambda db, key: values[key])
        return load_smtp_config(None)

    assert load() == SmtpConfig(
        "mail.example.test", 587, "starttls", "dashboard@example.test", "", True, ("team@example.test",)
    )
    assert load(**{"smtp.security": "ssl"}).port == 465
    assert load(**{"smtp.security": "none"}).port == 25
    assert load(**{"smtp.port": 2525}).port == 2525
    assert load(**{"smtp.tls_verify": False}).tls_verify is False
    assert load(**{"smtp.username": "mailer"}).username == "mailer"
    for key in ("smtp.host", "smtp.from", "smtp.security"):
        assert load(**{key: ""}) is None
