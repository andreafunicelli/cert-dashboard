"""Worker-only SMTP transport with typed, code-only outcomes (Plan 2 Contract decisions 8, 12, 20).

Nothing the peer says and nothing an exception says ever reaches an outcome, a step or a log line.
``redact()`` cannot catch an unlabeled credential echoed in a reply line, so redaction is by
construction: every failure is reduced at the boundary to a fixed step name, an integer reply code
and an integer errno / certificate verify code, and the text comes from the closed table in
``outcome_message``. ``str(exc)``, ``exc.args``, ``smtp_error``, SSL reason strings and AUTH
challenges are never read, formatted or logged (no ``exc_info``), and ``set_debuglevel`` stays 0.
The password is decoded only inside the ``login`` call.
"""

import errno
import smtplib
import socket
import ssl
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.utils import formatdate, getaddresses, make_msgid
from typing import Literal, Self

from sqlalchemy.orm import Session

from app.services.settings import get_setting

SMTP_TIMEOUT_SECONDS = 30
_AUTH_REPLY_CODES = frozenset({530, 534, 535})

SmtpSecurity = Literal["starttls", "ssl", "none"]
SmtpStepName = Literal["connect", "ehlo", "starttls", "auth", "mail", "rcpt", "data", "quit"]
OutcomeCode = Literal[
    "sent", "smtp_not_configured", "no_recipients", "smtp_transient", "smtp_rejected", "smtp_auth", "smtp_tls"
]

_DEFAULT_PORTS: dict[str, int] = {"starttls": 587, "ssl": 465, "none": 25}
_STEPS = frozenset(("connect", "ehlo", "starttls", "auth", "mail", "rcpt", "data", "quit"))
_SETUP_STEPS = frozenset(("connect", "ehlo", "starttls", "auth"))
_WIRE = policy.SMTP.clone(cte_type="7bit")  # CRLF line endings, 7-bit safe transfer encodings
_FIXED_TEXT = {
    "sent": "sent",
    "no_starttls": "STARTTLS not offered by the server",
    "no_auth": "AUTH not offered by the server",
    "auth_needs_tls": "AUTH requires starttls or ssl",
    "not_configured": "smtp.host, smtp.from or smtp.security is not set",
    "no_recipients": "no recipients",
}


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    security: SmtpSecurity
    sender: str
    username: str
    tls_verify: bool
    reply_to: tuple[str, ...]


@dataclass(frozen=True)
class SmtpStep:
    """One protocol step: a fixed name and the integer reply code (200-599) when there was one."""

    step: SmtpStepName
    code: int | None


@dataclass(frozen=True)
class SendOutcome:
    delivered: bool
    code: OutcomeCode
    message: str  # always from the fixed template table
    retryable: bool
    steps: tuple[SmtpStep, ...] = ()


def load_smtp_config(db: Session) -> SmtpConfig | None:
    """The configured transport, or None when ``smtp.host``, ``smtp.from`` or ``smtp.security`` is unset."""
    host, sender, security = (get_setting(db, f"smtp.{name}") for name in ("host", "from", "security"))
    if not (isinstance(host, str) and host and isinstance(sender, str) and sender):
        return None
    if not isinstance(security, str) or security not in _DEFAULT_PORTS:
        return None
    port = get_setting(db, "smtp.port")
    username = get_setting(db, "smtp.username")
    recipients = get_setting(db, "alert.recipients")
    return SmtpConfig(
        host=host,
        port=port if type(port) is int and port > 0 else _DEFAULT_PORTS[security],
        security=security,  # type: ignore[arg-type]
        sender=sender,
        username=username if isinstance(username, str) else "",
        tls_verify=get_setting(db, "smtp.tls_verify") is not False,
        reply_to=tuple(item for item in recipients if isinstance(item, str))
        if isinstance(recipients, list)
        else (),
    )


def _reply_code(code: object) -> int | None:
    return code if type(code) is int and 200 <= code <= 599 else None


def outcome_message(
    kind: str,
    *,
    step: SmtpStepName | None = None,
    code: int | None = None,
    errno_value: int | None = None,
    verify_code: int | None = None,
) -> str:
    """The only constructor of outcome text: a closed table of templates fed by integers and step names."""
    if kind in _FIXED_TEXT:
        return _FIXED_TEXT[kind]
    if kind == "connect":
        symbol = errno.errorcode.get(errno_value) if type(errno_value) is int else None
        return f"connection failed ({symbol})" if symbol else "connection failed"
    if kind == "tls":
        suffix = f" (verify code {verify_code})" if type(verify_code) is int else ""
        return f"TLS handshake or certificate verification failed{suffix}"
    if kind in ("reply", "timeout", "closed") and step in _STEPS:
        if kind == "timeout":
            return f"timed out at {step}"
        if kind == "closed":
            return f"server closed the connection at {step}"
        reply = _reply_code(code)
        return f"{reply} at {step}" if reply is not None else f"unexpected reply at {step}"
    raise ValueError("unknown outcome kind")


def job_error_class(code: str) -> str:
    """The job ``error_class`` for a failed outcome (Plan 1 retry policy vocabulary)."""
    return {"smtp_transient": "smtp_transient", "smtp_auth": "auth"}.get(code, "config_invalid")


def smtp_tls_context(verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()  # system trust store, hostname checking
    if not verify:  # explicit operator opt-out (smtp.tls_verify=false), flagged unsafe in Settings
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def build_message(
    config: SmtpConfig, recipients: Sequence[str], subject: str, text: str, html: str | None, now: datetime
) -> EmailMessage:
    message = EmailMessage(policy=_WIRE)
    message["Message-ID"] = make_msgid(domain=config.sender.rpartition("@")[2] or None)
    message["Date"] = formatdate(now.timestamp(), usegmt=True)
    message["From"] = config.sender
    message["To"] = ", ".join(recipients)
    if config.reply_to:
        message["Reply-To"] = ", ".join(config.reply_to)
    message["Subject"] = subject
    message.set_content(text)
    if html is not None:
        message.add_alternative(html, subtype="html")
    return message


def test_message(config: SmtpConfig, recipient: str, now: datetime) -> EmailMessage:
    """The fixed test e-mail: no settings value beyond ``From`` (not even the team ``Reply-To``)."""
    text = "This is a test message from Cert Dashboard. SMTP delivery works; no action is needed.\n"
    return build_message(replace(config, reply_to=()), [recipient], "Cert Dashboard test email", text, None, now)


test_message.__test__ = False  # type: ignore[attr-defined]  # not a pytest test when imported by name


def transcript_summary(steps: Sequence[SmtpStep]) -> str:
    """``connect 220, ehlo 250, auth 535``: fixed step names and integer codes only."""
    return ", ".join(f"{s.step} {s.code}" if s.code is not None else s.step for s in steps)


class _Abort(Exception):
    """Internal: a finished failure (outcome code + fixed text); carries nothing from the peer."""

    def __init__(self, code: OutcomeCode, text: str) -> None:
        super().__init__()
        self.code, self.text = code, text


def _reply_failure(step: SmtpStepName, code: object, *, connect: bool = False) -> tuple[OutcomeCode, str]:
    reply = _reply_code(code)
    text = outcome_message("reply", step=step, code=reply)
    if connect or (reply is not None and 400 <= reply < 500):
        return "smtp_transient", text
    if step == "auth" or reply in _AUTH_REPLY_CODES:  # Contract decision 8: 530/534/535 whatever the command
        return "smtp_auth", text
    return ("smtp_tls" if step == "starttls" else "smtp_rejected"), text


class SmtpSession:
    """One lazily connected session; at most one reconnect per send after the server hung up."""

    def __init__(
        self, config: SmtpConfig, password: bytes | None, context: ssl.SSLContext, timeout_seconds: int
    ) -> None:
        self._config = config
        self._password = password
        self._context = context
        self._timeout = timeout_seconds
        self._wants_auth = bool(config.username) and bool(password)
        self._client: smtplib.SMTP | None = None
        self._steps: list[SmtpStep] = []
        self._step: SmtpStepName = "connect"
        self._broken: SendOutcome | None = None  # a failed setup is final for this session

    @property
    def steps(self) -> tuple[SmtpStep, ...]:
        return tuple(self._steps)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        client = self._client
        if client is None:
            return
        with suppress(Exception):  # the peer's complaint on QUIT is of no interest
            self._record("quit", client.quit()[0])
        self._drop()

    def send(self, message: EmailMessage) -> SendOutcome:
        """Deliver ``message`` to its To recipients. Never raises; failures are typed outcomes."""
        start = len(self._steps)
        if self._broken is not None:
            return self._broken
        recipients = [addr for _, addr in getaddresses([str(v) for v in message.get_all("To", [])]) if addr]
        if not recipients:
            return self._outcome(False, "no_recipients", outcome_message("no_recipients"), start)
        if self._wants_auth and self._config.security == "none":
            return self._fail("smtp_not_configured", outcome_message("auth_needs_tls"), start, final=True)
        try:
            payload = message.as_bytes(policy=_WIRE)
        except Exception:  # noqa: BLE001 - header/encoding problems; never echo their text
            return self._fail("smtp_rejected", outcome_message("reply", step="data"), start)
        reconnected = False
        while True:
            try:
                self._connect()
                self._deliver(recipients, payload)
                return self._outcome(True, "sent", outcome_message("sent"), start)
            except _Abort as abort:
                return self._fail(abort.code, abort.text, start)
            except smtplib.SMTPServerDisconnected as exc:
                timed_out = isinstance(exc.__context__, TimeoutError)  # only the type is inspected
                self._record(self._step, None)
                self._drop()
                if not timed_out and not reconnected:
                    reconnected = True
                    continue
                kind = "timeout" if timed_out else "closed"
                return self._fail("smtp_transient", outcome_message(kind, step=self._step), start)
            except Exception as exc:  # noqa: BLE001 - reduced to (step, code) at the boundary
                code, text = self._classify(exc)
                return self._fail(code, text, start)

    # -- internals ---------------------------------------------------------------------------

    def _record(self, step: SmtpStepName, code: object) -> object:
        self._steps.append(SmtpStep(step, _reply_code(code)))
        return code

    def _outcome(self, delivered: bool, code: OutcomeCode, text: str, start: int) -> SendOutcome:
        return SendOutcome(delivered, code, text, code == "smtp_transient", tuple(self._steps[start:]))

    def _fail(self, code: OutcomeCode, text: str, start: int, *, final: bool = False) -> SendOutcome:
        outcome = self._outcome(False, code, text, start)
        if final or self._step in _SETUP_STEPS:
            self._broken = outcome
            self._drop()
        elif self._step in ("rcpt", "data"):
            self._reset()
        return outcome

    def _drop(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            with suppress(Exception):
                client.close()

    def _reset(self) -> None:
        if self._client is not None:
            try:
                self._client.rset()
            except Exception:  # noqa: BLE001 - a session we cannot reset is not reused
                self._drop()

    def _classify(self, exc: Exception) -> tuple[OutcomeCode, str]:
        """Reduce an exception to a code and fixed text using its type and integer fields only."""
        step = self._step
        if isinstance(exc, ssl.SSLError):
            verify = exc.verify_code if isinstance(exc, ssl.SSLCertVerificationError) else None
            self._record(step, None)
            return "smtp_tls", outcome_message("tls", verify_code=verify)
        if isinstance(exc, TimeoutError):
            self._record(step, None)
            return "smtp_transient", outcome_message("timeout", step=step)
        if isinstance(exc, smtplib.SMTPNotSupportedError):
            self._record(step, None)
            return (
                ("smtp_tls", outcome_message("no_starttls"))
                if step == "starttls"
                else (
                    "smtp_auth",
                    outcome_message("no_auth"),
                )
            )
        if isinstance(exc, smtplib.SMTPResponseException):
            code = self._record(step, exc.smtp_code)  # the integer only; smtp_error is never read
            return _reply_failure(step, code, connect=isinstance(exc, smtplib.SMTPConnectError))
        if isinstance(exc, OSError) and not isinstance(exc, smtplib.SMTPException):
            self._record(step, None)
            return "smtp_transient", outcome_message("connect", errno_value=exc.errno)
        self._record(step, None)
        return ("smtp_auth" if step == "auth" else "smtp_rejected"), outcome_message("reply", step=step)

    def _expect(self, step: SmtpStepName, code: object, accepted: Sequence[int] = (250,)) -> None:
        self._record(step, code)
        if code not in accepted:
            raise _Abort(*_reply_failure(step, code))

    def _connect(self) -> None:
        if self._client is not None:
            return
        config = self._config
        self._step = "connect"
        local_hostname = socket.gethostname() or "localhost"  # getfqdn() would do reverse DNS
        # The constructor connects and reads the banner; it raises SMTPConnectError unless the code is 220.
        # (Passing the host there also makes smtplib verify the certificate against it.)
        if config.security == "ssl":
            client: smtplib.SMTP = smtplib.SMTP_SSL(
                config.host,
                config.port,
                local_hostname=local_hostname,
                timeout=self._timeout,
                context=self._context,
            )
        else:
            client = smtplib.SMTP(
                config.host, config.port, local_hostname=local_hostname, timeout=self._timeout
            )
        self._client = client
        self._record("connect", 220)
        self._step = "ehlo"
        self._expect("ehlo", client.ehlo()[0])
        if config.security == "starttls":  # never fall back to plaintext
            self._step = "starttls"
            if not client.has_extn("starttls"):
                self._record("starttls", None)
                raise _Abort("smtp_tls", outcome_message("no_starttls"))
            self._record("starttls", client.starttls(context=self._context)[0])
            self._step = "ehlo"
            self._expect("ehlo", client.ehlo()[0])
        if self._wants_auth:
            self._step = "auth"
            if not client.esmtp_features.get("auth", "").split():  # no mechanism listed
                self._record("auth", None)
                raise _Abort("smtp_auth", outcome_message("no_auth"))
            assert self._password is not None
            self._record("auth", client.login(config.username, self._password.decode("utf-8"))[0])

    def _deliver(self, recipients: Sequence[str], payload: bytes) -> None:
        client = self._client
        assert client is not None
        self._step = "mail"
        self._expect("mail", client.mail(self._config.sender)[0])
        accepted, first_refusal = 0, None
        self._step = "rcpt"
        for address in recipients:
            code = self._record("rcpt", client.rcpt(address)[0])
            if code in (250, 251):
                accepted += 1
            elif first_refusal is None:
                first_refusal = code
        if not accepted:
            raise _Abort(*_reply_failure("rcpt", first_refusal))
        self._step = "data"
        self._expect("data", client.data(payload)[0])


def open_smtp(
    config: SmtpConfig,
    password: bytes | None,
    *,
    context: ssl.SSLContext | None = None,
    timeout_seconds: int = SMTP_TIMEOUT_SECONDS,
) -> SmtpSession:
    """A context manager owning one lazily connected session (connects on the first ``send``)."""
    return SmtpSession(config, password, context or smtp_tls_context(config.tls_verify), timeout_seconds)
