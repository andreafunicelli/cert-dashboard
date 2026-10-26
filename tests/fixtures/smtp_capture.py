"""Local SMTP capture server (aiosmtpd) for tests; also runs as the ``smtp`` compose test service.

Recipient scripting by local part: ``tempfail…`` -> ``451 4.3.0``, ``reject…`` -> ``550 5.1.1``,
``hangup…`` -> the server closes the connection. ``replies`` overrides the reply line per verb
(``AUTH``/``MAIL``/``RCPT``/``DATA``); ``{password}`` is replaced by the password the client sent, to
emulate a hostile relay that echoes credentials.

CLI: ``python -m tests.fixtures.smtp_capture --listen HOST:PORT --spool DIR`` stores every message as
an ``.eml`` file; ``--dump DIR`` prints the spooled messages as a JSON array of strings and exits.
"""

import argparse
import ipaddress
import json
import socket
import ssl
import sys
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email import message_from_bytes, policy
from email.message import EmailMessage
from pathlib import Path

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, AuthResult
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tests.fixtures.ca import FixtureCA


@dataclass(frozen=True)
class TLSMaterial:
    """A leaf for 127.0.0.1 issued by a fixture CA, with ready-made server and client contexts."""

    ca_pem: bytes
    chain_pem: bytes  # leaf + intermediate
    key_pem: bytes

    def server_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with tempfile.TemporaryDirectory() as directory:  # load_cert_chain only reads files
            chain, key = Path(directory, "chain.pem"), Path(directory, "key.pem")
            chain.write_bytes(self.chain_pem)
            key.write_bytes(self.key_pem)
            context.load_cert_chain(chain, key)
        return context

    def client_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cadata=self.ca_pem.decode("ascii"))


def make_tls_material() -> TLSMaterial:
    """OpenSSL verifies against wall-clock time, hence ``datetime.now(UTC)`` (Plan 2 decision 19)."""
    ca = FixtureCA(datetime.now(UTC))
    key = ec.generate_private_key(ec.SECP256R1())
    sans = [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    leaf = ca.issue(public_key=key.public_key(), common_name="127.0.0.1", sans=sans)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return TLSMaterial(ca.root_pem, leaf + ca.chain_pem, key_pem)


def _free_port(host: str) -> int:
    with socket.socket() as probe:
        probe.bind((host, 0))
        return probe.getsockname()[1]


class _Handler:
    def __init__(self, replies: Mapping[str, str], spool: Path | None) -> None:
        self.replies = dict(replies)
        self.spool = spool
        self.messages: list[EmailMessage] = []
        self.last_password = ""
        self._count = 0
        self._lock = threading.Lock()

    def _override(self, verb: str) -> str | None:
        reply = self.replies.get(verb)
        return None if reply is None else reply.replace("{password}", self.last_password)

    def authenticate(self, expected: str | None):
        def authenticator(server, session, envelope, mechanism, auth_data):
            self.last_password = bytes(auth_data.password).decode("utf-8", "replace")
            override = self._override("AUTH")
            if override is not None:
                return AuthResult(success=False, handled=False, message=override)
            return AuthResult(success=expected is not None and self.last_password == expected, handled=False)

        return authenticator

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        if (reply := self._override("MAIL")) is not None:
            return reply
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if (reply := self._override("RCPT")) is not None:
            return reply
        local = address.partition("@")[0].lower()
        if local.startswith("tempfail"):
            return "451 4.3.0 Temporary failure, try again later"
        if local.startswith("reject"):
            return "550 5.1.1 Mailbox unavailable"
        if local.startswith("hangup"):
            server.transport.close()
            return "421 4.3.0 Closing"
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        if (reply := self._override("DATA")) is not None:
            return reply
        message = message_from_bytes(envelope.original_content, policy=policy.default)
        with self._lock:
            self.messages.append(message)
            self._count += 1
            if self.spool is not None:
                (self.spool / f"{self._count:06d}.eml").write_bytes(envelope.original_content)
        return "250 OK"


class _CountingController(Controller):
    def __init__(self, *args, owner, **kwargs):
        self.owner = owner
        super().__init__(*args, **kwargs)

    def factory(self):
        owner = self.owner

        class Server(SMTP):
            def connection_made(self, transport):
                owner._peers.add(transport.get_extra_info("peername"))  # STARTTLS re-enters here
                owner._transports.append(transport)
                super().connection_made(transport)

        return Server(self.handler, **self.SMTP_kwargs)


class CaptureServer:
    """An in-process aiosmtpd listener on 127.0.0.1 (``port=None`` picks a free port)."""

    def __init__(
        self,
        *,
        port: int | None = None,
        tls: TLSMaterial | None = None,
        implicit_tls: bool = False,
        password: str | None = None,
        replies: Mapping[str, str] | None = None,
        host: str = "127.0.0.1",
        spool: Path | None = None,
    ) -> None:
        self._peers: set = set()
        self._transports: list = []
        self._handler = _Handler(replies or {}, spool)
        self.port = port or _free_port(host)
        options: dict = {}
        if tls is not None:
            context = tls.server_context()
            options["ssl_context" if implicit_tls else "tls_context"] = context
        if password is not None or "AUTH" in (replies or {}):
            options["authenticator"] = self._handler.authenticate(password)
            options["auth_require_tls"] = not implicit_tls  # aiosmtpd does not see implicit TLS as TLS
        else:
            options["auth_exclude_mechanism"] = ["LOGIN", "PLAIN"]  # AUTH is not offered
        self._controller = _CountingController(
            self._handler, owner=self, hostname=host, port=self.port, ready_timeout=10, **options
        )
        self._controller.start()
        self._peers.clear()  # the controller's readiness probe is not a client

    @property
    def connections(self) -> int:
        return len(self._peers)

    @property
    def messages(self) -> list[EmailMessage]:
        return self._handler.messages

    def drop_connections(self) -> None:
        """Close every open client connection from the server side."""
        transports, self._transports = self._transports, []
        for transport in transports:
            self._controller.loop.call_soon_threadsafe(transport.close)

    def close(self) -> None:
        self._controller.stop()


def _dump(directory: Path) -> str:
    return json.dumps([path.read_text("utf-8", "replace") for path in sorted(directory.glob("*.eml"))])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen", default="127.0.0.1:1025", help="HOST:PORT")
    parser.add_argument("--spool", type=Path, help="write each received message as an .eml file here")
    parser.add_argument("--dump", type=Path, help="print the .eml files of DIR as a JSON array and exit")
    args = parser.parse_args(argv)
    if args.dump is not None:
        sys.stdout.write(_dump(args.dump))
        return 0
    host, _, port = args.listen.rpartition(":")
    if args.spool is not None:
        args.spool.mkdir(parents=True, exist_ok=True)
    server = CaptureServer(host=host, port=int(port), spool=args.spool)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
