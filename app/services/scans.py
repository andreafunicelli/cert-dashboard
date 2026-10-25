"""Outbound TLS inspection: the served-chain primitive and the pull-import payload contract.

Only the worker ever calls ``pull_chain`` (spec 3.1: the web process makes no TLS inspection
connections). Plan 2 reuses it for scheduled scans.
"""

import errno
import selectors
import socket
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import ip_address

from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import SSL

from app.crypto.csr import parse_san
from app.jobs.queue import JobFailure
from app.models import JSONValue
from app.services.certificates import CertificateMetadata, InventoryError

PULL_ACTION = "import_pull"
MAX_CHAIN_CERTIFICATES = 10
MAX_CHAIN_BYTES = 1_048_576
_PAYLOAD_KEYS = frozenset({"action", "host", "port", "sni", "metadata"})
_METADATA_KEYS = ("owner_name", "owner_email", "team", "notes")
_HOST_MESSAGE = (
    "Enter a host name or an IP address only: no scheme, path, port, credentials or network range."
)
_SNI_MESSAGE = "Enter a DNS name for SNI (not an IP address, wildcard or URL)."
_PORT_MESSAGE = "Enter a port between 1 and 65535."


class PullPayloadError(ValueError):
    """Invalid pull-import input; ``errors`` maps a form field to a message safe to display."""

    def __init__(self, errors: Mapping[str, str]) -> None:
        super().__init__("invalid pull import payload")
        self.errors: dict[str, str] = dict(errors)


def _has_unsafe_character(value: str) -> bool:
    return any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)


def _dns_host(value: str, what: str) -> str:
    """Canonical (IDNA/UTS #46, lower-case) single DNS name; wildcards and IPs are not names."""
    if (
        not value
        or _has_unsafe_character(value)
        or any(char in value for char in "/@\\?#%[]:*")
    ):
        raise ValueError(what)
    try:
        ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError(what)
    try:
        name = parse_san("DNS:" + value)
    except ValueError:
        raise ValueError(what) from None
    return name.value  # type: ignore[attr-defined]  # "DNS:" always yields a DNSName


def canonical_host(value: object) -> str:
    """Return the canonical DNS name or IP literal for ``value``; ``ValueError`` if it is neither."""
    if not isinstance(value, str) or not value or _has_unsafe_character(value):
        raise ValueError(_HOST_MESSAGE)
    bracketed = value.startswith("[") and value.endswith("]")
    candidate = value[1:-1] if bracketed else value
    if ":" in candidate:  # only an IPv6 literal may contain a colon
        if "%" in candidate:
            raise ValueError(_HOST_MESSAGE)
        try:
            address = ip_address(candidate)
        except ValueError:
            raise ValueError(_HOST_MESSAGE) from None
        if address.version != 6:  # pragma: no cover - IPv4 never contains a colon
            raise ValueError(_HOST_MESSAGE)
        return str(address)
    if bracketed:
        raise ValueError(_HOST_MESSAGE)  # brackets are for IPv6 literals only
    try:
        return str(ip_address(candidate))
    except ValueError:
        return _dns_host(candidate, _HOST_MESSAGE)


def _metadata(value: object) -> dict[str, JSONValue]:
    if value is None:
        value = {}
    if not isinstance(value, Mapping) or not set(value) <= set(_METADATA_KEYS):
        raise ValueError("Metadata must contain only owner name, owner email, team and notes.")
    try:
        clean = CertificateMetadata(**{name: value.get(name) for name in _METADATA_KEYS})
    except InventoryError as exc:
        raise ValueError(exc.message) from None
    return {name: getattr(clean, name) for name in _METADATA_KEYS}


def validate_pull_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Validate and normalize a pull-import payload; raises ``PullPayloadError`` (a ``ValueError``).

    Used identically by the web form (before enqueue) and by the job registry (before dispatch).
    """
    if not isinstance(payload, Mapping):
        raise PullPayloadError({"payload": "The pull request is invalid."})
    errors: dict[str, str] = {}
    if not set(payload) <= _PAYLOAD_KEYS:
        errors["payload"] = "The pull request contains unexpected fields."
    if payload.get("action") != PULL_ACTION:
        errors["action"] = "The pull request has the wrong action."
    host = sni = metadata = None
    port = payload.get("port")
    try:
        host = canonical_host(payload.get("host"))
    except ValueError as exc:
        errors["host"] = str(exc)
    if type(port) is not int or not 1 <= port <= 65535:
        errors["port"] = _PORT_MESSAGE
    raw_sni = payload.get("sni")
    if raw_sni is not None:
        try:
            if not isinstance(raw_sni, str):
                raise TypeError
            sni = _dns_host(raw_sni, _SNI_MESSAGE)
        except (TypeError, ValueError):
            errors["sni"] = _SNI_MESSAGE
    try:
        metadata = _metadata(payload.get("metadata"))
    except ValueError as exc:
        errors["metadata"] = str(exc)
    if errors:
        raise PullPayloadError(errors)
    return {"action": PULL_ACTION, "host": host, "port": port, "sni": sni, "metadata": metadata}


# --- served-chain retrieval ----------------------------------------------------------------------


@dataclass(frozen=True)
class PulledChain:
    """Certificates exactly as served (leaf first), DER encoded, plus the negotiated TLS version."""

    der_chain: tuple[bytes, ...]
    tls_version: str


def format_hostport(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _unreachable(label: str, reason: str) -> JobFailure:
    return JobFailure("transient_network", f"{label} unreachable: {reason}", retryable=True)


def _handshake_failed(label: str) -> JobFailure:
    return JobFailure("config_invalid", f"{label}: TLS handshake failed")


def _remaining(deadline: float, label: str) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise _unreachable(label, "timeout")
    return left


def _is_ip(host: str) -> bool:
    try:
        ip_address(host)
    except ValueError:
        return False
    return True


def _addresses(host: str, port: int, deadline: float, label: str) -> list[tuple]:
    """Resolve within the deadline: ``getaddrinfo`` cannot be interrupted, so it runs on a daemon thread."""
    outcome: dict[str, object] = {}

    def work() -> None:
        try:
            outcome["infos"] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            outcome["failed"] = True

    resolver = threading.Thread(target=work, name="pull-resolve", daemon=True)
    resolver.start()
    resolver.join(_remaining(deadline, label))
    if resolver.is_alive():
        raise _unreachable(label, "timeout")
    if "infos" not in outcome:
        raise _unreachable(label, "dns")
    return list(outcome["infos"])  # type: ignore[call-overload]


def _connect(host: str, port: int, deadline: float, label: str) -> socket.socket:
    failure = _unreachable(label, "refused")
    for family, kind, proto, _, address in _addresses(host, port, deadline, label):
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(_remaining(deadline, label))
            sock.connect(address)
        except TimeoutError:
            sock.close()
            failure = _unreachable(label, "timeout")
        except OSError:
            sock.close()
            failure = _unreachable(label, "refused")
        except BaseException:
            sock.close()
            raise
        else:
            return sock
    raise failure


def _wait(sock: socket.socket, event: int, deadline: float, label: str) -> None:
    with selectors.DefaultSelector() as selector:
        selector.register(sock, event)
        if not selector.select(_remaining(deadline, label)):
            raise _unreachable(label, "timeout")


def _handshake(sock: socket.socket, host: str, sni: str | None, deadline: float, label: str) -> SSL.Connection:
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.set_verify(SSL.VERIFY_NONE)  # inspection only: what is served is recorded, never trusted
    server_name = sni or (None if _is_ip(host) else host)
    sock.setblocking(False)
    connection = SSL.Connection(context, sock)
    if server_name:
        connection.set_tlsext_host_name(server_name.encode("ascii"))
    connection.set_connect_state()
    while True:
        try:
            connection.do_handshake()
        except SSL.WantReadError:
            _wait(sock, selectors.EVENT_READ, deadline, label)
        except SSL.WantWriteError:
            _wait(sock, selectors.EVENT_WRITE, deadline, label)
        except SSL.SysCallError as exc:
            reset = bool(exc.args) and exc.args[0] in (errno.ECONNRESET, errno.EPIPE, errno.ECONNABORTED)
            raise (_unreachable(label, "refused") if reset else _handshake_failed(label)) from None
        except SSL.Error:
            raise _handshake_failed(label) from None
        else:
            return connection


def _served_chain(connection: SSL.Connection, label: str) -> tuple[bytes, ...]:
    try:
        chain = connection.get_peer_cert_chain(as_cryptography=True)
        if not chain:
            peer = connection.get_peer_certificate(as_cryptography=True)
            chain = [peer] if peer is not None else []
        ders: list[bytes] = []
        total = 0
        for cert in chain[:MAX_CHAIN_CERTIFICATES]:
            der = cert.public_bytes(Encoding.DER)
            if total + len(der) > MAX_CHAIN_BYTES:
                break
            ders.append(der)
            total += len(der)
    except Exception:  # noqa: BLE001 - a hostile peer must fail as a sanitized parse failure
        raise JobFailure("config_invalid", f"{label}: served certificate could not be parsed") from None
    if not ders:
        raise JobFailure("config_invalid", f"{label}: served certificate could not be parsed")
    return tuple(ders)


def pull_chain(host: str, port: int, sni: str | None, timeout_seconds: int = 10) -> PulledChain:
    """Connect to ``host:port`` and return the chain it serves, without verifying it.

    SNI is ``sni`` or, for a DNS name, the host itself; an IP literal without ``sni`` sends none.
    Resolution, connect, handshake and reads share one monotonic deadline of ``timeout_seconds``.
    Failures are ``JobFailure`` with fixed messages (host:port only; nothing the peer or the
    resolver said is echoed): DNS/refused/reset/timeout are retryable ``transient_network``;
    handshake/protocol/parse problems are ``config_invalid``.
    """
    label = format_hostport(host, port)
    deadline = time.monotonic() + timeout_seconds
    sock = _connect(host, port, deadline, label)
    try:
        connection = _handshake(sock, host, sni, deadline, label)
        der_chain = _served_chain(connection, label)
        return PulledChain(der_chain, connection.get_protocol_version_name())
    finally:
        sock.close()
