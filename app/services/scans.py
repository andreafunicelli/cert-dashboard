"""Outbound TLS inspection: the served-chain primitive and the pull-import payload contract.

Only the worker ever calls ``pull_chain`` (spec 3.1: the web process makes no TLS inspection
connections). Plan 2 reuses it for scheduled scans.
"""

import errno
import hashlib
import selectors
import socket
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from typing import Literal

from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import SSL
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.csr import parse_san
from app.crypto.parse import ParseError, parse_certificates
from app.jobs.queue import JobFailure, enqueue, safe_error_message
from app.models import Certificate, Endpoint, Job, JSONValue, ScanResult
from app.models.enums import JobType, ScanStatus
from app.services.audit import Actor
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


# --- endpoint observation and classified scan results ---------------------------------------------

_UNPARSEABLE_MESSAGE = "Served certificate could not be parsed."


@dataclass(frozen=True)
class ScanObservation:
    """What an endpoint served (or why nothing could be observed). Never imported, never trusted."""

    fingerprint: str | None
    common_name: str | None
    issuer_cn: str | None
    not_after: datetime | None
    chain_length: int | None
    tls_version: str | None
    failure: Literal["unreachable", "error"] | None
    error: str | None
    elapsed_ms: int


def observation_from_chain(pulled: PulledChain, elapsed_ms: int) -> ScanObservation:
    """Describe the served leaf; an unparseable leaf keeps its hash with a fixed error message."""
    leaf = pulled.der_chain[0]
    served = {
        "fingerprint": hashlib.sha256(leaf).hexdigest(),
        "chain_length": len(pulled.der_chain),
        "tls_version": pulled.tls_version,
        "elapsed_ms": elapsed_ms,
    }
    try:
        parsed = parse_certificates(leaf)[0]
    except (ParseError, IndexError):
        return ScanObservation(
            common_name=None, issuer_cn=None, not_after=None, failure="error", error=_UNPARSEABLE_MESSAGE, **served
        )
    return ScanObservation(
        common_name=parsed.common_name,
        issuer_cn=parsed.issuer_cn,
        not_after=parsed.not_after,
        failure=None,
        error=None,
        **served,
    )


def observe_endpoint(host: str, port: int, sni: str | None, timeout_seconds: int) -> ScanObservation:
    """Pull the served chain and describe it; network/TLS failures become observations, not exceptions."""
    started = time.monotonic()
    try:
        pulled = pull_chain(host, port, sni, timeout_seconds)
    except JobFailure as exc:
        failure = "unreachable" if exc.error_class == "transient_network" else "error"
        elapsed_ms = round((time.monotonic() - started) * 1000)
        return ScanObservation(None, None, None, None, None, None, failure, exc.message, elapsed_ms)
    return observation_from_chain(pulled, round((time.monotonic() - started) * 1000))


def classify_observation(observation: ScanObservation, expected_fingerprint: str | None, now: datetime) -> ScanStatus:
    """No leaf -> unreachable/error; else expired beats ok/mismatch; ok only on the expected fingerprint."""
    if observation.failure == "unreachable":
        return ScanStatus.UNREACHABLE
    if observation.failure == "error" or observation.fingerprint is None:
        return ScanStatus.ERROR
    if observation.not_after is not None and observation.not_after < now:
        return ScanStatus.EXPIRED
    if expected_fingerprint is not None and observation.fingerprint.lower() == expected_fingerprint.lower():
        return ScanStatus.OK
    return ScanStatus.MISMATCH


def record_scan(
    db: Session,
    endpoint_id: int,
    observation: ScanObservation,
    source: Literal["scheduled", "manual"],
    now: datetime,
) -> ScanResult:
    """Insert one ``scan_result`` and advance ``endpoint.last_scan_*`` unless a newer scan already did.

    Locks the endpoint row and snapshots its current expectation; reads ``certificate`` only for the
    expected fingerprint and writes nothing else. The caller owns the transaction (no commit here).
    """
    # populate_existing: an Endpoint already in this session's identity map must be overwritten with the
    # locked row, or a stale last_scan_at / expectation would be used (and a newer scan regressed).
    endpoint = db.execute(
        select(Endpoint).where(Endpoint.id == endpoint_id).with_for_update().execution_options(populate_existing=True)
    ).scalar_one()
    expected_id = endpoint.expected_certificate_id
    expected_fingerprint = (
        db.scalar(select(Certificate.sha256_fingerprint).where(Certificate.id == expected_id))
        if expected_id is not None
        else None
    )
    status = classify_observation(observation, expected_fingerprint, now)
    result = ScanResult(
        endpoint_id=endpoint.id,
        status=status,
        observed_fingerprint=observation.fingerprint,
        observed_common_name=observation.common_name,
        observed_issuer_cn=observation.issuer_cn,
        observed_not_after=observation.not_after,
        observed_chain_length=observation.chain_length,
        expected_certificate_id=expected_id,
        tls_version=observation.tls_version,
        error=safe_error_message(observation.error),
        source=source,
        checked_at=now,
        elapsed_ms=observation.elapsed_ms,
    )
    db.add(result)
    if endpoint.last_scan_at is None or endpoint.last_scan_at <= now:
        endpoint.last_scan_at = now
        endpoint.last_scan_status = status
    db.flush()
    return result


# --- scan/default: payload, target resolution and on-demand requests -----------------------------

ON_DEMAND_PRIORITY = 200
MAX_SCAN_ENDPOINTS = 1000
_SCAN_KEYS = frozenset({"action", "endpoint_ids", "certificate_id"})


@dataclass(frozen=True)
class ScanTarget:
    """Plain values for one endpoint, so no ORM object (or session) is needed during network I/O."""

    endpoint_id: int
    host: str
    port: int
    sni: str | None


class ScanRequestError(LookupError):
    """A scan was requested for an endpoint or certificate that does not exist."""


def _positive_int(value: object) -> bool:
    return type(value) is int and value >= 1


def validate_scan_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Accept ``{}``, ``{"endpoint_ids": [...]}`` or ``{"certificate_id": N}`` (plus ``action: default``).

    Endpoint ids are 1-1000 unique positive integers and are returned sorted; ``action`` is dropped.
    Anything else raises ``ValueError``.
    """
    if not isinstance(payload, Mapping) or not set(payload) <= _SCAN_KEYS:
        raise ValueError("unexpected scan payload keys")
    if payload.get("action", "default") != "default":
        raise ValueError("invalid scan action")
    if "endpoint_ids" in payload and "certificate_id" in payload:
        raise ValueError("a scan targets endpoints or a certificate, not both")
    clean: dict[str, JSONValue] = {}
    if "endpoint_ids" in payload:
        ids = payload["endpoint_ids"]
        if (
            not isinstance(ids, list)
            or not 1 <= len(ids) <= MAX_SCAN_ENDPOINTS
            or not all(_positive_int(item) for item in ids)
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("endpoint_ids must be 1-1000 unique positive integers")
        clean["endpoint_ids"] = sorted(ids)
    if "certificate_id" in payload:
        if not _positive_int(payload["certificate_id"]):
            raise ValueError("certificate_id must be a positive integer")
        clean["certificate_id"] = payload["certificate_id"]
    return clean


def scan_targets(
    db: Session, payload: Mapping[str, JSONValue], *, only_unreachable: bool = False
) -> tuple[list[ScanTarget], int]:
    """Resolve a payload to the active endpoints to scan, plus how many in scope are inactive.

    ``only_unreachable`` (retry attempts) keeps just the endpoints whose latest scan was unreachable.
    """
    clean = validate_scan_payload(payload)
    query = select(Endpoint).order_by(Endpoint.id)
    if "endpoint_ids" in clean:
        query = query.where(Endpoint.id.in_(clean["endpoint_ids"]))  # type: ignore[arg-type]
    elif "certificate_id" in clean:
        query = query.where(Endpoint.expected_certificate_id == clean["certificate_id"])
    rows = db.scalars(query).all()
    active = [row for row in rows if row.is_active]
    if only_unreachable:
        active = [row for row in active if row.last_scan_status is ScanStatus.UNREACHABLE]
    targets = [ScanTarget(row.id, row.host, row.port, row.sni) for row in active]
    return targets, len(rows) - sum(row.is_active for row in rows)


def request_scan(db: Session, payload: Mapping[str, JSONValue], actor: Actor, now: datetime) -> Job:
    """Validate and enqueue an on-demand ``scan/default`` job; the web process never connects out."""
    clean = validate_scan_payload(payload)
    if "endpoint_ids" in clean:
        wanted = set(clean["endpoint_ids"])  # type: ignore[arg-type]
        known = set(db.scalars(select(Endpoint.id).where(Endpoint.id.in_(wanted))))
        if known != wanted:
            raise ScanRequestError("One or more endpoints do not exist.")
    elif "certificate_id" in clean and db.get(Certificate, clean["certificate_id"]) is None:
        raise ScanRequestError("The certificate does not exist.")
    return enqueue(
        db, JobType.SCAN, clean, actor, priority=ON_DEMAND_PRIORITY, run_after=now, max_attempts=3
    )
