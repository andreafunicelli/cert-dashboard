"""Explicit audit metadata and a shared second barrier against secret leakage.

Only labeled secrets, PEM, Bearer/Basic credentials, URL credentials and long
base64 runs are caught. Unlabeled secrets are not: call sites must pass explicit
allowlisted metadata and must never submit request/form bodies.
"""

import logging
import re
import traceback
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_interface

from sqlalchemy import cast, func, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Session

from app.models import AuditLog, JSONValue

_REDACTED = "[REDACTED]"
_TEXT_LIMIT = 65_536
_TRUNCATED = "…[TRUNCATED]"
_SAFE_METADATA = {
    "sha256fingerprint",
    "publickeysha256",
    "masterkeysha256",
    "masterkeyversion",
    "masterkeyactive",
    "privatekeyid",
    "keyid",
    "keytype",
    "keysize",
    "totpenabled",
}
_SENSITIVE_PARTS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "authorization",
    "cookie",
    "apikey",
    "keyring",
    "masterkey",
    "privatekey",
    "recoverycode",
    "totp",
    "ciphertext",
)
_SENSITIVE_NAMES = {
    "pwd",
    "keys",
    "pem",
    "pfx",
    "otp",
    "session",
    "sessionid",
    "body",
    "requestbody",
    "responsebody",
    "rawbody",
    "form",
    "formbody",
    "formdata",
    "requestform",
}
_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ][A-Z0-9 -]*-----.*?(?:-----END [A-Z0-9 ][A-Z0-9 -]*-----|$)",
    re.DOTALL | re.IGNORECASE,
)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{64,}={0,2}(?![A-Za-z0-9+/_=-])")
_HEX_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_INLINE = re.compile(r"""(?<![\w.-])(?P<key>[A-Za-z0-9_.-]{1,256})(?P<separator>['"]?\s*+[:=]\s*+)""")
_QUOTED_VALUE = re.compile(r""""(?:\\.|[^"\\])*+"|'(?:\\.|[^'\\])*+'""")
_INLINE_VALUE = re.compile(r"[^\s]*+")
_AUTH = re.compile(
    r"(?<![\w@:])(?:AWS4-HMAC-SHA256|Bearer|Basic|Digest|Token|Negotiate|NTLM)\b[^\r\n]*+",
    re.IGNORECASE,
)
_AUTH_SCHEME = re.compile(
    r"(?:AWS4-HMAC-SHA256|Bearer|Basic|Digest|Token|Negotiate|NTLM)\b", re.IGNORECASE
)
_LINE_VALUE = re.compile(r"[^\r\n]*+")
_AUTHORIZATION_KEYS = {"authorization", "proxyauthorization", "wwwauthenticate"}
_URL_PASSWORD = re.compile(r"(?P<prefix>[a-z][a-z0-9+.-]{0,31}://[^/\s:@]*:)[^@\s/]+(?=@)", re.IGNORECASE)
_SCHEMELESS_URL_PASSWORD = re.compile(r"(?P<prefix>//[^/\s:@]*:)[^@\s/]+(?=@)")
_STANDARD_LOG_FIELDS = frozenset(logging.makeLogRecord({}).__dict__)
_BODY_ASSIGNMENT = re.compile(
    r"\b(?:body|(?:request|response|raw)[_-]?body|form(?:[_-]?(?:data|body))?|request[_-]?form)"
    r"""['"]?\s*+[:=]\s*+(?!['"]?\[REDACTED\])""",
    re.IGNORECASE,
)


def _normalized_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.casefold())


def _sensitive(key: str, value: object) -> bool:
    normalized = _normalized_key(key)
    if normalized in _SAFE_METADATA or (normalized.endswith("present") and isinstance(value, bool)):
        return False
    return (
        normalized in _SENSITIVE_NAMES
        or normalized.endswith("pem")
        or any(part in normalized for part in _SENSITIVE_PARTS)
    )


def _inline_text(value: str) -> str:
    # Find assignments once; each value scan is limited to its own segment.
    # Whole-token starts prevent retrying a dotted run at each internal word.
    matches = list(_INLINE.finditer(value))
    # Punctuation inside a credential is not a new field boundary, but labels
    # after message prefixes (error:password=...) must still be found.
    ends = [len(value)] * len(matches)
    next_field = len(value)
    for index in range(len(matches) - 1, -1, -1):
        match = matches[index]
        ends[index] = next_field
        if match.start() == 0 or value[match.start() - 1].isspace():
            next_field = match.start()
    parts = []
    cursor = 0
    for index, match in enumerate(matches):
        start = match.end()
        scheme_value = _AUTH_SCHEME.match(value, start) is not None
        if match.start() < cursor or (not _sensitive(match["key"], "") and not scheme_value):
            continue
        if value.startswith(_REDACTED, start):
            end = start + len(_REDACTED)
        elif quoted := _QUOTED_VALUE.match(value, start):
            end = quoted.end()
        elif (
            scheme_value
            or _normalized_key(match["key"]) in _AUTHORIZATION_KEYS
            or value[start : start + 1] in {"'", '"'}
        ):
            end = _LINE_VALUE.match(value, start).end()
        else:
            end = _INLINE_VALUE.match(value, start, ends[index]).end()
            end = start + len(value[start:end].rstrip())
        parts.extend((value[cursor:start], _REDACTED))
        cursor = end
    parts.append(value[cursor:])
    return "".join(parts)


def _text(value: str) -> str:
    # Bound every regex's input, including unstructured logging/tracebacks.
    suffix = _TRUNCATED if len(value) > _TEXT_LIMIT else ""
    value = value[:_TEXT_LIMIT]
    # Raw bodies may contain unlabeled secrets; discard that whole text event.
    # Already-redacted structured fields do not hide adjacent safe metadata.
    if _BODY_ASSIGNMENT.search(value):
        return _REDACTED + suffix
    value = _PEM.sub(_REDACTED, value)
    value = _BASE64.sub(lambda match: match[0] if _HEX_SHA256.fullmatch(match[0]) else _REDACTED, value)
    # Auth schemes are whitespace-delimited; scrub them before the inline scanner
    # consumes only the first word of an unquoted value.
    value = _AUTH.sub(_REDACTED, value)
    value = _inline_text(value)
    if "://" in value:
        value = _URL_PASSWORD.sub(lambda match: match["prefix"] + _REDACTED, value)
    value = _SCHEMELESS_URL_PASSWORD.sub(lambda match: match["prefix"] + _REDACTED, value)
    return value + suffix


def redact(value: JSONValue) -> JSONValue:
    """Return a fresh JSON tree, hiding secret fields/PEM and long base64 runs.

    Long runs start at 64 characters; exact 64-character hex SHA-256 fingerprints
    remain visible. Short credentials require labeled fields.
    """
    if isinstance(value, dict):
        return {
            str(key): _REDACTED if _sensitive(str(key), item) else redact(item) for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [redact(item) for item in value]
    return _text(value) if isinstance(value, str) else value


def _require_json(value: object) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _require_json(item)
    elif isinstance(value, list):
        for item in value:
            _require_json(item)
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise TypeError("audit details must contain only JSON-native values after redaction")


@dataclass(frozen=True)
class Actor:
    user_id: int | None
    label: str
    ip: str | None = None
    user_agent: str | None = None


def record(
    db: Session,
    actor: Actor,
    action: str,
    target_type: str,
    target_id: str | None,
    details: Mapping[str, JSONValue],
) -> AuditLog:
    """Stage the audit alongside the caller's mutation; never flush or commit."""
    clean_details = redact(dict(details))
    _require_json(clean_details)
    row = AuditLog(
        actor_user_id=actor.user_id,
        actor_label=_text(actor.label),
        ip=actor.ip,
        user_agent=_text(actor.user_agent) if actor.user_agent is not None else None,
        action=_text(action),
        target_type=_text(target_type),
        target_id=_text(target_id) if target_id is not None else None,
        details=clean_details,
    )
    db.add(row)
    return row


ACTION_PREFIX_MAX = 100
# Address or address/prefix-length only: Python also accepts netmask and scope-id forms that Postgres refuses.
_IP_SYNTAX = re.compile(r"[0-9A-Fa-f:.]{2,45}(?:/[0-9]{1,3})?")


@dataclass(frozen=True)
class AuditFilters:
    """Read-only audit query. ``start`` is inclusive, ``end`` exclusive; naive datetimes are UTC.

    ``ip`` is one address or a CIDR network. Invalid values raise ``ValueError`` at construction.
    """

    actor: str | None = None
    action_prefix: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    ip: str | None = None

    def __post_init__(self) -> None:
        if self.action_prefix is not None and len(self.action_prefix) > ACTION_PREFIX_MAX:
            raise ValueError("action prefix is too long")
        if self.ip is not None:
            if _IP_SYNTAX.fullmatch(self.ip) is None:
                raise ValueError("invalid IP address or network")
            try:
                ip_interface(self.ip)
            except ValueError:
                raise ValueError("invalid IP address or network") from None


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _audit_clauses(filters: AuditFilters) -> list:
    clauses = []
    if filters.actor is not None:
        clauses.append(func.lower(AuditLog.actor_label) == filters.actor.lower())
    if filters.action_prefix is not None:
        clauses.append(AuditLog.action.startswith(filters.action_prefix, autoescape=True))
    if filters.target_type is not None:
        clauses.append(AuditLog.target_type == filters.target_type)
    if filters.target_id is not None:
        clauses.append(AuditLog.target_id == filters.target_id)
    if filters.start is not None:
        clauses.append(AuditLog.created_at >= _utc(filters.start))
    if filters.end is not None:
        clauses.append(AuditLog.created_at < _utc(filters.end))
    if filters.ip is not None:
        clauses.append(AuditLog.ip.op("<<=")(cast(filters.ip, INET)))
    return clauses


def list_audit(
    db: Session, filters: AuditFilters, page: int = 1, page_size: int = 50
) -> tuple[list[AuditLog], int]:
    """One page of matching rows, newest first (``id`` breaks ties), and the total match count."""
    if page < 1 or not 1 <= page_size <= 100:
        raise ValueError("page must be >= 1 and page_size between 1 and 100")
    clauses = _audit_clauses(filters)
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*clauses)) or 0
    rows = db.scalars(
        select(AuditLog)
        .where(*clauses)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    ).all()
    return list(rows), total


def export_audit(db: Session, filters: AuditFilters, limit: int) -> tuple[list[AuditLog], int]:
    """Up to ``limit`` matching rows, newest first, and the total match count (for truncation)."""
    clauses = _audit_clauses(filters)
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*clauses)) or 0
    rows = db.scalars(
        select(AuditLog)
        .where(*clauses)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(limit)
    ).all()
    return list(rows), total


def _log_value(value: object) -> JSONValue:
    if isinstance(value, Mapping):
        return {
            str(key): _REDACTED if _sensitive(str(key), item) else _log_value(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_log_value(item) for item in value]
    if isinstance(value, bytes):
        return _text(value.decode("utf-8", errors="replace"))
    if value is None or isinstance(value, (bool, int, float, str)):
        return redact(value)
    return _text(str(value))


class SecretRedactionFilter(logging.Filter):
    """Attach to output handlers to scrub propagated logs and tracebacks.

    Installation belongs to application/worker logging setup. Importing this
    module does not modify global logger state or caller-owned structured inputs.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # String templates must remain intact until getMessage substitutes args.
            if not isinstance(record.msg, str):
                record.msg = _log_value(record.msg)
            if isinstance(record.args, Mapping):
                record.args = _log_value(record.args)
            else:
                record.args = tuple(_log_value(item) for item in record.args or ())
            record.msg = _text(record.getMessage())
        except Exception:  # noqa: BLE001 - logging must fail closed for arbitrary formatting hooks.
            # Formatting and user-defined __str__ must not break the caller.
            record.msg = _REDACTED + " invalid log formatting"
        record.args = ()
        for name, value in vars(record).copy().items():
            if name not in _STANDARD_LOG_FIELDS and name not in {"message", "asctime"}:
                try:
                    replacement = _REDACTED if _sensitive(name, value) else _log_value(value)
                except Exception:  # noqa: BLE001 - one unrenderable field must not break logging.
                    replacement = _REDACTED + " unrenderable"
                setattr(record, name, replacement)
        if record.exc_info:
            record.exc_text = _text("".join(traceback.format_exception(*record.exc_info)))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = _text(record.exc_text)
        if record.stack_info:
            record.stack_info = _text(record.stack_info)
        if hasattr(record, "message"):
            record.message = record.msg
        return True
