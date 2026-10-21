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
_INLINE = re.compile(
    r"\b(?P<key>[A-Za-z0-9_.-]{0,128}(?:password|passwd|passphrase|pwd|secret|token|authorization|cookie|"
    r"api[_-]?key|keyring|master[_-]?key|private[_-]?key|recovery[_-]?codes?|totp|ciphertext|session[_-]?id|pem)"
    r"[A-Za-z0-9_.-]{0,128})(?P<separator>['\"]?\s*[:=]\s*)"
    r"""(?P<value>\[REDACTED\]|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|.+?(?=\s+[A-Za-z_][\w.-]*\s*[:=]|[,;\r\n}\]]|$))""",
    re.IGNORECASE,
)
_AUTH = re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*", re.IGNORECASE)
_URL_PASSWORD = re.compile(r"(?P<prefix>[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+(?=@)", re.IGNORECASE)
_STANDARD_LOG_FIELDS = frozenset(logging.makeLogRecord({}).__dict__)
_BODY_ASSIGNMENT = re.compile(
    r"\b(?:body|(?:request|response|raw)[_-]?body|form(?:[_-]?(?:data|body))?|request[_-]?form)"
    r"""['"]?\s*+[:=]\s*+(?!['"]?\[REDACTED\])""",
    re.IGNORECASE,
)


def _sensitive(key: str, value: object) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    if normalized in _SAFE_METADATA or (normalized.endswith("present") and isinstance(value, bool)):
        return False
    return (
        normalized in _SENSITIVE_NAMES
        or normalized.endswith("pem")
        or any(part in normalized for part in _SENSITIVE_PARTS)
    )


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
    value = _INLINE.sub(
        lambda match: (
            match["key"] + match["separator"] + _REDACTED
            if _sensitive(match["key"], match["value"])
            else match[0]
        ),
        value,
    )
    value = _AUTH.sub(_REDACTED, value)
    value = _URL_PASSWORD.sub(lambda match: match["prefix"] + _REDACTED, value)
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
        # String templates must remain intact until getMessage substitutes args.
        if not isinstance(record.msg, str):
            record.msg = _log_value(record.msg)
        if isinstance(record.args, Mapping):
            record.args = _log_value(record.args)
        else:
            record.args = tuple(_log_value(item) for item in record.args or ())
        try:
            record.msg = _text(record.getMessage())
        except (TypeError, ValueError):
            record.msg = _REDACTED + " invalid log formatting"
        record.args = ()
        for name, value in vars(record).copy().items():
            if name not in _STANDARD_LOG_FIELDS and name not in {"message", "asctime"}:
                setattr(record, name, _REDACTED if _sensitive(name, value) else _log_value(value))
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
