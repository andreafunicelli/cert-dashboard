"""Typed application settings (``app_setting``): an explicit allowlist, one validator per key.

Only the 32 keys seeded by the v1 schema exist; anything else (including anything that looks like a
secret) is an "unknown setting". Secrets never live in this table: the SMTP password only comes from
the worker secret file. ``update_settings`` validates the *whole* patch first, writes nothing when any
key is invalid, and records ONE ``settings.update`` audit with before/after values per effective patch.
The caller owns the transaction; ``get_setting`` falls back to the seeded default for a missing row.
"""

import ipaddress
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import get_args
from urllib.parse import unquote, urlsplit
from zoneinfo import ZoneInfo

from sqlalchemy import func, literal, or_, select, true, tuple_
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.orm import Session, aliased

from app.crypto.keyring import Keyring
from app.jobs.worker import LIVENESS_WINDOW, TICK_INTERVAL_SECONDS, worker_liveness
from app.models import (
    AppSetting,
    Certificate,
    Job,
    JSONValue,
    NotificationLog,
    SchedulerState,
    WorkerHeartbeat,
)
from app.models.enums import CertificateStatus, JobStatus, JobType, NotificationStatus
from app.services.audit import Actor, record
from app.services.certificates import missing_master_key_versions, stale_master_key_rows

__all__ = [
    "SETTING_KEYS",
    "NotificationFailureView",
    "SettingsValidationError",
    "get_setting",
    "latest_smtp_test",
    "notification_failures",
    "smtp_health",
    "smtp_test_jobs",
    "smtp_test_view",
    "status_snapshot",
    "update_settings",
]

UNKNOWN_SETTING = "unknown setting"


class SettingsValidationError(Exception):
    """A patch was refused; ``errors`` maps each offending key to its messages. Nothing was written."""

    def __init__(self, errors: Mapping[str, tuple[str, ...]]) -> None:
        self.errors = {key: tuple(messages) for key, messages in errors.items()}
        super().__init__("invalid settings: " + ", ".join(sorted(self.errors)))


# --- validators: each returns the normalised value or raises ValueError(user-facing message) ---------

type Validator = Callable[[JSONValue], JSONValue]

_HHMM = re.compile(r"([01][0-9]|2[0-3]):[0-5][0-9]")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_EMAIL = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)
_REF = re.compile(r"[A-Za-z0-9._/-]{1,200}")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_TIMEZONE_CHARS = re.compile(r"[A-Za-z0-9_+/-]{1,64}")
_SCP_URL = re.compile(r"(?P<user>[A-Za-z0-9._-]+)@(?P<host>[A-Za-z0-9.-]+):(?P<path>[A-Za-z0-9._~/-]+)")
_SMTP_SECURITY = ("", "starttls", "ssl", "none")
_CONTROL = re.compile(r"[\x00-\x1f\x7f\s]")


def _is_int(value: JSONValue) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _boolean(value: JSONValue) -> JSONValue:
    if isinstance(value, bool):
        return value
    raise ValueError("must be true or false")


def _integer(low: int, high: int, *, nullable: bool = False) -> Validator:
    def check(value: JSONValue) -> JSONValue:
        if value is None and nullable:
            return None
        if not _is_int(value) or not low <= value <= high:  # type: ignore[operator]
            suffix = " (or empty)" if nullable else ""
            raise ValueError(f"must be a whole number between {low} and {high}{suffix}")
        return value

    return check


def _time_of_day(value: JSONValue) -> JSONValue:
    if not isinstance(value, str) or not _HHMM.fullmatch(value):
        raise ValueError("must be a UTC time in HH:MM format (00:00–23:59)")
    return value


def _thresholds(value: JSONValue) -> JSONValue:
    message = "must be 1–10 distinct whole numbers of days between 0 and 365"
    if not isinstance(value, list) or not 1 <= len(value) <= 10:
        raise ValueError(message)
    if not all(_is_int(item) and 0 <= item <= 365 for item in value) or len(set(value)) != len(value):  # type: ignore[operator]
        raise ValueError(message)
    return sorted(value, reverse=True)  # type: ignore[type-var]


def _valid_email(value: str) -> bool:
    return len(value) <= 254 and _EMAIL.fullmatch(value) is not None


def _recipients(value: JSONValue) -> JSONValue:
    message = "each recipient must be a valid email address (at most 50, no duplicates)"
    if not isinstance(value, list) or len(value) > 50:
        raise ValueError(message)
    if not all(isinstance(item, str) and _valid_email(item) for item in value):
        raise ValueError(message)
    if len({item.lower() for item in value}) != len(value):  # type: ignore[union-attr]
        raise ValueError(message)
    return list(value)


def _hostname_or_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return True
    return len(value) <= 253 and all(_LABEL.fullmatch(label) for label in value.split("."))


def _smtp_host(value: JSONValue) -> JSONValue:
    if not isinstance(value, str) or (value and not _hostname_or_ip(value)):
        raise ValueError("must be empty or a host name / IP address (at most 253 characters)")
    return value


def _smtp_security(value: JSONValue) -> JSONValue:
    if value not in _SMTP_SECURITY or not isinstance(value, str):
        raise ValueError("must be one of: (empty = SMTP not configured), starttls, ssl, none")
    return value


def _smtp_from(value: JSONValue) -> JSONValue:
    if not isinstance(value, str) or (value and not _valid_email(value)):
        raise ValueError("must be empty or a valid email address")
    return value


def _smtp_username(value: JSONValue) -> JSONValue:
    if not isinstance(value, str) or len(value) > 254 or re.search(r"[\x00-\x1f\x7f]", value):
        raise ValueError("must be at most 254 characters, without control characters")
    return value


_REPO_FORMS = "must be empty or an https://host/path, ssh://[user@]host/path or user@host:path URL"
_REPO_SECRETS = "must not contain credentials, tokens, query strings or fragments"


_URL_SECRET_WORDS = re.compile(
    r"pass(?:w|phrase)|secret|token|api[-_.]?key|access[-_.]?key|credential|bearer|private[-_.]?key"
    r"|signature|\bsig\b|\bauth(?:orization)?\b"
    r"|\bgh[pousr]_|github_pat_|glpat-|\bxox[abprs]-",
)


def _decoded_variants(value: str) -> list[str]:
    """The URL as submitted plus every successive percent-decoding (so %61ccess_token is seen)."""
    variants = [value]
    for _ in range(5):
        decoded = unquote(variants[-1])
        if decoded == variants[-1]:
            break
        variants.append(decoded)
    return variants


def _carries_secret_material(value: str) -> bool:
    """Credentials can hide in any URL component (path, ;params, encoded forms), not only userinfo."""
    for variant in _decoded_variants(value):
        if _URL_SECRET_WORDS.search(variant.lower()) or "=" in variant or ";" in variant:
            return True
    return False


def _repo_url(value: JSONValue) -> JSONValue:
    if not isinstance(value, str) or len(value) > 500 or _CONTROL.search(value):
        raise ValueError(_REPO_FORMS)
    if value == "":
        return value
    if _carries_secret_material(value):
        raise ValueError(_REPO_SECRETS)
    if "://" in value:
        try:
            parts = urlsplit(value)
            host, _ = parts.hostname, parts.port  # reading .port rejects a malformed port
        except ValueError:
            raise ValueError(_REPO_FORMS) from None
        if parts.scheme not in ("https", "ssh"):
            raise ValueError(_REPO_FORMS)
        userinfo = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else None
        if parts.query or parts.fragment or (userinfo is not None and ":" in userinfo):
            raise ValueError(_REPO_SECRETS)
        if userinfo is not None and parts.scheme == "https":
            raise ValueError(_REPO_SECRETS)  # a lone user name may be a token (e.g. a PAT)
        if not host or not _hostname_or_ip(host) or len(parts.path) < 2:
            raise ValueError(_REPO_FORMS)
        return value
    scp = _SCP_URL.fullmatch(value)
    if scp is None:
        if "?" in value or "#" in value or ("@" in value and ":" in value.partition("@")[0]):
            raise ValueError(_REPO_SECRETS)
        raise ValueError(_REPO_FORMS)
    if not _hostname_or_ip(scp["host"]):
        raise ValueError(_REPO_FORMS)
    return value


def _git_ref(value: JSONValue) -> JSONValue:
    if (
        not isinstance(value, str)
        or (value and (not _REF.fullmatch(value) or ".." in value or value.startswith("-")))
    ):
        raise ValueError("must be empty or a git ref (letters, digits, . _ / -; at most 200; no '..')")
    return value


def _checkout_path(value: JSONValue) -> JSONValue:
    message = "must be empty or a relative path inside the checkout (no '..', no leading '/', no '\\')"
    if not isinstance(value, str) or len(value) > 255:
        raise ValueError(message)
    if value == "":
        return value
    if value.startswith("/") or "\\" in value or _CONTROL.search(value):
        raise ValueError(message)
    if any(segment in ("", ".", "..") for segment in value.split("/")):
        raise ValueError(message)
    return value


def _webserver_var(value: JSONValue) -> JSONValue:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("must be an identifier (letters, digits, underscore; at most 64)")
    return value


def _timezone(value: JSONValue) -> JSONValue:
    message = "must be a valid time zone name such as Europe/Rome or UTC"
    if not isinstance(value, str) or not _TIMEZONE_CHARS.fullmatch(value):
        raise ValueError(message)
    try:
        ZoneInfo(value)
    except (KeyError, ValueError, OSError):
        raise ValueError(message) from None
    return value


@dataclass(frozen=True)
class _Setting:
    default: JSONValue
    validate: Validator


_SETTINGS: dict[str, _Setting] = {
    "alert.digest_enabled": _Setting(True, _boolean),
    "alert.recipients": _Setting([], _recipients),
    "alert.thresholds_days": _Setting([60, 30, 14, 7, 1, 0], _thresholds),
    "cleanup.daily_at": _Setting("04:00", _time_of_day),
    "cleanup.enabled": _Setting(True, _boolean),
    # 0 keeps target-host backups forever: the only setting where zero means "no limit".
    "deploy.backup_retention_days": _Setting(30, _integer(0, 3650)),
    "deploy.batch_percent": _Setting(10, _integer(1, 100)),
    "deploy.concurrency": _Setting(5, _integer(1, 50)),
    "deploy.host_timeout_seconds": _Setting(600, _integer(60, 7200)),
    "deploy.pause_after_canary": _Setting(True, _boolean),
    "deploy.pause_timeout_hours": _Setting(24, _integer(1, 168)),
    "digest.daily_at": _Setting("07:30", _time_of_day),
    "discovery.enabled": _Setting(True, _boolean),
    "discovery.nightly_at": _Setting("03:00", _time_of_day),
    "expiry_check.daily_at": _Setting("07:00", _time_of_day),
    "expiry_check.enabled": _Setting(True, _boolean),
    "inventory.path": _Setting("", _checkout_path),
    "inventory.ref": _Setting("", _git_ref),
    "inventory.repo_url": _Setting("", _repo_url),
    "inventory.webserver_var": _Setting("webserver_type", _webserver_var),
    "retention.days": _Setting(90, _integer(1, 3650)),
    "scan.daily_at": _Setting("02:00", _time_of_day),
    "scan.enabled": _Setting(True, _boolean),
    "scan.timeout_seconds": _Setting(10, _integer(1, 60)),
    "smtp.from": _Setting("", _smtp_from),
    "smtp.host": _Setting("", _smtp_host),
    "smtp.port": _Setting(None, _integer(1, 65535, nullable=True)),
    "smtp.security": _Setting("", _smtp_security),
    "smtp.tls_verify": _Setting(True, _boolean),
    "smtp.username": _Setting("", _smtp_username),
    "trust.include_public_bundle": _Setting(True, _boolean),
    "ui.timezone": _Setting("UTC", _timezone),
}

SETTING_KEYS = frozenset(_SETTINGS)


def get_setting(db: Session, key: str) -> JSONValue:
    """The stored value, or the seeded default when the row is missing. Unknown keys raise KeyError."""
    setting = _SETTINGS[key]
    row = db.execute(select(AppSetting.value).where(AppSetting.key == key)).first()
    return setting.default if row is None else row[0]


def is_valid_setting(key: str, value: JSONValue) -> bool:
    """Whether ``value`` passes the validator of a known key (never raises, never echoes the value)."""
    setting = _SETTINGS.get(key)
    if setting is None:
        return False
    try:
        setting.validate(value)
    except ValueError:
        return False
    return True


def update_settings(db: Session, changes: Mapping[str, JSONValue], actor: Actor) -> None:
    """Validate the whole patch, then upsert the keys that really change and audit them once."""
    errors: dict[str, tuple[str, ...]] = {}
    clean: dict[str, JSONValue] = {}
    for key, raw in changes.items():
        setting = _SETTINGS.get(key) if isinstance(key, str) else None
        if setting is None:
            errors[key] = (UNKNOWN_SETTING,)
            continue
        try:
            clean[key] = setting.validate(raw)
        except ValueError as exc:
            errors[key] = (str(exc),)
    if errors:
        raise SettingsValidationError(errors)
    if not clean:
        return
    ordered = sorted(clean)  # a stable lock order for concurrent saves
    rows = {
        row.key: row
        for row in db.scalars(select(AppSetting).where(AppSetting.key.in_(ordered)).with_for_update())
    }
    effective: dict[str, JSONValue] = {}
    for key in ordered:
        row, after = rows.get(key), clean[key]
        before = _SETTINGS[key].default if row is None else row.value
        if before == after and type(before) is type(after):
            continue
        effective[key] = {"before": before, "after": after}
        if row is None:
            db.add(AppSetting(key=key, value=after, updated_by=actor.user_id))
        else:
            row.value, row.updated_by = after, actor.user_id
    if effective:
        record(db, actor, "settings.update", "settings", None, {"changes": effective})


# --- operational status (Settings → Status) ---------------------------------------------------------

_FINISHED_STATUSES = (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED)
_FAILURE_WINDOW = timedelta(hours=24)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat()


# --- delivery failures and SMTP health (read-only) ---------------------------------------------------


@dataclass(frozen=True)
class NotificationFailureView:
    id: int
    kind: str
    certificate_id: int | None
    threshold_days: int | None
    recipients: tuple[str, ...]
    attempts: int
    last_attempt_at: datetime | None
    next_attempt_at: datetime | None
    error: str | None


def notification_failures(db: Session, limit: int = 50) -> list[NotificationFailureView]:
    """Attempted-but-undelivered ledger rows, newest attempt first (one bounded query)."""
    rows = db.scalars(
        select(NotificationLog)
        .where(NotificationLog.status == NotificationStatus.FAILED, NotificationLog.attempts >= 1)
        .order_by(NotificationLog.last_attempt_at.desc(), NotificationLog.id.desc())
        .limit(limit)
    )
    return [
        NotificationFailureView(
            row.id,
            row.kind,
            row.certificate_id,
            row.threshold_days,
            tuple(row.recipients),
            row.attempts,
            row.last_attempt_at,
            row.next_attempt_at,
            row.error,
        )
        for row in rows
    ]


def smtp_test_view(job: Job) -> dict[str, JSONValue]:
    """A test job as plain values; steps are re-filtered to ``{step, code}`` so only fixed text renders."""
    from app.services.smtp import SmtpStepName  # smtp imports this module: a top-level import is circular

    step_names = frozenset(get_args(SmtpStepName))
    result = job.result if isinstance(job.result, dict) else {}
    raw_steps = result.get("steps")
    steps: list[JSONValue] = [
        {"step": item["step"], "code": item["code"]}
        for item in (raw_steps if isinstance(raw_steps, list) else [])
        if isinstance(item, dict)
        and item.get("step") in step_names
        and (item.get("code") is None or type(item.get("code")) is int)
    ]
    recipient = result.get("recipient")
    return {
        "job_id": str(job.id),
        "status": getattr(job.status, "value", job.status),
        "requested_at": job.created_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at is not None else None,
        "recipient": recipient if isinstance(recipient, str) else None,
        "steps": steps,
        "error_class": job.error_class,
        "error_message": job.error_message,
    }


def smtp_test_jobs():
    from app.jobs.handlers.smtp_test import (
        SMTP_TEST_ACTION,  # handler -> smtp -> this module: circular at top level
    )

    return select(Job).where(Job.type == JobType.ALERT_EXPIRY, Job.payload["action"].as_string() == SMTP_TEST_ACTION)


def latest_smtp_test(db: Session) -> dict[str, JSONValue] | None:
    """The newest ``alert_expiry/smtp_test`` job as plain values, or None when none was ever queued."""
    job = db.scalars(smtp_test_jobs().order_by(Job.created_at.desc(), Job.id.desc()).limit(1)).first()
    return None if job is None else smtp_test_view(job)


def smtp_health(db: Session) -> dict[str, JSONValue]:
    """Delivery state from the ledger: the failure streak since the newest ``sent`` row (ordered by
    ``last_attempt_at DESC, id DESC``), its newest error, the last delivery and the last test send.
    Test sends are jobs, never ledger rows, so they never count as failures."""

    def in_streak():
        sent = aliased(NotificationLog)
        newer_sent = (
            select(sent.id)
            .where(
                sent.status == NotificationStatus.SENT,
                tuple_(sent.last_attempt_at, sent.id) > tuple_(NotificationLog.last_attempt_at, NotificationLog.id),
            )
            .exists()
        )
        return (NotificationLog.status == NotificationStatus.FAILED, NotificationLog.attempts >= 1, ~newer_sent)

    streak_length = select(func.count()).where(*in_streak()).scalar_subquery()
    streak_error = (
        select(NotificationLog.error)
        .where(*in_streak())
        .order_by(NotificationLog.last_attempt_at.desc(), NotificationLog.id.desc())
        .limit(1)
        .scalar_subquery()
    )
    last_success = (
        select(func.max(NotificationLog.sent_at))
        .where(NotificationLog.status == NotificationStatus.SENT)
        .scalar_subquery()
    )
    newest_test = aliased(
        Job, smtp_test_jobs().order_by(Job.created_at.desc(), Job.id.desc()).limit(1).subquery()
    )
    one_row = select(literal(1).label("one")).subquery()
    failures, error, success_at, test_job = db.execute(
        select(streak_length, streak_error, last_success, newest_test)
        .select_from(one_row)
        .outerjoin(newest_test, true())
    ).one()
    return {
        "consecutive_failures": failures,
        "last_error": error,
        "last_success_at": _iso(success_at),
        "last_test": None if test_job is None else smtp_test_view(test_job),
    }


def status_snapshot(
    db: Session,
    keyring: Keyring,
    now: datetime,
    *,
    keyring_sha256: str | None = None,
) -> dict[str, JSONValue]:
    """Read-only operational state: JSON-native (datetimes are ISO 8601 UTC) and secret-free.

    ``keyring_sha256`` is the digest of the keyring *file* (``Settings.keyring_sha256``); the keyring
    object itself does not carry it, so the web layer passes it in. Only versions, counts and digests
    appear here, never key bytes or any secret.
    """
    missing = sorted(missing_master_key_versions(db, keyring))
    heartbeat = db.execute(
        select(
            func.max(WorkerHeartbeat.last_seen_at),
            func.count().filter(WorkerHeartbeat.last_seen_at >= now - LIVENESS_WINDOW),
        )
    ).one()
    liveness = worker_liveness(db, now)  # the same rule as /healthz and the page banner
    open_jobs = dict(
        db.execute(
            select(Job.status, func.count())
            .where(Job.status.in_((JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.PAUSED)))
            .group_by(Job.status)
        ).all()
    )
    failed_24h = db.scalar(
        select(func.count())
        .select_from(Job)
        .where(Job.status == JobStatus.FAILED, Job.finished_at >= now - _FAILURE_WINDOW)
    )
    last_jobs: dict[str, JSONValue] = {
        job_type.value: {"status": JobStatus(status).value, "finished_at": _iso(finished_at)}
        for job_type, status, finished_at in db.execute(
            select(Job.type, Job.status, Job.finished_at)
            .ext(distinct_on(Job.type))
            .where(Job.status.in_(_FINISHED_STATUSES), Job.finished_at.is_not(None))
            .order_by(Job.type, Job.finished_at.desc())
        )
    }
    warnings: list[JSONValue] = []
    smtp = smtp_health(db)
    if not get_setting(db, "smtp.host"):
        warnings.append("smtp_not_configured")
    if smtp["consecutive_failures"]:
        warnings.append("smtp_failing")
    if get_setting(db, "smtp.tls_verify") is False:
        warnings.append("smtp_tls_unverified")
    if not get_setting(db, "inventory.repo_url"):
        warnings.append("inventory_not_configured")
    if not get_setting(db, "alert.recipients") and db.scalar(
        select(Certificate.id)
        .where(
            Certificate.status == CertificateStatus.ACTIVE,
            or_(Certificate.owner_email.is_(None), Certificate.owner_email == ""),
        )
        .limit(1)
    ):
        warnings.append("no_alert_recipients")
    if missing:
        warnings.append("missing_key_versions")
    if liveness == "stale":
        warnings.append("worker_stale")
    return {
        "keyring": {
            "active_version": keyring.active,
            "file_sha256": keyring_sha256,
            "loaded_versions": sorted(keyring.keys),
            "missing_versions": missing,
            "stale_rows": stale_master_key_rows(db, keyring),
        },
        "worker": {
            "state": liveness,
            "last_seen_at": _iso(heartbeat[0]),
            "heartbeat_interval_seconds": int(TICK_INTERVAL_SECONDS),
            "stale_after_seconds": int(LIVENESS_WINDOW.total_seconds()),
            "workers": heartbeat[1],
        },
        "queue": {
            "queued": open_jobs.get(JobStatus.QUEUED, 0),
            "running": open_jobs.get(JobStatus.RUNNING, 0),
            "paused": open_jobs.get(JobStatus.PAUSED, 0),
            "failed_24h": failed_24h,
        },
        "db_size_bytes": db.scalar(select(func.pg_database_size(func.current_database()))),
        "last_runs": {
            key: _iso(last_run_at)
            for key, last_run_at in db.execute(
                select(SchedulerState.key, SchedulerState.last_run_at).order_by(SchedulerState.key)
            )
        },
        "last_jobs": last_jobs,
        "smtp": smtp,
        "warnings": warnings,
    }
