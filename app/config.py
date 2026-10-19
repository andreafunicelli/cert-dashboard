"""Load a validated, immutable startup snapshot without exposing secrets."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from app.crypto.keyring import Keyring


class ConfigurationError(ValueError):
    """A configuration failure safe to show in startup logs."""


@dataclass(frozen=True, kw_only=True)
class DatabaseSettings:
    db_password: bytes = field(repr=False)
    db_host: str = "db"
    db_port: int = 5432
    db_name: str = "cert_dashboard"
    db_user: str = "app_role"


@dataclass(frozen=True, kw_only=True)
class Settings(DatabaseSettings):
    profile: Literal["web", "worker", "cli"]
    keyring: Keyring = field(repr=False)
    keyring_sha256: str
    session_secret: bytes | None = field(default=None, repr=False)
    ansible_ssh_key: bytes | None = field(default=None, repr=False)
    ansible_vault_password: bytes | None = field(default=None, repr=False)
    inventory_git_token: bytes | None = field(default=None, repr=False)
    smtp_password: bytes | None = field(default=None, repr=False)
    worker_concurrency: int = 4
    max_parallel_jobs: int = 2
    inventory_root: Path = Path("/srv/inventory")
    artifacts_root: Path = Path("/srv/artifacts")
    key_staging_dir: Path = Path("/run/cert-keys")

    @property
    def ssh_available(self) -> bool:
        return self.ansible_ssh_key is not None

    def startup_metadata(self) -> dict[str, str | int | bool]:
        return {
            "profile": self.profile,
            "master_key_present": True,
            "master_key_active": self.keyring.active,
            "master_key_sha256": self.keyring_sha256,
            "db_password_present": True,
            "session_secret_present": self.session_secret is not None,
            "ansible_ssh_key_present": self.ssh_available,
            "smtp_password_present": self.smtp_password is not None,
        }



def _secret(
    name: str, environ: Mapping[str, str], secrets_dir: Path, *, required: bool = False
) -> bytes | None:
    path = secrets_dir / name
    try:
        value = path.read_bytes()
    except FileNotFoundError:
        raw = environ.get(name.upper())
        value = raw.encode("utf-8") if raw is not None else None
    except OSError:
        raise ConfigurationError(f"{name}: cannot read secret; check file permissions") from None
    if value is None:
        if not required:
            return None
        raise ConfigurationError(f"{name}: required secret missing; mount /run/secrets/{name}")
    if not value.strip():
        raise ConfigurationError(f"{name}: secret is empty; supply a non-empty secret file")
    return value if name == "master_key" else value.rstrip(b"\r\n")


def _positive_int(environ: Mapping[str, str], name: str, default: int, maximum: int | None = None) -> int:
    try:
        value = int(environ.get(name, str(default)))
    except (TypeError, ValueError):
        raise ConfigurationError(f"{name}: expected a positive integer") from None
    if value < 1 or (maximum is not None and value > maximum):
        raise ConfigurationError(f"{name}: integer outside allowed range")
    return value


def load_settings(
    profile: Literal["web", "worker", "cli"],
    environ: Mapping[str, str],
    secrets_dir: Path,
) -> Settings:
    from app.crypto.keyring import load_keyring

    if profile not in {"web", "worker", "cli"}:
        raise ConfigurationError("profile: expected web, worker or cli")
    database = load_database_settings(environ, secrets_dir)
    master = _secret("master_key", environ, secrets_dir, required=True)
    assert master is not None
    ring = load_keyring(master)
    session = _secret("session_secret", environ, secrets_dir, required=True) if profile == "web" else None
    if session is not None and len(session) < 32:
        raise ConfigurationError("session_secret: expected at least 32 random bytes")
    worker_secrets = {
        name: _secret(name, environ, secrets_dir)
        for name in ("ansible_ssh_key", "ansible_vault_password", "inventory_git_token", "smtp_password")
    } if profile == "worker" else {}
    ssh_key = worker_secrets.get("ansible_ssh_key")
    if ssh_key is not None:
        from cryptography.hazmat.primitives import serialization

        try:
            if ssh_key.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
                serialization.load_ssh_private_key(ssh_key, password=None)
            else:
                serialization.load_pem_private_key(ssh_key, password=None)
        except Exception:  # noqa: BLE001 - normalize all third-party key parser failures
            # Parser/backend failures must not expose key material or internals.
            raise ConfigurationError("ansible_ssh_key: expected an unencrypted SSH private key") from None
    return Settings(
        profile=profile, keyring=ring, keyring_sha256=hashlib.sha256(master).hexdigest(),
        **asdict(database),
        session_secret=session, worker_concurrency=_positive_int(environ, "WORKER_CONCURRENCY", 4),
        max_parallel_jobs=_positive_int(environ, "MAX_PARALLEL_JOBS", 2), **worker_secrets,
    )


def load_database_settings(environ: Mapping[str, str], secrets_dir: Path) -> DatabaseSettings:
    """DB-only configuration for one-shot migrations; no app secrets required."""
    password = _secret("db_password", environ, secrets_dir, required=True)
    assert password is not None
    return DatabaseSettings(
        db_password=password, db_host=environ.get("DB_HOST", "db"),
        db_port=_positive_int(environ, "DB_PORT", 5432, 65535),
        db_name=environ.get("DB_NAME", "cert_dashboard"), db_user=environ.get("DB_USER", "app_role"),
    )
