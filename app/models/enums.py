"""Stable Python/SQL enumeration names for the v1 schema."""

from enum import StrEnum

from sqlalchemy import Enum


class CertificateStatus(StrEnum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


class ChainStatus(StrEnum):
    TRUSTED = "trusted"
    INCOMPLETE = "incomplete"
    UNTRUSTED_ROOT = "untrusted_root"
    UNCHECKED = "unchecked"


class TrustAnchorSource(StrEnum):
    PUBLIC_BUNDLE = "public_bundle"
    UPLOADED = "uploaded"


class PrivateKeyType(StrEnum):
    RSA = "rsa"
    ECDSA = "ecdsa"


class RenewalState(StrEnum):
    DRAFT = "draft"
    CSR_GENERATED = "csr_generated"
    SUBMITTED = "submitted"
    ISSUED = "issued"
    DEPLOYED = "deployed"
    DONE = "done"
    CANCELLED = "cancelled"


class WebserverType(StrEnum):
    NGINX = "nginx"
    APACHE = "apache"


class JobType(StrEnum):
    DISCOVER = "discover"
    DEPLOY = "deploy"
    SCAN = "scan"
    ALERT_EXPIRY = "alert_expiry"
    DIGEST = "digest"
    CLEANUP = "cleanup"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobHostStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


class ScanStatus(StrEnum):
    OK = "ok"
    MISMATCH = "mismatch"
    EXPIRED = "expired"
    UNREACHABLE = "unreachable"
    ERROR = "error"


class EndpointSource(StrEnum):
    MANUAL = "manual"
    DISCOVERY = "discovery"


class NotificationStatus(StrEnum):
    SENT = "sent"
    FAILED = "failed"


class AuthBackend(StrEnum):
    LOCAL = "local"
    LDAP = "ldap"


def pg_enum(enum: type[StrEnum], name: str) -> Enum:
    return Enum(
        enum, name=name, values_callable=lambda values: [item.value for item in values], validate_strings=True
    )
