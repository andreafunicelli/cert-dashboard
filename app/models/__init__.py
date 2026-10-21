"""Import every v1 mapper so Alembic sees the complete schema."""

from app.models.app_setting import AppSetting
from app.models.audit_log import AuditLog
from app.models.base import Base, JSONValue
from app.models.binding import Binding
from app.models.certificate import Certificate
from app.models.endpoint import Endpoint
from app.models.job import Job
from app.models.job_host import JobHost
from app.models.login_rate_limit import LoginRateLimit
from app.models.notification_log import NotificationLog
from app.models.private_key import PrivateKey
from app.models.renewal import Renewal
from app.models.scan_result import ScanResult
from app.models.scheduler_state import SchedulerState
from app.models.server import Server
from app.models.trust_anchor import TrustAnchor
from app.models.user import User
from app.models.user_session import UserSession
from app.models.worker_heartbeat import WorkerHeartbeat

__all__ = [
    "AppSetting",
    "AuditLog",
    "Base",
    "Binding",
    "Certificate",
    "Endpoint",
    "JSONValue",
    "Job",
    "JobHost",
    "LoginRateLimit",
    "NotificationLog",
    "PrivateKey",
    "Renewal",
    "ScanResult",
    "SchedulerState",
    "Server",
    "TrustAnchor",
    "User",
    "UserSession",
    "WorkerHeartbeat",
]
