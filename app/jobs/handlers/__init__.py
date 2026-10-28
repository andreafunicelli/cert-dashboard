"""Job handler registry shared by the worker (dispatch) and the web app (capability checks)."""

from app.jobs.handlers.cleanup import cleanup, validate_cleanup_payload
from app.jobs.handlers.digest import send_digest, validate_digest_payload
from app.jobs.handlers.discover import discover as run_discovery
from app.jobs.handlers.discover import validate_discover_payload
from app.jobs.handlers.expiry import expiry_check, validate_expiry_payload
from app.jobs.handlers.import_pull import import_pull as pull_import
from app.jobs.handlers.scan import scan_endpoints
from app.jobs.handlers.smtp_test import SMTP_TEST_ACTION, smtp_test, validate_smtp_test_payload
from app.jobs.handlers.test_pull import TEST_PULL_ACTION, validate_test_pull_payload
from app.jobs.handlers.test_pull import test_pull as pull_test
from app.jobs.handlers.trust_recheck import (
    TRUST_RECHECK_ACTION,
    trust_recheck,
    validate_trust_recheck_payload,
)
from app.jobs.worker import JobRegistry
from app.models.enums import JobType
from app.services.scans import PULL_ACTION, validate_pull_payload, validate_scan_payload


def build_registry() -> JobRegistry:
    """Return a fresh registry; side-effect free (no I/O, no module-level state)."""
    registry = JobRegistry()
    registry.register(JobType.CLEANUP, cleanup, validator=validate_cleanup_payload)
    registry.register(JobType.SCAN, scan_endpoints, validator=validate_scan_payload)
    registry.register(JobType.SCAN, pull_import, action=PULL_ACTION, validator=validate_pull_payload)
    registry.register(
        JobType.SCAN, trust_recheck, action=TRUST_RECHECK_ACTION, validator=validate_trust_recheck_payload
    )
    registry.register(JobType.ALERT_EXPIRY, expiry_check, validator=validate_expiry_payload)
    registry.register(JobType.DIGEST, send_digest, validator=validate_digest_payload)
    registry.register(
        JobType.ALERT_EXPIRY, smtp_test, action=SMTP_TEST_ACTION, validator=validate_smtp_test_payload
    )
    registry.register(JobType.DISCOVER, run_discovery, validator=validate_discover_payload)
    registry.register(JobType.DISCOVER, pull_test, action=TEST_PULL_ACTION, validator=validate_test_pull_payload)
    return registry
