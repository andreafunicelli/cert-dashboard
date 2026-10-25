"""Job handler registry shared by the worker (dispatch) and the web app (capability checks)."""

from app.jobs.handlers.cleanup import cleanup, validate_cleanup_payload
from app.jobs.handlers.import_pull import import_pull as pull_import
from app.jobs.worker import JobRegistry
from app.models.enums import JobType
from app.services.scans import PULL_ACTION, validate_pull_payload


def build_registry() -> JobRegistry:
    """Return a fresh registry; side-effect free (no I/O, no module-level state)."""
    registry = JobRegistry()
    registry.register(JobType.CLEANUP, cleanup, validator=validate_cleanup_payload)
    # scan/default (scheduled endpoint scans) is registered by Plan 2; only the pull import exists now.
    registry.register(JobType.SCAN, pull_import, action=PULL_ACTION, validator=validate_pull_payload)
    return registry
