"""Job handler registry shared by the worker (dispatch) and the web app (capability checks)."""

from app.jobs.handlers.cleanup import cleanup, validate_cleanup_payload
from app.jobs.worker import JobRegistry
from app.models.enums import JobType


def build_registry() -> JobRegistry:
    """Return a fresh registry; side-effect free (no I/O, no module-level state)."""
    registry = JobRegistry()
    registry.register(JobType.CLEANUP, cleanup, validator=validate_cleanup_payload)
    return registry
