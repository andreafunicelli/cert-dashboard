"""Worker handler for ``discover/test_pull``: the "Test pull" button of Settings → Inventory.

The web process has no inventory volume, Git token or SSH key, so it only enqueues this job. The handler
prepares the inventory exactly like a discovery would (locks, pull, staged secrets) and lists it with
``ansible-inventory --list``: no connection to any target is made. The result carries the resolved
revision and the host and group counts, never an inventory value (Plan 3 Contract decision 13).
"""

from collections.abc import Mapping
from datetime import timedelta

from app.ansible.runner import build_env
from app.jobs.handlers.ansible_context import LockBusy, ansible_job
from app.jobs.queue import JobFailure, JobRequeued
from app.jobs.worker import JobContext
from app.models import JSONValue
from app.services.inventory import list_inventory, revision_result

__all__ = ["TEST_PULL_ACTION", "test_pull", "validate_test_pull_payload"]

TEST_PULL_ACTION = "test_pull"
LOCK_RETRY_DELAY = timedelta(seconds=30)


def validate_test_pull_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Accept exactly ``{"action": "test_pull"}``; anything else raises ``ValueError``."""
    if not isinstance(payload, Mapping) or dict(payload) != {"action": TEST_PULL_ACTION}:
        raise ValueError("a test pull payload is exactly its action")
    return {"action": TEST_PULL_ACTION}


def test_pull(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
    try:
        with ansible_job(context) as job:
            if job.revision is None or job.config is None or job.inventory_path is None:
                raise JobFailure("internal", "the inventory was not prepared")
            hosts = list_inventory(
                job.inventory_path,
                webserver_var=job.config.webserver_var,
                env=build_env(job.runner.secrets, job.runner.run_dir),
            )
            groups = {group for host in hosts for group in host.groups}
            return {**revision_result(job.revision), "hosts": len(hosts), "groups": len(groups)}
    except LockBusy:
        # A reset is changing the checkout right now. Nothing ran, so the claim is simply handed back.
        raise JobRequeued(context.clock() + LOCK_RETRY_DELAY) from None
