"""The shared context of every Ansible job: locks, the inventory checkout, staged secrets, artifacts.

``ansible_job`` is what ``test_pull``, ``discover`` and ``deploy`` open first (Plan 3 Contract decisions
4-6). Order matters and is fixed here, once:

1. configuration and preconditions that need no lock (inventory configured, ``known_hosts`` present);
2. the caller's *exclusive* locks (``deploy:global``), non-blocking: a held lock is ``LockBusy``;
3. the SSH key staged on the tmpfs ``key_staging_dir`` (``0700``/``0600``, removed on exit);
4. ``<artifacts_root>/<job_id>`` (``0700``), recorded in ``job.ansible_artifact_dir``;
5. the inventory refresh: ``inventory:pull`` is taken **exclusively** to pull, then **shared** (and the
   exclusive hold dropped) for the whole run, so no reset can change files under a running playbook. When
   the exclusive lock is unavailable the job reads the current checkout under the shared hold instead, and
   when even that is refused a reset is in progress and the job is ``LockBusy``.

All locks live on one dedicated connection: leaving the context (or dying) releases every one of them.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from app.ansible.runner import RunnerContext, prepare_run_dir, stage_runner_secrets
from app.ansible.staging import StagingArea, StagingError
from app.jobs.locks import INVENTORY_LOCK, AdvisoryLocks, LockSession
from app.jobs.queue import JobFailure
from app.models import Job
from app.services.inventory import (
    InventoryConfig,
    InventoryRevision,
    audit_inconsistency,
    git_environment,
    load_inventory_config,
    refresh_checkout,
)

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from app.jobs.worker import JobContext

__all__ = ["AnsibleJob", "LockBusy", "ansible_job"]

CHECKOUT_DIRECTORY = "repo"
_NOT_CONFIGURED = "inventory repository is not configured"
_KNOWN_HOSTS_MISSING = "SSH known_hosts file is missing"
_OUTSIDE_CHECKOUT = "inventory path is outside the checkout"


class LockBusy(Exception):
    """A non-blocking advisory lock is held by someone else; the caller decides whether to requeue."""

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"lock {key} is busy")


@dataclass(frozen=True)
class AnsibleJob:
    """What a handler needs to run Ansible. With ``with_inventory=False`` the first four are ``None``."""

    revision: InventoryRevision | None
    config: InventoryConfig | None
    checkout: Path | None
    inventory_path: Path | None
    runner: RunnerContext
    staging: StagingArea
    locks: LockSession


def ansible_job(
    context: JobContext, *, exclusive: Sequence[str] = (), with_inventory: bool = True
) -> AbstractContextManager[AnsibleJob]:
    """Open the job context described in the module docstring; everything is released on exit."""
    return _ansible_job(context, tuple(exclusive), with_inventory)


@contextmanager
def _ansible_job(context: JobContext, exclusive: tuple[str, ...], with_inventory: bool) -> Iterator[AnsibleJob]:
    settings = context.settings
    config: InventoryConfig | None = None
    if with_inventory:
        with context.factory() as db:
            config = load_inventory_config(db)
        if config is None:
            raise JobFailure("config_invalid", _NOT_CONFIGURED)
    if not settings.known_hosts_file.is_file():
        raise JobFailure("config_invalid", _KNOWN_HOSTS_MISSING)

    locks = AdvisoryLocks(context.factory.kw["bind"])
    with ExitStack() as stack:
        stack.callback(locks.close)
        session = stack.enter_context(locks.session())
        for key in exclusive:
            if not session.try_lock(key):
                raise LockBusy(key)
        try:
            staging = stack.enter_context(StagingArea(settings.key_staging_dir, context.job_id))
            secrets = stage_runner_secrets(settings, staging)
        except StagingError as error:
            if settings.ansible_ssh_key is None:
                raise JobFailure("config_invalid", "the worker has no ansible_ssh_key") from None
            raise JobFailure("internal", f"cannot stage the job secrets: {error}") from None
        artifact_dir = _artifact_directory(settings.artifacts_root, context)
        run_dir = artifact_dir / "run"
        prepare_run_dir(run_dir)

        revision = checkout = inventory_path = None
        if config is not None:
            checkout = settings.inventory_root / CHECKOUT_DIRECTORY
            env = git_environment(
                token=settings.inventory_git_token,
                ssh_key=secrets.ssh_key,
                known_hosts=secrets.known_hosts,
                home=run_dir / "home",
            )
            revision = _refresh_inventory(context, session, config, checkout, env)
            inventory_path = _inventory_path(checkout, config)
        # Without an inventory the runner gets the empty one (``/dev/null``): implicit localhost only.
        runner = RunnerContext(secrets, inventory_path or Path(os.devnull), run_dir, artifact_dir)
        yield AnsibleJob(revision, config, checkout, inventory_path, runner, staging, session)


def _artifact_directory(root: Path, context: JobContext) -> Path:
    """``<artifacts_root>/<job_id>`` (``0700``), recorded on the job row."""
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / str(context.job_id)
    if path.is_symlink():
        raise JobFailure("internal", "the job artifact directory is not a plain directory")
    path.mkdir(mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)  # independent of the umask
    with context.factory.begin() as db:
        job = db.get(Job, context.job_id)
        if job is not None:
            job.ansible_artifact_dir = str(path)
    return path


def _refresh_inventory(
    context: JobContext, session: LockSession, config: InventoryConfig, checkout: Path, env: dict[str, str]
) -> InventoryRevision:
    """Contract decision 5: exclusive to pull, then shared for the whole run."""
    arguments = {
        "env": env,
        "now": context.clock(),
        "on_inconsistent": audit_inconsistency(context.factory, job_id=str(context.job_id)),
    }
    if session.try_lock(INVENTORY_LOCK):
        try:
            revision = refresh_checkout(config.repo_url, config.ref, checkout, pull=True, **arguments)
            session.try_lock(INVENTORY_LOCK, shared=True)  # the same session never conflicts with itself
        finally:
            session.unlock(INVENTORY_LOCK)
        return revision
    # Another job is reading or pulling. Reading is only safe under a shared hold: if that is refused too, a
    # reset is in progress right now and the files must not be touched.
    if not session.try_lock(INVENTORY_LOCK, shared=True):
        raise LockBusy(INVENTORY_LOCK)
    return refresh_checkout(config.repo_url, config.ref, checkout, pull=False, **arguments)


def _inventory_path(checkout: Path, config: InventoryConfig) -> Path:
    """``inventory.path`` resolved inside the checkout (symlinks followed); anything outside is refused."""
    root = checkout.resolve()
    resolved = (root / config.path).resolve() if config.path else root
    if resolved != root and root not in resolved.parents:
        raise JobFailure("config_invalid", _OUTSIDE_CHECKOUT)
    return resolved
