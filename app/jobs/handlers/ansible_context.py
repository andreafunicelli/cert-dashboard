"""The shared context of every Ansible job: locks, the inventory, staged secrets, artifacts.

``ansible_job`` is what ``test_pull``, ``discover`` and ``deploy`` open first (Plan 3 Contract decisions
4-6, Slice B contract §7). Order matters and is fixed here, once:

1. configuration and preconditions that need no lock: the inventory (a repository, active manual hosts,
   or both — decision D1), and an effective ``known_hosts`` (the mounted file and the dashboard-trusted
   host keys, contract §7.4);
2. the caller's *exclusive* locks (``deploy:global``), non-blocking: a held lock is ``LockBusy``;
3. the SSH key and the effective ``known_hosts`` staged on the tmpfs ``key_staging_dir``
   (``0700``/``0600``, removed on exit);
4. ``<artifacts_root>/<job_id>`` (``0700``), recorded in ``job.ansible_artifact_dir``;
5. the inventory refresh: ``inventory:pull`` is taken **exclusively** to pull, then **shared** (and the
   exclusive hold dropped) for the whole run, so no reset can change files under a running playbook. When
   the exclusive lock is unavailable the job reads the current checkout under the shared hold instead, and
   when even that is refused a reset is in progress and the job is ``LockBusy``;
6. the effective listing: the repository inventory as ``ansible-inventory`` reads it, plus the active
   manual hosts whose hostname the repository lacks. Those manual hosts are rendered into a YAML inventory
   file in the run directory and both files are passed to the playbook; a dashboard-only installation
   passes the manual file alone.

All locks live on one dedicated connection: leaving the context (or dying) releases every one of them.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from app.ansible.runner import RunnerContext, build_env, prepare_run_dir, stage_runner_secrets
from app.ansible.staging import StagingArea, StagingError
from app.jobs.locks import INVENTORY_LOCK, AdvisoryLocks, LockSession
from app.jobs.queue import JobFailure
from app.models import Job
from app.services.inventory import (
    InventoryConfig,
    InventoryHost,
    InventoryRevision,
    ManualInventorySettings,
    audit_inconsistency,
    git_environment,
    inventory_source,
    list_inventory,
    load_host_keys,
    load_inventory_config,
    load_manual_hosts,
    manual_inventory_settings,
    merge_inventory,
    refresh_checkout,
)
from app.services.inventory_sources import (
    DEFAULT_SSH_PORT,
    MANUAL_SOURCE,
    NO_INVENTORY,
    HostKey,
    InventoryRenderError,
    ManualHost,
    render_inventory,
    render_known_hosts,
)

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from app.jobs.worker import JobContext

__all__ = ["AnsibleJob", "LockBusy", "ansible_job"]

CHECKOUT_DIRECTORY = "repo"
MANUAL_INVENTORY_FILE = "inventory-manual.yml"
_NOT_CONFIGURED = "inventory repository is not configured"
_KNOWN_HOSTS_MISSING = "SSH known_hosts file is missing"
_OUTSIDE_CHECKOUT = "inventory path is outside the checkout"
_UNSAFE_INVENTORY = "the dashboard data cannot be rendered as an inventory"
_UNSAFE_KEYS = "the dashboard-trusted host keys cannot be rendered as known_hosts"


class LockBusy(Exception):
    """A non-blocking advisory lock is held by someone else; the caller decides whether to requeue."""

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"lock {key} is busy")


@dataclass(frozen=True)
class AnsibleJob:
    """What a handler needs to run Ansible.

    ``inventory_path`` is the *repository* inventory (``None`` without a repository) and stays the path
    ``test_pull`` lists. ``hosts`` is the effective listing every discover/deploy job reconciles and
    scopes against, ``source`` the marker reconciliation writes into ``server.inventory_source`` and
    ``manual_hostnames`` the hosts that must keep ``manual`` even while Git lists them elsewhere.
    With ``with_inventory=False`` the inventory fields are empty and the runner gets an empty inventory.
    """

    revision: InventoryRevision | None
    config: InventoryConfig | None
    checkout: Path | None
    inventory_path: Path | None
    hosts: tuple[InventoryHost, ...]
    source: str
    manual_hostnames: frozenset[str]
    runner: RunnerContext
    staging: StagingArea
    locks: LockSession


def ansible_job(
    context: JobContext,
    *,
    exclusive: Sequence[str] = (),
    with_inventory: bool = True,
    require_repository: bool = True,
) -> AbstractContextManager[AnsibleJob]:
    """Open the job context described in the module docstring; everything is released on exit.

    ``require_repository`` is for the jobs that test the configured repository itself (``test_pull``):
    they keep needing one (contract §7.1), while discover and deploy pass ``False`` and run on manual
    hosts alone (decision D1).
    """
    return _ansible_job(context, tuple(exclusive), with_inventory, require_repository)


@contextmanager
def _ansible_job(
    context: JobContext, exclusive: tuple[str, ...], with_inventory: bool, require_repository: bool
) -> Iterator[AnsibleJob]:
    settings = context.settings
    config: InventoryConfig | None = None
    manual_hosts: list[ManualHost] = []
    # Placeholder for the ``with_inventory=False`` jobs; replaced from the settings whenever there is one.
    manual_settings = ManualInventorySettings("webserver_type", None, DEFAULT_SSH_PORT)
    with context.factory() as db:
        if with_inventory:
            config = load_inventory_config(db)
            manual_hosts = load_manual_hosts(db)
            manual_settings = manual_inventory_settings(db)
        host_keys = load_host_keys(db)
    if with_inventory:
        if config is None and require_repository:
            # "Test pull" tests the configured repository itself; it keeps needing one (contract §7.1).
            raise JobFailure("config_invalid", _NOT_CONFIGURED)
        if config is None and not manual_hosts:
            raise JobFailure("config_invalid", NO_INVENTORY)
    known_hosts = _effective_known_hosts(settings.known_hosts_file, host_keys)

    locks = AdvisoryLocks(context.factory.kw["bind"])
    with ExitStack() as stack:
        stack.callback(locks.close)
        session = stack.enter_context(locks.session())
        for key in exclusive:
            if not session.try_lock(key):
                raise LockBusy(key)
        try:
            staging = stack.enter_context(StagingArea(settings.key_staging_dir, context.job_id))
            staged_known_hosts = staging.write("known_hosts", known_hosts)
            secrets = stage_runner_secrets(settings, staging, known_hosts=staged_known_hosts)
        except StagingError as error:
            if settings.ansible_ssh_key is None:
                raise JobFailure("config_invalid", "the worker has no ansible_ssh_key") from None
            raise JobFailure("internal", f"cannot stage the job secrets: {error}") from None
        artifact_dir = _artifact_directory(settings.artifacts_root, context)
        run_dir = artifact_dir / "run"
        prepare_run_dir(run_dir)

        revision = checkout = inventory_path = None
        hosts: tuple[InventoryHost, ...] = ()
        source = MANUAL_SOURCE
        manual_names: frozenset[str] = frozenset()
        inventory_files: list[Path] = []
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
            source = inventory_source(config, revision.rev)
            git_hosts = list_inventory(
                inventory_path, webserver_var=config.webserver_var, env=build_env(secrets, run_dir)
            )
            hosts, manual_names = merge_inventory(git_hosts, manual_hosts)
            inventory_files.append(inventory_path)
        elif manual_hosts:
            hosts, manual_names = merge_inventory([], manual_hosts)
        if manual_names:
            inventory_files.append(
                _render_manual_inventory(run_dir, manual_hosts, manual_names, manual_settings)
            )
        # Without an inventory the runner gets the empty one (``/dev/null``): implicit localhost only.
        runner = RunnerContext(secrets, tuple(inventory_files) or Path(os.devnull), run_dir, artifact_dir)
        yield AnsibleJob(
            revision, config, checkout, inventory_path, hosts, source, manual_names, runner, staging, session
        )


def _effective_known_hosts(mounted: Path, host_keys: Sequence[HostKey]) -> bytes:
    """The mounted file (read only) followed by the dashboard-trusted keys; fails when neither exists.

    Contract §7.4: the "no known_hosts" failure applies only when the file is absent **and** no key is
    trusted in the dashboard. The mounted file itself is never written: only its bytes are read.
    """
    content: bytes | None = None
    if mounted.is_file():
        try:
            content = mounted.read_bytes()
        except OSError:
            raise JobFailure("config_invalid", _KNOWN_HOSTS_MISSING) from None
    if content is None and not host_keys:
        raise JobFailure("config_invalid", _KNOWN_HOSTS_MISSING)
    try:
        return render_known_hosts(content, host_keys)
    except InventoryRenderError:
        raise JobFailure("config_invalid", _UNSAFE_KEYS) from None


def _render_manual_inventory(
    run_dir: Path, manual_hosts: Sequence[ManualHost], manual_names: frozenset[str], settings: ManualInventorySettings
) -> Path:
    """Write the manual hosts the repository lacks into the run directory and return the file.

    The file holds hostnames, groups and the D6 connection defaults — never a secret — and lives in the
    job's own ``0700`` run directory. An unsafe value (impossible through the validated Inventory forms)
    fails the job instead of reaching Ansible.
    """
    try:
        text = render_inventory(
            [host for host in manual_hosts if host.hostname in manual_names],
            webserver_var=settings.webserver_var,
            ssh_user=settings.ssh_user,
            ssh_port=settings.ssh_port,
        )
    except InventoryRenderError:
        raise JobFailure("config_invalid", _UNSAFE_INVENTORY) from None
    path = run_dir / MANUAL_INVENTORY_FILE
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)
    return path


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
