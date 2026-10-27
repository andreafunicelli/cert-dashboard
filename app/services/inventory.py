"""Read-only Git inventory checkout and host listing (spec 6.1, 7.7, 3.6, 9.5, 9.7).

The checkout is refreshed by fetching into a private ref and only then resetting the work tree, so a
failed fetch never leaves a half-updated tree. Git and Ansible output is parsed or dropped in memory:
stderr and stdout are never stored, logged or put into an error message, and credentials reach git only
through ``GIT_ASKPASS`` / an SSH key *path* (nothing lands in ``.git/config`` or argv).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from app.ansible.runner import GIT_ASKPASS
from app.jobs.queue import SYSTEM_ACTOR, JobFailure
from app.models.enums import WebserverType
from app.services.audit import record
from app.services.settings import get_setting

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

    from app.models import JSONValue

_LOG = logging.getLogger(__name__)

PULL_MIN_INTERVAL = timedelta(seconds=60)
CHECKOUT_MAX_AGE = timedelta(hours=24)
GIT_TIMEOUT_SECONDS = 120
FETCH_REF = "refs/cert-dashboard/fetch"
# Lives inside .git: `git clean` never touches it and Ansible never sees it as an inventory source.
MARKER = Path(".git") / "last_pull.json"
PULL_FAILED_WARNING = "pull failed; using the last good revision"
_ALLOWED_PROTOCOLS = "https:ssh:file"
_PSEUDO_GROUPS = frozenset({"all", "ungrouped"})
_SHA = re.compile(r"[0-9a-f]{40}")
_UNREADABLE = "inventory could not be read"
INCONSISTENT_MESSAGE = "inventory checkout does not match its recorded revision"


@dataclass(frozen=True)
class InventoryConfig:
    repo_url: str
    ref: str
    path: str
    webserver_var: str


@dataclass(frozen=True)
class InventoryRevision:
    rev: str
    rev_date: datetime
    pulled_at: datetime
    refreshed: bool
    warning: str | None


@dataclass(frozen=True)
class InventoryInconsistency:
    """``git rev-parse HEAD`` and the pull marker disagree (or the marker is unusable).

    ``expected`` is the revision the marker records, ``actual`` the one the checkout contains; both are
    commit SHAs of the configuration repository, never secrets.
    """

    reason: Literal["mismatch", "marker_missing", "marker_corrupt"]
    expected: str | None
    actual: str | None


InconsistencyHook = Callable[[InventoryInconsistency], None]


@dataclass(frozen=True)
class InventoryHost:
    hostname: str
    groups: tuple[str, ...]
    connection_address: str | None
    webserver: WebserverType | None


def load_inventory_config(db: Session) -> InventoryConfig | None:
    """The inventory settings, or None while no repository is configured."""
    repo_url = get_setting(db, "inventory.repo_url")
    if not repo_url or not isinstance(repo_url, str):
        return None
    values = [get_setting(db, f"inventory.{name}") for name in ("ref", "path", "webserver_var")]
    ref, path, webserver_var = (value if isinstance(value, str) else "" for value in values)
    return InventoryConfig(repo_url, ref, path, webserver_var)


def inventory_source(config: InventoryConfig, rev: str) -> str:
    """``<ref or HEAD>:<path or .>@<rev>`` — never the repository URL."""
    return f"{config.ref or 'HEAD'}:{config.path or '.'}@{rev}"


def revision_result(revision: InventoryRevision) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {
        "inventory_rev": revision.rev,
        "inventory_rev_date": revision.rev_date.astimezone(UTC).isoformat(),
        "inventory_refreshed": revision.refreshed,
    }
    if revision.warning:
        result["inventory_warning"] = revision.warning
    return result


def git_environment(*, token: bytes | None, ssh_key: Path | None, known_hosts: Path, home: Path) -> dict[str, str]:
    """The complete environment of every git child (nothing is inherited)."""
    env = {
        "PATH": os.pathsep.join([str(Path(sys.executable).parent), "/usr/local/bin", "/usr/bin", "/bin"]),
        "HOME": str(home),
        "GIT_ALLOW_PROTOCOL": _ALLOWED_PROTOCOLS,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    if token is not None:
        env["GIT_ASKPASS"] = str(GIT_ASKPASS)
        env["CERT_DASHBOARD_GIT_TOKEN"] = token.decode()
    if ssh_key is not None:
        env["GIT_SSH_COMMAND"] = " ".join(
            [
                "ssh",
                "-i",
                shlex.quote(str(ssh_key)),
                "-o IdentitiesOnly=yes",
                "-o StrictHostKeyChecking=yes",
                f"-o UserKnownHostsFile={shlex.quote(str(known_hosts))}",
                "-o BatchMode=yes",
            ]
        )
    return env


class _GitFailed(Exception):
    """A git command failed; deliberately carries no output."""


def _git(checkout: Path, env: Mapping[str, str], *args: str) -> str:
    child_env = {
        **env,
        "GIT_ALLOW_PROTOCOL": _ALLOWED_PROTOCOLS,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        done = subprocess.run(
            ["git", "-c", "credential.helper=", *args],
            cwd=checkout,
            env=child_env,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise _GitFailed from None
    if done.returncode != 0:
        raise _GitFailed
    return done.stdout.decode("utf-8", "replace").strip()


def _read_marker(checkout: Path) -> tuple[InventoryRevision | None, Literal["marker_missing", "marker_corrupt"] | None]:
    """The marker as a cache entry: the revision it records, or why there is none."""
    try:
        text = (checkout / MARKER).read_text()
    except FileNotFoundError:
        return None, "marker_missing"
    except OSError:
        return None, "marker_corrupt"
    try:
        data = json.loads(text)
        rev = data["rev"]
        rev_date = datetime.fromisoformat(data["rev_date"])
        pulled_at = datetime.fromisoformat(data["pulled_at"])
    except (ValueError, KeyError, TypeError):
        return None, "marker_corrupt"
    if not isinstance(rev, str) or not _SHA.fullmatch(rev) or rev_date.tzinfo is None or pulled_at.tzinfo is None:
        return None, "marker_corrupt"
    return InventoryRevision(rev, rev_date, pulled_at, False, None), None


def _read_environment() -> dict[str, str]:
    """Environment for the local, read-only ``rev-parse`` of a caller that has no git environment."""
    return {
        "PATH": os.pathsep.join([str(Path(sys.executable).parent), "/usr/local/bin", "/usr/bin", "/bin"]),
        "HOME": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
    }


def _head(checkout: Path, env: Mapping[str, str]) -> str | None:
    """The commit the checkout really contains (the truth), or None when it has none.

    ``--git-dir`` is explicit so a broken ``.git`` never makes git walk up into an enclosing repository.
    """
    try:
        rev = _git(checkout, env, f"--git-dir={checkout / '.git'}", "rev-parse", "--verify", "HEAD^{commit}")
    except _GitFailed:
        return None
    return rev if _SHA.fullmatch(rev) else None


def _inspect(checkout: Path, env: Mapping[str, str]) -> tuple[InventoryRevision | None, InventoryInconsistency | None]:
    """Compare the marker with HEAD. ``(None, None)`` means the checkout was never pulled.

    The marker is only ever a cache: a revision is trusted solely when it equals HEAD.
    """
    head = _head(checkout, env)
    marker, problem = _read_marker(checkout)
    if marker is not None and marker.rev == head:
        return marker, None
    if marker is None and problem == "marker_missing" and head is None:
        return None, None
    reason: Literal["mismatch", "marker_missing", "marker_corrupt"] = problem or "mismatch"
    return None, InventoryInconsistency(reason, marker.rev if marker is not None else None, head)


def _report(finding: InventoryInconsistency, hook: InconsistencyHook | None) -> JobFailure:
    """Announce one detection (audit hook) and build the sanitized, retryable failure to raise."""
    if hook is not None:
        try:
            hook(finding)
        except Exception as error:  # noqa: BLE001 - an audit outage must not replace the typed failure
            _LOG.warning("inventory inconsistency could not be audited: %s", type(error).__name__)
    return JobFailure("inventory_inconsistent", INCONSISTENT_MESSAGE, retryable=True)


def current_revision(checkout: Path, *, on_inconsistent: InconsistencyHook | None = None) -> InventoryRevision | None:
    """The revision of the last successful pull, or None when there has been none.

    Fails closed (``inventory_inconsistent``) unless the marker equals ``git rev-parse HEAD``.
    """
    revision, finding = _inspect(checkout, _read_environment())
    if finding is not None:
        raise _report(finding, on_inconsistent)
    return revision


def audit_inconsistency(factory: sessionmaker[Session], *, job_id: str | None = None) -> InconsistencyHook:
    """A hook that writes one ``inventory.inconsistent`` audit row (own transaction) per detection."""

    def write(finding: InventoryInconsistency) -> None:
        details: dict[str, JSONValue] = {
            "reason": finding.reason,
            "expected_rev": finding.expected,
            "actual_rev": finding.actual,
        }
        if job_id is not None:
            details["job_id"] = job_id
        with factory.begin() as db:
            record(db, SYSTEM_ACTOR, "inventory.inconsistent", "inventory", None, details)

    return write


def _write_marker(checkout: Path, revision: InventoryRevision) -> None:
    payload = {
        "rev": revision.rev,
        "rev_date": revision.rev_date.isoformat(),
        "pulled_at": revision.pulled_at.isoformat(),
    }
    target = checkout / MARKER
    temp = target.with_name(f"{target.name}.{os.getpid()}.tmp")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(payload, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)


def _prepare_checkout(checkout: Path, env: Mapping[str, str]) -> None:
    """Create the checkout on first use; never initialise (and later `clean`) a foreign directory."""
    if (checkout / ".git").exists():
        return
    checkout.mkdir(parents=True, exist_ok=True)
    if any(entry.name != "lost+found" for entry in checkout.iterdir()):
        raise JobFailure("config_invalid", "inventory checkout directory is not empty and not a git checkout")
    _git(checkout, env, "init", "--quiet", "--initial-branch=main")


def _fetch(remote: str, ref: str, checkout: Path, env: Mapping[str, str]) -> tuple[str, int]:
    """Fetch ``ref`` into the temporary ref; the working tree is not touched."""
    _prepare_checkout(checkout, env)
    _git(checkout, env, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--", remote, f"+{ref or 'HEAD'}:{FETCH_REF}")
    rev = _git(checkout, env, "rev-parse", "--verify", f"{FETCH_REF}^{{commit}}")
    if not _SHA.fullmatch(rev):
        raise _GitFailed
    return rev, int(_git(checkout, env, "log", "-1", "--format=%ct", rev))


def _apply(checkout: Path, env: Mapping[str, str], rev: str) -> None:
    _git(checkout, env, "reset", "--quiet", "--hard", rev)
    _git(checkout, env, "clean", "-ffdxq")


def _restore(checkout: Path, env: Mapping[str, str], last: InventoryRevision) -> bool:
    """Put the previous revision back after a failure past the reset; True only once it is verified."""
    try:
        _apply(checkout, env, last.rev)
        return _git(checkout, env, "rev-parse", "--verify", "HEAD^{commit}") == last.rev
    except (_GitFailed, OSError, ValueError):
        return False


def _pull(
    remote: str, ref: str, checkout: Path, env: Mapping[str, str], now: datetime, last: InventoryRevision | None
) -> InventoryRevision | None:
    """Fetch, then reset the working tree. Returns the new revision, or None when nothing was changed."""
    try:
        rev, committed = _fetch(remote, ref, checkout, env)
    except (_GitFailed, OSError, ValueError):
        return None
    revision = InventoryRevision(rev, datetime.fromtimestamp(committed, UTC), now, True, None)
    try:
        _apply(checkout, env, rev)
        # The marker is the very last write, and only once HEAD really is the new revision: an interruption
        # anywhere before it leaves marker != HEAD, which every later read refuses to serve.
        if _head(checkout, env) != rev:
            raise _GitFailed
        _write_marker(checkout, revision)
    except (_GitFailed, OSError, ValueError):
        # The working tree may already be at the new revision: never answer with the old SHA unless it is back.
        if last is not None and _restore(checkout, env, last):
            return None
        (checkout / MARKER).unlink(missing_ok=True)
        raise JobFailure(
            "transient_network", "inventory checkout could not be updated and is in an unknown state", retryable=True
        ) from None
    return revision


def refresh_checkout(
    remote: str,
    ref: str,
    checkout: Path,
    *,
    env: Mapping[str, str],
    now: datetime,
    pull: bool = True,
    on_inconsistent: InconsistencyHook | None = None,
) -> InventoryRevision:
    """Bring the checkout to the remote's ``ref`` (default branch when empty), or keep the last good one.

    A pull is skipped when the last one is younger than ``PULL_MIN_INTERVAL`` or ``pull`` is false. A failed
    pull keeps the last good revision while it is at most ``CHECKOUT_MAX_AGE`` old and fails the job otherwise.
    With ``pull`` false the checkout is returned as is, but only while it is at most ``CHECKOUT_MAX_AGE`` old.

    Integrity: the marker is a cache and ``git rev-parse HEAD`` the truth. A marker that is absent, corrupt or
    different from HEAD is never served; ``on_inconsistent`` is called once for the detection and the call
    fails with the retryable ``inventory_inconsistent`` when ``pull`` is false, or when the repair pull fails.
    With ``pull`` true the full fetch, reset, clean, marker sequence runs regardless of the 60 s interval.
    """
    last, finding = _inspect(checkout, env)
    failure: JobFailure | None = None
    if finding is not None:
        failure = _report(finding, on_inconsistent)
        if not pull:
            raise failure
    if last is None and not pull:
        raise JobFailure("transient_network", "inventory checkout is not available yet", retryable=True)
    if last is not None and not pull:
        if now - last.pulled_at > CHECKOUT_MAX_AGE:
            raise JobFailure(
                "transient_network", "inventory checkout is older than 24 hours and no pull was allowed", retryable=True
            )
        return last
    if last is not None and timedelta(0) <= now - last.pulled_at < PULL_MIN_INTERVAL:
        return last
    try:
        pulled = _pull(remote, ref, checkout, env, now, last)
    except JobFailure:
        if failure is not None:
            # A repair that fails past the reset is still the detected inconsistency, never a plain network error.
            raise failure from None
        raise
    if pulled is not None:
        return pulled
    if failure is not None:
        raise failure
    if last is None:
        raise JobFailure("transient_network", "inventory pull failed and no checkout is available", retryable=True)
    if now - last.pulled_at > CHECKOUT_MAX_AGE:
        raise JobFailure(
            "transient_network",
            "inventory pull failed and the last good checkout is older than 24 hours",
            retryable=True,
        )
    return InventoryRevision(last.rev, last.rev_date, last.pulled_at, False, PULL_FAILED_WARNING)


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _group_members(groups: Mapping[str, Mapping[str, object]]) -> dict[str, set[str]]:
    """Every host of each group, children included (``ansible-inventory`` lists direct hosts only)."""

    def collect(name: str, seen: frozenset[str]) -> set[str]:
        node = groups.get(name, {})
        hosts = {host for host in node.get("hosts", []) if isinstance(host, str)}  # type: ignore[attr-defined]
        for child in node.get("children", []):  # type: ignore[attr-defined]
            if isinstance(child, str) and child not in seen:
                hosts |= collect(child, seen | {name})
        return hosts

    return {name: collect(name, frozenset()) for name in groups}


def list_inventory(
    inventory: Path, *, webserver_var: str, env: Mapping[str, str], timeout_seconds: int = 120
) -> list[InventoryHost]:
    """Hosts, groups, ``ansible_host`` and the webserver variable from ``ansible-inventory --list``.

    Runs under the runner environment (so vaulted vars decrypt through the vault client) from the worker's
    own home directory, so an ``ansible.cfg`` inside the repository is never read. Only four fields are
    kept; stdout and stderr are discarded.
    """
    if not inventory.exists():
        raise JobFailure("config_invalid", _UNREADABLE)
    binary = Path(sys.executable).parent / "ansible-inventory"
    try:
        done = subprocess.run(
            [str(binary), "-i", str(inventory), "--list"],
            cwd=env.get("HOME", "/"),
            env=dict(env),
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise JobFailure("timeout", "inventory listing timed out") from None
    except OSError:
        raise JobFailure("config_invalid", _UNREADABLE) from None
    if done.returncode != 0:
        raise JobFailure("config_invalid", _UNREADABLE)
    try:
        return _hosts(json.loads(done.stdout), webserver_var)
    except (ValueError, TypeError, AttributeError):
        raise JobFailure("config_invalid", _UNREADABLE) from None


def _hosts(document: object, webserver_var: str) -> list[InventoryHost]:
    if not isinstance(document, dict) or not isinstance(document.get("_meta", {}), dict):
        raise TypeError
    hostvars = document.get("_meta", {}).get("hostvars", {})
    groups = {name: node for name, node in document.items() if name != "_meta" and isinstance(node, dict)}
    members = _group_members(groups)
    hostnames = set(hostvars) | members.get("all", set())
    result = []
    for hostname in sorted(hostnames):
        variables = hostvars.get(hostname, {})
        address = _text(variables.get("ansible_host"))
        value = variables.get(webserver_var)
        try:
            webserver = WebserverType(value) if isinstance(value, str) else None
        except ValueError:
            webserver = None
        names = sorted(name for name, hosts in members.items() if hostname in hosts and name not in _PSEUDO_GROUPS)
        result.append(InventoryHost(hostname, tuple(names), None if address == hostname else address, webserver))
    return result
