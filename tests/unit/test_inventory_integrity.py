"""The marker is a cache: ``git rev-parse HEAD`` is the truth, and a disagreement fails closed (real git)."""

import json
import shutil
import subprocess
from datetime import timedelta

import pytest

from app.jobs.queue import JobFailure
from app.services.inventory import (
    InventoryInconsistency,
    audit_inconsistency,
    current_revision,
    git_environment,
    refresh_checkout,
)
from tests.fixtures.git_inventory import make_bare_repo

HOSTS_V1 = "all:\n  hosts:\n    web01.example.internal:\n"
HOSTS_V2 = "all:\n  hosts:\n    web01.example.internal:\n    web02.example.internal:\n"
INCONSISTENT = "inventory checkout does not match its recorded revision"
MARKER = ".git/last_pull.json"


class _Killed(BaseException):
    """Stands for the worker process dying: nothing in the service may catch it."""


def environment(tmp_path):
    return git_environment(token=None, ssh_key=None, known_hosts=tmp_path / "known_hosts", home=tmp_path / "home")


def head(checkout):
    done = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return done.stdout.strip()


def marker_rev(checkout):
    return json.loads((checkout / MARKER).read_text())["rev"]


def crashed_between_reset_and_marker(tmp_path, now, monkeypatch):
    """Checkout at B, marker still at A: the process died after ``reset --hard``, before the marker write."""
    from app.services import inventory

    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    first = refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    second = remote.commit({"inventory/hosts.yml": HOSTS_V2})
    real = inventory._git

    def dying(checkout_dir, child_env, *args):
        if args and args[0] == "clean":
            raise _Killed
        return real(checkout_dir, child_env, *args)

    with monkeypatch.context() as patch:
        patch.setattr(inventory, "_git", dying)
        with pytest.raises(_Killed):
            refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(hours=1))
    assert head(checkout) == second and marker_rev(checkout) == first.rev
    return remote, checkout, env, first.rev, second


def test_no_pull_after_an_interrupted_reset_fails_closed_and_leaves_the_marker_alone(tmp_path, now, monkeypatch):
    remote, checkout, env, first, second = crashed_between_reset_and_marker(tmp_path, now, monkeypatch)
    marker = (checkout / MARKER).read_bytes()
    findings = []
    with pytest.raises(JobFailure) as failure:
        refresh_checkout(
            remote.url,
            "main",
            checkout,
            env=env,
            now=now + timedelta(hours=2),
            pull=False,
            on_inconsistent=findings.append,
        )
    assert (failure.value.error_class, failure.value.message, failure.value.retryable) == (
        "inventory_inconsistent",
        INCONSISTENT,
        True,
    )
    for hidden in (first, second, str(tmp_path), remote.url):
        assert hidden not in failure.value.message
    assert (checkout / MARKER).read_bytes() == marker
    assert findings == [InventoryInconsistency("mismatch", expected=first, actual=second)]


def test_the_minimum_interval_never_serves_a_marker_that_disagrees_with_head(tmp_path, now, monkeypatch):
    remote, checkout, env, first, second = crashed_between_reset_and_marker(tmp_path, now, monkeypatch)
    findings = []
    healed = refresh_checkout(
        remote.url, "main", checkout, env=env, now=now + timedelta(seconds=30), on_inconsistent=findings.append
    )
    assert (healed.rev, healed.refreshed, healed.warning) == (second, True, None)
    assert findings == [InventoryInconsistency("mismatch", expected=first, actual=second)]


def test_the_next_pull_heals_an_interrupted_reset(tmp_path, now, monkeypatch):
    remote, checkout, env, _first, second = crashed_between_reset_and_marker(tmp_path, now, monkeypatch)
    later = now + timedelta(hours=2)
    with pytest.raises(JobFailure):
        refresh_checkout(remote.url, "main", checkout, env=env, now=later, pull=False)
    healed = refresh_checkout(remote.url, "main", checkout, env=env, now=later + timedelta(minutes=1))
    assert (healed.rev, healed.refreshed, healed.warning) == (second, True, None)
    assert head(checkout) == second == marker_rev(checkout)
    assert (checkout / "inventory/hosts.yml").read_text() == HOSTS_V2
    again = refresh_checkout(remote.url, "main", checkout, env=env, now=later + timedelta(minutes=2), pull=False)
    assert (again.rev, again.refreshed) == (second, False)


def test_a_failed_heal_never_falls_back_to_the_untrusted_checkout(tmp_path, now, monkeypatch):
    remote, checkout, env, _first, _second = crashed_between_reset_and_marker(tmp_path, now, monkeypatch)
    shutil.rmtree(remote.path)
    with pytest.raises(JobFailure) as failure:
        refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(hours=2))
    assert (failure.value.error_class, failure.value.message) == ("inventory_inconsistent", INCONSISTENT)


def test_a_heal_that_fails_after_the_reset_is_still_reported_as_inconsistent(tmp_path, now, monkeypatch):
    from app.services import inventory

    remote, checkout, env, _first, _second = crashed_between_reset_and_marker(tmp_path, now, monkeypatch)
    real = inventory._git

    def failing_clean(checkout_dir, child_env, *args):
        if args and args[0] == "clean":
            raise inventory._GitFailed
        return real(checkout_dir, child_env, *args)

    findings = []
    monkeypatch.setattr(inventory, "_git", failing_clean)
    with pytest.raises(JobFailure) as failure:
        refresh_checkout(
            remote.url, "main", checkout, env=env, now=now + timedelta(hours=2), on_inconsistent=findings.append
        )
    assert (failure.value.error_class, failure.value.message, failure.value.retryable) == (
        "inventory_inconsistent",
        INCONSISTENT,
        True,
    )
    assert len(findings) == 1
    assert not (checkout / MARKER).exists()


@pytest.mark.parametrize(
    ("damage", "reason"),
    [("missing", "marker_missing"), ("corrupt", "marker_corrupt"), ("not a sha", "marker_corrupt")],
)
def test_a_missing_or_corrupt_marker_fails_closed_like_a_mismatch(tmp_path, now, damage, reason):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    first = refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    marker = checkout / MARKER
    if damage == "missing":
        marker.unlink()
    elif damage == "corrupt":
        marker.write_text("{not json")
    else:
        marker.write_text(json.dumps({"rev": "zz", "rev_date": now.isoformat(), "pulled_at": now.isoformat()}))
    findings = []
    with pytest.raises(JobFailure) as failure:
        refresh_checkout(
            remote.url,
            "main",
            checkout,
            env=env,
            now=now + timedelta(seconds=5),
            pull=False,
            on_inconsistent=findings.append,
        )
    assert (failure.value.error_class, failure.value.message) == ("inventory_inconsistent", INCONSISTENT)
    assert findings == [InventoryInconsistency(reason, expected=None, actual=first.rev)]
    healed = refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(seconds=10))
    assert (healed.rev, healed.refreshed) == (first.rev, True)


def test_a_marker_naming_a_commit_other_than_head_is_a_mismatch(tmp_path, now):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    first = refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    document = json.loads((checkout / MARKER).read_text())
    document["rev"] = "0" * 40
    (checkout / MARKER).write_text(json.dumps(document))
    findings = []
    with pytest.raises(JobFailure):
        current_revision(checkout, on_inconsistent=findings.append)
    assert findings == [InventoryInconsistency("mismatch", expected="0" * 40, actual=first.rev)]


def test_a_consistent_checkout_is_served_without_network_or_findings(tmp_path, now, monkeypatch):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    first = refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    calls, real_run = [], subprocess.run

    def recording_run(argv, *args, **kwargs):
        calls.append(list(argv))
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", recording_run)
    findings = []
    for pull, offset in ((False, 5), (True, 30), (False, 3600)):
        served = refresh_checkout(
            remote.url,
            "main",
            checkout,
            env=env,
            now=now + timedelta(seconds=offset),
            pull=pull,
            on_inconsistent=findings.append,
        )
        assert (served.rev, served.refreshed, served.warning) == (first.rev, False, None)
    assert findings == [] and calls
    assert all("fetch" not in argv and "reset" not in argv for argv in calls)


def test_the_marker_is_written_last_and_only_once_head_is_the_new_revision(tmp_path, now, monkeypatch):
    from app.services import inventory

    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    second = remote.commit({"inventory/hosts.yml": HOSTS_V2})
    seen, real = [], inventory._write_marker

    def checking(checkout_dir, revision):
        seen.append((head(checkout_dir), revision.rev, (checkout_dir / "inventory/hosts.yml").read_text()))
        real(checkout_dir, revision)

    monkeypatch.setattr(inventory, "_write_marker", checking)
    refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(hours=1))
    assert seen == [(second, second, HOSTS_V2)]


def test_a_first_pull_that_never_completed_is_unavailable_not_inconsistent(tmp_path, now):
    env, checkout = environment(tmp_path), tmp_path / "inventory"
    with pytest.raises(JobFailure):
        refresh_checkout((tmp_path / "missing.git").as_uri(), "main", checkout, env=env, now=now)
    findings = []
    with pytest.raises(JobFailure) as failure:
        refresh_checkout(
            "file:///nowhere", "main", checkout, env=env, now=now, pull=False, on_inconsistent=findings.append
        )
    assert failure.value.error_class == "transient_network" and findings == []


def test_an_invalid_git_directory_never_reads_the_head_of_an_enclosing_repository(tmp_path):
    outer = tmp_path / "outer"
    subprocess.run(["git", "init", "-q", str(outer)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(outer), "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty", "-m", "x"],
        check=True,
        capture_output=True,
    )
    (outer / "inventory/.git").mkdir(parents=True)  # not a valid git directory: git would walk up to ``outer``
    (outer / "inventory" / MARKER).write_text(json.dumps({"rev": head(outer), "rev_date": "2026-10-19T12:00:00+00:00", "pulled_at": "2026-10-19T12:00:00+00:00"}))
    findings = []
    with pytest.raises(JobFailure):
        current_revision(outer / "inventory", on_inconsistent=findings.append)
    assert [(item.reason, item.actual) for item in findings] == [("mismatch", None)]


class _FakeFactory:
    def __init__(self):
        self.rows = []

    def begin(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def add(self, row):
        self.rows.append(row)


def test_audit_inconsistency_records_one_event_with_both_revisions():
    factory = _FakeFactory()
    audit_inconsistency(factory, job_id="job-1")(InventoryInconsistency("mismatch", expected="a" * 40, actual="b" * 40))
    (row,) = factory.rows
    assert (row.action, row.target_type, row.actor_label) == ("inventory.inconsistent", "inventory", "system")
    assert row.details == {"reason": "mismatch", "expected_rev": "a" * 40, "actual_rev": "b" * 40, "job_id": "job-1"}


def test_a_failing_audit_hook_never_hides_the_typed_failure(tmp_path, now, monkeypatch):
    remote, checkout, env, _first, _second = crashed_between_reset_and_marker(tmp_path, now, monkeypatch)

    def broken(finding):
        raise RuntimeError("database is down")

    with pytest.raises(JobFailure) as failure:
        refresh_checkout(
            remote.url, "main", checkout, env=env, now=now + timedelta(hours=2), pull=False, on_inconsistent=broken
        )
    assert failure.value.error_class == "inventory_inconsistent"
