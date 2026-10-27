import json
import shutil
import subprocess
from datetime import datetime, timedelta

import pytest

from app.ansible.runner import GIT_ASKPASS
from app.jobs.queue import JobFailure
from app.services.inventory import (
    InventoryRevision,
    current_revision,
    git_environment,
    refresh_checkout,
    revision_result,
)
from tests.fixtures.git_inventory import make_bare_repo

HOSTS_V1 = "all:\n  hosts:\n    web01.example.internal:\n"
HOSTS_V2 = "all:\n  hosts:\n    web01.example.internal:\n    web02.example.internal:\n"
PULL_FAILED = "pull failed; using the last good revision"


def environment(tmp_path, **overrides):
    values = {"token": None, "ssh_key": None, "known_hosts": tmp_path / "known_hosts", "home": tmp_path / "home"}
    return git_environment(**{**values, **overrides})


def test_refresh_keeps_the_last_good_revision_until_it_is_a_day_old(tmp_path, now):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    first = refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    assert first.refreshed and first.rev == remote.head and (checkout / "inventory/hosts.yml").read_text() == HOSTS_V1
    remote.commit({"inventory/hosts.yml": HOSTS_V2})
    assert refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(seconds=59)).rev == first.rev
    shutil.rmtree(remote.path)
    kept = refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(hours=23))
    assert (kept.rev, kept.refreshed, kept.warning) == (first.rev, False, PULL_FAILED)
    with pytest.raises(JobFailure) as failure:
        refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(hours=24, seconds=1))
    assert failure.value.error_class == "transient_network" and "older than 24 hours" in failure.value.message


def test_a_new_commit_is_pulled_once_the_minimum_interval_has_passed(tmp_path, now):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    second = remote.commit({"inventory/hosts.yml": HOSTS_V2})
    pulled = refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(seconds=60))
    assert (pulled.rev, pulled.refreshed, pulled.warning) == (second, True, None)
    assert (checkout / "inventory/hosts.yml").read_text() == HOSTS_V2
    assert pulled.pulled_at == now + timedelta(seconds=60)
    assert pulled.rev_date == datetime.fromisoformat(remote.head_date)


def test_local_edits_are_reset_and_untracked_files_removed(tmp_path, now):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1, ".gitignore": "ignored.txt\n"})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    (checkout / "inventory/hosts.yml").write_text("tampered\n")
    (checkout / "untracked.yml").write_text("x")
    (checkout / "ignored.txt").write_text("x")
    nested = checkout / "nested"
    subprocess.run(["git", "init", "-q", str(nested)], check=True, capture_output=True)
    (nested / "file").write_text("x")
    refreshed = refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(minutes=5))
    assert refreshed.refreshed
    assert (checkout / "inventory/hosts.yml").read_text() == HOSTS_V1
    assert not (checkout / "untracked.yml").exists() and not (checkout / "ignored.txt").exists()
    assert not nested.exists()


def test_empty_ref_follows_the_remote_default_branch_and_tags_resolve(tmp_path, now):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    tagged = remote.head
    remote.tag("v1", annotated=True)
    remote.tag("light")
    other = remote.commit({"inventory/hosts.yml": HOSTS_V2}, branch="release")
    env = environment(tmp_path)
    on_main = refresh_checkout(remote.url, "", tmp_path / "a", env=env, now=now)
    assert on_main.rev == tagged
    remote.set_default_branch("release")
    assert refresh_checkout(remote.url, "", tmp_path / "b", env=env, now=now).rev == other
    assert refresh_checkout(remote.url, "v1", tmp_path / "c", env=env, now=now).rev == tagged
    assert refresh_checkout(remote.url, "light", tmp_path / "d", env=env, now=now).rev == tagged
    assert refresh_checkout(remote.url, "release", tmp_path / "e", env=env, now=now).rev == other


def test_token_reaches_git_only_through_askpass(tmp_path, now, monkeypatch):
    token = "git-token-canary-5d2c81"
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    calls = []
    real_run = subprocess.run

    def recording_run(argv, *args, **kwargs):
        calls.append((list(argv), dict(kwargs.get("env") or {}), kwargs.get("timeout")))
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", recording_run)
    checkout, env = tmp_path / "inventory", environment(tmp_path, token=token.encode())
    refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    assert calls
    for argv, child_env, timeout in calls:
        assert argv[0] == "git" and not any(token in part for part in argv)
        assert [key for key, value in child_env.items() if token in value] == ["CERT_DASHBOARD_GIT_TOKEN"]
        assert child_env["GIT_ASKPASS"] == str(GIT_ASKPASS)
        assert child_env["GIT_TERMINAL_PROMPT"] == "0" and child_env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert child_env["GIT_ALLOW_PROTOCOL"] == "https:ssh:file"
        assert "credential.helper=" in argv and timeout == 120
    for path in (checkout / ".git").rglob("*"):
        if path.is_file():
            assert token.encode() not in path.read_bytes(), path
    assert "credential" not in (checkout / ".git/config").read_text()


def test_ssh_command_is_set_only_with_a_key_and_checks_host_keys(tmp_path):
    assert "GIT_SSH_COMMAND" not in environment(tmp_path)
    assert "CERT_DASHBOARD_GIT_TOKEN" not in environment(tmp_path)
    key = tmp_path / "deploy key"
    command = environment(tmp_path, ssh_key=key)["GIT_SSH_COMMAND"]
    assert command.startswith("ssh -i ")
    for option in ("IdentitiesOnly=yes", "StrictHostKeyChecking=yes", "BatchMode=yes"):
        assert f"-o {option}" in command
    assert f"UserKnownHostsFile={tmp_path / 'known_hosts'}" in command and "'" + str(key) + "'" in command


def test_ext_transport_is_refused(tmp_path, now):
    marker, control = tmp_path / "marker", tmp_path / "control"
    env = environment(tmp_path)
    with pytest.raises(JobFailure):
        refresh_checkout(f"ext::sh -c touch% {marker}", "main", tmp_path / "inventory", env=env, now=now)
    assert not marker.exists()
    # The same remote does run its command when the protocol allow-list is lifted, so the refusal is real.
    lifted = {**env, "GIT_ALLOW_PROTOCOL": "ext"}
    subprocess.run(["git", "init", "-q", str(tmp_path / "probe")], check=True, capture_output=True)
    subprocess.run(
        ["git", "fetch", f"ext::sh -c touch% {control}", "HEAD"],
        check=False,
        cwd=tmp_path / "probe",
        env=lifted,
        capture_output=True,
        timeout=60,
    )
    assert control.exists()


def test_pull_false_reports_the_current_revision(tmp_path, now):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    first = refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    remote.commit({"inventory/hosts.yml": HOSTS_V2})
    later = now + timedelta(hours=2)
    current = refresh_checkout(remote.url, "main", checkout, env=env, now=later, pull=False)
    assert (current.rev, current.refreshed, current.warning) == (first.rev, False, None)
    assert current.pulled_at == now and (checkout / "inventory/hosts.yml").read_text() == HOSTS_V1


def test_pull_false_refuses_a_checkout_older_than_a_day(tmp_path, now):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    first = refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    edge = refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(hours=24), pull=False)
    assert (edge.rev, edge.refreshed) == (first.rev, False)
    with pytest.raises(JobFailure) as failure:
        refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(hours=24, seconds=1), pull=False)
    assert failure.value.error_class == "transient_network" and failure.value.retryable
    assert "older than 24 hours" in failure.value.message and remote.url not in failure.value.message


def test_pull_false_without_a_checkout_fails_without_touching_the_remote(tmp_path, now):
    with pytest.raises(JobFailure) as failure:
        refresh_checkout("file:///does/not/exist", "main", tmp_path / "inventory", env=environment(tmp_path), now=now, pull=False)
    assert failure.value.error_class == "transient_network"


def test_marker_is_atomic_json_and_survives_clean(tmp_path, now):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    assert current_revision(checkout) is None
    revision = refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    marker = checkout / ".git/last_pull.json"
    assert json.loads(marker.read_text()) == {
        "rev": revision.rev,
        "rev_date": revision.rev_date.isoformat(),
        "pulled_at": now.isoformat(),
    }
    assert not list(marker.parent.glob("last_pull.json.*"))
    assert current_revision(checkout) == InventoryRevision(revision.rev, revision.rev_date, now, False, None)
    marker.write_text("{not json")
    assert current_revision(checkout) is None


def test_revision_result_carries_the_documented_keys(tmp_path, now):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    env = environment(tmp_path)
    revision = refresh_checkout(remote.url, "main", tmp_path / "inventory", env=env, now=now)
    result = revision_result(revision)
    assert result == {
        "inventory_rev": remote.head,
        "inventory_rev_date": revision.rev_date.isoformat(),
        "inventory_refreshed": True,
    }
    assert len(result["inventory_rev"]) == 40 and result["inventory_rev_date"].endswith("+00:00")
    kept = InventoryRevision(revision.rev, revision.rev_date, revision.pulled_at, False, PULL_FAILED)
    assert revision_result(kept)["inventory_warning"] == PULL_FAILED


def test_a_failed_first_pull_has_nothing_to_fall_back_on(tmp_path, now):
    with pytest.raises(JobFailure) as failure:
        refresh_checkout(
            (tmp_path / "missing.git").as_uri(), "main", tmp_path / "inventory", env=environment(tmp_path), now=now
        )
    assert failure.value.error_class == "transient_network" and str(tmp_path) not in failure.value.message


def test_a_foreign_non_empty_directory_is_never_initialised_or_cleaned(tmp_path, now):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    foreign = tmp_path / "srv"
    foreign.mkdir()
    (foreign / "precious.txt").write_text("keep")
    with pytest.raises(JobFailure) as failure:
        refresh_checkout(remote.url, "main", foreign, env=environment(tmp_path), now=now)
    assert failure.value.error_class == "config_invalid"
    assert (foreign / "precious.txt").read_text() == "keep" and not (foreign / ".git").exists()


def _fail_git_command(monkeypatch, name, *, times):
    """Make the given git subcommand fail ``times`` times (real git for everything else)."""
    from app.services import inventory

    real, remaining = inventory._git, {"n": times}

    def flaky(checkout, env, *args):
        if args and args[0] == name and remaining["n"] > 0:
            remaining["n"] -= 1
            raise inventory._GitFailed
        return real(checkout, env, *args)

    monkeypatch.setattr(inventory, "_git", flaky)


def test_a_failure_after_the_reset_restores_and_reports_the_previous_revision(tmp_path, now, monkeypatch):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    first = refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    remote.commit({"inventory/hosts.yml": HOSTS_V2})
    _fail_git_command(monkeypatch, "clean", times=1)
    kept = refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(hours=1))
    assert (kept.rev, kept.refreshed, kept.warning) == (first.rev, False, PULL_FAILED)
    head = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout
    assert head.strip() == first.rev and (checkout / "inventory/hosts.yml").read_text() == HOSTS_V1


def test_a_failure_after_the_reset_that_cannot_be_undone_fails_closed(tmp_path, now, monkeypatch):
    remote = make_bare_repo(tmp_path / "remote.git", {"inventory/hosts.yml": HOSTS_V1})
    checkout, env = tmp_path / "inventory", environment(tmp_path)
    refresh_checkout(remote.url, "main", checkout, env=env, now=now)
    remote.commit({"inventory/hosts.yml": HOSTS_V2})
    _fail_git_command(monkeypatch, "clean", times=99)
    with pytest.raises(JobFailure) as failure:
        refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(hours=1))
    assert failure.value.error_class == "transient_network" and failure.value.retryable
    assert current_revision(checkout) is None
    with pytest.raises(JobFailure):
        refresh_checkout(remote.url, "main", checkout, env=env, now=now + timedelta(hours=1), pull=False)
