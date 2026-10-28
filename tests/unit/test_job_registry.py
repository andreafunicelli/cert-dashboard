"""Registry, schedule arithmetic, timeouts and artifact pruning; no database is touched here."""

import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from app.config import Settings
from app.crypto.keyring import Keyring, KeyUnwrapError
from app.jobs import worker
from app.jobs.handlers import build_registry
from app.jobs.handlers.cleanup import prune_artifacts, validate_cleanup_payload
from app.jobs.handlers.test_pull import TEST_PULL_ACTION, validate_test_pull_payload
from app.jobs.handlers.trust_recheck import TRUST_RECHECK_ACTION, validate_trust_recheck_payload
from app.jobs.queue import InvalidJobState, JobCancelled, JobControl, JobFailure, JobPaused, JobRequeued
from app.jobs.worker import JobContext, JobRegistry
from app.models import Job
from app.models.enums import JobType

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def make_context(**overrides):
    values = {
        "job_id": uuid4(),
        "worker_id": "w1",
        "factory": None,
        "settings": None,
    }
    values.update(overrides)
    return JobContext(**values)


def job_of(job_type, payload):
    return Job(id=uuid4(), type=job_type, payload=payload)


def ok_handler(context, payload):
    return {"seen": sorted(payload)}


def accept(payload):
    return dict(payload)


def test_context_clock_defaults_to_utc_now():
    before = datetime.now(UTC)
    value = make_context().clock()
    assert before <= value <= datetime.now(UTC)
    assert value.tzinfo is not None


def test_build_registry_supports_cleanup_pull_import_and_the_default_scan():
    registry = build_registry()
    assert registry.supports(JobType.CLEANUP)
    assert registry.supports(JobType.CLEANUP, "default")
    assert not registry.supports(JobType.DEPLOY)
    assert registry.supports(JobType.SCAN, "import_pull")  # Task 16
    assert registry.supports(JobType.SCAN)  # scan/default (Plan 2 Task 2)
    assert build_registry() is not build_registry()


def test_registry_supports_the_test_pull_and_the_default_discovery():
    registry = build_registry()
    assert TEST_PULL_ACTION == "test_pull"
    assert registry.supports(JobType.DISCOVER, "test_pull")
    assert registry.supports(JobType.DISCOVER)  # discover/default (Plan 3 Task 10)
    assert registry.supports(JobType.DISCOVER, "default")
    assert not registry.supports(JobType.DEPLOY)  # arrives with Plan 3 Task 16


def test_test_pull_payload_is_exactly_its_action():
    assert validate_test_pull_payload({"action": "test_pull"}) == {"action": "test_pull"}
    for payload in ({}, {"action": "smtp_test"}, {"action": "test_pull", "hosts": ["a"]}, {"hosts": ["a"]}):
        with pytest.raises(ValueError):
            validate_test_pull_payload(payload)


def test_duplicate_registration_is_rejected():
    registry = JobRegistry()
    registry.register(JobType.SCAN, ok_handler, validator=accept)
    registry.register(JobType.SCAN, ok_handler, action="import_pull", validator=accept)
    with pytest.raises(ValueError):
        registry.register(JobType.SCAN, ok_handler, validator=accept)
    with pytest.raises(ValueError):
        registry.register(JobType.SCAN, ok_handler, action="import_pull", validator=accept)


def test_dispatch_runs_the_validated_payload_through_the_handler():
    registry = JobRegistry()
    registry.register(JobType.SCAN, ok_handler, validator=lambda p: {"clean": 1})
    assert registry.dispatch(make_context(), job_of(JobType.SCAN, {"anything": 1})) == {"seen": ["clean"]}


def test_dispatch_selects_by_action():
    registry = JobRegistry()
    registry.register(JobType.SCAN, lambda c, p: {"which": "default"}, validator=accept)
    registry.register(
        JobType.SCAN, lambda c, p: {"which": "pull"}, action="import_pull", validator=accept
    )
    context = make_context()
    assert registry.dispatch(context, job_of(JobType.SCAN, {}))["which"] == "default"
    assert registry.dispatch(context, job_of(JobType.SCAN, {"action": "import_pull"}))["which"] == "pull"


@pytest.mark.parametrize(
    ("job_type", "payload"),
    [
        (JobType.DEPLOY, {}),  # type not registered
        (JobType.SCAN, {"action": "bogus"}),  # action not registered
        (JobType.SCAN, {"action": 7}),  # unhashable/non-text action
        (JobType.SCAN, {"action": ["x"]}),
        (JobType.SCAN, ["not", "a", "dict"]),
        (JobType.SCAN, None),
        (JobType.SCAN, "text"),
    ],
)
def test_unknown_or_poison_payload_is_a_validation_failure(job_type, payload):
    registry = JobRegistry()
    registry.register(JobType.SCAN, ok_handler, validator=accept)
    with pytest.raises(JobFailure) as caught:
        registry.dispatch(make_context(), job_of(job_type, payload))
    assert caught.value.error_class == "validation"
    assert caught.value.retryable is False


def test_unrecognized_job_type_is_a_sanitized_validation_failure():
    registry = JobRegistry()
    registry.register(JobType.SCAN, ok_handler, validator=accept)
    with pytest.raises(JobFailure) as caught:
        registry.dispatch(make_context(), Job(id=uuid4(), type="unrecognized", payload={}))
    assert caught.value.error_class == "validation"
    assert caught.value.retryable is False
    assert "unrecognized" not in str(caught.value)


def test_validator_exception_is_a_sanitized_validation_failure():
    def explode(payload):
        raise RuntimeError("password=fixture-validator-secret")

    registry = JobRegistry()
    registry.register(JobType.SCAN, ok_handler, validator=explode)
    with pytest.raises(JobFailure) as caught:
        registry.dispatch(make_context(), job_of(JobType.SCAN, {"x": 1}))
    assert caught.value.error_class == "validation"
    assert "fixture-validator-secret" not in str(caught.value)
    assert "fixture-validator-secret" not in caught.value.message


def test_handler_is_not_called_when_validation_fails():
    called = []
    registry = JobRegistry()
    registry.register(
        JobType.SCAN,
        lambda c, p: called.append(p) or {},
        validator=lambda p: (_ for _ in ()).throw(ValueError("no")),
    )
    with pytest.raises(JobFailure):
        registry.dispatch(make_context(), job_of(JobType.SCAN, {}))
    assert called == []


def test_job_failure_from_a_handler_passes_through_unchanged():
    def handler(context, payload):
        raise JobFailure("transient_network", "connect refused", retryable=True)

    registry = JobRegistry()
    registry.register(JobType.SCAN, handler, validator=accept)
    with pytest.raises(JobFailure) as caught:
        registry.dispatch(make_context(), job_of(JobType.SCAN, {}))
    assert caught.value.error_class == "transient_network"
    assert caught.value.retryable is True


def test_key_unwrap_error_maps_to_key_unwrap_without_leaking_its_text():
    def handler(context, payload):
        raise KeyUnwrapError

    registry = JobRegistry()
    registry.register(JobType.SCAN, handler, validator=accept)
    with pytest.raises(JobFailure) as caught:
        registry.dispatch(make_context(), job_of(JobType.SCAN, {}))
    assert caught.value.error_class == "key_unwrap"
    assert caught.value.message == "master key unavailable for this record"


def test_unexpected_exception_is_internal_and_only_its_class_is_logged(caplog):
    def handler(context, payload):
        raise RuntimeError("password=fixture-handler-secret")

    registry = JobRegistry()
    registry.register(JobType.SCAN, handler, validator=accept)
    with caplog.at_level(logging.DEBUG), pytest.raises(JobFailure) as caught:
        registry.dispatch(make_context(), job_of(JobType.SCAN, {}))
    assert caught.value.error_class == "internal"
    assert caught.value.message == "internal error"
    assert caught.value.__cause__ is None
    assert "RuntimeError" in caplog.text
    assert "fixture-handler-secret" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize(
    "payload",
    [{}, {"reason": "scheduled"}, {"reason": "manual_prune"}],
)
def test_cleanup_validator_accepts(payload):
    assert validate_cleanup_payload(payload) == payload


@pytest.mark.parametrize(
    "payload",
    [{"reason": "other"}, {"reason": None}, {"reason": 1}, {"action": "default"}, {"extra": 1},
     {"reason": "scheduled", "path": "/"}],
)
def test_cleanup_validator_rejects(payload):
    with pytest.raises(ValueError):
        validate_cleanup_payload(payload)


def test_poison_cleanup_payload_is_a_validation_failure():
    with pytest.raises(JobFailure) as caught:
        build_registry().dispatch(make_context(), job_of(JobType.CLEANUP, {"path": "/etc"}))
    assert caught.value.error_class == "validation"


# --- schedule arithmetic -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [("04:00", (4, 0)), ("00:00", (0, 0)), ("23:59", (23, 59)), ("07:30", (7, 30))],
)
def test_parse_daily_time_accepts_hh_mm(value, expected):
    assert worker.parse_daily_time(value) == expected


@pytest.mark.parametrize("value", ["4:00", "24:00", "04:60", "0400", "04:00:00", "", None, 4, ["04:00"], "ab:cd"])
def test_parse_daily_time_rejects_everything_else(value):
    assert worker.parse_daily_time(value) is None


def test_latest_occurrence_is_today_when_already_passed_else_yesterday():
    today = datetime(2026, 10, 19, 4, 0, tzinfo=UTC)
    assert worker.latest_occurrence(today, (4, 0)) == today
    assert worker.latest_occurrence(today + timedelta(minutes=31), (4, 0)) == today
    assert worker.latest_occurrence(today - timedelta(seconds=1), (4, 0)) == today - timedelta(days=1)
    assert worker.latest_occurrence(datetime(2026, 10, 19, 0, 0, tzinfo=UTC), (0, 0)) == datetime(
        2026, 10, 19, 0, 0, tzinfo=UTC
    )


def test_latest_occurrence_normalizes_to_utc():
    from datetime import timezone

    plus_two = timezone(timedelta(hours=2))
    local = datetime(2026, 10, 19, 6, 30, tzinfo=plus_two)  # 04:30 UTC
    assert worker.latest_occurrence(local, (4, 0)) == datetime(2026, 10, 19, 4, 0, tzinfo=UTC)


def test_default_schedule_table_has_cleanup_scan_expiry_check_digest_and_discovery():
    assert set(worker.SCHEDULES) == {"cleanup", "scan", "trust_recheck", "expiry_check", "digest", "discovery"}
    assert worker.SCHEDULES["discovery"] == worker.Schedule("discovery", JobType.DISCOVER, "default")
    assert worker.SCHEDULES["digest"] == worker.Schedule("digest", JobType.DIGEST, "default")
    assert (worker.SCHEDULES["expiry_check"].job_type, worker.SCHEDULES["expiry_check"].action) == (
        JobType.ALERT_EXPIRY,
        "default",
    )
    assert (worker.SCHEDULES["scan"].job_type, worker.SCHEDULES["scan"].action) == (JobType.SCAN, "default")
    assert worker.SCHEDULES["cleanup"].job_type == JobType.CLEANUP
    assert worker.SCHEDULES["cleanup"].action == "default"


def test_register_schedule_rejects_duplicate_keys(monkeypatch):
    monkeypatch.setattr(worker, "SCHEDULES", dict(worker.SCHEDULES))
    with pytest.raises(ValueError):
        worker.register_schedule("digest", JobType.DIGEST)
    with pytest.raises(ValueError):
        worker.register_schedule("expiry_check", JobType.ALERT_EXPIRY)
    with pytest.raises(ValueError):
        worker.register_schedule("scan", JobType.SCAN)
    with pytest.raises(ValueError):
        worker.register_schedule("cleanup", JobType.CLEANUP)


# --- timeouts --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("job_type", "seconds"),
    [
        (JobType.DISCOVER, 1800),
        (JobType.SCAN, 1800),
        (JobType.ALERT_EXPIRY, 300),
        (JobType.DIGEST, 300),
        (JobType.CLEANUP, 600),
        (JobType.DEPLOY, 900),
    ],
)
def test_timeout_for_per_type(job_type, seconds):
    assert worker.timeout_for(None, job_of(job_type, {})) == seconds


def test_deploy_timeout_uses_the_registered_callback(monkeypatch):
    monkeypatch.setattr(worker, "_TIMEOUT_CALLBACKS", {})
    seen = []
    worker.register_timeout(JobType.DEPLOY, lambda db, job: seen.append((db, job.type)) or 4200)
    assert worker.timeout_for("DB", job_of(JobType.DEPLOY, {})) == 4200
    assert seen == [("DB", JobType.DEPLOY)]
    with pytest.raises(ValueError):
        worker.register_timeout(JobType.DEPLOY, lambda db, job: 1)
    with pytest.raises(ValueError):
        worker.register_timeout(JobType.SCAN, lambda db, job: 1)


# --- artifact pruning -------------------------------------------------------------------------

DAY = 86_400
CUTOFF = NOW - timedelta(days=30)


def age(path: Path, days: float) -> None:
    stamp = (NOW - timedelta(days=days)).timestamp()
    os.utime(path, (stamp, stamp), follow_symlinks=False)


def make_file(path: Path, days: float, data: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    age(path, days)
    return path


def test_prune_removes_only_entries_older_than_cutoff(tmp_path):
    root = tmp_path / "artifacts"
    old = make_file(root / "old.log", 31)
    new = make_file(root / "new.log", 29)
    assert prune_artifacts(root, CUTOFF) == 1
    assert not old.exists() and new.exists() and root.is_dir()


def test_prune_removes_old_directory_trees_but_keeps_trees_with_recent_files(tmp_path):
    root = tmp_path / "artifacts"
    make_file(root / "run-old" / "env" / "stdout", 40)
    make_file(root / "run-old" / "status", 40)
    for sub in (root / "run-old" / "env", root / "run-old"):
        age(sub, 40)
    make_file(root / "run-mixed" / "old.log", 40)
    make_file(root / "run-mixed" / "fresh.log", 1)
    age(root / "run-mixed", 40)
    removed = prune_artifacts(root, CUTOFF)
    assert not (root / "run-old").exists()
    assert not (root / "run-mixed" / "old.log").exists()
    assert (root / "run-mixed" / "fresh.log").exists()
    assert removed == 5  # stdout, env/, status, run-old/, old.log


def test_prune_never_removes_the_root_itself_even_when_empty_and_old(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    age(root, 400)
    assert prune_artifacts(root, CUTOFF) == 0
    assert root.is_dir()


def test_prune_missing_or_non_directory_root_is_a_noop(tmp_path):
    assert prune_artifacts(tmp_path / "absent", CUTOFF) == 0
    plain = make_file(tmp_path / "plain", 90)
    assert prune_artifacts(plain, CUTOFF) == 0
    assert plain.exists()


def test_prune_never_follows_or_removes_symlinks(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    outside = tmp_path / "outside"
    victim = make_file(outside / "victim.txt", 400)
    age(outside, 400)
    (root / "link-dir").symlink_to(outside, target_is_directory=True)
    (root / "link-file").symlink_to(victim)
    (root / "dangling").symlink_to(tmp_path / "nowhere")
    for name in ("link-dir", "link-file", "dangling"):
        age(root / name, 400)
    assert prune_artifacts(root, CUTOFF) == 0
    assert victim.exists() and outside.is_dir()
    assert all((root / name).is_symlink() for name in ("link-dir", "link-file", "dangling"))


def test_prune_leaves_a_directory_that_still_holds_a_symlink(tmp_path):
    root = tmp_path / "artifacts"
    outside = make_file(tmp_path / "outside.txt", 400)
    make_file(root / "run" / "old.log", 60)
    (root / "run" / "link").symlink_to(outside)
    age(root / "run", 60)
    assert prune_artifacts(root, CUTOFF) == 1
    assert (root / "run" / "link").is_symlink() and outside.exists()
    assert not (root / "run" / "old.log").exists()


def test_prune_through_a_symlinked_root_stays_inside_the_resolved_root(tmp_path):
    real = tmp_path / "real"
    old = make_file(real / "old.log", 60)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    assert prune_artifacts(alias, CUTOFF) == 1
    assert not old.exists() and real.is_dir()


def test_prune_does_not_touch_siblings_of_the_root(tmp_path):
    root = tmp_path / "artifacts"
    sibling = make_file(tmp_path / "artifacts-keep" / "old.log", 400)
    make_file(root / "old.log", 400)
    assert prune_artifacts(root, CUTOFF) == 1
    assert sibling.exists()


def test_settings_type_is_importable_for_context():
    # JobContext only annotates Settings/Keyring; make sure the real types still line up.
    assert Settings and Keyring


# --- trust recheck (Plan 2 Task 3) ------------------------------------------------------------


def test_registry_supports_the_trust_recheck_scan_action():
    registry = build_registry()
    assert registry.supports(JobType.SCAN, "trust_recheck")
    assert registry.supports(JobType.SCAN, "import_pull") and registry.supports(JobType.SCAN)


def test_trust_recheck_payload_is_exactly_the_action():
    assert validate_trust_recheck_payload({"action": TRUST_RECHECK_ACTION}) == {"action": "trust_recheck"}


@pytest.mark.parametrize(
    "payload",
    [{}, {"action": "default"}, {"action": "trust_recheck", "extra": 1}, {"action": "trust_recheck", "endpoint_ids": [1]}],
)
def test_trust_recheck_payload_validator_rejects_anything_else(payload):
    with pytest.raises(ValueError):
        validate_trust_recheck_payload(payload)


def test_trust_recheck_is_scheduled_under_the_scan_settings():
    assert worker.SCHEDULES["trust_recheck"] == worker.Schedule("trust_recheck", JobType.SCAN, "trust_recheck")
    assert worker._TIME_SETTING["trust_recheck"] == "scan.daily_at"
    assert worker._ENABLED_SETTING["trust_recheck"] == "scan.enabled"


# --- success hooks and job control (Plan 3 Task 1) ---------------------------------------------


def test_registry_rejects_a_non_callable_success_hook():
    registry = JobRegistry()
    with pytest.raises(TypeError, match="on_success"):
        registry.register(JobType.DEPLOY, ok_handler, validator=accept, on_success="not callable")
    assert not registry.supports(JobType.DEPLOY)  # nothing half-registered


def test_success_hook_is_looked_up_per_type_and_action():
    registry = JobRegistry()

    def hook(db, job, now):
        return None

    registry.register(JobType.DEPLOY, ok_handler, validator=accept, on_success=hook)
    registry.register(JobType.DEPLOY, ok_handler, action="other", validator=accept)
    registry.register(JobType.CLEANUP, ok_handler, validator=accept)
    assert registry.success_hook(JobType.DEPLOY) is hook
    assert registry.success_hook(JobType.DEPLOY, "default") is hook
    assert registry.success_hook(JobType.DEPLOY, "other") is None
    assert registry.success_hook(JobType.CLEANUP) is None
    assert registry.success_hook(JobType.SCAN) is None


def test_dispatch_passes_job_control_through_unchanged():
    for outcome in (
        JobPaused(resume_from_batch=1, result={"phase": "paused"}),
        JobRequeued(NOW),
        JobCancelled("stopped", {"phase": "cancelled"}),
    ):

        def raiser(context, payload, outcome=outcome):
            raise outcome

        registry = JobRegistry()
        registry.register(JobType.DEPLOY, raiser, validator=accept)
        with pytest.raises(JobControl) as exc:
            registry.dispatch(make_context(), job_of(JobType.DEPLOY, {}))
        assert exc.value is outcome


def test_job_control_outcomes_carry_their_arguments():
    paused = JobPaused(2, {"a": 1})
    assert (paused.resume_from_batch, paused.result) == (2, {"a": 1})
    assert JobRequeued(NOW).run_after == NOW
    cancelled = JobCancelled("m", {"a": 1})
    assert (cancelled.message, cancelled.result) == ("m", {"a": 1})
    assert issubclass(InvalidJobState, ValueError)
    assert not issubclass(JobControl, JobFailure)
