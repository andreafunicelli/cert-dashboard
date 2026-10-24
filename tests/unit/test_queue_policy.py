"""Pure queue policy and argument validation; no database is touched here."""

from datetime import UTC, datetime

import pytest

from app.jobs.queue import (
    NON_RETRYABLE_CLASSES,
    RETRY_POLICY,
    JobFailure,
    StaleJobError,
    enqueue,
    is_retryable,
    retry_delay_seconds,
    safe_error_class,
)
from app.models.enums import JobType
from app.services.audit import Actor

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
ACTOR = Actor(1, "fixture-admin")


def test_every_job_type_has_a_policy():
    assert set(RETRY_POLICY) == set(JobType)


def test_policy_attempt_caps():
    caps = {job_type: policy.max_attempts for job_type, policy in RETRY_POLICY.items()}
    assert caps == {
        JobType.DISCOVER: 3,
        JobType.SCAN: 3,
        JobType.ALERT_EXPIRY: 3,
        JobType.DIGEST: 3,
        JobType.CLEANUP: 2,
        JobType.DEPLOY: 1,
    }


@pytest.mark.parametrize(
    ("job_type", "error_class", "expected"),
    [
        (JobType.DISCOVER, "transient_network", True),
        (JobType.SCAN, "transient_network", True),
        (JobType.SCAN, "smtp_transient", False),
        (JobType.ALERT_EXPIRY, "smtp_transient", True),
        (JobType.DIGEST, "smtp_transient", True),
        (JobType.DIGEST, "transient_network", False),
        (JobType.CLEANUP, "transient_network", True),
        (JobType.CLEANUP, "operational", True),
        (JobType.DEPLOY, "transient_network", False),
        (JobType.DEPLOY, "operational", False),
        (JobType.DEPLOY, "smtp_transient", False),
    ],
)
def test_retryable_classes_per_type(job_type, error_class, expected):
    assert is_retryable(job_type, error_class) is expected


@pytest.mark.parametrize("error_class", sorted(NON_RETRYABLE_CLASSES))
def test_non_retryable_classes_never_retry(error_class):
    assert not any(is_retryable(job_type, error_class) for job_type in JobType)


def test_non_retryable_set_is_the_contract_set():
    assert NON_RETRYABLE_CLASSES == {
        "auth",
        "validation",
        "config_invalid",
        "key_unwrap",
        "internal",
        "timeout",
    }


def test_retry_delays_follow_the_spec_sequence():
    assert [retry_delay_seconds(attempt) for attempt in (1, 2, 3)] == [30, 120, 300]
    with pytest.raises(ValueError):
        retry_delay_seconds(0)


def test_job_failure_defaults_to_non_retryable_and_persists_the_marker():
    failure = JobFailure("transient_network", "connection reset")
    assert (failure.error_class, failure.message, failure.retryable) == (
        "transient_network",
        "connection reset",
        False,
    )
    assert failure.result() == {"retryable": False}
    assert JobFailure("transient_network", "reset", retryable=True).result() is None
    assert isinstance(failure, Exception) and issubclass(StaleJobError, Exception)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_attempts": 0},
        {"max_attempts": -1},
        {"max_attempts": 4},
    ],
)
def test_enqueue_rejects_invalid_max_attempts_before_touching_the_database(kwargs):
    with pytest.raises(ValueError, match="max_attempts"):
        enqueue(None, JobType.SCAN, {}, ACTOR, priority=100, run_after=NOW, **kwargs)


def test_enqueue_deploy_must_be_single_attempt():
    with pytest.raises(ValueError, match="max_attempts"):
        enqueue(None, JobType.DEPLOY, {}, ACTOR, priority=300, run_after=NOW, max_attempts=2)
    with pytest.raises(ValueError, match="max_attempts"):
        enqueue(None, JobType.CLEANUP, {}, ACTOR, priority=10, run_after=NOW, max_attempts=3)


@pytest.mark.parametrize(
    "payload",
    [
        {"password": "fixture-password"},
        {"nested": {"api_token": "fixture-token"}},
        {"items": [{"private_key": "fixture"}]},
        {"note": "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----"},
        {"note": "Bearer fixture-credential"},
        {"blob": "A" * 80},
    ],
)
def test_enqueue_rejects_secret_bearing_payloads(payload):
    with pytest.raises(ValueError, match="secret"):
        enqueue(None, JobType.SCAN, payload, ACTOR, priority=100, run_after=NOW)


@pytest.mark.parametrize(
    "payload",
    [
        {"when": NOW},
        {"ids": {1, 2}},
        {"pair": (1, 2)},
        {1: "non-string key"},
        {"raw": b"bytes"},
        {"ratio": float("nan")},
    ],
)
def test_enqueue_rejects_non_json_payloads(payload):
    with pytest.raises(ValueError, match="JSON"):
        enqueue(None, JobType.SCAN, payload, ACTOR, priority=100, run_after=NOW)


def test_enqueue_rejects_naive_run_after_and_unknown_scheduled_reason():
    with pytest.raises(ValueError, match="run_after"):
        enqueue(None, JobType.SCAN, {}, ACTOR, priority=100, run_after=datetime(2026, 10, 19, 12, 0))
    with pytest.raises(ValueError, match="scheduled_reason"):
        enqueue(None, JobType.SCAN, {}, ACTOR, priority=100, run_after=NOW, scheduled_reason="whenever")


@pytest.mark.parametrize(
    "bad", ["password=fixture-class-secret", "Bearer fixture-class-token", "has space", "x" * 200, ""]
)
def test_job_failure_normalizes_unsafe_error_class(bad):
    failure = JobFailure(bad, "failure")
    assert failure.error_class == "internal"
    assert "fixture-class-secret" not in str(failure)


def test_job_failure_redacts_and_truncates_message():
    failure = JobFailure("transient_network", "bad password=fixture-secret " + "x" * 5000)
    assert "fixture-secret" not in failure.message and len(failure.message) <= 2000
    assert "fixture-secret" not in str(failure)


def test_safe_error_class_keeps_plain_classifications():
    assert safe_error_class("transient_network") == "transient_network"
    assert safe_error_class("smtp_transient") == "smtp_transient"
    assert safe_error_class(None) == "internal"
