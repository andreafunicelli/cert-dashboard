"""Notification retry ladder (Contract decision 7): 30 s, then 120 s, then stop."""

from datetime import UTC, datetime, timedelta

import pytest

from app.services.notifications import MAX_NOTIFICATION_ATTEMPTS, next_attempt_after

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(("attempts", "seconds"), [(1, 30), (2, 120)])
def test_retryable_failures_back_off_on_the_job_ladder(attempts, seconds):
    assert next_attempt_after(attempts, NOW, True) == NOW + timedelta(seconds=seconds)


def test_the_third_attempt_is_the_last():
    assert MAX_NOTIFICATION_ATTEMPTS == 3
    assert next_attempt_after(3, NOW, True) is None


@pytest.mark.parametrize("attempts", [1, 2, 3])
def test_non_retryable_failures_are_never_rescheduled(attempts):
    assert next_attempt_after(attempts, NOW, False) is None
