"""Pure expiry-alert rules (§7.4): threshold choice, recipients and the UTC-day dedupe key."""

from datetime import timedelta
from zoneinfo import ZoneInfo

import pytest

from app.services.alerts import crossed_threshold, expiry_dedupe_key, resolve_recipients


@pytest.mark.parametrize(
    ("remaining", "expected"),
    [
        (timedelta(days=61), None),
        (timedelta(days=60), 60),
        (timedelta(days=29), 30),
        (timedelta(days=6, hours=23), 7),
        (timedelta(hours=5), 1),
        (timedelta(0), 0),
        (-timedelta(days=3), 0),
    ],
)
def test_smallest_crossed_threshold_wins(now, remaining, expected):
    assert crossed_threshold(now + remaining, now, [60, 30, 14, 7, 1, 0]) == expected


def test_thresholds_may_arrive_in_any_order(now):
    assert crossed_threshold(now + timedelta(days=10), now, [0, 60, 14, 30]) == 14


def test_recipients_are_owner_first_and_deduplicated():
    assert resolve_recipients("Owner@Example.test", ["team@example.test", "owner@example.test"]) == (
        "Owner@Example.test",
        "team@example.test",
    )
    assert resolve_recipients(None, ["team@example.test"]) == ("team@example.test",)
    assert resolve_recipients("", []) == ()


def test_blank_owner_and_team_entries_are_ignored():
    assert resolve_recipients("  ", [" a@example.test ", "", "A@example.test"]) == ("a@example.test",)


def test_dedupe_key_uses_the_utc_run_date(now):
    assert expiry_dedupe_key(42, 30, now.astimezone(ZoneInfo("Pacific/Kiritimati"))) == "expiry:42:30:2026-10-19"
    late_utc = now.replace(hour=23, minute=59)
    assert expiry_dedupe_key(7, 0, late_utc.astimezone(ZoneInfo("Asia/Tokyo"))) == "expiry:7:0:2026-10-19"
