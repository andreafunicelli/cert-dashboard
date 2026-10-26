"""Pure digest rendering (§7.5): section headings, caps, escaping, time zones and counts-only results."""

from datetime import timedelta

import pytest

from app.services.audit import redact
from app.services.digest import (
    DigestBinding,
    DigestCertificate,
    DigestData,
    DigestEndpoint,
    DigestHost,
    DigestJob,
    DigestNotification,
    DigestServer,
    digest_counts,
    render_digest,
)

HEADINGS = [
    "Expiring within 7 days",
    "Already expired",
    "New TLS mismatches",
    "Unknown certificates found by discovery",
    "Servers with failed or stale discovery",
    "Failed jobs in the last 24 hours",
    "Rolled-back hosts in the last 24 hours",
    "Failed notifications in the last 24 hours",
]


def build(now, **changes):
    values = {
        "generated_at": now,
        "since": now - timedelta(hours=24),
        "expiring": [DigestCertificate(1, "soon.example.test", now + timedelta(days=3), 3, "Ops")],
        "expired": [DigestCertificate(2, "gone.example.test", now - timedelta(days=2), -2, None)],
        "new_mismatches": [
            DigestEndpoint(5, "web.example.test", 443, None, "web.example.test", "other.example.test", None, "ok", "mismatch", now)
        ],
        "mismatch_count": 4,
        "unknown_certificates": [
            DigestBinding(7, "web01", "shop.example.test", 443, "/etc/ssl/shop.pem", "a" * 64, "matched", now)
        ],
        "stale_servers": [DigestServer("web02", "failed", now - timedelta(days=3))],
        "failed_jobs": [DigestJob("job-1", "scan", "transient_network", now)],
        "rolled_back_hosts": [DigestHost("job-2", "web03", True, "restore failed", now)],
        "failed_notifications": [DigestNotification("expiry", 1, 7, 3, "smtp_transient: 451 at rcpt", now)],
        "inventory_rev": None,
        "inventory_rev_date": None,
        "totals": {
            "expiring": 1,
            "expired": 1,
            "new_mismatches": 1,
            "unknown_certificates": 1,
            "stale_servers": 1,
            "failed_jobs": 1,
            "rolled_back_hosts": 1,
            "failed_notifications": 1,
        },
    }
    return DigestData(**{**values, **changes})


def empty(now):
    return build(
        now,
        expiring=[],
        expired=[],
        new_mismatches=[],
        mismatch_count=0,
        unknown_certificates=[],
        stale_servers=[],
        failed_jobs=[],
        rolled_back_hosts=[],
        failed_notifications=[],
        totals=dict.fromkeys(build(now).totals, 0),
    )


def test_every_section_heading_is_listed_in_text_and_html(now):
    mail = render_digest(build(now), "UTC", "https://certs.example.test/")
    for heading in HEADINGS:
        assert heading in mail.text and heading in mail.html
    assert mail.subject == "Cert Dashboard daily digest - 2026-10-19"
    assert "Current mismatches: 4" in mail.text
    assert "https://certs.example.test/certificates/1" in mail.text
    assert "Nothing to report" not in mail.text


def test_empty_digest_says_nothing_to_report_and_no_revision(now):
    mail = render_digest(empty(now), "UTC", None)
    assert "Nothing to report" in mail.text and "Nothing to report" in mail.html
    assert "Inventory revision: none recorded" in mail.text
    assert not any(heading in mail.text for heading in HEADINGS)


def test_inventory_revision_and_age_are_shown_once_recorded(now):
    data = build(now, inventory_rev="abc1234", inventory_rev_date=now - timedelta(days=2, hours=3))
    assert "Inventory revision: abc1234 (2 days old)" in render_digest(data, "UTC", None).text


def test_capped_lists_say_how_many_are_shown(now):
    data = build(now, totals={**build(now).totals, "unknown_certificates": 55})
    mail = render_digest(data, "UTC", None)
    assert "showing 1 of 55" in mail.text
    full = build(now, unknown_certificates=data.unknown_certificates * 50, totals={**data.totals, "unknown_certificates": 55})
    assert "showing 50 of 55" in render_digest(full, "UTC", None).text


def test_html_escapes_hostnames_and_common_names(now):
    evil = "<script>alert(1)</script>.example.test"
    data = build(
        now,
        expiring=[DigestCertificate(1, evil, now + timedelta(days=1), 1, "<b>Ops</b>")],
        new_mismatches=[DigestEndpoint(5, evil, 443, None, evil, evil, None, None, "mismatch", now)],
    )
    mail = render_digest(data, "UTC", None)
    assert "<script>" not in mail.html and "&lt;script&gt;" in mail.html and "<b>Ops</b>" not in mail.html
    assert evil in mail.text  # the text part is not HTML


def test_times_show_the_display_zone_and_utc(now):
    rome = render_digest(build(now), "Europe/Rome", None)
    assert "2026-10-19 14:00 CEST (2026-10-19 12:00 UTC)" in rome.text
    assert "(2026-10-19 12:00 UTC)" not in render_digest(build(now), "UTC", None).text
    assert "2026-10-19 12:00 UTC" in render_digest(build(now), "No/Such_Zone", None).text


def test_rollback_failures_are_flagged_for_manual_attention(now):
    clean = build(now, rolled_back_hosts=[DigestHost("job-2", "web03", True, None, now)])
    assert "needs manual attention" not in render_digest(clean, "UTC", None).text
    flagged = render_digest(build(now), "UTC", None)
    assert "needs manual attention" in flagged.text and "needs manual attention" in flagged.html


@pytest.mark.parametrize("make", [build, empty])
def test_result_counts_pass_the_redactor_unchanged(now, make):
    counts = digest_counts(make(now))
    assert set(counts) == {
        "expiring",
        "expired",
        "new_mismatches",
        "mismatches",
        "unknown_certificates",
        "stale_servers",
        "failed_jobs",
        "rolled_back_hosts",
        "failed_notifications",
    }
    assert redact(counts) == counts
