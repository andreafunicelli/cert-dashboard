"""Plan 2 Task 9: digest sections are decided against the state at the last digest (real PostgreSQL)."""

import itertools
from datetime import timedelta

from sqlalchemy import select

from app.jobs.queue import SYSTEM_ACTOR
from app.models import AuditLog, Certificate, Job, JobHost, NotificationLog
from app.models.enums import CertificateStatus, JobStatus, JobType, NotificationStatus
from app.services.bindings import BINDING_STATE_ACTION, BindingState, audit_binding_state, binding_state
from app.services.digest import (
    DIGEST_LIST_LIMIT,
    collect_digest,
    digest_dedupe_key,
    digest_since,
    new_mismatches,
    new_unknown_bindings,
)
from tests.integration.conftest import add_binding, add_endpoint, add_results, add_server, reconcile

_counter = itertools.count(1)


def add_cert(db, now, days, *, cn, **overrides):
    n = next(_counter)
    values = {
        "common_name": cn,
        "subject_dn": f"CN={cn}",
        "sans": [cn],
        "issuer_dn": "CN=Fixture CA,O=Example",
        "issuer_cn": "Fixture CA",
        "serial": f"{n:040x}",
        "not_before": now - timedelta(days=300),
        "not_after": now + timedelta(days=days),
        "sha256_fingerprint": f"{n:064x}",
        "pem": "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
        "imported_from": "upload_pem",
    }
    cert = Certificate(**{**values, **overrides})
    db.add(cert)
    db.flush()
    return cert


def test_new_mismatch_predecessor_is_computed_across_the_cutoff(db, now):
    since = now - timedelta(hours=24)
    before, after = since - timedelta(hours=1), since + timedelta(hours=1)
    repeat, flipped, first, blip, healed = (
        add_endpoint(db, f"{name}.example.internal") for name in ("repeat", "flipped", "first", "blip", "healed")
    )
    add_results(db, repeat, [(before, "mismatch"), (after, "mismatch")])  # mismatch across cutoff: repeat
    add_results(db, flipped, [(before, "ok"), (after, "mismatch")])  # ok -> mismatch across cutoff: new
    add_results(db, first, [(after, "mismatch")])  # first observation: new
    add_results(db, blip, [(before - timedelta(hours=1), "mismatch"), (before, "unreachable"), (after, "mismatch")])
    add_results(db, healed, [(before, "ok"), (after, "mismatch"), (after + timedelta(hours=1), "ok")])
    items, total = new_mismatches(db, since)
    assert {item.id: item.previous_status for item in items} == {flipped: "ok", first: None, healed: "ok"}
    assert total == 3 and {item.id: item.current_status for item in items}[healed] == "ok"
    assert collect_digest(db, now).mismatch_count == 4  # repeat, flipped, first, blip are mismatching now


def test_new_mismatch_reports_the_transition_and_skips_inactive_endpoints(db, now):
    since = now - timedelta(hours=24)
    expected = add_cert(db, now, 90, cn="expected.example.test")
    run = add_endpoint(db, "run.example.internal", expected_certificate_id=expected.id)
    off = add_endpoint(db, "off.example.internal", is_active=False)
    first, second = since - timedelta(hours=1), since + timedelta(hours=1)
    add_results(db, run, [(first, "ok"), (second, "mismatch"), (second + timedelta(hours=1), "mismatch")])
    add_results(db, off, [(second, "mismatch")])
    items, total = new_mismatches(db, since)
    assert total == 1 and [item.id for item in items] == [run]
    assert items[0].previous_status == "ok" and items[0].checked_at == second  # the transition, not the repeat
    assert items[0].expected_common_name == "expected.example.test"
    assert (items[0].host, items[0].port, items[0].current_status) == ("run.example.internal", 443, "mismatch")
    assert collect_digest(db, now).mismatch_count == 1


def test_unknown_certificates_follow_binding_transitions_across_the_cutoff(db, now):
    since = now - timedelta(hours=24)
    long_ago, after = since - timedelta(days=10), since + timedelta(hours=1)
    server = add_server(db, "web01.example.internal")
    old_matched = add_binding(db, server, "a.example.internal", match_state="matched", fingerprint="a" * 64, at=long_ago)
    old_unknown = add_binding(db, server, "b.example.internal", match_state="unknown", fingerprint="b" * 64, at=long_ago)
    swapped = add_binding(db, server, "c.example.internal", match_state="unknown", fingerprint="c" * 64, at=long_ago)
    reconcile(db, old_matched, match_state="unknown", fingerprint="d" * 64, at=after)  # matched -> unknown: new
    assert reconcile(db, old_unknown, match_state="unknown", fingerprint="b" * 64, at=after) is None  # repeat
    reconcile(db, swapped, match_state="unknown", fingerprint="e" * 64, at=after)  # another unknown cert: new
    fresh = add_binding(db, server, "f.example.internal", match_state="unknown", fingerprint="f" * 64, at=after)
    items, total = new_unknown_bindings(db, since)
    assert {item.binding_id: item.previous_state for item in items} == {
        old_matched.id: "matched",
        swapped.id: "unknown",
        fresh.id: None,
    }
    assert total == 3 and all(item.found_at == after for item in items)
    assert old_matched.created_at < since  # creation time alone would have hidden it


def test_unknown_round_trips_inside_the_window_are_not_new(db, now):
    since = now - timedelta(hours=24)
    long_ago, before, after = since - timedelta(days=10), since - timedelta(hours=1), since + timedelta(hours=1)
    later = after + timedelta(hours=1)
    server = add_server(db, "web02.example.internal")
    flapping = add_binding(db, server, "a.example.internal", match_state="unknown", fingerprint="a" * 64, at=long_ago)
    reconcile(db, flapping, match_state="missing_file", fingerprint=None, at=after)
    reconcile(db, flapping, match_state="unknown", fingerprint="a" * 64, at=later)  # same certificate again
    healed = add_binding(db, server, "b.example.internal", match_state="matched", fingerprint="b" * 64, at=long_ago)
    reconcile(db, healed, match_state="unknown", fingerprint="c" * 64, at=after)
    reconcile(db, healed, match_state="matched", fingerprint="b" * 64, at=later)  # matched again before the digest
    revived = add_binding(db, server, "c.example.internal", match_state="unknown", fingerprint="d" * 64, at=long_ago)
    reconcile(db, revived, is_active=False, at=before)
    reconcile(db, revived, is_active=True, at=after)  # reactivated as unknown after the cutoff: new
    items, total = new_unknown_bindings(db, since)
    assert [(item.binding_id, item.previous_state, item.found_at) for item in items] == [
        (revived.id, "unknown", after)
    ]
    assert total == 1


def test_audit_binding_state_writes_only_on_change(db, now, actor):
    server = add_server(db, "web03.example.internal")
    binding = add_binding(db, server, "a.example.internal", match_state="matched", fingerprint="a" * 64, at=now)
    binding.notes = "password=fixture-secret"

    def rows():
        return db.scalars(
            select(AuditLog).where(AuditLog.action == BINDING_STATE_ACTION, AuditLog.target_id == str(binding.id))
        ).all()

    (inserted,) = rows()
    assert inserted.target_type == "binding" and inserted.created_at == now
    assert inserted.details == {
        "from_state": None,
        "from_fingerprint": None,
        "was_active": False,
        "to_state": "matched",
        "on_disk_fingerprint": "a" * 64,
        "is_active": True,
        "server_id": server.id,
        "job_id": None,
    }
    assert audit_binding_state(db, binding, binding_state(binding), SYSTEM_ACTOR, job_id=None, now=now) is None
    assert len(rows()) == 1
    deactivated = reconcile(db, binding, is_active=False, at=now + timedelta(hours=1))
    assert deactivated is not None and len(rows()) == 2
    assert deactivated.details["was_active"] is True and deactivated.details["is_active"] is False
    assert deactivated.details["from_state"] == deactivated.details["to_state"] == "matched"
    stamped = audit_binding_state(db, binding, BindingState("unknown", None, False), actor, job_id="job-1", now=now)
    db.flush()
    assert stamped is not None and stamped.created_at == now and stamped.actor_user_id == actor.user_id
    assert stamped.details["job_id"] == "job-1" and set(stamped.details) == set(inserted.details)
    assert "fixture-secret" not in repr([row.details for row in rows()])


def test_collect_digest_reports_the_seeded_world(db, now):
    hour, day = timedelta(hours=1), timedelta(hours=24)
    add_cert(db, now, 3, cn="soon.example.test", owner_name="Ada")
    add_cert(db, now, -2, cn="gone.example.test")
    add_cert(db, now, 3, cn="old.example.test", status=CertificateStatus.SUPERSEDED)
    add_cert(db, now, -2, cn="revoked.example.test", status=CertificateStatus.REVOKED)
    add_cert(db, now, 30, cn="later.example.test")
    add_server(db, "failed.example.internal", last_discovery_status="failed", last_discovery_at=now - hour)
    add_server(db, "old.example.internal", last_discovery_status="ok", last_discovery_at=now - 49 * hour)
    add_server(db, "never.example.internal")
    add_server(db, "healthy.example.internal", last_discovery_status="ok", last_discovery_at=now - hour)
    add_server(db, "retired.example.internal", last_discovery_status="failed", is_active=False)

    def job(job_type, status, finished, **columns):
        row = Job(type=job_type, status=status, priority=100, payload={}, run_after=now, finished_at=finished, **columns)
        db.add(row)
        db.flush()
        return row

    failed = job(JobType.SCAN, JobStatus.FAILED, now - 2 * hour, error_class="transient_network")
    job(JobType.SCAN, JobStatus.FAILED, now - day - hour)  # too old
    job(JobType.SCAN, JobStatus.SUCCEEDED, now - hour)
    deploy = job(JobType.DEPLOY, JobStatus.SUCCEEDED, now - hour)
    stale_rev = job(
        JobType.DISCOVER,
        JobStatus.SUCCEEDED,
        now - 5 * hour,
        result={"inventory_rev": "0" * 40, "inventory_rev_date": "2026-10-10T08:00:00+00:00"},
    )
    newest = job(
        JobType.DISCOVER,
        JobStatus.SUCCEEDED,
        now - 3 * hour,
        result={"inventory_rev": "a" * 40, "inventory_rev_date": "2026-10-18T08:00:00+00:00"},
    )
    assert stale_rev.id != newest.id
    web = add_server(db, "web04.example.internal", last_discovery_status="ok", last_discovery_at=now - hour)
    for suffix, finished, columns in (
        ("rolled", now - hour, {"rolled_back": True}),
        ("stuck", now - 2 * hour, {"rollback_error": "restore failed"}),
        ("older", now - day - hour, {"rolled_back": True}),
        ("clean", now - hour, {}),
    ):
        host = add_server(db, f"{suffix}.host", last_discovery_status="ok", last_discovery_at=now - hour)
        db.add(JobHost(job_id=deploy.id, server_id=host.id, finished_at=finished, **columns))
    db.add(JobHost(job_id=failed.id, server_id=web.id, finished_at=now - hour))
    for key, status, attempts, last in (
        ("expiry:1:30:x", NotificationStatus.FAILED, 3, now - hour),
        ("expiry:2:30:x", NotificationStatus.FAILED, 1, now - day - hour),
        ("expiry:3:30:x", NotificationStatus.SENT, 1, now - hour),
        ("expiry:4:30:x", NotificationStatus.FAILED, 0, None),
    ):
        db.add(
            NotificationLog(
                kind="expiry", certificate_id=None, threshold_days=30, recipients=["a@example.test"], status=status,
                error="smtp_transient: 451 at rcpt" if attempts else None, dedupe_key=key, attempts=attempts,
                last_attempt_at=last,
            )
        )
    db.flush()

    data = collect_digest(db, now)

    assert (data.generated_at, data.since) == (now, now - day)
    assert [(c.common_name, c.days_remaining, c.owner) for c in data.expiring] == [("soon.example.test", 3, "Ada")]
    assert [(c.common_name, c.days_remaining) for c in data.expired] == [("gone.example.test", -2)]
    assert sorted(s.hostname for s in data.stale_servers) == [
        "failed.example.internal",
        "never.example.internal",
        "old.example.internal",
    ]
    assert [(j.id, j.type, j.error_class) for j in data.failed_jobs] == [(str(failed.id), "scan", "transient_network")]
    assert sorted((h.hostname, h.rolled_back, h.rollback_error) for h in data.rolled_back_hosts) == [
        ("rolled.host", True, None),
        ("stuck.host", False, "restore failed"),
    ]
    assert [(n.kind, n.attempts, n.error) for n in data.failed_notifications] == [
        ("expiry", 3, "smtp_transient: 451 at rcpt")
    ]
    assert (data.inventory_rev, data.inventory_rev_date.isoformat()) == ("a" * 40, "2026-10-18T08:00:00+00:00")
    assert data.new_mismatches == [] and data.unknown_certificates == [] and data.mismatch_count == 0
    assert data.totals == {
        "expiring": 1,
        "expired": 1,
        "new_mismatches": 0,
        "unknown_certificates": 0,
        "stale_servers": 3,
        "failed_jobs": 1,
        "rolled_back_hosts": 2,
        "failed_notifications": 1,
    }


def test_lists_are_capped_but_totals_are_not(db, now):
    since = now - timedelta(hours=24)
    for index in range(55):
        add_results(db, add_endpoint(db, f"bulk{index:02}.example.internal"), [(since + timedelta(minutes=index + 1), "mismatch")])
    data = collect_digest(db, now)
    assert DIGEST_LIST_LIMIT == 50
    assert len(data.new_mismatches) == 50 and data.totals["new_mismatches"] == 55 and data.mismatch_count == 55
    newest_first = [item.checked_at for item in data.new_mismatches]
    assert newest_first == sorted(newest_first, reverse=True)


def test_since_is_the_last_sent_digest_or_24_hours(db, now):
    assert digest_since(db, now) == now - timedelta(hours=24)
    assert digest_dedupe_key(now) == "digest:2026-10-19"

    def digest_row(key, status, sent_at):
        db.add(
            NotificationLog(
                kind="digest", certificate_id=None, threshold_days=None, recipients=["a@example.test"],
                status=status, dedupe_key=key, attempts=1, sent_at=sent_at,
            )
        )
        db.flush()

    digest_row("digest:2026-10-17", NotificationStatus.SENT, now - timedelta(days=2))
    digest_row("digest:2026-10-18", NotificationStatus.FAILED, None)
    assert digest_since(db, now) == now - timedelta(days=2)
    digest_row("digest:2026-10-19", NotificationStatus.SENT, now - timedelta(hours=5))
    assert digest_since(db, now) == now - timedelta(hours=5)
