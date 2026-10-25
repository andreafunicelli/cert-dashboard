"""Task 21: read-only audit browser and metadata-only JSON export (real Postgres, real HTTP stack)."""

import re
import uuid
from datetime import UTC, datetime, timedelta
from html import unescape
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.models import AuditLog
from app.services.audit import Actor, AuditFilters, list_audit, record

EXPORT_KEYS = {
    "id",
    "created_at",
    "actor_label",
    "actor_user_id",
    "action",
    "target_type",
    "target_id",
    "details",
    "ip",
    "user_agent",
}
BASE = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)


def _stage(db, label, action, target_type, target_id, created_at, *, ip=None, agent="fixture-browser", **details):
    row = record(db, Actor(None, label, ip, agent), action, target_type, target_id, details)
    row.created_at = created_at
    return row


@pytest.fixture
def csrf(signed_in):
    """The signed-in session's token (the pre-auth login token would be refused for an authenticated session)."""
    return signed_in.fixture_csrf


@pytest.fixture
def audited_changes(web_factory):
    """Rows with a per-test unique actor / target type so module-shared databases stay unambiguous."""
    tag = uuid.uuid4().hex[:8]
    alice, bob = f"alice-{tag}", f"Bob-{tag}"
    kind = f"kind{tag}"
    with web_factory.begin() as db:
        rows = [
            _stage(db, alice, "certificate.import", kind, "42", BASE, ip="192.0.2.10", agent="agent-one", cn="a.example.test"),
            _stage(db, alice, "certificate.update", kind, "42", BASE + timedelta(hours=1), ip="192.0.2.11"),
            _stage(db, bob, "key.export", kind, "7", BASE + timedelta(hours=2), ip="198.51.100.5"),
            _stage(db, bob, "certificate.import", kind, "420", BASE + timedelta(hours=3), ip="2001:db8::1"),
            _stage(db, "worker:fixture", "job.finished", kind, None, BASE + timedelta(hours=4)),
        ]
        db.flush()
        ids = [row.id for row in rows]
    return SimpleNamespace(tag=tag, alice=alice, bob=bob, kind=kind, ids=[str(item) for item in ids])


def _export(client, **params):
    response = client.get("/audit/export.json", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def _page_actions(client, **params):
    response = client.get("/audit", params=params)
    assert response.status_code == 200, response.text
    return response


def test_audit_is_filterable_and_read_only(signed_in, audited_changes, csrf):
    page = signed_in.get("/audit?action_prefix=certificate.&target_id=42")
    assert page.status_code == 200 and "certificate.import" in page.text
    assert "key.export" not in page.text
    exported = signed_in.get("/audit/export.json?target_id=42").json()
    assert all(row["target_id"] == "42" for row in exported)
    assert signed_in.post("/audit/delete", data={"csrf_token": csrf}).status_code in (404, 405)


def test_actor_filter_is_case_insensitive_exact(signed_in, audited_changes):
    rows = _export(signed_in, actor=audited_changes.bob.upper())
    assert {row["actor_label"] for row in rows} == {audited_changes.bob}
    assert _export(signed_in, actor=audited_changes.bob[:-1]) == []


def test_action_prefix_escapes_like_wildcards(signed_in, audited_changes):
    assert {row["action"] for row in _export(signed_in, target_type=audited_changes.kind, action_prefix="certificate.")} == {
        "certificate.import",
        "certificate.update",
    }
    for wildcard in ("%", "_", "certificate_", "cert%", "\\"):
        assert _export(signed_in, target_type=audited_changes.kind, action_prefix=wildcard) == []
    assert _export(signed_in, target_type=audited_changes.kind, action_prefix="job.")[0]["target_id"] is None


def test_target_type_and_id_are_exact(signed_in, audited_changes):
    rows = _export(signed_in, target_type=audited_changes.kind, target_id="42")
    assert [row["action"] for row in rows] == ["certificate.update", "certificate.import"]
    assert _export(signed_in, target_type=audited_changes.kind.upper()) == []
    assert len(_export(signed_in, target_type=audited_changes.kind)) == 5


def test_date_range_start_inclusive_end_exclusive(signed_in, audited_changes):
    kind = audited_changes.kind
    start, end = BASE + timedelta(hours=1), BASE + timedelta(hours=3)
    rows = _export(signed_in, target_type=kind, start=start.isoformat(), end=end.isoformat())
    assert [row["action"] for row in rows] == ["key.export", "certificate.update"]
    assert [row["created_at"] for row in rows] == ["2026-03-01T14:00:00Z", "2026-03-01T13:00:00Z"]


def test_dates_accept_day_naive_zone_aware_and_z_forms(signed_in, audited_changes):
    kind = audited_changes.kind
    assert len(_export(signed_in, target_type=kind, start="2026-03-01", end="2026-03-02")) == 5
    assert _export(signed_in, target_type=kind, end="2026-03-01") == []
    assert len(_export(signed_in, target_type=kind, start="2026-03-01T16:00:00")) == 1  # naive means UTC
    assert len(_export(signed_in, target_type=kind, start="2026-03-01T16:00:00Z")) == 1
    assert len(_export(signed_in, target_type=kind, start="2026-03-01T17:00:00+01:00")) == 1
    assert len(_export(signed_in, target_type=kind, start="2026-03-01T17:00:01+01:00")) == 0


@pytest.mark.parametrize("name,value", [("start", "yesterday"), ("end", "2026-13-40"), ("start", "x" * 80)])
def test_invalid_dates_are_refused(signed_in, name, value):
    assert signed_in.get("/audit", params={name: value}).status_code == 422
    assert signed_in.get("/audit/export.json", params={name: value}).status_code == 422


def test_ip_filter_exact_address_and_cidr(signed_in, audited_changes):
    kind = audited_changes.kind
    exact = _export(signed_in, target_type=kind, ip="192.0.2.10")
    assert [row["ip"] for row in exact] == ["192.0.2.10"]
    assert sorted(row["ip"] for row in _export(signed_in, target_type=kind, ip="192.0.2.0/24")) == [
        "192.0.2.10",
        "192.0.2.11",
    ]
    assert [row["ip"] for row in _export(signed_in, target_type=kind, ip="2001:db8::/32")] == ["2001:db8::1"]
    assert [row["ip"] for row in _export(signed_in, target_type=kind, ip="2001:db8::1")] == ["2001:db8::1"]
    assert _export(signed_in, target_type=kind, ip="203.0.113.9") == []


@pytest.mark.parametrize("value", ["not-an-ip", "192.0.2.300", "192.0.2.0/33", "fe80::1%eth0", "192.0.2.1; DROP", "1.2.3.4/"])
def test_invalid_ip_is_refused(signed_in, value):
    assert signed_in.get("/audit", params={"ip": value}).status_code == 422
    assert signed_in.get("/audit/export.json", params={"ip": value}).status_code == 422


def test_action_prefix_longer_than_100_is_refused(signed_in):
    assert signed_in.get("/audit", params={"action_prefix": "a" * 100}).status_code == 200
    assert signed_in.get("/audit", params={"action_prefix": "a" * 101}).status_code == 422


def test_filter_values_are_bound_parameters(signed_in, audited_changes):
    payload = "' OR '1'='1"
    for name in ("actor", "action_prefix", "target_type", "target_id"):
        assert _export(signed_in, **{name: payload}) == []
    assert signed_in.get("/audit").status_code == 200  # nothing was dropped or altered


def test_blank_filters_mean_no_filter(signed_in, audited_changes):
    page = signed_in.get(
        "/audit?actor=&action_prefix=&target_type=&target_id=&start=&end=&ip=&page=&page_size="
    )
    assert page.status_code == 200
    assert len(_export(signed_in, actor="", target_type=audited_changes.kind)) == 5


def test_newest_first_with_id_tie_break(web_factory, signed_in):
    tag = uuid.uuid4().hex[:8]
    with web_factory.begin() as db:
        rows = [_stage(db, f"tie-{tag}", "tie.row", f"tie{tag}", str(n), BASE) for n in range(4)]
        rows.append(_stage(db, f"tie-{tag}", "tie.row", f"tie{tag}", "newest", BASE + timedelta(seconds=1)))
        db.flush()
        expected_ties = sorted((str(row.id) for row in rows[:4]), reverse=True)
    exported = _export(signed_in, actor=f"tie-{tag}")
    assert exported[0]["target_id"] == "newest"
    assert [row["id"] for row in exported[1:]] == expected_ties


def test_pagination_bounds_and_links_preserve_filters(web_factory, signed_in):
    tag = uuid.uuid4().hex[:8]
    with web_factory.begin() as db:
        for n in range(5):
            _stage(db, f"page-{tag}", "page.row", f"page{tag}", str(n), BASE + timedelta(minutes=n))
    first = _page_actions(signed_in, actor=f"page-{tag}", page_size=2)
    assert first.text.count('data-audit-row') == 2
    assert "Page 1 of 3" in first.text and 'rel="prev"' not in first.text
    next_link = re.search(r'rel="next" href="([^"]+)"', first.text).group(1).replace("&amp;", "&")
    assert f"actor=page-{tag}" in next_link and "page=2" in next_link and "page_size=2" in next_link
    last = signed_in.get(next_link.replace("page=2", "page=3"))
    assert last.text.count("data-audit-row") == 1 and 'rel="next"' not in last.text and 'rel="prev"' in last.text
    assert _page_actions(signed_in, actor=f"page-{tag}", page=99).text.count("data-audit-row") == 0
    for params in ({"page": 0}, {"page": -1}, {"page": "x"}, {"page_size": 0}, {"page_size": 101}, {"page_size": "x"}):
        assert signed_in.get("/audit", params=params).status_code == 422
    assert _page_actions(signed_in, actor=f"page-{tag}", page_size=100).status_code == 200


def test_list_audit_service_counts_and_slices(web_factory, audited_changes):
    with web_factory() as db:
        rows, total = list_audit(db, AuditFilters(target_type=audited_changes.kind), page=2, page_size=2)
    assert total == 5
    assert [row.action for row in rows] == ["key.export", "certificate.update"]


def test_service_rejects_invalid_filters():
    with pytest.raises(ValueError):
        AuditFilters(ip="nonsense")
    with pytest.raises(ValueError):
        AuditFilters(action_prefix="a" * 101)


def test_html_escapes_details_ip_and_user_agent(web_factory, signed_in):
    tag = uuid.uuid4().hex[:8]
    with web_factory.begin() as db:
        _stage(
            db,
            f"<b>actor</b>-{tag}",
            "xss.test",
            f"<i>type</i>{tag}",
            "<img src=x onerror=alert(1)>",
            BASE,
            ip="192.0.2.77",
            agent="<script>alert('ua')</script>",
            note="<script>alert('details')</script>",
        )
    html = signed_in.get("/audit", params={"ip": "192.0.2.77"}).text
    for raw in ("<script>alert", "<img src=x", "<b>actor", "<i>type"):
        assert raw not in html
    assert "&lt;script&gt;alert(&#39;ua&#39;)&lt;/script&gt;" in html
    assert "&lt;script&gt;alert(&#39;details&#39;)&lt;/script&gt;" in html
    assert "192.0.2.77" in html


def test_rows_expand_with_details_ip_and_agent_without_javascript(signed_in, audited_changes):
    html = _page_actions(signed_in, actor=audited_changes.alice, action_prefix="certificate.import").text
    row = html[html.index("data-audit-row") :]
    assert "<details" in row and "<summary" in row
    assert '"cn": "a.example.test"' in unescape(row)  # pretty-printed details JSON
    assert "agent-one" in row and "192.0.2.10" in row
    assert re.search(r'<time datetime="2026-03-01T12:00:00Z">', html)


def test_export_is_allowlisted_newest_first_attachment(signed_in, audited_changes):
    response = signed_in.get("/audit/export.json", params={"target_type": audited_changes.kind})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"] == 'attachment; filename="audit.json"'
    assert response.headers["cache-control"] == "no-store"
    rows = response.json()
    assert isinstance(rows, list) and len(rows) == 5
    assert all(set(row) == EXPORT_KEYS for row in rows)
    assert [row["id"] for row in rows] == list(reversed(audited_changes.ids))
    first = rows[-1]
    assert first["created_at"] == "2026-03-01T12:00:00Z" and first["details"] == {"cn": "a.example.test"}
    assert first["actor_user_id"] is None and first["user_agent"] == "agent-one"
    assert rows[0]["ip"] is None and rows[0]["target_id"] is None


def test_export_is_capped_at_5000_rows_and_flags_truncation(web_factory, signed_in):
    tag = uuid.uuid4().hex[:8]
    with web_factory.begin() as db:
        db.execute(
            AuditLog.__table__.insert(),
            [
                {
                    "actor_label": f"bulk-{tag}",
                    "action": "bulk.row",
                    "target_type": f"bulk{tag}",
                    "target_id": str(n),
                    "details": {},
                    "created_at": BASE + timedelta(seconds=n),
                }
                for n in range(5003)
            ],
        )
    response = signed_in.get("/audit/export.json", params={"actor": f"bulk-{tag}"})
    rows = response.json()
    assert len(rows) == 5000 and rows[0]["target_id"] == "5002" and rows[-1]["target_id"] == "3"
    assert response.headers["x-total-count"] == "5003" and response.headers["x-truncated"] == "true"
    small = signed_in.get("/audit/export.json", params={"actor": f"bulk-{tag}", "target_id": "3"})
    assert small.headers["x-total-count"] == "1" and small.headers["x-truncated"] == "false"


def test_reading_and_exporting_do_not_write_audit_rows(web_factory, signed_in, audited_changes):
    def count():
        with web_factory() as db:
            return db.scalar(select(func.count()).select_from(AuditLog))

    before = count()
    signed_in.get("/audit")
    signed_in.get("/audit/export.json")
    assert count() == before


@pytest.mark.parametrize("path", ["/audit", "/audit/export.json"])
def test_unauthenticated_requests_are_denied(client, path):
    redirected = client.get(path, follow_redirects=False)
    assert redirected.status_code in (303, 401)
    if redirected.status_code == 303:
        assert redirected.headers["location"] == "/login"
    assert client.get(path, headers={"Accept": "application/json"}).status_code == 401


def test_html_has_no_csv_edit_delete_or_purge_controls(signed_in, audited_changes):
    html = _page_actions(signed_in, target_type=audited_changes.kind).text.lower()
    assert 'method="post"' not in html and "<button" in html  # only the GET filter form's submit
    for word in ("csv", "delete", "purge", "remove", "truncate"):
        assert not re.search(rf"\b{word}", html), word
    assert not re.search(r"\bedit\b", html)
    assert "/export.json" in html and "audit.csv" not in html


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
@pytest.mark.parametrize(
    "path", ["/audit", "/audit/export.json", "/audit/delete", "/audit/purge", "/audit/export.csv", f"/audit/{uuid.uuid4()}"]
)
def test_mutation_methods_are_rejected_even_with_valid_csrf(signed_in, csrf, audited_changes, path, method):
    response = getattr(signed_in, method)(path, headers={"X-CSRF-Token": csrf})
    assert response.status_code in (404, 405)


def test_csv_export_route_does_not_exist(signed_in):
    assert signed_in.get("/audit/export.csv").status_code == 404
    assert signed_in.get("/audit/export").status_code == 404


def test_audit_nav_item_is_enabled(signed_in):
    html = signed_in.get("/audit").text
    assert re.search(r'<a href="/audit">Audit</a>', html)
    assert 'aria-disabled="true" title="Available in a later implementation task">Audit' not in html


def test_audit_rows_stay_unchanged_after_browsing(web_factory, signed_in, audited_changes):
    signed_in.get("/audit", params={"target_type": audited_changes.kind})
    with web_factory() as db:
        rows = db.scalars(select(AuditLog).where(AuditLog.target_type == audited_changes.kind)).all()
    assert len(rows) == 5 and {str(row.id) for row in rows} == set(audited_changes.ids)
