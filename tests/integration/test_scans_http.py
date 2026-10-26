"""Plan 2 Task 12: the Scan results screen (real Postgres, real HTTP stack)."""

import re
from datetime import timedelta

from sqlalchemy import select

from app.jobs.worker import JobRegistry
from app.models import Endpoint, Job, ScanResult
from app.models.enums import EndpointSource, JobType, ScanStatus
from app.services.endpoints import ENDPOINT_EXPORT_FIELDS
from tests.integration.conftest import add_endpoint, add_results

HOSTILE = '<script>alert("x")</script>'


def _post(client, path, token=True, **fields):
    data = {"csrf_token": client.fixture_csrf, **fields} if token else fields
    return client.post(path, data=data, follow_redirects=False)


def _hosts(html):
    return re.findall(r'data-host="([^"]+)"', html)


def test_scans_list_filters_paginates_and_exports_allowlisted_fields(signed_in, scan_world):
    page = signed_in.get(
        f"/scans?status=mismatch&server_id={scan_world.server_id}&sort=host&page=1&page_size=10"
    )
    assert page.status_code == 200
    assert scan_world.mismatch_host in page.text and scan_world.ok_host not in page.text
    exported = signed_in.get("/scans/export.json?status=mismatch").json()
    assert exported and all(set(row) == set(ENDPOINT_EXPORT_FIELDS) for row in exported)
    assert all(row["status"] == "mismatch" for row in exported)
    first = signed_in.get(f"/scans?search={scan_world.token}&sort=host&page_size=3")
    second = signed_in.get(f"/scans?search={scan_world.token}&sort=host&page_size=3&page=2")
    assert len(_hosts(first.text)) == 3 and len(_hosts(second.text)) == 3  # 6 active of 7 endpoints
    assert not set(_hosts(first.text)) & set(_hosts(second.text))
    assert 'rel="next"' in first.text and "page=2" in first.text


def test_history_shows_the_last_twenty_results_and_explains_a_mismatch(signed_in, scan_world):
    drawer = signed_in.get(f"/scans/{scan_world.mismatch_id}/history", headers={"HX-Request": "true"})
    assert drawer.text.count('class="scan-history-row"') == 20
    assert "<html" not in drawer.text
    detail = signed_in.get(f"/scans/{scan_world.mismatch_id}").text
    assert scan_world.expected_fingerprint in detail and scan_world.served_fingerprint in detail
    assert "Renew and deploy" in detail and "update the expectation" in detail
    assert f'href="/certificates/{scan_world.served_certificate_id}"' in detail  # served cert is in inventory
    assert f'href="/certificates/{scan_world.expected_certificate_id}"' in detail
    assert f"/certificates/import?host={scan_world.mismatch_host}&amp;port=443" not in detail  # already in inventory
    ok = signed_in.get(f"/scans/{scan_world.ok_id}").text
    assert "Renew and deploy" not in ok and scan_world.ok_sni in ok


def test_history_without_htmx_falls_back_to_the_detail_page(signed_in, scan_world):
    response = signed_in.get(f"/scans/{scan_world.mismatch_id}/history", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/scans/{scan_world.mismatch_id}#history"
    assert signed_in.get("/scans/999999999").status_code == 404
    assert signed_in.get("/scans/999999999/history", headers={"HX-Request": "true"}).status_code == 404


def test_every_filter_and_sort_is_whitelisted(signed_in, scan_world):
    world, token, hosts = scan_world, scan_world.token, scan_world.hosts

    def listed(query):
        response = signed_in.get(f"/scans?search={token}&{query}")
        assert response.status_code == 200, query
        return _hosts(response.text)

    active = set(hosts.values()) - {hosts["off"]}
    assert listed("status=unreachable") == [hosts["down"]]
    assert listed("status=error") == [hosts["broken"]] and listed("status=expired") == [hosts["expired"]]
    assert set(listed(f"certificate_id={world.expected_certificate_id}")) == {
        hosts[name] for name in ("mismatch", "expired", "down", "broken")
    }
    assert set(listed(f"server_id={world.server_id}&group={world.group}")) == set(listed("")) == active
    assert listed("group=no-such-group") == []
    assert listed("active=false") == [hosts["off"]] and set(listed("active=all")) == set(hosts.values())
    assert signed_in.get(f"/scans?search={world.ok_sni}").text.count("data-host=") == 1  # SNI search
    assert listed("sort=-host") == sorted(active, reverse=True)
    for sort in ("host", "port", "server", "checked_at", "-checked_at", "expected", "status"):
        assert signed_in.get(f"/scans?sort={sort}").status_code == 200, sort
    for bad in (
        "sort=password",
        "sort=host;drop",
        "status=bogus",
        "page_size=0",
        "page_size=101",
        "page=0",
        "server_id=abc",
        "certificate_id=-1",
        "active=maybe",
    ):
        assert signed_in.get(f"/scans?{bad}").status_code == 422, bad
        assert signed_in.get(f"/scans/export.json?{bad}").status_code == 422, bad


def test_default_sort_puts_problems_first_then_never_scanned_then_ok(signed_in, scan_world):
    hosts = scan_world.hosts
    order = _hosts(signed_in.get(f"/scans?search={scan_world.token}").text)
    assert order == [hosts[name] for name in ("expired", "mismatch", "down", "broken", "never", "ok")]


def test_list_query_count_is_independent_of_rows(signed_in, web_factory, count_statements, now):
    def seed(prefix, count):
        with web_factory.begin() as db:
            for number in range(count):
                endpoint_id = add_endpoint(db, f"{prefix}-{number}.example.test")
                add_results(db, endpoint_id, [(now, "mismatch"), (now - timedelta(hours=1), "ok")])

    def statements(prefix):
        with count_statements() as counter:
            response = signed_in.get(f"/scans?search={prefix}&page_size=100")
        assert response.status_code == 200
        return counter.count, response.text.count("data-host=")

    seed("few", 5)
    seed("many", 50)
    assert signed_in.get("/scans").status_code == 200  # warm the per-app worker-liveness cache
    (few_count, few_rows), (many_count, many_rows) = statements("few"), statements("many")
    assert (few_rows, many_rows) == (5, 50)
    assert few_count == many_count


def test_scan_now_and_scan_all_enqueue_without_connecting(signed_in, scan_world, web_factory):
    def queued():
        with web_factory() as db:
            return list(db.scalars(select(Job).where(Job.type == JobType.SCAN).order_by(Job.created_at)))

    before = len(queued())
    one = _post(signed_in, "/scans/run", scope="endpoint", endpoint_id=str(scan_world.ok_id))
    assert one.status_code == 303 and one.headers["location"] == f"/scans/{scan_world.ok_id}"
    everything = _post(signed_in, "/scans/run", scope="all")
    assert everything.status_code == 303 and everything.headers["location"] == "/scans"
    jobs = queued()[before:]
    assert [job.payload for job in jobs] == [{"endpoint_ids": [scan_world.ok_id]}, {}]
    assert {job.priority for job in jobs} == {200} and all(job.requested_by is not None for job in jobs)
    assert _post(signed_in, "/scans/run", token=False, scope="all").status_code == 403
    assert _post(signed_in, "/scans/run", scope="endpoint", endpoint_id="999999999").status_code == 404
    for bad in ({"scope": "everything"}, {"scope": "endpoint"}, {"scope": "endpoint", "endpoint_id": "x"}):
        assert _post(signed_in, "/scans/run", **bad).status_code == 422, bad
    inactive = _post(signed_in, "/scans/run", scope="endpoint", endpoint_id=str(scan_world.ids["off"]))
    assert inactive.status_code == 422
    assert len(queued()) == before + 2
    assert "Scan all" in signed_in.get("/scans").text
    assert "Scan now" in signed_in.get(f"/scans/{scan_world.ok_id}").text


def test_scans_navigation_is_enabled_when_the_handler_is_registered(signed_in, web_settings, monkeypatch):
    assert '<a href="/scans">Scans</a>' in signed_in.get("/").text
    monkeypatch.setattr("app.jobs.handlers.build_registry", JobRegistry)
    from app.main import create_app

    scans = next(item for item in create_app(web_settings).state.navigation if item["label"] == "Scans")
    assert scans["enabled"] is False and scans["reason"] == "handler scan/default not registered (Plan 2)"


def test_unreachable_and_error_rows_show_the_sanitized_error(signed_in, scan_world, web_factory):
    hosts = scan_world.hosts
    page = signed_in.get(f"/scans?search={scan_world.token}").text
    assert f"{hosts['down']}:443 unreachable: refused" in page
    with web_factory.begin() as db:
        newest = db.scalars(select(ScanResult).where(ScanResult.endpoint_id == scan_world.ids["broken"])).one()
        newest.error = f"{HOSTILE} handshake failed"
    broken = signed_in.get(f"/scans/{scan_world.ids['broken']}").text
    assert "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; handshake failed" in broken and HOSTILE not in broken
    assert scan_world.served_fingerprint not in broken  # nothing was observed


def test_pages_escape_hostile_values_and_require_sign_in(signed_in, client, web_factory, now):
    with web_factory.begin() as db:
        endpoint = Endpoint(host=f"h{HOSTILE}", port=443, sni=f"s{HOSTILE}", source=EndpointSource.MANUAL)
        db.add(endpoint)
        db.flush()
        db.add(
            ScanResult(
                endpoint_id=endpoint.id,
                status=ScanStatus.MISMATCH,
                observed_fingerprint="a" * 64,
                observed_common_name=f"cn{HOSTILE}",
                observed_issuer_cn=f"issuer{HOSTILE}",
                source="manual",
                checked_at=now,
            )
        )
        endpoint_id = endpoint.id
    pages = [signed_in.get(url).text for url in ("/scans?search=script", f"/scans/{endpoint_id}")]
    pages.append(signed_in.get(f"/scans/{endpoint_id}/history", headers={"HX-Request": "true"}).text)
    for page in pages:
        assert HOSTILE not in page and "&lt;script&gt;" in page
    client.cookies.clear()
    for url in ("/scans", "/scans/1", "/scans/1/history", "/scans/export.json"):
        response = client.get(url, follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"] == "/login", url
    assert client.post("/scans/run", data={"scope": "all"}, follow_redirects=False).status_code == 403


def test_import_page_is_prefilled_from_the_mismatch_link(signed_in):
    page = signed_in.get("/certificates/import?host=db.example.test&port=8443&sni=www.example.test").text
    for field, value in (("pull_host", "db.example.test"), ("pull_port", "8443"), ("pull_sni", "www.example.test")):
        assert re.search(rf'id="{field}"[^>]*value="{re.escape(value)}"', page), field
