"""Plan 2 Task 14: Servers list and server detail (real Postgres, real HTTP stack)."""

import re
from datetime import timedelta

from app.models import Job, JobHost, Server
from app.models.enums import JobHostStatus, JobStatus, JobType
from app.services.servers import SERVER_EXPORT_FIELDS
from tests.integration.conftest import add_server, set_setting

WEB01 = "web01.example.internal"
WEB02 = "web02.example.internal"
OLD01 = "old01.example.internal"


def _ids(html):
    return [int(value) for value in re.findall(r'data-server-id="(\d+)"', html)]


def test_servers_list_counts_and_filters_without_n_plus_one(signed_in, server_map, count_statements, web_factory):
    with web_factory.begin() as db:  # more rows than the small page shows
        for number in range(30):
            add_server(db, f"bulk{number}-{server_map.token}.example.internal", ansible_groups=[server_map.group])
    assert signed_in.get("/servers").status_code == 200  # warm the per-app worker-liveness cache
    with count_statements() as small:
        assert signed_in.get("/servers?page_size=5").status_code == 200
    with count_statements() as large:
        page = signed_in.get(f"/servers?group={server_map.group}&page_size=50")
    assert small.count == large.count and len(_ids(page.text)) > 30
    web01 = server_map.server(WEB01)
    assert f'data-server-id="{web01.id}"' in page.text
    assert f'data-server-id="{server_map.server("db01.example.internal").id}"' not in page.text  # other group
    rows = {row["id"]: row for row in signed_in.get(f"/servers/export.json?search={server_map.token}").json()}
    assert set(rows[web01.id]) == set(SERVER_EXPORT_FIELDS)
    counts = ("binding_count", "attention_count", "mismatch_count")
    assert tuple(rows[web01.id][name] for name in counts) == (
        3,
        2,
        1,
    )  # inactive binding/endpoint not counted
    web02 = rows[server_map.server(WEB02).id]
    assert tuple(web02[name] for name in counts) == (2, 0, 0)  # an expired endpoint is not a mismatch
    assert web02["last_discovery_status"] == "failed" and web02["groups"] == [server_map.group]
    assert all("notes" not in row for row in rows.values())


def test_servers_list_sorts_are_whitelisted_and_paged(signed_in, server_map):
    by_count = signed_in.get(f"/servers?group={server_map.group}&sort=-binding_count")
    assert _ids(by_count.text) == [server_map.server(WEB01).id, server_map.server(WEB02).id]
    by_mismatch = signed_in.get(f"/servers?search={server_map.token}&sort=-mismatch_count&page_size=1")
    assert _ids(by_mismatch.text) == [server_map.server(WEB01).id] and 'rel="next"' in by_mismatch.text
    for bad in ("sort=notes", "page_size=0", "page_size=101", "active=maybe", "page=0"):
        assert signed_in.get(f"/servers?{bad}").status_code == 422, bad
    assert signed_in.get("/servers/export.json?sort=notes").status_code == 422  # validated like the list


def test_inactive_servers_are_hidden_unless_requested(signed_in, server_map):
    old = server_map.server(OLD01).id
    assert old not in _ids(signed_in.get(f"/servers?search={server_map.token}").text)
    assert old in _ids(signed_in.get(f"/servers?search={server_map.token}&active=all").text)
    assert _ids(signed_in.get(f"/servers?search={server_map.token}&active=false").text) == [old]
    exported = signed_in.get(f"/servers/export.json?search={server_map.token}&active=false").json()
    assert [row["id"] for row in exported] == [old] and exported[0]["is_active"] is False


def test_server_detail_shows_paths_owners_modes_and_match_state(signed_in, server_map):
    web01 = server_map.server(WEB01)
    page = signed_in.get(f"/servers/{web01.id}")
    assert page.status_code == 200
    text, token = page.text, server_map.token
    for name in ("fullchain.pem", "chain.pem", "privkey.pem"):
        assert f"/etc/ssl/www-{token}.example.test/{name}" in text
    assert "root:ssl-cert 0644" in text and "root:ssl-cert 0640" in text and "root:ssl-cert 0600" in text
    assert server_map.certificate_fingerprint in text
    assert f'href="/certificates/{server_map.certificate_id}"' in text
    assert 'data-match-state="key_mismatch"' in text and 'data-match-state="missing_file"' in text
    assert text.count('class="binding-row') == 4  # three active bindings plus the retired one, marked
    assert "(inactive)" in text and "10.20.0.11" in text and "web01 note" in text
    assert 'href="/bindings/help"' in text  # fix instructions for key_mismatch / missing_file
    assert f"/scans?server_id={web01.id}" in text


def test_discovery_history_comes_from_discover_job_hosts(signed_in, server_map, web_factory, now):
    text = signed_in.get(f"/servers/{server_map.server(WEB01).id}").text
    runs = re.findall(r'<tr class="discovery-run" data-job-status="(\w+)"', text)
    assert runs == ["succeeded", "failed", "succeeded"]  # newest first; the deploy job_host is not history
    assert "1f3c9a7" in text and "0d4e5b2" in text and "1 min 35 s" in text
    assert "ssh: connect to host failed" in text and "fixture-leaked-secret" not in text  # sanitized
    with web_factory.begin() as db:  # 22 runs on a server without any: only the newest 20 are listed
        for index in range(22):
            started = now - timedelta(minutes=index)
            job = Job(
                type=JobType.DISCOVER,
                status=JobStatus.SUCCEEDED,
                priority=100,
                payload={},
                run_after=started,
                result={"inventory_rev": f"rev{index:02d}"},
            )
            db.add(job)
            db.flush()
            db.add(
                JobHost(
                    job_id=job.id,
                    server_id=server_map.server(WEB02).id,
                    status=JobHostStatus.SUCCEEDED,
                    started_at=started,
                    finished_at=started + timedelta(seconds=5),
                )
            )
    crowded = signed_in.get(f"/servers/{server_map.server(WEB02).id}").text
    assert re.findall(r"rev(\d\d)", crowded) == [f"{index:02d}" for index in range(20)]


def test_discovery_actions_are_enabled_now_that_the_handler_is_registered(signed_in, server_map, web_factory):
    set_setting(web_factory, "inventory.repo_url", "https://git.example.test/inventory.git")
    web01 = server_map.server(WEB01)
    text = signed_in.get(f"/servers/{web01.id}").text
    actions = text.split('id="actions"', 1)[1].split("</section>", 1)[0]
    assert "discover/default not registered" not in text
    assert f'<form class="inline" method="post" action="/servers/{web01.id}/discover">' in actions
    assert '<button type="submit">Run discovery</button>' in actions
    assert f'<a href="/servers/{web01.id}/dump">Last raw dump summary</a>' in actions  # Task 11
    assert f'<a href="/scans?server_id={web01.id}">Open endpoint scan</a>' in actions


def test_discovery_actions_are_disabled_with_the_reason_when_the_handler_is_missing(signed_in, server_map):
    from app.jobs.worker import JobRegistry

    signed_in.app.state.job_registry = JobRegistry()
    web01 = server_map.server(WEB01)
    text = signed_in.get(f"/servers/{web01.id}").text
    reason = "handler discover/default not registered (Plan 3)"
    assert re.search(rf'<button type="button" disabled title="{re.escape(reason)}">Run discovery</button>', text)
    assert f'<a href="/servers/{web01.id}/dump">Last raw dump summary</a>' in text  # stored data: always readable
    assert f'<a href="/scans?server_id={web01.id}">Open endpoint scan</a>' in text
    assert "<form" not in text.split('id="actions"', 1)[1].split("</section>", 1)[0]


def test_servers_navigation_is_enabled(signed_in):
    assert '<a href="/servers">Servers</a>' in signed_in.get("/").text


def test_unknown_server_is_404_and_values_are_escaped(signed_in, web_factory, server_map):
    assert signed_in.get("/servers/999999999").status_code == 404
    assert signed_in.get("/servers/not-a-number").status_code == 404
    hostile = '<script>alert("x")</script>'
    with web_factory.begin() as db:
        server = Server(
            hostname=f"evil-{server_map.token}.example.internal",
            display_name=hostile,
            notes=hostile,
            ansible_groups=[hostile],
            inventory_source="fixture",
        )
        db.add(server)
        db.flush()
        server_id = server.id
    paths = (
        f"/servers/{server_id}",
        f"/servers?search={server_map.token}",
        f"/servers?group={hostile}",
        f"/servers?search={hostile}",
    )
    for path in paths:
        text = signed_in.get(path).text
        assert hostile not in text and "&lt;script&gt;" in text, path
