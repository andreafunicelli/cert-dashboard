"""Plan 3 Task 11: discovery screens — raw dump summary, stale/unknown bindings, chain diagnostics and banners.

Everything runs against the real HTTP stack and PostgreSQL; the worker is only needed to report its capabilities
(``worker.start`` audit row plus a fresh heartbeat), exactly as the web process sees it in production.
"""

import re
import secrets
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.jobs.worker import record_worker_start
from app.models import Binding, Job, JobHost, Server, WorkerHeartbeat
from app.models.enums import JobHostStatus, JobStatus, JobType, WebserverType
from app.services.servers import DumpSummary, last_dump_summary
from tests.integration.conftest import add_server, set_setting

NO_SSH_KEY = "Discovery and deploy are unavailable: the worker has no ansible_ssh_key"
NO_KNOWN_HOSTS = "Discovery and deploy are unavailable: the worker has no known_hosts file"
NO_INVENTORY = "No inventory repository is configured"
REPO = "https://git.example.test/inventory.git"
INCOMPLETE = "incomplete chain: no configured file holds this leaf's issuer"
HOSTILE = "<script>alert('x')</script>"
SHA = ("ab12cd34ef56" * 6)[:64]  # 64 hex characters


@pytest.fixture(autouse=True)
def isolated(web_factory):
    """No worker has reported, and the inventory is configured, unless a test says otherwise."""
    with web_factory.begin() as db:
        db.query(WorkerHeartbeat).delete()
    set_setting(web_factory, "inventory.repo_url", REPO)


def report_worker(factory, clock, worker):
    """What a started worker leaves behind: its ``worker.start`` row and a fresh heartbeat."""
    record_worker_start(factory, worker.settings, worker.worker_id, clock())
    worker.tick()


@pytest.fixture
def worker_without_ssh_key(web_factory, make_worker, clock):
    worker = make_worker(web_factory)  # no ansible_ssh_key, no known_hosts file
    report_worker(web_factory, clock, worker)
    return worker


@pytest.fixture
def ready_worker(web_factory, ansible_worker, clock):
    worker = ansible_worker(web_factory)  # key and an existing known_hosts file
    report_worker(web_factory, clock, worker)
    return worker


def add_run(db, server_id, *, at, precheck, status=JobHostStatus.SUCCEEDED, job_type=JobType.DISCOVER):
    job = Job(
        type=job_type,
        status=JobStatus.SUCCEEDED,
        priority=100,
        payload={},
        run_after=at,
        started_at=at,
        finished_at=at + timedelta(seconds=30),
    )
    db.add(job)
    db.flush()
    db.add(
        JobHost(
            job_id=job.id,
            server_id=server_id,
            status=status,
            started_at=at,
            finished_at=at + timedelta(seconds=30),
            precheck=precheck,
        )
    )
    return str(job.id)


def summary_of(**changes):
    return {
        "webserver": "nginx",
        "binaries": {"nginx": "/usr/sbin/nginx"},
        "config_files": ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/www.conf"],
        "bindings": 2,
        "warnings": [],
        "parse_suspected": False,
        "dump_bytes": 48213,
        "dump_sha256": SHA,
        **changes,
    }


@pytest.fixture
def discovered_server(web_factory, now):
    """A server whose newest discover run carries a raw-dump summary; an older run and other kinds are decoys."""
    with web_factory.begin() as db:
        server = add_server(db, f"disc-{SHA[:6]}-{secrets.token_hex(4)}.example.internal", webserver=WebserverType.NGINX)
        other = add_server(db, f"other-{SHA[:6]}-{secrets.token_hex(4)}.example.internal")
        add_run(db, server.id, at=now - timedelta(days=2), precheck=summary_of(bindings=9, dump_sha256="f" * 64))
        job_id = add_run(db, server.id, at=now - timedelta(hours=1), precheck=summary_of())
        add_run(db, server.id, at=now, precheck=summary_of(bindings=7), job_type=JobType.DEPLOY)  # not discovery
        add_run(db, other.id, at=now, precheck=summary_of(bindings=5, dump_sha256="e" * 64))  # another server
    return SimpleNamespace(id=server.id, hostname=server.hostname, other_id=other.id, job_id=job_id, dump_sha256=SHA)


def binding_rows(html):
    """``{binding id: row html}`` of every binding row on a Bindings or server detail page."""
    chunks = re.split(r'(?=<tr class="binding-row)', html)[1:]
    return {int(re.search(r'data-binding-id="(\d+)"', chunk)[1]): chunk.split("</tr>", 1)[0] for chunk in chunks}


def binding_id(factory, server_id, vhost):
    with factory() as db:
        return db.query(Binding.id).filter(Binding.server_id == server_id, Binding.vhost_name == vhost).scalar()


# --- raw dump summary ------------------------------------------------------------------------------


def test_last_raw_dump_summary_never_shows_dump_text(signed_in, web_factory, discovered_server):
    page = signed_in.get(f"/servers/{discovered_server.id}/dump")
    assert page.status_code == 200
    assert "/etc/nginx/conf.d/www.conf" in page.text and "2 bindings" in page.text
    assert "ssl_certificate " not in page.text and discovered_server.dump_sha256[:16] in page.text
    assert "48213" in page.text and "nginx" in page.text
    assert discovered_server.job_id in page.text  # the run it belongs to
    detail = signed_in.get(f"/servers/{discovered_server.id}").text
    assert f'<a href="/servers/{discovered_server.id}/dump">Last raw dump summary</a>' in detail


def test_the_summary_is_the_newest_discover_row_of_that_server(web_factory, discovered_server):
    with web_factory() as db:
        found = last_dump_summary(db, discovered_server.id)
        assert isinstance(found, DumpSummary)
        assert (found.job_id, found.webserver, found.bindings) == (discovered_server.job_id, "nginx", 2)
        assert found.config_files == ("/etc/nginx/nginx.conf", "/etc/nginx/conf.d/www.conf")
        assert (found.dump_bytes, found.dump_sha256, found.parse_suspected) == (48213, SHA, False)
        assert found.warnings == () and found.collected_at is not None
        assert last_dump_summary(db, 2_000_000_000) is None


def test_a_server_without_any_summary_says_so(signed_in, web_factory, now):
    with web_factory.begin() as db:
        server = add_server(db, f"fresh-{secrets.token_hex(4)}.example.internal")
        add_run(db, server.id, at=now, precheck=None, status=JobHostStatus.FAILED)  # unreachable: nothing captured
    page = signed_in.get(f"/servers/{server.id}/dump")
    assert page.status_code == 200 and "No raw dump has been captured" in page.text


def test_dump_route_404_and_escaping(signed_in, web_factory, now):
    assert signed_in.get("/servers/2000000000/dump").status_code == 404
    assert signed_in.get("/servers/not-a-number/dump").status_code in (404, 422)
    with web_factory.begin() as db:
        server = add_server(db, f"hostile-{secrets.token_hex(4)}.example.internal")
        add_run(
            db,
            server.id,
            at=now,
            precheck=summary_of(
                config_files=[f"/etc/nginx/{HOSTILE}.conf"], warnings=[f"unparsed block {HOSTILE}"], webserver=HOSTILE
            ),
        )
    text = signed_in.get(f"/servers/{server.id}/dump").text
    assert HOSTILE not in text and "&lt;script&gt;" in text
    assert text.count("&lt;script&gt;") >= 3  # file, warning and web server name are all escaped


def test_dump_summary_requires_sign_in(client, discovered_server):
    response = client.get(f"/servers/{discovered_server.id}/dump", follow_redirects=False)
    assert response.status_code in (303, 401)


# --- capability banner and disabled actions --------------------------------------------------------


def test_missing_ssh_key_banner_and_disabled_actions(signed_in, web_factory, worker_without_ssh_key, discovered_server):
    page = signed_in.get("/servers").text
    assert NO_SSH_KEY in page
    assert 'disabled title="Discovery and deploy are unavailable' in page
    assert 'action="/servers/discover"' not in page
    detail = signed_in.get(f"/servers/{discovered_server.id}").text
    assert NO_SSH_KEY in detail and f'action="/servers/{discovered_server.id}/discover"' not in detail
    assert re.search(r'<button type="button" disabled title="Discovery and deploy[^"]+">Run discovery</button>', detail)
    # Stored summaries are readable whatever the worker can do.
    assert signed_in.get(f"/servers/{discovered_server.id}/dump").status_code == 200


def test_the_banner_is_only_on_servers_bindings_deploy_and_settings(signed_in, worker_without_ssh_key):
    for path in ("/servers", "/bindings", "/settings"):
        page = signed_in.get(path).text
        assert 'data-banner="capability"' in page and NO_SSH_KEY in page, path
    for path in ("/", "/certificates", "/audit", "/scans"):
        page = signed_in.get(path).text
        assert 'data-banner="capability"' not in page and NO_SSH_KEY not in page, path


def test_a_missing_known_hosts_file_is_reported_too(signed_in, web_factory, make_worker, clock, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    )
    report_worker(
        web_factory, clock, make_worker(web_factory, ansible_ssh_key=key, known_hosts_file=tmp_path / "absent")
    )
    page = signed_in.get("/servers").text
    assert NO_KNOWN_HOSTS in page and NO_SSH_KEY not in page
    assert 'disabled title="Discovery and deploy are unavailable' in page


def test_a_capable_worker_leaves_no_banner_and_enabled_actions(signed_in, ready_worker, discovered_server):
    page = signed_in.get("/servers").text
    assert 'data-banner="capability"' not in page and 'action="/servers/discover"' in page
    assert f'action="/servers/{discovered_server.id}/discover"' in signed_in.get(f"/servers/{discovered_server.id}").text


def test_a_worker_that_has_not_reported_is_a_hint_not_a_block(signed_in, discovered_server):
    page = signed_in.get("/servers").text  # nobody reported a start row: the stale-worker banner covers a dead one
    assert 'data-banner="capability"' not in page and 'action="/servers/discover"' in page


def test_inventory_unconfigured_disables_discovery(signed_in, web_factory, ready_worker, discovered_server):
    set_setting(web_factory, "inventory.repo_url", "")
    page = signed_in.get("/servers").text
    assert NO_INVENTORY in page and 'disabled title="No inventory repository is configured' in page
    assert 'action="/servers/discover"' not in page and 'data-banner="capability"' not in page
    detail = signed_in.get(f"/servers/{discovered_server.id}").text
    assert NO_INVENTORY in detail and f'action="/servers/{discovered_server.id}/discover"' not in detail
    set_setting(web_factory, "inventory.repo_url", REPO)
    assert 'action="/servers/discover"' in signed_in.get("/servers").text


def test_the_missing_key_reason_wins_over_the_unconfigured_inventory(signed_in, web_factory, worker_without_ssh_key):
    set_setting(web_factory, "inventory.repo_url", "")
    page = signed_in.get("/servers").text
    assert 'disabled title="Discovery and deploy are unavailable' in page and NO_SSH_KEY in page


def test_ansible_unavailable_reason_is_a_plain_function(web_factory, clock, ready_worker):
    from app.web.common import ansible_unavailable_reason

    with web_factory() as db:
        assert ansible_unavailable_reason(db, clock()) == ""
        assert ansible_unavailable_reason(db, clock() + timedelta(hours=1)) == ""  # nobody alive: not a reason


def test_ansible_unavailable_reason_names_the_missing_piece(web_factory, clock, worker_without_ssh_key):
    from app.web.common import ansible_unavailable_reason

    with web_factory() as db:
        assert ansible_unavailable_reason(db, clock()) == NO_SSH_KEY


# --- stale, unknown and diagnosed bindings --------------------------------------------------------


def test_stale_bindings_are_badged_after_a_failed_discovery(signed_in, server_map, web_factory):
    web01, web02 = (server_map.server(f"web0{n}.example.internal") for n in (1, 2))  # ok / failed
    page = signed_in.get(f"/bindings?server_id={web02.id}&active=all").text
    rows = binding_rows(page)
    assert len(rows) == 2 and all("stale since" in row and 'data-stale="true"' in row for row in rows.values())
    assert 'datetime="' in next(iter(rows.values())).split("stale since", 1)[1]
    healthy = binding_rows(signed_in.get(f"/bindings?server_id={web01.id}&active=all").text)
    assert healthy and all("stale since" not in row for row in healthy.values())  # including the retired one
    detail = binding_rows(signed_in.get(f"/servers/{web02.id}").text)
    assert len(detail) == 2 and all("stale since" in row for row in detail.values())
    # Staleness is derived: the next successful discovery clears it without touching a binding.
    with web_factory.begin() as db:
        db.get(Server, web02.id).last_discovery_status = "ok"
    assert all("stale since" not in row for row in binding_rows(signed_in.get(f"/servers/{web02.id}").text).values())


def unknown_world(web_factory, now, vhost="shop.example.test"):
    with web_factory.begin() as db:
        server = add_server(db, f"unk-{secrets.token_hex(4)}.example.internal", last_discovery_status="ok")
        live = Binding(
            server_id=server.id, webserver=WebserverType.NGINX, vhost_name=vhost, vhost_names=[vhost], port=8443,
            config_file="/etc/nginx/conf.d/shop.conf", cert_path="/etc/ssl/shop.pem", key_path="/etc/ssl/shop.key",
            on_disk_fingerprint="d" * 64, match_state="unknown", last_seen_at=now + timedelta(days=30), is_active=True,
        )
        retired = Binding(
            server_id=server.id, webserver=WebserverType.NGINX, vhost_name="old." + vhost, vhost_names=["old." + vhost],
            port=443, config_file="/etc/nginx/conf.d/old.conf", cert_path="/etc/ssl/old.pem", key_path="/etc/ssl/old.key",
            on_disk_fingerprint="9" * 64, match_state="unknown", last_seen_at=now, is_active=False,
        )
        db.add_all([live, retired])
        db.flush()
        return SimpleNamespace(server=server, live=live.id, retired=retired.id, vhost=vhost)


def test_unknown_binding_offers_import_as_certificate(signed_in, web_factory, now):
    world = unknown_world(web_factory, now)
    link = f'href="/certificates/import?from_binding={world.live}"'
    bindings = binding_rows(signed_in.get(f"/bindings?server_id={world.server.id}&active=all").text)
    assert link in bindings[world.live] and "d" * 64 in bindings[world.live]
    assert "Import as certificate" in bindings[world.live]
    assert "from_binding" not in bindings[world.retired]  # a retired binding has nothing to import
    detail = binding_rows(signed_in.get(f"/servers/{world.server.id}").text)
    assert link in detail[world.live] and "from_binding" not in detail[world.retired]
    overview = signed_in.get("/").text
    assert link in overview and "d" * 64 in overview
    assert f"from_binding={world.retired}" not in overview


def test_import_page_explains_that_nothing_is_fetched_from_the_target(signed_in, web_factory, now):
    world = unknown_world(web_factory, now, vhost=f"{HOSTILE}.example.test")
    page = signed_in.get(f"/certificates/import?from_binding={world.live}")
    assert page.status_code == 200
    text = page.text
    assert "must be pasted or uploaded" in text and "Nothing is fetched from the server" in text
    assert "d" * 64 in text and world.server.hostname in text
    assert HOSTILE not in text and "&lt;script&gt;" in text
    notes = re.search(r'<textarea id="notes"[^>]*>(.*?)</textarea>', text, re.DOTALL)[1]
    assert world.server.hostname in notes and "d" * 64 in notes  # the hint pre-fills the owner notes only
    for bad in ("0", "999999999", "abc", "-1", "1;2"):
        plain = signed_in.get(f"/certificates/import?from_binding={bad}")
        assert plain.status_code == 200 and "must be pasted or uploaded" not in plain.text, bad


def test_parse_suspected_host_is_listed_for_review(signed_in, web_factory, now):
    with web_factory.begin() as db:
        server = add_server(db, f"suspect-{secrets.token_hex(4)}.example.internal", last_discovery_status="ok")
        add_run(db, server.id, at=now, precheck=summary_of(bindings=0, parse_suspected=True, warnings=["no ssl_certificate found"]))
        quiet = add_server(db, f"quiet-{secrets.token_hex(4)}.example.internal", last_discovery_status="ok")
        add_run(db, quiet.id, at=now, precheck=summary_of())
    page = signed_in.get(f"/servers/{server.id}").text
    assert 'data-warning="parse-suspected"' in page
    assert "its bindings were kept" in page and f'href="/servers/{server.id}/dump"' in page
    assert 'data-warning="parse-suspected"' not in signed_in.get(f"/servers/{quiet.id}").text
    assert "no ssl_certificate found" in signed_in.get(f"/servers/{server.id}/dump").text
    assert "parse suspected" in signed_in.get(f"/servers/{server.id}/dump").text.lower()


def test_binding_chain_diagnostic_is_shown_escaped_on_server_and_bindings_pages(signed_in, web_factory, now):
    with web_factory.begin() as db:
        server = add_server(db, f"chain-{secrets.token_hex(4)}.example.internal", last_discovery_status="ok")
        plain = Binding(
            server_id=server.id, webserver=WebserverType.NGINX, vhost_name="diag.example.test", vhost_names=["diag.example.test"],
            port=443, config_file="/etc/nginx/a.conf", cert_path="/c", key_path="/k", match_state="unknown", last_seen_at=now,
            notes=INCOMPLETE,
        )
        hostile = Binding(
            server_id=server.id, webserver=WebserverType.NGINX, vhost_name="evil.example.test", vhost_names=["evil.example.test"],
            port=444, config_file="/etc/nginx/b.conf", cert_path="/c2", key_path="/k2", match_state="unknown", last_seen_at=now,
            notes=f"{INCOMPLETE}; {HOSTILE}",
        )
        silent = Binding(
            server_id=server.id, webserver=WebserverType.NGINX, vhost_name="quiet.example.test", vhost_names=["quiet.example.test"],
            port=445, config_file="/etc/nginx/c.conf", cert_path="/c3", key_path="/k3", match_state="unknown", last_seen_at=now,
        )
        db.add_all([plain, hostile, silent])
        db.flush()
        ids = (plain.id, hostile.id, silent.id)
    escaped = INCOMPLETE.replace("'", "&#39;")
    for page in (
        signed_in.get(f"/servers/{server.id}").text,
        signed_in.get(f"/bindings?server_id={server.id}").text,
    ):
        rows = binding_rows(page)
        assert escaped in rows[ids[0]] and escaped in rows[ids[1]] and "incomplete chain" not in rows[ids[2]]
        assert HOSTILE not in page and "&lt;script&gt;" in rows[ids[1]]
    exported = signed_in.get(f"/bindings/export.json?server_id={server.id}").json()
    assert all("notes" not in row for row in exported)  # the export stays allowlisted


def test_binding_screens_keep_a_constant_query_count(signed_in, web_factory, server_map, now, count_statements):
    web02 = server_map.server("web02.example.internal")
    assert signed_in.get("/bindings").status_code == 200  # warm per-app caches
    with count_statements() as small:
        assert signed_in.get(f"/bindings?server_id={web02.id}").status_code == 200
        assert signed_in.get(f"/servers/{web02.id}").status_code == 200
        assert signed_in.get("/servers?page_size=5").status_code == 200
    with web_factory.begin() as db:
        for number in range(25):
            db.add(
                Binding(
                    server_id=web02.id, webserver=WebserverType.NGINX, vhost_name=f"bulk{number}.example.test",
                    vhost_names=[f"bulk{number}.example.test"], port=1000 + number, config_file="/etc/nginx/x.conf",
                    cert_path="/c", key_path="/k", match_state="unknown", on_disk_fingerprint="a" * 64,
                    last_seen_at=now, notes=INCOMPLETE,
                )
            )
    with count_statements() as large:
        page = signed_in.get(f"/bindings?server_id={web02.id}&page_size=50").text
        assert len(binding_rows(page)) > 25
        assert signed_in.get(f"/servers/{web02.id}").status_code == 200
        assert signed_in.get("/servers?page_size=5").status_code == 200
    assert small.count == large.count
