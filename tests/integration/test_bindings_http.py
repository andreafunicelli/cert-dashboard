"""Plan 2 Task 15: cross-server bindings view (real Postgres, real HTTP stack)."""

import re

from app.models import Binding, Server
from app.models.enums import WebserverType
from app.services.servers import BINDING_EXPORT_FIELDS
from tests.integration.conftest import add_server

HOSTILE = '<script>alert("x")</script>'


def _vhosts(html):
    return re.findall(r'data-vhost="([^"]*)"', html)


def _exported(signed_in, query):
    response = signed_in.get(f"/bindings/export.json?{query}")
    assert response.status_code == 200, query
    return response.json()


def test_where_is_this_certificate_used(signed_in, server_map):
    page = signed_in.get(f"/bindings?certificate_id={server_map.certificate_id}&sort=server")
    assert page.status_code == 200
    assert all(host in page.text for host in server_map.hosts_using_certificate)
    exported = signed_in.get(f"/bindings/export.json?certificate_id={server_map.certificate_id}").json()
    assert {row["server"] for row in exported} == set(server_map.hosts_using_certificate)
    assert all(set(row) == set(BINDING_EXPORT_FIELDS) for row in exported)
    assert all("notes" not in row and "key" not in row for row in exported)
    by_vhost = {row["vhost_name"]: row for row in exported}
    mismatch = by_vhost[f"api-{server_map.token}.example.test"]
    assert (mismatch["cert_mode"], mismatch["key_mode"]) == ("0644", "0600")  # octal strings
    assert mismatch["vhost_names"] == [mismatch["vhost_name"]] and mismatch["is_active"] is True
    assert re.match(r"\d{4}-\d\d-\d\dT", mismatch["last_seen_at"])
    assert server_map.certificate_fingerprint in page.text
    assert f'href="/certificates/{server_map.certificate_id}"' in page.text
    assert 'filename="bindings.json"' in signed_in.get("/bindings/export.json").headers["content-disposition"]


def test_every_binding_filter(signed_in, server_map, web_factory, now):
    token, group = server_map.token, server_map.group
    web01, web02 = (server_map.server(f"web0{n}.example.internal") for n in (1, 2))
    with web_factory.begin() as db:  # a second name served by one binding, found through vhost_names
        sibling = Binding(
            server_id=web02.id, webserver=WebserverType.APACHE, vhost_name=f"main-{token}.example.test",
            vhost_names=[f"main-{token}.example.test", f"Alias-{token}.example.test"], port=8443,
            config_file="/etc/apache2/sites-enabled/main.conf", cert_path="/etc/ssl/main.pem",
            key_path="/etc/ssl/main.key", match_state="unknown", last_seen_at=now,
        )
        db.add(sibling)

    def names(query):
        return {row["vhost_name"].split("-")[0] for row in _exported(signed_in, f"group={group}&{query}")}

    assert names("") == {"www", "api", "gone", "shop", "blog", "main"}  # active bindings only
    assert names(f"server_id={web01.id}") == {"www", "api", "gone"}
    assert names("webserver=apache") == {"shop", "blog", "main"}
    assert names("webserver=nginx") == {"www", "api", "gone"}
    assert names("match_state=key_mismatch") == {"api"}
    assert names("match_state=unknown") == {"shop", "main"}
    assert names(f"vhost=SHOP-{token}") == {"shop"}  # case-insensitive substring of vhost_name
    assert names(f"vhost=alias-{token}") == {"main"}  # ... or of any of vhost_names
    assert names("vhost=%25") == set() and names("vhost=_") == set()  # LIKE wildcards are literal
    assert names("active=all") == {"www", "api", "gone", "retired", "shop", "blog", "main"}
    assert names("active=false") == {"retired"}
    assert {row["server"] for row in _exported(signed_in, f"group={group}&certificate_id={server_map.other_certificate_id}&active=all")} == {web01.hostname}
    assert _exported(signed_in, "group=no-such-group") == []
    page = signed_in.get(f"/bindings?group={group}&match_state=key_mismatch&webserver=nginx")
    assert _vhosts(page.text) == [f"api-{token}.example.test"]
    for bad in ("webserver=iis", "match_state=bogus", "active=maybe", "server_id=abc", "certificate_id=-1", "sort=notes"):
        assert signed_in.get(f"/bindings?{bad}").status_code == 422, bad
        assert signed_in.get(f"/bindings/export.json?{bad}").status_code == 422, bad


def test_attention_rows_link_to_fix_instructions(signed_in, server_map):
    text = signed_in.get(f"/bindings?group={server_map.group}").text
    assert re.search(r'data-match-state="key_mismatch"[^>]*>key_mismatch</a>', text)
    assert 'href="/bindings/help#key_mismatch"' in text and 'href="/bindings/help#missing_file"' in text
    assert text.count("/bindings/help#") == 2  # matched and unknown rows carry no warning
    help_page = signed_in.get("/bindings/help")
    assert help_page.status_code == 200
    assert 'id="key_mismatch"' in help_page.text and 'id="missing_file"' in help_page.text
    plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", help_page.text))
    assert "does not fix" in plain and "blocks deploys of that virtual host" in plain


def test_bindings_query_count_is_independent_of_rows(signed_in, server_map, count_statements, web_factory, now):
    with web_factory.begin() as db:
        server = add_server(db, f"bulk-{server_map.token}.example.internal", ansible_groups=[server_map.group])
        for number in range(30):
            db.add(
                Binding(
                    server_id=server.id, webserver=WebserverType.NGINX, vhost_name=f"bulk{number:02d}.example.test",
                    vhost_names=[f"bulk{number:02d}.example.test"], config_file="/etc/nginx/bulk.conf",
                    cert_path=f"/etc/ssl/bulk{number}.pem", key_path=f"/etc/ssl/bulk{number}.key",
                    certificate_id=server_map.certificate_id, match_state="matched", last_seen_at=now,
                )
            )
    assert signed_in.get("/bindings").status_code == 200  # warm the per-app worker-liveness cache
    with count_statements() as small:
        assert signed_in.get(f"/bindings?group={server_map.group}&page_size=2").status_code == 200
    with count_statements() as large:
        page = signed_in.get(f"/bindings?group={server_map.group}&page_size=100")
    assert small.count == large.count and len(_vhosts(page.text)) > 30
    with count_statements() as export_small:
        _exported(signed_in, f"server_id={server_map.server('web02.example.internal').id}")
    with count_statements() as export_large:
        _exported(signed_in, f"group={server_map.group}")
    assert export_small.count == export_large.count


def test_pagination_limits_and_whitelisted_sorts(signed_in, server_map):
    token, base = server_map.token, f"/bindings?group={server_map.group}"
    ascending = _vhosts(signed_in.get(f"{base}&sort=vhost").text)
    assert ascending == sorted(ascending) and len(ascending) == 5
    assert _vhosts(signed_in.get(f"{base}&sort=-vhost").text) == ascending[::-1]
    by_state = _vhosts(signed_in.get(f"{base}&sort=match_state").text)
    assert by_state[0] == f"api-{token}.example.test"  # key_mismatch sorts before matched, missing_file, unknown
    by_server = _vhosts(signed_in.get(f"{base}&sort=-server").text)
    assert by_server[:2] != _vhosts(signed_in.get(f"{base}&sort=server").text)[:2]
    first = signed_in.get(f"{base}&sort=vhost&page_size=2")
    second = signed_in.get(f"{base}&sort=vhost&page_size=2&page=2")
    assert _vhosts(first.text) == ascending[:2] and _vhosts(second.text) == ascending[2:4]
    assert 'rel="next"' in first.text and 'rel="prev"' not in first.text and 'rel="prev"' in second.text
    assert "5 bindings" in first.text
    for bad in ("page_size=0", "page_size=101", "page=0", "page=x", "sort=-notes", "sort=server;drop"):
        assert signed_in.get(f"/bindings?{bad}").status_code == 422, bad


def test_bindings_require_sign_in_and_escape_paths(signed_in, client, web_factory, server_map, now):
    with web_factory.begin() as db:
        server = Server(
            hostname=f"evil-{server_map.token}.example.internal", ansible_groups=[HOSTILE], inventory_source="fixture"
        )
        db.add(server)
        db.flush()
        db.add(
            Binding(
                server_id=server.id, webserver=WebserverType.NGINX, vhost_name=f"v{HOSTILE}",
                vhost_names=[f"v{HOSTILE}"], config_file=f"/c{HOSTILE}", cert_path=f"/p{HOSTILE}",
                key_path=f"/k{HOSTILE}", match_state="key_mismatch", last_seen_at=now, notes=HOSTILE,
            )
        )
    for path in ("/bindings?vhost=script", f"/bindings?group={HOSTILE}", f"/bindings?vhost={HOSTILE}"):
        text = signed_in.get(path).text
        assert HOSTILE not in text and "&lt;script&gt;" in text, path
    export = signed_in.get("/bindings/export.json?vhost=script")
    assert export.status_code == 200 and "notes" not in export.json()[0]
    client.cookies.clear()
    for url in ("/bindings", "/bindings/export.json", "/bindings/help"):
        response = client.get(url, follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"] == "/login", url
