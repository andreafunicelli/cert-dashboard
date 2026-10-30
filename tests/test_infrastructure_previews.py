"""Repository-only infrastructure contracts; fixtures are not runtime image inputs."""

import re
from copy import deepcopy
from pathlib import Path

from jinja2 import StrictUndefined

from scripts.render_previews import environment, fixtures, infrastructure_fixtures
from tests.test_ui_previews import Elements, FormContracts


def rendered(name, **updates):
    source, context = fixtures()[name]
    return environment().get_template(source).render(context | updates)


def test_all_infrastructure_templates_render_with_explicit_read_models():
    env = environment()
    env.undefined = StrictUndefined
    for name in infrastructure_fixtures():
        source, context = fixtures()[name]
        html = env.get_template(source).render(context)
        assert 'style="' not in html and '<script>' not in html
        elements = Elements(html).elements
        assert [a["src"] for t, a in elements if t == "script"] == ["/static/htmx.min.js"]
        ids = [a["id"] for _, a in elements if "id" in a]
        assert len(ids) == len(set(ids)), name
        head = html.split("<head>", 1)[1].split("</head>", 1)[0]
        styles = [a["href"] for t, a in Elements(head).elements if t == "link" and a.get("rel") == "stylesheet"]
        assert styles[0] == "/static/app.css"
        assert styles[1] == ("/static/pages/servers.css" if name.startswith("server-") else "/static/pages/bindings.css")
        if name in ("server-detail", "server-failed", "server-never", "server-empty-discovery", "server-parse-warning"):
            assert styles[2] == "/static/pages/bindings.css"


def test_discovery_forms_and_filter_names_are_preserved():
    page = rendered("server-list")
    forms = FormContracts(page).forms
    posts = [f for f in forms if f.get("method") == "post"]
    assert len(posts) == 2
    for form in posts:
        assert form["action"] == "/servers/discover"
        assert any(a.get("name") == "csrf_token" and a.get("type") == "hidden" for a in form["inputs"])
    expected = {
        "server-list": {"search", "group", "active", "sort", "page_size", "csrf_token", "scope"},
        "binding-list": {"certificate_id", "server_id", "group", "vhost", "webserver", "match_state", "active", "sort", "page_size"},
    }
    for name, names in expected.items():
        actual = {a["name"] for t, a in Elements(rendered(name)).elements if t in ("input", "select") and "name" in a}
        assert actual == names
    detail = rendered("server-detail")
    assert '<form class="inline" method="post" action="/servers/1/discover">' in detail
    assert '<button type="submit">Run discovery</button>' in detail
    blocked = rendered("server-detail", discovery_reason="No inventory repository is configured")
    assert 'disabled title="No inventory repository is configured">Run discovery</button>' in blocked
    assert 'action="/servers/1/discover"' not in blocked


def test_shared_relationship_retains_row_hooks_raw_hashes_and_warning_links():
    for name in ("binding-list", "server-detail"):
        html = rendered(name)
        rows = re.split(r'(?=<tr class="binding-row)', html)[1:]
        assert len(rows) == 4
        assert 'data-match-state="key_mismatch">key_mismatch</a>' in rows[0]
        assert "binding-drift" in rows[0] and "badge-warn" in rows[0] and "Drift:" in rows[0]
        assert "row-attention" in rows[2] and "badge-danger" in rows[2] and "File failure:" in rows[2]
        assert "Inventory match" in rows[1] and "Unknown certificate" in rows[3]
        assert "ab12cd34" * 8 in rows[0]  # exact DOM and HTML text, no inserted grouping
        assert "root:ssl-cert 0644" in rows[0] and "root:ssl-cert 0600" in rows[0]
        assert 'href="/certificates/42"' in rows[0]
        assert "Observed on disk" in html and "Inventory / expectation" in html
        assert "Configured SNI / virtual-host names" in html and "443" in rows[0]
        assert 'href="/bindings/help#key_mismatch"' in rows[0]
        assert 'data-stale="true"' in rows[3] and "stale since" in rows[3]
        assert '<script>fixture escaping check</script>' not in html and "&lt;script&gt;" in rows[3]
        assert "Desired deployment and expected fingerprint are not supplied" in html
    assert 'data-vhost="gateway.ops.example.test"' in rendered("binding-list")


def test_recorded_empty_never_failed_and_parse_suspected_are_different():
    never = rendered("server-never")
    empty = rendered("server-empty-discovery")
    failed = rendered("server-failed")
    assert "Never discovered" in never and "No captured dump is available" in never
    assert "No bindings found in the captured configuration" in empty
    assert "not a host that never ran" in empty
    assert "ssh: connect to host failed: connection timed out" in failed
    assert failed.index("ssh: connect to host failed") < failed.index('id="actions"')
    assert 'data-job-status="failed"' in failed
    assert "Changes since the previous run: unavailable" in empty
    warning = rendered("server-parse-warning")
    assert 'data-warning="parse-suspected" role="alert" aria-label="Review needed"' in warning
    assert "its bindings were kept" in warning
    assert "No raw dump has been captured" in rendered("server-dump-empty")
    assert "4 bindings" in rendered("server-dump")
    assert "Last captured dump, not necessarily the latest attempted run" in rendered("server-dump")


def test_missing_error_and_stale_observations_never_become_healthy_claims():
    source, context = fixtures()["server-failed"]
    context = deepcopy(context)
    context["detail"].discovery_history[0].error_message = None
    html = environment().get_template(source).render(context)
    assert "No failure reason recorded" in html
    assert "not a current host verdict" in html
    source, context = fixtures()["server-detail"]
    context = deepcopy(context)
    context["server"].hostname = '<img src=x onerror="bad">'
    context["detail"].bindings[0].cert_path = '<script>bad</script>'
    html = environment().get_template(source).render(context)
    assert "&lt;img" in html and "&lt;script&gt;bad" in html
    assert '<img src=x' not in html and '<script>bad' not in html
    context["server"].last_discovery_at = None
    context["server"].last_discovery_status = "unreachable"
    context["detail"].discovery_history = []
    context["detail"].dump_summary = None
    html = environment().get_template(source).render(context)
    assert "Unreachable" in html and "Time not recorded" in html
    assert "Never discovered" not in html and "has not been discovered yet" not in html
    source, context = fixtures()["binding-list"]
    context = deepcopy(context)
    context["page"].items[-1].is_active = False
    html = environment().get_template(source).render(context)
    retired = re.split(r'(?=<tr class="binding-row)', html)[-1]
    assert "(retired)" in retired and "from_binding" not in retired


def test_area_styles_reuse_tokens_and_bound_long_server_rows():
    root = Path(__file__).resolve().parents[1]
    for area in ("servers", "bindings"):
        css = (root / f"app/static/pages/{area}.css").read_text()
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(", css)
        assert "overflow-wrap: anywhere" in css
        assert "table-layout: fixed" in css
    css = (root / "app/static/pages/servers.css").read_text()
    assert "width: 28%" in css and "width: 26%" in css
    assert 'data-server-id="2"' in rendered("server-list")
    assert "View host failure reason" in rendered("server-list")
