"""Repository-level preview tests: fixture assets are not shipped in runtime images."""

from html.parser import HTMLParser

import pytest

from scripts.render_previews import OUTPUT, environment, fixtures, render


class Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


def test_preview_templates_and_form_contracts():
    env = environment()
    for name, (template, context) in fixtures().items():
        html = env.get_template(template).render(context)
        elements = Elements(html).elements
        if not name.startswith('email-'):
            assert 'id="main-content"' in html and 'href="#main-content"' in html
        assert 'style="' not in html and "|safe" not in html
        scripts = [] if name.startswith('email-') else ['/static/htmx.min.js']
        if name.startswith('settings-'):
            scripts.append('/static/settings.js')
        assert [a['src'] for t, a in elements if t == 'script'] == scripts
        inputs = {a.get("name"): a for t, a in elements if t == "input"}
        if name.startswith("login"):
            assert inputs["csrf_token"]["value"] == context["csrf_token"]
            assert inputs["csrf_token"]["type"] == "hidden"
            if name.startswith("login-2fa"):
                assert inputs["code"]["autocomplete"] == "one-time-code"
                assert [(a["method"], a["action"]) for t, a in elements if t == "form"] == [
                    ("post", "/login/2fa"), ("post", "/logout"),
                ]
            else:
                assert inputs["password"]["type"] == "password"
                assert "value" not in inputs["password"]
                assert inputs["username"]["value"] == context["username"]
            ids = {a["id"] for t, a in elements if "id" in a}
            assert all(a["for"] in ids for t, a in elements if t == "label")
        if name == "bootstrap":
            assert "<form" not in html and "csrf_token" not in html
            assert "python -m app.cli bootstrap-admin" in html
        if name == "shell":
            assert '<span aria-current="page"><a href="/">Overview</a></span>' in html
            for item in context["navigation"]:
                assert f'<a href="{item["url"]}">{item["label"]}</a>' in html
            for hook in ("worker", "capability", "flash"):
                assert f'data-banner="{hook}"' in html


def test_rendering_escapes_user_values():
    template = environment().get_template("login.html.j2")
    context = fixtures()["login"][1] | {"username": '<img src=x onerror="bad">', "error": "<script>bad</script>"}
    html = template.render(context)
    assert "&lt;img" in html and "&lt;script&gt;" in html
    assert "<img" not in html and "<script>bad" not in html


def test_confirmation_demonstrates_inert_post_and_csrf():
    template, context = fixtures()["shell"]
    html = environment().get_template(template).render(context)
    _, marker, confirmation = html.partition('<details class="confirmation">')
    assert marker
    confirmation = confirmation.split("</details>", 1)[0]
    elements = Elements(confirmation).elements
    assert [(a["method"], a["action"]) for t, a in elements if t == "form"] == [
        ("post", "#main-content"),
    ]
    assert [a for t, a in elements if t == "input"] == [
        {"type": "hidden", "name": "csrf_token", "value": "preview-only-not-a-valid-token"},
    ]
    assert "Deletion removes this certificate from the inventory." in confirmation
    assert "Static preview only; no certificate will be deleted." in confirmation
    assert "Confirm deletion (preview)" in confirmation
    assert any(t == "button" and a.get("type") == "submit"
               and a.get("class") == "button-destructive" and "disabled" in a
               for t, a in elements)
    assert any(t == "a" and a.get("href") == "shell.html" for t, a in elements)


def test_committed_previews_match_renderer(tmp_path):
    render(tmp_path)
    expected = {f"{name}.html" for name in fixtures()}
    assert {path.name for path in OUTPUT.glob("*.html")} == expected
    for name in expected:
        generated = (tmp_path / name).read_bytes()
        assert (OUTPUT / name).read_bytes() == generated, name
        assert all(line == line.rstrip() for line in generated.splitlines()), name


def preview(name, **overrides):
    template, context = fixtures()[name]
    return environment().get_template(template).render(context | overrides)


class FormContracts(HTMLParser):
    """Track each form independently, including its confirmation ancestors."""

    def __init__(self, html):
        super().__init__()
        self.forms = []
        self.form = None
        self.details = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "details":
            self.details.append(attrs.get("class", ""))
        if tag == "form":
            assert self.form is None, "Nested forms are invalid"
            self.form = attrs | {"inputs": [], "buttons": [], "confirmation": "confirmation" in self.details}
        if self.form is not None and tag in ("input", "button"):
            self.form["inputs" if tag == "input" else "buttons"].append(attrs)

    def handle_endtag(self, tag):
        if tag == "form":
            self.forms.append(self.form)
            self.form = None
        if tag == "details":
            self.details.pop()


@pytest.mark.parametrize("name", ["account", "account-enrollment", "account-required", "account-directory", "account-error", "users"])
def test_operator_posts_keep_csrf_password_privacy_and_destructive_confirmations(name):
    for form in FormContracts(preview(name)).forms:
        assert form["method"] == "post"
        tokens = [item for item in form["inputs"] if item.get("name") == "csrf_token"]
        assert len(tokens) == 1 and tokens[0]["type"] == "hidden"
        assert tokens[0]["value"] == "preview-only-not-a-valid-token"
        for field in form["inputs"]:
            if field.get("type") == "password":
                assert "value" not in field
        if form["action"].endswith(("/disable", "/reset-password", "/reset-totp", "/deactivate")):
            assert form["confirmation"]
            assert any("button-destructive" in button.get("class", "") for button in form["buttons"])


def test_user_totp_reset_explains_optional_reenrollment_before_submit():
    html = preview("users")
    confirmations = html.split('<details class="confirmation"><summary>Reset two-factor authentication</summary>')[1:]
    assert len(confirmations) == len(fixtures()["users"][1]["users"])
    for confirmation in confirmations:
        explanation = confirmation.split("<form", 1)[0]
        assert "Removes the authenticator and recovery codes and signs this user out everywhere." in explanation
        assert (
            "Future sign-ins will require only a password until the user chooses "
            "to set up two-factor authentication again."
        ) in explanation
        assert "They must set up" not in confirmation.split("</details>", 1)[0]


def test_overview_state_precedes_actions_and_details_and_all_counters_link():
    html = preview("overview")
    assert html.index('aria-label="Certificate expiry"') < html.index('data-status-strip="true"')
    assert html.index("Recent failures") < html.index('aria-label="Overview actions"') < html.index('<table class="recent-jobs">')
    elements = Elements(html).elements
    counters = [attrs for tag, attrs in elements if "data-counter" in attrs or "data-tls" in attrs]
    assert len(counters) == 13 and all(attrs["href"].startswith(("/certificates?", "/scans", "/bindings?")) for attrs in counters)
    assert html.count('<strong>') >= len(counters)
    assert 'class="status-icon"' in html and "Scan freshness is not summarized here" in html
    assert "No jobs have run yet" in preview("overview-empty")
    assert "No renewals in flight" in preview("overview-empty")


def test_audit_read_only_full_width_detail_and_escaping_contracts():
    html = preview("audit")
    assert html.count("data-audit-row") == 2
    assert html.count('colspan="5"') == 2
    assert '<details>' in html and '<pre>' in html
    assert "&lt;script&gt;fixture escaping check&lt;/script&gt;" in html
    assert '<script>fixture' not in html
    assert 'title="worker:edge-' in html
    assert all(form["method"] == "get" for form in FormContracts(html).forms)
    assert 'data-total="0"' in preview("audit-empty")


def test_account_branches_preserve_existing_routes_and_one_time_hooks():
    html = preview("account-enrollment")
    assert "data-secret>PREVIEW-KEY-NOT-A-REAL-SECRET<" in html
    assert html.count("data-recovery-code>") == 2
    forms = FormContracts(html).forms
    enroll = next(form for form in forms if form["action"] == "/account/totp/enroll")
    assert enroll["confirmation"]
    assert {form["action"] for form in forms} == {"/account/password", "/account/totp/confirm", "/account/totp/enroll", "/logout"}
    assert "/account/totp/" not in preview("account-required")
    assert 'action="/account/password"' not in preview("account-directory")
    assert 'class="confirmation" open' in preview("account-error")
