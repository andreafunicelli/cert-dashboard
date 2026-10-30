"""Database-free UI contracts, fixture generation and WCAG palette checks."""

import re
from html.parser import HTMLParser

from scripts.render_previews import ROOT, environment, fixtures


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
        assert 'id="main-content"' in html and 'href="#main-content"' in html
        assert 'style="' not in html and "|safe" not in html
        assert [a["src"] for t, a in elements if t == "script"] == ["/static/htmx.min.js"]
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
            assert 'href="/" aria-current="page"' in html
            for hook in ("worker", "capability", "flash"):
                assert f'data-banner="{hook}"' in html


def test_rendering_escapes_user_values():
    template = environment().get_template("login.html.j2")
    context = fixtures()["login"][1] | {"username": '<img src=x onerror="bad">', "error": "<script>bad</script>"}
    html = template.render(context)
    assert "&lt;img" in html and "&lt;script&gt;" in html
    assert "<img" not in html and "<script>bad" not in html


def luminance(value):
    channels = [int(value[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= .04045 else ((c + .055) / 1.055) ** 2.4 for c in channels]
    return sum(c * w for c, w in zip(linear, (.2126, .7152, .0722), strict=True))


def contrast(a, b):
    high, low = sorted([luminance(a), luminance(b)], reverse=True)
    return (high + .05) / (low + .05)


def test_css_tokens_and_both_theme_contrast():
    css = (ROOT / "app/static/app.css").read_text()
    blocks = re.findall(r":root\s*\{([^}]+)\}", css)
    palettes = [dict(re.findall(r"--([\w-]+):\s*(#[0-9a-f]{6});", block)) for block in blocks[:2]]
    definitions = set(re.findall(r"--([\w-]+)\s*:", css))
    assert set(re.findall(r"var\(--([\w-]+)\)", css)) <= definitions
    assert not re.search(r"#[0-9a-fA-F]{3,8}", re.sub(r":root\s*\{[^}]+\}", "", css))
    assert len(css.splitlines()) < 450
    for palette in palettes:
        for background in ("surface", "surface-raised", "surface-inset"):
            for foreground in ("text", "text-muted", "accent"):
                assert contrast(palette[foreground], palette[background]) >= 4.5, (foreground, background)
            for foreground in ("border", "focus"):
                assert contrast(palette[foreground], palette[background]) >= 3
        for state in ("ok", "warn", "danger"):
            assert contrast(palette[state], palette[f"{state}-surface"]) >= 4.5
        for background in ("accent-fill", "danger-fill"):
            assert contrast(palette["on-accent"], palette[background]) >= 4.5
