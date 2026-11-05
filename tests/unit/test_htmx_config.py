"""Global HTMX configuration and error-surface contracts (UX-08), without a database.

htmx reads only the *first* ``<meta name="htmx-config">`` it finds. A1 therefore moves the single
configuration into ``base.html.j2`` (sourced from ``app/web/management.py``) so a CSRF refusal, a
missing page or a server error is swapped into ``#main-content`` on every page, not only on the
Slice B management screens.

This file stays inside ``tests/unit`` (the image runs it without ``scripts/``): it renders the shell
and the error page with a local Jinja environment instead of importing the preview generator. The
"every page" sweep lives in the repository-level preview tests.
"""

import json
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader

from app.web.administration import DEFAULT_BRAND, HTMX_CONFIG, HTMX_CONFIG_JSON
from app.web.management import _HTMX_CONFIG

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "app/templates"


class Head(HTMLParser):
    """Every start tag inside ``<head>``, in document order, with entity-decoded attributes."""

    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict]] = []
        self._in_head = False
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == "head":
            self._in_head = True
        if self._in_head:
            self.tags.append((tag, dict(attrs)))

    def handle_endtag(self, tag):
        if tag == "head":
            self._in_head = False


def _environment() -> Environment:
    from markupsafe import Markup

    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=True)
    env.globals["brand"] = DEFAULT_BRAND
    env.globals["htmx_config"] = Markup(HTMX_CONFIG_JSON)
    return env


def _shell_context(**overrides):
    request = SimpleNamespace(
        url=SimpleNamespace(path="/scans"),
        state=SimpleNamespace(worker_stale=False),
        headers={"HX-Request": "false"},
    )
    return {
        "request": request,
        "navigation": [],
        "user": SimpleNamespace(display_name="Fixture operator"),
        "status_banner": "",
        "capability_banner": "",
        "flash": [],
        **overrides,
    }


def test_the_shell_emits_one_global_config_between_viewport_and_stylesheets():
    source = (TEMPLATES / "base.html.j2").read_text()
    viewport = source.index('<meta name="viewport"')
    config = source.index('<meta name="htmx-config"')
    stylesheet = source.index('<link rel="stylesheet"')
    extra_css = source.index("{% block extra_css %}")
    assert viewport < config < stylesheet < extra_css
    assert source.count('name="htmx-config"') == 1

    tags = Head(_environment().get_template("base.html.j2").render(_shell_context())).tags
    viewport_index = next(i for i, (tag, attrs) in enumerate(tags)
                          if tag == "meta" and attrs.get("name") == "viewport")
    metas = [i for i, (tag, attrs) in enumerate(tags)
             if tag == "meta" and attrs.get("name") == "htmx-config"]
    assert metas == [viewport_index + 1]
    assert json.loads(tags[metas[0]][1]["content"]) == HTMX_CONFIG


def test_the_rule_list_extends_the_management_config_with_error_page_swaps():
    handling = HTMX_CONFIG["responseHandling"]
    assert [rule["code"] for rule in handling] == [
        "204", "[23]..", "422", "403", "404", "500", "503", "[45].."]
    management = {rule["code"]: rule for rule in _HTMX_CONFIG["responseHandling"]}
    by_code = {rule["code"]: rule for rule in handling}
    assert by_code["403"] == management["403"]
    assert by_code["422"] == management["422"]
    assert by_code["[45].."] == management["[45].."]
    for code in ("403", "404", "500", "503"):
        rule = by_code[code]
        assert rule["swap"] is True and rule["error"] is True
        assert rule["target"] == rule["select"] == "#main-content"
        assert rule["swapOverride"] == "outerHTML"


def test_enhanced_forms_no_longer_emits_a_competing_meta():
    template = _environment().get_template("_inventory_ui.html.j2")
    assert "htmx-config" not in str(template.module.enhanced_forms())


def test_error_page_focuses_its_heading_only_for_htmx_requests():
    template = _environment().get_template("error.html.j2")
    context = _shell_context(status=404, message="Page not found.", request_id="fixture-request")

    def render(header: str) -> str:
        request = SimpleNamespace(
            url=SimpleNamespace(path="/scans"), state=SimpleNamespace(worker_stale=False),
            headers={"HX-Request": header},
        )
        return template.render(context | {"request": request})

    assert '<h1 tabindex="-1" autofocus>' in render("true")
    assert '<h1 tabindex="-1"' not in render("false")
