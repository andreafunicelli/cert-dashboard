"""Global HTMX configuration and error-surface contracts (UX-08), without a database.

htmx reads only the *first* ``<meta name="htmx-config">`` it finds. A1 therefore moves the single
configuration into ``base.html.j2`` (sourced from ``app/web/management.py``) so a CSRF refusal, a
missing page or a server error is swapped into ``#main-content`` on every page, not only on the
Slice B management screens.
"""

import json
from html.parser import HTMLParser
from types import SimpleNamespace

from app.web.administration import HTMX_CONFIG
from app.web.management import _HTMX_CONFIG
from scripts.render_previews import environment, fixtures


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


def _pages():
    env = environment()
    for name, (template, context) in fixtures().items():
        if name.startswith("email-"):
            continue  # mail templates do not extend the shell
        yield name, env.get_template(template).render(context)


def test_every_shell_page_emits_the_global_config_first_after_the_viewport():
    for name, html in _pages():
        tags = Head(html).tags
        viewport = next(i for i, (tag, attrs) in enumerate(tags)
                        if tag == "meta" and attrs.get("name") == "viewport")
        metas = [i for i, (tag, attrs) in enumerate(tags)
                 if tag == "meta" and attrs.get("name") == "htmx-config"]
        assert metas == [viewport + 1], name
        before = tags[: metas[0]]
        assert not any(tag == "link" and attrs.get("rel") == "stylesheet" for tag, attrs in before), name
        assert json.loads(tags[metas[0]][1]["content"]) == HTMX_CONFIG, name


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
    template = environment().get_template("_inventory_ui.html.j2")
    assert "htmx-config" not in str(template.module.enhanced_forms())


def test_error_page_focuses_its_heading_only_for_htmx_requests():
    template = environment().get_template("error.html.j2")
    context = fixtures()["error-404"][1]

    def render(header: str) -> str:
        request = SimpleNamespace(
            url=SimpleNamespace(path="/scans"), state=SimpleNamespace(worker_stale=False),
            headers={"HX-Request": header},
        )
        return template.render(context | {"request": request})

    assert '<h1 tabindex="-1" autofocus>' in render("true")
    assert '<h1 tabindex="-1"' not in render("false")
