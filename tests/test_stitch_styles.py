"""Repository-only CSS/DOM regressions on real Jinja list fixtures, no browser/DB dependency.

The small evaluator below deliberately supports only the shared row component's
selector grammar. It evaluates selectors against the rendered DOM and cascades
its equal-specificity rules in source order; it is not a general CSS engine.
"""

import re
from copy import deepcopy
from html.parser import HTMLParser
from itertools import permutations
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement

import pytest

from scripts.render_previews import environment, fixtures
from tests.unit.test_ui_foundation import theme_palettes

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "app/static/app.css").read_text()


class DOM(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.root = Element("document")
        self.stack = [self.root]
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = SubElement(self.stack[-1], tag, {k: v or "" for k, v in attrs})
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        SubElement(self.stack[-1], tag, {k: v or "" for k, v in attrs})

    def handle_endtag(self, tag):
        if self.stack[-1].tag == tag:
            self.stack.pop()

    def handle_data(self, data):
        node = self.stack[-1]
        node.text = (node.text or "") + data


def rendered(name, context=None):
    template, defaults = fixtures()[name]
    return DOM(environment().get_template(template).render(defaults if context is None else context)).root


def classes(node):
    return node.get("class", "").split()


def row_paint(row, palette):
    """Match the shipped :has branches, cascade state, and paint the leading td."""
    state, paint = None, None
    rules = re.findall(r"(tbody\s*>\s*tr:has\([^{}]+)\{([^{}]+)\}", CSS)
    assert rules, "shared status-row component must exist"
    for selector, body in rules:
        match = re.fullmatch(r"tbody > tr:has\((.+)\)( > td:first-child)?\s*", selector)
        assert match, f"unsupported component selector: {selector}"
        branches = match[1].split(",")
        matches = []
        for branch in branches:
            condition = re.fullmatch(r"\s*> td \.([\w-]+)\s*", branch)
            assert condition, f"unsupported :has branch: {branch}"
            matches.append(any(condition[1] in classes(node) for td in row.findall("td") for node in td.iter() if node is not td))
        if not any(matches):
            continue
        value = re.search(r"--row-state:\s*var\(--([\w-]+)\)", body)
        if value:
            state = palette[value[1]]
        if match[2]:
            shadow = re.search(r"box-shadow:\s*([^;]+);", body)
            assert shadow and state is not None
            paint = shadow[1].replace("var(--status-width)", palette["status-width"]).replace("var(--row-state)", state)
    return paint


@pytest.mark.parametrize("theme", [0, 1], ids=["dark", "light"])
@pytest.mark.parametrize("name,expected", [
    ("certificate-list", ["warn", "ok", "danger", "danger", "text-muted"]),
    ("server-list", ["warn", "danger", "text-muted", "warn"]),
    ("binding-list", ["warn", "ok", "danger", "text-muted"]),
    ("scan-list", ["danger"]),
])
def test_shared_bar_matches_real_list_rows(name, expected, theme):
    root = rendered(name)
    rows = root.findall(".//tbody/tr")
    palette = theme_palettes(CSS)[theme]
    assert len(rows) == len(expected)
    for row, severity in zip(rows, expected, strict=True):
        assert row_paint(row, palette) == f"inset {palette['status-width']} 0 {palette[severity]}"
        badges = [n for n in row.iter() if "badge" in classes(n)]
        assert badges and all(b.find("svg") is not None and "".join(b.itertext()).strip() for b in badges)


@pytest.mark.parametrize("theme", [0, 1], ids=["dark", "light"])
@pytest.mark.parametrize("status,attention,drift,expected", [
    (None, 0, 0, "text-muted"),
    ("ok", 0, 0, "ok"),
    ("ok", 1, 0, "warn"),  # warning beats OK regardless of badge DOM order
    ("failed", 1, 1, "danger"),  # danger beats both warnings
    (None, 0, 1, "warn"),  # warning beats unknown fallback
])
def test_status_precedence_uses_actual_server_observations(status, attention, drift, expected, theme):
    _, context = fixtures()["server-list"]
    context = deepcopy(context)
    seed = context["page"].items[0]
    seed.last_discovery_status, seed.attention_count, seed.mismatch_count = status, attention, drift
    context["page"].items = [seed]
    row = rendered("server-list", context).find(".//tbody/tr")
    assert row is not None
    palette = theme_palettes(CSS)[theme]
    for cells in permutations(list(row)):
        row[:] = cells
        assert row_paint(row, palette) == f"inset {palette['status-width']} 0 {palette[expected]}"


@pytest.mark.parametrize("theme", [0, 1], ids=["dark", "light"])
@pytest.mark.parametrize("severities,expected", [
    (["text-muted", "ok"], "ok"),
    (["text-muted", "ok", "warn"], "warn"),
    (["text-muted", "ok", "warn", "danger"], "danger"),
])
def test_all_severities_compete_independently_of_badge_order(theme, severities, expected):
    rows = rendered("certificate-list").findall(".//tbody/tr")
    badges = {state: next(n for n in rows[index].iter() if "badge" in classes(n))
              for state, index in [("warn", 0), ("ok", 1), ("danger", 2), ("text-muted", 4)]}
    palette = theme_palettes(CSS)[theme]
    for order in permutations(severities):
        row = Element("tr")
        cell = SubElement(row, "td")
        for state in order:
            cell.append(deepcopy(badges[state]))
        assert row_paint(row, palette) == f"inset {palette['status-width']} 0 {palette[expected]}"


def test_unbadged_rows_are_not_painted():
    palette = theme_palettes(CSS)[0]
    for row in rendered("audit").findall(".//tbody/tr"):
        assert row_paint(row, palette) is None


@pytest.mark.parametrize("name,table_class,columns", [
    ("certificate-list", "certificates", [2]),
    ("server-list", "servers", [4]),
    ("audit", "audit", [0]),
    ("scan-list", "scans", [3]),
    ("scan-findings", None, [0]),
    ("server-detail", "discovery-history", [0]),
])
def test_date_column_headers_and_cells_align_in_rendered_lists(name, table_class, columns):
    tables = rendered(name).findall(".//table")
    table = next(t for t in tables if table_class is None or table_class in classes(t))
    headers = table.findall("./thead/tr/th")
    rows = [r for r in table.findall("./tbody/tr") if len(r.findall("td")) == len(headers)]
    assert rows
    for index in columns:
        assert "numeric" in classes(headers[index]), (name, "header", index)
        for row in rows:
            cell = row.findall("td")[index]
            assert "numeric" in classes(cell), (name, "cell", index)
        assert any(row.findall("td")[index].find(".//time") is not None for row in rows)
    if name == "server-list":
        assert rows[0].findall("td")[4].find("p/time") is not None, "exercise nested dates, not just td > time"
    # The rendered hooks must consume the shipped alignment and tabular type rules.
    assert re.search(r"\.numeric\s*\{\s*text-align:\s*right;", CSS)
    assert re.search(r"[^{}]*\.numeric[^{}]*\{[^{}]*font-family:\s*var\(--font-mono\);[^{}]*font-variant-numeric:\s*tabular-nums;", CSS)
