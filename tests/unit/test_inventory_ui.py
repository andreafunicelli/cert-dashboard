"""Shipped-template contracts: no database, preview files or browser required."""

import json
import re
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

import pytest
from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[2]


def macros():
    env = Environment(loader=FileSystemLoader(ROOT / "app/templates"), autoescape=True)
    return env.get_template("_inventory_ui.html.j2").module


@pytest.mark.parametrize(
    "status,days,label,kind",
    [
        ("active", 100, "Valid", "ok"),
        ("active", 20, "Expiring", "warn"),
        ("active", 1, "Expiring", "warn"),
        ("active", -1, "Expired", "danger"),
        ("revoked", 100, "Revoked", "danger"),
        ("superseded", 100, "Superseded", "warn"),
        ("unknown", 100, "Unknown validity", "info"),
    ],
)
def test_certificate_states_have_icon_colour_and_label(status, days, label, kind):
    now = datetime(2026, 10, 30, tzinfo=UTC)
    cert = SimpleNamespace(
        status=SimpleNamespace(value=status),
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=days),
    )
    html = str(macros().certificate_state(cert, now))
    assert label in html and f"badge-{kind}" in html
    assert '<svg class="status-icon"' in html and 'aria-hidden="true"' in html


@pytest.mark.parametrize(
    "status,label",
    [
        ("trusted", "Trusted chain"),
        ("incomplete", "Incomplete chain"),
        (None, "Incomplete chain"),
        ("unchecked", "Chain not verified"),
    ],
)
def test_chain_verdict_does_not_claim_unverified_trust(status, label):
    assert label in str(macros().chain_verdict(status))


@pytest.mark.parametrize(
    "status,label",
    [
        ("ok", "No findings"),
        ("mismatch", "Findings: mismatch"),
        ("expired", "Findings: expired"),
        ("unreachable", "Scan failed"),
        ("error", "Scan failed"),
        (None, "Not scanned"),
    ],
)
def test_scan_execution_failure_is_not_no_findings(status, label):
    html = str(macros().scan_state(status))
    assert label in html and '<svg class="status-icon"' in html


class Text(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.text = []
        self.feed(html)

    def handle_data(self, data):
        self.text.append(data)


def test_grouping_keeps_identifier_copy_text_exact_and_escaped():
    value = "0123456789abcdef" * 4
    html = str(macros().identifier(value))
    assert "".join(Text(html).text) == value
    assert html.count('class="identifier-group"') == 16
    assert 'tabindex="0"' in html
    hostile = str(macros().identifier('<img src=x onerror="bad">'))
    assert "<img" not in hostile and "&lt;" in hostile


def test_vendored_htmx_handles_422_declaratively():
    html = str(macros().enhanced_forms())
    content = re.search(r"content='([^']+)'", html).group(1)
    rules = json.loads(content)["responseHandling"]
    assert next(rule for rule in rules if re.fullmatch(rule["code"], "422")) == {
        "code": "422",
        "swap": True,
        "error": False,
    }
    for status in ("403", "404", "500"):
        rule = next(rule for rule in rules if re.fullmatch(rule["code"], status))
        assert not rule["swap"] and rule["error"]
    assert "responseHandling" in (ROOT / "app/static/htmx.min.js").read_text()


def test_inventory_templates_have_no_inline_scripts_styles_or_unescaped_data():
    templates = ROOT / "app/templates"
    paths = [p for area in ("certificates", "renewals", "scans") for p in (templates / area).glob("*.j2")]
    paths += [
        templates / "import.html.j2",
        templates / "import_progress.html.j2",
        templates / "_inventory_ui.html.j2",
    ]
    for path in paths:
        source = path.read_text()
        assert "<script" not in source and "style=" not in source and "|safe" not in source, path


def test_page_css_reuses_known_tokens_and_shared_controls():
    shared = (ROOT / "app/static/app.css").read_text()
    tokens = set(re.findall(r"--([\w-]+)\s*:", shared))
    for area in ("certificates", "renewals", "import", "scans"):
        css = (ROOT / f"app/static/pages/{area}.css").read_text()
        assert set(re.findall(r"var\(--([\w-]+)\)", css)) <= tokens
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b|\b\d+(?:px|rem)\b", css.replace("719px", ""))
    assert "white-space: nowrap" in shared and "user-select: all" in shared
