"""Per-area stylesheet extension stays inert unless a child overrides it."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader

TEMPLATES = Path(__file__).resolve().parents[2] / "app/templates"
HOOK = "{% block extra_css %}{% endblock %}"


def environment(overrides=None):
    return Environment(
        loader=ChoiceLoader([DictLoader(overrides or {}), FileSystemLoader(TEMPLATES)]),
        autoescape=True,
    )


@pytest.mark.parametrize("page", ["login", "account"])
def test_default_stylesheet_hook_preserves_rendered_bytes(page):
    base = (TEMPLATES / "base.html.j2").read_text()
    assert base.count(HOOK) == 1
    context = {
        "navigation": [],
        "request": SimpleNamespace(url=SimpleNamespace(path=f"/{page}"),
                                   state=SimpleNamespace(worker_stale=False)),
        "user": SimpleNamespace(display_name="Fixture operator") if page == "account" else None,
        "username": "operator",
        "csrf_token": "fixture-only",
        "can_change_password": True,
        "totp_enabled": True,
        "recovery_remaining": 4,
    }
    before = environment({"base.html.j2": base.replace(HOOK, "")})
    after = environment()
    template = f"{page}.html.j2"
    assert after.get_template(template).render(context) == before.get_template(template).render(context)


def test_area_stylesheet_override_follows_shared_stylesheet_in_head():
    link = '<link rel="stylesheet" href="/static/pages/certificates.css">'
    env = environment({
        "area.html.j2": '{% extends "base.html.j2" %}{% block extra_css %}' + link + '{% endblock %}',
    })
    html = env.get_template("area.html.j2").render()
    head = html.split("<head>", 1)[1].split("</head>", 1)[0]
    assert '<link rel="stylesheet" href="/static/app.css">' + link in head
    assert head.index(link) < head.index('<script src="/static/htmx.min.js"')
    assert html.count(link) == 1
