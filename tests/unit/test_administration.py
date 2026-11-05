"""Database-free coverage for the Administration hub and the create disclosure context."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI

from app.web import administration as administration_web
from app.web import users as users_web


def test_administration_get_renders_the_hub_context(monkeypatch):
    app = FastAPI()
    app.state.templates = SimpleNamespace(env=SimpleNamespace(globals={}))
    monkeypatch.setattr(administration_web, "install_template_helpers", lambda app: None)
    administration_web.register_administration_routes(app)
    route = next(route for route in app.routes if route.path == '/administration')
    assert route.methods == {'GET'}
    render = MagicMock(return_value='rendered')
    monkeypatch.setattr(administration_web, '_render', render)
    context = {'setup': 'fixture-setup', 'groups': ['fixture-group']}
    monkeypatch.setattr(administration_web, '_hub_context', lambda request: context)
    request = SimpleNamespace(app=app)
    assert route.endpoint(request) == 'rendered'
    render.assert_called_once_with(request, 'administration.html.j2', **context)


def test_users_module_no_longer_owns_the_administration_route(monkeypatch):
    app = FastAPI()
    monkeypatch.setattr(users_web, 'install_template_helpers', lambda app: None)
    users_web.register_user_routes(app)
    assert '/administration' not in {route.path for route in app.routes}


@pytest.mark.parametrize('url, expected', [
    ('https://git.example.test/team/inventory.git', 'https://git.example.test/team/inventory.git'),
    ('https://user:secret@git.example.test/team/inventory.git', 'https://git.example.test/team/inventory.git'),
    ('https://user:secret@git.example.test:8443/team/inventory.git?token=secret#frag',
     'https://git.example.test:8443/team/inventory.git'),
])
def test_repository_status_never_exposes_credentials(url, expected):
    status = administration_web._redacted_repository(url, 'main')
    assert status == f'{expected} @ main'
    assert 'secret' not in status


def test_status_fragments_escape_text_once_and_keep_trusted_links():
    assert str(administration_web._status('a & b')) == 'a &amp; b'
    link = administration_web._link('Add a host', '/inventory')
    assert str(administration_web._status('No hosts yet · ', link)) == (
        'No hosts yet · <a href="/inventory">Add a host</a>'
    )


@pytest.mark.parametrize('query, values, expected', [
    ({}, None, False), ({'create': '1'}, None, True), ({'create': '0'}, None, False),
    ({}, {}, True), ({}, {'username': 'existing'}, True),
])
def test_create_opens_for_deep_link_and_validation_retry_only(monkeypatch, query, values, expected):
    factory = MagicMock()
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(factory=factory)),
        state=SimpleNamespace(session=SimpleNamespace(user_id=1, csrf_token='fixture-csrf')),
        query_params=query,
    )
    monkeypatch.setattr(users_web, 'display_timezone', lambda db: 'UTC')
    monkeypatch.setattr(users_web, '_listing', lambda request: [])
    render = MagicMock(return_value='rendered')
    monkeypatch.setattr(users_web, '_render', render)
    assert users_web._page(request, values=values) == 'rendered'
    assert render.call_args.kwargs['create_open'] is expected
    assert render.call_args.kwargs['csrf_token'] == 'fixture-csrf'
    assert set(render.call_args.kwargs['values']) == {'username', 'email', 'display_name'}
