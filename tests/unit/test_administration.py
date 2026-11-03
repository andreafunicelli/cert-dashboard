"""Database-free coverage for the additive Administration GET and create disclosure context."""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI

from app.web import users as users_web


def test_administration_get_uses_only_an_aggregate_of_active_users(monkeypatch):
    app = FastAPI()
    monkeypatch.setattr(users_web, 'install_template_helpers', lambda app: None)
    users_web.register_user_routes(app)
    route = next(route for route in app.routes if route.path == '/administration')
    assert route.methods == {'GET'}
    db = MagicMock()
    db.scalar.return_value = 3
    factory = MagicMock()
    factory.return_value.__enter__.return_value = db
    app.state.factory = factory
    request = SimpleNamespace(app=app)
    render = MagicMock(return_value='rendered')
    monkeypatch.setattr(users_web, '_render', render)
    assert route.endpoint(request) == 'rendered'
    render.assert_called_once_with(request, 'administration.html.j2', active_user_count=3)
    query = str(db.scalar.call_args.args[0])
    assert 'count(*)' in query and '"user".is_active IS true' in query
    assert 'password' not in query and 'totp' not in query
    db.execute.assert_not_called()


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
