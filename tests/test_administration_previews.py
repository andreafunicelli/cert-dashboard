"""Administration wayfinding and native user-creation contracts (no database)."""
import re
from types import SimpleNamespace

import pytest

from scripts.render_previews import environment, fixtures


def preview(name, **overrides):
    template, context = fixtures()[name]
    return environment().get_template(template).render(context | overrides)


@pytest.mark.parametrize('path', ['/administration', '/users', '/audit', '/settings', '/account'])
def test_administration_navigation_and_personal_account_name(path):
    request = SimpleNamespace(url=SimpleNamespace(path=path), state=SimpleNamespace(worker_stale=False))
    html = preview('administration', request=request)
    main = re.search(r'<nav aria-label="Main">(.*?)</nav>', html, re.DOTALL)[1]
    assert '<a href="/administration">Administration</a>' in main
    subnav = re.search(r'<nav class="area-navigation".*?</nav>', html, re.DOTALL)[0]
    assert re.findall(r'<a href="([^"]+)">([^<]+)</a>', subnav) == [
        ('/users', 'Users'), ('/audit', 'Audit'), ('/settings', 'Settings'), ('/account', 'My account')]
    assert '<a href="/account">My account</a>' in html.split('class="user-menu"')[1]
    assert '>Account</a>' not in html


@pytest.mark.parametrize('count, label', [(0, '0 users can sign in'), (1, '1 user can sign in'), (12, '12 users can sign in')])
def test_landing_has_live_count_and_direct_creation_link(count, label):
    html = preview('administration', active_user_count=count)
    content = html.split('<main', 1)[1]
    assert label in re.sub(r'<[^>]+>', '', content)
    assert '<header class="page-header">' in content
    assert 'href="/users?create=1#create-heading"' in content
    for path in ['/users', '/audit', '/settings', '/account']:
        assert f'href="{path}"' in content


@pytest.mark.parametrize('name, is_open', [('users', False), ('users-create', True), ('users-create-error', True)])
def test_primary_header_disclosure_contains_single_unchanged_create_form(name, is_open):
    html = preview(name)
    header = html.split('<header class="page-header">', 1)[1].split('</header>', 1)[0]
    details = re.search(r'<details class="user-create"([^>]*)>(.*?)</details>', header, re.DOTALL)
    assert details is not None
    assert ('open' in details[1]) is is_open
    assert '<summary class="button">Create user</summary>' in details[2]
    assert html.count('action="/users"') == 1
    form = re.search(r'<form method="post" action="/users">(.*?)</form>', details[2], re.DOTALL)[1]
    assert re.findall(r'name="([^"]+)"', form) == [
        'csrf_token', 'username', 'email', 'display_name', 'password', 'confirm_password']
    assert 'type="hidden" name="csrf_token"' in form
    assert not re.search(r'type="password"[^>]*value=', form)
    assert 'id="create-heading"' in details[2]
    assert 'style=' not in html and '<script>' not in html


def test_my_account_header_describes_only_personal_security():
    html = preview('account')
    assert '<h1>My account</h1>' in html
    assert 'Your password, your two-factor authentication and your sessions.' in html
