"""Administration hub and native user-creation contracts (no database)."""
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
        ('/administration', 'Administration'), ('/users', 'Users'), ('/settings', 'Settings'),
        ('/audit', 'Audit'), ('/account', 'My account')]
    assert '<a href="/account">My account</a>' in html.split('class="user-menu"')[1]
    assert '<a href="/administration">Administration</a>' in html.split('class="user-menu"')[1]
    assert '>Account</a>' not in html


HUB_ROUTES = [
    '/users', '/account', '/inventory', '/settings?tab=inventory', '/settings?tab=worker', '/ssh-keys',
    '/settings?tab=smtp', '/settings?tab=alerts', '/settings?tab=deployment', '/settings?tab=schedule',
    '/settings?tab=trust', '/settings?tab=status', '/settings?tab=maintenance', '/audit',
]


def test_hub_lists_every_entry_with_a_server_side_status_and_no_form():
    html = preview('administration')
    content = html.split('<main', 1)[1]
    for href in HUB_ROUTES:
        assert f'href="{href}"' in content, href
    assert '<form' not in content and '<script' not in content and 'style="' not in content
    for group in ['People and access', 'Servers and access', 'Alerts and email',
                  'Operations policy', 'System']:
        assert group in content
    for status in ['1 active users · 0 inactive', '12 active hosts (4 manual, 8 repository)',
                   'ssh://git@example.test/inventory.git @ main', 'SSH key: configured',
                   '0 trusted in the dashboard · Mounted known_hosts: absent', 'Configured',
                   'Thresholds: 60, 30, 14, 7, 1, 0 days', 'Batch 10% · concurrency 5',
                   'Nightly discovery 01:00', '0 warnings', 'Job retention: 90 days']:
        assert status in content, status


def test_hub_empty_states_offer_the_next_action():
    html = preview('administration-empty')
    content = html.split('<main', 1)[1]
    assert 'No hosts yet' in content and '<a href="/inventory">Add a host</a>' in content
    assert 'Not configured — optional' in content
    assert 'SSH key: missing · Vault password: not set · Git token: not set' in content
    assert 'href="/settings?tab=inventory"' in content


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
