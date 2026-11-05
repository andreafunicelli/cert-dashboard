"""Repository-only regressions for consistent operations page composition."""

from copy import deepcopy
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from jinja2 import StrictUndefined

from scripts.render_previews import environment, fixtures
from tests.test_inventory_previews import fragment, rendered
from tests.test_stitch_styles import DOM, classes
from tests.test_ui_previews import FormContracts

PAGES = ('server-list', 'server-detail', 'binding-list', 'scan-list', 'scan-findings',
         'deploy-allowed', 'deploy-failure', 'deploy-jobs', 'audit', 'users', 'settings-schedule')


@pytest.mark.parametrize('name', PAGES)
def test_each_area_reuses_one_header_with_purpose_and_one_primary_action(name):
    root = DOM(rendered(name)).root
    headers = [n for n in root.iter('header') if 'page-header' in classes(n)]
    assert len(headers) == 1
    header = headers[0]
    assert len(header.findall('.//h1')) == 1
    assert any('page-subtitle' in classes(n) and ''.join(n.itertext()).strip() for n in header.iter('p'))
    primary = [n for n in header.iter() if (n.tag == 'a' and 'button' in classes(n))
               or (n.tag == 'button' and not {'button-secondary', 'button-destructive'} & set(classes(n)))]
    assert len(primary) == 1
    assert all(n.get('role') != 'menu' for n in header.iter())


@pytest.mark.parametrize('name,path,values', [
    ('server-list', '/servers', {'search': 'edge', 'group': 'a&b', 'active': 'false'}),
    ('binding-list', '/bindings', {'vhost': '<script>', 'match_state': 'key_mismatch', 'certificate_id': '42'}),
    ('scan-list', '/scans', {'search': 'edge', 'status': 'mismatch', 'server_id': '1'}),
    ('audit', '/audit', {'actor': '<script>', 'start': '2026-10-01', 'ip': '192.0.2.1'}),
    ('deploy-jobs', '/deploy/jobs', {'outcome': 'rolled_back', 'type': 'deploy'}),
])
def test_filter_disclosures_keep_one_get_form_and_precise_removable_chips(name, path, values):
    template, context = fixtures()[name]
    values = values | {'page': '3', 'page_size': '50'}
    html = environment().get_template(template).render(context | {'values': values})
    root = DOM(html).root
    details = [n for n in root.iter('details') if 'filter-disclosure' in classes(n)]
    assert len(details) == 1 and 'open' not in details[0].attrib
    forms = [f for f in FormContracts(html).forms if f.get('action') == path and f.get('method') == 'get']
    assert len(forms) == 1
    chips = [n for n in root.iter('a') if 'filter-chip' in classes(n)]
    assert len(chips) == len(values) - 2
    for chip in chips:
        query = parse_qs(urlsplit(chip.get('href')).query)
        removed = set(values) - set(query) - {'page'}
        assert len(removed) == 1
        assert query == {k: [v] for k, v in values.items() if k not in removed | {'page'}}
    assert '<script>' not in html


def test_server_detail_prioritises_state_bindings_history_then_configuration():
    html = rendered('server-detail')
    positions = [html.index(f'id="{name}"') for name in ('server-panel', 'bindings-panel', 'discovery-history', 'actions', 'server-configuration')]
    assert positions == sorted(positions)
    assert 'Discovery state' in rendered('server-list')
    assert 'Last seen / discovery' in rendered('server-list')
    assert 'TLS drift' in rendered('server-list')


def test_scans_are_endpoint_verdicts_not_inline_history_or_certificate_dumps():
    html = rendered('scan-list-verdicts')
    root = DOM(html).root
    table = next(n for n in root.iter('table') if 'scans' in classes(n))
    assert len(table.findall('./thead/tr/th')) == 5
    rows = table.findall('./tbody/tr')
    assert len(rows) == 5
    assert '1 h ago' in html and '2 h ago' in html and 'Not observed' in html
    for row in rows:
        badges = [n for n in row.iter() if 'badge' in classes(n)]
        assert len(badges) == 1 and badges[0].find('svg') is not None
        history = next(n for n in row.iter('a') if n.get('href', '').endswith('#history'))
        assert 'hx-get' not in history.attrib
    assert 'Observed certificate' not in html and 'Observed fingerprint' not in html
    assert 'name="endpoint_id"' in html and 'name="csrf_token"' in html
    assert 'history-drawer' not in html  # history belongs on the detail, not as a list drawer


@pytest.mark.parametrize('delta,label', [(timedelta(seconds=20), 'Less than a minute ago'),
    (timedelta(minutes=4), '4 min ago'), (timedelta(hours=2), '2 h ago'),
    (timedelta(days=3), '3 d ago'), (timedelta(minutes=-2), 'Time ahead of server clock')])
def test_observation_age_uses_request_clock_and_does_not_mask_future_times(delta, label):
    template, context = fixtures()['scan-list']
    context = deepcopy(context)
    context['page'].items[0].checked_at = context['now'] - delta
    assert label in environment().get_template(template).render(context)


@pytest.mark.parametrize('tab,canonical,forms', [
    ('schedule', 'schedule', {'/settings/schedule', '/settings/scanning'}),
    ('scanning', 'schedule', {'/settings/schedule', '/settings/scanning'}),
    ('maintenance', 'maintenance', {'/settings/general', '/settings/maintenance/prune'}),
    ('general', 'maintenance', {'/settings/general', '/settings/maintenance/prune'}),
])
def test_consolidated_settings_tabs_preserve_independent_native_save_contracts(tab, canonical, forms):
    html = rendered('settings-' + tab)
    root = DOM(html).root
    nav = next(n for n in root.iter('nav') if n.get('aria-label') == 'Settings sections')
    links = nav.findall('.//a')
    assert len(links) == 9
    assert [n.get('href') for n in links if n.get('aria-current') == 'page'] == ['/settings?tab=' + canonical]
    actual = {form['action'] for form in FormContracts(html).forms if form.get('method') == 'post'}
    assert actual == forms
    for form in FormContracts(html).forms:
        assert any(field.get('name') == 'csrf_token' for field in form['inputs'])
    ids = [n.get('id') for n in root.iter() if n.get('id')]
    assert len(ids) == len(set(ids))
    assert any(n.get('data-settings-tab-draft') == tab for n in nav.iter())
    assert f'id="settings-panel" data-tab="{tab}"' in html
    assert 'Without JavaScript, unsaved changes are lost when switching tabs.' in html
    assert 'saving one does not apply the other' in html
    assert len([n for n in root.iter('section') if n.get('data-settings-section')]) == 2


def test_grouped_422_fragment_keeps_field_error_and_sibling_form():
    html = fragment('settings-scanning', 'panel', errors={'timeout_seconds': ['must be between 1 and 60']})
    assert 'data-field="timeout_seconds" role="alert"' in html
    assert 'must be between 1 and 60' in html
    assert 'action="/settings/schedule"' in html and 'action="/settings/scanning"' in html
    assert '<html' not in html


def test_new_previews_render_with_strict_fixture_data_and_settings_header_targets_real_form():
    env = environment()
    env.undefined = StrictUndefined
    for name in ('scan-list-verdicts', 'scan-list-empty', 'deploy-jobs', 'deploy-jobs-empty', 'settings-schedule', 'settings-general', 'settings-maintenance'):
        template, context = fixtures()[name]
        root = DOM(env.get_template(template).render(context)).root
        ids = {n.get('id') for n in root.iter() if n.get('id')}
        assert all(n.get('form') in ids for n in root.iter('button') if n.get('form'))
