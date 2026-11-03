"""Repository-only Worker template and empty-state link contracts."""
from copy import deepcopy

import pytest

from scripts.render_previews import environment, fixtures
from tests.test_stitch_styles import DOM, classes


@pytest.mark.parametrize('name', ['settings-worker', 'settings-worker-empty', 'settings-worker-mounted',
                                  'settings-worker-error', 'settings-worker-saved'])
def test_worker_has_blank_write_only_fields_and_native_forms(name):
    template, context = fixtures()[name]
    html = environment().get_template(template).render(context)
    root = DOM(html).root
    assert not any(n.get('style') for n in root.iter())
    assert all(n.get('src') for n in root.iter('script'))
    assert all(not ''.join(n.itertext()).strip() for n in root.iter('textarea'))
    secrets = [n for n in root.iter() if 'data-settings-secret' in n.attrib]
    assert len(secrets) == 4
    assert all(not n.get('value') and n.get('autocomplete') == 'off' for n in secrets)
    assert {n.get('type') for n in secrets if n.tag == 'input'} == {'file', 'password'}
    forms = [n for n in root.iter('form') if n.get('action', '').startswith('/settings/worker/')]
    assert all(n.get('method') == 'post' for n in forms)
    assert all(any(i.get('name') == 'csrf_token' for i in n.iter('input')) for n in forms)
    removals = [n for n in root.iter('details') if 'confirmation' in classes(n)]
    assert len(removals) == (3 if name not in ('settings-worker-empty', 'settings-worker-mounted') else 0)
    if removals:
        assert 'discovery and deploy stop working until a key is set' in ''.join(removals[0].itertext())
    assert 'data-settings-tab-draft="worker"' in html
    assert 'form="settings-form-worker"' not in html
    assert 'Without JavaScript, leaving this page loses unsaved input without a warning.' in html


def test_banner_links_directly_to_worker_and_keeps_critical_semantics():
    template, context = fixtures()['settings-worker-empty']
    html = environment().get_template(template).render(context)
    banner = next(n for n in DOM(html).root.iter('aside') if n.get('data-banner') == 'capability')
    assert banner.get('role') == 'alert' and 'banner-critical' in classes(banner)
    assert banner.find('a').get('href') == '/settings?tab=worker'
    assert 'Configure it in Settings → Worker.' in ''.join(banner.itertext())
    other = environment().get_template(template).render(context | {'capability_banner': 'Missing known_hosts'})
    banner = next(n for n in DOM(other).root.iter('aside') if n.get('data-banner') == 'capability')
    assert banner.find('a').get('href') == '/settings?tab=status'


def test_unknown_secret_fields_in_context_never_render_even_in_422_fragment():
    template, context = fixtures()['settings-worker-error']
    context = deepcopy(context)
    marker = 'DO-NOT-RENDER-PRIVATE-MATERIAL-123'
    context['values'] = {'private_key': marker, 'vault_password': marker, 'inventory_token': marker}
    for state in context['worker_credentials'].values():
        state.value = marker
    env = environment()
    html = env.get_template(template).render(context)
    fragment = ''.join(env.get_template(template).blocks['panel'](env.get_template(template).new_context(context)))
    assert marker not in html + fragment
    assert 'this is a public key' in fragment
    assert context['worker_credentials']['worker.ssh_private_key'].fingerprint_sha256 in html


def test_metadata_is_autoescaped():
    template, context = fixtures()['settings-worker']
    context = deepcopy(context)
    context['worker_credentials']['worker.ssh_private_key'].updated_by = '<script>unsafe</script>'
    html = environment().get_template(template).render(context)
    assert '<script>unsafe</script>' not in html and '&lt;script&gt;unsafe&lt;/script&gt;' in html
