"""Repository-only contracts for the operations UI and real Jinja fragment rendering."""

import json
from copy import deepcopy
from pathlib import Path

from scripts.render_previews import environment, fixtures
from tests.test_inventory_previews import fragment, rendered
from tests.test_ui_previews import Elements

ROOT = Path(__file__).resolve().parents[1]


def test_guardrail_verdict_and_compliant_active_job_alternative():
    assert 'Guardrails passed' in rendered('deploy-allowed')
    blocked = rendered('deploy-blocked')
    assert 'Deploy blocked' in blocked
    assert 'href="/deploy/fixture-active-job"' in blocked
    assert 'disabled data-start-disabled=' in blocked
    assert 'class="button-destructive"' in rendered('deploy-allowed')
    assert 'name="confirm" value="yes" required' in rendered('deploy-allowed')


def test_failure_precedes_metadata_and_expands_stopping_batch():
    html = rendered('deploy-failure')
    banner = html.split('data-banner="failure"', 1)[1].split('</section>', 1)[0]
    assert 'edge-01.example.test' in banner and 'healthcheck_failed' in banner
    assert 'href="#deploy-controls"' in banner
    assert html.index('data-banner="failure"') < html.index('id="deploy-header"')
    assert 'data-batch="0" open' in html
    assert 'Automatic restoration to' in html
    assert 'Rollback time is not supplied' in html
    assert '/rollback"' not in html
    assert 'name="reason"' in html and 'name="override_reason"' in html


def test_live_controls_and_native_confirmation_keep_methods_csrf_and_hooks():
    for name in ('deploy-allowed', 'deploy-blocked', 'deploy-failure', 'deploy-paused', 'deploy-running', 'settings-smtp'):
        elements = Elements(rendered(name)).elements
        ids = [a['id'] for _, a in elements if 'id' in a]
        assert len(ids) == len(set(ids))
        assert all(a['for'] in ids for t, a in elements if t == 'label' and 'for' in a)
        assert all(a['method'] in ('get', 'post') and a['action'].startswith('/') for t, a in elements if t == 'form')
        assert all(a['type'] == 'hidden' for t, a in elements if t == 'input' and a.get('name') == 'csrf_token')
    html = rendered('deploy-paused')
    assert '/continue"' in html and '/cancel"' in html
    assert '<details class="confirmation" id="deploy-cancel-confirmation" hx-preserve>' in html
    assert 'This does not undo hosts already deployed.' in html
    assert 'hx-trigger="every 2s"' in rendered('deploy-running')
    assert 'hx-trigger="every 2s"' not in rendered('deploy-failure')


def test_settings_and_smtp_fragments_work_without_parent_imports():
    for block, expected in [('panel', 'SMTP'), ('smtp_test_result', 'Authentication refused.')]:
        html = fragment('settings-smtp', block)
        assert expected in html and '<html' not in html and '<script' not in html
    assert 'data-test-status="failed"' in fragment('settings-smtp', 'smtp_test_result')
    assert 'Delivered' in fragment('settings-smtp-succeeded', 'smtp_test_result')
    assert 'hx-trigger="every 2s"' in fragment('settings-smtp-queued', 'smtp_test_result')
    assert 'does not guarantee inbox delivery' in rendered('settings-smtp-succeeded')


def test_error_configuration_is_head_only_and_preserves_server_errors():
    for name in ('settings-smtp', 'deploy-allowed', 'deploy-failure'):
        elements = Elements(rendered(name)).elements
        config = next(a['content'] for t, a in elements if t == 'meta' and a.get('name') == 'htmx-config')
        handling = json.loads(config)['responseHandling']
        assert {'code': '422', 'swap': True, 'error': False} in handling
        assert {'code': '[45]..', 'swap': False, 'error': True} in handling
        assert 'htmx:beforeSwap' not in rendered(name)
    assert 'Without JavaScript, unsaved changes are lost when switching tabs.' in rendered('settings-smtp')


def test_untrusted_values_are_escaped_in_mail_preview_and_progress():
    source, context = fixtures()['deploy-failure']
    context = deepcopy(context)
    context['view'].first_failed_host = '<script>bad</script>'
    assert '&lt;script&gt;bad&lt;/script&gt;' in environment().get_template(source).render(context)
    source, context = fixtures()['email-expiry']
    html = environment().get_template(source).render(context | {'notes': '<img src=x onerror=bad>'})
    assert '&lt;img' in html and '<img' not in html
    assert '<script' not in html and '/static/' not in html


def test_styles_only_use_shared_tokens_and_the_script_is_settings_only():
    for area in ('deploy', 'settings', 'email'):
        css = (ROOT / f'app/static/pages/{area}.css').read_text()
        assert '#' not in css.replace('#deploy', '').replace('#settings', '').replace('#smtp', '')
        assert '@import' not in css and 'http' not in css
    for path in (ROOT / 'app/templates').rglob('*.j2'):
        if path.name != 'settings.html.j2':
            assert '/static/settings.js' not in path.read_text()
    js = (ROOT / 'app/static/settings.js').read_text()
    assert 'innerHTML' not in js and 'eval(' not in js and 'localStorage' not in js
    assert "addEventListener('submit'" not in js
