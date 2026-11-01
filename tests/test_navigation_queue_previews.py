"""Real-template regressions for the native shell and task-first landing page."""
import re
from types import SimpleNamespace

import pytest

from scripts.render_previews import environment, fixtures


def overview(**overrides):
    template, context = fixtures()["overview"]
    return environment().get_template(template).render(context | overrides)


@pytest.mark.parametrize("path, area, leaf", [
    ("/certificates", "Certificates", "/certificates"),
    ("/certificates/42", "Certificates", "/certificates"),
    ("/certificates/import", "Certificates", "/certificates/import"),
    ("/renewals/fixture", "Certificates", "/renewals"),
    ("/servers/42", "Infrastructure", "/servers"),
    ("/bindings/help", "Infrastructure", "/bindings"),
    ("/scans/42", "Operations", "/scans"),
    ("/deploy/fixture", "Operations", "/deploy"),
    ("/deploy/jobs", "Operations", "/deploy/jobs"),
    ("/users", "Administration", "/users"),
    ("/audit", "Administration", "/audit"),
    ("/settings", "Administration", "/settings"),
    ("/account", "Administration", "/account"),
])
def test_area_and_exact_page_are_marked_without_rewriting_anchors(path, area, leaf):
    html = overview(request=SimpleNamespace(url=SimpleNamespace(path=path), state=SimpleNamespace(worker_stale=False)))
    main = re.search(r'<nav aria-label="Main">(.*?)</nav>', html, re.DOTALL)[1]
    assert 'aria-current="location"><a href=' in main
    assert f'>{area}</a>' in main
    subnav = re.search(r'<nav class="area-navigation".*?</nav>', html, re.DOTALL)[0]
    current = re.findall(r'<span aria-current="page"><a href="([^"]+)">', subnav)
    assert current == [leaf]
    assert f'aria-label="{area} pages"' in subnav
    assert '<details class="mobile-navigation">' in html
    assert '<summary>Menu' in html
    assert '/servers#discovery-actions' in html


def test_disabled_capability_keeps_reason_and_cannot_be_activated():
    context = fixtures()["overview"][1]
    navigation = [item | {"enabled": False, "reason": "Scan handler unavailable"}
                  if item["url"] == "/scans" else item for item in context["navigation"]]
    html = overview(navigation=navigation)
    assert '<span aria-disabled="true" title="Scan handler unavailable">Scans</span>' in html


def test_attention_is_at_most_four_rows_with_exact_count_destinations():
    html = overview()
    table = html.split('<table class="work-queue">', 1)[1].split('</table>', 1)[0]
    assert table.count('<tr>') == 5  # one header, four work rows
    for href in [
        '/certificates?expiry=expired&amp;status=active',
        '/certificates?expiry=lt7&amp;status=active', '/scans?status=mismatch',
        '/deploy/jobs?type=deploy&amp;outcome=failed',
        '/deploy/jobs?type=deploy&amp;outcome=rolled_back',
    ]:
        assert f'href="{href}"' in table
    assert '<td class="numeric">3</td>' in table  # 2 failed + 1 rolled back, disjoint
    for href in ['/renewals?state=awaiting_certificate', '/deploy/jobs?type=scan&amp;outcome=running',
                 '/deploy/jobs?type=deploy&amp;outcome=running']:
        assert f'href="{href}"' in html
    assert html.count('data-status-strip="true"') == 1


def test_clear_queue_is_calm_even_with_inventory_and_old_failures():
    _, context = fixtures()["overview"]
    html = overview(queue={key: 0 for key in context['queue']})
    assert 'Nothing needs attention in the work queue.' in html
    assert '<table class="work-queue">' not in html
    assert 'Get started' not in html
    assert 'Recent failures' in html  # retained diagnostic history, not queue counts
    assert 'class="filter-disclosure overview-details"' in html


def test_queue_count_is_not_derived_from_ten_recent_jobs():
    _, context = fixtures()["overview"]
    html = overview(queue=context['queue'] | {'deploy_jobs_failed': 150, 'deploy_jobs_rolled_back': 7},
                    snapshot=context['snapshot'] | {'recent_jobs': []})
    assert '<td class="numeric">157</td>' in html
    assert 'Review failed (<span class="mono">150</span>)' in html
    assert 'Review rolled back (<span class="mono">7</span>)' in html
