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
    ("/inventory", "Infrastructure", "/inventory"),
    ("/inventory/42/edit", "Infrastructure", "/inventory"),
    ("/servers/42", "Infrastructure", "/servers"),
    ("/bindings/help", "Infrastructure", "/bindings"),
    ("/ssh-keys", "Infrastructure", "/ssh-keys"),
    ("/scans/42", "Operations", "/scans"),
    ("/deploy/fixture", "Operations", "/deploy"),
    ("/deploy/jobs", "Operations", "/deploy/jobs"),
    ("/administration", "Administration", "/administration"),
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


@pytest.mark.parametrize("url, area", [("/certificates", "Certificates"), ("/scans", "Operations")])
@pytest.mark.parametrize("active", [False, True])
def test_disabled_group_entry_keeps_reason_and_cannot_be_activated(url, area, active):
    context = fixtures()["overview"][1]
    reason = "Handler unavailable"
    navigation = [item | {"enabled": False, "reason": reason}
                  if item["url"] == url else item for item in context["navigation"]]
    request = SimpleNamespace(url=SimpleNamespace(path=url if active else "/"),
                              state=SimpleNamespace(worker_stale=False))
    html = overview(navigation=navigation, request=request)
    main = re.search(r'<nav aria-label="Main">(.*?)</nav>', html, re.DOTALL)[1]
    assert f'href="{url}"' not in main
    assert f'aria-disabled="true" title="{reason}">{area}</span>' in main
    mobile = re.search(r'<nav aria-label="All pages">(.*?)</nav>', html, re.DOTALL)[1]
    assert f'href="{url}"' not in mobile
    if active:
        subnav = re.search(r'<nav class="area-navigation".*?</nav>', html, re.DOTALL)[0]
        assert f'href="{url}"' not in subnav
    # A disabled area landing page does not hide its other supported subpages.
    assert 'href="/deploy"' in html
    assert 'href="/certificates/import"' in html


@pytest.mark.parametrize("url, area, leaf, group_href", [
    ("/servers", "Infrastructure", "Servers", "/inventory"),
    ("/settings", "Administration", "Settings", "/administration"),
])
def test_disabled_page_entry_keeps_its_new_group_entry_reachable(url, area, leaf, group_href):
    """Servers and Settings are pages, not group links, since the IA rebuild (§2.1 N2/N3)."""
    context = fixtures()["overview"][1]
    reason = "Handler unavailable"
    navigation = [item | {"enabled": False, "reason": reason}
                  if item["url"] == url else item for item in context["navigation"]]
    request = SimpleNamespace(url=SimpleNamespace(path=url), state=SimpleNamespace(worker_stale=False))
    html = overview(navigation=navigation, request=request)
    main = re.search(r'<nav aria-label="Main">(.*?)</nav>', html, re.DOTALL)[1]
    assert f'href="{url}"' not in main
    assert f'<a href="{group_href}">' in main
    subnav = re.search(r'<nav class="area-navigation".*?</nav>', html, re.DOTALL)[0]
    assert f'href="{url}"' not in subnav
    assert f'<span aria-disabled="true" title="{reason}">{leaf}</span>' in html
    assert f'aria-label="{area} pages"' in subnav


def test_overview_is_one_main_entry_without_an_area_bar():
    request = SimpleNamespace(url=SimpleNamespace(path="/"), state=SimpleNamespace(worker_stale=False))
    html = overview(request=request)
    main = re.search(r'<nav aria-label="Main">(.*?)</nav>', html, re.DOTALL)[1]
    assert '<span class="active-area" aria-current="location"><a href="/">Overview</a></span>' in main
    assert 'aria-current="page"' not in main
    assert '<nav class="area-navigation"' not in html


def test_desktop_main_entries_and_narrow_menu_match_the_ia():
    request = SimpleNamespace(url=SimpleNamespace(path="/"), state=SimpleNamespace(worker_stale=False))
    html = overview(request=request)
    main = re.search(r'<nav aria-label="Main">(.*?)</nav>', html, re.DOTALL)[1]
    assert re.findall(r'<a href="[^"]+">([^<]+)</a>', main) == [
        "Overview", "Certificates", "Infrastructure", "Operations", "Administration"]
    mobile = re.search(r'<nav aria-label="All pages">(.*?)</nav>', html, re.DOTALL)[1]
    for href in ["/", "/certificates", "/certificates/import", "/renewals", "/inventory", "/servers",
                 "/bindings", "/servers#discovery-actions", "/ssh-keys", "/scans", "/deploy",
                 "/deploy/jobs", "/administration", "/users", "/settings", "/audit", "/account"]:
        assert f'href="{href}"' in mobile, href


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
