"""Repository-only contracts for the Settings -> Branding tab and the custom shell brand.

Every state of ``docs/ui/branding.md`` §"State machine" is rendered here from an explicit fixture:
default, custom saved, staged preview, invalid preview, 409 conflict, 410 expired, unavailable
stored bytes, plus the custom header/sign-in brand. No database, no browser.
"""

import re

from scripts.render_previews import environment, fixtures

UNCHANGED = "Your current logo has not changed."


def preview(name):
    template, context = fixtures()[name]
    return environment().get_template(template).render(context)


def content(html):
    return html.split("<main", 1)[1]


def test_default_state_shows_the_first_party_lockup_and_no_save_or_reset():
    html = preview("settings-branding-default")
    main = content(html)
    assert 'href="/settings?tab=branding" aria-current="page">Branding' in html
    assert "Default logo" in main
    assert "No custom logo. Cert Dashboard’s default logo is in use." in main
    assert '<picture class="branding-lockup">' in main
    assert "/static/branding/lockup.svg" in main
    assert 'action="/settings/branding/preview"' in main
    assert 'enctype="multipart/form-data"' in main
    assert 'name="logo"' in main and 'accept="image/svg+xml,image/png,.svg,.png"' in main
    assert ">Preview logo</button>" in main
    assert "Save logo" not in main
    assert "/settings/branding/reset" not in main and "Reset to default" not in main
    assert "data-settings-draft" not in html
    assert not re.search(r"<form[^>]*\shx-", main)


def test_persistent_help_and_selection_copy_are_present():
    main = content(preview("settings-branding-default"))
    assert (
        "Set the logo shown in navigation and on the sign-in page for everyone. The product name "
        "and browser icon stay Cert Dashboard. Do not upload confidential images: the saved logo is "
        "visible before sign-in." in main
    )
    assert "SVG or PNG, up to 256 KiB. Use a transparent image with a square or wide layout." in main
    assert "Square art at least 48 × 48px; wide art at least 240 × 48px" in main
    assert "For SVG, convert lettering to paths." in main
    assert (
        "Selecting a file does not upload or save it. Choose Preview logo to check it before saving. "
        "Leaving this page discards the preview after 30 minutes." in main
    )


def test_custom_state_shows_the_saved_image_filename_dimensions_and_reset_disclosure():
    main = content(preview("settings-branding-custom"))
    assert "Custom logo" in main
    assert '<img src="/branding/logo?v=' not in main  # the class attribute comes first
    assert 'class="branding-current-image" src="/branding/logo?v=' in main
    assert "&lt;b&gt;team-logo&lt;/b&gt;.svg" in main
    assert "<b>team-logo</b>" not in main
    assert "320 × 80 px" in main and "SVG" in main
    assert '<details class="confirmation branding-reset">' in main
    assert "<summary>Reset to default…</summary>" in main
    assert (
        "Reset to default logo? This removes the custom logo for everyone, including the sign-in "
        "page. You cannot undo this without uploading it again." in main
    )
    assert 'name="confirm" value="RESET"' in main
    assert ">Reset logo</button>" in main
    assert 'href="/settings?tab=branding">Cancel</a>' in main
    assert "data-settings-draft" not in main
    assert not re.search(r"<form[^>]*\shx-", main)


def test_preview_state_keeps_the_current_logo_and_offers_save_and_discard():
    main = content(preview("settings-branding-preview"))
    assert "Preview only. Your current logo has not changed." in main
    assert "Current logo" in main
    assert '<img src="/settings/branding/draft/fixture-draft-token"' in main
    assert 'action="/settings/branding/preview"' in main  # a new candidate can still replace this one
    assert 'action="/settings/branding"' in main and ">Save logo</button>" in main
    assert 'name="draft_token" value="fixture-draft-token"' in main
    assert 'name="base_revision" value="default"' in main
    assert 'action="/settings/branding/discard"' in main and ">Discard preview</button>" in main
    assert main.count('class="branding-surface branding-surface-dark"') == 1
    assert main.count('class="branding-surface branding-surface-light"') == 1
    assert "candidate-logo.svg" in main and "120 × 40 px" in main
    assert "SVG" in main and "2 KiB" in main
    assert "Cert Dashboard" in main  # the persistent product name renders beside both slots


def test_invalid_preview_summary_is_an_autofocused_alert_linked_to_the_file_input():
    main = content(preview("settings-branding-error"))
    summary = re.search(
        r'<div class="form-error" id="branding-error" role="alert" tabindex="-1" autofocus>(.*?)</div>',
        main,
        re.DOTALL,
    )
    assert summary is not None
    assert "This SVG uses unsupported content." in summary[1]
    assert UNCHANGED in summary[1]
    field = re.search(r'<input[^>]*id="f-branding-logo"[^>]*>', main)[0]
    assert 'aria-invalid="true"' in field
    assert 'aria-describedby="branding-logo-help branding-logo-error"' in field
    inline = re.search(r'<p class="form-error" id="branding-logo-error" data-field="logo">(.*?)</p>', main, re.DOTALL)
    assert inline is not None and "This SVG uses unsupported content." in inline[1]
    assert "Save logo" not in main and "/settings/branding/draft/" not in main


def test_conflict_keeps_the_candidate_but_hides_save_and_offers_discard():
    main = content(preview("settings-branding-conflict"))
    assert (
        "Branding changed since you opened this page. Review the current logo and preview your file "
        "again before saving." in main
    )
    assert "/settings/branding/draft/fixture-draft-token" in main
    assert ">Save logo</button>" not in main
    assert ">Preview logo</button>" in main and ">Discard preview</button>" in main


def test_expired_state_asks_for_a_new_file_and_has_no_candidate():
    main = content(preview("settings-branding-expired"))
    assert "Logo preview expired. Choose the file again and select Preview logo." in main
    assert "Save logo" not in main
    assert "/settings/branding/draft/" not in main


def test_unavailable_stored_bytes_fall_back_to_the_default_with_a_warning():
    main = content(preview("settings-branding-unavailable"))
    assert (
        "Custom logo is unavailable. The default logo is being shown. Upload a replacement or reset "
        "to default." in main
    )
    assert "/static/branding/lockup.svg" in main
    assert 'action="/settings/branding/reset"' in main


def test_custom_shell_brand_keeps_the_name_and_the_default_favicon():
    html = preview("shell-custom")
    header = html.split('<header class="site-header">', 1)[1].split("</header>", 1)[0]
    assert '<a class="brand" href="/" aria-label="Cert Dashboard home">' in header
    assert '<img class="brand-custom-lockup" src="/branding/logo?v=' in header
    assert 'alt="" width="120" height="24">' in header
    assert '<span class="brand-custom-name">Cert Dashboard</span>' in header
    assert '<picture class="brand-lockup">' not in header
    assert '<link rel="icon" type="image/svg+xml" href="/static/branding/favicon.svg">' in html
    assert '<link rel="icon" type="image/png" sizes="32x32" href="/static/branding/favicon-32.png">' in html
    assert "/static/pages/branding.css" in html


def test_custom_sign_in_brand_uses_the_wide_auth_slot_and_keeps_the_heading():
    html = preview("login-custom")
    assert '<div class="auth-mark"><img class="auth-mark-custom" src="/branding/logo?v=' in html
    assert 'alt="" width="160" height="48"></div>' in html
    assert html.index('class="auth-mark"') < html.index("<h1>Sign in</h1>")
    assert "Cert Dashboard" in html
