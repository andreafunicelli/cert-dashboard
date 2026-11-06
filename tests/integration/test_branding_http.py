"""A2b: Settings → Branding over the real HTTP stack and PostgreSQL (``docs/ui/branding.md``).

These tests drive the complete preview → save → discard → reset state machine, every error row of
the normative copy table with its status code, the CSRF-before-parsing rule, the authorization gates
and the shell/sign-in resolver. Integration tests run in CI (the Hermes container has no Docker).
"""

import re
import struct
import zlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.models import AuditLog, BrandingAsset, BrandingDraft
from app.services.branding_image import validate_logo
from tests.integration.conftest import create_login_user

SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
    b'<path d="M0 0 L10 10 Z" fill="#4cd7f6"/></svg>'
)
OTHER_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
    b'<rect width="24" height="24" fill="#006579"/></svg>'
)
UNSAFE_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
    b'<script>alert(1)</script><path d="M0 0 L10 10 Z"/></svg>'
)
UNCHANGED = "Your current logo has not changed."
DEFAULT_LOCKUP = '<picture class="brand-lockup">'
TOO_LARGE = "Logo is too large. Choose an SVG or PNG no larger than 256 KiB."
CONFLICT = (
    "Branding changed since you opened this page. Review the current logo and preview your file "
    "again before saving."
)
EXPIRED = "Logo preview expired. Choose the file again and select Preview logo."


def png(width: int, height: int, seed: int = 0) -> bytes:
    rows = b"".join(b"\x00" + bytes([(seed + row) % 256]) * (width * 4) for row in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(rows))
        + _chunk(b"IEND", b"")
    )


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


@pytest.fixture
def web_factory(queue_factory):
    """A private, migrated database per test: branding and audit rows are committed by design."""
    return queue_factory


@pytest.fixture
def web_user(web_factory):
    return create_login_user(web_factory, "admin")


@pytest.fixture
def csrf(signed_in):
    return signed_in.fixture_csrf


@pytest.fixture
def branding_page(signed_in):
    response = signed_in.get("/settings?tab=branding")
    assert response.status_code == 200
    return response.text


def _preview(client, csrf, data=SVG, filename="logo.svg", content_type="image/svg+xml"):
    return client.post(
        "/settings/branding/preview",
        data={"csrf_token": csrf},
        files={"logo": (filename, data, content_type)},
        follow_redirects=False,
    )


def _save(client, csrf, token, base_revision):
    return client.post(
        "/settings/branding",
        data={"csrf_token": csrf, "draft_token": token, "base_revision": base_revision},
        follow_redirects=False,
    )


def _discard(client, csrf, token):
    return client.post(
        "/settings/branding/discard",
        data={"csrf_token": csrf, "draft_token": token},
        follow_redirects=False,
    )


def _reset(client, csrf, base_revision, confirm="RESET"):
    return client.post(
        "/settings/branding/reset",
        data={"csrf_token": csrf, "confirm": confirm, "base_revision": base_revision},
        follow_redirects=False,
    )


def _hidden(html: str, name: str) -> str:
    return re.search(rf'name="{name}" value="([^"]+)"', html).group(1)


def _draft_token(html: str) -> str:
    return _hidden(html, "draft_token")


def _stanched(factory):
    revision = _asset_revision(factory)
    assert revision != "default"
    return revision


def _asset_revision(factory) -> str:
    with factory() as db:
        asset = db.get(BrandingAsset, 1)
        return "default" if asset is None else asset.sha256


def _drafts(factory):
    """Open (unconsumed) candidates only: a saved draft leaves a 30-minute receipt behind."""
    with factory() as db:
        return (
            db.scalar(
                select(func.count())
                .select_from(BrandingDraft)
                .where(BrandingDraft.consumed_at.is_(None))
            )
            or 0
        )


def _audits(factory, action):
    with factory() as db:
        return db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == action)) or 0


def _login_page(client):
    return client.get("/login")


def _second_client(web_app, web_factory, clock, username="second-admin"):
    from app.auth.sessions import issue_session

    user = create_login_user(web_factory, username)
    with web_factory.begin() as db:
        session = issue_session(db, user.id, clock(), "192.0.2.150", "fixture-browser")
    client = TestClient(web_app, base_url="https://testserver", client=("192.0.2.150", 4000))
    client.__enter__()
    client.cookies.set("cd_session", session.id, domain="testserver.local", path="/")
    client.fixture_csrf = session.csrf_token
    return client


# --- default, preview, save, reset ----------------------------------------------------------------


def test_default_state_shows_the_default_identity_without_save_or_reset(signed_in, branding_page):
    html = branding_page
    assert 'action="/settings/branding/preview"' in html
    assert 'enctype="multipart/form-data"' in html
    assert "Default logo" in html
    assert "No custom logo. Cert Dashboard’s default logo is in use." in html
    assert DEFAULT_LOCKUP in html
    assert ">Preview logo</button>" in html
    assert "Save logo" not in html
    assert "/settings/branding/reset" not in html
    assert "data-settings-draft" not in html
    assert 'aria-current="page">Branding' in html
    assert "no-store" in signed_in.get("/settings?tab=branding").headers["cache-control"]


def test_valid_preview_stages_a_candidate_without_touching_the_shell(
    signed_in, csrf, web_factory, branding_page
):
    response = _preview(signed_in, csrf)
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=branding"
    assert _asset_revision(web_factory) == "default"

    home = signed_in.get("/")
    assert DEFAULT_LOCKUP in home.text
    assert "/branding/logo?v=" not in home.text

    page = signed_in.get("/settings?tab=branding").text
    assert "Preview only. Your current logo has not changed." in page
    assert "Current logo" in page
    token = _draft_token(page)
    assert f"/settings/branding/draft/{token}" in page
    assert 'action="/settings/branding"' in page and ">Save logo</button>" in page
    assert 'action="/settings/branding/discard"' in page and ">Discard preview</button>" in page
    assert "logo.svg" in page and "24 × 24 px" in page and "SVG" in page and "1 KiB" in page
    assert _hidden(page, "base_revision") == "default"
    assert 'action="/settings/branding/preview"' in page  # a new candidate can replace this one

    draft = signed_in.get(f"/settings/branding/draft/{token}")
    canonical = validate_logo("logo.svg", "image/svg+xml", SVG).content
    assert draft.status_code == 200 and draft.content == canonical
    assert draft.headers["content-type"].split(";")[0] == "image/svg+xml"
    assert draft.headers["cache-control"] == "no-store"
    assert draft.headers["x-content-type-options"] == "nosniff"
    assert draft.headers["content-disposition"] == 'inline; filename="logo.svg"'
    assert "sandbox" in draft.headers["content-security-policy"]


def test_save_updates_header_and_sign_in_but_not_favicon_or_product_name(
    client, signed_in, csrf, web_factory, branding_page
):
    assert _preview(signed_in, csrf).status_code == 303
    page = signed_in.get("/settings?tab=branding").text
    saved = _save(signed_in, csrf, _draft_token(page), _hidden(page, "base_revision"))
    assert saved.status_code == 303
    revision = _asset_revision(web_factory)
    assert revision != "default"

    flash = signed_in.get("/settings?tab=branding").text
    assert "Logo saved. It is now shown in navigation and on the sign-in page." in flash
    assert "Custom logo" in flash and f"/branding/logo?v={revision}" in flash

    home = signed_in.get("/").text
    header = home.split('<header class="site-header">', 1)[1].split("</header>", 1)[0]
    assert f'src="/branding/logo?v={revision}"' in header
    assert '<span class="brand-custom-name">Cert Dashboard</span>' in header
    assert DEFAULT_LOCKUP not in header
    assert 'href="/static/branding/favicon.svg"' in home
    assert 'href="/static/branding/favicon-32.png"' in home
    assert "<title>Overview · Cert Dashboard</title>" in home

    login = _login_page(client).text
    assert f'/branding/logo?v={revision}' in login
    assert '<img class="auth-mark-custom"' in login
    assert 'alt="" width="160" height="48"' in login
    assert "<h1>Sign in</h1>" in login
    assert "Sign in · Cert Dashboard" in login


def test_reset_restores_the_default_lockup_everywhere(signed_in, csrf, web_factory, branding_page):
    _preview(signed_in, csrf)
    page = signed_in.get("/settings?tab=branding").text
    _save(signed_in, csrf, _draft_token(page), "default")
    revision = _asset_revision(web_factory)
    page = signed_in.get("/settings?tab=branding").text
    assert f'name="base_revision" value="{revision}"' in page
    assert ">Reset logo</button>" in page

    response = _reset(signed_in, csrf, revision)
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=branding"
    after = signed_in.get("/settings?tab=branding").text
    assert "Default logo restored." in after
    assert _asset_revision(web_factory) == "default"
    assert DEFAULT_LOCKUP in signed_in.get("/").text
    assert "/branding/logo?v=" not in signed_in.get("/").text
    assert _login_page(signed_in).text.count("auth-mark-custom") == 0


def test_default_state_reset_is_a_harmless_noop(signed_in, csrf, web_factory):
    response = _reset(signed_in, csrf, "default")
    assert response.status_code == 303
    assert "Default logo restored." in signed_in.get("/settings?tab=branding").text
    assert _asset_revision(web_factory) == "default"


def test_png_preview_and_save(signed_in, csrf, web_factory):
    response = _preview(signed_in, csrf, png(4, 4), "logo.png", "image/png")
    assert response.status_code == 303
    page = signed_in.get("/settings?tab=branding").text
    assert "PNG" in page and "4 × 4 px" in page
    token = _draft_token(page)
    draft = signed_in.get(f"/settings/branding/draft/{token}")
    assert draft.status_code == 200
    assert draft.headers["content-type"].split(";")[0] == "image/png"
    assert draft.content.startswith(b"\x89PNG\r\n\x1a\n")

    assert _save(signed_in, csrf, token, "default").status_code == 303
    served = signed_in.get("/branding/logo")
    assert served.status_code == 200
    assert served.headers["content-type"].split(";")[0] == "image/png"
    assert served.headers["content-disposition"] == 'inline; filename="logo.png"'
    assert f"/branding/logo?v={_asset_revision(web_factory)}" in signed_in.get("/").text


def test_discard_deletes_the_candidate_and_keeps_the_current_logo(signed_in, csrf, web_factory):
    _preview(signed_in, csrf, SVG, "first.svg")
    page = signed_in.get("/settings?tab=branding").text
    _save(signed_in, csrf, _draft_token(page), "default")
    revision = _asset_revision(web_factory)

    _preview(signed_in, csrf, OTHER_SVG, "second.svg")
    page = signed_in.get("/settings?tab=branding").text
    token = _draft_token(page)
    response = _discard(signed_in, csrf, token)
    assert response.status_code == 303
    assert "Preview discarded. Your current logo has not changed." in signed_in.get("/settings?tab=branding").text
    assert _drafts(web_factory) == 0
    assert signed_in.get(f"/settings/branding/draft/{token}").status_code == 404
    assert _asset_revision(web_factory) == revision


def test_second_preview_replaces_the_first_and_only_the_second_can_be_saved(signed_in, csrf, web_factory):
    _preview(signed_in, csrf, SVG, "first.svg")
    first = _draft_token(signed_in.get("/settings?tab=branding").text)
    _preview(signed_in, csrf, OTHER_SVG, "second.svg")
    page = signed_in.get("/settings?tab=branding").text
    second = _draft_token(page)
    assert second != first
    assert "second.svg" in page and "first.svg" not in page
    assert signed_in.get(f"/settings/branding/draft/{first}").status_code == 404
    assert _save(signed_in, csrf, second, "default").status_code == 303
    served = signed_in.get("/branding/logo")
    assert served.content == validate_logo("second.svg", "image/svg+xml", OTHER_SVG).content


# --- validation copy and error screens ------------------------------------------------------------


@pytest.mark.parametrize(
    "case, data, filename, content_type, status, message",
    [
        ("missing", None, None, None, 422, "Choose an SVG or PNG to preview."),
        ("file-too-large", b"x" * (262_144 + 1), "logo.svg", "image/svg+xml", 413, TOO_LARGE),
        ("file-too-large-mid-bound", b"x" * 300_000, "logo.svg", "image/svg+xml", 413, TOO_LARGE),
        ("request-too-large", b"x" * 330_000, "logo.svg", "image/svg+xml", 413, TOO_LARGE),
        ("wrong-format", SVG, "logo.png", "image/svg+xml", 422,
         "Unsupported logo format. Choose an SVG or PNG file."),
        ("corrupt-png", b"\x89PNG\r\n\x1a\nnot-a-real-png", "logo.png", "image/png", 422,
         "This image could not be read. Export it again as SVG or PNG."),
        ("dimensions", png(2049, 1), "wide.png", "image/png", 422,
         "Use an image 1–2048 pixels per side, with a width-to-height ratio between 0.5 and 6."),
        ("unsafe-svg", UNSAFE_SVG, "logo.svg", "image/svg+xml", 422,
         "This SVG uses unsupported content. Convert lettering to paths, remove embedded resources, or export a PNG."),
    ],
)
def test_every_validation_refusal_uses_the_exact_copy(
    signed_in, csrf, web_factory, case, data, filename, content_type, status, message
):
    if data is None:
        response = signed_in.post("/settings/branding/preview", data={"csrf_token": csrf}, follow_redirects=False)
    else:
        response = _preview(signed_in, csrf, data, filename, content_type)
    assert response.status_code == status, case
    page = response.text
    assert message in page
    assert UNCHANGED in page
    summary = re.search(
        r'<div class="form-error" id="branding-error" role="alert" tabindex="-1" autofocus>', page
    )
    assert summary is not None
    field = re.search(r'<input[^>]*id="f-branding-logo"[^>]*>', page)[0]
    assert 'aria-invalid="true"' in field
    assert 'aria-describedby="branding-logo-help branding-logo-error"' in field
    assert 'id="branding-logo-error"' in page
    assert "Save logo" not in page and "/settings/branding/draft/" not in page
    assert _drafts(web_factory) == 0


def test_invalid_preview_clears_a_previous_candidate(signed_in, csrf, web_factory):
    _preview(signed_in, csrf)
    assert _drafts(web_factory) == 1
    response = _preview(signed_in, csrf, UNSAFE_SVG, "bad.svg", "image/svg+xml")
    assert response.status_code == 422
    page = signed_in.get("/settings?tab=branding").text
    assert "Save logo" not in page and "/settings/branding/draft/" not in page
    assert _drafts(web_factory) == 0


def test_csrf_refusal_happens_before_any_image_parsing(signed_in, web_factory, monkeypatch):
    import app.web.branding as branding_web

    def explode(*args, **kwargs):
        raise AssertionError("image parsing ran before the CSRF refusal")

    monkeypatch.setattr(branding_web, "stage_draft", explode)
    response = _preview(signed_in, "wrong-token")
    assert response.status_code == 403
    assert "Your form expired" in response.text
    assert _drafts(web_factory) == 0


def test_expired_draft_returns_410_and_clears_the_bytes(signed_in, csrf, clock, web_factory):
    _preview(signed_in, csrf)
    page = signed_in.get("/settings?tab=branding").text
    token, base = _draft_token(page), _hidden(page, "base_revision")
    draft_url = f"/settings/branding/draft/{token}"
    clock.advance(minutes=31)
    assert signed_in.get(draft_url).status_code == 410
    response = _save(signed_in, csrf, token, base)
    assert response.status_code == 410
    assert EXPIRED in response.text and UNCHANGED in response.text
    assert _drafts(web_factory) == 0
    assert "cd_branding_draft" not in signed_in.cookies
    assert signed_in.get(draft_url).status_code == 404


def test_conflict_409_keeps_the_candidate_but_hides_save(signed_in, csrf, web_app, clock, web_factory):
    _preview(signed_in, csrf, SVG, "mine.svg")
    page = signed_in.get("/settings?tab=branding").text
    token, base = _draft_token(page), _hidden(page, "base_revision")

    other = _second_client(web_app, web_factory, clock)
    try:
        assert _preview(other, other.fixture_csrf, OTHER_SVG, "theirs.svg").status_code == 303
        other_page = other.get("/settings?tab=branding").text
        assert _save(other, other.fixture_csrf, _draft_token(other_page), "default").status_code == 303
    finally:
        other.__exit__(None, None, None)

    response = _save(signed_in, csrf, token, base)
    assert response.status_code == 409
    assert CONFLICT in response.text and UNCHANGED in response.text
    assert f"/settings/branding/draft/{token}" in response.text
    assert ">Save logo</button>" not in response.text
    assert ">Preview logo</button>" in response.text and ">Discard preview</button>" in response.text
    assert _drafts(web_factory) == 1  # the candidate is retained until its normal expiry


def test_save_503_retains_the_candidate(signed_in, csrf, monkeypatch):
    from sqlalchemy.exc import OperationalError

    import app.web.branding as branding_web

    _preview(signed_in, csrf)
    page = signed_in.get("/settings?tab=branding").text
    token, base = _draft_token(page), _hidden(page, "base_revision")

    def fail(*args, **kwargs):
        raise OperationalError("stmt", {}, Exception("boom"))

    monkeypatch.setattr(branding_web, "save_draft", fail)
    response = _save(signed_in, csrf, token, base)
    assert response.status_code == 503
    assert "Logo could not be saved. Your current logo has not changed. Try Save logo again." in response.text
    assert f"/settings/branding/draft/{token}" in response.text
    assert ">Save logo</button>" in response.text


def test_preview_store_failure_503_clears_the_candidate(signed_in, csrf, monkeypatch, web_factory):
    import app.web.branding as branding_web
    from app.services.branding import BrandingStorageUnavailable

    _preview(signed_in, csrf)
    assert _drafts(web_factory) == 1

    def refuse(*args, **kwargs):
        raise BrandingStorageUnavailable

    monkeypatch.setattr(branding_web, "stage_draft", refuse)
    response = _preview(signed_in, csrf, OTHER_SVG, "other.svg")
    assert response.status_code == 503
    assert "Logo could not be stored. Try Preview logo again." in response.text
    assert UNCHANGED in response.text
    assert "Save logo" not in response.text
    assert _drafts(web_factory) == 0


def test_reset_failure_503_keeps_the_current_logo(signed_in, csrf, monkeypatch, web_factory):
    from sqlalchemy.exc import OperationalError

    import app.web.branding as branding_web

    _preview(signed_in, csrf)
    page = signed_in.get("/settings?tab=branding").text
    _save(signed_in, csrf, _draft_token(page), "default")
    revision = _asset_revision(web_factory)

    def fail(*args, **kwargs):
        raise OperationalError("stmt", {}, Exception("boom"))

    monkeypatch.setattr(branding_web, "reset_branding", fail)
    response = _reset(signed_in, csrf, revision)
    assert response.status_code == 503
    assert "Logo could not be reset. Your current logo has not changed. Try again." in response.text
    assert _asset_revision(web_factory) == revision


# --- gates, ownership and the broken-row fallback -------------------------------------------------


def test_branding_routes_require_sign_in(client):
    anonymous = client
    assert anonymous.get("/settings?tab=branding", follow_redirects=False).status_code == 303
    assert anonymous.get("/settings/branding/draft/token", follow_redirects=False).headers["location"] == "/login"
    assert anonymous.post("/settings/branding/preview", data={}, follow_redirects=False).status_code == 403


def test_forced_password_change_user_cannot_reach_the_routes(client, web_factory, clock):
    from app.auth.sessions import issue_session

    flagged = create_login_user(web_factory, "flagged", must_change_password=True)
    with web_factory.begin() as db:
        session = issue_session(db, flagged.id, clock(), "192.0.2.160", "fixture-browser")
    client.cookies.set("cd_session", session.id, domain="testserver.local", path="/")

    response = client.get("/settings?tab=branding", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/account"
    for call in (
        lambda: _preview(client, session.csrf_token),
        lambda: _save(client, session.csrf_token, "token", "default"),
        lambda: _discard(client, session.csrf_token, "token"),
        lambda: _reset(client, session.csrf_token, "default"),
    ):
        refused = call()
        assert refused.status_code == 303 and refused.headers["location"] == "/account"
    assert _drafts(web_factory) == 0


def test_draft_image_is_session_owned(signed_in, csrf, web_app, clock, web_factory):
    _preview(signed_in, csrf)
    page = signed_in.get("/settings?tab=branding").text
    token = _draft_token(page)

    other = _second_client(web_app, web_factory, clock, "other-admin")
    try:
        assert other.get(f"/settings/branding/draft/{token}").status_code == 404
        assert _save(other, other.fixture_csrf, token, "default").status_code == 410
    finally:
        other.__exit__(None, None, None)
    assert signed_in.get(f"/settings/branding/draft/{token}").status_code == 200


def test_unreadable_stored_bytes_fall_back_to_the_default_everywhere(signed_in, web_factory):
    broken = b"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><rect width='24' height='24'/></svg>"
    with web_factory.begin() as db:
        db.add(
            BrandingAsset(
                id=1,
                mime="image/svg+xml",
                content=broken,
                width=24,
                height=24,
                sha256="0" * 64,
                display_filename="broken.svg",
            )
        )
    page = signed_in.get("/settings?tab=branding").text
    assert (
        "Custom logo is unavailable. The default logo is being shown. Upload a replacement or reset "
        "to default." in page
    )
    assert DEFAULT_LOCKUP in page
    home = signed_in.get("/").text
    assert DEFAULT_LOCKUP in home and "/branding/logo?v=" not in home
    assert signed_in.get("/branding/logo", follow_redirects=False).status_code == 307
    hub = signed_in.get("/administration").text
    assert "Branding" in hub and "Default logo" in hub

    corpus = signed_in.get("/settings?tab=branding").text
    base_revision = _hidden(corpus, "base_revision")
    assert _reset(signed_in, signed_in.fixture_csrf, base_revision).status_code == 303
    with web_factory() as db:
        assert db.get(BrandingAsset, 1) is None


def test_hub_reflects_the_saved_state(signed_in, csrf, branding_page):
    hub = signed_in.get("/administration").text
    assert 'href="/settings?tab=branding"' in hub and "Default logo" in hub
    _preview(signed_in, csrf)
    page = signed_in.get("/settings?tab=branding").text
    _save(signed_in, csrf, _draft_token(page), "default")
    hub = signed_in.get("/administration").text
    assert "Custom logo" in hub and "Default logo" not in hub


def test_double_save_creates_one_asset_and_one_audit_row(signed_in, csrf, web_factory):
    _preview(signed_in, csrf)
    page = signed_in.get("/settings?tab=branding").text
    token, base = _draft_token(page), _hidden(page, "base_revision")
    assert _save(signed_in, csrf, token, base).status_code == 303
    assert _save(signed_in, csrf, token, base).status_code == 303
    with web_factory() as db:
        assert db.scalar(select(func.count()).select_from(BrandingAsset)) == 1
    assert _audits(web_factory, "branding.save") == 1
