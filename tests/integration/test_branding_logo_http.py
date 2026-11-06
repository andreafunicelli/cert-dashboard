"""``GET /branding/logo`` (A2-D4): public bytes, fixed headers and safe fallbacks.

The route must work signed out (the sign-in page needs it) and must never surface a database error
or an unvalidated original. Only the singleton sanitized row is served; everything else redirects
to the first-party mark.
"""

import hashlib
import struct
import zlib

import pytest
from sqlalchemy import text

from app.models import BrandingAsset

DEFAULT_PATH = "/static/branding/mark.svg"
SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
    b'<path d="M0 0 L10 10 Z" fill="#4cd7f6"/></svg>'
)
SVG_CSP = "default-src 'none'; style-src 'none'; script-src 'none'; sandbox"


def png(width: int, height: int) -> bytes:
    rows = b"".join(b"\x00" + bytes([row % 256]) * (width * 4) for row in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(rows))
        + _chunk(b"IEND", b"")
    )


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


@pytest.fixture(autouse=True)
def clean_branding(web_factory):
    def clear():
        with web_factory.begin() as db:
            db.execute(text("DELETE FROM branding_asset"))
            db.execute(text("DELETE FROM branding_draft"))

    clear()
    yield clear
    clear()


def store(factory, *, content=SVG, mime="image/svg+xml", width=24, height=24, revision=None):
    with factory.begin() as db:
        db.add(
            BrandingAsset(
                id=1,
                mime=mime,
                content=content,
                width=width,
                height=height,
                sha256=revision or hashlib.sha256(content).hexdigest(),
                display_filename="logo.svg" if mime == "image/svg+xml" else "logo.png",
            )
        )


def test_no_asset_redirects_to_the_default_mark_even_signed_out(client):
    response = client.get("/branding/logo", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == DEFAULT_PATH


def test_saved_svg_is_served_with_constant_headers_signed_out(client, web_factory):
    store(web_factory)
    response = client.get("/branding/logo?v=stale-revision", follow_redirects=False)
    assert response.status_code == 200
    assert response.content == SVG
    assert response.headers["content-type"].split(";")[0] == "image/svg+xml"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-disposition"] == 'inline; filename="logo.svg"'
    assert response.headers["content-security-policy"] == SVG_CSP


def test_saved_png_is_served_with_png_headers_and_no_svg_policy(client, web_factory):
    content = png(2, 2)
    store(web_factory, content=content, mime="image/png", width=2, height=2)
    response = client.get("/branding/logo", follow_redirects=False)
    assert response.status_code == 200 and response.content == content
    assert response.headers["content-type"].split(";")[0] == "image/png"
    assert response.headers["content-disposition"] == 'inline; filename="logo.png"'
    assert "content-security-policy" not in response.headers


def test_signed_in_requests_see_the_same_current_bytes(signed_in, web_factory):
    store(web_factory)
    response = signed_in.get("/branding/logo", follow_redirects=False)
    assert response.status_code == 200 and response.content == SVG


@pytest.mark.parametrize(
    "changes",
    [
        {"revision": "0" * 64},  # hash/content mismatch
        {"content": b"", "revision": hashlib.sha256(b"").hexdigest()},  # empty
        {"width": 0},  # impossible stored dimensions
    ],
)
def test_corrupt_stored_rows_fall_back_without_error_text(client, web_factory, changes):
    content = changes.get("content", SVG)
    store(
        web_factory,
        content=content,
        mime="image/svg+xml",
        width=changes.get("width", 24),
        height=24,
        revision=changes.get("revision", hashlib.sha256(content).hexdigest()),
    )
    response = client.get("/branding/logo", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == DEFAULT_PATH
    assert b"error" not in response.content.lower()


def test_only_the_exact_logo_path_is_public(client):
    unauthorised = client.get("/branding/logo/other", follow_redirects=False)
    assert unauthorised.status_code == 303
    assert unauthorised.headers["location"] == "/login"
    settings = client.get("/settings?tab=branding", follow_redirects=False)
    assert settings.status_code == 303
    assert settings.headers["location"] == "/login"
