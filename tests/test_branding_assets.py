"""Repository-only original asset checks; no docs or tools added to runtime image."""

import struct
import zlib
from html.parser import HTMLParser
from xml.etree import ElementTree as ET

from scripts.render_branding import ASSETS, OUTPUT, png_from_mark, render
from scripts.render_previews import OUTPUT as PAGE_PREVIEWS


class Images(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.images = []
        self.stylesheets = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == 'img':
            self.images.append(dict(attrs))
        if tag == 'link' and dict(attrs).get('rel') == 'stylesheet':
            self.stylesheets.append(dict(attrs)['href'])


def test_original_assets_and_regeneration_are_deterministic(tmp_path):
    generated = tmp_path / 'branding'
    preview = tmp_path / 'branding.html'
    render(assets=generated, output=preview)
    assert {p.name: p.read_bytes() for p in generated.iterdir()} == {
        p.name: p.read_bytes() for p in ASSETS.iterdir()
    }
    assert preview.read_bytes() == OUTPUT.read_bytes()
    assert {p.name for p in ASSETS.iterdir()} == {
        'mark.svg', 'mark-light.svg', 'mark-mono.svg',
        'lockup.svg', 'lockup-light.svg', 'lockup-mono.svg', 'favicon.svg', 'favicon-32.png',
    }


def test_svgs_are_self_contained_and_keep_geometry():
    geometry = None
    for path in ASSETS.glob('*.svg'):
        # Trusted committed assets, not a user-upload XML parser.
        root = ET.fromstring(path.read_text())
        assert root.attrib['viewBox'] == ('0 0 202 24' if 'lockup' in path.name else '0 0 24 24')
        assert root.find('{*}title').text == 'Cert Dashboard'
        assert all(node.tag.split('}')[-1] in {'svg', 'title', 'g', 'polyline', 'text', 'rect'}
                   for node in root.iter())
        assert all(not key.startswith('on') and key not in {'href', 'style'}
                   for node in root.iter() for key in node.attrib)
        points = [node.attrib['points'] for node in root.findall('.//{*}polyline')]
        geometry = geometry or points
        assert points == geometry
        if 'lockup' in path.name:
            assert root.find('{*}text').text == 'Cert Dashboard'
            assert 'system-ui' in root.find('{*}text').attrib['font-family']


def test_png_is_32px_rgba_crc_valid_and_matches_svg_source():
    data = (ASSETS / 'favicon-32.png').read_bytes()
    assert data[:8] == b'\x89PNG\r\n\x1a\n'
    assert data == png_from_mark((ASSETS / 'favicon.svg').read_text(), 32)
    pos, compressed = 8, b''
    while pos < len(data):
        length = struct.unpack('!I', data[pos:pos + 4])[0]
        tag = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        crc = struct.unpack('!I', data[pos + 8 + length:pos + 12 + length])[0]
        assert crc == zlib.crc32(tag + body)
        if tag == b'IHDR':
            assert struct.unpack('!2I5B', body) == (32, 32, 8, 6, 0, 0, 0)
        if tag == b'IDAT':
            compressed += body
        pos += length + 12
    pixels = zlib.decompress(compressed)
    assert len(pixels) == 32 * (1 + 32 * 4)
    assert bytes.fromhex('4cd7f6ff') in pixels  # Real opaque cyan ink, not a blank PNG.
    assert bytes.fromhex('0b1326ff') in pixels


def test_contact_sheet_sizes_relative_assets_and_no_active_ui():
    assert OUTPUT.parent != PAGE_PREVIEWS
    html = OUTPUT.read_text()
    assert 'style="' not in html and '<script' not in html
    assert '<form' not in html and '<button' not in html
    parsed = Images(html)
    assert len(parsed.stylesheets) == 2
    assert all((OUTPUT.parent / href).resolve().is_file() for href in parsed.stylesheets)
    images = parsed.images
    assert len(images) == 12
    for image in images:
        path = (OUTPUT.parent / image['src']).resolve()
        assert path.is_file() and ASSETS in path.parents
        assert image['alt']
    assert {image['height'] for image in images} == {'16', '24', '32', '48'}
    for theme in ('dark', 'light', 'mono'):
        assert f'class="swatch {theme}"' in html
    assert 'not a working settings screen' in html
