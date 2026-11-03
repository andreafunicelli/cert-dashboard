"""Rebuild original branding assets and a static contact sheet. No new dependencies.

Run: uv run python scripts/render_branding.py
The tiny PNG rasterizer supports only the authored SVG's rect/polyline subset;
it is an offline asset tool, NOT an upload sanitizer or application renderer.
"""

import struct
import zlib
from base64 import b64encode
from html import escape
from itertools import pairwise
from math import hypot
from pathlib import Path
from xml.etree import ElementTree as ET

from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "app/static/branding"
OUTPUT = ROOT / "docs/ui/previews/branding.html"
# One 24-unit drawing shared by all variants; seal intentionally has no checkmark.
LINES = (
    "12,22 4,22 4,2 14,2 20,8 20,12",
    "14,2 14,8 20,8",
    "8,11 12,11",
    "8,15 10,15",
    "17,14 21,16 21,20 17,22 13,20 13,16 17,14",
)


def drawing(color):
    return f'<g fill="none" stroke="{color}" stroke-width="1.6" ' + (
        'stroke-linecap="round" stroke-linejoin="round">'
        + "".join(f'<polyline points="{points}"/>' for points in LINES)
        + '</g>'
    )


def svg(kind, color, text_color):
    lockup = kind == "lockup"
    width = 202 if lockup else 24
    body = drawing(color)
    if lockup:
        body += (
            f'<text x="34" y="18" fill="{text_color}" font-size="18" font-weight="600" '
            'font-family="system-ui, -apple-system, Segoe UI, sans-serif">Cert Dashboard</text>'
        )
    if kind == "favicon":
        body = '<rect width="24" height="24" rx="3" fill="#0b1326"/>' + body
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="24" '
        f'viewBox="0 0 {width} 24" role="img" aria-labelledby="title">'
        '<title id="title">Cert Dashboard</title>' + body + '</svg>\n'
    )


def png_from_mark(source, size):
    """Supersample the SVG's round-stroked segments directly, then encode RGBA PNG."""
    # Only our locally authored SVG is parsed, never untrusted input.
    root = ET.fromstring(source)
    group = root.find("{*}g")
    assert group is not None
    color = bytes.fromhex(group.attrib["stroke"].removeprefix("#"))
    radius = float(group.attrib["stroke-width"]) / 2
    lines = []
    for element in group:
        points = [tuple(map(float, pair.split(","))) for pair in element.attrib["points"].split()]
        lines.extend(pairwise(points))
    rect = root.find("{*}rect")
    background = bytes.fromhex(rect.attrib["fill"].removeprefix("#")) if rect is not None else None

    def inside(x, y):
        for (ax, ay), (bx, by) in lines:
            dx, dy = bx - ax, by - ay
            t = max(0, min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
            if hypot(x - ax - t * dx, y - ay - t * dy) <= radius:
                return True
        return False

    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            coverage = sum(
                inside((x + (sx + .5) / 4) * 24 / size, (y + (sy + .5) / 4) * 24 / size)
                for sy in range(4) for sx in range(4)
            ) / 16
            if background is not None:
                # Match the favicon's 3-unit rounded tile, including its alpha corners.
                tile = sum(
                    hypot(max(3 - px, 0, px - 21), max(3 - py, 0, py - 21)) <= 3
                    for sy in range(4) for sx in range(4)
                    for px, py in [((x + (sx + .5) / 4) * 24 / size,
                                    (y + (sy + .5) / 4) * 24 / size)]
                ) / 16
                rows.extend(round(a * coverage + b * (1 - coverage)) for a, b in zip(color, background))
                rows.append(round(255 * tile))
            else:
                rows.extend(color)
                rows.append(round(255 * coverage))

    def chunk(tag, data):
        return struct.pack('!I', len(data)) + tag + data + struct.pack('!I', zlib.crc32(tag + data))

    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('!2I5B', size, size, 8, 6, 0, 0, 0))
            + chunk(b'tEXt', b'Source\x00Original Cert Dashboard favicon.svg; scripts/render_branding.py')
            + chunk(b'IDAT', zlib.compress(bytes(rows))) + chunk(b'IEND', b''))


def render(assets=ASSETS, output=OUTPUT):
    assets.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    for suffix, accent, text in (("", "#4cd7f6", "#dae2fd"),
                                 ("-light", "#006579", "#172033"),
                                 ("-mono", "#172033", "#172033")):
        for kind in ("mark", "lockup"):
            (assets / f'{kind}{suffix}.svg').write_text(svg(kind, accent, text))
    favicon = svg("favicon", "#4cd7f6", "#dae2fd")
    (assets / 'favicon.svg').write_text(favicon)
    (assets / 'favicon-32.png').write_bytes(png_from_mark(favicon, 32))
    env = Environment(loader=FileSystemLoader(ROOT / 'docs/ui/fixtures'),
                      autoescape=select_autoescape(['j2', 'html']))
    html = env.get_template('branding.html.j2').render()
    output.write_text(html)
    return html


def standalone():
    """Self-contained copy for browser inspection only; committed preview uses relative assets."""
    html = OUTPUT.read_text()
    for css in ('../../../app/static/app.css', 'branding.css'):
        content = (OUTPUT.parent / css).resolve().read_text()
        html = html.replace(f'<link rel="stylesheet" href="{css}">', f'<style>{content}</style>')
    for path in ASSETS.iterdir():
        mime = 'image/png' if path.suffix == '.png' else 'image/svg+xml'
        url = 'data:' + mime + ';base64,' + b64encode(path.read_bytes()).decode()
        html = html.replace('../../../app/static/branding/' + escape(path.name), url)
    return html


if __name__ == '__main__':
    render()
    print(f'Wrote assets to {ASSETS} and static preview to {OUTPUT}')
