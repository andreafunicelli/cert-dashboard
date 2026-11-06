"""Strict logo validation (``docs/ui/branding.md`` "Validation"): every refusal and canonical output.

Pure standard-library checks: PNG chunks are decoded, CRC-checked and re-encoded; SVG is parsed with
``xml.parsers.expat`` against the allowlist and serialized fresh. No upload is ever served as-is.
"""

import struct
import zlib
from xml.etree import ElementTree

import pytest

from app.services.branding_image import (
    MAX_FILE_BYTES,
    MAX_REQUEST_BYTES,
    BrandingImageError,
    clean_display_filename,
    request_within_limit,
    validate_logo,
)

SIGNATURE = b"\x89PNG\r\n\x1a\n"
CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
ALLOWED_ELEMENTS = {
    "svg",
    "g",
    "path",
    "rect",
    "circle",
    "ellipse",
    "line",
    "polyline",
    "polygon",
    "title",
    "desc",
}


def chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def png(
    width: int,
    height: int,
    *,
    colour_type: int = 6,
    bit_depth: int = 8,
    interlace: int = 0,
    rows: bytes | None = None,
    palette: bytes | None = None,
    transparency: bytes | None = None,
    before_idat: tuple[tuple[bytes, bytes], ...] = (),
    trailing: bytes = b"",
) -> bytes:
    channels = CHANNELS[colour_type]
    if rows is None:
        rows = b"".join(b"\x00" + bytes(width * channels) for _ in range(height))
    header = struct.pack(">IIBBBBB", width, height, bit_depth, colour_type, 0, 0, interlace)
    out = SIGNATURE + chunk(b"IHDR", header)
    if palette is not None:
        out += chunk(b"PLTE", palette)
    if transparency is not None:
        out += chunk(b"tRNS", transparency)
    for kind, data in before_idat:
        out += chunk(kind, data)
    return out + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"") + trailing


def chunk_types(data: bytes) -> list[bytes]:
    assert data.startswith(SIGNATURE)
    kinds, pos = [], 8
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        kinds.append(data[pos + 4 : pos + 8])
        pos += 12 + length
    return kinds


def svg(body: str = "", *, viewbox: str = "0 0 24 24", root_attrs: str = "") -> bytes:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{viewbox}" {root_attrs}>{body}</svg>'
    ).encode()


def refusal(code: str, filename: str, data: bytes, content_type: str | None) -> BrandingImageError:
    with pytest.raises(BrandingImageError) as exc:
        validate_logo(filename, content_type, data)
    assert exc.value.code == code, str(exc.value)
    return exc.value


# --- size, request bound and file name ---------------------------------------------------------


def test_file_size_is_inclusive_and_limit_plus_one_is_too_large():
    # Exactly the limit reaches decoding (and fails as unreadable); one more byte is refused by size.
    at_limit = SIGNATURE + b"\x00" * (MAX_FILE_BYTES - len(SIGNATURE))
    assert refusal("unreadable", "logo.png", at_limit, "image/png")
    refusal("too_large", "logo.png", at_limit + b"\x00", "image/png")


def test_request_bound_helper_fails_closed():
    assert request_within_limit(None) is True
    assert request_within_limit(str(MAX_REQUEST_BYTES)) is True
    assert request_within_limit(MAX_REQUEST_BYTES) is True
    assert request_within_limit(str(MAX_REQUEST_BYTES + 1)) is False
    assert request_within_limit("nonsense") is False
    assert request_within_limit("-1") is False


def test_display_filename_strips_directories_and_control_characters_and_caps_length():
    assert clean_display_filename("../../evil.png") == "evil.png"
    assert clean_display_filename(r"C:\Users\ada\Logo.PNG") == "Logo.PNG"
    assert clean_display_filename("logo\x00\x1f.png") == "logo.png"
    assert len(clean_display_filename("x" * 400 + ".svg")) == 120
    assert clean_display_filename("") == "logo"


def test_mime_and_extension_must_agree_with_the_decoded_format():
    good = png(2, 2)
    assert validate_logo("Logo.PNG", "image/png", good).mime == "image/png"
    assert validate_logo("logo.png", "application/octet-stream", good).mime == "image/png"
    refusal("format", "logo.svg", good, "image/svg+xml")
    refusal("format", "logo.png", good, "image/svg+xml")
    refusal("format", "logo.png", good, "text/plain")
    refusal("format", "logo.gif", good, None)
    refusal("format", "logo", good, None)
    refusal("format", "logo.svg", svg(), "image/png")


# --- PNG --------------------------------------------------------------------------------------


def test_valid_png_is_canonicalized_and_metadata_is_dropped():
    source = png(4, 3, before_idat=((b"tEXt", b"Comment\x00private"),), trailing=b"hidden-after-iend")
    result = validate_logo("logo.png", "image/png", source)
    assert (result.width, result.height, result.mime) == (4, 3, "image/png")
    assert chunk_types(result.content) == [b"IHDR", b"IDAT", b"IEND"]
    assert result.content.endswith(chunk(b"IEND", b""))
    assert b"private" not in result.content and b"hidden-after-iend" not in result.content
    assert result.sha256 == __import__("hashlib").sha256(result.content).hexdigest()


@pytest.mark.parametrize(
    "data",
    [
        b"not a png at all",
        png(2, 2)[:-8],  # truncated before IEND
    ],
)
def test_corrupt_or_truncated_png_is_unreadable(data):
    refusal("unreadable", "logo.png", data, "image/png")


def test_bad_crc_is_unreadable():
    data = bytearray(png(2, 2))
    index = data.index(b"IDAT")
    data[index + 4] ^= 0xFF
    refusal("unreadable", "logo.png", bytes(data), "image/png")


def test_apng_is_refused():
    actl = struct.pack(">II", 2, 0)
    refusal("unreadable", "logo.png", png(2, 2, before_idat=((b"acTL", actl),)), "image/png")


def test_interlaced_and_sixteen_bit_png_are_unreadable():
    refusal("unreadable", "logo.png", png(2, 2, interlace=1), "image/png")
    refusal("unreadable", "logo.png", png(2, 2, colour_type=0, bit_depth=16), "image/png")


def test_decompression_bomb_is_refused():
    rows = zlib.compress(b"\x00" * 64)
    data = (
        SIGNATURE
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", rows)
        + chunk(b"IEND", b"")
    )
    refusal("unreadable", "logo.png", data, "image/png")


def test_invalid_filter_byte_is_refused():
    refusal("unreadable", "logo.png", png(2, 2, rows=b"\x07" + bytes(8)), "image/png")


def test_palette_is_required_for_colour_type_three():
    refusal("unreadable", "logo.png", png(2, 2, colour_type=3), "image/png")
    palette = bytes([0, 0, 0, 255, 255, 255])
    result = validate_logo("logo.png", "image/png", png(2, 2, colour_type=3, palette=palette))
    assert chunk_types(result.content) == [b"IHDR", b"PLTE", b"IDAT", b"IEND"]


@pytest.mark.parametrize(
    "width,height,accepted",
    [(0, 1, False), (1, 1, True), (2048, 1024, True), (2049, 1, False), (2048, 2048, True)],
)
def test_png_dimension_bounds(width, height, accepted):
    data = png(width, height)
    if accepted:
        assert (validate_logo("logo.png", "image/png", data).width) == width
    else:
        refusal("dimensions", "logo.png", data, "image/png")


@pytest.mark.parametrize("width,height", [(1, 3), (6, 1), (1, 2), (7, 1)])
def test_png_aspect_bounds(width, height):
    data = png(width, height)
    if 0.5 <= width / height <= 6:
        assert validate_logo("logo.png", "image/png", data).width == width
    else:
        refusal("dimensions", "logo.png", data, "image/png")


# --- SVG --------------------------------------------------------------------------------------


def test_valid_svg_is_reparsed_and_stripped_to_the_allowlist():
    source = svg(
        '<title>Example</title><desc>Mark</desc><g transform="translate(1,2) scale(2)" fill="#4cd7f6">'
        '<path d="M0 0 L10 10 Z" stroke="none"/><rect x="1" y="2" width="3" height="4" rx="1"/>'
        '<circle cx="1" cy="1" r="1" opacity="0.5"/><polyline points="0,0 1,1"/></g>',
        root_attrs='width="24" height="24"',
    )
    result = validate_logo("logo.svg", "image/svg+xml", source)
    assert (result.width, result.height, result.mime) == (24, 24, "image/svg+xml")
    root = ElementTree.fromstring(result.content)
    assert root.tag.rsplit("}", 1)[-1] == "svg"
    assert root.attrib["viewBox"] == "0 0 24 24"
    for element in root.iter():
        assert element.tag.rsplit("}", 1)[-1] in ALLOWED_ELEMENTS
        for attribute in element.attrib:
            assert attribute in {
                "xmlns",
                "viewBox",
                "width",
                "height",
                "d",
                "points",
                "x",
                "y",
                "x1",
                "x2",
                "y1",
                "y2",
                "cx",
                "cy",
                "r",
                "rx",
                "ry",
                "fill",
                "stroke",
                "stroke-width",
                "stroke-linecap",
                "stroke-linejoin",
                "stroke-miterlimit",
                "fill-rule",
                "opacity",
                "fill-opacity",
                "stroke-opacity",
                "transform",
            }
    assert b"<script" not in result.content
    assert b"Example" in result.content
    assert result.sha256 == __import__("hashlib").sha256(result.content).hexdigest()


UNSAFE_SVG = {
    "script": svg("<script>alert(1)</script>"),
    "event": svg('<path d="M0 0" onload="alert(1)"/>'),
    "foreign_object": svg("<foreignObject><div/></foreignObject>"),
    "style_element": svg("<style>path{fill:red}</style>"),
    "style_attribute": svg('<path d="M0 0" style="fill:red"/>'),
    "href": svg('<path d="M0 0" href="https://example.test/x"/>'),
    "url_paint": svg('<rect width="1" height="1" fill="url(#gradient)"/>'),
    "data_url": svg('<rect width="1" height="1" fill="url(data:image/png;base64,AAAA)"/>'),
    "doctype": b'<!DOCTYPE svg [<!ENTITY x "y">]>' + svg(),
    "processing_instruction": b'<?xml-stylesheet href="x"?>' + svg(),
    "foreign_namespace": b'<x:svg xmlns:x="http://evil.test" viewBox="0 0 1 1"/>',
    "wrong_default_namespace": b'<svg xmlns="http://evil.test" viewBox="0 0 1 1"/>',
    "loose_text": svg("Cert Dashboard"),
    "text": svg("<text>Cert Dashboard</text>"),
    "filter": svg("<filter/>"),
    "animation": svg("<animate/>"),
    "current_color": svg('<rect width="1" height="1" fill="currentColor"/>'),
    "out_of_range": svg('<rect x="100001" width="1" height="1"/>'),
    "missing_viewbox": b'<svg xmlns="http://www.w3.org/2000/svg"/>',
    "unknown_attribute": svg('<rect width="1" height="1" data-x="1"/>'),
    "nested_svg": svg('<svg viewBox="0 0 1 1"/>'),
    "comment": svg("<!-- hidden -->"),
}


@pytest.mark.parametrize("payload", UNSAFE_SVG.values(), ids=UNSAFE_SVG.keys())
def test_unsafe_svg_content_is_refused(payload):
    refusal("unsafe_svg", "logo.svg", payload, "image/svg+xml")


def test_svg_depth_elements_and_path_command_caps():
    deep = "<g>" * 16 + "</g>" * 16  # root + 16 nested groups = depth 17
    refusal("unsafe_svg", "logo.svg", svg(deep), "image/svg+xml")
    sixteen = "<g>" * 15 + "</g>" * 15  # root + 15 = depth 16
    assert validate_logo("logo.svg", "image/svg+xml", svg(sixteen)).width == 24
    too_many = "<g/>" * 512  # 513 elements including the root
    refusal("unsafe_svg", "logo.svg", svg(too_many), "image/svg+xml")
    at_cap = "<g/>" * 511
    assert validate_logo("logo.svg", "image/svg+xml", svg(at_cap)).width == 24
    too_complex_path = '<path d="M0 0 ' + "L1 1 " * 16_384 + '"/>'
    refusal("unsafe_svg", "logo.svg", svg(too_complex_path), "image/svg+xml")


@pytest.mark.parametrize(
    "viewbox,width,height",
    [
        ("0 0 1 1", 1, 1),
        ("0 0 24 24", 24, 24),
        ("0 0 100 200", 100, 200),
        ("0 0 600 100", 600, 100),
        ("0 0 2048 2048", 2048, 2048),
    ],
)
def test_svg_dimension_and_aspect_bounds_accept(viewbox, width, height):
    result = validate_logo("logo.svg", "image/svg+xml", svg(viewbox=viewbox))
    assert (result.width, result.height) == (width, height)


@pytest.mark.parametrize("viewbox", ["0 0 0 10", "0 0 2049 10", "0 0 1 3", "0 0 7 1"])
def test_svg_dimension_and_aspect_bounds_refuse(viewbox):
    refusal("dimensions", "logo.svg", svg(viewbox=viewbox), "image/svg+xml")


def test_malformed_xml_is_unreadable():
    refusal("unreadable", "logo.svg", b"<svg", "image/svg+xml")
    refusal("unreadable", "logo.svg", b"\xff\xfe\x00bad", "image/svg+xml")


def test_svg_that_serializes_over_the_byte_limit_is_too_large():
    # Many short elements stay inside 512 nodes but the serialized tree gains the xmlns declaration.
    payload = svg("<rect width='1' height='1'/>" * 500)
    assert len(payload) < MAX_FILE_BYTES
    result = validate_logo("logo.svg", "image/svg+xml", payload)
    assert len(result.content) <= MAX_FILE_BYTES
