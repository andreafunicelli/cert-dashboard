"""Strict, dependency-free validation for an uploaded logo (``docs/ui/branding.md``).

Nothing an administrator uploads is stored or served as-is. A PNG is fully decoded, CRC-checked,
bounded and re-encoded from its inflated scanlines; an SVG is parsed with ``xml.parsers.expat``
under an allowlist and serialized from a fresh tree. Both paths return only canonical bytes.

The profile is deliberately narrow (``docs/ux-spec.md`` A2-D2): no new dependency, no external
entity, no animation, no embedded resource and no live lettering. A safe-but-complex image can be
exported to PNG; the profile is never relaxed to accept arbitrary editor output.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
import zlib
from dataclasses import dataclass
from xml.etree import ElementTree
from xml.parsers import expat

MAX_FILE_BYTES = 262_144
MAX_REQUEST_BYTES = 327_680
MAX_DIMENSION = 2_048
MAX_PIXELS = 4_194_304
MIN_ASPECT = 0.5
MAX_ASPECT = 6.0
MAX_SVG_ELEMENTS = 512
MAX_SVG_DEPTH = 16
MAX_SVG_PATH_POINTS = 16_384
MAX_COORDINATE = 100_000.0
MAX_FILENAME = 120
SVG_MIME = "image/svg+xml"
PNG_MIME = "image/png"

MESSAGES = {
    "too_large": "Logo is too large. Choose an SVG or PNG no larger than 256 KiB.",
    "format": "Unsupported logo format. Choose an SVG or PNG file.",
    "unreadable": "This image could not be read. Export it again as SVG or PNG.",
    "dimensions": (
        "Use an image 1–2048 pixels per side, with a width-to-height ratio between 0.5 and 6."
    ),
    "unsafe_svg": (
        "This SVG uses unsupported content. Convert lettering to paths, remove embedded "
        "resources, or export a PNG."
    ),
}

__all__ = [
    "MAX_FILE_BYTES",
    "MAX_REQUEST_BYTES",
    "MESSAGES",
    "PNG_MIME",
    "SVG_MIME",
    "BrandingImageError",
    "ValidatedImage",
    "canonical_png",
    "canonical_svg",
    "clean_display_filename",
    "request_within_limit",
    "validate_logo",
]

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
_PNG_REFUSED_CHUNKS = {b"acTL", b"fcTL", b"fdAT"}
_SVG_NS = "http://www.w3.org/2000/svg"

_SVG_ELEMENT_ATTRIBUTES = {
    "path": {"d"},
    "rect": {"x", "y", "width", "height", "rx", "ry"},
    "circle": {"cx", "cy", "r"},
    "ellipse": {"cx", "cy", "rx", "ry"},
    "line": {"x1", "y1", "x2", "y2"},
    "polyline": {"points"},
    "polygon": {"points"},
}
_SVG_PRESENTATION = {
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
_SVG_ROOT_ATTRIBUTES = {"xmlns", "viewBox", "width", "height"}
_SVG_COORDINATES = {"x", "y", "x1", "y1", "x2", "y2", "cx", "cy"}
_SVG_LENGTHS = {"r", "rx", "ry", "width", "height", "stroke-width"}
_NUMBER = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")
_PATH_COMMANDS = set("MmLlHhVvCcSsQqTtAaZz")
_PATH_ARITY = {"M": 2, "L": 2, "H": 1, "V": 1, "C": 6, "S": 4, "Q": 4, "T": 2, "A": 7, "Z": 0}
_TRANSFORM = re.compile(r"(matrix|translate|scale|rotate|skewX|skewY)\s*\(([^()]*)\)")
_TRANSFORM_ARITY = {
    "matrix": {6},
    "translate": {1, 2},
    "scale": {1, 2},
    "rotate": {1, 3},
    "skewX": {1},
    "skewY": {1},
}


class BrandingImageError(ValueError):
    """A refused upload; ``code`` is one of the closed set used by the UI copy."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(MESSAGES[code])


@dataclass(frozen=True)
class ValidatedImage:
    content: bytes
    mime: str
    width: int
    height: int
    sha256: str
    display_filename: str


def request_within_limit(content_length: str | int | None) -> bool:
    """A2-D3: refuse an upload request by ``Content-Length`` before multipart parsing.

    A missing length is passed through to the streaming count; anything unparseable or negative
    fails closed so an invalid header cannot bypass the bound.
    """
    if content_length is None:
        return True
    try:
        length = int(content_length)
    except (TypeError, ValueError):
        return False
    return 0 <= length <= MAX_REQUEST_BYTES


def clean_display_filename(filename: str) -> str:
    """Strip directory components and control characters, cap at 120 and keep the suffix."""
    raw = (filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    raw = "".join(character for character in raw if ord(character) >= 32 and ord(character) != 127).strip()
    if not raw:
        return "logo"
    suffix = ""
    dot = raw.rfind(".")
    if dot > 0 and 1 < len(raw) - dot <= 10 and raw[dot + 1 :].isascii() and raw[dot + 1 :].isalpha():
        suffix = raw[dot:]
    stem = raw[: len(raw) - len(suffix)] if suffix else raw
    stem = stem[: MAX_FILENAME - len(suffix)]
    name = (stem + suffix)[:MAX_FILENAME]
    return name if name and name != suffix else "logo" + suffix


def validate_logo(filename: str, content_type: str | None, data: bytes) -> ValidatedImage:
    """Validate, canonicalize and describe one upload. Raises ``BrandingImageError``."""
    display_filename = clean_display_filename(filename)
    if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
        raise BrandingImageError("too_large")
    lowered = display_filename.lower()
    if lowered.endswith(".png"):
        mime = PNG_MIME
        decoder = canonical_png
    elif lowered.endswith(".svg"):
        mime = SVG_MIME
        decoder = canonical_svg
    else:
        raise BrandingImageError("format")
    declared = (content_type or "").split(";", 1)[0].strip().lower()
    if declared not in {"", "application/octet-stream", mime}:
        raise BrandingImageError("format")
    if mime == PNG_MIME and not data.startswith(_PNG_SIGNATURE):
        raise BrandingImageError("format" if data.lstrip().startswith(b"<") else "unreadable")
    if mime == SVG_MIME and data.startswith(_PNG_SIGNATURE):
        raise BrandingImageError("format")
    try:
        content, width, height = decoder(data)
    except BrandingImageError:
        raise
    except Exception:  # noqa: BLE001 - hostile input: every decoder failure is the same refusal.
        raise BrandingImageError("unreadable") from None
    return ValidatedImage(
        content=content,
        mime=mime,
        width=width,
        height=height,
        sha256=hashlib.sha256(content).hexdigest(),
        display_filename=display_filename,
    )


# --- PNG ---------------------------------------------------------------------------------------


def _png_chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)


def _png_chunks(data: bytes):
    position = len(_PNG_SIGNATURE)
    while True:
        if position + 12 > len(data):
            raise BrandingImageError("unreadable")
        (length,) = struct.unpack(">I", data[position : position + 4])
        if length > 0x7FFFFFFF:
            raise BrandingImageError("unreadable")
        end = position + 12 + length
        if end > len(data):
            raise BrandingImageError("unreadable")
        kind = data[position + 4 : position + 8]
        body = data[position + 8 : position + 8 + length]
        (crc,) = struct.unpack(">I", data[position + 8 + length : end])
        if zlib.crc32(kind + body) & 0xFFFFFFFF != crc:
            raise BrandingImageError("unreadable")
        yield kind, body
        if kind == b"IEND":
            return
        position = end


def _png_header(header: bytes) -> tuple[int, int, int, int, int]:
    if len(header) != 13:
        raise BrandingImageError("unreadable")
    width, height, bit_depth, colour_type, compression, filtering, interlace = struct.unpack(
        ">IIBBBBB", header
    )
    if compression != 0 or filtering != 0 or bit_depth != 8 or interlace != 0:
        raise BrandingImageError("unreadable")
    if colour_type not in _PNG_CHANNELS:
        raise BrandingImageError("unreadable")
    if not 1 <= width <= MAX_DIMENSION or not 1 <= height <= MAX_DIMENSION:
        raise BrandingImageError("dimensions")
    if width * height > MAX_PIXELS:
        raise BrandingImageError("dimensions")
    if not MIN_ASPECT <= width / height <= MAX_ASPECT:
        raise BrandingImageError("dimensions")
    return width, height, bit_depth, colour_type, interlace


def canonical_png(data: bytes) -> tuple[bytes, int, int]:
    """Decode a static 8-bit PNG, then re-emit only IHDR/PLTE/tRNS/IDAT/IEND.

    Everything else (metadata, APNG chunks, trailing bytes) is dropped; a decompression bomb,
    truncation, bad CRC or unsupported variant is refused rather than partially decoded.
    """
    if not data.startswith(_PNG_SIGNATURE):
        raise BrandingImageError("format")
    header = None
    palette = None
    transparency = None
    idat: list[bytes] = []
    idat_started = False
    ended = False
    for kind, body in _png_chunks(data):
        if header is None and kind != b"IHDR":
            raise BrandingImageError("unreadable")
        if kind == b"IHDR":
            if header is not None:
                raise BrandingImageError("unreadable")
            header = body
        elif kind == b"PLTE":
            if idat_started or palette is not None:
                raise BrandingImageError("unreadable")
            palette = body
        elif kind == b"tRNS":
            if idat_started or transparency is not None:
                raise BrandingImageError("unreadable")
            transparency = body
        elif kind == b"IDAT":
            idat_started = True
            idat.append(body)
        elif kind == b"IEND":
            if body:
                raise BrandingImageError("unreadable")
            ended = True
            break
        elif kind in _PNG_REFUSED_CHUNKS:
            raise BrandingImageError("unreadable")
        elif kind[0] & 0x20 == 0:
            # An unknown critical chunk cannot be safely ignored.
            raise BrandingImageError("unreadable")
    if header is None or not idat or not ended:
        raise BrandingImageError("unreadable")
    width, height, _bit_depth, colour_type, _interlace = _png_header(header)

    if palette is not None and (
        not 3 <= len(palette) <= 768 or len(palette) % 3
    ):
        raise BrandingImageError("unreadable")
    if colour_type == 3:
        if palette is None or len(palette) // 3 > 256:
            raise BrandingImageError("unreadable")
    elif colour_type in {0, 4} and palette is not None:
        raise BrandingImageError("unreadable")
    if transparency is not None:
        allowed = {0: {2}, 2: {6}, 3: {len(palette) // 3 if palette is not None else 0}}
        if colour_type not in allowed or len(transparency) not in allowed[colour_type]:
            raise BrandingImageError("unreadable")

    channels = _PNG_CHANNELS[colour_type]
    row_bytes = width * channels
    expected = height * (row_bytes + 1)
    inflater = zlib.decompressobj()
    try:
        scanlines = inflater.decompress(b"".join(idat), expected + 1)
    except zlib.error:
        raise BrandingImageError("unreadable") from None
    if (
        len(scanlines) != expected
        or inflater.unconsumed_tail
        or inflater.unused_data
        or not inflater.eof
    ):
        raise BrandingImageError("unreadable")
    for row in range(height):
        if scanlines[row * (row_bytes + 1)] not in range(5):
            raise BrandingImageError("unreadable")

    output = _PNG_SIGNATURE + _png_chunk(b"IHDR", header)
    if palette is not None:
        output += _png_chunk(b"PLTE", palette)
    if transparency is not None:
        output += _png_chunk(b"tRNS", transparency)
    output += _png_chunk(b"IDAT", zlib.compress(scanlines, 9)) + _png_chunk(b"IEND", b"")
    if len(output) > MAX_FILE_BYTES:
        raise BrandingImageError("too_large")
    return output, width, height


# --- SVG ---------------------------------------------------------------------------------------


def _skip_separators(text: str, position: int) -> int:
    while position < len(text) and (text[position].isspace() or text[position] == ","):
        position += 1
    return position


def _number(value: str, *, minimum: float | None = None, maximum: float | None = None) -> float:
    text = value.strip()
    if not _NUMBER.fullmatch(text):
        raise BrandingImageError("unsafe_svg")
    number = float(text)
    if not math.isfinite(number) or abs(number) > MAX_COORDINATE:
        raise BrandingImageError("unsafe_svg")
    if minimum is not None and number < minimum:
        raise BrandingImageError("unsafe_svg")
    if maximum is not None and number > maximum:
        raise BrandingImageError("unsafe_svg")
    return number


def _view_box(value: str) -> tuple[int, int]:
    parts = [part for part in re.split(r"[\s,]+", value.strip()) if part]
    if len(parts) != 4:
        raise BrandingImageError("unsafe_svg")
    numbers = [_number(part) for part in parts]
    width, height = numbers[2], numbers[3]
    if width <= 0 or height <= 0 or width > MAX_DIMENSION or height > MAX_DIMENSION:
        raise BrandingImageError("dimensions")
    if not MIN_ASPECT <= width / height <= MAX_ASPECT:
        raise BrandingImageError("dimensions")
    return max(1, round(width)), max(1, round(height))


def _path_points(value: str) -> int:
    text = value.strip()
    if not text:
        raise BrandingImageError("unsafe_svg")
    position, command, points = 0, None, 0
    while True:
        position = _skip_separators(text, position)
        if position >= len(text):
            break
        if text[position] in _PATH_COMMANDS:
            command = text[position]
            position += 1
        elif command is None or command in "Zz":
            raise BrandingImageError("unsafe_svg")
        if command in "Zz":
            command = "Z"
            continue
        arity = _PATH_ARITY[command.upper()]
        while True:
            position = _skip_separators(text, position)
            for _ in range(arity):
                match = _NUMBER.match(text, position)
                if match is None:
                    raise BrandingImageError("unsafe_svg")
                number = float(match.group())
                if not math.isfinite(number) or abs(number) > MAX_COORDINATE:
                    raise BrandingImageError("unsafe_svg")
                position = _skip_separators(text, match.end())
            points += 1
            if points > MAX_SVG_PATH_POINTS:
                raise BrandingImageError("unsafe_svg")
            if position >= len(text) or text[position] in _PATH_COMMANDS:
                break
            if text[position] in "+-." or text[position].isdigit():
                if command in "Mm":
                    command = "l" if command == "m" else "L"
                continue
            raise BrandingImageError("unsafe_svg")
    return points


def _point_pairs(value: str) -> int:
    numbers: list[float] = []
    position = 0
    text = value.strip()
    while True:
        position = _skip_separators(text, position)
        if position >= len(text):
            break
        match = _NUMBER.match(text, position)
        if match is None:
            raise BrandingImageError("unsafe_svg")
        number = float(match.group())
        if not math.isfinite(number) or abs(number) > MAX_COORDINATE:
            raise BrandingImageError("unsafe_svg")
        numbers.append(number)
        position = match.end()
    if len(numbers) < 4 or len(numbers) % 2:
        raise BrandingImageError("unsafe_svg")
    pairs = len(numbers) // 2
    if pairs > MAX_SVG_PATH_POINTS:
        raise BrandingImageError("unsafe_svg")
    return pairs


def _transform(value: str) -> None:
    text = value.strip()
    if not text:
        raise BrandingImageError("unsafe_svg")
    position = 0
    while True:
        position = _skip_separators(text, position)
        if position >= len(text):
            break
        match = _TRANSFORM.match(text, position)
        if match is None:
            raise BrandingImageError("unsafe_svg")
        name, raw = match.group(1), match.group(2)
        numbers = [part for part in re.split(r"[\s,]+", raw.strip()) if part]
        if len(numbers) not in _TRANSFORM_ARITY[name]:
            raise BrandingImageError("unsafe_svg")
        for number in numbers:
            _number(number)
        position = match.end()


def _paint(value: str) -> None:
    if value == "none":
        return
    if re.fullmatch(r"#[0-9A-Fa-f]{3}", value) or re.fullmatch(r"#[0-9A-Fa-f]{6}", value):
        return
    raise BrandingImageError("unsafe_svg")


def _check_attribute(element: str, name: str, value: str) -> None:
    if name in {"fill", "stroke"}:
        _paint(value)
    elif name == "fill-rule":
        if value not in {"nonzero", "evenodd"}:
            raise BrandingImageError("unsafe_svg")
    elif name == "stroke-linecap":
        if value not in {"butt", "round", "square"}:
            raise BrandingImageError("unsafe_svg")
    elif name == "stroke-linejoin":
        if value not in {"miter", "round", "bevel"}:
            raise BrandingImageError("unsafe_svg")
    elif name in {"opacity", "fill-opacity", "stroke-opacity"}:
        _number(value, minimum=0, maximum=1)
    elif name == "stroke-miterlimit":
        _number(value, minimum=1)
    elif name in _SVG_COORDINATES:
        _number(value)
    elif name in _SVG_LENGTHS:
        _number(value, minimum=0)
    elif name == "d":
        _path_points(value)
    elif name == "points":
        _point_pairs(value)
    elif name == "transform":
        _transform(value)
    elif name == "viewBox":
        _view_box(value)
    elif name in {"width", "height"} and element == "svg":
        _number(value, minimum=0.000001)
    elif name == "xmlns":
        if value != _SVG_NS:
            raise BrandingImageError("unsafe_svg")
    else:
        raise BrandingImageError("unsafe_svg")


def canonical_svg(data: bytes) -> tuple[bytes, int, int]:
    """Parse an SVG under the allowlist and serialize a fresh tree; never returns input bytes."""
    root: ElementTree.Element | None = None
    stack: list[ElementTree.Element] = []
    elements = 0
    view_box: tuple[int, int] | None = None

    def refuse(code: str = "unsafe_svg"):
        raise BrandingImageError(code)

    def start(name: str, attributes) -> None:
        nonlocal root, elements, view_box
        elements += 1
        if elements > MAX_SVG_ELEMENTS or len(stack) + 1 > MAX_SVG_DEPTH:
            refuse()
        if root is None:
            if name != "svg" or stack:
                refuse()
        elif stack and stack[-1].tag in {"title", "desc"}:
            refuse()
        allowed: set[str] = set()
        if name == "svg":
            if stack:
                refuse()
            allowed = _SVG_ROOT_ATTRIBUTES | _SVG_PRESENTATION
        elif name == "g":
            allowed = set(_SVG_PRESENTATION)
        elif name in _SVG_ELEMENT_ATTRIBUTES:
            allowed = _SVG_ELEMENT_ATTRIBUTES[name] | _SVG_PRESENTATION
        elif name in {"title", "desc"}:
            allowed = set()
        else:
            refuse()
        pairs = [(attributes[index], attributes[index + 1]) for index in range(0, len(attributes), 2)]
        seen = [pair[0] for pair in pairs]
        if len(set(seen)) != len(seen):
            refuse()
        for attribute, value in pairs:
            if attribute not in allowed:
                refuse()
            _check_attribute(name, attribute, value)
            if attribute == "viewBox":
                nonlocal_view = _view_box(value)
                if name == "svg":
                    if view_box is not None:
                        refuse()
                    view_box = nonlocal_view
        node = ElementTree.Element(name, dict(pairs))
        if stack:
            stack[-1].append(node)
        else:
            root = node
        stack.append(node)

    def end(_name: str) -> None:
        if not stack:
            refuse()
        stack.pop()

    def characters(text: str) -> None:
        if not stack:
            if text.strip():
                refuse()
            return
        current = stack[-1]
        if current.tag in {"title", "desc"}:
            current.text = (current.text or "") + text
        elif text.strip():
            # Live lettering is not part of the upload profile, even though <title>/<desc> keep text.
            refuse()

    def always_refuse(*_args, **_kwargs) -> None:
        raise BrandingImageError("unsafe_svg")

    parser = expat.ParserCreate()
    parser.buffer_text = True
    parser.ordered_attributes = True
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = characters
    parser.StartDoctypeDeclHandler = always_refuse
    parser.EntityDeclHandler = always_refuse
    parser.UnparsedEntityDeclHandler = always_refuse
    parser.ProcessingInstructionHandler = always_refuse
    parser.CommentHandler = always_refuse
    parser.ExternalEntityRefHandler = lambda *_args: 0
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(data, True)
    except BrandingImageError:
        raise
    except (expat.ExpatError, ValueError, TypeError):
        raise BrandingImageError("unreadable") from None
    if root is None or root.tag != "svg" or stack or view_box is None:
        raise BrandingImageError("unsafe_svg")
    if "xmlns" not in root.attrib:
        raise BrandingImageError("unsafe_svg")
    output = ElementTree.tostring(root, encoding="utf-8", short_empty_elements=True)
    if len(output) > MAX_FILE_BYTES:
        raise BrandingImageError("too_large")
    return output, view_box[0], view_box[1]
