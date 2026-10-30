"""Database-free UI contracts, fixture generation and WCAG palette checks."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def luminance(value):
    channels = [int(value[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= .04045 else ((c + .055) / 1.055) ** 2.4 for c in channels]
    return sum(c * w for c, w in zip(linear, (.2126, .7152, .0722), strict=True))


def contrast(a, b):
    high, low = sorted([luminance(a), luminance(b)], reverse=True)
    return (high + .05) / (low + .05)


def test_css_tokens_and_both_theme_contrast():
    css = (ROOT / "app/static/app.css").read_text()
    blocks = re.findall(r":root\s*\{([^}]+)\}", css)
    palettes = [dict(re.findall(r"--([\w-]+):\s*(#[0-9a-f]{6});", block)) for block in blocks[:2]]
    definitions = set(re.findall(r"--([\w-]+)\s*:", css))
    assert set(re.findall(r"var\(--([\w-]+)\)", css)) <= definitions
    assert not re.search(r"#[0-9a-fA-F]{3,8}", re.sub(r":root\s*\{[^}]+\}", "", css))
    assert len(css.splitlines()) < 450
    for palette in palettes:
        for background in ("surface", "surface-raised", "surface-inset"):
            for foreground in ("text", "text-muted", "accent"):
                assert contrast(palette[foreground], palette[background]) >= 4.5, (foreground, background)
            for foreground in ("border", "focus"):
                assert contrast(palette[foreground], palette[background]) >= 3
        for state in ("ok", "warn", "danger"):
            assert contrast(palette[state], palette[f"{state}-surface"]) >= 4.5
        for background in ("accent-fill", "danger-fill"):
            assert contrast(palette["on-accent"], palette[background]) >= 4.5
