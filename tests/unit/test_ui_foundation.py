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


def theme_palettes(css):
    """Resolve inherited aliases just as custom properties do in each theme."""
    palettes, tokens = [], {}
    for block in re.findall(r":root\s*\{([^}]+)\}", css)[:2]:
        tokens.update(re.findall(r"--([\w-]+):\s*([^;]+);", block))

        def resolve(name):
            value = tokens[name]
            alias = re.fullmatch(r"var\(--([\w-]+)\)", value)
            return resolve(alias[1]) if alias else value

        palettes.append({name: resolve(name) for name in tokens})
    return palettes


def test_css_tokens_and_both_theme_contrast():
    css = (ROOT / "app/static/app.css").read_text()
    palettes = theme_palettes(css)
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
        assert contrast(palette["on-accent"], palette["accent-fill"]) >= 4.5
        assert contrast(palette["on-danger"], palette["danger-fill"]) >= 4.5


def test_stitch_shared_style_contract():
    css = (ROOT / "app/static/app.css").read_text()
    assert "--focus-width: 2px;" in css
    assert "outline-offset: var(--focus-width)" in css
    assert "--radius-panel: var(--radius);" in css
    assert "--radius-pill: var(--radius);" in css
    assert "position: sticky;" in css
    assert "box-shadow: inset var(--status-width) 0 var(--row-state)" in css
    for state in ("ok", "warn", "danger", "text-muted"):
        assert f"--row-state: var(--{state})" in css
    assert len(set(re.findall(r"font-size:\s*var\(--([\w-]+)\)", css))) <= 5
    for path in (ROOT / "app/static/pages").glob("*.css"):
        assert not re.search(r"#[0-9a-fA-F]{3,8}", path.read_text()), path
