# Branding proof provenance

- `branding-proof-desktop.png`: actual Chromium screenshot of the committed static
  contact sheet, 1280 × 1440 CSS pixels, device scale factor 1.
- `branding-proof-mobile.png`: same fixture, 390 × 1440, device scale factor 1.
- Captured with Browser Use CDP `Page.captureScreenshot` after loading a
  self-contained data-URL copy from `scripts.render_branding.standalone()`.
  Only that inspection copy inlines the existing CSS and image bytes; committed
  `branding.html` retains relative external stylesheet/image paths and no scripts.
- Both captures show all identity variants and the SVG/PNG favicon row. All 12
  images loaded; document scroll width was no larger than viewport at either size.
- These are **static fixture screenshots, not deployed application screenshots**.
  The replacement settings flow is specified, not implemented or smoke-tested.
- Original asset artwork is deterministic code, not generated or stock imagery.
  `favicon-32.png` comes from `favicon.svg` geometry using the committed standard-
  library rasterizer, and embeds its source in a PNG text chunk.

Independent finish review: **ship**, no required changes, scoped to these assets,
the contact sheet and the design contract. Runtime upload/security verification
still belongs to the implementation card.
