# Operations UI design system

## Intent

An operator reads certificate state and security failures before taking action.
Use quiet, near-black surfaces, blue actions, generous table rows and restrained
hairlines. Light mode supports daytime/projector use without a second component
system. No illustrations, gradients, web fonts, animation on entry or build step.

## Tokens (`app/static/app.css`)

Dark is the root theme; `prefers-color-scheme: light` overrides the same names.
Use `var(--token)` in rules; never introduce page-specific colours.

| Token | Dark | Light | Meaning |
|---|---|---|---|
| `surface` | `#101419` | `#f3f5f7` | Page canvas |
| `surface-raised` | `#1b222b` | `#ffffff` | Header, panels, table body |
| `surface-inset` | `#151b22` | `#e8edf3` | Inputs, table headings, code |
| `border` | `#8290a1` | `#697789` | Interactive boundaries (3:1 minimum) |
| `separator` | `#394552` | `#c5ced8` | Decorative row/panel dividers, not control boundaries |
| `text` | `#edf1f6` | `#172333` | Main content |
| `text-muted` | `#b3bfcd` | `#49596c` | Help and secondary content |
| `accent` | `#93c5fd` | `#204f89` | Links, selection indicators, info |
| `accent-fill` | `#244f83` | same | Primary button and text selection |
| `on-accent` | `#ffffff` | same | Filled-button/selection text |
| `ok` / `ok-surface` | `#91d8af` / `#173529` | `#21633d` / `#e2f2e8` | Valid/success |
| `warn` / `warn-surface` | `#f1cd7d` / `#382e1b` | `#775000` / `#fff1cf` | Expiring, degraded, requires attention |
| `danger` / `danger-surface` | `#ffb4b4` / `#422528` | `#9b252e` / `#fce8e9` | Expired, critical, errors |
| `danger-fill` | `#963c43` | same | Destructive button |
| `focus` | `#f1cd7d` | `#865b00` | Keyboard focus, 3px outline + 3px offset |

Body/help/link text is tested at 4.5:1 on all three neutral surfaces; state
text at 4.5:1 on its state surface; control boundaries/focus at 3:1.
These palette checks are not a complete accessibility audit.

- Spacing: `space-0` through `space-8` = `0, .25, .5, .75, 1, 1.5, 2, 3, 4rem`.
- Type: `text-sm .875rem`, `text-base 1rem`, `text-brand 1.125rem`,
  `text-lg 1.5rem`, `text-xl 2rem`; line heights `leading 1.6`, `leading-tight 1.25`;
  weights `weight-medium 600`, `weight-bold 700`. Body measure `72ch`.
- `font-sans`: system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif.
  `font-mono`: ui-monospace, SFMono-Regular, Consolas, Liberation Mono, monospace.
  Numbers, dates, serials and fingerprints use tabular numerals and monospace,
  not monospaced prose. Add `.numeric` for right alignment and `.mono` for identifiers.
- Radius: `radius .25rem`, `radius-panel .5rem`, `radius-pill 2rem`.
  `line 1px`; controls minimum `control-height 2.75rem`.
- Widths: content `80rem`, panel `42rem`, auth `30rem`, field `24rem`,
  filter/menu `12rem`, definition-list label `14rem`.
- Elevation: user-menu only, `0 .5rem 1.5rem #00000040` dark,
  `0 .5rem 1.5rem #17233320` light. Ordinary panels are flat.
- Motion: button background transition `duration 120ms`,
  `ease cubic-bezier(.2, 0, 0, 1)`; reduced motion replaces duration with
  `duration-reduced 0s`. No animated page entrances or scrolling.
- Shell stacks below 720px (media query `max-width: 719px`). Navigation wraps;
  the open user menu stays in flow on small screens. Tables scroll inside `.table-wrap`.

## Canonical components

| Component | Markup / classes |
|---|---|
| Primary action | `<button>` or `<a class="button" href="…">` |
| Secondary action | `.button-secondary` (add `.button` on links) |
| Destructive action | `.button-destructive`; always explicit label + confirmation |
| Disabled action | Native `disabled` on buttons; non-link text for unavailable navigation. `.button[aria-disabled="true"]` is visual only: omit `href` to prevent activation. |
| Text field | Native `label[for]` + `input[id]`; `.panel` stacks labels/fields |
| Help / field error | `.help` (legacy `.hint`); `.form-error[role="alert"]`; link field-specific messages with `aria-describedby`, use `aria-invalid="true"` when known |
| Select | Native `<select>` with associated label; shared input definition |
| Checkbox | `<label class="checkbox" for="…"><input type="checkbox" id="…"> Label</label>` |
| Table | `.table-wrap > table`; semantic `thead`, `th`, `tbody`; `.numeric`, `.mono` cells |
| State pill | `.badge` + `.badge-ok`, `.badge-warn`, `.badge-danger`, `.badge-info`; shared `.chip` aliases remain for later page migrations |
| State icons | Jinja `icon(kind)` from `_ui.html.j2`: `ok` check, `warn` triangle, `danger` cross-circle, `info` information-circle; authored SVG, hidden from assistive technology because adjacent visible label carries the meaning |
| Banners | `.banner.banner-info`, `.banner.banner-warning`, `.banner.banner-critical`; include visible severity and icon; preserve `role="status"` / `role="alert"` and existing `data-banner` hooks |
| Empty state | `.empty-state` with heading, explanation, optional recovery action |
| Pagination | `<nav class="pager" aria-label="Pagination">`; `aria-current="page"`; unavailable Previous/Next are text with `aria-disabled="true"`, not live links |
| Confirmation | Native `<details class="confirmation">` with explicit destructive summary, consequences, final POST form/CSRF and `.button-destructive`, and Cancel link to current safe page; no JS needed. This is an inline confirmation disclosure, **not** a modal dialog; never claim modal semantics/focus trapping. |
| Skip link | `.skip-link` targets `main#main-content[tabindex="-1"]` |
| Header / user menu | `.site-header`, `.brand`, native `details.user-menu`, `.user-menu-links`; main nav marks the current item's wrapper with `aria-current="page"` for exact and descendant paths, preserving the existing anchor markup |
| Auth / setup / errors | `.panel.narrow.auth-panel`, `.panel.narrow.bootstrap-panel`, `.error`, `.error-status`; messages, request IDs and bootstrap command remain visible |

`button.link`, `.notice`, `.secret-once`, `.warning-note`, `.filters`, `.counter*`,
`.fields`, `.actions`, `.lineage`, `.codes`, `.notes`, `.plain`, `.warnings`, `.tabs`,
`.action-disabled`, `.row-attention`, `.row-inactive`, legacy badge/chip state names
and `table.users` hooks retain shared, token-based compatibility for cards 2–5.
Do not fork button/table/badge implementations during those migrations. Existing
page markup is not migrated by this card; state icons and numeric modifiers must
be applied as those pages come into scope.

## Preview and verification

Run `uv run python scripts/render_previews.py`, then open
`docs/ui/previews/login.html`, `login-2fa.html`, `bootstrap.html`, `error-403.html`,
`error-404.html`, `error-500.html`, `login-error.html`, `login-2fa-error.html`, or
`shell.html`. Assets resolve relative to the repository, including the unchanged
vendored HTMX. Shell fixtures exercise every core component and all banner kinds.
Forms/links are fixture demonstrations, not a running service. The generator uses
Jinja directly with autoescaping; no app import, database, new dependency or JS.

`tests/unit/test_ui_foundation.py` checks token coverage, palette contrast and CSS
budget using only assets shipped in the test image. `tests/test_ui_previews.py`
checks auth forms, escaping, banner hooks, the destructive POST/CSRF confirmation
contract and byte-for-byte equality of every committed preview with regenerated
output at repository level (fixtures/scripts are not runtime assets). The static
confirmation submit is disabled, uses a fixture-only CSRF token and a fragment
action, and explicitly states that no certificate will be deleted; production
confirmations use the existing destructive POST route and a real CSRF token.
Existing
`tests/integration/test_login_account.py` checks CSRF field extraction, unchanged
POST routes, username retention/no password echo, error copy, MFA/cancel flow,
bootstrap command and absence of registration forms, and only vendored scripts.
No CSP policy is set in `app/main.py` or elsewhere in this repository; this change
still introduces neither inline scripts/styles nor remote resources.

Structural checks passed; visual verification pending on the deployed instance.
Review dark/light, narrow/wide, keyboard navigation, user-menu expansion, zoom,
long failure messages and auth flows there before asserting visual accessibility.
