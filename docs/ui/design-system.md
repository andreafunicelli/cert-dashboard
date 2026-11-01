# Operations UI design system

## Intent

An operator reads certificate state and security failures before taking action.
Use quiet, blue-black surfaces, cyan actions, generous table rows and restrained
hairlines. Light mode supports daytime/projector use without a second component
system. No illustrations, gradients, web fonts, animation on entry or build step.

## Tokens (`app/static/app.css`)

Dark is the root theme; `prefers-color-scheme: light` overrides the same names.
Use `var(--token)` in rules; never introduce page-specific colours.

| Token | Dark | Light | Meaning |
|---|---|---|---|
| `surface` | `#0b1326` | `#f5f7fc` | Page canvas |
| `surface-raised` | `#171f33` | `#ffffff` | Header, panels, table body |
| `surface-inset` | `#222a3d` | `#e8edf5` | Inputs, sticky table headings, code |
| `surface-variant` | `#2d3449` | `#dce3ee` | Reserved stronger neutral from reference; not another card layer |
| `border` | `#869397` | `#68777b` | One interactive outline colour (3:1 minimum) |
| `separator` | `#3d494c` | `#c0cbce` | One decorative hairline colour; not a control boundary |
| `text` | `#dae2fd` | `#172033` | Main content |
| `text-muted` | `#bcc9cd` | `#47565c` | Help, secondary content, unknown state |
| `primary` / `accent` | `#4cd7f6` | `#006579` | Links and selection indicators; accent aliases primary |
| `primary-container` / `accent-fill` | `#06b6d4` | `#006579` | Primary button and text selection |
| `secondary` | `#c0c1ff` | `#52538c` | Reference token only; not a second action colour |
| `on-accent` | `#002e38` | `#ffffff` | Primary-button/selection text |
| `on-danger` | `#ffffff` | same | Destructive-button text, distinct from on-accent |
| `ok` / `ok-surface` | `#1bbd85` / `#10352b` | `#006b48` / `#def5e9` | Reference tertiary / valid / success |
| `warn` / `warn-surface` | `#f1cd7d` / `#382e1b` | `#775000` / `#fff1cf` | Expiring, degraded, requires attention |
| `danger` / `danger-surface` | `#ffb4ab` / `#4b2025` | `#a1262b` / `#ffebe8` | Expired, critical, errors |
| `danger-fill` | `#93000a` | same | Reference error-container / destructive button |
| `focus` | `#4cd7f6` | `#006579` | Primary-colour keyboard focus, 2px outline + 2px offset |

Body/help/link text is tested at 4.5:1 on all three neutral surfaces; state
text at 4.5:1 on its state surface; control boundaries/focus at 3:1.
These palette checks are not a complete accessibility audit.

- Three working surface layers: canvas → raised card/table → inset control/header.
  Normal panels have no visible outline; control outlines and table hairlines keep
  their distinct accessibility roles. No new per-page grey or decorative shadow.
- Spacing: an 8px grid; `space-0` through `space-8` =
  `0, .5, .5, 1, 1, 1.5, 2, 3, 4rem`. Compatibility token names are retained;
  adjacent aliases intentionally coincide rather than introducing off-grid values.
- Type: `text-sm .875rem`, `text-base 1rem`, `text-brand 1.125rem`,
  `text-lg 1.5rem`, `text-xl 2rem`; line heights `leading 1.6`, `leading-tight 1.25`;
  weights `weight-medium 600`, `weight-bold 700`. Body measure `72ch`.
- `font-sans`: `Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`.
  `font-mono`: `ui-monospace, "JetBrains Mono", "SFMono-Regular", Menlo, Consolas, monospace`.
  LAN-only deployments must not request a CDN: installed fonts are preferred,
  otherwise local system fallbacks apply. No font files are fetched or bundled.
  Embedding Inter requires a separate operator decision and committed font files.
  Numbers, dates, serials and fingerprints use tabular numerals and monospace,
  not monospaced prose. Add `.numeric` to both a dedicated date/number column's
  heading and cells (including missing-value cells), and `.mono` for identifiers.
  Do not rely on `td:has(> time)`: nested timestamps such as server discovery
  live inside a paragraph. Explicit column classes align their headings too.
- Exactly five type sizes (14/16/18/24/32px at the default root). H1 is largest;
  H2 is 24px, H3/brand 18px, all tables 14px. Counter figures are subordinate to H1.
- One radius: `radius .25rem` (4px); `radius-panel` and `radius-pill` alias it.
  `line 1px`; inputs/selects/buttons share minimum `control-height 3rem` and
  8px block / 16px inline padding. Certificate rows use `row-height 3.5rem` (56px).
- Widths: content `80rem`, panel `42rem`, auth `30rem`, field `24rem`,
  filter/menu `12rem`, definition-list label `14rem`.
- Elevation: overlapping user/action menus only, `0 .5rem 1.5rem #00000040` dark,
  `0 .5rem 1.5rem #17233320` light. Ordinary panels are flat.
- Motion: button background transition `duration 120ms`,
  `ease cubic-bezier(.2, 0, 0, 1)`; reduced motion replaces duration with
  `duration-reduced 0s`. No animated page entrances or scrolling.
- Shell stacks below 720px (media query `max-width: 719px`). Navigation becomes
  a native Menu disclosure containing grouped page links; desktop shows the four
  areas and only the current area's second-level bar. The open user menu stays
  in flow on small screens. Tables scroll inside `.table-wrap`.
  Shared table regions cap at `table-height 36rem` so the stronger sticky header
  stays visible during region scrolling. The desktop certificate list keeps its
  existing overflow-visible action menus and page scrolling; its header sticks
  to the viewport instead. On narrow screens its horizontal scroll stays local.

### Measured contrast (WCAG relative luminance)

| Foreground / background | Dark | Light |
|---|---:|---:|
| Body / surface | 14.34:1 | 15.18:1 |
| Muted / surface | 10.90:1 | 7.12:1 |
| Accent / surface | 10.88:1 | 6.24:1 |
| On-accent / primary button | 5.97:1 | 6.69:1 |
| OK / OK background | 5.53:1 | 5.74:1 |
| Warning / warning background | 8.74:1 | 6.39:1 |
| Danger / danger background | 8.07:1 | 6.47:1 |
| On-danger / destructive button | 9.35:1 | 9.35:1 |

White on the reference's bright cyan fails AA, so dark primary buttons use dark
on-primary text; destructive red buttons retain white. Tests resolve inherited
aliases in both themes and check all three neutral layers, not just the canvas.

### Shared status-row component

Existing state macros remain the presentation source of truth: authored SVG icon
plus visible word inside `.badge` (legacy `.chip` supported). One shared CSS
component decorates `tbody > tr:has(> td .badge, > td .chip)` with a 4px inset
left bar on the first cell. It does not change table width, routes, fields, hooks,
accessible names or lifecycle decisions. Multiple observations use worst-severity
precedence: danger → warning → OK → muted/unknown. This is visual aggregation,
not a new host health verdict. Unknown badges are muted, not action-cyan.

The same implementation covers certificate, endpoint scan, server discovery,
binding, recent-job, discovery-history, scan-history and deployment-host rows.
No template hooks, duplicate state mapping, JavaScript or new icon assets are
needed. Browsers without CSS `:has()` retain the existing accessible icon/word;
they omit only the supplementary bar. Target browsers are current Chromium,
Firefox and Safari. Status text never depends on that bar to convey meaning.

## Page styles

Shared tokens and components live in `app/static/app.css`. Styles specific to one
area live in `app/static/pages/<area>.css`, loaded by that area's own template
through the empty-by-default `extra_css` block immediately after the shared stylesheet:

```jinja
{% block extra_css %}<link rel="stylesheet" href="/static/pages/certificates.css">{% endblock %}
```

Fixed area filenames (one area, one file; never name a file after a lane):
`overview.css`, `account.css`, `users.css`, `audit.css`, `certificates.css`,
`renewals.css`, `import.css`, `scans.css`, `servers.css`, `bindings.css`,
`deploy.css`, `settings.css`, `email.css`.

- **`app.css` is shared property.** A lane card may add a shared token or component
  only when genuinely needed, and must call out that shared-file change in its PR
  description so the reviewer can anticipate conflicts.
- Page styles never go in `app.css` or a `<style>` element. Inline styles are
  forbidden by the CSP contract; use external stylesheets, not `style` attributes.
- Use plain CSS and the existing `:root` tokens; no new colour literals.

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
page markup keeps its existing state macros. The shared Stitch status-row
component consumes those existing badges without changing the markup contracts.

## Calmer list composition (certificate area)

Reuse these shared components for subsequent areas rather than adding another
button, badge or header style:

- `.page-header`: flex title/subtitle group on the left, `.page-actions` on the
  right; stacks naturally on narrow screens. The `h1` remains `text-xl`, the
  largest page text. `.page-subtitle` is muted `text-sm`. There is exactly one
  visible filled primary action: **Import certificate**. Secondary tasks go into
  native `details.action-menu > summary` with `.action-menu-items` (no ARIA menu
  role: this is ordinary links/forms with native Tab order, not a JS menu widget).
- `.filter-bar`: always-visible search capped by `search-width: 20rem` on desktop,
  full-width on mobile. All eight other filters remain successful controls in
  the same native GET form behind `details.filter-disclosure`. Closed controls
  still submit their selected values. `Filters · N` counts non-search filters;
  `.applied-filters` appears only with an active filter, next to Reset. Chip links
  remove just that filter, reset pagination, and preserve all remaining filters,
  sort and page size with Jinja's URL encoding and automatic HTML escaping.
- `.certificates` row contract: common-name link, issuer, right-aligned monospaced
  exact expiry date, **one** icon/word state, right-aligned bindings count, native
  row actions. `certificate_state(..., compact=true)` shares lifecycle precedence
  with detail; expiring active certificates show days instead of a second expiry
  badge, unknown shows Unknown. SAN count, owner, source and key remain available
  on detail, not repeated in the default list. No hidden duplicate status.
- Rows use `row-height: 3.5rem` (56px at default text size) with 48px action-summary
  targets, no vertical cell padding. Header uses muted text and the existing
  inset surface/hairline separators. Cells do not wrap at desktop widths;
  oversized common names/issuers ellipsize with full text in `title` and on the
  common-name detail link. Below 1280px (`max-width: 1279px`) column priorities
  reserve more space for dates/status; below 720px the table scrolls **inside**
  its labelled focusable region. On mobile open row menus stay in flow to avoid
  clipping inside that scroll region; desktop menus overlay without changing
  row height, including at the last row.
- Row menus use existing detail, POST scan + CSRF, leaf download and destructive
  lifecycle-confirmation destinations. **There is no certificate delete route**:
  the menu explicitly explains deletion is unavailable and points to confirmed
  revoke/supersede on detail. Do not invent a delete endpoint or imply a download
  contains private keys. Destructive links use `.action-destructive` with the
  existing danger token; actual mutation remains behind the detail confirmation.

Text wrapping uses `break-word` instead of `anywhere` throughout normal content:
`anywhere` lowers intrinsic word widths and previously let table/flex tracks
collapse words into character columns. Bounded raw material and fingerprint
regions retain their intentional behavior; `.identifier`/`.material` remain
non-wrapping scrollable exact-copy values. The global wrapping substitution is
mechanical, not a redesign of the other areas.

`certificate-list-dense.html` contains twenty synthetic rows; filtered/empty
variants exercise disclosures and removable chips. After the Stitch token pass,
static Chromium checks at 1024px (900px viewport height) covered all 70 non-email
fixtures in **both themes**: 140 fixture/theme combinations, no page overflow,
and exactly five computed type sizes (14/16/18/24/32px). Every matching state row
had a computed inset bar, including certificate, endpoint, server, binding, job
and deployment-host lists. At 1280px, the certificate fixture has 10 complete rows
above the fold and all twenty rows measure 56px. Its sticky header remained at
viewport top after scrolling; keyboard focus measured 2px plus 2px offset in both
themes. This supersedes the earlier 48px/12-row evidence. Palette tests check
dark and light contrast. These checks are not a complete WCAG audit or a
database-backed application test.

The existing generator regenerates all 72 HTML previews. The initial token pass
left their bytes unchanged; the review correction adds `.numeric` classes to the
date headers/cells in audit, server inventory/discovery history and endpoint
inventory/scan history. No template structure or fixture content changed.
Screenshots inspected here are **static fixtures**, never the deployed app.

`tests/test_stitch_styles.py` is a repository-only, Docker-independent CSS/DOM
regression suite. It renders real certificate, server, binding and endpoint lists,
matches the shared component's deliberately bounded selector grammar against
their DOM, and checks the cascaded bar for both palettes. It exercises every
severity/fallback, competing observations, reordered cells/badges and unbadged
audit rows. Date-column assertions cover matching headings/cells, missing values
and server timestamps nested inside `p`. The evaluator is not a browser engine;
unsupported component selector syntax fails rather than being silently ignored.
The suite runs in normal repository CI, not the runtime-image unit suite (which
does not ship the preview generator). No dependency or browser install is needed.
Separate static Chromium checks of seven fixtures in both themes at 1024×900
confirmed 30 date/header pairs aligned right with monospaced timestamps, 42
painted status rows and no page overflow. This is not deployed-flow evidence.

Structural checks passed; visual verification pending on the deployed instance.

## Task-first shell and overview

`_navigation.html.j2` owns presentation-only grouping; existing `navigation`
entries remain the capability source for the existing page links. URLs are not
rewritten. Desktop has Overview plus Certificates, Infrastructure, Operations and
Administration; only the active area exposes a second row. Its outlined,
heavy-bottom tab and the selected page's inset background/underline are shape
cues as well as colour. Current page wrappers retain `aria-current="page"` and
exact anchor markup for compatibility; the area uses `aria-current="location"`.
The same page-link macro renders mobile groups inside native `details` with a
Menu summary. CSS displays only one navigation variant at a time; hidden links
are not keyboard stops. No scripts or ARIA menu widget are involved.

Discovery is the existing `/servers#discovery-actions` section, not a new route
or an automatic discovery trigger. The server page remains the current page
because URL fragments are not available to the server. Import-progress URLs
belong to Import, renewal screens to Renewals, and deployment job lists to Jobs.
Account/Users remain in the existing utility disclosure as well as Administration.

The overview reuses `.page-header`, the shared table/status-row/icon/badge
components and native `.filter-disclosure` instead of a second card system.
It displays at most four nonzero attention rows, sourced only from `QueueCounts`.
The fourth row totals the disjoint failed/rolled-back deployment counts and
provides **two exact filtered links**, rather than inventing an unsupported
union filter. Historical failures are retained in the diagnostic disclosure,
not used as a proxy for queue counts. Empty attention is one calm sentence;
it does not imply every endpoint passed every TLS check.

In-flight counts link to the real awaiting-certificate, running-scan and
running-deployment lists. Awaiting includes draft/CSR-generated/submitted, not
issued/deployed. All renewal states and their older per-request age details
remain reachable. System is one shared-surface strip with four compact fields,
wrapping on small screens, and a direct Settings → Status link. Last discovery
means last **successful** discovery; heartbeat remains in the diagnostic
disclosure. Existing inventory and TLS counters retain their hooks and ranges.

`overview-clear.html` adds an inventory-present, empty-queue fixture alongside
the populated and first-run previews. All shell-using previews are regenerated
because the base template changed. Repository tests cover exact active leaves,
capability fallback, count/list URLs, four-row bounds, independent large queue
counts, calm zero state, all old counters and deterministic preview bytes.
Shared-file hotspot: `app.css` changes only navigation; palette, buttons, badges
and status-row implementation are reused unchanged.

Structural checks passed; visual verification pending on the deployed instance.
Static Chromium fixture checks with JavaScript disabled covered seven pages
(overview populated/clear/first-run, certificates, servers, scans, settings status),
both themes and widths 375/719/720/1024/1280/1440px: 84 combinations, no document
horizontal overflow. Native Menu opened without JavaScript; the diagnostic
summary toggled by keyboard and revealed existing expiry/TLS counters. Inspected
dark overview, light certificate navigation and open mobile Menu captures.
Static fixtures are not database-backed or deployed-flow evidence. Verify full
keyboard order/focus, zoom and all filtered queue destinations on deployment.

## Preview and verification

### Deploy, settings and outbound email

`deploy.css`, `settings.css` and `email.css` are opt-in area styles. No shared
palette, button, badge or table implementation is forked, and `app.css` is unchanged.
`deploy/_ui.html.j2` maps worker states to the canonical icon + badge + label.
The guardrail verdict precedes the preview details; rollout options are a native
disclosure so the verdict is not buried under the options form. Start still requires
the explicit plan checkbox, plan hash and existing POST/CSRF. Cancel is a native
confirmation; `hx-preserve` keeps that disclosure open through live progress swaps.
Failure host, reason code and recovery links precede job metadata. Failed/restored
batches open automatically; no scroll behaviour is added. Rollback is automatic,
not an operator command. Its per-host state and old fingerprint come from the
worker's view; rollback time is not exposed by this view and is labelled unavailable.

SMTP test results remain on the page, including timestamps, step/reply codes and
failure details, with an ordinary refresh link for non-HTMX use. Test send uses
saved settings. “Delivered” is the existing recorded SMTP outcome, not a claim
that the message arrived in the recipient's inbox. Outbound HTML mail uses native
semantic headings, row headers and text links without scripts, styles, remote
assets or a second email palette. Its text/plain alternatives remain unchanged.
Mail-client default fonts/colours are intentional: these messages must remain
readable without fetching LAN-only CSS and without relying on CSS support.

#### Approved settings progressive-enhancement exception

The operator approved one dependency-free script, `app/static/settings.js`, because
full tab navigations otherwise discard unsaved configuration. Only settings loads
it, with `defer`. It uses no inline handler, `eval`, HTML injection, auto-submit or
submit interception. It works with `script-src 'self'`; CSP policy itself is not
changed. HTMX 422 behaviour uses the existing declarative `enhanced_forms()` macro.

- Tabs with pending drafts retain a visible “unsaved draft” label, including when
  a different section is open. Text/select/checkbox changes get a warning-colour boundary **and** visible
  “Unsaved change” text, plus a persistent section status.
- Explicit tab navigation asks before leaving; other exits use `beforeunload`
  (browser-controlled wording; browser may suppress prompts without interaction).
- Non-secret configuration drafts and their initial values are scoped per section
  in this browser tab's `sessionStorage`. Returning restores the draft and dirty
  indicators. A successful save marker clears only that section's draft; HTTP 422
  retains it and preserves server-rendered validation values. A consumed `saved`
  URL flag is removed so reload does not clear a subsequently edited draft.
  The trust-bundle toggle uses its existing one-shot success flash instead of a
  `saved` URL flag; uploads/deletions do not clear an unrelated pending toggle.
- Password controls, hidden/file inputs and any field name containing `secret`,
  `key` or `token` are never read or stored. Repository URLs are also never stored:
  even an invalid URL can contain credentials. Their changes are marked but must
  be saved before switching. Trust uploads, typed destructive confirmations and
  CLI key rotation are not configuration drafts and are not persisted.
- No draft is a server-side save. Closing the browser tab ends its drafts; anyone
  using that same browser tab can read its non-secret drafts. Storage denial is
  reported visibly and the tab confirmation explicitly warns that switching
  discards unsaved changes; cancelling keeps the values and unload guard active.
  The always-visible
  no-JavaScript notice explains that unsaved values are lost across sections.

Extend `scripts/render_previews.py` via `operations_fixtures()`; do not create a
second renderer. New previews cover allowed/blocked deploys, failed/running/paused
jobs, all ten settings tabs, queued/succeeded SMTP outcomes and both outbound HTML
messages. `tests/test_operations_previews.py` checks native forms, hooks, escaping,
fragments, state hierarchy, confirmation and the script/CSS boundaries. Run
`node --test tests/settings_drafts.test.cjs` for dependency-free draft lifecycle,
secret exclusion, navigation guard, 422/success and storage-denial tests. Node is
a test-only tool, not a runtime dependency or a build step.

Structural checks passed; visual verification pending on the deployed instance.
Static preview inspection is not deployed application, email-client, inbox-delivery
or complete WCAG proof. On deployment, verify no-HTMX saves/422s, actual SMTP
results, keyboard focus, both themes, narrow layouts, slow live swaps and canary
failure restoration using synthetic demo data.

### Inventory, renewals, import and scans

These areas load `certificates.css`, `renewals.css`, `import.css`, `scans.css` via
`extra_css`. They reuse shared buttons, tables, badges, confirmations and icons;
no page-specific palette is introduced. Shared additions in `app.css`:

- `material-height: 16rem`, `identifier-width: 36ch` bound long data.
- `.bounded`: vertically/horizontally scrollable SAN, DN or diagnostic region;
  use `tabindex="0"`, `role="region"` and a descriptive `aria-label` when scrollable.
- `.material`: selectable, non-wrapping PEM/CSR in a bounded `<pre>`.
- `.identifier`: keyboard-focusable, selectable serial/hash; no mid-value wrapping.
  `identifier(value)` in `_inventory_ui.html.j2` groups four characters with CSS
  margins, **not inserted characters**: DOM text/copy remains byte-for-byte the
  original value. Tables bound the identifier viewport, not the stored value.
  The exact value is also in the title. Copy uses native selection and the
  clipboard shortcut; no misleading JS-only copy button is shown.

Presentation macros in `_inventory_ui.html.j2`:

- `certificate_state(cert, now)`: revoked/superseded lifecycle takes priority;
  active certificates show not-yet-valid, expired, expiring (<60 days, matching
  existing expiry buckets), or valid. Unrecognised state/missing dates shows
  unknown validity. Each uses the canonical badge + SVG + visible word. The compact
  list variant shows days in the same badge for expiring active certificates;
  the exact date remains a separate right-aligned monospaced column.
- `chain_verdict(status)`: trusted / incomplete / untrusted root / not verified;
  missing diagnostics explicitly shows incomplete chain **verification**, not a
  fabricated verdict about missing intermediates. Detail prioritises the current assessment, never silently
  substitutes cached trust. Cached state and download inputs remain below it.
- `scan_state(status)`: no findings, findings (expired/mismatch), scan failed
  (unreachable/error), and not scanned are separate labels with shared icons.
  “No findings” means only the expiry/mismatch checks, not a full TLS audit.
- `enhanced_forms()`: head metadata configures the **unchanged vendored HTMX 2.0.8**
  to swap HTTP 422 form fragments, replacing legacy inline script handlers. Other
  4xx/5xx responses retain the default non-swapping behaviour. Native form methods,
  actions, CSRF and validation work without HTMX. No JavaScript is added.

Renewal position reflects the six real screens supplied by the existing route:
Basics, CSR, Order, Upload, Ready, Done. Do not invent four backend steps. Future
unavailable screens are plain text, not links that bounce to the current screen;
the Order/Upload pair remains navigable in submitted state. Each screen retains
its existing transition controls and an inventory/certificate exit. Ready shows
the pre-deploy summary; finalization names the new and previous certificates.
Status changes, stored-chain replacement, cancellation and finalization use native
target-named confirmation disclosures and destructive submit buttons. No delete
route is invented; overwrite-on-deploy confirmation belongs to the deploy area.

Inventory previews generated by the existing script:
`certificate-list.html`, `certificate-detail.html`, `certificate-edit.html`,
`certificate-export.html`, `renewal-basics.html`, `renewal-csr.html`,
`renewal-submitted.html`, `renewal-upload.html`, `renewal-ready.html`,
`renewal-done.html`, `scan-list.html`, `scan-findings.html`, `scan-clear.html`,
`scan-failed.html`, `scan-unscanned.html`, `import.html`, `import-progress.html`.
These are explicit synthetic fixtures, not recorded service results. Long SAN/DN
and CSR fixtures exercise bounded markup. Tests cover macro outcomes, exact copy
text, escaping, field names, fragment rendering, confirmation targets, head-only
HTMX configuration, relative assets and deterministic regeneration.

Structural checks passed; visual verification pending on the deployed instance.
Check 1280px and narrow layouts, both themes, long input/PEM scrolling, native
selection/copy, keyboard focus, no-HTMX POST/error flows, HTMX 422 swaps and all
wizard states on deployment. Static checks do not prove absence of page overflow
or complete WCAG 2.2 AA conformance.

Run `uv run python scripts/render_previews.py`, then open
`docs/ui/previews/login.html`, `login-2fa.html`, `bootstrap.html`, `error-403.html`,
`error-404.html`, `error-500.html`, `login-error.html`, `login-2fa-error.html`, or
`shell.html`. Assets resolve relative to the repository, including the unchanged
vendored HTMX. Shell fixtures exercise every core component and all banner kinds.
Forms/links are fixture demonstrations, not a running service. The generator uses
Jinja directly with autoescaping; no app import, database or new dependency. Only
settings previews load the approved settings-only enhancement described above.

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

### Operator surfaces (overview, account, users, audit)

The renderer also produces `overview.html`, `overview-empty.html`, `account.html`,
`account-enrollment.html`, `account-required.html`, `account-directory.html`,
`account-error.html`, `users.html`, `users-empty.html`, `audit.html` and
`audit-empty.html`. Fixtures include a stale worker, expiry buckets, failed jobs,
directory-managed accounts, disabled actions, one-time **fake** enrollment material,
and long audit actor/path/user-agent values with an escaping canary.

- Overview order is Needs attention → In flight → System → the native Inventory
  and history disclosure. Counter links and `data-*` hooks are unchanged; all old
  counters, unknown bindings, recent jobs/failures and renewal details are inside
  that one-click disclosure. First-run setup remains visible outside it.
  TLS counts are last recorded results, not live probes. The read model does not
  expose scan freshness: inspect timestamps via the Scans link. The never-scanned
  count continues to open all endpoints (no matching list filter exists).
- Account uses the existing confirmation disclosure for disabling 2FA and replacing
  pending enrollment, with consequences before the final password-protected POST.
  Current-session logout is not a revoke-all control; there is no session listing
  in the read model. Enrollment codes are never synthesized in production markup.
- All active users are administrators in v1; there is no editable role selector.
  User security actions reuse `.confirmation` and `.button-destructive`, retaining
  directory-disabled password resets and self-deactivation warnings.
- Audit summary uses a fixed-layout shared table with ellipsis/title values.
  Each event's native disclosure occupies a following full-width row; full actor,
  action, target, agent and wrapped JSON remain keyboard-reachable without JS.
  The summary retains the single `data-audit-row` hook per event for pagination.
- Page composition lives in the four documented per-area stylesheets. No new
  shared tokens or components were needed; `app.css` is unchanged.

Repository preview checks additionally verify operator POST/CSRF contracts,
password non-echo, confirmation ancestors, overview ordering and counter links,
audit escaping/full-width detail, account variants and exact generated bytes.
`test_page_styles.py` now uses login/bootstrap for the inert-hook comparison:
account intentionally overrides that hook and has a dedicated stylesheet check.

Structural checks passed; visual verification pending on the deployed instance.
Review dark/light, narrow/wide, keyboard navigation, user-menu expansion, zoom,
long failure messages and auth flows there before asserting visual accessibility.

### Infrastructure surfaces (servers, bindings, discovery)

`servers.css` composes the server inventory, detail and raw-dump summary;
`bindings.css` composes the cross-server relationships and is also loaded by
server detail. All colours, type and spacing reuse the canonical tokens. No
shared token/component styles, backend, dependencies or JavaScript are changed.
The presentation macro `bindings/_presentation.html.j2` defines discovery badges,
binding-state badges and relationship cells once for both tables, using `_ui` SVGs.

- Server inventory uses a fixed-layout six-column table with wrapping identities
  and groups. Identity gets 27%, discovery 24%; numbers align right and short
  drift/attention badges stay on one line. The 1280px no-scroll criterion was
  exercised on the committed previews; deployed visual verification is pending.
- Bindings read as virtual host/SNI names → server → port → configured files.
  Four columns compare the relationship, observed disk evidence, inventory
  evidence/expectation and state/freshness. Native disclosures retain config,
  owner/mode, key and chain detail without JavaScript. Fingerprints are selectable
  exact text, monospaced and wrapped instead of expanding the page. Below 720px the
  four-column comparison keeps a 48rem minimum inside a labelled, focusable
  `.table-wrap` region, so the page itself never scrolls sideways.
- Key mismatch is warning-coloured with a triangle and “Drift”; missing/unreadable
  file is critical with a cross-circle and “File failure”. Inventory match has a
  check; unknown has an information icon. The short badge word carries the meaning;
  the raw state name stays a contiguous help link. Raw `data-match-state`/`data-stale`
  hooks and help anchors remain unchanged. Secondary text inside a drift row is
  tinted from the warning hue, never grey.
- **Read-model boundary:** `BindingRow.certificate_id` is an observed inventory
  match, not a desired deployment. It does not supply the expected fingerprint.
  The UI says so; “Inventory match” must not become “In sync” without a real
  desired-state comparison. No fingerprint is fabricated or inferred from a name.
- Discovery shows the last attempt separately from the last captured dump, warns
  when bindings were kept after suspected parsing failure and distinguishes a
  recorded empty dump from never discovered. `DiscoveryRun`/`DumpSummary` expose no
  previous binding snapshot/change diff: “changes unavailable” is not “no changes”.
- Failed hosts remain in inventory. `ServerRow` exposes status but no error reason;
  the row links directly to server detail, where the supplied newest host error
  appears before actions. A missing error says “No failure reason recorded”, never
  guesses SSH/DNS/authentication failure. Stale bindings stay stored observations,
  not fresh verdicts about an unreachable host. The stale note is one flex row of
  exactly two items — icon plus a single `.binding-stale-text` span holding the whole
  sentence. Status notes never split their sentence into bare text nodes beside an
  icon: each text node would become its own flex item and wrap into character
  columns. A preview contract asserts that structure.

`infrastructure_fixtures()` additively extends the existing renderer. It produces
`server-list.html`, `server-list-empty.html`, `server-detail.html`,
`server-failed.html`, `server-never.html`, `server-empty-discovery.html`,
`server-parse-warning.html`, `server-dump.html`, `server-dump-empty.html`,
`binding-list.html`, `binding-drift.html`, `binding-empty.html`, `binding-help.html`.
All are explicitly synthetic observations. Repository tests cover strict fixture
rendering, native POST/CSRF, filter names, row hooks, warning help links, escaping,
exact hash text, failed/empty/never/parse-suspected states and deterministic output.

Structural checks passed; visual verification pending on the deployed instance.
Check 1280px inventory overflow, narrow binding layout, dark/light contrast,
keyboard disclosures, long hashes/paths, no-HTMX discovery POST and failure
messaging there. Static checks are not a complete WCAG 2.2 AA audit.

## Consistent operations pages and grouped settings

Servers (including dump summary), bindings/help, endpoint scans/detail, deployment
planning/jobs/progress, audit, users and settings reuse the certificate area's
`.page-header`, `.page-actions`, `.action-menu` and `.filter-disclosure` components.
`_operations_ui.html.j2` owns composition macros, not another visual system. Titles
have a short purpose statement and one primary header action; secondary links
live in a native disclosure. Read-only audit exports metadata instead of inventing
a mutation. Header title groups have `min-width: 0` / `max-width: 100%` so a long
host name wraps inside the narrow layout rather than widening the document.

The filter macro keeps one native GET form, including closed disclosure controls,
and uses the same removable chips as certificates. Removing a chip drops only
that filter and pagination, preserving other filters, sort and page size. The
list summary's spacing/measure is now one shared rule, replacing four area rules.

`.verdict-list` reuses `row-height` and the existing status-row/icon/word badges.
Its compact density removes vertical cell/badge padding, not their palette or
state semantics. Default server/endpoint rows measure 56px at 1280px. Two-line
identities and exact date/age stay scannable; long identities have full titles
and a detail destination. Groups allow up to two lines, with full text on detail.
Server column allocation is now 25% identity / 11% groups / 18% discovery state /
11% bindings / 24% discovery time / 11% TLS drift, superseding the earlier layout.
Binding count means **bindings**, not a fabricated distinct-certificate count.
Discovery state and last discovery time remain separate from current TLS drift;
there is no aggregate live host-health claim or invented last-seen heartbeat.
Server detail is state → bindings → history → captured evidence → configuration.
Discovery actions remain native POST/CSRF forms after those sections.

The endpoint list is five columns: endpoint/SNI, server, latest verdict, observation
age/exact time, actions. Observation age is rendered against the request's server
clock, never a browser timer; a future observation explicitly reports clock skew.
Expected/served certificate evidence and history stay on detail. History links
navigate to detail even with HTMX enabled (the legacy drawer hook/route is retained).
Per-endpoint scan POSTs remain in native row actions; expanded menus stay in flow
inside the scrolling table so they cannot clip. No scroll or toast behavior is added.
Deploy guardrail verdict → scope/batches → file detail, failed-host-first progress,
expanded failed batches, preserved cancellation and automatic-restoration states
remain intact. No rollback control is invented.

### Eight settings tabs, independent saves

Schedule and scans groups Schedule's six fields with Scanning's three. System and
maintenance groups General's two fields with read-only rotation/cleanup operations.
Both legacy GET tabs and every original POST field/allowlist/redirect remain valid;
there is no combined save endpoint or cross-section mutation. Additive route context
(`section_tabs`, `section_tab`, `section_label`, `related_sections`) supplies the
sibling's stored values, never a secret or a fabricated response. The canonical
navigation has eight links; legacy Scanning/General links remain in More actions.
`settings/_form.html.j2` renders configuration controls once; the maintenance
partial is reused for both legacy destinations. Primary header Save buttons use
native `form=` associations and remain functional without JavaScript/HTMX.

The existing approved `settings.js` now tracks each grouped section separately,
retaining its original per-section sessionStorage key and baseline. A successful
save clears only that section; native navigation or an HTMX 422 restores the
other section's draft and retains refused values. Every edited field has visible
text plus a boundary; either section's draft marks the canonical tab. The same
leave confirmation and secret/repository-URL exclusions apply. No new script,
submit interception, persistence mechanism or dependency is introduced. The
always-visible fallback additionally explains that without JavaScript saving
one section reloads the tab and discards edits in other sections.

### Verification and remaining scope

Regenerate with `uv run python scripts/render_previews.py`. New fixtures include
`scan-list-verdicts.html`, `scan-list-empty.html`, `deploy-jobs.html` and
`deploy-jobs-empty.html`; all touched existing previews are regenerated.
Repository regressions verify common headers, exact filter chips, server ordering,
five-column endpoint verdicts, age boundaries/clock skew, eight settings tabs,
legacy destinations, independent POST/CSRF forms, header form targets and grouped
422 fragments. Ten dependency-free Node tests exercise the draft lifecycle,
including sibling restoration after success/422 and excluding maintenance secrets.
Static Chromium fixture checks covered 43 area previews at 375/1024/1280 × 900px
in both themes (258 combinations), with no document overflow or missing state bars.
The first narrow pass caught intrinsic-width header overflow, fixed in the shared
header component. The grouped Scanning field and tab marker were also exercised
in the browser. These are **synthetic static fixtures**, not deployed-flow tests.

Product-wide audit: authentication/setup/error screens intentionally retain narrow
forms; account, import, certificate detail/edit/export, and renewal screens still
use their earlier composition rather than this list header. They are outside this
card's scope. Legacy `.chip`/`.badge` aliases and old `.counter` compatibility CSS
remain in the shared stylesheet; this card adds neither a second implementation
nor a new one-off colour. No literal palette colours were found in area CSS.
The repeated in-scope list-summary rule was consolidated rather than hidden.

Structural checks passed; visual verification pending on the deployed instance.
Run native/HTMX saves and validation against the real database, verify keyboard
focus/zoom, tab-leave prompts, both themes and live failed-host progress there.
The sandbox has no usable Docker daemon: the full local unit run records the
known topology-test failures separately; required exact-head CI must pass the
complete suite without weakening or skipping its gates.
