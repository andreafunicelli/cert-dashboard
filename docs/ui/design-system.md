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
page markup is not migrated by this card; state icons and numeric modifiers must
be applied as those pages come into scope.

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
- Password controls, hidden/file inputs and any field name containing `secret`,
  `key` or `token` are never read or stored. Repository URLs are also never stored:
  even an invalid URL can contain credentials. Their changes are marked but must
  be saved before switching. Trust uploads, typed destructive confirmations and
  CLI key rotation are not configuration drafts and are not persisted.
- No draft is a server-side save. Closing the browser tab ends its drafts; anyone
  using that same browser tab can read its non-secret drafts. Storage denial is
  reported visibly and falls back to save-before-navigation. The always-visible
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
  unknown validity. Each uses the canonical badge + SVG + visible word. The
  existing expiry-chip text and classes are retained; days/counts are right-aligned
  monospaced tabular data in the certificate list, separate from the state word.
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

- Overview order is expiry → worker/inventory/digest → recent failures → TLS health
  → review actions → detail tables. Counter links and `data-*` hooks are unchanged.
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
