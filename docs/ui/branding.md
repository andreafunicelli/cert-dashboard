# Default identity and replaceable branding

Status: implementation-ready design contract; **assets and documentation only in this PR**.
Application integration belongs to Slice A (`t_8439d40d`). No existing route, field,
permission, template or stylesheet is changed here. UI language is English.

## Identity and asset manifest

Keep the product name **Cert Dashboard**. A folded certificate and six-sided seal
are recognizable at compact sizes without suggesting a successful trust check.
No checkmark, padlock, green status color, gradient or decorative illustration.
The cyan is the incumbent action/identity color, not a certificate-state verdict.
System sans lettering matches the existing UI and does not fetch a font. It is
live SVG text with system fallbacks (explicitly allowed by this brief); minor
platform text-metric differences are expected. Do not crop or distort it.

All URLs begin `/static/branding/`:

| File | Use | Intrinsic canvas |
|---|---|---|
| `lockup.svg` | Cyan mark + light wordmark on dark | 202 × 24 |
| `lockup-light.svg` | Deep cyan mark + dark wordmark on light | 202 × 24 |
| `lockup-mono.svg` | One-ink dark mark + wordmark on light/print | 202 × 24 |
| `mark.svg` | Cyan mark on transparent dark placement | 24 × 24 |
| `mark-light.svg` | Deep cyan mark on transparent light placement | 24 × 24 |
| `mark-mono.svg` | One-ink dark mark on transparent light/print | 24 × 24 |
| `favicon.svg` | Cyan mark on rounded blue-black tile | 24 × 24 |
| `favicon-32.png` | Same favicon, antialiased RGBA | 32 × 32 |

Asset colors are frozen exports of `app.css`: dark accent `#4cd7f6`, dark text
`#dae2fd`, light accent `#006579`, light text `#172033`, favicon ground `#0b1326`.
Standalone SVG images cannot inherit page custom properties; exports intentionally
contain these literal colors. Do not add parallel application tokens. The contact
sheet's fixed light/dark swatches are documentation fixtures, not new UI colors.

Rebuild with `uv run python scripts/render_branding.py`. This generates all assets
and `docs/ui/previews/branding.html` from its Jinja fixture. The PNG is rasterized
from the exact authored favicon segments, with 4× supersampling, using the Python
standard library only. Its source is embedded in a PNG text chunk. No image package,
browser or build step is added to the app. The offline rasterizer only understands
our rect/polyline subset: **never use it to process uploads**.

### Placement and accessibility (future integration)

- Header: replace the existing text brand with the 202 × 24 lockup. Link to `/`,
  accessible name `Cert Dashboard home`, minimum 48px high hit target; reserve
  202px width and 24px height to prevent layout shift. Clear space: 8px minimum.
- Compact/collapsed navigation: use the 24 × 24 mark, same link and accessible name.
  Switch to mark-only when the brand slot cannot fit 202px; do not shrink lettering.
  Preserve current desktop/mobile navigation and active-state contracts.
- Sign-in: retain the header; add a centered 48 × 48 mark immediately before the
  unchanged `Sign in` heading inside the auth panel, with 16px space below. Mark is
  decorative (`alt=""`) because the header already names the product. Apply the
  same pattern to second-factor sign-in, not every error page or password form.
- Default light-mode `<picture>` uses the `-light` image at
  `(prefers-color-scheme: light)` and dark `<img>` fallback. Mono is for print/export,
  not an automatic high-contrast substitute. No CSS filters, motion or inline style.
- Favicon links in the shared head: SVG `type="image/svg+xml"`, then PNG
  `type="image/png" sizes="32x32"`, using manifest paths above. The favicon stays
  the default even after custom upload: one small image cannot reliably supply a
  wide organization logo and a legible favicon. State this beside the setting.
- Custom image replaces the mark, **not** the product name. Header custom-image
  slot: maximum 120 × 24px, object-fit contain, plus visible `Cert Dashboard` text
  with 8px gap. Compact slot: contain in 24 × 24px. Auth slot: contain in 160 × 48px.
  Never crop, stretch, recolor or interpret uploaded text. Decorative custom image
  (`alt=""`); unchanged visible name/link provides the accessible identity. An
  organization wordmark may duplicate words but must never hide product identity.
- Transparent custom images see the actual theme surface. Preview both themes;
  recommend contrast but do not silently add a background/recolor an upload.

See the committed contact sheet for exact-size light/dark/mono proofs and flow
annotations. It is not a deployed screen and its example states do not save data.

## Settings → Branding (future implementation)

Add **Branding** to the existing settings sections, at `/settings?tab=branding`.
Do not invent a parallel settings hub or rename existing tabs. Follow the current
settings authorization policy: authenticated, fully authorized settings users only
(the current app uses `require_user`, not a new admin-role scheme). Apply the same
policy to every preview/save/reset/draft route; existing forced-password-change
and MFA gates remain effective. This setting is instance-wide, not per user.

Layout: existing page header and section tabs, then `Branding` heading, scope help,
current logo, chooser and preview, followed by a separate reset section. On narrow
screens stack previews/buttons; no horizontal page overflow. Only the preview
section owns a Save action; do not show the generic `Save branding settings` header
button or mark this form as a settings draft. No autosave or immediate local-file
preview. The existing enhancement does not persist file inputs or draft tokens.

Persistent help:

> Set the logo shown in navigation and on the sign-in page for everyone. The
> product name and browser icon stay Cert Dashboard. Do not upload confidential
> images: the saved logo is visible before sign-in.

Chooser label **Logo image**; file input `name="logo"`,
`accept="image/svg+xml,image/png,.svg,.png"`, associated help and error IDs.
Help: **SVG or PNG, up to 256 KiB. Use a transparent image with a square or wide
layout.** Recommendations: square art at least 48 × 48px; wide art at least
240 × 48px; no hard minimum beyond validation below.

### State machine and exact actions

1. **Default**: show theme-correct default, badge `Default logo`, copy **No custom
   logo. Cert Dashboard’s default logo is in use.** Chooser + `Preview logo` primary
   submit. No Save button yet. Hide Reset entirely. File selection alone does nothing.
2. **Custom saved**: show current image, `Custom logo` label and original filename
   as escaped text (never a URL or HTML), pixel dimensions and format. Same chooser
   + `Preview logo`. Offer `Reset to default…` secondary/destructive disclosure.
3. **Preview**: explicit multipart POST validates and stages a candidate without
   changing current branding. Show **Preview only. Your current logo has not changed.**
   Above the candidate retain a clearly labeled `Current logo` thumbnail. Candidate
   appears on dark and light raised surfaces, at header 24px and auth 48px high,
   including the persistent product name. Display filename, dimensions, type, size
   rounded up to KiB. `Save logo` primary; `Discard preview` secondary POST. Keep
   chooser + `Preview logo` so a new candidate can replace this one. No image enters
   the global shell until Save. A second valid Preview replaces this session's draft;
   an invalid Preview clears the previous draft and hides Save to avoid saving an
   old selection accidentally. Current saved branding is always preserved.
4. **Save**: explicit POST applies only this validated candidate. On success 303 to
   the Branding tab, flash **Logo saved. It is now shown in navigation and on the
   sign-in page.** Full-page refresh updates the shell and ends preview. Double
   submit must not create duplicate assets/audits. Retain a 30-minute consumed-token
   receipt to make retry redirect to the same success state.
5. **Discard**: delete candidate and 303 to Branding; **Preview discarded. Your
   current logo has not changed.** Normal navigation may leave the draft staged
   until expiry; returning to Branding in the same session resumes it. Help:
   **Selecting a file does not upload or save it. Choose Preview logo to check it
   before saving. Leaving this page discards the preview after 30 minutes.**
6. **Reset**: `Reset to default…` opens native `<details>` confirmation, never changes
   data itself. Copy **Reset to default logo? This removes the custom logo for
   everyone, including the sign-in page. You cannot undo this without uploading it
   again.** Destructive `Reset logo` submit includes `confirm=RESET`; `Cancel` is a
   normal link to Branding. Reset removes the active custom asset and current
   session's draft atomically; 303 + **Default logo restored.** Default-state reset
   requests are harmless no-ops. No typed confirmation required for a replaceable
   non-secret image. Every action is keyboard-operable without HTMX or JavaScript.

### Endpoint / form contract to implement

These are new proposed endpoints; nothing here changes existing routes. Register
literal action paths before the existing `/settings/{tab}` handler.

| Method / path | Fields | Result |
|---|---|---|
| GET `/settings?tab=branding` | none | Current state, session draft if unexpired |
| POST `/settings/branding/preview` | `csrf_token`, `logo` file | 303 back on valid stage; 422 full page on validation |
| GET `/settings/branding/draft/{draft_token}` | token in path | Session-owned validated candidate image; no-store |
| POST `/settings/branding` | `csrf_token`, `draft_token`, `base_revision` | Atomic save then 303 |
| POST `/settings/branding/discard` | `csrf_token`, `draft_token` | Delete session-owned draft then 303 |
| POST `/settings/branding/reset` | `csrf_token`, `confirm=RESET`, `base_revision` | Atomic reset then 303 |
| GET `/branding/logo` | optional `v=<sha256>` cache buster | Current validated image, or 307 to default mark |

All mutation routes check CSRF before parsing/processing images. HTMX is optional;
use ordinary multipart POST for preview and full-page PRG after save/reset so shell
updates cannot become stale. No new enhancement script or CSP exception is needed.
If HTMX enhancement is added later it must preserve these complete non-JS flows.
Errors include summary `role="alert"` linked to `logo`, inline text with
`aria-invalid="true"`/`aria-describedby`; do not refill the file input. After a
validation response direct focus to summary using server-rendered `autofocus` on a
focusable summary. Use existing status/error components, not another color system.

### Validation: hard limits and safe SVG profile

Validate on the server, not just `accept` or extension. Maximum file bytes **262144
(256 KiB)** inclusive; stop reading at limit + 1. Bound the whole multipart request
to **320 KiB**; over-limit requests render 413 with the same useful size explanation.
One file only. Require `.svg` or `.png` suffix (case-insensitive), matching decoded
format; accept matching MIME or `application/octet-stream`, reject conflicting MIME.
Filename display: strip directory components/control characters, cap at 120 chars,
escape at rendering; never use it for storage paths or response header values.

- PNG: fully decode before accepting; 1–2048px each dimension, at most 4194304
  pixels, aspect ratio width/height **0.5–6 inclusive**. Reject corrupt/truncated,
  animated/APNG or unsupported image data, including decompression bombs; merely
  checking the signature/IHDR is insufficient. Re-encode static RGBA PNG without
  original metadata/trailing data; cap stored bytes at 262144 too. Encoder/decoder
  dependency selection requires the normal explicit approval if not already in repo;
  this design PR does not authorize a new package.
- SVG: UTF-8 XML, finite positive viewBox width/height (at most 2048 each, same
  aspect bounds); viewBox mandatory and defines aspect ratio regardless of optional
  root dimensions. Reject DTD/entities, processing instructions, non-SVG namespaces,
  scripts, event attributes, foreignObject/HTML, style elements/attributes, href,
  use/image, external references, fonts/text, filters, animation and URL paint values
  (including data URLs). Accepted tags only `svg`, `g`, `path`, `rect`, `circle`,
  `ellipse`, `line`, `polyline`, `polygon`, `title`, `desc`. Accepted attributes only
  root `xmlns`, `viewBox`, `width`, `height`; shapes' `d`, `points`, `x`, `y`, `x1`,
  `x2`, `y1`, `y2`, `cx`, `cy`, `r`, `rx`, `ry`, `width`, `height`; and presentation
  `fill`, `stroke`, `stroke-width`, `stroke-linecap`, `stroke-linejoin`,
  `stroke-miterlimit`, `fill-rule`, `opacity`, `fill-opacity`, `stroke-opacity`,
  `transform`. Presentation attrs are also allowed on groups/root. Paint is only
  `none`, #RGB or #RRGGBB; default black is allowed, `currentColor` is not (external
  images do not inherit page color). Validate numeric/path/transform grammars;
  finite coordinates and transform components bounded to absolute 100000, opacity
  0–1, nonnegative radii/widths; enums per SVG standard. Reject, don't silently
  remove, anything outside this profile. Max 512 elements, depth 16, 16384 total
  path commands/point pairs. Serialize a fresh allowlisted tree; ensure candidate
  bytes still fit 262144. Only sanitized bytes may be previewed or served.

SVG intentionally excludes live lettering; uploaders must convert text to outlines
or use PNG. Default first-party SVG lettering is not an upload-profile precedent.
Label in help: **For SVG, convert lettering to paths. Scripts, embedded images and
external resources are not supported.** A safe-but-complex rejected image can be
exported to PNG; never relax security to accept arbitrary editor exports.

### Persistence, serving, cleanup and concurrency

Use a dedicated singleton **`branding_asset` database record**, not a file written
under `app/static`. Store sanitized bytes, actual MIME, dimensions, SHA-256 revision,
escaped-on-output display filename, UTC update time and actor ID. No row = default.
Database backup/restore includes branding. The shipped web container is read-only
and has no artifacts mount; worker `/srv/artifacts` is not an appropriate location.
This contract requires a migration in the implementation card, not this asset PR.

Pending bytes live in a separate `branding_draft` DB record tied to authenticated
session ID, random 256-bit token, current active revision (`default` if absent), and
fixed 30-minute expiry from Preview. At most one candidate per session; replacing
it deletes the old one. Tokens never enter localStorage, public image URLs or logs.
Expiry/session revocation makes draft read/save return 410 and deletes bytes; cleanup
also purges expired drafts/receipts opportunistically on branding requests and in
existing daily cleanup. Cap total pending bytes per instance at 16 MiB; refuse new
Preview with 503 recovery copy rather than growing storage unbounded. Draft GET
from another session returns 404 without revealing existence.

Save/reset compare submitted `base_revision` against current revision atomically.
Mismatch is 409: keep candidate until its normal expiry, show both current and
candidate, hide Save and offer **Preview again** (new upload based on latest state)
and **Discard preview**. Never overwrite another user's change silently. Failed
storage transaction leaves old bytes/revision intact. Reset also conflicts if the
current revision changed since opening confirmation. Saved file name/byte content
must never be placed in audit metadata; record save/reset, actor, dimensions, MIME
and revision only, following existing auditing conventions.

`/branding/logo` is intentionally public for sign-in; serve only current sanitized
bytes, never a draft, arbitrary path, database error or uploaded original. No
revision history is public: a mismatched `v` still returns current bytes. Always
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, constant Content-Type
and `Content-Disposition: inline; filename="logo.svg"` (or `.png`). SVG response CSP:
`default-src 'none'; style-src 'none'; script-src 'none'; sandbox`. Embed only with
`<img>`, never inline markup, `<object>`, `<embed>` or `|safe`. Add only this exact
public image path to authentication middleware; don't bypass `/branding/*`.

When no custom exists, shell resolves the default static theme variants directly;
public image fallback redirects to `mark.svg`. Missing/unreadable/corrupt custom data
must yield the same default and a private settings warning, without exposing DB
errors or breaking sign-in. The context resolver must also catch asset lookup errors
and use default URLs. No custom-image JavaScript error handler: server checks the
asset before choosing its URL. A page already open retains its old image until the
next full navigation; save/reset responses force full navigation. Keep favicon,
product name, certificate status colors and page titles unchanged.

Current repo inspection: no CSP declaration was found in `app/main.py` or `app/`;
that is not permission to add inline handlers/styles. Integration must work with
proxy CSP `script-src 'self'; style-src 'self'; img-src 'self'`, no data/blob images
or CSP weakening. Staged images use same-origin protected HTTP URLs.

### Exact error and status copy

All upload errors append **Your current logo has not changed.**

| Case | Message / recovery |
|---|---|
| Missing file | Choose an SVG or PNG to preview. |
| File > limit | Logo is too large. Choose an SVG or PNG no larger than 256 KiB. |
| Type/MIME mismatch | Unsupported logo format. Choose an SVG or PNG file. |
| Corrupt PNG/XML | This image could not be read. Export it again as SVG or PNG. |
| Dimensions/aspect | Use an image 1–2048 pixels per side, with a width-to-height ratio between 0.5 and 6. |
| Unsafe/complex SVG | This SVG uses unsupported content. Convert lettering to paths, remove embedded resources, or export a PNG. |
| Expired draft, 410 | Logo preview expired. Choose the file again and select Preview logo. |
| Concurrent update, 409 | Branding changed since you opened this page. Review the current logo and preview your file again before saving. |
| Store/cap failure, 503 | Logo could not be stored. Try Preview logo again. |
| Save transaction failure, 503 | Logo could not be saved. Your current logo has not changed. Try Save logo again. |
| Reset failure, 503 | Logo could not be reset. Your current logo has not changed. Try again. |
| Missing/unreadable active bytes | Custom logo is unavailable. The default logo is being shown. Upload a replacement or reset to default. |
| CSRF/session expiry | Reuse the existing form-expiry/sign-in response; never weaken or replace it. |

For 422/413, clear any previous candidate and require file re-selection. On 409
retain candidate; on save 503 retain candidate; on expiry remove it. Storage failure
before staging clears any previous candidate and reports that there is no new
preview. Do not show a success notice on any failure. Browser HTTP cache may not be
used as evidence of the saved state; fresh requests must agree after Save/Reset.

## Verification and developer acceptance checklist

This PR: run `uv run ruff check .`, `uv run pytest -q tests/unit`,
`uv run pytest -q tests/test_branding_assets.py`, regenerate assets, inspect contact
sheet at actual 24/48px and SVG/PNG favicon sizes. No application templates or routes
changed, so integration markup contracts are untouched. Static contact sheet checks
are separate from deployed application verification.

Implementation card must exercise, with and without HTMX/JS: default → valid SVG/
PNG Preview (global shell unchanged) → Save (header + login updated) → Reset;
chooser cancellation, discard, re-preview, refresh/back, reload/restart persistence;
1 byte over limit, multipart over cap, false MIME/extension, corrupt PNG, APNG,
SVG script/event/foreignObject/style/url/entity/deep tree/overcomplex path, dimensions
and ratio boundaries; no unvalidated bytes served; unauthorized/cross-session drafts;
CSRF/forced-password/MFA gates; expiry/cleanup/cap; concurrent save/reset; transaction
failure/fallback; light/dark and 320px viewport; keyboard/error-summary focus;
public logo vs private drafts; no secrets in audit, file paths or logs. Decoder
availability/security and new dependencies must be resolved explicitly, not faked.

**Structural checks passed; visual verification pending on the deployed instance.**
This sentence describes the required handoff distinction, not a claim that the
replacement UI has been implemented. Record actual local test/render evidence in
the PR description.
