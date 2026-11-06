# UX acceptance — Plan 4, human run of `docs/ux-spec.md` §10

Verdict: **accepted with three P2 findings, no P0/P1**. Every numbered step of the manual script was run
in order against a disposable stack built from `main`; three sub-steps that need a lab SSH host or a
reachable Git remote are listed as explicit exclusions with the CI tests that cover them (§[Exclusions](#exclusions)).

| | |
| --- | --- |
| Tested head | `e61ec5a5d9d98823b22f91396254e22213ef56f7` (`main`, "docs: refresh README, docs and screenshots for the new dashboard (#106)") |
| Spec | `docs/ux-spec.md` §9 and §10; `docs/slice-b-contract.md` §9 R; `docs/ui/branding.md` |
| Date | 2026-11-06 |
| Viewports | 1440 × 900 and 390 × 844 (CDP device-metrics override, device scale factor 1, dark colour scheme; CSS width 390 so the ≤719 px breakpoint applies) |
| Scripts | Enabled, except step 10 (native half) and the §9 "no JavaScript" checks, where script execution was disabled through CDP |
| Evidence | `docs/ux-acceptance/*.png` (80 files, PNG, losslessly re-deflated; both viewports wherever the script asks for them) |

## Environment

A throwaway stack, never the certlab staging data:

- **Database** — PostgreSQL 16.4 from a fresh `initdb` cluster on `127.0.0.1:55439` (UTF-8), schema at
  `alembic head` (`0001`…`0004_branding`). The cluster was deleted after the run.
- **Web** — `uvicorn` 0.54.0 on Python 3.12.16 (uv 0.13.1, `uv.lock` frozen) behind a self-signed
  certificate generated for this run, `create_app()` with `known_hosts_file` pointing at a **missing**
  file, empty inventory/artifact directories and no Git credentials.
- **Worker** — a real `app.jobs.worker.run_worker()` process (same `Settings`, `create_session_factory`)
  so the job queue, capability probe, banner and Test pull are exercised end to end. Its Ed25519 client
  key was stored through `services.worker_credentials.set_credential()` — the code path of
  Settings → Worker — instead of a mounted file.
- **Accounts** — the first administrator row was seeded with `auth.hash_password()` (there is no CLI
  bootstrap user in the container); every later account came from the dashboard. All passwords are
  random and were passed to the browser by the automation, never typed into chat or written to a file
  that is committed.
- **Not configured, on purpose** (they are what the script wants to see handled): no Git repository, no
  mounted `known_hosts`, no trusted host key at the start, no SMTP.

## Steps 1–19

| Step | Verdict | Evidence | What happened |
| --- | --- | --- | --- |
| 1 | PASS | `01-sign-in-desktop.png`, `01-overview-desktop.png` | Signed in as a real form POST. Header shows the 202 × 24 `lockup.svg` image; `<head>` links `favicon.svg` + `favicon-32.png`, both `200` and `no-store`. |
| 2 | PASS | `02-owner-persisted-desktop.png`, `02-filter-desktop.png`, `02-filter-empty-desktop.png`, `02-certificates-narrow.png` | Uploaded a leaf and its chain (flash: `Untrusted root · Root: CN=Acceptance CA`), opened the detail page, edited Owner, reloaded — the owner persisted. Search, status and the no-match state (`No matching certificates`) all work. |
| 3 | PASS (queue) · EXCLUDED (fetch) | `03-test-pull-queued-desktop.png`, `03-test-pull-result-desktop.png`, `03-repository-cleared-desktop.png` | Saved `https://git.example.test/acceptance.git`, pressed Test pull: `Test pull queued; the worker runs it and the result appears below.`, the real worker picked it up, and the result rendered `Failed … transient_network: inventory pull failed and no checkout is available` (no Git remote in this container). The browser never left the dashboard. URL cleared again. |
| 4 | PASS | `04-navigation-desktop.png` | Overview, Certificates, Import, Renewals, Inventory, Servers, Bindings, SSH keys, Scans, Deploy, Jobs, Administration, Users, Settings, Audit, My account: each sets `aria-current="location"` on its area and `aria-current="page"` on the page. Infrastructure opens Inventory, Administration opens the hub. |
| 5 | PASS | `05-menu-open-narrow.png`, `05-menu-keyboard-narrow.png` | `Menu` reaches Inventory, SSH keys, Users, Settings and the hub. Tab produced a visible 2 px solid outline on every link visited (`skip → brand → menu → Overview → Certificates → Import → Renewals`). `scrollWidth 375 ≤ innerWidth 390` on every page tested. |
| 6 | PASS | `06-setup-desktop.png`, `06-setup-narrow.png` | `Setup: 2 of 6 steps done`. With a worker key configured and no mounted/trusted host key, step 4 is `To do … Trust your servers' SSH host keys · Trust host keys` linking to `/ssh-keys`. |
| 7 | PASS | `07-administration-desktop.png`, `07-administration-narrow.png`, `19-restored-hub-desktop.png` | All 15 hub entries open their page. `Inventory repository (optional) — Not configured — optional` after step 3 cleared it. No secret is shown: the worker card prints type and public fingerprint only. Copy nit recorded as F3. |
| 8 | **FAIL (P2)** | `08-settings-inventory-narrow.png` | Picker reads `Section: Inventory repository`, as required — but with a single banner on screen the repository URL field starts at `y ≈ 951` on an 844 px-tall viewport, so it is **not visible without scrolling** (§10 step 8). See F1. |
| 9 | PASS | `09-no-servers-desktop.png`, `09-no-servers-narrow.png`, `09-filtered-servers-desktop.png` | `No servers yet` with *Add hosts* and *Connect a repository (optional)*; adding a search filter gives `No servers match these filters` + *Clear filters*. |
| 10 | PASS | `10-expired-htmx-desktop.png`, `10-expired-nojs-desktop.png`, `10-scans-narrow.png` | Changing the hidden `csrf_token` and submitting replaces the main area with `Your form expired. Reload the page and try again.` (an `H1` that takes focus), with `Error 403` and a request ID. Repeated with script execution disabled: same text. No endpoint was created (`0 endpoints` afterwards). |
| 11 | PASS | `11-branding-default-*.png`, `11-svg-preview-*.png`, `11-svg-saved-*.png`, `11-custom-login-*.png` | Default state has no Reset disclosure. A valid SVG previews on dark and light with `Preview only. Your current logo has not changed.` while the live shell stays on the default. Save logo updates header and `/login` (cookies cleared) to `/branding/logo?v=b5ff5ce5…`, loaded before sign-in; favicon and the product name are unchanged. |
| 12 | PASS | `12-png-preview-*.png`, `12-png-discard-*.png` | PNG preview staged with `logo.png · 48 × 48 px · PNG`; `Discard preview` answers `Preview discarded. Your current logo has not changed.` and the saved SVG survives. |
| 13 | **FAIL (P2)** | `13-unsafe-svg-*.png`, `13-oversize-*.png`, `13-disguised-*.png` | `<script>` SVG → `This SVG uses unsupported content…`; 300 KiB file → `Logo is too large…256 KiB`; both end with `Your current logo has not changed.` A **genuine JPEG renamed `logo.png`** → `This image could not be read. Export it again as SVG or PNG.`, where `docs/ui/branding.md` gives the type-mismatch copy `Unsupported logo format. Choose an SVG or PNG file.` See F2. |
| 14 | PASS | `14-reset-confirm-desktop.png`, `14-reset-desktop.png`, `14-default-login-desktop.png`, `14-*-narrow.png` | `Reset to default…` discloses `Reset to default logo? This removes the custom logo for everyone, including the sign-in page…`; confirming restores the default lockup in the shell and on `/login` with `Default logo restored.` Steps 11–14 repeated at 390 × 844. |
| 15 | PASS | `15-deactivate-confirm-*.png`, `15-deactivated-desktop.png`, `15-reactivated-desktop.png` | The disclosure explains *Scheduled scans of this endpoint stop. Its history is kept…*; closing it changes nothing; confirming renders `Endpoint deactivated.` with the `Inactive: scheduled scans skip this endpoint.` badge, the History section is retained, and Activate is a single immediate button. |
| 16 | PASS | `16-invalid-host-*.png`, `16-deactivated-desktop.png`, `16-reactivated-desktop.png`, `16-delete-confirm-desktop.png`, `16-deleted-desktop.png`, `16-inventory-empty-desktop.png` | With no repository: added `web01.example.test` (groups `web prod`, nginx), edited notes, submitted `-bad` in the in-row edit form → the error is rendered on that row (`Use letters, digits, dots, hyphens or underscores…`), deactivated, reactivated, deleted with confirmation; the empty state returns. |
| 17 | EXCLUDED (lab compare) · PASS (local rules) | `17-verified-required-desktop.png`, `17-added-desktop.png`, `17-duplicate-desktop.png`, `17-private-key-refused-desktop.png`, `17-delete-confirm-desktop.png`, `17-deleted-desktop.png`, `17-ssh-keys-narrow.png` | The fixture host key (`ssh-keygen -lf` → `SHA256:xKNaEsdNKHevtBWD/dJUMxqQqj/0as3cyBgShE15h9A`) is refused without the verification box (`Confirm that you verified the fingerprints with the server before trusting them.`), accepted with it, and the listed fingerprint equals `ssh-keygen -lf` output. Pasting it again reports the duplicate and its provenance. A pasted `BEGIN OPENSSH PRIVATE KEY` block is refused with *"This looks like a private key…"* and the textarea comes back **empty**. Delete with confirmation rings the source-aware flash. The lab fingerprint comparison itself is excluded — see [Exclusions](#exclusions). |
| 18 | PASS | `18-user-created-desktop.png`, `18-deactivate-form-desktop.png`, `18-user-deactivated-desktop.png`, `18-user-reactivated-desktop.png`, `18-forced-change-gate-*.png` | Invited a local administrator, opened `/users/{id}`, deactivated with the acting admin's current password (`User … deactivated and signed out.`), reactivated with a new temporary password, then signed in as that user: land on `/account` with `You must change your password before you can use the rest of the application.`, and `/`, `/certificates`, `/inventory`, `/administration`, `/settings?tab=branding`, `/users` all redirect to `/account`. |
| 19 | PASS (failure texts) · EXCLUDED (real fetch) | `19-ssh-test-pull-failure-desktop.png`, `19-https-test-pull-desktop.png`, `19-restored-narrow.png`, `19-restored-hub-desktop.png` | With no mounted `known_hosts` and no trusted key, `https://` Test pull fails on the fetch (`transient_network: inventory pull failed and no checkout is available`) and no longer on host trust; `ssh://` fails with exactly `config_invalid: no trusted SSH host keys: trust them in Infrastructure → SSH keys or mount a known_hosts file`. The repository URL was cleared afterwards; the hub shows `Not configured — optional`. |

## Defects

No P0 and no P1, therefore no developer card was created for this run.

| # | Step | Expected | Observed | Evidence | Severity |
| --- | --- | --- | --- | --- | --- |
| F1 | 8 | At 390 × 844 with at most one banner, the repository URL field is visible without scrolling. | Field top at `y ≈ 951` on an 844 px viewport (hero + Save button + "More actions" + drafts help + picker above it); only `Section: Inventory repository` sits at the fold. | `08-settings-inventory-narrow.png` | P2 |
| F2 | 13 | A `.png` that is really a JPEG shows the type-mismatch copy of `branding.md`: `Unsupported logo format. Choose an SVG or PNG file.` | `This image could not be read. Export it again as SVG or PNG.` — `app/services/branding_image.py` classifies a non-PNG body that is not XML as `unreadable` rather than `format`. Wording only; the upload is refused either way and the current logo is kept. | `13-disguised-desktop.png`, `13-disguised-narrow.png` | P2 |
| F3 | 7 / 9 | Counts agree with their noun. | The hub hard-codes both plurals: with one account it read `1 active users · 0 inactive` (`07-administration-desktop.png`), and with one host `1 active hosts (1 manual, 0 repository)` (`99-final-hub-desktop.png`). `app/web/administration.py` builds both strings without a singular branch. | `07-administration-desktop.png`, `99-final-hub-desktop.png` | P2 |

## Exclusions

| Item | Why | Covered by |
| --- | --- | --- |
| Step 17 — comparing the lab host fingerprint (`ssh-keyscan -t ed25519 <host> \| ssh-keygen -lf -`) | The container has no lab SSH target and no `sshd`; `172.18.0.2:22/2222` refuse connections. The consequence of trusting an unverified key cannot be produced without one. | `tests/integration/test_ssh_keys_http.py` (rules 1–10, fingerprint equality, duplicate/rotation refusals, no private-key echo) in the `verify` run of `e61ec5a` |
| Step 3 and step 19 — the real Git fetch | No Git remote is reachable from the disposable stack, so the pull itself cannot succeed. Everything the script actually asserts about the *dashboard* was run: queue, result rendering, the `https://` exemption and the exact `ssh://` text. | `tests/integration/test_test_pull.py`, `tests/unit` job-context tests for `require_repository`, `test_settings_http.py` |
| Step 2 — a wedged renewal/download chain | Not part of §10; downloads, PFX and the renewal wizard are untouched by this plan's diff and are covered by `test_downloads.py` / `test_renewal_wizard.py`. | same suites in the `verify` run |

## §9 regression criteria

| Criterion | Verdict | Evidence |
| --- | --- | --- |
| Certificates: import, list filters, detail, metadata edit, downloads/PFX, renewal wizard | PASS (live for import, detail, edit, filters; downloads/renewal cited) | steps 2 and 3 above; `test_upload_import.py`, `test_pull_import.py`, `test_certificates.py`, `test_downloads.py`, `test_renewal_wizard.py`, `test_renewal_list_http.py` — `verify` green at `e61ec5a` (CI run 42285106563) |
| Git repository ("GitHub") flow: save URL/ref/path, Test pull enqueue and result, discovery from a repository, adoption of a manual host | PASS for save/clear/Test pull; EXCLUDED live for fetch-dependent halves | steps 3 and 19; `test_settings_http.py`, `test_test_pull.py`, `test_inventory_http.py`, `test_discovery_jobs.py`, `test_manual_inventory_jobs.py` |
| Discovery/deploy screens and jobs | PASS (screens) · cited (jobs) | `/servers`, `/bindings`, `/deploy`, `/deploy/jobs` render with actionable banners and empty states; `test_discovery_screens.py`, `test_servers_http.py`, `test_bindings_http.py`, `test_deploy_start_http.py`, `test_deploy_job_http.py` |
| Scans/endpoints, users, SSH keys, sessions/CSRF/errors, worker settings | PASS (live) | steps 10, 15, 17, 18; `test_scans_http.py`, `test_endpoints_http.py`, `test_users_http.py`, `test_users_detail_http.py`, `test_ssh_keys_http.py`, `test_sessions_http.py`, `test_login_account.py`, `test_worker_credentials_db.py` |
| Every URL that existed on `4d553a3` still answers with the same method and status for a signed-in admin | PASS | Route tables built from `create_app()` on `4d553a3` and on `e61ec5a`: 91 → 103 paths, **0 removed, 0 method losses**, 12 additions (the Slice B inventory routes, the branding routes and `/branding/logo`). All 49 GET paths of the old table were requested in the live run: 35 × 200, 2 × 303, 6 × 422 (job-fragment routes given a non-existent id), 6 × 404 (absent resources) — every route answered, `/administration` keeps its URL. |
| No response redirects outside the dashboard origin | PASS | No `Location` outside `https://172.18.0.2:8849` in the 49-route sweep, and every form response in steps 1–19 was a same-origin 303. |
| Every form still works with JavaScript disabled | PASS | Step 10 native submission (`10-expired-nojs-desktop.png`); a manual host created with script execution disabled (`20-nojs-inventory-create-desktop.png`); a branding preview and save with script execution disabled (`20-nojs-branding-preview-desktop.png`, `20-nojs-branding-saved-desktop.png`). The login form, settings forms and management forms are plain HTML forms; `tests/test_management_pages_http.py` pins the non-HTMX fallbacks. |

## Secret hygiene

- No password, temporary password, session cookie, private key or Git token appears in any screenshot or
  in this document. Passwords were entered through the automation into `type="password"` fields and are
  never re-rendered by the application; every such field is empty in the captures.
- The only key material on screen is **public**: the worker key's type and public fingerprint, and the
  fixture host key's public line and SHA-256 fingerprint.
- The pasted private key in step 17 was refused and the textarea was cleared before the screenshot
  (`17-private-key-refused-desktop.png`).
- The disposable environment (secrets, session cookie, TLS key, fixtures, worker setup) lives in a
  git-ignored `.acceptance/` directory and is **not** part of this change: the diff touches `docs/` only.

## Reproducing

The stack is disposable and was removed after the run. To repeat it: fresh `initdb` cluster, `alembic`
upgrade with `database_url` set, `uvicorn` on `create_app(settings)` with a missing `known_hosts_file`,
one `run_worker()` process with a dashboard-stored Ed25519 key, and a browser at 1440 × 900 and
390 × 844. Evidence files are named `<step>-<state>-<viewport>.png`.

## Findings index

- F1 — narrow Settings hides the repository URL below the fold (P2, step 8).
- F2 — a JPEG named `.png` gets the "could not be read" copy instead of the type-mismatch copy (P2, step 13).
- F3 — the Administration hub prints `1 active hosts` (P2, step 7).
