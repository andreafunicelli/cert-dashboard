# cert-dashboard UX audit — live staging walkthrough

## Decision summary and evidence boundary

Live target: **certlab**, `https://certlab.funilab.org`, audited 2026-11-03 22:57–23:09 UTC (screens display Europe/Rome, crossing midnight). Remote checkout: `2489211`, `feat(ui): a Worker tab for the credentials, and a banner that leads somewhere`. db/web/worker were healthy before and after testing. The running web/worker image was created on November 2; the observed UI, rather than checkout alone, is the authority here.

**This report supersedes the old static-only conclusions.** The [historical static audit](ux-audit/static-audit.md) and its [91 labeled fixture captures](ux-audit/README.md) remain a supplement at baseline `fe928fd`. They are not fresh live evidence. In particular:

- **SSH credential management already exists:** Settings → Worker supports SSH key replacement/removal, Ansible vault password and inventory token. Do not build a duplicate key editor from the old audit's “absent” finding.
- **Users already supports create/edit/reset/deactivate**, and every active user is an administrator. There is no non-admin role to select. First sign-in requires changing a temporary password.
- **Managed hosts still require external Git inventory authoring.** Generic Git is supported; GitHub is not mandatory and no GitHub OAuth/picker exists.
- **Branding still has no replacement/name editor** on this deployed baseline.

Real browser form login, disposable user lifecycle, certificate imports/metadata editing, endpoint creation/expectation editing/deactivation, worker TLS mismatch and failed repository Test pull were exercised. Persistence was checked by reload, plus read-only database queries for the user, endpoint and scan. No production code changes, database inserts, migration, deployment, CA operation or preexisting-record deletion occurred.

**Limits that remain:** a genuinely empty Overview could not be reached without deleting existing lab data; its only image is the explicitly labeled historical fixture. Actual empty Servers/Bindings/Renewals and a filtered-empty Certificates view were captured live. No safe live 500 trigger exists; its historical fixture remains supplemental. Successful SSH replacement/removal was intentionally not submitted because the singleton key was preexisting and protected by the authorization. A working Git checkout/discovery was blocked by missing worker `known_hosts`; this is a measured product/setup gap, not a fabricated successful import. No physical phone, screen reader, full WCAG, performance benchmark or completed renewal/deployment was tested.

Structural checks passed for the original fixture supplement; **visual verification pending on the deployed instance no longer applies to the live screens actually captured and inspected here**. Untested states above remain unverified, not implicitly passed.

## Setup and exact execution

The earlier local attempt followed README prerequisites: `docker info` failed (`Cannot connect to the Docker daemon at unix:///var/run/docker.sock`). PostgreSQL/worker could not be launched in the Hermes sandbox. `uv sync --frozen` and fixture rendering worked; see historical report for exact commands/results.

The operator explicitly supplied an existing isolated runtime, so no new VM, package, image or database was provisioned:

```sh
cd /opt/data/projects/cert-dashboard/.worktrees/t_f79b9a14
ssh -i /opt/data/home/.ssh/id_ed25519 root@192.168.1.42
cd /opt/cert-dashboard
git log -1 --oneline
docker compose ps --format '{{.Service}} {{.Health}}'
/opt/shotvenv/bin/python /root/uxaudit-live.py
/opt/shotvenv/bin/python /root/uxaudit-crud.py
/opt/shotvenv/bin/python /root/uxaudit-followup.py
/opt/shotvenv/bin/python /root/uxaudit-verify.py
```

Those audit harnesses remain root-only operational files on certlab, not dependencies or production code in this PR. They drive real Playwright Chromium page controls; they are not requests against synthesized HTML. They must not be rerun blindly: CRUD scripts are not general-purpose idempotent provisioning tools. Reproducible human steps are below. Credentials were read **on certlab only** from the supplied 0600 file, passed inside the process through environment variables, never printed, committed, put on a command line or included in captures. No cookies were injected for authentication. The assertion after login required the URL not to contain `/login`.

Capture settings: desktop **1440×900**, narrow **390×844**, DPR 1, dark color-scheme. Actual PNG dimensions/sizes and SHA-256 hashes are in [live index](ux-audit/live/README.md) and [image manifest](ux-audit/live/images.json). Screenshots are viewport captures; an action may scroll the document to its control. A second scrolled shot is provided for buried settings/SSH fields. No touch gestures were synthesized.

### Synthetic certificate / scan setup

Following the demo-data recipe, `docker compose exec -T web python - < /root/uxaudit-mint.py` created a synthetic CA plus valid (200 days), expiring (5 days), expired and distinct served leaves, all under `uxaudit-*.example.test`. Files were copied out of the container tmpfs with `docker compose exec -T web tar -C /tmp/uxaudit-certs -cf - .` into a root-only audit directory. Three certificates were imported **through the actual upload form**, not inserted into the DB. Private keys were not uploaded, displayed or committed. Their root is not a trusted application anchor; chain/trust warnings are truthful and were not hidden.

For a real mismatch, a temporary `openssl s_server -accept 18443 -cert /root/uxaudit-certs/served.pem -key /root/uxaudit-certs/served.key -www` served a different synthetic leaf. A single audit-only hosts alias mapped `uxaudit-tls.example.test` to the worker's host gateway. `/etc/hosts` inside the hardened worker was read-only; the alias was instead added to that container's host-side Docker HostsPath, without modifying Compose or restarting services. The exact tagged line was removed afterward, and the audit's own tracked TLS-server PID was stopped. Resolution absence and process exit were verified, then all three service health states rechecked.

Read-only database verification (no credential/hash/ciphertext columns):

```sql
select endpoint_id, status, observed_common_name
from scan_result where endpoint_id = 2;
-- 2 | mismatch | uxaudit-served.example.test
select id, host, is_active from endpoint where host like 'uxaudit-%';
-- 2 | uxaudit-tls.example.test | f
select username, email, is_active, must_change_password
from "user" where username like 'uxaudit-%';
-- uxaudit-walkthrough | uxaudit-edited@example.test | f | t
```

Executed with `docker compose exec -T db psql -U db_owner -d cert_dashboard -c '<query>'`. Initial guesses `cert_owner`, `scan_endpoint`, `must_change` failed; actual model/table/column names above were then used. Do not reuse the failed guesses as setup instructions.

## Screen/state coverage

Live image paths below are relative to `docs/ux-audit/live/`. The complete generated index includes every capture. The original read-only crawl's [manifest](ux-audit/live/manifest.json), [CRUD log](ux-audit/live/walkthrough.json), [follow-up log](ux-audit/live/followup.json) and [CSRF verification](ux-audit/live/verification.json) retain observed text and responses without hidden form tokens or secrets.

| Requested surface | Live evidence | Boundary |
|---|---|---|
| Login and error | `login.png`, `login-deactivated-user.png` | Real form login and refused inactive user; no MFA enrollment/lockout attempt |
| Overview with data | `overview.png`, `overview-after-import.png`, `overview-mobile.png` | Lab data before/after imports; not an empty database |
| Empty Overview | Historical `../overview-empty-desktop.png` | **Fixture only**, existing lab records protected |
| Certificates list/detail/edit/import | `certificates.png`, `certificate-detail.png`, `certificate-import.png`, `certificate-imported-expected.png`, `certificate-metadata-edited.png` | Three actual imports; edit survived reload |
| Empty/error certificate states | `certificate-filter-empty.png`, `certificate-imported-expired.png`, `certificate-imported-expiring.png` | Filtered empty ≠ pristine inventory |
| Inventory | `servers-empty.png`, `bindings-empty.png`, `inventory-scanned-empty.png` | Truly no managed servers/bindings; discovery disabled |
| Users | `users.png`, `users-create-open.png`, `users-created.png`, `users-edited.png`, `users-reset-confirm.png`, `users-reset-done.png`, `users-deactivate-confirm.png`, `users-deactivated.png` | Actual native form POSTs, not fixture interactions |
| Temporary-password sign-in | `user-forced-password-change.png` | Redirected to Account; password change itself not completed |
| SSH key management | `settings-worker.png`, `ssh-controls.png`, `ssh-remove-confirm.png`, `ssh-validation-error.png` | Real editor/confirmation and invalid-material rejection; preexisting key not overwritten |
| Settings/logo search | `administration.png`, all `settings-*.png` | Real settings groups, no logo editor |
| GitHub repository flow | `github-repository-saved.png`, `github-test-pull-queued.png`, `github-test-pull-result.png` | Generic Git URL saved; worker failed missing known_hosts; original empty URL restored |
| Scans/detail/history | `scans.png`, `scan-detail.png`, `endpoint-created.png`, `endpoint-mismatch.png`, `endpoint-expectation-edited.png`, `endpoint-deactivated.png` | Actual mismatch confirmed in DB; only audit endpoint mutated |
| Operations/account/audit | `deploy.png`, `deploy-jobs.png`, `renewals-empty.png`, `renewal-new.png`, `account.png`, `audit.png` | Reachable screens only; no deployment or issued renewal |
| Narrow viewport | `*-mobile.png`, `navigation-mobile-open.png` | Layout emulation only, not physical touch testing |
| HTTP errors | `not-found.png` (404), `csrf-forbidden.png` (403), `csrf-htmx.png` (403 hidden from user) | 500 only in historical fixture; no failure induced in shared runtime |
| No JavaScript | `scan-no-javascript.png` | Real native login/navigation; native user mutations also exercised with JS enabled but no hx-post |

The exploratory paths `/jobs`, `/discovery` and `/certificates/7/export/pfx` returned 404. They were guesses, **not links emitted by the application**, and their duplicate images were excluded; do not report these as broken navigation. Actual Jobs is `/deploy/jobs`; Discovery is `/servers#discovery-actions`. PFX export is not available for the audit leaf without an imported key.

## Human-style walkthrough: actions, outcomes and friction

1. **Arrive and log in.** Opened HTTPS `/login`, filled the actual form and submitted. Reached Overview with a real server-issued session. Main groups and attention counters were readable. No runtime was started locally because its prerequisite failed; the authorized healthy staging stack was used instead.
2. **Add a managed inventory item.** Clicked Infrastructure → Servers → Run discovery. No Add/Edit/Delete host/group action exists. The empty page suggests Discover all while discovery is disabled by a critical missing-known_hosts banner. Settings → Inventory contains source configuration, not host authoring. This is distinct from adding a scan endpoint.
3. **Create a local user.** Administration → Users → Create user opens a native disclosure, not the old static audit's bottom-of-page anchor. Entered `uxaudit-walkthrough`, synthetic email/name and a generated temporary password. Created successfully; row persisted on reload. Every active user is an administrator, so the requested “non-admin test account” is impossible on this baseline.
4. **Edit and reset that user.** Opened its Manage control, changed email/display name and saved. Then opened Reset password, read confirmation, supplied a generated temporary password plus the administrator's current password and submitted. Specific success text confirmed sign-out and forced password change. A separate real login with that temporary password redirected to `/account` and showed the required-change screen. No credentials appear in evidence.
5. **Try user deletion.** No hard-delete exists. Deactivate is the supported equivalent: opened its confirmation, supplied administrator reauthentication, submitted, reloaded and verified inactive DB state. A separate login with the reset password was refused. The retained inactive row has no Reactivate. Did not touch the only preexisting administrator or intentionally test last-admin lockout.
6. **Find and try SSH management.** Administration → Settings → Worker exposes the actual singleton credential. Opened Replace key and Remove key disclosures; removal requires a typed confirmation. The public fingerprint/type/source are visible; stored private material is not. Submitted `uxaudit-not-a-private-key`; received a specific validation error, and the original key's configured fingerprint/set-by timestamp remained unchanged. Did not install/remove a disposable key over the preexisting one. There is no named multi-key list/per-host selector.
7. **Link a GitHub repository.** In Settings → Inventory saved `https://github.com/uxaudit-no-such-org/uxaudit-inventory.git` as a disposable URL. Stayed inside the dashboard (no OAuth redirect/GitHub bounce). Clicked Test pull; saw queued then **failed: `config_invalid: SSH known_hosts file is missing`**. This even blocks the HTTPS source test before an actual fetch. Cleared the URL again through the form and verified the original empty value after reload. Successful checkout, content editing, discovery and GitHub-side creation remain untested/unavailable; a nonexistent repo was deliberately used, not claimed imported.
8. **Import certificates.** Uploaded synthetic valid, expiring and expired leaves plus chain through Import. Reached real detail pages #7, #8, #9. Edited #7 owner/notes, reloaded and verified the saved owner. Warnings about chain/trust were retained. Imported audit certificates remain labeled for later lab cleanup; no unsupported hard-delete workaround was used.
9. **Create an endpoint and verify a scan.** Operations → Scans → Add endpoint with `uxaudit-tls.example.test:18443`, audit SNI and expected certificate #7. Opened detail #2 → Scan now. Worker actually observed the different served leaf and stored mismatch; queried `scan_result` to prove it. Changed expectation to audit certificate #8 through the form, then Deactivate. Deactivation submitted immediately with **no confirmation**, but retained history; reload and DB confirmed inactive.
10. **Find settings and branding.** Administration now has a hub; Settings and user-menu destinations are present. Header is still text “Cert Dashboard,” not a replaceable organization mark. Inspected System and maintenance and other settings; no branding controls. The older missing-admin-hub observation must not be reused.
11. **Try narrow navigation and errors.** At 390×844 expanded Menu, opened list/detail/settings and user-management disclosure, then scrolled to repository/SSH fields. No document-wide overflow in the initial narrow crawl; the user table has its own two-axis scroll. Rejected a deliberately corrupted CSRF token, once with HTMX and once without scripts. Both HTTP responses were **403**; only the native flow displayed the useful “Your form expired. Reload the page and try again.” HTMX left the original form on-screen without that message. A made-up GET returned the real 404 screen.

## Prioritized reproducible findings

P0 = critical safety/outage blocker; P1 = substantial task-blocking gap or major friction; P2 = meaningful friction with a workaround. **No P0 established.** This is a targeted workflow audit, not a numeric WCAG/performance certification.

### UX-01 — P1 — Managed-host inventory cannot be authored inside the dashboard

- Reproduce: Infrastructure → Servers → look for Add/Edit/Delete host/group → Settings → Inventory.
- Expected: optional local/manual inventory alongside Git sources.
- Actual: Git source settings and discovery, but no managed-host/group authoring. Manual scan endpoints are not managed Ansible hosts.
- Evidence: `servers-empty.png`, `settings-inventory.png`; source `app/web/servers.py` discovery/list/detail routes.
- Impact/action: first usable managed inventory needs external repository permissions and Ansible knowledge. Specify local host/group lifecycle, provenance and reconciliation; preserve generic Git.

### UX-02 — P1 — Credential editor exists, but safe host-trust onboarding still leaves the UI

- Reproduce: Settings → Worker: key is Configured → Servers: discovery disabled → Settings → Inventory: save a disposable HTTPS URL → Test pull.
- Expected: distinguish missing SSH key from missing host trust and provide a verifiable path to finish onboarding; HTTPS test should not misleadingly imply key configuration solves everything.
- Actual: no UI for known_hosts; banner says missing known_hosts; Test pull fails with that same error before even fetching HTTPS. Key replacement cannot fix this state. **This supersedes the old “no SSH editor” finding.**
- Evidence: `settings-worker.png`, `ssh-controls.png`, `github-test-pull-result.png`; live follow-up log.
- Impact/action: discovery/deploy and even source testing are blocked. Add explicit fail-closed host-key verification/onboarding (not automatic trust), and separate capability requirements for Git HTTPS vs SSH. Reuse the existing encrypted credential service/editor.

### UX-03 — P1 — User management traps long forms in a two-axis table scroll

- Reproduce: Users → audit row Manage → Reset password; inspect the expanded Actions cell.
- Expected: readable full-width editing and security consequences.
- Actual: measured table client area 1230×574, scroll area 1271×1153; confirmation extends below/right of the viewport while other columns occupy the enlarged row.
- Evidence: `users-manage-live.png`, `users-manage-mobile.png`; live measurement in follow-up log. CRUD still succeeded; this is not a claim of reset failure.
- Impact/action: additional coordinated scrolling to review consequences/submit. Use a dedicated detail surface or full-width management region; preserve reauthentication, CSRF, confirmations and history.

### UX-04 — P2 — Narrow settings bury the task below navigation and repeated guidance

- Reproduce: at 390×844 open Settings → Inventory at scroll top.
- Expected: source field/setup status within prompt reach.
- Actual: shell, critical banner, heading/actions, long draft warning and nine wrapping section links consume the initial viewport; repository field is absent until scrolling. Same problem precedes Worker controls.
- Evidence: `settings-inventory-mobile.png`, `settings-inventory-fields-mobile.png`, `settings-worker-mobile.png`.
- Action: compact task navigation and concise save/draft guidance; retain plain no-JavaScript limitations and visible consequence copy. This is not page-wide horizontal overflow.

### UX-05 — P2 — No in-dashboard organization/logo replacement

- Reproduce: inspect header/login → Administration → Settings → System and maintenance.
- Expected: a default identity and replace/reset organization logo/name.
- Actual: fixed text brand, no editor/preview/upload/reset.
- Evidence: `login.png`, `administration.png`, `settings-general.png`; base template.
- Action: consume the separately designed default branding and provide validated image replacement/reset and accessible text fallback. No logo production change belongs in this audit PR.

### UX-06 — P2 — User lifecycle is irreversible from the UI

- Reproduce: create audit user → deactivate with reauthentication → reload Users → inspect retained row.
- Expected: clear lifecycle with a decided recovery path.
- Actual: deactivation and history retention work, but no reactivation, username rename or hard delete. UI explicitly explains no reactivation. All active accounts are administrators.
- Evidence: `users-deactivated.png`, `login-deactivated-user.png`, DB query above.
- Action: decide reactivation and role policy before adding controls; preserve immutable audit and last-admin safeguards. This is not GitHub-based user management.

### UX-07 — P2 — “Inventory” source setup is separated from the empty managed-host task

- Reproduce: Infrastructure → Servers on zero hosts → Run discovery → Settings → Inventory.
- Expected: actionable first-host/source guidance from the empty state.
- Actual: says “No servers match these filters / Clear the filters” although the unfiltered table genuinely has zero hosts, then suggests a disabled discovery action. Source configuration is in another administration surface.
- Evidence: `servers-empty.png`, `inventory-scanned-empty.png`, `settings-inventory.png`.
- Action: distinguish never-configured, filtered-empty and failed-discovery states; provide a direct Inventory sources/setup link and local-vs-Git choice, without conflating certificate inventory and managed hosts.

### UX-08 — P1 — HTMX hides a real CSRF refusal from the operator

- Reproduce on staging: Scans → Add endpoint; corrupt only that form's hidden CSRF token using browser test tooling; submit. Repeat with JavaScript disabled. This is an invalid-token test, not proof of a naturally aged session.
- Expected: rejected operation displays expiry/reload guidance without implying success; must not create an endpoint.
- Actual: both requests return 403. With HTMX, unchanged Scans form remains, no expiry message; without scripts, “Your form expired. Reload the page and try again.” appears on the 403 page. No rejected endpoint was persisted.
- Evidence: `csrf-htmx.png`, `csrf-forbidden.png`, `verification.json` with actual response statuses; endpoint DB query lists only the authorized created endpoint.
- Impact/action: repeated clicks cannot explain/fix a rejected form. Render server error guidance for HTMX failures accessibly while preserving strict CSRF validation; cover 403 and session-expiry tests for enhanced/native flows.

### UX-09 — P2 — Endpoint deactivation is immediate, not confirmable

- Reproduce: open an active **audit-only** endpoint → Manage → Scheduled scans → Deactivate.
- Expected: destructive-looking, explicit confirmation before stopping monitoring.
- Actual: immediate POST/HTMX update switches to Activate; no disclosure/interstitial or reauthentication. History remains, and it is reversible, so not P0/P1.
- Evidence: `endpoint-expectation-edited.png`, `endpoint-deactivated.png`; `app/templates/scans/detail.html.j2` active form.
- Action: consistent danger treatment and native confirmation with cancellation; retain activation/history behavior.

## Per-screen strengths and remaining test boundaries

- **Overview/certificates:** attention-first words/icons/counts, direct next steps, actual expired/expiring differentiation, stored-vs-live language and import/edit persistence work. Empty Overview not live-tested.
- **Infrastructure:** useful failure banner prevents treating unavailable discovery as success. No managed servers were created externally just to fake a populated screenshot; historical server/detail/dump fixture states remain labeled.
- **Users/account:** native creation now opens where the operator clicked; reset/deactivate explain effects and require current administrator password. Temporary-password login enforces the change gate. User reset-TOTP, MFA enrollment, full password change and last-admin refusal were not exercised.
- **Worker settings:** encrypted write-only singleton secret lifecycle, fingerprint/source metadata, typed remove confirmation, invalid-key validation and secret-draft warning are already present. Successful rotation/removal, token/vault saves and worker reload semantics were not tested over protected existing settings.
- **Other settings:** SMTP/alerts/inventory/deployment/schedule/trust/status/system surfaces captured. Repository save/restore was tested; broad SMTP/trust/schedule mutation was not authorized or needed for this audit.
- **Operations:** real manual scan mismatches are meaningful and DB-backed; renewal/deploy screens captured without contacting a CA or deploying to hosts. No target SSH/known_hosts/CA exists for completed flows.
- **Navigation/narrow:** real Admin hub and expanded mobile navigation are present. No initial narrow document overflow; interior table clipping and buried forms remain. Browser pageerror list was empty for the initial crawl; HTTP failures (notably 403) are tracked separately, not called “no errors.” No full accessibility or contrast score is claimed.

## Explicit outside-dashboard gap matrix (current live baseline)

| Task | Available inside dashboard? | External dependency / missing capability |
|---|---|---|
| Import certificate, edit metadata, add/modify scan expectation | Yes, exercised | Scan endpoints are not managed inventory hosts |
| Create/edit/reset/deactivate local user | Yes, exercised | Initial bootstrap remains CLI; no role other than admin |
| Reactivate/rename/hard-delete account | No supported UI | Product policy needed; no external workaround asserted |
| Author managed host/group inventory | No | Edit generic Git/Ansible inventory externally; then discovery |
| Configure repository URL/ref/path, Test pull | Yes, exercised | Creation/content editing remains in Git host/CLI; runtime missing known_hosts prevented fetch |
| GitHub OAuth/repository browser | No | Not mandatory for generic Git; no automatic external bounce observed |
| Replace/remove SSH key, vault password, inventory token | **Yes, existing Worker tab** | Not a missing-key-editor feature; valid mutation not submitted over existing protected key |
| Named multiple SSH keys / per-host credential selection | No observed UI | Current model is one effective worker key; decide whether multiple credentials are needed |
| Verify/pin SSH host keys | No | Operator-managed known_hosts file mount; current lab lacks it |
| Change SMTP password | No observed UI | Worker-only secret file (do not infer Worker inventory-token field covers SMTP) |
| Bootstrap/migrate/master-key custody | CLI/host only | Security/operations responsibility, not automatically appropriate for web UI |
| Replace logo / organization identity | No | Code/template change today; separate branding spec exists |

## Concrete follow-up capabilities

1. **Local inventory + optional generic Git sources:** managed host/group create/edit/deactivate, clear provenance/reconciliation and first-run setup. Preserve certificate/scan inventory distinctions and existing source configuration.
2. **Finish worker access onboarding, do not rebuild it:** use existing SSH/vault/token editor; add safe known_hosts verification and precise capability diagnostics. Decide named/per-host credentials separately.
3. **Improve existing user management:** dedicated readable management view and explicit reactivation/role/rename policy; retain reset/reauth/history/security gates.
4. **Error and action consistency:** HTMX/native 403 recovery parity; confirm monitoring deactivation and preserve cancel paths.
5. **Settings and branding:** compact responsive navigation, direct setup links, default local logo plus safe replacement/reset/preview.

## Acceptance and verification handoff

This is a docs/images-only deliverable with real live workflow evidence and historical fixture supplementation, not a claim that every conceivable state was exercised. The strict request to replace **empty Overview** with a live screenshot remains incompatible with preserving existing shared lab data. Successful SSH mutation is similarly incompatible with protecting its preexisting singleton key. A live 500 was not intentionally caused. These require operator acceptance of the documented exclusions or a disposable fresh app/database and credential slot; they must not be silently called passed.

Exact final lint/unit/remote-CI results are recorded in the PR and task handoff. No production route/template/business-logic file was changed by this audit, so there is no new runtime integration contract to regress. The historical test counts apply only to the original attempt; they are not substituted for the refreshed PR's checks.
