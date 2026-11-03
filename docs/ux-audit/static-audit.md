# Historical static UX audit — superseded baseline fe928fd

> Retained fixture-only evidence from the first attempt. This is not the current capability inventory or task status. In particular, its absent-SSH-editor and missing-administration-hub observations are superseded by the [live audit](../ux-audit.md) at deployed baseline 2489211. Follow the live report for decisions.


## Evidence boundary and decision summary

Baseline: `fe928fd` (`feat(ui): one product across operations and grouped settings`). This is a **source-backed and static-browser audit, not a completed live manual test**. No production code was changed. Screenshots are real Chromium captures of the repository's regenerated Jinja fixture previews; their certificate counts, identities, dates and worker results are synthetic fixture data, not observations of a running service. They must not be presented as live screenshots.

**structural checks passed; visual verification pending on the deployed instance**.

The requested live app launch, login, persistence, validation responses, Git checkout, SSH and destructive CRUD actions could not be exercised. The local Docker client exists, but the daemon is unavailable. This card therefore remains blocked rather than marking its acceptance criteria complete. Provide an isolated reachable staging instance and a vault-managed test administrator (plus permission to create/deactivate disposable accounts and run repository tests), or an approved runtime with PostgreSQL and worker services. Do not use production for destructive exploration.

Important corrections to the original hypothesis:

- Users **already have** in-dashboard creation, profile editing, password/2FA resets and deactivation. Do not specify a replacement user manager on the assumption it does not exist.
- Managed-server inventory is Git-backed; **GitHub specifically is not required**. The UI accepts generic HTTPS/SSH Git repositories. There is no observed automatic bounce to GitHub, OAuth connection or GitHub repository picker.
- Certificates can already be imported by upload or network pull, and scan endpoints can be added manually. These are not equivalent to managing the Ansible server inventory.
- There is no SSH-key manager or customizable logo in this baseline.

## Setup and exact execution

From the task worktree:

```sh
cd /opt/data/projects/cert-dashboard/.worktrees/t_f79b9a14
git log -1 --format='%h %s'
docker info
uv sync --frozen
uv run python -m scripts.render_previews
uv run ruff check .
uv run pytest -q tests/unit
uv run pytest -q tests/unit -k 'not test_topology'
uv run pytest -q tests/test_ui_previews.py tests/test_navigation_queue_previews.py tests/test_operations_previews.py
```

Results:

- `docker info`: client 26.1.5; `Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?` Exit 1. README Quick start requires Docker build, database, owner migrations, bootstrap-admin, then web/worker. Those operations were not run after this prerequisite failed. No system services, production credentials or secret files were changed.
- `uv sync --frozen`: succeeded, CPython 3.12.16 and the lockfile dependencies.
- Preview generator: succeeded; all 77 existing previews regenerated with no tracked diff.
- Ruff: `All checks passed!`.
- Full unfiltered unit command: timed out at the 180-second execution limit before finishing; **not a passing full-suite claim**.
- README's documented Docker-less gate: **1310 passed, 39 deselected, 34 warnings**, 206.98 seconds. Warnings concern `forkpty` in a multithreaded process.
- Repository preview checks: **45 passed**, 10.68 seconds.
- Impeccable context launcher: permission denied; existing README, design system, templates and routes read directly instead. No changes to the skill installation.

The browser opened `file:///…/docs/ui/previews/<name>.html`, never the ASGI application. Capture dimensions and dark media preference were applied **after each navigation**, then verified from PNG headers. Desktop is 1440×1000; narrow emulation is 390×844, device scale 1. No physical mobile device or touch gesture testing occurred. Screenshots are viewport captures, not assertions that all below-fold content is visible.

## Screenshot coverage

[Full capture index](README.md) links every image; [machine-readable manifest](captures.json) records fixture, dimensions, theme and rendered text. There are 77 desktop fixture captures, 10 narrow captures and 4 additional native-interaction states. All 91 PNG dimensions match the manifest. The ten narrow initial views had document width 390px: no page-wide horizontal overflow in those fixtures. Tables can still require internal horizontal scrolling.

| Requested area | Evidence | Boundary |
|---|---|---|
| Login, invalid credentials and 2FA | [login](login-desktop.png), [error](login-error-desktop.png), [2FA](login-2fa-desktop.png) | No real authentication attempted |
| Empty/data dashboard | [empty](overview-empty-desktop.png), [data](overview-desktop.png), [narrow](overview-mobile.png) | Synthetic counts and worker states |
| Certificate list/detail/edit/import | [list](certificate-list-desktop.png), [detail](certificate-detail-desktop.png), [edit](certificate-edit-desktop.png), [import](import-desktop.png) | No upload, download, persistence or network pull |
| Managed inventory | [servers](server-list-desktop.png), [empty](server-list-empty-desktop.png), [repository settings](settings-inventory-desktop.png) | No local inventory CRUD screen exists |
| Users | [list](users-desktop.png), [create anchor](users-add-disclosure-desktop.png), [manage/reset confirmation](users-manage-confirm-desktop.png) | Native controls clicked; no POST or password entry |
| SSH keys | [inventory capability area](settings-inventory-desktop.png), [status](settings-status-desktop.png) | **No SSH management screen exists to capture**; no fabricated screenshot |
| Settings/branding | [general](settings-general-desktop.png), [maintenance](settings-maintenance-desktop.png) | No branding/logo editor exists |
| GitHub-repo-only flows | [repository configuration](settings-inventory-desktop.png), [test-pull fixture result](settings-inventory-fields-mobile.png) | Generic Git only; no GitHub-specific screen exists; result is fixture, not executed pull |
| Error/empty states | [403](error-403-desktop.png), [404](error-404-desktop.png), [500](error-500-desktop.png), plus all existing empty fixtures in index | HTTP status handling/CSRF/expiry not exercised |
| Other reachable page families | Account/MFA, audit, scans, bindings, deploy preview/jobs/results, server discovery details/dumps and renewal steps in index | Template-state coverage, not live route reachability proof |

## Human-style walkthrough: what actually happened

1. **Arrive at sign-in.** Opened the login preview and inspected the labeled username/password controls, focused username field and recovery guidance. Stopped before credentials: this file has no working authentication service. Invalid-credentials and 2FA fixtures were captured separately, not reached by a fabricated failed sign-in.
2. **Understand the landing screen.** Opened populated and empty Overview fixtures. The attention table provides icon, label, count and next-action link; work in flight and stored system timestamps are separated. No claim that any displayed scan or worker actually ran.
3. **Try to add an inventory server.** Inspected Infrastructure → Servers and its discovery actions. There is Run discovery, Discover all/group and export, but no server Add/Edit/Delete form. Inspected Settings → Inventory: repository URL, ref, path and webserver variable. Route inspection confirms discovery-only mutations, not host CRUD. The Git repository remains the external authoring surface.
4. **Try to add a user.** Opened Users fixture. Clicked Add local user: URL hash became `#create-heading` and the create heading was brought into view. Inspected username/email/display name and temporary-password confirmation. Did not type a password or submit the form. Source confirms `POST /users` and its validation/notice paths.
5. **Try to edit/remove a user.** Clicked the first row's Manage, then Reset password disclosure; both opened. Inspected profile edit, reset and deactivation controls and consequence copy. A hard-delete control and reactivation control are absent by explicit backend design. No account changed. See the actual [interaction log](interaction-log.json).
6. **Try to add/edit/delete an SSH key.** Inspected navigation, settings sections, worker capability reporting and credential configuration. No key CRUD route or form exists. `ansible_ssh_key` is a worker-only file mount; installation/replacement requires external operations. This is source-confirmed, not a failed live upload.
7. **Try to link/import a GitHub repository.** Inspected generic repository fields (fixture `ssh://git@example.test/inventory.git`, ref `main`, path `hosts`). UI offers save and Test pull. There is no provider login or browse/create repository action. Did not submit, fetch or visit a real repository. To change a host today, an operator must edit the external Git inventory, then refresh/discover; they are not automatically redirected to GitHub.
8. **Find settings and the logo.** Desktop Administration lands on Settings; Users is also available from the user menu. On narrow view, clicked Menu and captured its expanded navigation. The header brand is literal `Cert Dashboard` text linking home. General/System and maintenance contain no organization name/logo upload/reset.
9. **Check narrow rendering.** Opened ten fixtures at 390×844; inspected repository settings and certificate detail screenshots. The inventory fields start below the first viewport because save controls, a long fallback explanation and wrapped settings tabs precede them. Certificate identity wraps; table regions keep overflow internal. This does not establish touch usability, mobile keyboard behavior or real form submission.

## Prioritized findings

Severity here: P0 = critical operational/safety blocker; P1 = major workflow gap or substantial task friction; P2 = friction with a practical workaround. **No P0 is established by this partial audit.** Three P1 and four P2 findings follow. Capability gaps are relative to the new self-contained-dashboard goal, not allegations that documented v1 behavior is a regression.

### UX-01 — P1 — Managed-server inventory cannot be authored inside the dashboard

- **Reproduce:** inspect Servers → look for Add/Edit/Delete → inspect Settings → Inventory. Only repository configuration and discovery are offered.
- **Expected for target goal:** create/edit/deactivate a local host/group without Git; retain optional Git sources.
- **Actual:** hosts are discovered from read-only Git inventory; server routes expose lists/details/dumps/exports and discovery, not host CRUD. Certificate imports and manual scan endpoints do not fill this gap.
- **Evidence:** `app/templates/servers/list.html.j2:8–11,57–80`; `app/web/servers.py:274–348`; README Deployment; [servers screenshot](server-list-desktop.png).
- **Impact/recommendation:** new operators need repository access and Ansible inventory knowledge before discovering their first host. Add explicit local vs Git source management with provenance, collision policy, validation and confirmation before deactivation; do not silently overwrite discovered hosts.

### UX-02 — P1 — SSH access setup and credential lifecycle leave the UI

- **Reproduce:** inspect Administration/Settings sections → Inventory worker capability → Status → look for SSH credential add/replace/remove and known-host verification controls.
- **Expected:** an administrator can safely configure access and diagnose missing credentials within the dashboard.
- **Actual:** worker receives `ansible_ssh_key`, `inventory_git_token` and pinned known hosts via filesystem/Compose mounts. There is no key-management page, selector or lifecycle route.
- **Evidence:** `docker-compose.credentials.yml:3–23`; `app/config.py:150–166`; `app/templates/settings.html.j2:209–234`; [status](settings-status-desktop.png).
- **Impact/recommendation:** dashboard-only onboarding is impossible. Specify write-only upload/replace/remove, fingerprint metadata, audit and worker reload/effective-state semantics; never render private material, retain it in browser drafts or weaken host-key checking. Known-host setup needs an explicit safe workflow too.

### UX-03 — P1 — User management expands into a cramped scrolling table cell

- **Reproduce (performed on fixture):** Users → first row Manage → Reset password. Observe the rightmost Actions cell and scroll region.
- **Expected:** editing/security confirmation remains readable without two-axis hunting.
- **Actual:** inline forms expand the row inside a bounded table; fields extend to the right of the visible region while reset confirmation continues below it. Many unrelated cells occupy the enlarged row height.
- **Evidence:** [opened manage/confirmation](users-manage-confirm-desktop.png); `app/templates/users.html.j2:46–90`. This is a rendered layout finding, not a failed reset.
- **Impact/recommendation:** operators must coordinate internal horizontal and vertical scrolling to inspect consequences and controls. Move management into a full-width detail section/page, retaining native confirmation, current-password checks, CSRF and last-admin protections.

### UX-04 — P2 — Inventory settings fields are below the initial narrow viewport

- **Reproduce:** open Settings → Inventory at 390×844, at scroll top.
- **Expected:** reach the repository field promptly and understand where it is saved.
- **Actual:** page header, primary save, More actions, draft explanation and wrapped section links consume the first viewport; the Inventory panel starts at its bottom.
- **Evidence:** [initial narrow state](settings-inventory-mobile.png), [scrolled fields](settings-inventory-fields-mobile.png).
- **Impact/recommendation:** frequent vertical navigation before configuration; put succinct save/draft guidance beside the form and compress section navigation without removing the no-JavaScript warning. No page-wide overflow was measured here.

### UX-05 — P2 — No organization branding/logo management

- **Reproduce:** inspect header brand → Administration → Settings → System and maintenance/General; search for logo/name/upload/reset.
- **Expected for target goal:** usable default identity, organization label and replace/reset logo.
- **Actual:** literal text brand in base template, no asset/logo editor or branding settings.
- **Evidence:** `app/templates/base.html.j2:13`; [login header](login-desktop.png); [general](settings-general-desktop.png).
- **Recommendation:** design a default local logo and safe image replacement/reset with size/type validation, descriptive text fallback and previews in both themes. This card creates no logo or production assets.

### UX-06 — P2 — User lifecycle is intentionally one-way in the UI

- **Reproduce:** Users → Manage an account → inspect Deactivate consequence and available actions, including inactive account.
- **Expected:** clearly bounded user lifecycle, with a recovery path if reactivation is part of the target scope.
- **Actual:** deactivation retains account/history and explicitly says reactivation is unavailable; no delete/reactivate route exists. Email/display name can be edited; username is not an edit field.
- **Evidence:** `app/web/users.py:1–7,146–211`; `app/templates/users.html.j2:81–100`; [users](users-desktop.png).
- **Recommendation:** decide reactivation and username policies; preserve immutable audit history and do not add hard deletion merely to complete CRUD. This is not GitHub-based user administration.

### UX-07 — P2 — Two inventory meanings obscure setup location

- **Reproduce:** navigate Certificates → Infrastructure → Servers → Administration → Settings → Inventory.
- **Expected:** distinguish stored certificates, managed hosts and inventory-source configuration without guessing.
- **Actual:** certificate inventory exists in Certificates, hosts in Infrastructure, source configuration in a separate Settings tab; Servers emphasizes discovery but offers no direct inventory-source setup action in its page-header actions.
- **Evidence:** `_navigation.html.j2:5–8`; `servers/list.html.j2:8–11,49–50`; [server empty state](server-list-empty-desktop.png).
- **Recommendation:** name the source surface “Inventory sources,” expose it from Infrastructure and include a first-run setup link; keep certificate imports separate. Existing grouped navigation is a useful base, not a reason to rebuild the entire shell.

## Per-screen observations and strengths to preserve

- **Login/2FA/account:** labeled controls, visible focus, specific recovery guidance and MFA states exist. No authenticated success, lockout, expiry, CSRF or server response was verified.
- **Overview:** attention-first table uses icons + words + counts and direct next steps. Stored results are labeled as recorded, not live probes. Empty and clear states exist.
- **Certificates:** list, filtered/empty/dense fixtures, detail, metadata edit, PFX export and import screens exist. Narrow detail has a wrapping identity and scrollable SAN block. No certificate action was submitted.
- **Infrastructure/bindings/discovery:** useful failure, never-discovered, suspected-parse, no-bindings and dump-empty fixtures exist. Do not conflate stored discovery with live TLS reachability or desired-state compliance.
- **Users:** real functionality already exists; resets and deactivation are confirmable, visibly destructive and explain session effects. Main issue is presentation and incomplete reversible lifecycle, not lack of user creation.
- **Settings:** SMTP, alerts, inventory, deployment, schedule/scanning, trust, status and maintenance are represented. Explicit section saves and draft limitations are documented; actual save/restore/HTMX behavior remains untested.
- **Scans/deploy/renewal:** fixture coverage includes mismatch/error/unscanned results, deployment guardrails/paused/running/failure states and renewal steps. No network, deployment, rollback or CA workflow was executed.
- **Errors:** distinct 403/404/500 previews include clear status messaging. Their existence is not evidence of actual status-code or expiry handling.
- **Accessibility/performance/theming:** not scored. Focus styling and semantic controls are visible/source-backed, but no full contrast, assistive-technology, performance or WCAG conformance audit was executed. Dark captures are not proof of light-theme quality.

## Explicit outside-dashboard gap matrix

| Task today | In dashboard? | External dependency / important distinction |
|---|---|---|
| Import certificate, edit metadata | Yes, upload/pull and edit routes | Not live-tested here |
| Add manual TLS scan endpoint | Yes | Does not create managed Ansible inventory host |
| Create/edit local user; password/2FA reset; deactivate | Yes | Not GitHub/file-only; first bootstrap uses CLI |
| Reactivate/hard-delete user; rename username | No UI route | Explicit lifecycle/product decision needed; no supported external reactivation recipe established by this audit |
| Add/edit/remove managed server/group | No authoring UI | Edit external Git inventory, then refresh/discover; reconciliation does not delete bindings |
| Link/change repository URL/ref/path | Yes | Generic Git source configuration; repo creation/content editing remains outside dashboard |
| Browse/create repo through GitHub OAuth | No | Not needed for generic Git support; do not fabricate a provider flow |
| Install/rotate/remove worker SSH key and Git credential | No | Operator-managed file secrets and worker lifecycle |
| Pin SSH host keys | No | External known_hosts mount; verification must remain fail-closed |
| Change SMTP password | No | Worker-only `smtp_password` file |
| Bootstrap first admin, migrations, master-key custody/rotation | No ordinary UI | CLI/host operations; not automatically appropriate to move into web UI |
| Replace logo/organization name | No | Template/code change today, not a Git inventory edit |

## Concrete capabilities for the follow-up specification

1. **Local/manual managed inventory alongside optional Git sources** (UX-01, UX-07): first-run choice, source list/status, host/group create/edit/deactivate, source provenance and explicit merge/collision/deletion policy. Preserve existing Git URL/ref/path and test-pull/discovery flows.
2. **Safe in-dashboard worker credential management** (UX-02): write-only secret lifecycle, fingerprints, effective-worker-state reporting, tested reload semantics and known-host verification. Never expose private keys in HTML, logs, downloads or draft storage.
3. **Improve the existing user manager** (UX-03, UX-06): dedicated readable management view, existing create/edit/reset/deactivate preserved, reactivation policy settled, no accidental last-admin lockout or audit deletion.
4. **Settings/setup discoverability** (UX-04, UX-07): direct setup destinations from Infrastructure, concise first-run guidance, readable narrow layout, explicit section-save/dirty-state behavior and no-JavaScript fallback.
5. **Default logo plus organization branding editor** (UX-05): replace/reset, safe file validation, both-theme preview, readable text fallback and keyboard-accessible controls.

These are capability requirements for architect decisions, not new route/API schemas invented by this docs card.

## Live verification still required before accepting this audit

On isolated staging, record the deployed commit, exact startup commands, browser console/network failures and fresh screenshots. Use disposable synthetic records and vault-managed credentials, never passwords in chat/scripts. Repeat with HTMX disabled and at narrow width.

1. Sign in → optional MFA → Overview. Exercise invalid login, expiry and recovery without locking the only administrator.
2. Empty database → import disposable certificate → list/detail/edit → confirm success survives reload; capture empty and populated states.
3. Infrastructure → attempt local host/group creation/edit/delete and document actual unavailable actions; configure disposable Git repository → save → Test pull → observe worker result → discovery → inspect server/bindings. Test unreachable/invalid repository and missing credentials. Never deploy to real hosts.
4. Users → create disposable account → verify forced password change → edit email/name → reset password/2FA with administrator re-authentication → deactivate → prove sign-in is refused and last-admin protection holds. Record missing hard-delete/reactivation as designed, not guessed failures.
5. Attempt SSH-key add/replace/remove through UI; record absent capability, then validate any approved external setup separately without exposing private material.
6. Settings → save valid/invalid values → observe 422, success, drafts and native fallback. Inspect branding absence. Test actual 403/404/500 and CSRF/expired-session response through safe test mechanisms.
7. Repeat navigation, long tables and open user-management confirmations on narrow view; use keyboard Tab/Enter/Escape and real/synthesized touch where supported. Capture below-fold results and errors rather than relying on initial viewport images.

**Acceptance status:** docs and static screenshot evidence delivered in a draft PR; live/manual criteria and missing-screen requirements remain explicitly unresolved. Do not release downstream implementation on an assertion that this was a live end-to-end audit.
