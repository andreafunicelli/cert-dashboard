# Dashboard UX implementation spec — information architecture, sources, Slices A and B

Status: **normative** for the cards listed in §4. Where this document and the design spec
(`docs/superpowers/specs/2026-10-19-cert-dashboard-design.md`) differ, this document wins for the items it
names; the design spec carries a pointer here (§4.20, §8, §8.2, §8.6, §8.10, §9.8). Two sibling contracts stay
normative for their own scope and are **not** restated here:

- `docs/slice-b-contract.md` — Slice B (inventory, users, SSH keys): routes, fields, rules, its own
  acceptance checklists and smoke script.
- `docs/ui/branding.md` — default identity and replaceable logo: assets, placement, state machine, routes,
  validation, storage, error copy.

Plans 1–3 Global Constraints and Contract decisions keep applying to everything this document does not
change (CSRF on every POST, POST→303, usable without JavaScript, mutation + audit in one transaction, no
secret in UI/logs/audit, `web` never runs Ansible/Git/SSH).

Owner request: card `t_198538ae` — *"make the user manage the inventory, the users, the ssh keys everything
inside the dashboard. The user should only manage the dashboard, not external github repos, maintain the
possibility to use github repos but not only those. […] Also create a logo and make the user replace it."*
Evidence: `docs/ux-audit.md` (PR #90, live certlab walkthrough at `2489211`, 74 live captures).

Baseline: `main` at `4d553a3`. Slice B foundation, worker integration, users and SSH keys are merged
(`49aef42`, `2cf7aff`, `4e860c6`, `2613bd8`); Slice B inventory is PR #96 (card `t_c95126de`); default
branding assets are merged (`eb027e9`).

---

## 1. Audit findings → spec items

Every audit finding maps to a spec item or an explicit out-of-scope note. The audit established no P0.

| Finding | Prio | Resolution | Where | State on 2026-11-05 |
| --- | --- | --- | --- | --- |
| UX-01 managed-host inventory cannot be authored in the dashboard | P1 | Manual hosts on `/inventory`, Git optional; manual hosts reach discover/deploy | Slice B INV + W (`slice-b-contract.md` §4, §7); source model §3 here | W merged `2cf7aff`; INV PR #96 in review |
| UX-02 host-trust onboarding leaves the UI; HTTPS test pull blocked by known_hosts | P1 | (a) dashboard trust store for host keys; (b) known_hosts banner and setup checklist point at `/ssh-keys`, key vs host trust shown as separate steps; (c) HTTPS "Test pull" no longer needs known_hosts; job error names the fix | (a) Slice B SSH + W; (b) A1 §5.2, §5.4; (c) B-W2 §8.2 | (a) merged `2613bd8`/`2cf7aff`; (b)(c) to build |
| UX-03 user management trapped in a two-axis table scroll | P1 | Full-width `/users/{id}` page | Slice B USR (`slice-b-contract.md` §5) | merged `4e860c6` |
| UX-08 HTMX hides a real CSRF refusal | P1 | One global `htmx-config` in the shell that swaps 403/404/500/503 error pages into `#main-content` on every page | A1 §5.5 | to build (Slice B pages already patched by F, `49aef42`) |
| UX-04 narrow settings bury the task | P2 | Compact section picker and one-line draft guidance on narrow screens | A1 §5.3 | to build |
| UX-05 no organization logo replacement | P2 | Default lockup in the shell (A1 §5.6); upload/preview/save/reset (A2) | A1, A2a, A2b; `docs/ui/branding.md` | assets merged `eb027e9`; integration to build |
| UX-06 user lifecycle irreversible | P2 | Reactivation with a new temporary password; no roles, no rename, no hard delete (decided, `slice-b-contract.md` D3) | Slice B USR | merged `4e860c6` |
| UX-07 inventory source setup separated from the empty host task | P2 | `/inventory` empty states (B INV); `/servers` never-configured vs filtered-empty states and setup links (A1 §5.4); Overview setup checklist (A1 §5.1) | B INV, A1 | INV in review; A1 to build |
| UX-09 endpoint deactivation is immediate | P2 | Native confirmation disclosure before deactivation | A3 §7 | to build |

Gap-matrix rows of the audit that stay outside the dashboard by decision (§11): bootstrap of the first
administrator, migrations and master-key custody (CLI/host by design, spec §11), SMTP password (worker
secret file), GitHub OAuth/repository browser and editing repository content, named/multiple worker client
keys and per-host credentials, roles.

## 2. Target information architecture

### 2.1 Navigation

One shell for every signed-in page (`base.html.j2` + `_navigation.html.j2`). Desktop: a main bar of five
entries; the current group shows its pages in the area bar below. Narrow screens (the existing breakpoint
that hides `.desktop-navigation`): the `Menu · <area>` disclosure lists every group with all its pages.

| Main entry | Group link | Area pages (order) | Area matches paths starting with |
| --- | --- | --- | --- |
| Overview | `/` | — | `/` exactly |
| Certificates | `/certificates` | Certificates `/certificates`, Import `/certificates/import`, Renewals `/renewals` | `/certificates`, `/imports`, `/renewals` |
| Infrastructure | **`/inventory`** (was `/servers`) | Inventory `/inventory`, Servers `/servers`, Bindings `/bindings`, Discovery `/servers#discovery-actions`, SSH keys `/ssh-keys` | `/inventory`, `/servers`, `/bindings`, `/ssh-keys` |
| Operations | `/scans` | Scans `/scans`, Deploy `/deploy`, Jobs `/deploy/jobs` | `/scans`, `/deploy` |
| Administration | `/administration` | Administration `/administration`, Users `/users`, Settings `/settings`, Audit `/audit`, My account `/account` | `/administration`, `/users`, `/settings`, `/audit`, `/account` |

Decisions:

- **N1.** The landing page keeps the name **Overview** (spec §8.2, existing tests and previews). "Dashboard"
  in the requests means Overview at `/`. No rename.
- **N2.** Infrastructure opens on **Inventory**: it is where hosts are created, and it works with no
  repository. Servers stays the discovery-results list.
- **N3.** Administration gains its own first area page (`Administration`, the hub, §2.3) so the hub is
  reachable from the area bar and from the narrow menu, not only from the group link.
- **N4.** Capability-disabled entries (`app.state.navigation` with `enabled = false`, e.g. Deploy/Scans on
  a build without those handlers) keep rendering as `aria-disabled` text with the reason as `title`.
- **N5.** The user menu (`<details class="user-menu">`) lists My account, Administration, Users.
- **N6.** Active state: the main entry carries `aria-current="location"`; exactly one area page carries
  `aria-current="page"` (no page for anchor-only entries such as Discovery). Every link has a visible
  `:focus-visible` outline from existing tokens; hit targets ≥ 44 × 44 px on narrow screens.

### 2.2 Overview (landing page)

Unchanged: attention-first counters, TLS health, recent jobs, renewals in flight, status strip (spec §8.2).
Changed by A1:

- **Setup checklist** replaces the empty-state checklist. It is shown while **any** step is incomplete:
  open (`<details open>`) when there is no certificate, collapsed otherwise with the summary
  `Setup: <done> of 6 steps done`. Hidden when all six are done. No dismiss button (nothing persisted).

  | # | Step | Done when | Action link |
  | --- | --- | --- | --- |
  | 1 | Import a certificate | ≥ 1 `certificate` row | `/certificates/import` |
  | 2 | Add the servers you deploy to | ≥ 1 active `server` row (any source) | `/inventory` *Add hosts*; secondary *or connect a Git repository (optional)* → `/settings?tab=inventory` |
  | 3 | Give the worker its SSH key | `credential_configured(db, SSH_PRIVATE_KEY)` or the live worker reports a mounted key file | `/settings?tab=worker` |
  | 4 | Trust your servers' SSH host keys | live worker reports a mounted known_hosts file **or** ≥ 1 `ssh_host_key` row | `/ssh-keys` |
  | 5 | Configure SMTP for alerts | `smtp.host` setting non-empty | `/settings?tab=smtp` |
  | 6 | Run discovery | ≥ 1 `server` with `last_discovery_status = 'ok'` | `/servers#discovery-actions` |

  Each item shows `Done` (badge-ok) or `To do` (badge-info) as text, never colour alone. Steps 3 and 4 are
  separate so a configured key never hides missing host trust (UX-02). When no worker has reported, steps 3
  and 4 use only the database facts and say `Worker not reporting` next to the badge.
- **Status strip** "Inventory" cell: `<n> active hosts (<m> manual, <k> repository)`, then the repository
  revision as today when one exists, else `No repository (optional)`.

### 2.3 Administration hub (`/administration`)

The settings hub. One page that answers "what is configured, what is missing, where do I change it". Every
entry is a link plus a one-line status computed server-side (no async loading). Groups and entries:

| Group | Entry → link | Status line |
| --- | --- | --- |
| People and access | Users → `/users` | `<n> active users` · `<k> inactive` |
| | My account → `/account` | `Two-factor authentication on/off` for the signed-in user |
| Servers and access | Inventory hosts → `/inventory` | `<n> active hosts (<m> manual, <k> repository)` or `No hosts yet` |
| | Inventory repository (optional) → `/settings?tab=inventory` | `Not configured — optional` or `<redacted URL> @ <ref>` (existing redaction; never the token) |
| | Worker credentials → `/settings?tab=worker` | `SSH key: configured (<type>, <fingerprint>) / missing`; vault password and Git token `set/not set` (booleans from `credential_states`, never values) |
| | SSH host keys → `/ssh-keys` | `<n> trusted in the dashboard` · `Mounted known_hosts: present/absent/unknown` |
| Alerts and email | SMTP → `/settings?tab=smtp`; Alerts → `/settings?tab=alerts` | `Configured`/`Not configured`; alert thresholds summary |
| Operations policy | Deployment, Schedule and scans, Trust anchors → their tabs | one line each from existing settings read models |
| System | Status → `/settings?tab=status` (`<n> warnings`), System and maintenance → `/settings?tab=maintenance`, Audit → `/audit`, Branding → `/settings?tab=branding` (**added by A2b**: `Default logo`/`Custom logo`) | |

The Settings tabs stay the place where values are edited; the hub never duplicates a form. The Settings
section `Inventory` is relabelled **`Inventory repository`** with the help line
*Optional. You can also add hosts directly in Infrastructure → Inventory.* (tab key `inventory` and its
POST routes unchanged).

### 2.4 Where each management task lives

| Task | Screen | Route(s) | Slice |
| --- | --- | --- | --- |
| Add / edit / deactivate / reactivate / delete a host | Infrastructure → Inventory | `/inventory`, `/inventory/{id}/…` | B INV |
| Connect an optional Git repository, Test pull | Administration → Settings → Inventory repository | `/settings?tab=inventory`, `/settings/inventory/test-pull` | existing; A1 relabels |
| Import hosts from the repository | Infrastructure → Inventory → *Import from repository* | `POST /inventory/import` | B INV |
| Worker SSH client key, vault password, Git token | Administration → Settings → Worker | `/settings?tab=worker`, `/settings/worker/{slug}` | existing (PR #87) |
| Trust server host keys | Infrastructure → SSH keys | `/ssh-keys`, `/ssh-keys/host-keys…` | B SSH |
| Create / edit / deactivate / reactivate users, reset password or 2FA | Administration → Users → user page | `/users`, `/users/{id}…` | B USR |
| Replace / reset the logo | Administration → Settings → Branding | `/settings?tab=branding`, `/settings/branding/…` | A2b |

## 3. Source model — manual first, Git optional

Decided in `slice-b-contract.md` D1 and implemented by W; restated here at implementation level so Slice A
copy and status lines agree with it.

- **Host sources.** `server.inventory_source` is `manual` (created on `/inventory`) or
  `<ref>:<path>@<sha>` (listed by the configured Git inventory). There is no third source and no per-host
  repository link.
- **"GitHub" = any Git repository.** `inventory.repo_url` accepts the existing `https://`, `ssh://` and
  scp-like URLs; GitHub, GitLab, Gitea or a plain server are equal. The dashboard has no GitHub API,
  OAuth, app installation or repository browser, and **no route redirects outside the dashboard**.
- **Optional.** With `inventory.repo_url` empty every screen works: Inventory, Servers, Bindings,
  discovery and deploy run on manual hosts (W). Only "Test pull" and "Import from repository" need a
  repository and are disabled with a reason without one.
- **Union and precedence.** Each discover/deploy job uses repository hosts ∪ active manual hosts not listed
  by the repository. Git is authoritative for every hostname it lists: a manual row with the same name is
  adopted (id, bindings, history, display name, notes kept). A manual row is never deactivated for being
  absent from Git. Repository rows are read-only on `/inventory` except display name and notes.
- **Connection.** Manual hosts use `inventory.manual_ssh_user` / `inventory.manual_ssh_port` (global).
  Every job uses the worker key from Settings → Worker and known_hosts = mounted file ∪ dashboard-trusted
  host keys.
- **Capability matrix (what the UI must say).**

  | Repository | Manual hosts | Discovery/deploy | Test pull | Import from repository | No-inventory sentence |
  | --- | --- | --- | --- | --- | --- |
  | none | none | disabled | disabled | disabled | `No inventory: add a host in Inventory or configure a repository.` |
  | none | ≥ 1 | enabled | disabled | disabled | — |
  | set | any | enabled | enabled | enabled | — |

  (Discovery/deploy additionally need the worker SSH key and host trust; those reasons come from
  `ansible_unavailable_reason` and are shown first.)

## 4. Slices, cards and ownership

### 4.1 Cards

| Slice | Card | Scope | Runs |
| --- | --- | --- | --- |
| A1 | `t_8439d40d` | shell, navigation, Overview checklist, Administration hub, settings narrow layout, `/servers` empty states, global HTMX error parity, default branding in the shell | after this spec merges |
| A2a | `t_e8c0f619` | branding storage: migration `0004_branding`, image validation, public `/branding/logo`, draft cleanup | after A1 |
| A2b | `t_860fb51c` | Settings → Branding UI: preview/save/discard/reset, shell and sign-in resolver, hub entry | after A2a |
| A3 | `t_6fab5610` | endpoint deactivation confirmation (UX-09) | after A2b |
| B (F, W, USR, SSH) | `t_ccb6f82e`, `t_d94e4b93`, `t_ffd019cc`, `t_ba115a93` | `slice-b-contract.md` | merged |
| B INV | `t_c95126de` | `slice-b-contract.md` §4 | PR #96, parallel to A |
| B-W2 | `t_214beeb1` | HTTPS test pull without known_hosts; job error text and allowlist (§8.2) | after this spec, parallel to A |
| B R | `t_9ab63e2d` | Slice B review/smoke, closes PR #92 | after INV |
| Docs | `t_4c8f8378` | README/docs/screenshots after all of the above | last |

Slice A cards run strictly in the order A1 → A2a → A2b → A3 (each card's parent is the previous one):
they share `base.html.j2`, `app/main.py`, `app/web/settings.py` and the generated previews. Slice B cards
in flight (INV, W2) own disjoint files and run in parallel with Slice A.

### 4.2 File and route ownership

A card may modify only files listed for its slice. A needed change in a file owned by another slice is a
`hotspot: <path> — <reason>` comment on the card, not an edit.

| Owner | Files | Routes |
| --- | --- | --- |
| **Slice A** (A1, A2a, A2b, A3 in order) | `app/templates/base.html.j2`, `_navigation.html.j2`, `_ui.html.j2`, `_inventory_ui.html.j2` (certificate UI; only to drop its `htmx-config` meta), `overview.html.j2`, `administration.html.j2`, `settings.html.j2`, `app/templates/settings/*`, `login.html.j2`, `login_2fa.html.j2`, `error.html.j2`, `app/templates/servers/*`, `app/templates/scans/detail.html.j2` (A3); `app/static/app.css`, `app/static/pages/{overview,settings,servers,scans,branding,administration}.css`; `app/static/branding/*` (read-only use); `app/web/overview.py`, `app/web/administration.py` (new, A1), `app/web/settings.py`, `app/web/servers.py`, `app/web/branding.py` (new, A2a/A2b), `app/web/scans.py` (A3, deactivate route only); `app/services/setup_status.py` (new, A1), `app/services/branding.py` + `app/services/branding_image.py` (new, A2a), `app/models/branding.py` (new, A2a), `app/models/__init__.py` (A2a, one import), `app/migrations/versions/0004_branding.py` (new, A2a), `app/jobs/handlers/cleanup.py` (A2a, one purge call); `app/main.py` (`app.state.navigation`, `public_paths`, route registration lines, template globals only); `scripts/render_previews.py`, `docs/ui/previews/*`, `tests/test_*previews.py`, `tests/unit/test_ui_foundation.py`, `tests/unit/test_page_styles.py`, `tests/unit/test_settings_sections.py`, `tests/unit/test_administration.py`; `tests/integration/test_schema.py` (A2a: new tables only); existing tests extended by §5.8/§7: `tests/integration/test_servers_http.py`, `test_discovery_screens.py`, `test_settings_http.py`, `test_sessions_http.py` and the HTTP test that owns `POST /scans/{id}/active` (`test_scans_http.py` or `test_endpoints_http.py`, A3); new Slice A test files named in §5–§7 | `/`, `/administration`, `/settings…` (all tabs incl. new `branding`), `/servers…`, `/bindings…`, `/branding/logo`, `/settings/branding/…`, `POST /scans/{id}/active` (A3) |
| **Slice B** (INV, W2, R) | everything `slice-b-contract.md` §2 assigns to INV/W/USR/SSH; for W2: `app/jobs/handlers/ansible_context.py`, `app/jobs/handlers/test_pull.py`, `app/services/deploy_views.py` (`JOB_FAILURE_REASONS` only), `tests/unit/test_known_hosts_render.py`, `tests/integration/test_test_pull.py`, `tests/integration/test_manual_inventory_jobs.py`, `tests/integration/test_deploy_job_http.py` | `/inventory…`, `/ssh-keys…`, `/users`, `/users/{id}…` |

Boundary clarifications:

- `app/web/users.py` is Slice B's. A1 **moves** the `GET /administration` handler out of it into
  `app/web/administration.py` (the only A edit to that file: deleting the handler and nothing else).
- `app/web/management.py` / `_management_ui.html.j2` are Slice B's. A1 does not edit them; their
  per-page `htmx-config` meta becomes redundant once the global one comes first in `<head>` (§5.5). Removing
  it is a later cleanup, not part of either slice.
- `app/web/common.py` keeps W's functions and constants; Slice A reads `NO_SSH_KEY`, `NO_KNOWN_HOSTS`,
  `NO_INVENTORY`, `ansible_unavailable_reason` and does not edit them.
- Previews: only Slice A regenerates `docs/ui/previews/*` (A1's navigation change touches every preview).
  INV and W2 add no preview.
- Navigation entries for `/inventory`, `/ssh-keys` and `/users` are Slice A's from now on (F's one-time
  edit is done); Slice B never edits `_navigation.html.j2`.

## 5. Slice A1 — shell, navigation, hub, empty states, HTMX error parity

**Routes:** no new route. Changed GET pages: `/`, `/administration`, `/settings`, `/servers`. All pages get
the new shell. Every response stays server-rendered HTML; no new JavaScript file, no new dependency, no
inline style or script (proxy CSP `script-src 'self'; style-src 'self'; img-src 'self'`).

### 5.1 Overview setup checklist

`app/services/setup_status.py`: `SetupStatus` frozen dataclass (`certificates: bool`, `hosts: bool`,
`host_counts: tuple[int, int, int]` = active total/manual/repository, `ssh_key: bool`, `host_trust: bool`,
`worker_reporting: bool`, `smtp: bool`, `discovered: bool`, `done: int`) and
`setup_status(db, now) -> SetupStatus` using only existing read models (`credential_configured`,
`worker_capabilities`, `has_trusted_host_keys`, `get_setting`) and count queries. Constant query count
(≤ 8 statements, asserted with the existing `count_statements` helper). Overview and the hub both use it.

States: no certificate → checklist open; certificates but incomplete → collapsed with counter; complete →
absent. Error: a database error renders the styled 500 page (existing). Loading: none (full page).

### 5.2 Administration hub

`app/web/administration.py` registers `GET /administration` (moved, §4.2) and renders §2.3 from
`setup_status`, `credential_states`, `worker_capabilities`, user counts and the existing settings read
models. Empty states: no hosts → `No hosts yet` + *Add a host* link; no repository → `Not configured —
optional`; no worker reporting → `Unknown (no worker has reported recently)` for worker-reported facts.
The page has no form.

### 5.3 Settings on narrow screens (UX-04)

- The section links render twice, like the shell navigation: the existing list (desktop) and a
  `<details class="settings-sections">` whose summary reads `Section: <current label>` (narrow only; CSS
  shows exactly one of the two per breakpoint).
- The draft guidance becomes one sentence — *Save each section explicitly; unsaved changes may be lost
  when you switch sections.* — followed by `<details>` **How drafts work** containing the current full text
  verbatim.
- Label `Inventory` → `Inventory repository` + the optional help line (§2.3). The status warning
  `inventory_not_configured` label and `_NO_INVENTORY` in `app/web/settings.py` use the `NO_INVENTORY`
  sentence (§3), resolving W's hotspot.
- `settings.js` keeps working: its selectors must still find the section links (`data-settings-tab-draft`
  markers stay on the desktop list).

### 5.4 Servers empty states and capability banners (UX-07, UX-02)

`/servers` distinguishes:

| State | Condition | Content |
| --- | --- | --- |
| Never configured | no `server` row at all and no filter in the query | `No servers yet` · *Servers are the hosts in your inventory. Add hosts in Inventory, or connect an optional Git repository and import them.* · actions *Add hosts* → `/inventory`, *Connect a repository (optional)* → `/settings?tab=inventory` |
| Filtered empty | any filter/search parameter set and no match | `No servers match these filters` · *Clear filters* → `/servers` |
| Hosts but never discovered | rows exist | the table (existing), rows show `Never discovered` |

The discovery panel keeps its disabled-with-reason behaviour. In `base.html.j2` the capability banner link
follows the reason: `NO_SSH_KEY` → `/settings?tab=worker` (existing), `NO_KNOWN_HOSTS` → *Trust host keys
in Infrastructure → SSH keys.* (`/ssh-keys`), any other → `/settings?tab=status`.

### 5.5 Global HTMX error parity (UX-08)

- `base.html.j2` emits **one** `<meta name="htmx-config">` as the **first** element after
  `<meta name="viewport">` (before any stylesheet and before `{% block extra_css %}`), so htmx (which
  reads the first such meta) uses it on every page.
- Content: the `responseHandling` list from `app/web/management.py` `_HTMX_CONFIG` (imported, not copied —
  exposed to templates by `app/web/administration.py` or `app/main.py` as a global), extended with the same
  `#main-content` rule for `404`, `500` and `503`:
  `204` no swap; `[23]..` swap; `422` swap; `403`/`404`/`500`/`503` swap with `target` and `select`
  `#main-content`, `swapOverride: outerHTML`, `error: true`; any other `[45]..` no swap.
- `_inventory_ui.html.j2` `enhanced_forms()` stops emitting its own meta (certificate/import/renewal pages
  then use the global one; their 422 behaviour is unchanged because both configs swap 422).
- `error.html.j2` keeps `role="alert"` on the error section and gains `tabindex="-1"` + `autofocus` on its
  `<h1>` only when rendered for an htmx request (`HX-Request: true`), so the swapped message is announced
  and focused. CSRF semantics are unchanged: the request is still refused with 403 and nothing is stored.
- Session expiry keeps spec §9.8 (`401` + `HX-Redirect: /login`).

### 5.6 Default branding in the shell (UX-05, static part)

Per `docs/ui/branding.md` "Placement and accessibility", with the merged assets only (no database):
header lockup in `<picture>` (`lockup-light.svg` for `prefers-color-scheme: light`, `lockup.svg` fallback),
link `/` with accessible name `Cert Dashboard home`, reserved 202 × 24 slot; mark-only (`mark*.svg`, 24 ×
24) when the narrow layout is active; favicon links (`favicon.svg`, then `favicon-32.png` 32 × 32);
decorative 48 × 48 mark before the `Sign in` heading on `/login` and `/login/2fa`. Templates reference a
template global `brand` (A1: always the default URLs) so A2b swaps the source without touching markup.

### 5.7 HTMX expectations (A1)

A1 adds no htmx form. Existing htmx forms keep their targets. Loading feedback for existing htmx forms is
unchanged; A1 must not add `hx-boost` to the shell. Full-page navigations everywhere else.

### 5.8 A1 acceptance criteria

- [ ] Navigation matches §2.1 for every listed path: main entry `aria-current="location"`, exactly one area
      page `aria-current="page"`, Infrastructure links to `/inventory`, Administration area lists the hub
      first; narrow menu lists every page (extend `tests/test_navigation_queue_previews.py`).
- [ ] `/inventory`, `/ssh-keys`, `/users`, `/settings` and `/administration` are reachable
      from both desktop and narrow navigation (preview test).
- [ ] Capability-disabled navigation entries still render `aria-disabled` with their reason (existing test
      stays green).
- [ ] `tests/integration/test_overview_setup_http.py`: each of the six steps flips from `To do` to `Done`
      when its fact is seeded; open when no certificate, collapsed with `Setup: n of 6 steps done` otherwise,
      absent when complete; steps 3 and 4 independent (key configured + no host trust → step 4 `To do`);
      statement count ≤ 8 for `setup_status`.
- [ ] `tests/integration/test_administration_hub_http.py`: every §2.3 entry links to its route; status lines
      for no hosts / no repository / no worker / configured states; the repository line never contains the
      Git token or URL credentials (write a `inventory.repo_url` with `user:secret@` directly into the test
      database, assert `secret` absent); signed-out GET
      → `/login`.
- [ ] Settings: section picker markup present with `Section: <label>`; `How drafts work` disclosure holds
      the previous text; label `Inventory repository` with the optional help; status warning uses the
      `NO_INVENTORY` sentence (`tests/unit/test_settings_sections.py`, `tests/integration/test_settings_http.py`
      existing assertions updated, not deleted).
- [ ] `/servers` never-configured vs filtered-empty states exactly as §5.4, both with no repository
      (`tests/integration/test_servers_http.py`); no response redirects off-site.
- [ ] Banner link per reason as §5.4 (`tests/integration/test_discovery_screens.py` extended).
- [ ] `tests/unit/test_htmx_config.py`: every full page rendered through `base.html.j2` has the global
      config as its first `htmx-config` meta; its 403 rule equals `management._HTMX_CONFIG`'s; 404/500/503
      rules target and select `#main-content`; `enhanced_forms()` emits no meta.
- [ ] HTMX CSRF refusal on a non-management page (e.g. `POST /scans/endpoints` with `HX-Request: true` and
      a corrupted token): 403, body contains `main#main-content` with `Your form expired. Reload the page and
      try again.` and an autofocused heading; no endpoint row created (`tests/integration/test_sessions_http.py`).
- [ ] Default branding: header lockup + accessible name, favicon links, sign-in mark with `alt=""`; no
      inline style; `tests/test_branding_assets.py` and preview tests green.
- [ ] Previews regenerated with `scripts/render_previews.py`; every preview test green.
- [ ] Regression criteria §9 hold.

## 6. Slice A2 — replaceable logo

`docs/ui/branding.md` is the normative contract (Settings → Branding state machine, endpoint table,
validation limits and safe SVG profile, persistence, serving, exact copy, verification checklist). This
section fixes only what that document leaves to implementation.

**Decisions.**

- **A2-D1 Migration `0004_branding` (additive).** Authorized by the owner request ("make the user replace
  it") and `branding.md` ("requires a migration in the implementation card"); precedent
  `slice-b-contract.md` D4. Tables:
  - `branding_asset` — singleton: `id smallint PK CHECK (id = 1)`, `mime text CHECK IN ('image/svg+xml',
    'image/png')`, `content bytea not null` (≤ 262144, CHECK on `octet_length`), `width int`, `height int`,
    `sha256 text not null` (the revision), `display_filename text not null` (≤ 120), `updated_at timestamptz
    not null`, `updated_by bigint null FK user(id)`. No row = default logo.
  - `branding_draft` — `token_sha256 text PK` (SHA-256 of the random 256-bit token; the token itself is
    never stored), `session_id char(64) not null FK user_session(id) ON DELETE CASCADE`, `content bytea
    null` (NULL once consumed or discarded), `mime`, `width`, `height`, `sha256`, `byte_size`,
    `display_filename`, `base_revision text not null` (`default` when no asset), `created_at`,
    `expires_at` (= created + 30 min), `consumed_at timestamptz null` (the save receipt), partial unique
    index: one unconsumed draft per session.
  - Grants: `SELECT, INSERT, UPDATE, DELETE` on both to `app_role`. A draft is valid only while its session
    is not revoked and not expired.
- **A2-D2 No new dependency.** PNG: a standard-library canonicalizer (`zlib`, `struct`) — parse chunks,
  require IHDR first, CRCs valid, non-interlaced, bit depth 8, colour types 0/2/3/4/6, PLTE when type 3,
  refuse `acTL` (APNG); inflate IDAT with `zlib.decompressobj().decompress(data, max_length=expected + 1)`
  where `expected = height × (1 + rowbytes)` and refuse anything but exactly `expected` bytes with filter
  bytes 0–4 (bomb, truncation and trailing data refused). Re-emit **only** IHDR, PLTE, tRNS, one fresh
  IDAT (re-deflated scanlines) and IEND. This drops every metadata/trailing byte, which is the purpose of
  `branding.md`'s "re-encode as RGBA" while keeping the original colour type; other PNG variants (16-bit,
  interlaced) get `This image could not be read. Export it again as SVG or PNG.` SVG: `xml.parsers.expat`
  with handlers that raise on DOCTYPE, entity declarations, processing instructions and external entity
  refs; then the `branding.md` allowlist; serialize a fresh tree. Never use `scripts/render_branding.py`'s
  rasterizer on uploads.
- **A2-D3 Request bound.** Refuse `Content-Length` > 327680 with 413 before parsing; without a length,
  count streamed bytes and stop at 327681. File ≤ 262144 bytes.
- **A2-D4 Authorization.** Same as every settings page (signed-in, fully authorized session; forced
  password change and MFA gates apply). `/branding/logo` is the only new public path
  (`app.state.public_paths`), exact match.
- **A2-D5 Settings tab.** `branding` added to `_TAB_LABELS`/`_SECTION_LABELS` as a non-field tab (like
  `worker`, `trust`); its POST routes are registered before `/settings/{tab}`; it is not a settings-draft
  form (`settings.js` must ignore it: no `data-settings-draft`).
- **A2-D6 Cleanup.** `purge_branding_drafts(db, now)` deletes expired drafts and receipts older than 30
  minutes; called on every branding request and by the existing daily cleanup handler.

**A2a — storage, validation, serving** (`app/models/branding.py`, `0004_branding.py`,
`app/services/branding_image.py` pure validators, `app/services/branding.py` stage/save/discard/reset/
current/purge with `base_revision` compare-and-set, `GET /branding/logo`, cleanup hook). Acceptance:

- [ ] Migration upgrades a `0003` database; `alembic check` clean; `test_schema.py` asserts both tables,
      CHECKs, FK cascade and grants.
- [ ] `tests/unit/test_branding_image.py`: every `branding.md` validation case — size limit and limit + 1,
      MIME/extension mismatch, corrupt/truncated PNG, CRC error, APNG, interlaced/16-bit, decompression bomb
      (expected size exceeded), trailing data removed from output, dimensions 0/1/2048/2049, pixel cap,
      aspect 0.5/6 bounds; SVG: script, event attribute, `foreignObject`, `style` element/attribute,
      `href`, `url(` paint, data URL, entity/DOCTYPE, PI, unknown namespace, text, filter, animation, depth
      17, 513 elements, path-command cap, `currentColor`, out-of-range numbers; accepted output re-parses
      and contains only allowlisted names.
- [ ] Service tests (integration): stage/save/discard/reset; second preview replaces the draft; invalid
      preview clears it; 409 on revision mismatch (save and reset); 410 on expired draft; cross-session
      draft read → not found; revoked session → draft unusable; 16 MiB pending cap → 503; double save →
      one asset row, one audit row; audit details never contain bytes or filename.
- [ ] `/branding/logo`: no asset → 307 to `/static/branding/mark.svg`; asset → exact bytes, constant
      `Content-Type`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
      `Content-Disposition: inline; filename="logo.svg|png"`, SVG CSP header; works signed out; corrupt
      stored row → default, no error text.

**A2b — Settings → Branding UI and shell integration** (`app/web/branding.py` settings routes,
`app/templates/settings/_branding.html.j2`, `app/static/pages/branding.css`, `settings.html.j2`,
`app/web/settings.py` tab entry, shell/login `brand` resolver, hub entry). Screens and states exactly as
`branding.md` §"State machine": Default, Custom saved, Preview (incl. invalid preview), Save success,
Discard, Reset confirmation, 409 conflict, 410 expired, 413/422/503 errors; native multipart forms only (no
`hx-*` on these forms; full-page PRG after save/reset). Acceptance:

- [ ] `tests/integration/test_branding_http.py`: default → valid SVG preview (shell unchanged on the next
      GET of `/`) → save (header and `/login` show `/branding/logo?v=<sha256>`) → reset (default lockup
      back); PNG path; discard; re-preview; every error row of `branding.md` "Exact error and status copy"
      with its status code and `Your current logo has not changed.`; error summary `role="alert"` with
      autofocus and `aria-invalid`/`aria-describedby` on `logo`; CSRF refusal before any image parsing
      (assert the validator is not called); forced-password-change user cannot reach the routes.
- [ ] The favicon and the visible product name stay the defaults after a custom save.
- [ ] Hub shows `Branding: Default logo` / `Custom logo`; previews for the Branding tab states regenerated.
- [ ] Regression criteria §9 hold.

## 7. Slice A3 — endpoint deactivation confirmation (UX-09)

`app/templates/scans/detail.html.j2` + `app/web/scans.py` (`POST /scans/{endpoint_id}/active` only).

- Deactivate (`active=false`) renders a native `<details class="confirmation">` disclosure: summary
  `Deactivate monitoring…`, consequence *Scheduled scans of this endpoint stop. Its history is kept and you
  can activate it again.*, submit `Deactivate <host>:<port>` posting `confirm=1`, cancel = closing the
  disclosure. Activate (`active=true`) stays a single button (not destructive).
- Server: `active=false` without `confirm=1` → 422 with `Confirm the action to continue.` rendered in the
  existing `errors.active` slot; nothing changes, no audit row. With `confirm=1` → unchanged behaviour.
- HTMX: keeps `hx-post`/`hx-target="#manage-panel"`/`outerHTML`; the submit button carries
  `hx-disabled-elt="this"` while the request runs (loading state); 422 swaps the panel (global config, §5.5).
- Acceptance: native and htmx deactivation with and without `confirm` (`tests/integration/test_scans_http.py`
  or `test_endpoints_http.py`, whichever owns the route today); activation unchanged; scan history retained;
  preview for the scan detail regenerated.

## 8. Slice B

### 8.1 Contracted and merged

`docs/slice-b-contract.md` is complete and normative: decisions D1–D6, ownership §2, fields §3, routes and
states §4–§6, worker rules §7, conventions C1–C10 §8, acceptance §9, smoke script §9 R. Summary of the
screens it delivers, for orientation only:

| Screen | Route | States | HTMX |
| --- | --- | --- | --- |
| Inventory | `GET/POST /inventory`, `/inventory/{id}/edit|deactivate|activate|delete`, `/inventory/connection`, `/inventory/import` | empty (`No hosts yet` + *Add a host* / *Import from repository* or *Configure a repository (optional)*), filtered empty, 422 inline (row-targeted), 409 import without capability, flash success | `hx-post` + panel `hx-select`, success `200 + HX-Redirect` |
| SSH keys | `GET /ssh-keys`, `POST /ssh-keys/host-keys`, `/ssh-keys/host-keys/{id}/delete` | empty (`No host keys trusted…` + open form), 422 all-or-nothing with `Line n:` errors, private key refused and not echoed, confirmation, flash | same |
| Users | `GET/POST /users`, `GET /users/{id}`, `/users/{id}/edit|deactivate|reactivate|reset-password|reset-totp` | only-user empty state, 422/423 inline, inactive/locked/must-change badges, flash | native (htmx optional) |

### 8.2 B-W2 — finish host-trust onboarding (UX-02 remainder)

Files: `app/jobs/handlers/ansible_context.py`, `app/jobs/handlers/test_pull.py`,
`app/services/deploy_views.py` (`JOB_FAILURE_REASONS` only), and the tests named in §4.2.

- "Test pull" with an `https://` repository URL (case-insensitive scheme) does **not** require
  known_hosts: the job stages an empty known_hosts file when neither the mounted file nor a trusted key
  exists. `ssh://` and scp-like URLs, and every discover/deploy job, keep requiring it (fail closed).
  `StrictHostKeyChecking=yes` and every other runner setting are unchanged.
- The failure text `SSH known_hosts file is missing` becomes
  `no trusted SSH host keys: trust them in Infrastructure → SSH keys or mount a known_hosts file`
  (job error, Settings test-pull result). `JOB_FAILURE_REASONS` gains it **and keeps** the old text so
  existing job rows still render; it also gains the `NO_INVENTORY` sentence (W hotspot).
- Acceptance: CI has no HTTPS Git server, so prove the rule at the job-context layer:
  `ansible_job(..., require_repository=True)` with an `https://` config, no mounted file and no rows does
  not raise and stages an empty known_hosts file (unit or integration test); same with `ssh://` raises
  `config_invalid` with the new text; discover with no trust raises the new text; deploy screen renders
  both the new and the old text and the `NO_INVENTORY` sentence (`test_deploy_job_http.py`); existing
  `test_test_pull.py` and `test_manual_inventory_jobs.py` stay green.

Out of scope for W2: dropping the SSH-key requirement for test pull (claim capability, Plan 3 Contract
decision 22) and fetching host keys from targets.

## 9. Regression criteria (every Slice A and B card)

Each is proved by the named existing suites staying green in the required `verify` check, plus the manual
script §10.

- [ ] Certificates: upload/paste/pull import, list filters, detail, metadata edit, downloads/PFX, renewal
      wizard (`test_upload_import.py`, `test_pull_import.py`, `test_certificates.py`, `test_downloads.py`,
      `test_renewal_wizard.py`, `test_renewal_list_http.py`).
- [ ] Git repository ("GitHub") flow: save `inventory.repo_url`/ref/path, Test pull enqueue and result,
      discovery from a repository, adoption of a manual host by Git (`test_settings_http.py`,
      `test_test_pull.py`, `test_inventory_http.py`, `test_discovery_jobs.py`, `test_manual_inventory_jobs.py`).
- [ ] Discovery/deploy screens and jobs (`test_discovery_screens.py`, `test_servers_http.py`,
      `test_bindings_http.py`, `test_deploy_start_http.py`, `test_deploy_job_http.py`).
- [ ] Scans/endpoints (`test_scans_http.py`, `test_endpoints_http.py`), users (`test_users_http.py`,
      `test_users_detail_http.py`), SSH keys (`test_ssh_keys_http.py`), sessions/CSRF/errors
      (`test_sessions_http.py`, `test_login_account.py`), worker settings (`test_worker_credentials_db.py`).
- [ ] Every URL that existed on `4d553a3` still answers with the same method and status for a signed-in
      admin (no route removed or renamed); `/administration` keeps its URL.
- [ ] No response redirects outside the dashboard origin.
- [ ] Every form still works with JavaScript disabled.

## 10. Manual test script (reviewer, human steps)

Use a disposable stack or the certlab staging stack with the operator's approval. Desktop 1440 × 900 and
narrow 390 × 844 (browser device emulation). Record screenshots of each numbered result in the PR.

**Setup and regression baseline (all cards)**

1. Sign in. Note that the header shows the Cert Dashboard lockup (after A1) and the browser tab shows the
   favicon.
2. Certificates → Import: upload a test leaf and chain; open its detail page; edit Owner; reload — the
   owner persists. Certificates list filters still work.
3. Administration → Settings → Inventory repository: save a repository URL, click Test pull, wait for the
   result; then clear the URL again. The dashboard never navigates to GitHub.

**Slice A1**

4. Navigation (desktop): visit Overview, each main entry and every area page of §2.1. The current entry
   and page are highlighted; Infrastructure opens Inventory; Administration opens the hub.
5. Navigation (narrow): open `Menu`, reach Inventory, SSH keys, Users, Settings and the hub; Tab through
   the menu and see a visible focus outline on every link; no horizontal page scroll.
6. Overview on an installation missing some setup: the checklist shows `Setup: n of 6 steps done`; with a
   worker key configured but no known_hosts/trusted key, step 4 is `To do` and links to SSH keys.
7. Administration hub: every entry opens its page; repository line shows `Not configured — optional`
   when cleared in step 3; no secret is visible.
8. Narrow Settings → Inventory repository: the section picker reads `Section: Inventory repository`; the
   repository URL field is visible without scrolling when at most one banner is shown.
9. Servers with no hosts: `No servers yet` with *Add hosts* and *Connect a repository (optional)*; add a
   filter → `No servers match these filters` + *Clear filters*.
10. UX-08: on Scans → Add endpoint, use the browser dev tools to change the hidden `csrf_token` value, then
    submit. The main area is replaced by `Your form expired. Reload the page and try again.` (focus on the
    heading); repeat with JavaScript disabled — same text. No endpoint was created.

**Slice A2 (after A2b)**

11. Administration → Settings → Branding: default state, no Reset button. Choose a valid SVG → Preview
    logo: the header is unchanged; previews on dark and light appear. Save logo: header and `/login` (open a
    private window) show it; the favicon and the name "Cert Dashboard" are unchanged.
12. Preview a PNG, then Discard preview: current logo unchanged.
13. Try an SVG with `<script>`, a 300 KiB file and a `.png` that is really a JPEG: each shows its exact
    error and `Your current logo has not changed.`
14. Reset to default…: confirm; the default lockup is back everywhere. Repeat 11–14 at 390 × 844.

**Slice A3**

15. Scans → an audit-only endpoint → Manage → Deactivate monitoring…: the confirmation explains the
    consequence; cancel leaves it active; confirm deactivates it and its history is still listed; Activate
    is immediate.

**Slice B (also `slice-b-contract.md` §9 R) and B-W2**

16. With the repository URL empty: Infrastructure → Inventory → add `web01.example.test`, edit it, try the
    invalid hostname `-bad` (inline error on that row), deactivate, reactivate, delete with confirmation.
17. Infrastructure → SSH keys: compare the fingerprint of the lab host key on its console with
    `ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -`; only if equal, paste the line with the verification
    box ticked; a pasted private key is refused and the textarea comes back empty.
18. Administration → Users → add a user, open it, deactivate and reactivate it; sign in as that user and
    meet the change-password gate.
19. B-W2: with no mounted known_hosts and no trusted key, save an `https://` repository URL and Test pull:
    the job no longer fails on known_hosts (it fails or succeeds on the fetch itself). With an `ssh://`
    URL it fails with `no trusted SSH host keys: trust them in Infrastructure → SSH keys or mount a
    known_hosts file`. Restore the original URL.

## 11. Out of scope

GitHub OAuth, GitHub App or repository browser; creating or editing repository content from the
dashboard; per-host repository links; roles/RBAC, user rename, hard user delete; multiple named worker
client keys or per-host credentials; per-host SSH user/port; fetching host keys from targets
(trust-on-first-use is refused by design); showing the worker public key for `authorized_keys`; changing
the SMTP password in the UI; bootstrap of the first administrator and master-key custody in the UI;
replacing the favicon or the product name with uploads (`branding.md`); removing the now-redundant
per-page `htmx-config` metas of Slice B pages; extending the private-key discard of the SSH form to the
`hosts`/`comment` fields (follow-up hardening noted at PR #95 review); a physical-device, screen-reader or
full WCAG audit.

## 12. Decision log (this document)

| Id | Decision | Why |
| --- | --- | --- |
| N1–N6 | IA in §2.1 (Overview name kept, Infrastructure → Inventory, hub as Administration's first page) | Smallest change to the merged grouped navigation that makes inventory, SSH keys and users first-class |
| S1 | Slice A split into A1/A2a/A2b/A3, strictly chained | Each part stays a reviewable PR; they share shell, settings and previews |
| S2 | B-W2 created for the HTTPS test-pull and job-text remainder of UX-02 | Worker files are Slice B's; disjoint from Slice A so it runs in parallel |
| H1 | One global `htmx-config` first in `<head>`, sourced from `management._HTMX_CONFIG` | htmx reads only the first meta; reusing the merged config keeps one rule set and needs no Slice B edit |
| A2-D1…D6 | §6 | Fill implementation gaps `branding.md` left open without new dependencies |
