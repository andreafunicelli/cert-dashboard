# Slice B implementation contract — inventory, users and SSH keys in the dashboard

Status: **normative** for the Slice B cards. Where this document and the design spec
(`docs/superpowers/specs/2026-10-19-cert-dashboard-design.md`) differ, this document wins for the
items it names, and the spec carries a pointer here (§6.1, §4.7, §4.19, §8.6, §8.10, §9.3).
Everything this document does not mention keeps the spec, Plan 1–3 Global Constraints and
Contract decisions unchanged.

Owner request: card `t_198538ae` — *"make the user manage the inventory, the users, the ssh keys
everything inside the dashboard. The user should only manage the dashboard, not external github
repos, maintain the possibility to use github repos but not only those."* Evidence of the gaps:
`docs/ux-audit.md` (PR #90) findings UX-01, UX-02, UX-03, UX-06, UX-07.

Cards (cite them by these letters in PRs and comments):

| Letter | Card | Runs |
| --- | --- | --- |
| F | `t_ccb6f82e` foundation: schema, shared UI conventions, page skeletons, navigation entries, docs rows | first, alone |
| W | `t_d94e4b93` worker integration: manual hosts and trusted host keys reach discover/deploy | after F, in parallel with INV/USR/SSH |
| INV | `t_c95126de` inventory management (`/inventory`) | after F, parallel |
| USR | `t_ffd019cc` users management (`/users`) | after F, parallel |
| SSH | `t_ba115a93` SSH keys (`/ssh-keys`) | after F, parallel |
| R | `t_9ab63e2d` review, smoke, merge | after W, INV, USR, SSH |

R merges in this order: F → W → INV, USR, SSH (any order). `main` therefore never advertises a
manual host that the worker cannot use.

PR #92 (`wt/t_6ef753d3`, head `c0cf32b`) is superseded by these cards. Its code may be reused where it
matches this contract (notably hostname/group validation in `app/services/inventory_entries.py`, the
row-targeted edit error re-render, the HX-Redirect success path and the private-key echo guard). R closes
PR #92 once INV and SSH are merged.

---

## 1. Decisions

**D1 — Inventory has two sources; Git is optional.** A host is either *manual* (created in the
dashboard, `server.inventory_source = 'manual'`) or *repository* (listed by the configured Git
inventory, `inventory_source = '<ref>:<path>@<sha>'`, unchanged). Manual hosts are first-class: W makes
discover and deploy run against them with no repository configured. No new column: the existing text
column carries the marker. Rationale: owner request above; the reviewer's escalation on PR #92 asked
exactly whether manual hosts must be usable by the worker — yes, otherwise the user still has to manage
a Git repository.

- Git stays authoritative for every hostname it lists. A repository listing that contains a manual
  hostname adopts that row on the next discovery (source becomes the revision; id, bindings, history,
  `display_name` and `notes` are kept; audited `server.update`).
- Reconciliation never deactivates a manual row for being absent from Git.
- "GitHub" in the requests means *any* Git repository configured in Settings → Inventory
  (`inventory.repo_url`). Slice B adds no GitHub API, OAuth or per-entry repository link: a per-row link
  would be a new column with no consumer. The optional repository appears in the Inventory page as a
  source status panel, a "Configure repository" link and an "Import from repository" action (§4).

**D2 — "SSH keys" means the worker's client key plus trusted host keys.** The worker's private key is
already managed in Settings → Worker (`encrypted_setting`, PR #87) and is not duplicated. The missing
capability (UX-02, P1) is host trust: today `known_hosts` is a mounted file only. Slice B adds a
dashboard trust store of **host public keys** (`ssh_host_key` table, §3.3). Keys are trusted only by
explicit administrator entry; nothing is ever auto-accepted and `ANSIBLE_HOST_KEY_CHECKING=True` stays.
Effective trust per job = mounted file ∪ table rows. Deleting a table row removes only that row's
trust: the dashboard never edits or overwrites the mounted file, so a key the mounted file also lists
stays trusted, and other trusted key types for the same host still apply. Administrators verify every
fingerprint against the server through an independent channel before adding it (§6, rule 10):
`ssh-keyscan` output is unauthenticated. A pasted public key with no host is meaningless for SSH and is not
accepted (the PR #92 "labelled public key registry" had no consumer and is dropped).

**D3 — Users: no roles, no hard delete; reactivation added.** Spec §2.2 (every user is an admin) and
§9.3 (deleting users = deactivation only) stand; the owner request does not ask for roles. UX-06 asks for
a decided recovery path: an administrator may **reactivate** an inactive user, which always issues a new
temporary password (`must_change_password = true`) and requires the acting administrator's current
password, like deactivation. "Invite" = create with a temporary password (there is no email invite:
spec §8.1, internal tool). UX-03 (P1): management moves to a full-width detail page `/users/{id}`.

**D4 — Schema change: one additive migration.** `0003_ssh_host_key` creates one table. Nothing existing
changes (no column, enum value or constraint is altered). Plans 2–3 "no new migration" constraints bound
those plans' tasks; post-plan owner-requested features already use additive migrations (`0002`, merged in
68fd7bc). Two new settings keys need no migration (`app_setting` defaults live in code).

**D5 — Delete vs deactivate for hosts.** A manual host with no dependent rows (bindings, endpoints,
job hosts, scan results — anything with a foreign key to `server`) may be deleted; otherwise delete is
refused and the page offers Deactivate. Inactive manual hosts can be reactivated. Repository hosts cannot
be deleted, deactivated or have their inventory fields edited here (Git would overwrite them); their
`display_name` and `notes` are editable because discovery never writes those two fields.

**D6 — Manual-host connection defaults are global settings.** `inventory.manual_ssh_user` (default
`""` = Ansible default user) and `inventory.manual_ssh_port` (default `22`) apply to every manual host.
Per-host user/port is out of scope (would need columns).

## 2. File ownership

A card may modify only the files listed for it. Files under "Slice A" belong to the shell/navigation card
`t_8439d40d`; no Slice B card edits them, except F's one-time navigation edit listed below.

| Card | Creates | Modifies |
| --- | --- | --- |
| F | `app/migrations/versions/0003_ssh_host_key.py`, `app/models/ssh_host_key.py`, `app/services/inventory_sources.py`, `app/web/management.py`, `app/templates/_management_ui.html.j2`, `app/static/pages/management.css`, `app/web/inventory.py` (skeleton), `app/web/ssh_keys.py` (skeleton), `app/templates/inventory/list.html.j2` (skeleton), `app/templates/ssh_keys/list.html.j2` (skeleton), `tests/unit/test_management_ui.py`, `tests/integration/test_management_pages_http.py` | `app/models/__init__.py`, `app/main.py` (route registration lines only), `app/services/settings.py` (two allowlist keys only), `app/templates/_navigation.html.j2` (§2.1 only), `tests/integration/test_schema.py`, regenerated `docs/ui/previews/*.html` (navigation change only), `docs/development.md` (route table rows for all §4–§6 routes), `CHANGELOG.md` (one Unreleased entry for Slice B) |
| W | `tests/unit/test_manual_inventory_render.py`, `tests/unit/test_known_hosts_render.py`, `tests/integration/test_manual_inventory_jobs.py` | `app/services/inventory_sources.py` (rendering functions), `app/jobs/handlers/ansible_context.py`, `app/jobs/handlers/discover.py`, `app/jobs/handlers/deploy.py` (only if plumbing needs it), `app/services/discovery.py`, `app/services/inventory.py`, `app/ansible/runner.py`, `app/jobs/worker.py` (capability), `app/web/common.py` (only `ansible_unavailable_reason`, `inventory_unconfigured_reason`, `NO_*` constants), `app/services/settings.py` (only the `inventory_not_configured` status condition) |
| INV | `app/services/managed_hosts.py`, `app/templates/inventory/_host_form.html.j2`, `app/templates/inventory/_host_row.html.j2`, `app/static/pages/inventory-hosts.css`, `tests/unit/test_managed_host_rules.py`, `tests/integration/test_inventory_management_http.py` | `app/web/inventory.py`, `app/templates/inventory/list.html.j2` |
| USR | `app/templates/users/detail.html.j2`, `tests/integration/test_users_detail_http.py` | `app/web/users.py` (not the `/administration` handler), `app/templates/users.html.j2`, `app/templates/_user_create.html.j2`, `app/auth/local.py` (add `reactivate_user` only), `app/static/pages/users.css`, `tests/integration/test_users_http.py`, regenerated `docs/ui/previews/users*.html` |
| SSH | `app/services/ssh_host_keys.py`, `app/templates/ssh_keys/_host_key_form.html.j2`, `app/static/pages/ssh-keys.css`, `tests/unit/test_ssh_host_key_rules.py`, `tests/integration/test_ssh_keys_http.py` | `app/web/ssh_keys.py`, `app/templates/ssh_keys/list.html.j2` |

**Slice A (not Slice B):** `app/templates/base.html.j2`, `_ui.html.j2`, `_navigation.html.j2` (after F),
`app/static/app.css` and tokens, `app/static/branding/*`, `app.state.navigation` in `app/main.py`,
`/administration` handler and `administration.html.j2`, `app/web/settings.py` and `app/templates/settings*`,
account/overview/login/error templates, global htmx configuration or JS, `scripts/render_previews.py`, the
preview manifest, `tests/test_*previews.py` (Slice B may only regenerate preview HTML it changes),
`docs/ui/*`. Also untouched by Slice B: `app/web/servers.py` and `app/templates/servers/*` (the `/servers`
empty-state link of UX-07 belongs to Slice A), `app/templates/_inventory_ui.html.j2` (certificate
inventory, unrelated despite the name).

If a card needs a change in a file it does not own, it stops and comments on its card with
`hotspot: <path> — <reason>`; it does not edit the file.

### 2.1 Navigation entries (F, once)

F adds to the **Infrastructure** group of `_navigation.html.j2`: `('Inventory', '/inventory')` as the
first page and `('SSH keys', '/ssh-keys')` as the last; and maps paths starting with `/inventory` and
`/ssh-keys` to the Infrastructure area. Users stays where it is (Administration). F regenerates the
previews with `scripts/render_previews.py` and commits only that output. Slice A must keep these three URLs
reachable from whatever navigation it builds. Feature cards never edit navigation.

## 3. Fields

### 3.1 Inventory host (`server`, spec §4.7 — no schema change)

| Field | Form name | Manual: create/edit | Repository row | Rule |
| --- | --- | --- | --- | --- |
| `hostname` | `hostname` | required on create; editable only while the host has no dependent rows | read-only | ≤ 253 chars; dot-separated labels of `A–Z a–z 0–9 _ -`, each 1–63 chars, not starting or ending with `-`; or an IPv4/IPv6 literal; stored lower-case; unique across all `server` rows (any source, any state) |
| `display_name` | `display_name` | optional | editable | single line, ≤ 200 chars, blank → NULL |
| `connection_address` | `connection_address` | optional | read-only | same syntax as hostname, no user, no port; equal to hostname → NULL |
| `webserver` | `webserver` | optional select: blank (auto-detect), `nginx`, `apache` | read-only | enum `webserver_type` |
| `ansible_groups` | `groups` | optional, comma- or space-separated | read-only | each `[A-Za-z_][A-Za-z0-9_]{0,63}`; ≤ 64 groups; de-duplicated, order kept; `all`/`ungrouped` refused |
| `notes` | `notes` | optional | editable | multi-line, ≤ 2000 chars |
| `is_active` | — (actions) | Deactivate/Reactivate actions | read-only | — |
| `inventory_source` | — | always `manual` | shown as "Repository · `<ref>:<path>@<sha7>`" | set by the service, never by the form |
| `last_discovery_at`, `last_discovery_status` | — | read-only | read-only | written by discovery only |

Settings edited on `/inventory` (D6, allowlist keys added by F): `inventory.manual_ssh_user`
(`""` or `[a-z_][a-z0-9_.-]{0,31}`), `inventory.manual_ssh_port` (integer 1–65535, default 22). Saved
through `update_settings` (audited like every setting).

### 3.2 User (`user`, spec §4.12 — no schema change)

| Field | Form name | Create | Edit | Rule (existing `app/auth/local.py`, unchanged) |
| --- | --- | --- | --- | --- |
| `username` | `username` | required | read-only | 1–150 chars: letters, digits, `. _ @ -`; unique (citext) |
| `email` | `email` | required | editable | valid address ≤ 254 chars |
| `display_name` | `display_name` | optional | editable | ≤ 200 chars |
| temporary password | `password` | required | — (reset/reactivate only) | existing password policy; never re-rendered |
| `auth_backend` | — | always `local` | read-only | password actions disabled for non-local |
| `is_active` | — | true | Deactivate / Reactivate actions | last active user cannot be deactivated |
| `totp_enabled` | — | false | Reset 2FA action | — |
| `must_change_password` | — | true | set by reset/reactivate | — |
| `last_login_at`, `locked_until` | — | — | read-only | — |

No role, no GitHub identity, no rename, no hard delete (D3).

### 3.3 Trusted host key (`ssh_host_key`, new — F creates, D4)

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigserial PK | |
| `host` | text not null | normalized host token: lower-case hostname or IP literal, or `[host]:port` for a port other than 22 |
| `key_type` | text not null | CHECK in `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `ssh-rsa` |
| `public_key` | text not null | canonical base64 of the SSH wire-format key blob |
| `fingerprint_sha256` | text not null | `SHA256:` + unpadded base64 of SHA-256(blob), exactly as `ssh-keygen -lf` prints it |
| `comment` | text null | label, ≤ 100 chars |
| `created_by` | bigint null FK `user(id)` | |
| `created_at` | timestamptz not null default `now()` | rows are immutable: no `updated_at` (spec §4.17 applies to mutable tables) |

Constraint `UNIQUE (host, key_type)`. Runtime `app_role`: `SELECT, INSERT, DELETE` (no `UPDATE`) and
sequence usage. Removal deletes the row; the audit log keeps the history. Public material only: no
secret ever goes into this table.

Worker client key (displayed on `/ssh-keys`, managed in Settings → Worker, read through the existing
`credential_states`): presence, provenance (dashboard / mounted file), key type, public fingerprint. The
value is never read in the web process.

## 4. Inventory — routes and behaviour (INV)

| Method | Path | Purpose | Success | Refusal |
| --- | --- | --- | --- | --- |
| GET | `/inventory` | list + filters + create form (closed disclosure) + source panel + connection defaults | 200 | invalid query values fall back to defaults |
| POST | `/inventory` | create manual host | flash `Host <hostname> added.` → `/inventory` | 422 inline |
| POST | `/inventory/{server_id}/edit` | edit (manual: all §3.1 fields; repository: `display_name`, `notes` only) | flash `Host <hostname> updated.` → `/inventory` (filters preserved via hidden `return_to`, validated to start with `/inventory`) | 422 re-renders **that row's** edit form open, with its attempted values and errors; 404 unknown id |
| POST | `/inventory/{server_id}/deactivate` | manual only | flash `Host <hostname> deactivated. It is no longer discovered or deployed to.` | 422 (repository row, already inactive) |
| POST | `/inventory/{server_id}/activate` | manual only | flash `Host <hostname> reactivated.` | 422 |
| POST | `/inventory/{server_id}/delete` | manual, no dependent rows, `confirm=1` | flash `Host <hostname> deleted.` | 422 `<hostname> has discovery or deploy history; deactivate it instead.` / `Repository hosts are managed in Git.` / `Confirm the action to continue.` |
| POST | `/inventory/connection` | save D6 settings | flash `Connection defaults saved.` | 422 inline |
| POST | `/inventory/import` | optional: enqueue discovery of everything (`request_discovery(db, {}, actor, now)`) | flash `Discovery queued; repository hosts appear here when the worker finishes.` | button disabled with the `/servers` discovery reason (handler, SSH key/known_hosts, inventory) when that reason is non-empty; a forced POST then gets 409 and enqueues nothing |

The edited row must be rendered even when it is outside the current filter/page (PR #92 review note):
the 422 page lists it above the table as "Editing `<hostname>`".

List columns: Hostname (link `/servers/{id}`), Display name, Connection address, Groups, Web server
(`auto` when NULL), Source (`Manual` badge or `Repository · <ref>:<path>@<sha7>`), State, Last discovery
(time + status), Bindings, Actions. Filters (query string, bookmarkable): `q` (case-insensitive substring of
hostname, display name or connection address; ≤ 200 chars), `group`, `source` = `manual|repository`,
`webserver` = `nginx|apache|auto`, `state` = `active` (default) `|inactive|all`, `page`, `page_size`
(same defaults/limits as `/servers`: `LIST_DEFAULT_PAGE_SIZE`, `LIST_MAX_PAGE_SIZE`). Sort: hostname.

States: **empty** (no host at all) — "No hosts yet" with two actions: *Add a host* (opens the create form)
and, only when a repository is configured, *Import from repository*; otherwise a secondary link
*Configure a repository (optional)* → `/settings?tab=inventory`. **Filtered empty** — "No hosts match
these filters" + *Clear filters*. **Source panel** — "Repository: not configured" or "Repository:
`<redacted url>` @ `<ref>`, last pull …" (read through existing settings/overview read models; never the
token). **Connection defaults warning** — while `inventory.manual_ssh_user` is empty and a manual host
exists: "Manual hosts connect as the worker's default SSH user. Set the SSH user used on your servers."

Validation messages (field → text): hostname empty `Enter a hostname.`; syntax `Use letters, digits, dots,
hyphens or underscores (or an IP address); a label cannot start or end with a hyphen.`; duplicate `A host
named <hostname> already exists (<Manual|Repository>, <active|inactive>).`; display name `Display name must
be at most 200 characters and fit on one line.`; connection address `Enter a hostname or IP address
without a user or port.`; groups `Group names use letters, digits and underscores and cannot start with a
digit.` / `"all" and "ungrouped" are reserved by Ansible.` / `At most 64 groups.`; notes `Notes must be at
most 2000 characters.`; SSH user `Use a POSIX user name (lower-case letters, digits, _ . -).`; SSH port
`Enter a port between 1 and 65535.`

Audit: `server.create` / `server.update` (before/after of changed fields) / `server.deactivate` /
`server.activate` / `server.delete`, each with `{"hostname": …, "source": "manual"|"repository"}`.

## 5. Users — routes and behaviour (USR)

Existing URLs keep their methods and form field names (they are contracts used by tests and previews).

| Method | Path | Status | Purpose | Success | Refusal |
| --- | --- | --- | --- | --- | --- |
| GET | `/users` | existing, changed | list; `?create=1` opens the create form; rows link to `/users/{id}` | 200 | — |
| POST | `/users` | existing | create (invite) local user | flash `User <username> created. They must change the temporary password at first sign-in.` → `/users/{id}` | 422 inline in the create form, password cleared |
| GET | `/users/{user_id}` | **new** | full-width management page: details form, security actions, history summary | 200 | 404 |
| POST | `/users/{user_id}/edit` | existing | email, display name | flash `User <username> updated.` → `/users/{id}` | 422 inline on the detail page |
| POST | `/users/{user_id}/deactivate` | existing | needs `current_password` | flash `User <username> deactivated and signed out.` → `/users/{id}` | 422 (last active user, wrong password), 423 locked |
| POST | `/users/{user_id}/reactivate` | **new** | needs `current_password` + `password` (new temporary password) | flash `User <username> reactivated. They must change the temporary password at next sign-in.` → `/users/{id}` | 422 (already active, policy, wrong password), 423 |
| POST | `/users/{user_id}/reset-password` | existing | unchanged | flash (existing text) → `/users/{id}` | unchanged |
| POST | `/users/{user_id}/reset-totp` | existing | unchanged | flash (existing text) → `/users/{id}` | unchanged |

`reactivate_user(db, user_id, new_password, actor, now)` in `app/auth/local.py`: takes `lock_user_admin`,
refuses an active user (`already_active`: `This user is already active.`), sets `is_active = true`,
`must_change_password = true`, new password hash, clears `failed_attempts`/`locked_until`, audits
`user.reactivate {"username": …}`. Non-local backends: refused with the existing `not_supported` text.

List columns: Username, Display name, Email, Sign-in (backend), 2FA, State (`Active`, `Inactive`,
`Locked until …`, `Must change password`), Last login, Manage. Empty state: when the signed-in admin is the
only user — "You are the only user. Add another administrator so the dashboard is never locked out." + *Add
user*. The `?notice=` mechanism is replaced by the flash (§8); the query parameter is ignored afterwards.

## 6. SSH keys — routes and behaviour (SSH)

| Method | Path | Purpose | Success | Refusal |
| --- | --- | --- | --- | --- |
| GET | `/ssh-keys` | worker key card + trusted host keys list + add form | 200 | — |
| POST | `/ssh-keys/host-keys` | add one or more trusted host keys; requires `verified=1` (rule 10) | flash `Trusted <n> host key(s).` → `/ssh-keys` (the list shows host, type and fingerprint of each) | 422 inline, all-or-nothing |
| POST | `/ssh-keys/host-keys/{key_id}/delete` | remove one, `confirm=1` | flash `Removed the dashboard-trusted <type> key for <host≤64>. The mounted known_hosts file and other trusted keys still apply.` | 404 unknown id; 422 `Confirm the action to continue.` |

Worker key card: state and fingerprint from `credential_states`, plus the worker-reported "mounted
known_hosts file: present/absent". Action: *Replace or remove in Settings → Worker* (`/settings?tab=worker`,
a link, not a redirect). Empty host-key state: "No host keys trusted in the dashboard yet. Discovery and
deploy refuse to connect to a host whose key is not trusted." + the add form open. The add form always
shows this hint (verbatim): *Only trust a key whose fingerprint you checked with the server itself. Best:
paste `/etc/ssh/ssh_host_ed25519_key.pub` copied from the server's console or your provisioning system,
and enter the host. If you use `ssh-keyscan <host>`, first compare its fingerprints (`ssh-keyscan <host> |
ssh-keygen -lf -`) with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` run on the server: ssh-keyscan
does not authenticate the server.*

`<host≤64>` in flashes: the host token, cut to its first 63 characters plus `…` when longer than 64, so the
delete flash stays under 200 characters and never reaches the 240-character `set_flash` truncation (a
truncated warning is a bug). Flashes never claim that SSH to a host now fails: the dashboard cannot know
what the mounted file trusts. The delete confirmation (C5) consequence reads: `The dashboard stops trusting
this key. Keys for this host in the mounted known_hosts file are not changed and still apply.`

List columns: Host, Key type, Fingerprint (`SHA256:…`, monospace, full), Comment, Added (date) by
(username), Actions (Delete with confirmation).

Add form fields: `entries` (textarea, required) and `hosts` (optional), `comment` (optional, ≤ 100),
`verified` (checkbox, value `1`, required, never pre-checked, rendered unchecked on every 422; label `I
compared these fingerprints with the server's own host keys through a trusted channel.`).
Validation (`app/services/ssh_host_keys.py`, pure parser + transactional `add_host_keys`):

1. Input ≤ 16 KiB; after dropping blank lines and `#` comment lines, 1–20 lines. Else `Paste between 1 and
   20 host keys.`
2. Any occurrence of `PRIVATE KEY` (any case) anywhere: refuse the whole submission with `This looks like
   a private key. Paste the host's public key (for example the output of ssh-keyscan); private keys are
   never accepted here.` The textarea is re-rendered **empty** and the text is never logged or echoed.
3. Each line is either `<hosts> <type> <base64> [comment]` (known_hosts / ssh-keyscan format) or
   `<type> <base64> [comment]` (public-key format; then the `hosts` field is required: `Enter the host this
   key belongs to.`). A line comment is used when the `comment` field is blank.
4. `@cert-authority` / `@revoked` markers → `Certificate-authority and revoked entries are not supported.`
   Hashed names `|1|…` → `Hashed host names are not supported; run ssh-keyscan without -H.`
5. Host tokens (comma-separated, ≤ 20 per line): hostname or IP literal (§3.1 hostname syntax) or
   `[host]:port` (1–65535); `[host]:22` is stored as `host`; lower-cased. Wildcards/negation (`* ? !`) →
   `Host patterns are not supported; list each host.`
6. Key type in the §3.3 list, else `Unsupported key type <type>. Accepted: ssh-ed25519, ecdsa-sha2-nistp256,
   ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-rsa.` (this refuses `ssh-dss` and `sk-*`).
7. Base64 decodes strictly (`validate=True`); the blob's embedded type string equals the declared type;
   `cryptography.hazmat.primitives.serialization.load_ssh_public_key` accepts it; RSA ≥ 2048 bits. Messages:
   `The key data is not valid base64.` / `The key data does not match its type <type>.` / `RSA host keys
   shorter than 2048 bits are refused.`
8. Duplicates (per host token): same `(host, key_type)` and same blob → `<host> already trusts this <type>
   key (<fingerprint>), added <date> by <username>.`; same `(host, key_type)` with a different blob →
   `<host> already has a different trusted <type> key (<old fingerprint>). If the host key was rotated,
   delete the old key first.` Identical lines inside one paste collapse silently; conflicting lines inside
   one paste are an error. The DB unique constraint is the concurrency backstop: an `IntegrityError` maps to
   the same messages.
9. All-or-nothing: if any line fails, nothing is stored; errors are listed as `Line <n>: <message>` in the
   error summary and the input is preserved (except rule 2).
10. `verified` missing or not `1` → `Confirm that you verified the fingerprints with the server before
    trusting them.` (field error on `verified`); nothing is stored. No auto-accept, no trust-on-first-use,
    no server-side `ssh-keyscan`: the dashboard stores only keys the administrator pasted and attested.

Audit: `ssh_host_key.add` (one row per stored key: host, type, fingerprint, `"verified": true`) and
`ssh_host_key.remove` (host, type, fingerprint). No key material beyond the public fingerprint goes into the audit details.

## 7. Worker integration rules (W)

1. Inventory per discover/deploy job: Git listing (when a repository is configured) ∪ active manual hosts
   whose hostname the Git listing lacks. Rendered as a YAML inventory file in the job's run directory:
   manual hosts under their groups (ungrouped under `all.hosts`), `ansible_host` = `connection_address`
   when set, the `inventory.webserver_var` host variable when `webserver` is set, `ansible_user` /
   `ansible_port` from D6 when set. Test pull still requires a repository.
2. No repository and no active manual host → the job fails `config_invalid` with `no inventory: add a host
   in Inventory or configure a repository`; `inventory_unconfigured_reason` returns the same sentence
   only in that case; Settings → Status `inventory_not_configured` follows the same condition.
3. Reconciliation: hosts from the Git listing get the revision source (adoption per D1); manual hosts
   keep `manual`; a manual row is never deactivated for being absent from Git.
4. known_hosts per job: mounted file content (if present) followed by one `host key_type public_key` line
   per `ssh_host_key` row, written `0600` into the job staging area, removed on exit, passed to Ansible and
   to Git exactly where the mounted file path is passed today. The mounted file is only read, never
   written. The "no known_hosts" failure and banner
   apply only when the file is absent **and** the table is empty.
5. Renderers refuse (raise) any value containing whitespace, a newline or a leading `-`, as defence in depth
   behind the validated inputs.

## 8. Shared conventions (F provides, INV/USR/SSH use)

F creates `app/web/management.py` and `app/templates/_management_ui.html.j2`; features import from them
and do not re-implement them.

- **C1 Native first.** Every form is `method="post"` with the session `csrf_token` hidden field and works
  with JavaScript disabled. GET never mutates.
- **C2 Success.** `done(request, location, note)`: native → `303` to `location`; htmx (`HX-Request: true`)
  → `200` with `HX-Redirect: location`. Both set the signed flash cookie (`set_flash`), rendered by the
  existing `base.html.j2` banner on the next full page. Notes: one sentence, names the entity, ≤ 240 chars,
  never a secret. This is the only success channel (no `?notice=`, no success text inside fragments).
- **C3 Refusal.** Validation and business refusals return **422** with the full page re-rendered:
  `error_summary(errors)` at the top of the affected panel (`role="alert"`, each message links to
  `#field-<name>`), `field_error(errors, name)` under the field (`id="error-<name>"`; the input carries
  `aria-invalid="true" aria-describedby="error-<name>"`), previous input preserved except passwords and
  rule-2 pastes. Unknown id → 404 page. Mutually exclusive state (e.g. discovery unavailable) → 409 as today.
- **C4 htmx forms.** `hx-post` = the form's `action`, `hx-target="#<panel-id>"`, `hx-select="#<panel-id>"`,
  `hx-swap="outerHTML"`; the server renders the same page for native and htmx requests. Pages include
  `management_head()` in `{% block extra_css %}`: it links `management.css` + the page stylesheet and emits
  an `htmx-config` meta that swaps `422` and swaps `403` responses into `#main-content` (so a stale-form
  refusal shows the shared "Your form expired…" text instead of nothing — UX-08 for Slice B pages; the
  global fix remains Slice A's). Required for INV and SSH forms; optional for USR (native only is fine).
  Panel ids: `inventory-panel`, `inventory-connection`, `ssh-host-keys-panel`, `user-detail-panel`.
- **C5 Confirmation.** `confirm_action(url, label, consequence)` renders a `<details>` disclosure with the
  consequence sentence and a submit button named after the action and entity, posting `confirm=1`; the
  server refuses a missing `confirm` with 422 `Confirm the action to continue.` No `hx-confirm`/JS dialogs.
  User actions keep their existing current-password re-authentication instead.
- **C6 Empty states.** `empty_state(title, body, actions)`; "nothing yet" (primary action) is always
  distinct from "no match for these filters" (*Clear filters*).
- **C7 Audit and transactions.** Every mutation runs in one `_transact` transaction with exactly the audit
  rows named in §4–§6. The target change and its success audit commit together or not at all: a
  validation, business or confirmation refusal changes no target row and writes no success audit.
  **Mandatory exception:** a failed current-password re-authentication (`PasswordChangeError` from
  `reauthenticate`) keeps the existing `_transact` behaviour in `app/web/common.py` — the acting
  administrator's failed-attempt counter, any lockout and the security audit row are **committed**, while
  the target user is left unchanged (re-authentication runs before the target change, via
  `_reauthenticated`). Feature code never catches, wraps or rolls back that path (Plan 1 Global
  Constraints: lockout and audit integrity).
- **C8 Badges.** `source_badge(source)` → `Manual` / `Repository · <ref>:<path>@<sha7>`; `state_badge`
  → `Active` / `Inactive`.
- **C9 Styles and assets.** Page styles in `app/static/pages/<area>.css` using existing tokens; no edits to
  `app.css`; no new JS file; no new dependency.
- **C10 No external redirects.** No route answers with a redirect outside the dashboard; repository
  configuration is a link to `/settings?tab=inventory`.

## 9. Acceptance criteria and test checklists

Every box is proved by a named test or by CI. Integration tests use the existing HTTP fixtures (real
PostgreSQL, CSRF-valid sessions) and run with `inventory.repo_url` unset unless the test says otherwise.

### F — foundation
- [ ] Migration `0003_ssh_host_key` upgrades a `0002` database; `alembic check` clean; `test_schema.py`
      asserts the table, the unique constraint, the CHECK, and app_role grants (no UPDATE).
- [ ] `get_setting` defaults: `inventory.manual_ssh_user == ""`, `inventory.manual_ssh_port == 22`; invalid
      values refused by `update_settings`.
- [ ] `inventory_sources.MANUAL_SOURCE == "manual"`; `is_manual()` true only for that value.
- [ ] `done()` native 303 + flash; htmx 200 + `HX-Redirect` + flash; flash rendered on the next GET.
- [ ] Macros render: error summary links, field error ids/aria, confirm disclosure posts `confirm=1`,
      empty states, badges; `management_head()` emits the htmx-config with 422 and 403 rules.
- [ ] With no repository, no SSH key and no known_hosts: `GET /inventory`, `/ssh-keys`, `/users` return 200
      for a signed-in admin and redirect anonymous users to `/login`.
- [ ] Navigation shows Inventory and SSH keys under Infrastructure; previews regenerated; preview tests green.

### W — worker integration
- [ ] Renderer unit tests: groups/ungrouped layout, `ansible_host`, webserver var, user/port only when set,
      deterministic order, refusal of unsafe values; known_hosts renderer: file + rows, `0600`, exact line format.
- [ ] Integration: manual-only discovery reaches a compose SSH target and records bindings; repository +
      manual mix; adoption keeps id/notes and audits; manual row survives a Git listing without it.
- [ ] No inventory → `config_invalid` with the §7.2 sentence; banner/status say the same.
- [ ] DB-only host key lets discovery connect; empty table + no file → missing-known-hosts failure.
- [ ] Same host/key in the mounted file and in the table, then the row deleted: the rendered per-job
      known_hosts still contains the mounted line, discovery still connects, and the mounted file's bytes
      and mode are unchanged (hash before/after).
- [ ] Existing discover/deploy/test-pull suites green.

### INV — inventory
- [ ] Create, edit, deactivate, reactivate, delete a manual host with no repository configured (native and
      htmx), each with its flash and audit row.
- [ ] Every §3.1/§4 validation message, one test each; previous input preserved; 422 status.
- [ ] Row-targeted edit error, including a row on page 2 / filtered out / inactive.
- [ ] Delete refused with history (seed a binding) → deactivate offered; delete without `confirm` → 422.
- [ ] Repository row: inventory fields read-only, `display_name`/`notes` editable, delete/deactivate 422.
- [ ] Duplicate hostname across sources refused with the source/state in the message.
- [ ] Filters `q/group/source/webserver/state` and paging; empty vs filtered-empty states.
- [ ] Import: with a repository configured enqueues one discover job and flashes; without one the button is
      disabled with the reason and a forced POST is 409; no response redirects off-site.
- [ ] Connection defaults save/validate/audit; the empty-user warning appears only with manual hosts.

### USR — users
- [ ] Create (invite), edit, deactivate, reactivate, reset password, reset 2FA from `/users/{id}`, each with
      flash and audit; responses land on `/users/{id}`.
- [ ] Every existing `UserAdminError` and re-auth message rendered inline with 422/423; passwords never re-rendered.
- [ ] Reactivate: wrong current password, already active, policy failure, non-local backend; success forces
      a password change at next login.
- [ ] Wrong `current_password` on deactivate and on reactivate: 422; the target's `is_active`, password hash
      and `must_change_password` are unchanged and no `user.deactivate`/`user.reactivate` audit row exists,
      **while** the acting admin's `failed_attempts` is incremented and the re-authentication failure audit
      row exists — asserted from a fresh DB session after the response (C7 exception). Repeating it up to the
      lockout threshold returns 423.
- [ ] Last-active-user deactivation still refused; deleted-user route does not exist (POST `/users/{id}/delete` → 404/405).
- [ ] Only-user empty state; inactive/locked/must-change states visible in the list.
- [ ] Existing `test_users_http.py` and administration preview tests green (create form stays at `action="/users"`).

### SSH — SSH keys
- [ ] Add a valid ed25519, ecdsa-nistp256 and RSA-3072 key (ssh-keyscan format and public-key + hosts
      format); fingerprints equal `ssh-keygen -lf` output for the fixtures; audit rows written.
- [ ] One test per §6 rule 1–9 message, including: private key pasted (refused, not echoed — assert the
      response body does not contain the pasted text), hashed host, wildcard, `ssh-dss`, RSA-1024, bad
      base64, type mismatch, exact duplicate, different key for same host/type, conflicting lines in one
      paste, all-or-nothing (nothing stored when line 2 fails).
- [ ] `[host]:22` normalized to `host`; `[host]:2222` kept.
- [ ] Delete with confirmation removes the row, flashes, audits; without `confirm` → 422; unknown id → 404.
- [ ] Delete flash and confirmation text exactly as §6 (source-aware, no "now fails" claim); with a
      253-character host the flash is ≤ 240 characters and still ends with `still apply.`
- [ ] Add without `verified=1` → 422 with the rule 10 message, nothing stored; on every 422 the checkbox is
      unchecked; the add form shows the fingerprint-verification hint.
- [ ] Worker key card shows type/fingerprint/provenance and never any key value; works with no key configured.
- [ ] Works with no repository configured; no response redirects off-site.

### R — manual smoke (human steps, GitHub/Git repository unconfigured)
1. Clear Settings → Inventory repository URL. Sign in as an admin.
2. Infrastructure → Inventory: empty state shows *Add a host*; add `web01.example.test`, groups
   `web prod`, nginx; edit its notes; submit an invalid hostname `-bad` in the edit form and see the inline
   error on that row; deactivate, reactivate, delete (with confirmation).
3. Infrastructure → SSH keys: on the lab host's console run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`;
   run `ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -` and continue **only if the two fingerprints
   match**. Submit the `ssh-keyscan` line once without the verification box (refused), then with it; check
   the listed fingerprint equals the console one. Paste it again and see the duplicate message; paste an
   `-----BEGIN OPENSSH PRIVATE KEY-----` block and see the refusal with an empty textarea; delete the key
   with confirmation and read the source-aware flash (a key also in the mounted known_hosts file stays
   trusted).
4. Administration → Users: add a user, open it, edit the email, deactivate (current password), reactivate
   with a new temporary password, sign in as that user and get the change-password gate.
5. With a lab host key trusted and the worker SSH key configured, run discovery from `/servers` for the
   manual host and see `last_discovery_status = ok` (needs W).
6. Configure a repository: *Import from repository* queues discovery; repository hosts appear read-only;
   a manual host whose name is in the repository becomes a repository row with its notes kept.

## 10. Out of scope (follow-ups, not Slice B)

Fetching a host key from the target with explicit fingerprint confirmation (needs a new job type);
multiple worker client keys or per-host credentials; per-host SSH user/port; showing the worker's OpenSSH
public key for `authorized_keys` (needs public-key metadata at save time); roles/RBAC; hard user delete or
rename; editing repository content from the dashboard; GitHub OAuth/repository browser; `/servers` empty
state and global htmx error handling (Slice A).
