# Cert Dashboard — Plan 4: Dashboard UX — in-dashboard management, shell and branding

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an administrator run the dashboard without managing anything outside it: hosts, users and SSH host trust are managed in the UI, a Git repository ("GitHub") stays an optional source, the shell gets a coherent navigation, an Administration hub and a replaceable logo, and every audit P1 finding is closed.

**Spec:** `docs/ux-spec.md` (normative for this plan), with `docs/slice-b-contract.md` (Slice B) and `docs/ui/branding.md` (logo). Evidence: `docs/ux-audit.md`. The design spec `docs/superpowers/specs/2026-10-19-cert-dashboard-design.md` carries pointers in §8, §8.2, §8.6, §8.10 and §9.8.

**Global Constraints:** Plans 1–3 Global Constraints apply unchanged, except the two additive migrations this plan authorizes: `0003_ssh_host_key` (`slice-b-contract.md` D4, merged) and `0004_branding` (`docs/ux-spec.md` A2-D1). No new runtime or dev dependency. No new JavaScript file. Every form works without JavaScript. No route redirects outside the dashboard. File ownership per `docs/ux-spec.md` §4.2; Slice A cards run strictly in order A1 → A2a → A2b → A3; Slice B cards in flight (INV, W2) run in parallel because they own disjoint files.

**Local reality:** the Hermes container has no Docker. Locally run `uv run ruff check .` and `uv run pytest -q tests/unit` plus the task's DB-free tests; integration tests run in the required `verify` check on GitHub CI, which is the authority.

## Task status

Boxes are ticked only when the work is merged on `main`; each ticked box names its merge.

### Task B-F: Slice B foundation (`t_ccb6f82e`)
- [x] Schema `0003_ssh_host_key`, shared management conventions, page skeletons, navigation entries — merged `49aef42` (PR #94).

### Task B-W: manual hosts and trusted host keys reach discover/deploy (`t_d94e4b93`)
- [x] Effective inventory = Git ∪ manual hosts; effective known_hosts = mounted file ∪ `ssh_host_key` rows — merged `2cf7aff` (PR #98).

### Task B-USR: users management (`t_ffd019cc`)
- [x] `/users/{id}` full-width page, reactivation, inline errors — merged `4e860c6` (PR #97). Closes UX-03, UX-06.

### Task B-SSH: trusted host keys (`t_ba115a93`)
- [x] `/ssh-keys` trust store with verification attestation — merged `2613bd8` (PR #95).

### Task B-INV: inventory management (`t_c95126de`)
- [ ] `/inventory` CRUD, filters, empty states, optional repository import (`slice-b-contract.md` §4, §9 INV) — PR #96 in review.

### Task B-W2: finish host-trust onboarding (`t_214beeb1`, `docs/ux-spec.md` §8.2)
- [ ] Tests: HTTPS test pull without known_hosts; `ssh://` and discover still fail closed with the new text; deploy screen renders new and old texts and the no-inventory sentence.
- [ ] Implement in `ansible_context.py`, `test_pull.py`, `deploy_views.py` (`JOB_FAILURE_REASONS`).
- [ ] Required `verify` green; merged.

### Task B-R: Slice B review and smoke (`t_9ab63e2d`)
- [ ] `slice-b-contract.md` §9 R smoke; PR #92 closed as superseded.

### Task A1: shell, navigation, Overview checklist, Administration hub, HTMX error parity (`t_8439d40d`)
- [ ] Tests per `docs/ux-spec.md` §5.8 (navigation, setup checklist, hub, narrow settings, `/servers` empty states, banner links, global htmx-config, HTMX 403 on a non-management page, default branding).
- [ ] Implement §5.1–§5.7; regenerate previews.
- [ ] Regression criteria §9; required `verify` green; merged.

### Task A2a: branding storage, validation and serving (`t_e8c0f619`, `docs/ux-spec.md` §6)
- [x] Tests: migration/schema, every validation case, service state machine (409/410/503, cross-session, double save), `/branding/logo` headers and fallback — PR #103.
- [x] Implement `0004_branding`, `branding_image.py`, `branding.py`, `GET /branding/logo`, cleanup purge — PR #103.
- [ ] Required `verify` green; merged.

### Task A2b: Settings → Branding UI and shell integration (`t_860fb51c`, `docs/ux-spec.md` §6)
- [ ] Tests per §6 A2b (full preview/save/discard/reset flow, every error copy, CSRF before parsing, gates, favicon/name unchanged, hub entry).
- [ ] Implement routes, `_branding.html.j2`, resolver in header and sign-in; regenerate previews.
- [ ] Required `verify` green; merged.

### Task A3: endpoint deactivation confirmation (`t_6fab5610`, `docs/ux-spec.md` §7)
- [ ] Tests: deactivate with/without `confirm` (native and htmx), activation unchanged, history kept.
- [ ] Implement; regenerate the scan-detail previews.
- [ ] Required `verify` green; merged.

### Task D: documentation and screenshots (`t_4c8f8378`)
- [ ] README/docs/screenshots refreshed after every task above; tick this plan's remaining boxes.
