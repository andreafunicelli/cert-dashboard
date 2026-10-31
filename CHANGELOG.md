# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No release has
been tagged yet: `Unreleased` collects everything merged into `main` before the first tag,
with the pull request that delivered each group of changes.

## [Unreleased]

### Added

**Core platform (Plan 1 Tasks 1–10, PR #1)**

- Hardened runtime image and Compose stack: `web` and `worker` run as UID 10001 with a
  read-only root filesystem, dropped capabilities, `no-new-privileges` and tmpfs `/tmp`;
  the worker gets a private `noexec` tmpfs for decrypted key material. A separate one-shot
  `migrate` profile service runs as UID 999 with the database owner password as its only
  secret.
- File-secret provisioning and validation: `scripts/install-secrets.sh` applies the
  canonical owners and modes without reading or copying any value, and startup validates
  `master_key`, `session_secret` and `db_password`.
- The complete v1 PostgreSQL schema in one migration: certificates, private keys, bindings,
  endpoints, servers, jobs and job hosts, scan results, renewals, notifications, trust
  anchors, settings, users, sessions, login rate limit, worker heartbeat and scheduler
  state, plus a runtime role limited to DML and a sealed append-only `audit_log`.
- Transactional audit writer with a shared redaction filter for details, exception
  messages and log output.
- Row-bound AES-256-GCM encryption for private keys and TOTP seeds, a versioned keyring,
  and the `generate-master-key`, `rotate-master-key` and `verify-key` CLI commands.
- Key generation, SPKI matching and CSR construction for RSA 2048/3072/4096 and ECDSA
  P-256/P-384, with IDNA-validated, size-bounded SAN sets.
- Certificate parsing and chain normalisation: issuer/signature ordering, fingerprint
  dedupe, roots excluded from stored chains, deterministic missing-issuer diagnostics.
- Offline trust assessment against uploaded internal roots and the pinned certifi bundle,
  persisting `chain_status` per certificate.
- PFX import and construction primitives (password-protected bundles, normalised
  intermediate-only chain, in memory).
- Argon2 local authentication with account lockout and a pluggable backend contract;
  encrypted TOTP enrolment with single-use recovery codes.
- Server-side sessions, CSRF protection, typed error pages, request IDs and structured,
  redacted request logs.

**Sign-in, MFA and account security (Task 11, PR #2; operations notes PR #3)**

- `/login`, `/login/2fa`, `/logout` and `/account`, the `bootstrap-admin` CLI, a
  PostgreSQL-backed IP rate limit (sixth attempt per UTC minute returns 429) and a
  10-failure/15-minute account lockout.
- Password, TOTP and recovery-code management behind current-password re-authentication,
  with full session revocation on change.
- Operator instructions for bootstrap, sign-in and MFA in `docs/development.md` (PR #3).

**Queue, scheduler and worker (Tasks 12–13, PRs #4, #5, #6)**

- PostgreSQL job queue built on a single `FOR UPDATE SKIP LOCKED` claim, with terminal
  states, an ownership fence (`StaleJobError`), a timeout reaper, retry-due requeueing and
  a per-job-type retry policy table.
- Job registry (`build_registry()`) keyed by `(type, action)` with mandatory payload
  validators, shared by the worker (dispatch) and the web app (capability checks).
- Daily scheduler with `scheduler_state` dedupe, an advisory lock, a 12-hour missed-run
  rule, and the `cleanup` retention job (finished jobs, scan results, sessions, login
  counters, artifacts) seeded at 04:00 UTC.
- Worker process `python -m app.jobs.worker`: four slots, a two-job cap for
  discovery/scan, 30-second heartbeat and tick, five-minute staleness, key-staging wipe at
  startup, and bounded graceful shutdown.
- `/healthz` JSON probe and the stale-worker page banner, both driven by the same heartbeat
  query, and worker health in Compose.

**Inventory, import and browsing (Tasks 14–17, PRs #7, #8, #9, #10)**

- Certificate inventory service: race-safe dedupe by public key hash, key attachment to
  existing rows, lineage with cycle prevention, audited duplicate/reuse results and
  persisted chain status.
- Upload import for PEM/CRT/PFX with a 1 MiB cap, content-based parsing, aggregate blocking
  errors separated from non-blocking chain warnings, and explicit confirmation before a
  supplied key is attached to public-only inventory.
- Worker-side pull import from `host:port` over TLS (`scan/import_pull`) with SNI, bounded
  chain size, typed failures, a progress page that polls every two seconds and an upserted
  manual endpoint expectation.
- Expiry-only Overview with disjoint buckets, a filterable/sortable certificate list with
  bookmarkable queries, 1–100 rows per page and JSON export, and a detail page with public
  fields, key metadata, lineage, audits and chain warnings.

**Renewals and downloads (Tasks 18–20, PRs #11, #12, #13)**

- Audited renewal state machine `draft → csr_generated → submitted → issued → deployed →
  done` with row locking, cancel rules, atomic CSR/key storage and an issued-certificate
  gate that checks key and CSR SPKI, CN/SAN identity and validity.
- Resumable manual-CA wizard: prefill, CSR download, CA checklist, submitted step and an
  issued/ready step, persisted trust warnings, non-JS and htmx paths. The renewal stops at
  `issued` in Plan 1: `mark_deployed` is implemented but requires a successful deploy job and
  binding evidence, no deploy handler is registered, and finalisation (with the previous
  certificate's status change) is only reachable from `deployed` — all of it arrives with
  Plan 3.
- Audited `leaf.pem`, `chain.pem` and `fullchain.pem` downloads, and a re-authenticated,
  password-protected PFX export built entirely in memory.

**Observation and administration (Tasks 21–23, PRs #14, #15, #16, #17)**

- Read-only audit browser with filters, pagination and a metadata-only JSON export capped
  at 5,000 rows.
- Local user administration (create, edit, deactivate, password and TOTP resets) with
  re-authentication, session revocation and last-active-user protection.
- Typed settings across seven configuration tabs (SMTP, alerts, inventory, deployment,
  scanning, schedule, general) with an explicit 32-key allowlist, atomic audited patches and
  CSRF on every mutation.
- Trust-anchor management (PEM upload, deletion, public-bundle toggle with synchronous
  audited chain recheck), a read-only status snapshot (warnings, worker, queue, keyring,
  database) and the confirmation-gated maintenance prune.

**TLS observation, scanning and alerts (Plan 2 Tasks 1–17, PRs #21–#38)**

- Endpoint observation and classification (`app/services/scans.py`): a TLS handshake with SNI, the
  SHA-256 of the served leaf, TLS version, CN, issuer, `not_after`, chain length and elapsed time,
  classified as `ok`, `mismatch`, `expired`, `unreachable` or `error`. The served certificate is never
  imported, matched into inventory or trusted, and the expected certificate is snapshotted per result
  (Task 1, PR #21).
- `scan/default` job: 20 connections in flight, `scan.timeout_seconds`, active endpoints only,
  unreachable-only retries (three attempts, 30/120 s backoff), one `scan.run` audit per attempt,
  count-only results, a daily 02:00 schedule behind `scan.enabled`, and priority-200 on-demand scans
  from the certificate page and `/scans/run` (Task 2, PR #22).
- Background trust recheck `scan/trust_recheck`, sharing `scan.daily_at`/`scan.enabled`, with
  **Settings → Trust anchors → Recheck now** (Task 3, PR #23).
- Worker-only SMTP transport (`app/services/smtp.py`): STARTTLS, SSL/TLS or none, AUTH only over TLS,
  no plaintext downgrade, `smtp.tls_verify`, and code-only outcomes — fixed step names plus numeric
  reply codes instead of any peer reply text (Task 4, PR #24), with a dev-only `aiosmtpd` capture
  server.
- **Send test email** as the never-retried `alert_expiry/smtp_test` worker job, with its step/reply
  transcript on the SMTP tab (Task 5, PR #25).
- `notification_log` delivery ledger: unique dedupe key, row-locked sends (at-least-once delivery — a
  crash between SMTP acceptance and the commit can resend once), three bounded attempts with 30/120 s
  backoff for retryable failures, and the `notification_retry` scheduler tick step (Task 6, PR #26).
- Expiry evaluation and rendering: configured thresholds, smallest crossed threshold, owner-first
  recipients, text and minimal HTML mail, optional `DASHBOARD_URL` links (Task 7, PR #27).
- `alert_expiry/default` with the 07:00 `expiry_check` schedule, deduplicated per threshold (one row
  per certificate, threshold and UTC day) and partial-failure semantics (Task 8, PR #28).
- Digest collection against the state at the last digest — new TLS mismatches, unknown certificates,
  stale servers, failed jobs, rolled-back hosts, failed notifications — plus the `binding.match_state`
  audit producer (Task 9, PR #29).
- `digest/default` with the 07:30 schedule behind `alert.digest_enabled`, sent even when there is
  nothing to report (Task 10, PR #30).
- Settings: the Alerts tab lists recent delivery failures with attempts and the next attempt; Status
  adds an SMTP panel and the `smtp_failing`/`smtp_tls_unverified` warnings (Task 11, PR #31).
- `/scans` screen with filters, sorting, JSON export, a history drawer and **Scan now**/**Scan all**
  (Task 12, PR #32), plus endpoint management — add endpoint, set expectation (explicit certificate or
  the observed one), activate/deactivate — and the certificate detail endpoints panel (Task 13,
  PR #33).
- `/servers`, `/servers/{id}`, `/bindings` and `/bindings/help`: read-only views of servers, their
  bindings (paths, owners, octal modes, on-disk fingerprints, match state) and discovery history, with
  discovery controls disabled until Plan 3 (Tasks 14–15, PRs #34, #35).
- Overview slots: TLS health counters with links into the Scans/Bindings filters, the newest ten jobs,
  renewals in flight and a status strip with the worker state, inventory revision and last digest
  (Task 16, PR #36).
- Test stack: `docker-compose.test.yml` profile `targets` with digest-pinned `nginx` and `httpd` TLS
  targets and an SMTP capture service on loopback ports, pulled by CI and started with `--pull never`
  (Task 17, PR #37).
- Documentation: Plan 2 developer notes in `docs/development.md`, the operator chapter
  `docs/operations.md` §10, and the README status.

**Server discovery and automated deploy (Plan 3 Tasks 1–20, PRs #41–#64)**

- Job control: typed `JobPaused`/`JobRequeued`/`JobCancelled` outcomes, `release_claim` with the
  attempt refund, the `on_success` hook, PostgreSQL advisory locks (`deploy:global`,
  `deploy:enqueue`, `inventory:pull`, `deploy:<hostname>`) and the `worker.start` capability record
  (Task 1, PR #41).
- Ansible runner wrapper: child environment built from scratch, `ansible-runner` events, host and
  failure classification, file-only secrets in the tmpfs staging area, the vault/Git helper scripts
  and `SSH_KNOWN_HOSTS` (Task 2, PR #42).
- CI-only SSH-enabled nginx and Apache targets with pinned host keys, `become` and fault injection
  (Task 3, PR #43).
- Inventory checkout by fetch-into-a-private-ref and `reset --hard`, the 60-second no-pull window,
  the 24-hour staleness rule, fail-closed integrity and `ansible-inventory --list` (Task 4, PR #44),
  plus the Ansible job context and **Test pull** (Task 5, PR #45).
- nginx dump parser with D3 include attribution and the 85 % `app/ansible/parse_*` coverage gate
  (Task 6, PR #46); read-only Apache collector (Task 7A, PR #47) and parser (Task 7B, PR #48).
- Discovery binding assembly with D1 signature-based chain roles, the fixed `chain_diagnostic` texts
  and the D2 DER key-hash round trip (Task 8A, PR #49), and `discover.yml` with per-host §6.2
  documents, the certificate transport via `openssl crl2pkcs7 | openssl pkcs7`, and the static
  playbook rules (Task 8B, PR #50).
- Reconciliation into servers/bindings/endpoints with `audit_binding_state`, derived endpoints,
  cross-server alias ownership and the zero-binding `parse_suspected` guard (Task 9, PR #51).
- `discover/default` with the nightly `discovery` schedule (03:00 UTC default), per-host retries
  (unreachable only, 3 attempts at 30/120 s; `auth` never retried) and the Servers discovery actions
  (Task 10, PR #52); the discovery screens, unknown-certificate list, dump summary and capability
  banners (Task 11, PR #53).
- Rollout planning, incremental batch execution and D1 file-write planning (Task 12, PR #54); the
  preview with `plan_sha256`, guardrails, trust gate and audited enqueue (Task 13, PR #55).
- `deploy.yml` preflight and backup without a live write, with host-outcome mapping (Task 14,
  PR #56); the write path with config test, reload, verification, a single-attempt rollback and
  backup pruning (Task 15, PR #57).
- `deploy/default`: per-host locks, batched execution, stop at the first failure, row bookkeeping
  and the `mark_deployed` success hook (Task 16, PR #58); canary pause, Continue, Cancel, pause
  expiry and single-host retry (Task 17, PR #59), with the completion-log correction PR #60.
- Deploy job screen and live progress (Task 18, PR #61); deploy start screen, registry registration,
  navigation and certificate deploy panel (Task 19, PR #62), with the job-level failure reason
  PR #63.
- §10.4 acceptance against the container targets and the real-host operations runbook
  `docs/operations.md` §11–§12 (Task 20, PR #64).
- Test-only: deterministic parse-chain assertions (PR #65).

**Documentation**

- `README.md`, this changelog, and the Plan 3 developer notes in `docs/development.md` (PR #66).
- `docs/operations.md` §12.2 clarifies the two-host `grep` spot-check and the mandatory PFX round
  trip of the §10.4 acceptance (PR #66).

**Operator interface (PRs #70–#75)**

- A design system for the operator UI: `docs/ui/design-system.md` and the tokens in
  `app/static/app.css` (dark root theme with a light-mode override, no web fonts, no build step),
  applied to the sign-in, account and error surfaces (PR #70), with a per-area stylesheet hook for
  the page stylesheets that followed (PR #71).
- Overview, Account, Users and Audit rebuilt around what an operator reads first: expiry buckets,
  worker and inventory state, TLS health, MFA state and the audit filters (PR #72).
- Certificate inventory, renewals, import and Scans: status badges with days remaining, chain and key
  columns, the upload and pull forms, the renewal step list and the scan history (PR #73).
- Servers, bindings and discovery: discovery evidence, parse warnings, drift and the binding help
  page (PR #75).
- Deploy: guardrail state, the plan preview, the confirmation checkbox, rollout progress and per-host
  outcomes (PR #74).
- Settings keep unsaved drafts in the browser tab through `app/static/settings.js`, which never
  persists a secret, a key, a token or a repository URL (PR #74).
- 69 rendered previews of every screen under `docs/ui/previews/`, regenerated with
  `python -m scripts.render_previews`; `tests/test_ui_previews.py` fails when they drift from the
  templates (PRs #70–#75).

### Changed

- `README.md` rewritten around the product, the interface and the operator path, with screenshots
  rendered from `docs/ui/previews/` and stored under `docs/screenshots/` (PR #76).
- **Operator decisions D1–D3 (2026-10-25) are recorded and the spec is corrected.** D1: certificate
  chain roles are decided per file by signature verification, never by position or DN equality, so a
  same-CA RSA+ECDSA pair is two bindings; D2: key identity is the SHA-256 of the DER
  `SubjectPublicKeyInfo`, so the host command uses `-outform DER` and round-trips with
  `private_key.public_key_sha256`; D3: TLS material is read both inline and from included files, with
  Apache always unioning `apachectl -S` and the recursive `Include` tree and nginx relying on
  `nginx -T`'s own file markers. Spec §6.2 and Plan 3 Contract decision 9 / open questions carry the
  decision labels and summaries.
- **`ANSIBLE_SSH_ARGS` in `docker-compose.credentials.yml` is no longer read.** The Ansible runner
  builds the child environment from scratch with its own stricter
  `StrictHostKeyChecking=yes`/`UserKnownHostsFile`/`IdentitiesOnly=yes`/`BatchMode=yes` values;
  change host-key checking in `known_hosts`, never in that variable.
- `docs/operations.md` §11.1 now states the seeded `discovery.nightly_at` default (03:00 UTC) that
  `app/services/settings.py` and the migration actually use.

### Security

- No plaintext secret is stored in the database or rendered in the web interface: private
  keys and TOTP seeds live in PostgreSQL only as row-bound AES-256-GCM ciphertext under a
  versioned keyring read from a file secret, and the SMTP password appears only as
  secret-presence metadata. The master key itself never enters the database.
- File-held operational credentials — `master_key`, `session_secret`, `db_password`,
  `db_owner_password` and the optional worker credentials — exist only as read-only file
  mounts with fixed owners and modes; they are never taken from argv, compose values,
  environment listings, logs or audit details, and are read once at startup.
- The audit log is append-only: the application role cannot `UPDATE`, `DELETE` or
  `TRUNCATE` it, and owner-level mutation is blocked by triggers. Audit writes share the
  caller's transaction, so a rolled-back operation leaves no audit row.
- Row-bound AAD ties each ciphertext to its row identity and key version; rotation
  re-encrypts in audited batches of 100 and prints counts and digests only.
- Uploaded PFX bundles and encrypted PKCS#8 keys are parsed in a child process with a
  1 MiB input cap, a 10-second wall clock, 5-second CPU and 512 MiB address-space limits;
  only typed error codes cross back to the parent.
- Uploads are parsed by content rather than filename; blocking errors are aggregated and
  sanitized, and parsed key material is never echoed back into a form.
- Pull import accepts a host literal and a port only — no URL, path, credentials or network
  range — and never reports the raw error returned by the peer.
- PFX export always re-authenticates the signed-in user (counting toward the same lockout)
  and writes nothing to disk; PEM private-key export is deliberately not offered.
- Trust anchors must be self-signed CA roots with `CA:TRUE` and certificate-signing key
  usage; leaf certificates and intermediates are refused, and every add/remove/toggle
  rechecks stored chain statuses inside the same audited transaction.
- The settings URL validator rejects repository URLs that carry credentials, tokens, query
  strings or fragments, so a secret cannot be persisted through a configuration field.
- Session security: CSRF on every non-GET request, session-ID and CSRF rotation on sign-in
  and privilege changes, 10-minute pending-MFA sessions with no admin authority, and the
  last active administrator cannot be deactivated.
- Scanning observes and never trusts: what an endpoint serves is recorded in `scan_result` only, is
  never imported or matched into inventory, and `chain_status` changes only through an explicit trust
  recheck. Concurrency (20 connections), the per-endpoint timeout and per-endpoint retries keep a
  hostile or broken target from affecting the rest of the scan.
- The SMTP password exists only as the worker file secret `smtp_password`; the web process never
  loads it and never opens an SMTP connection. AUTH is attempted only over STARTTLS or SSL/TLS, a
  STARTTLS server cannot make the client downgrade to plaintext, and SMTP outcomes keep only fixed
  step names and numeric reply codes — no reply text, exception text, TLS reason or AUTH challenge is
  stored, logged or rendered, so a relay that echoes a credential cannot leak it.
- Mail goes only to resolved recipients: expiry alerts are addressed to `certificate.owner_email`
  first and then `alert.recipients` (deduplicated), while the daily digest is addressed to
  `alert.recipients` only and has no owner fallback. The ledger's unique dedupe key plus row lock
  keeps a threshold from being announced twice; delivery is at-least-once by design and documented
  as such.
- Discovery is read-only on the target: the playbooks write no file and reload no service, and
  `become` is used only to read root-owned configuration, certificates and keys. Raw dumps can
  contain the target's own inline credentials, so they stay on the worker's artifacts volume
  (`0600`, 30-day cleanup) and are never served to the browser.
- Ansible and SSH credentials are file-only: `ansible_ssh_key`, `known_hosts`/`SSH_KNOWN_HOSTS`, the
  optional vault password and the optional Git token never appear in argv, extra-vars,
  `ansible-runner` artifacts, job payloads/results/errors, audit details or logs. Keys reach Ansible
  and `git` as `0600` files in the tmpfs staging area and are removed in `finally`; a missing
  `known_hosts` fails discovery and deployment closed before any connection.
- Every deploy host write is preceded by a backup (`/var/backups/cert-dashboard/<job_id>/`, root
  `0700`, key backups `0600`, `manifest.json`) and any failure from the first write through
  verification triggers exactly one automatic rollback of every manifest path. The trust override is
  audited as `deploy.chain_override` and never bypasses key presence/match, leaf validity, drift or
  the config test; deploy jobs are never retried automatically.
