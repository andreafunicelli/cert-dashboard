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
- Resumable manual-CA wizard: prefill, CSR download, CA checklist, submitted/issued steps,
  persisted trust warnings, non-JS and htmx paths, and finalisation with previous-certificate
  status change.
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

**Documentation**

- `README.md`, this changelog, and the Task 12–23 operational and developer notes in
  `docs/development.md` (this PR).

### Security

- No secret is stored in the database or rendered in the web interface: private keys and
  TOTP seeds are AES-256-GCM encrypted under a versioned keyring read from a file secret,
  and the SMTP password appears only as secret-presence metadata.
- Secrets exist only as read-only file mounts with fixed owners and modes; they are never
  taken from argv, compose values, environment listings, logs or audit details, and are
  read once at startup.
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
