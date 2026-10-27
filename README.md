# cert-dashboard

An internal dashboard for keeping track of the TLS certificates an organisation owns: import
them, see what expires next, watch what the registered endpoints actually serve, mail the
people who need to know, run a manual-CA renewal from CSR to an issued, deployment-ready
certificate, and download audited copies of the material when a server needs it. It runs as
one Compose stack on a single internal Docker host, talks to no external service, and stores
private keys and TOTP seeds encrypted under a keyring the operators hold.

## Status

| Plan | State |
| --- | --- |
| Plan 1 — core (Tasks 1–23) | Merged on `main` (PRs #1–#17) |
| Plan 2 — TLS observation, scanning and alerts (Tasks 1–17) | Merged on `main` (PRs #21–#38) |
| Plan 3 — server discovery and automated deploy | Not started |

Working today: certificate inventory, upload and pull import, TLS scanning of registered
endpoints with classified results and history, the daily background trust recheck, expiry
alerts and a daily digest over SMTP, the renewal wizard up to issued, audited downloads,
audit browser, users/MFA, typed settings, the job queue, the worker and its scheduler, and the
Scans, Servers, Bindings and Overview screens. Every control owned by Plan 3 — discovery,
deployment, the inventory revision and *Test pull* — renders disabled together with the reason.

## Architecture

- `web` — FastAPI/Uvicorn on `127.0.0.1:8000`: server-rendered Jinja2 with a locally
  served htmx, PostgreSQL-backed sessions and CSRF on every mutating request.
- `worker` — `python -m app.jobs.worker`: four job slots, a 30-second heartbeat, the
  scheduler, retention cleanup, the worker-side pull import, TLS scanning (20 connections in
  flight), the background trust recheck, and worker-only SMTP delivery for expiry alerts and
  the digest.
- `db` — PostgreSQL 16 holding inventory, jobs, users and the append-only audit log;
  private keys and TOTP seeds are stored encrypted.
- One image (`cert-dashboard:local`) runs both `web` and `worker`; `migrate` is a separate
  one-shot Compose profile service that only receives the database owner password.
- The host owns what the application deliberately does not: TLS termination and the front
  proxy in front of `web`, `pg_dump` backups, the off-host copies of the master key and the
  SMTP relay.

## Quick start

Requirements: Docker Engine with the Compose plugin, a Linux host, and root access for the
one-time secret provisioning. Full prerequisites, secret ownership/modes, backup and
rotation procedures live in [`docs/operations.md`](docs/operations.md).

```sh
# 0. Build the runtime image used by every compose command below.
docker build -t cert-dashboard:local .

# 1. Generate the first master key and install it 0400 10001:10001 (see
#    docs/operations.md §2.1 for the digest-verified container recipe), provision
#    session_secret, db_password and db_owner_password, then canonicalise ownership.
sh scripts/install-secrets.sh /etc/cert-dashboard/secrets

# 2. Start the database and apply the schema with the owner-only migrate service.
docker compose up -d db
docker compose --profile migrate -f docker-compose.yml -f docker-compose.migrate.yml run --rm migrate

# 3. Create the first administrator. Run interactively: the password is typed at the
#    prompt and never reaches argv, logs or the audit row.
docker compose run --rm web python -m app.cli bootstrap-admin --username admin --email admin@example.internal

# 4. Start the application and sign in at http://127.0.0.1:8000/ (or through your proxy).
docker compose up -d web worker
```

After signing in, enroll TOTP on the Account page, import the first certificate, then
check **Settings → Status**: the worker must be `ok`, the keyring SHA-256 must match the
fingerprint you recorded, and there must be no missing-key-version warning.

## What it does

**Inventory.** Import PEM/CRT/PFX bundles by upload (1 MiB per file, PFX parsed in a
resource-limited child process) or pull the chain a host actually serves from
`host:port`. Certificates are deduplicated by SPKI hash, keys are attached to the
existing row instead of duplicated, renewal lineage is tracked, and every stored chain
is assessed against internal trust anchors plus the pinned public bundle.

**Observe what is served.** Register `host:port` (plus an optional SNI name) endpoints on the Scans
screen and the worker connects to each on the daily schedule or on demand, with a 10-second
`scan.timeout_seconds` deadline and at most 20 connections in flight. Every attempt records one
classified result — `ok`, `mismatch`, `expired`, `unreachable` or `error` — with the served
fingerprint, common name, issuer, expiry, TLS version, chain length and elapsed time; the last 20 are
browsable per endpoint and an unreachable endpoint is retried alone, at most three times, without
re-scanning the healthy ones. Observed certificates are **never imported, matched into inventory or
trusted**: scanning only records what the endpoint serves, and the expected certificate is snapshotted
into each result. A daily background recheck keeps the stored trust paths current, and the Settings
status page shows any chain that stopped being trusted.

**Alert and digest.** Each active certificate is watched against `alert.thresholds_days`
(60/30/14/7/1/0 by default): the smallest crossed threshold produces exactly one e-mail per
certificate and threshold, addressed to the certificate's owner first and then the team list, listing
the certificate facts, its active bindings and its renewal state. A `notification_log` ledger with a
unique dedupe key, a row lock and three bounded attempts (30 s and 120 s backoff) makes delivery
idempotent, and a scheduler tick step sweeps the failures of the day. A daily digest lists the
expiring, expired, new TLS mismatches, unknown certificates, stale servers, failed jobs, rolled-back
hosts and failed notifications plus the inventory revision — and is sent even when there is nothing to
report. Mail leaves the worker only, over STARTTLS, SSL/TLS or plaintext as configured, and AUTH is
attempted only over TLS.

**Find and inspect.** The Overview shows disjoint expiry buckets (expired, < 7, 7–< 30,
30–< 60 days) with setup guidance when the inventory is empty, plus TLS health, recent jobs, renewals
in flight and a status strip. The certificate, Scans, Servers and Bindings lists have filters, sorting,
bookmarkable queries, 1–100 rows per page and a JSON export; the certificate detail page shows public
fields, key presence/public fingerprint, related audits, lineage, chain status warnings, its endpoints
panel and editable metadata.

**Renew, up to issued.** A resumable manual-CA wizard walks through CSR generation (RSA
2048/3072/4096 or ECDSA P-256/P-384, RSA 2048 by default), download of the CSR, submission to
the CA, and upload of the issued PEM with optional chain; it then stops at **issued / ready to
deploy**. The issued-certificate gate checks key **and** CSR SPKI, CN/SAN set and validity
before accepting. The state machine continues to `deployed` and `done` and both service hooks
exist (`mark_deployed` verifies deploy-job and binding evidence, `finalize` changes the previous
certificate's status), but Plan 1 registers no deploy handler, so a renewal cannot leave
`issued`: deployment and finalisation, including the previous-certificate status change, are
gated until Plan 3. The ready page says so and offers no manual "deployed" button.

**Export.** Leaf, chain and full-chain PEM downloads and a password-protected PFX export
are audited. The PFX is rebuilt in memory after you re-enter your own password; nothing is
written to disk and no PEM private-key export exists.

**Administer and observe.** Users (local, admin), TOTP MFA with single-use recovery
codes, login lockout, the read-only audit browser with JSON export, typed settings across
seven configuration tabs, trust-anchor management, a status snapshot and a
confirmation-gated maintenance prune.

**Run jobs.** A PostgreSQL `SKIP LOCKED` queue with per-type retry policy, a timeout
reaper and stale-owner fencing; a worker with heartbeat, `/healthz` and a stale-worker
banner; daily UTC schedules for the endpoint scan and trust recheck (02:00), the retention
cleanup (04:00), the expiry check (07:00) and the digest (07:30), each with its own
time/enable setting.

## Security posture

- **File secrets only.** `master_key`, `session_secret`, `db_password`,
  `db_owner_password` (and the optional worker credentials) are read-only file mounts with
  fixed owners and modes; they are never placed in the database, a compose value, an
  environment listing or the web UI, and they are read once at startup.
- **Encrypted key material.** Private keys and TOTP seeds are AES-256-GCM encrypted with a
  row-bound AAD under a versioned keyring; rotation re-encrypts in audited batches and the
  CLI prints counts and digests only.
- **Audited everything.** The audit log is append-only for the application role, audit
  writes share the mutation's transaction, and exports/downloads are recorded
  (`certificate.download`, `key.export`, `key.export_failed`, `renewal.csr_download`).
- **Bounded input.** 4 MiB request bodies, 1 MiB per uploaded object, strict parsing, and a
  PFX reader that runs in a child process with CPU, memory and wall-clock budgets.
- **Hardened runtime.** Containers run as UID 10001 with a read-only root filesystem,
  dropped capabilities, `no-new-privileges`, `noexec` `/tmp` and a private tmpfs for
  decrypted key material that is wiped at worker startup.
- **No secret in a log.** Structured request logs carry route, status and request ID, never
  URLs with query strings, cookies, bodies or exception text; the same redaction covers
  audit details.
- **Observed, never trusted.** A scan records what an endpoint serves and changes nothing else:
  the served certificate is never imported, matched into inventory or trusted, and `chain_status`
  changes only through an explicit trust recheck.
- **Mail credentials stay in the worker.** `smtp_password` is a worker-only file secret; the web
  process never loads it and never opens an SMTP connection, AUTH runs only over STARTTLS or SSL/TLS,
  a STARTTLS server can never make the client fall back to plaintext, and SMTP failures are kept as
  fixed step names plus numeric reply codes — no peer reply text, exception text or AUTH challenge is
  stored, logged or rendered.

## Documentation

- [`docs/operations.md`](docs/operations.md) — install, secrets, migrate, backup/restore,
  master-key rotation, operational signals, Settings tabs.
- [`docs/development.md`](docs/development.md) — checkout and test commands, web modules,
  job queue/worker internals, isolated PFX parsing, test fixtures.
- [`docs/superpowers/specs/2026-10-19-cert-dashboard-design.md`](docs/superpowers/specs/2026-10-19-cert-dashboard-design.md)
  — the normative design (sections cited throughout the code).
- [`docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`](docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md)
  — the executed Plan 1 task list and its contract decisions.
- [`docs/superpowers/plans/2026-10-25-cert-dashboard-plan-2-tls-scan-and-alerts.md`](docs/superpowers/plans/2026-10-25-cert-dashboard-plan-2-tls-scan-and-alerts.md)
  — the executed Plan 2 task list (scanning, alerts, digest, screens).

## Development

Python 3.12 with `uv`. `tests/unit` needs no database and no network; its `test_topology`
cases (27) additionally need a reachable Docker daemon, so the local gate filters them.
Integration tests need Docker — PostgreSQL Testcontainers plus the `targets` profile of
`docker-compose.test.yml` — and run in CI.

```sh
uv sync --frozen
uv run ruff check .
uv run pytest -q tests/unit -k 'not test_topology'
```

The complete command set, including the coverage gates and the container smoke test that
CI runs, is in [`docs/development.md`](docs/development.md#development-and-container-setup).
