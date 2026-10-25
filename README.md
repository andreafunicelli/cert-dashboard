# cert-dashboard

An internal dashboard for keeping track of the TLS certificates an organisation owns:
import them, see what expires next, run a manual-CA renewal from CSR to deployed
certificate, and download audited copies of the material when a server needs it. It runs
as one Compose stack on a single internal Docker host, talks to no external service, and
stores private keys and TOTP seeds encrypted under a keyring the operators hold.

## Status

| Plan | State |
| --- | --- |
| Plan 1 — core (Tasks 1–23) | Merged on `main` (PRs #1–#17) |
| Plan 2 — endpoint scans, expiry alerts, e-mail digest | Not started |
| Plan 3 — server discovery and automated deploy | Not started |

Working today: certificate inventory, upload and pull import, expiry overview, renewal
wizard, audited downloads, audit browser, users/MFA, typed settings, the job queue, the
worker and its scheduler. The Overview, the navigation and the detail page render every
control owned by a later plan as disabled together with the reason.

## Architecture

- `web` — FastAPI/Uvicorn on `127.0.0.1:8000`: server-rendered Jinja2 with a locally
  served htmx, PostgreSQL-backed sessions and CSRF on every mutating request.
- `worker` — `python -m app.jobs.worker`: four job slots, a 30-second heartbeat, the
  scheduler, retention cleanup and the worker-side pull import.
- `db` — PostgreSQL 16 holding inventory, jobs, users and the append-only audit log;
  private keys and TOTP seeds are stored encrypted.
- One image (`cert-dashboard:local`) runs both `web` and `worker`; `migrate` is a separate
  one-shot Compose profile service that only receives the database owner password.
- The host owns what the application deliberately does not: TLS termination and the front
  proxy in front of `web`, `pg_dump` backups, and the off-host copies of the master key.

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

**Find and inspect.** The Overview shows disjoint expiry buckets (expired, < 7, 7–< 30,
30–< 60 days) with setup guidance when the inventory is empty. The certificate list has
filters, sorting, bookmarkable queries, 1–100 rows per page and a JSON export; the detail
page shows public fields, key presence/public fingerprint, related audits, lineage, chain
status warnings and editable metadata.

**Renew.** A resumable manual-CA wizard walks through CSR generation (RSA 2048/3072/4096 or
ECDSA P-256/P-384, RSA 2048 by default), download of the CSR, submission to the CA, upload
of the issued PEM with optional chain, and finalisation. The issued-certificate gate
checks key **and** CSR SPKI, CN/SAN set and validity before accepting. There is no manual
"deployed" button: deployment belongs to Plan 3.

**Export.** Leaf, chain and full-chain PEM downloads and a password-protected PFX export
are audited. The PFX is rebuilt in memory after you re-enter your own password; nothing is
written to disk and no PEM private-key export exists.

**Administer and observe.** Users (local, admin), TOTP MFA with single-use recovery
codes, login lockout, the read-only audit browser with JSON export, typed settings across
seven configuration tabs, trust-anchor management, a status snapshot and a
confirmation-gated maintenance prune.

**Run jobs.** A PostgreSQL `SKIP LOCKED` queue with per-type retry policy, a timeout
reaper and stale-owner fencing; a worker with heartbeat, `/healthz` and a stale-worker
banner; a daily retention cleanup at 04:00 UTC.

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

## Documentation

- [`docs/operations.md`](docs/operations.md) — install, secrets, migrate, backup/restore,
  master-key rotation, operational signals, Settings tabs.
- [`docs/development.md`](docs/development.md) — checkout and test commands, web modules,
  job queue/worker internals, isolated PFX parsing, test fixtures.
- [`docs/superpowers/specs/2026-10-19-cert-dashboard-design.md`](docs/superpowers/specs/2026-10-19-cert-dashboard-design.md)
  — the normative design (sections cited throughout the code).
- [`docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`](docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md)
  — the executed Plan 1 task list and its contract decisions.

## Development

Python 3.12 with `uv`. The unit suite needs no network and no database; nine topology
tests additionally need a reachable Docker daemon, and integration tests need one for
PostgreSQL Testcontainers.

```sh
uv sync --frozen
uv run ruff check .
uv run pytest -q tests/unit
```

The complete command set, including the coverage gates and the container smoke test that
CI runs, is in [`docs/development.md`](docs/development.md#development-and-container-setup).
