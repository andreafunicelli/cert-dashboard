# Development and container setup

Python 3.12 and uv 0.13.1 run the pinned dependencies in `uv.lock`.

Installation, upgrade, backup and rotation procedures for a deployed host live in
[`operations.md`](operations.md); this page covers the checkout, the test suite and the
internals a developer touches. The normative design is
`docs/superpowers/specs/2026-10-19-cert-dashboard-design.md`; the task-by-task history is
`docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`.

```sh
uv sync --frozen
uv run ruff check .
docker compose -f docker-compose.test.yml pull db
docker build --target test -t cert-dashboard:test .
docker build -t cert-dashboard:local .
uv run pytest -q --cov=app --cov-report=term-missing --cov-report=json
uv run coverage report --fail-under=85 --include='app/crypto/*'
uv run pip-audit
docker compose -f docker-compose.test.yml config --quiet
docker run --rm cert-dashboard:test pytest -q tests/unit -p no:cacheprovider
```

On Windows, use WSL's Linux Docker engine for authoritative tests. Keep its uv
environment outside the Windows checkout so Linux and Windows venvs stay distinct:

```sh
cd /mnt/c/Users/afunicelli/cert-dashboard
UV_PROJECT_ENVIRONMENT="$HOME/.venvs/cert-dashboard" uv run pytest -q
```

Host tests exercise Docker Compose rendering and isolated container permissions;
they require both images built above. Integration tests start one PostgreSQL 16
Testcontainers instance, apply the single v1 migration as db_owner, and roll back
app_role transactions per test. A separate isolated Compose project verifies the
real migrate command and `alembic check`, then removes only its own DB volume.
Docker-CLI checks skip inside the application test image, which has no host Docker socket or CLI. Its CI smoke
command runs only tests/unit; the full suite runs on the Docker-enabled host.
Unit tests do not contact network services. Prepare images/dependencies before running tests.

The v1 database schema, owner migration path, runtime readiness checker, web
foundation, sign-in/MFA flow, account-security forms, certificate inventory,
renewal workflow, audit browser, user administration and typed settings are
implemented, together with the transactional job queue and the worker runtime.
The test Compose app runs unit smoke checks after its owner-only migrate service
completes; the full integration suite runs on the Docker-enabled host.

The Docker-dependent topology tests (rendered Compose files, the pinned `pg_dump`
client, the isolated secrets installer and the database bootstrap) need a
reachable Docker daemon; without one they fail while the remaining `tests/unit`
modules still pass. GitHub CI is authoritative for them and for every integration
test.

## Web modules and routes

`create_app()` in `app/main.py` builds the application: it adds the `_WebFoundation`
middleware (session resolution, CSRF, 4 MiB body limit, request ID, redacted
structured logs, stale-worker probe), mounts `/static`, registers the health probes
and then calls one `register_<area>_routes(app)` per module in `app/web/`. Route
modules own HTTP concerns only — forms, CSRF, redirects, template context; business
rules and transactions live in `app/services/`.

| Module | Owns | Integration tests |
| --- | --- | --- |
| `app/web/overview.py` | `GET /` — expiry buckets and the setup empty state | `test_inventory_http.py` |
| `app/web/certificates.py` | `/certificates`, `/certificates/export.json`, detail, edit, status and chain forms, `leaf.pem`/`chain.pem`/`fullchain.pem`, `export.pfx`, upload import, pull-import route and `/imports/{job_id}` progress | `test_inventory_http.py`, `test_upload_import.py`, `test_pull_import.py`, `test_downloads.py` |
| `app/web/renewals.py` | `/renewals/{id}` wizard: edit, generate CSR, `csr.pem`, submit, issued, finalize, cancel | `test_renewal_wizard.py` |
| `app/web/audit.py` | `/audit` browser and `/audit/export.json` | `test_audit_http.py` |
| `app/web/users.py` | `/users` administration, password and TOTP resets, deactivation | `test_users_http.py` |
| `app/web/settings.py` | `/settings` — seven configuration tabs plus trust anchors, status and maintenance | `test_settings_http.py` |
| `app/web/common.py` | `require_user`/`require_admin`, error rendering, login rate limit — no routes | every module above |

`_register_auth_routes(app)` in `app/main.py` owns `/login`, `/login/2fa`, `/logout`
and `/account` (tests: `test_login_account.py`, `test_sessions_http.py`).

## Jobs, scheduler and worker

### Queue

`app/jobs/queue.py` is the only module that writes job state:

- `enqueue(db, job_type, payload, actor, priority=..., run_after=..., max_attempts=...)` inserts a
  `queued` row and its `job.enqueue` audit row in the caller's transaction. Payloads must be plain
  JSON (no bytes); nothing secret belongs in a payload, result or error.
- `claim(db, worker_id, now, timeout_seconds, eligible_types=...)` takes one due job with a single
  `UPDATE ... RETURNING` over a `FOR UPDATE SKIP LOCKED` pick ordered by `priority DESC, run_after,
  created_at, id`, and sets `timeout_at` inside the same transaction. Pass `eligible_types` when the
  worker cannot run every type: an unclaimable job must stay queued, never be claimed and released.
- `finish(db, job_id, worker_id, status, now, ...)` writes `succeeded`/`failed`/`cancelled` only while
  the row is still `running` under this `locked_by`. A reaped or re-claimed job raises
  `StaleJobError`, so a slow worker cannot overwrite another owner's result.
- `reap(db, now)` fails `running` rows past `timeout_at` (with `job.timeout` and the job's running
  hosts as `worker_lost`); `retry_due(db, now)` requeues retryable failures whose backoff elapsed.
  Both run on every scheduler tick.
- `RETRY_POLICY` is the single source of truth: discover and scan 3 attempts on `transient_network`,
  alert/digest 3 on `smtp_transient`, cleanup 2 on `transient_network`/`operational`, deploy 1. The
  30/120/300 s ladder is capped by those totals, so 300 s is never used. `auth`, `validation`,
  `config_invalid`, `key_unwrap`, `internal` and `timeout` never retry automatically, so a reaped
  job stays failed.

### Registry and payloads

`build_registry()` in `app/jobs/handlers/__init__.py` returns a fresh, side-effect-free
`JobRegistry` (in `app/jobs/worker.py`) keyed by `(JobType, action)`. `register()` refuses duplicate
registrations and requires a payload validator. `dispatch()` runs validator then handler and maps
every failure to a closed class: malformed or unknown `(type, action)` and validator rejections are
`validation`, a `KeyUnwrapError` is `key_unwrap`, and any other exception is logged by class name only
and reported as `internal`.

Today the registry holds `cleanup/default` and `scan/import_pull`; `scan/default` arrives with Plan 2
and `deploy/*` with Plan 3. The web application calls `build_registry()` too, but only to gate
navigation and controls on registered capabilities — the worker is the only dispatcher.

### Scheduler

Only the worker schedules. It holds a dedicated advisory-lock connection
(`pg_try_advisory_lock(hashtext('scheduler'))`) for its lifetime, and `scheduler_tick()` runs on the
same 30-second tick as the heartbeat. Each tick, for every `SCHEDULES` entry whose handler is
registered:

1. reads `<key>.daily_at` (UTC `HH:MM`) and `<key>.enabled` from `app_setting`; a malformed time or
   `enabled = false` skips the run;
2. takes the `scheduler_state` row lock and compares `last_run_at` with the latest `HH:MM` occurrence,
   so concurrent schedulers enqueue at most once per occurrence (the loser re-reads the winner's
   value);
3. skips an occurrence missed by `MISSED_RUN_LIMIT` (12 hours) or more, logging `schedule_missed` and
   still advancing `last_run_at`, so a long outage produces no burst of catch-up jobs;
4. enqueues the job, then runs `reap` and `retry_due` in their own transactions.

`cleanup` is the only schedule registered today: `cleanup.daily_at` defaults to `04:00` UTC and
`cleanup.enabled` to `true`. It deletes finished jobs and their `job_host` rows older than
`retention.days` (default 90), scan results older than 90 days, expired/idle (> 8 h)/revoked sessions,
login counters older than one day, and artifacts older than 30 days under `artifacts_root`. It never
touches `audit_log`, queued or running jobs, key material or key staging. The same handler runs for
the **Settings → Maintenance** prune (`reason = "manual_prune"`).

### Worker process

Compose starts the worker with `python -m app.jobs.worker` (the `worker` service). Settings come from
the `DB_*` environment plus the file secrets in `/run/secrets`. Unlike the CLI, the worker entry point
hard-codes that secret directory. Relevant knobs:

| Setting | Default | Meaning |
| --- | --- | --- |
| `WORKER_CONCURRENCY` | 4 | slots, i.e. maximum concurrently running jobs |
| `MAX_PARALLEL_JOBS` | 2 | cap on `discover`/`scan` jobs among those slots; the rest stay queued |
| `ansible_ssh_key` (secret) | absent | `ssh_available`; without it `discover` and `deploy` are never claimed |

The process wipes `key_staging_dir` (`/run/cert-keys`, a tmpfs) before anything else; a symlinked or
non-removable directory refuses startup rather than keeping leftover key material. Worker ID is
`hostname:pid:boot-uuid`. Exit codes: `0` clean stop, `1` unsafe key staging directory, `2`
configuration error.

Start it, follow it and restart it with:

```sh
docker compose up -d worker
docker compose logs -f --tail 100 worker
docker compose up -d --force-recreate worker
```

Running it outside Compose needs `/run/secrets` populated — the worker entry point hard-codes that
path, while only the CLI honours `SECRETS_DIR` — plus reachable `DB_*` settings and a writable
`/run/cert-keys`. In the checkout the supported way to exercise it is the test harness:
`make_worker`/`worker_harness` build a `Worker` over the integration database with an injected clock
and drive `tick()`, `poll()` and `run_queued()` directly.

Because discovery and deploy handlers are not registered yet, the default worker runs cleanup jobs
and at most `MAX_PARALLEL_JOBS` (2) concurrent pull imports inside its four slots.

### Shutdown and in-flight writes

`Worker.close()` stops claiming, drains running jobs within `MAX_DRAIN_SECONDS` (23 s) and then waits
at most `COMMIT_SETTLE_SECONDS` (2 s) for a `COMMIT` already underway — `MAX_GRACE_SECONDS` = 25 s in
total. A job whose `COMMIT` has already passed the last abandonment fence can therefore finish
**after** `close()` returns. That is an accepted, documented exception; the database statement and
commit timeouts bound its window. Jobs abandoned before the fence are collected by the reaper and
write nothing (no `job.succeeded`, no result). An absolute "no write after `close()`" guarantee is
deliberately **not** provided: it would need a persisted abandonment marker and a conditional
`UPDATE` in `_finish`.

### Health endpoints

| Endpoint | Body | Used by |
| --- | --- | --- |
| `GET /health/live` | `{"status": "ok"}` | process liveness |
| `GET /health/ready` | `{"status": "ok"}`; `503` while the database is unreachable | database readiness |
| `GET /healthz` | `{"web": "ok", "worker": "ok"\|"stale", "db": "ok"}`; `503` with `{"web": "ok", "worker": "unknown", "db": "unavailable"}` and `Retry-After: 5` while the database is unreachable | Compose `web` healthcheck, operators |

`worker` is `stale` when the newest `worker_heartbeat.last_seen_at` is more than five minutes old or
no heartbeat exists (`worker_liveness`, `LIVENESS_WINDOW`). The page banner calls the same function and
caches the answer for 30 seconds; the compose `worker` healthcheck applies the same five-minute rule
with its own query. All three probes are public paths and skip the per-request worker probe. Operator
procedures for these signals are in [`docs/operations.md`](operations.md#8-operational-signals).

## Isolated key and PFX parsing

Every upload is capped at `MAX_INPUT_BYTES` (1 MiB, `app/crypto/parse.py`), but a few hundred bytes of
PKCS#12 can pin an enormous KDF iteration count, so the cap alone does not bound the work. Password-
protected PFX bundles and encrypted PKCS#8 keys are therefore parsed in a fresh child interpreter
spawned by `app/crypto/pfx_isolated.py` (`app/crypto/pfx_child.py` runs inside it):

- the parent enforces a 10-second wall clock (`PFX_TIMEOUT_SECONDS`);
- the child sets its own CPU (`5 s`) and address-space (`512 MiB`) rlimits;
- password and bundle travel over stdin as length-prefixed frames; the child gets a minimal
  environment and its stderr is discarded;
- only typed, sanitized codes (`invalid_password`, `unsupported_encryption`, `key_mismatch`, …) cross
  back to the parent, which renders them; a killed or crashed child becomes a fixed budget message.

`tests/unit/test_pfx_isolated.py` exercises the real child and the `tests/fixtures/*_pfx_child.py`
stubs (`stalled`, `crashing`, `garbage`, `cpu_limited`); `PFX_CHILD_MODULE` is module-level so a test
can substitute one.

## Test fixtures

`tests/conftest.py` provides `secret_files`, `now` and the session-scoped `certs` (generated chain and
keys). `tests/integration/conftest.py` builds everything else:

| Fixture | Purpose |
| --- | --- |
| `database_urls`, `alembic_config`, `owner_engine`, `engine`, `db` | one PostgreSQL 16 Testcontainers instance, migrated once; app-role transactions roll back per test |
| `actor`, `now`, `clock` | audit actor and the injected clock every time-sensitive test advances |
| `web_factory`, `web_user`, `web_settings`, `web_app`, `client`, `signed_in`, `csrf` | the real application over `TestClient` |
| `plain_user`, `totp_user`, `create_login_user` | sign-in and MFA variants |
| `queue_template`, `queue_factory`, `seeded_jobs` | the queue tests commit real data over several connections, so each gets a private database copied from a migrated template |
| `make_worker`, `worker_harness` | `Worker` instances on any session factory with an injected clock; `worker_harness` shares the web database and clears heartbeats |
| `tls_servers`, `tls_server`, `pull_certs` | loopback TLS listeners (`tls`, `silent`, `garbage`) serving a leaf plus intermediates, recording the SNI they receive |
| `ca`, `keyring`, `previous_certificate`, `submitted_renewal` | the fixture CA that issues from a generated CSR, plus renewal starting points |

`tests/fixtures/` holds the shared generators: `ca.py` (`FixtureCA.issue`), `certificates.py`
(`generate_certificates`) and the PFX child stubs above. Fixtures stay in memory; nothing is written
to the repository.

## Linux deployment secrets

Provision canonical files beneath `/etc/cert-dashboard/secrets` through the
operator's normal secure process: `master_key`, `session_secret`, `db_password`,
and a distinct `db_owner_password`. Never commit them. Worker credentials
`ansible_ssh_key`, `ansible_vault_password`, `inventory_git_token`, `smtp_password`
are optional; mount only the ones provisioned using the credentials override.

An administrator runs the following as root on the deployment host (the agent does
not elevate or touch production secrets):

```sh
sh scripts/install-secrets.sh /etc/cert-dashboard/secrets
```

The installer changes ownership/modes only, reads no values, and creates no copies:

| Object | Owner | Mode |
| --- | --- | --- |
| Secret directory | root:root | 0711 |
| App/worker secrets | 10001:10001 | 0400 |
| Shared `db_password` | 10001:999 | 0440 |
| `db_owner_password` | 999:999 | 0400 |

The directory permits traversal of known filenames, but not listing. Compose file
secrets are read-only bind mounts preserving these numeric owners/modes; `mode:`
does not remap them outside Swarm. The pinned Debian PostgreSQL 16 image uses
postgres UID/GID 999. The application runs as 10001; the dedicated one-shot
`migrate` service runs as 999 with DB-only configuration. Its sole secret is
`db_owner_password`, mounted at `/run/secrets/db_password`; no application secrets
are mounted. Normal web/worker never mount the owner password. Rotate a secret by
replacing it, reapplying the installer, then restarting
the affected service. Keep the master-key backup copies separate from DB backups.

Migrations use:

```sh
docker compose --profile migrate -f docker-compose.yml -f docker-compose.migrate.yml run --rm migrate
```

Use the credentials override only after provisioning its entries and
`/etc/cert-dashboard/known_hosts`; remove unused optional mounts first. SSH host
keys are pinned and strict checking is enabled.

The offline htmx asset is upstream v2.0.8 from
`https://github.com/bigskysoftware/htmx/tree/v2.0.8`, with its upstream license in
`app/static/htmx.LICENSE`; the bundled JS SHA-256 is
`22283ef68cb7545914f0a88a1bdedc7256a703d1d580c1d255217d0a50d31313`.


## Administrator bootstrap, sign-in and MFA

No web route creates the first administrator. After migrations, run the CLI in the
web service, which already mounts `master_key` and `db_password`:

```sh
docker compose run --rm web python -m app.cli bootstrap-admin --username admin --email admin@example.internal
```

The command reads the password twice with getpass, compares the two entries and exits
1 on mismatch. `BOOTSTRAP_ADMIN_PASSWORD` replaces both prompts; the CLI reads it once
and removes it from its process environment, so pass it as an environment variable and
never as an argument:

```sh
docker compose run --rm -e BOOTSTRAP_ADMIN_PASSWORD web python -m app.cli bootstrap-admin --username admin --email admin@example.internal
```

The password never reaches argv, stdout, logs or audit details; the audited
`user.bootstrap_admin` row records the username only. Bootstrap and password changes
share `hash_password`: at least 12 characters, at most 1024 UTF-8 bytes, and not in
the vendored top-1000 denylist (case-insensitive). A refused password exits 1 without
creating a user. Username and email are stripped, must be non-empty and at most 254
characters; a duplicate username is refused, and `user.username` is `citext`, so that
check is case-insensitive. The new account is an active local administrator with
`must_change_password` false.

With no active user, `GET /login` redirects once (303) to `/login?bootstrap=1`, which
shows the command above; there is no registration route. Once an administrator exists
the same URL renders the normal sign-in form.

`POST /login` requires CSRF, then consumes one PostgreSQL-backed attempt for the
source IP (UTC minute window, IPv6 /128): the sixth attempt within a minute returns 429
with `Retry-After: 60`. Unknown, wrong-password and inactive accounts all return the
same "Invalid credentials." message. Ten consecutive failures lock the account for 15
minutes; locked sign-in attempts return 423 with a distinct message. Successful sign-in
lands on `/` (`POST_LOGIN_URL`, the Overview); there is no `next` parameter, so no open
redirect, and an account flagged `must_change_password` is redirected from there to
`/account`. `POST /logout`
(CSRF required) revokes only the current session and clears the cookie.

Accounts with TOTP enabled get a pending session with no admin authority and a 303 to
`/login/2fa`, which accepts a TOTP code (SHA-1, 6 digits, 30-second step, ±1 step) or
one recovery code. Every code and time step is single use, and MFA failures share the
same lockout counter and IP rate limit. `/account` owns the security forms: password
changes, enrollment and disabling re-authenticate the current password, while
confirmation requires a TOTP code; a wrong current password counts toward the same
lockout counter. Enrollment renders the secret, provisioning URI and
ten recovery codes once in the POST response with `Cache-Control: no-store`, and
stores only the encrypted secret plus argon2 hashes of the codes; confirmation enables
TOTP; disabling requires the current password and deletes all TOTP material. Password
changes, TOTP enable/disable and enrollment restarts revoke every session and reissue
one for the acting browser, so other browsers must sign in again. The remaining
recovery-code count is shown on `/account`.

There is no self-service or email password reset; the sign-in page tells users to
contact another administrator. While `must_change_password` is set, `require_user`
allows only `GET /account`, `POST /account/password` and `POST /logout`; every other
route returns 403.

## Key custody and rotation

`python -m app.cli generate-master-key --version 1 --output /etc/cert-dashboard/secrets/master_key.v1.new`
needs no database or configured secrets. It creates a new file exclusively with
exact mode `0400` regardless of umask, writes canonical UTF-8 JSON plus LF, syncs
the file and parent directory, and prints
only its SHA-256 and path. Compare the reported hash with `sha256sum` of the file
before installing it with `install -m 0400 -o 10001 -g 10001 SOURCE DESTINATION`.
Run installation with host privileges that can set those owners. Existing output
paths and realpath aliases of the merge source are refused; symlink loops produce
configuration errors. A write/sync failure removes only the partial inode created
by this command. Spec section 11.2 includes the container-only bootstrap using a
0700 host directory owned by UID 10001, digest verification, installation and cleanup;
it works with a read-only container filesystem.

`--merge PATH` retains the previous version; the new version must exceed every
merged version, within `1..2147483647`, with at most two live versions. Without
`--output`, legacy stdout JSON remains available with a stderr warning; **never
redirect onto the --merge path**, because the shell truncates it before Python
can read it.

Follow spec section 11.5 for rotation: keep separate key backups, then generate
into a new file, verify the printed SHA-256 against `sha256sum`, and install it:

```sh
python -m app.cli generate-master-key --version 2 --merge /etc/cert-dashboard/secrets/master_key --output /etc/cert-dashboard/secrets/master_key.v2.new
sha256sum /etc/cert-dashboard/secrets/master_key.v2.new
install -m 0400 -o 10001 -g 10001 /etc/cert-dashboard/secrets/master_key.v2.new /etc/cert-dashboard/secrets/master_key
```

Force-recreate web/worker to reread secrets. Run `docker compose run --rm web python -m app.cli rotate-master-key`.
The CLI commits batches of 100 across keys and TOTP rows, prints remaining counts,
and audits counts only. A failed batch rolls back; restart the same command to
resume. A fresh final transaction checks stale rows and missing versions; a late
legacy writer makes the command fail with counts/versions only. Reload old writers
and rerun before retiring any version. `verify-key --certificate-id ID` checks the
decrypted key against both its stored public hash and the certificate and emits metadata only. Keep the previous
version until both stale-row counts are zero and one PFX export succeeds (Certificate detail →
Export PFX; the CLI rotation and verification steps are in
[`docs/operations.md`](operations.md#6-master-key-rotation)).

A missing referenced version is reported by `missing_master_key_versions` and
blocks dependent unwrap/rotation operations. Public inventory remains readable.
Rotation keeps plaintext in a one-row helper and never writes it to SQL or files.


## Web sessions and reverse proxies

Set `TRUSTED_PROXIES` to a comma-separated list of the actual reverse-proxy CIDRs
when needed. It defaults to empty; forwarded headers from every other direct peer
are ignored. For a trusted peer, the right-most untrusted X-Forwarded-For hop is
the client; malformed or all-trusted chains fall back to the peer. Prefer individual
proxy /32 or /128 addresses. Compose passes this setting only to web. Keep
`--no-proxy-headers --no-access-log` when starting Uvicorn manually, matching the
image/Compose commands: application middleware owns trust decisions and emits
structured request logs without raw URLs, query strings, cookies or exception text.

`create_app()` loads default secrets only in lifespan. Tests inject settings, a real
PostgreSQL session factory and clock before entering TestClient. The app exposes the
three health probes, `/static`, the `/login`, `/login/2fa`, `/logout` and `/account`
routes, and the route modules listed under *Web modules and routes* above. No
`/_test` routes ship in production. Reusable session rotation revokes the old ID and
replaces both ID and CSRF token. Pending MFA sessions last at most ten minutes and
confer no admin authority. Authentication completes only after the caller verifies its
factors.

Every non-GET requires session CSRF, or a signed ten-minute double-submit token
before authentication. Bodies are bounded to 4 MiB; multipart parts stay in memory.
Per-file 1 MiB limits remain the upload service's responsibility. Connection
acquisition retries once; request mutations and partially committed work never replay.
