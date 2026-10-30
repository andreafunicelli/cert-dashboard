# Development and container setup

Python 3.12 and uv 0.13.1 run the pinned dependencies in `uv.lock`.

Installation, upgrade, backup and rotation procedures for a deployed host live in
[`operations.md`](operations.md); this page covers the checkout, the test suite and the
internals a developer touches. The normative design is
`docs/superpowers/specs/2026-10-19-cert-dashboard-design.md`; the task-by-task history is
`docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`,
`docs/superpowers/plans/2026-10-25-cert-dashboard-plan-2-tls-scan-and-alerts.md` and
`docs/superpowers/plans/2026-10-25-cert-dashboard-plan-3-discovery-and-deploy.md`. Operator and
production procedures for discovery and deployment are in
[`operations.md` §11–§12](operations.md#11-discovery-and-deployment); this page keeps only the
developer view.

```sh
uv sync --frozen
uv run ruff check .
uv run pytest -q tests/unit -k 'not test_topology'   # the full local gate on a Docker-less machine
docker compose -f docker-compose.test.yml pull db
docker compose -f docker-compose.test.yml --profile targets pull tls-nginx tls-apache
docker compose -f docker-compose.test.yml --profile ssh-targets build ssh-nginx-1 ssh-apache
docker build --target test -t cert-dashboard:test .
docker build -t cert-dashboard:local .
uv run pytest -q --cov=app --cov-report=term-missing --cov-report=json --cov-fail-under=70
uv run coverage report --fail-under=85 --include='app/crypto/*'
uv run coverage report --fail-under=85 --include='app/ansible/parse_*'
uv run coverage report --fail-under=85 --include='app/services/renewals.py'
uv run coverage report --fail-under=85 --include='app/services/deploy.py'
uv run pip-audit
docker compose -f docker-compose.test.yml config --quiet
docker compose -f docker-compose.test.yml --profile targets config --quiet
docker compose -f docker-compose.test.yml --profile ssh-targets config --quiet
docker run --rm cert-dashboard:test pytest -q tests/unit -p no:cacheprovider
```

The last four coverage commands are the CI gates exactly as `.github/workflows/ci.yml` runs them:
the `renewals.py` and `deploy.py` gates are guarded by `[ -f … ]` so the step also works on a
checkout that predates those modules.

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
real migrate command and `alembic check`, then removes only its own DB volume. The
`targets` profile of `docker-compose.test.yml` adds real nginx and Apache TLS
servers plus an SMTP capture container for the end-to-end scan and mail tests (see
*Test targets and the SMTP capture server* below).
Docker-CLI checks skip inside the application test image, which has no host Docker socket or CLI. Its CI smoke
command runs only tests/unit; the full suite runs on the Docker-enabled host.
No test reaches the internet: unit tests use in-process loopback listeners
(`smtp_server`, Plan 1's `tls_servers`), and CI pulls the pinned target images
before pytest. Prepare images/dependencies before running tests.

The v1 database schema, owner migration path, runtime readiness checker, web
foundation, sign-in/MFA flow, account-security forms, certificate inventory,
renewal workflow, audit browser, user administration, typed settings, the
transactional job queue and the worker runtime are implemented. Plan 2 adds TLS
observation and scanning, the background trust recheck, worker-only SMTP delivery,
expiry alerts with a delivery ledger, the daily digest, and the Scans, Servers and
Bindings screens with the Overview slots that read them. Plan 3 completes v1 with
read-only server discovery, reconciliation into servers/bindings/endpoints,
canary-first certificate deployment with automatic per-host rollback, the Deploy
screens and the §10.4 acceptance harness; §11–§12 of
[`operations.md`](operations.md#11-discovery-and-deployment) are its operator view.
The test Compose app runs unit smoke checks after its owner-only migrate service
completes; the full integration suite runs on the Docker-enabled host.

The Docker-dependent topology tests (rendered Compose files with and without
`--profile targets` and `--profile ssh-targets`, the pinned `pg_dump` client, the
isolated secrets installer and the database bootstrap) need a reachable Docker
daemon; the `test_topology` cases (35 today, 20 of which fail without a daemon) fail
or skip without one while the remaining `tests/unit` modules still pass, so
`uv run pytest -q tests/unit -k 'not test_topology'` is the local gate. GitHub CI is
authoritative for them and for every integration test.

## Web modules and routes

`create_app()` in `app/main.py` builds the application: it adds the `_WebFoundation`
middleware (session resolution, CSRF, 4 MiB body limit, request ID, redacted
structured logs, stale-worker probe), mounts `/static`, registers the health probes
and then calls one `register_<area>_routes(app)` per module in `app/web/`. Route
modules own HTTP concerns only — forms, CSRF, redirects, template context; business
rules and transactions live in `app/services/`.

| Module | Owns | Integration tests |
| --- | --- | --- |
| `app/web/overview.py` | `GET /` — expiry buckets, TLS health, recent jobs, renewals in flight, status strip and the setup empty state | `test_inventory_http.py`, `test_overview_slots.py` |
| `app/web/certificates.py` | `/certificates`, `/certificates/export.json`, detail, edit, status and chain forms, `leaf.pem`/`chain.pem`/`fullchain.pem`, `export.pfx`, upload import, pull-import route, `/imports/{job_id}` progress, `POST /certificates/{id}/scan`, the detail page's endpoints panel and the certificate deploy panel (guardrail reason, recent deploys, link to `/deploy?certificate_id=…`) | `test_inventory_http.py`, `test_upload_import.py`, `test_pull_import.py`, `test_downloads.py`, `test_endpoints_http.py`, `test_deploy_start_http.py` |
| `app/web/renewals.py` | `/renewals/{id}` wizard: edit, generate CSR, `csr.pem`, submit, issued, finalize (now reachable from `deployed`), cancel | `test_renewal_wizard.py`, `test_deploy_start_http.py` |
| `app/web/scans.py` | `/scans`, `/scans/export.json`, `/scans/{id}`, `/scans/{id}/history`, `POST /scans/run` (`scope=all\|endpoint`), `POST /scans/endpoints`, `POST /scans/{id}/expectation`, `POST /scans/{id}/active` | `test_scans_http.py`, `test_endpoints_http.py`, `test_scan_targets.py` |
| `app/web/servers.py` | `/servers`, `/servers/export.json`, `/servers/{id}`, `/servers/{id}/dump`, `/bindings`, `/bindings/export.json`, `/bindings/help`; discovery actions `POST /servers/discover` (`scope=all\|group`) and `POST /servers/{id}/discover`, enqueue-only and CSRF-protected | `test_servers_http.py`, `test_bindings_http.py`, `test_discovery_screens.py`, `test_discovery_jobs.py` |
| `app/web/deploy.py` | `GET /deploy` (start screen), `GET /deploy/preview` (htmx fragment), `POST /deploy` (plan hash + confirmation), `GET /deploy/{job_id}`, `GET /jobs/{job_id}/progress`, `GET /deploy/{job_id}/report.json`, `POST /deploy/{job_id}/continue`, `POST /deploy/{job_id}/cancel`, `POST /deploy/{job_id}/hosts/{server_id}/retry` | `test_deploy_start_http.py`, `test_deploy_job_http.py`, `test_deploy_controls.py` |
| `app/web/audit.py` | `/audit` browser and `/audit/export.json` | `test_audit_http.py` |
| `app/web/users.py` | `/users` administration, password and TOTP resets, deactivation | `test_users_http.py` |
| `app/web/settings.py` | `/settings` — seven configuration tabs plus trust anchors, status and maintenance; `POST /settings/smtp/test` and `GET /settings/smtp/test/{job_id}` (test-send outcome fragment); `POST /settings/inventory/test-pull` and `GET /settings/inventory/test-pull/{job_id}` (Test pull and its fragment); `POST /settings/trust-anchors/recheck`; the Alerts tab's failure list and the Status tab's SMTP panel | `test_settings_http.py`, `test_smtp_test_send.py`, `test_settings_alerts_status.py`, `test_trust_recheck_job.py`, `test_test_pull.py` |
| `app/web/common.py` | `require_user`/`require_admin`, error rendering, login rate limit, `unsupported_reason` — no routes | every module above |

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

Today the registry holds `cleanup/default`, `scan/default`, `scan/import_pull`, `scan/trust_recheck`,
`alert_expiry/default`, `alert_expiry/smtp_test`, `digest/default`, `discover/default`,
`discover/test_pull` and `deploy/default`, so no plan control is gated as unsupported; the remaining
disabled states are live capability reasons (no worker with `ansible_ssh_key`, empty inventory,
guardrail). The web application calls `build_registry()` too, but only to gate navigation and
controls on registered capabilities — the worker is the only dispatcher.

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

Six schedules are registered, all UTC and all deduplicated by the `scheduler_state` row lock:

| Key | Job | Time setting (default) | Enabled by | Priority |
| --- | --- | --- | --- | --- |
| `cleanup` | `cleanup/default` (`reason=scheduled`) | `cleanup.daily_at` (04:00) | `cleanup.enabled` | 10 |
| `scan` | `scan/default` (`{}`) | `scan.daily_at` (02:00) | `scan.enabled` | 100 |
| `trust_recheck` | `scan/trust_recheck` (`{"action": "trust_recheck"}`) | `scan.daily_at` (02:00) | `scan.enabled` | 100 |
| `expiry_check` | `alert_expiry/default` (`{}`) | `expiry_check.daily_at` (07:00) | `expiry_check.enabled` | 100 |
| `digest` | `digest/default` (`{}`) | `digest.daily_at` (07:30) | `alert.digest_enabled` | 50 |
| `discovery` | `discover/default` (`{}`) | `discovery.nightly_at` (03:00) | `discovery.enabled` | 100 |

`trust_recheck` deliberately reuses `scan.daily_at`/`scan.enabled`, so disabling the daily scan
disables both scan jobs. The `cleanup` handler deletes finished jobs and their `job_host` rows older
than `retention.days` (default 90), scan results older than 90 days
(`SCAN_RESULT_RETENTION`, independent of `retention.days`), expired/idle (> 8 h)/revoked sessions,
login counters older than one day, and artifacts older than 30 days under `artifacts_root`. It never
touches `audit_log`, queued or running jobs, key material or key staging. The same handler runs for
the **Settings → Maintenance** prune (`reason = "manual_prune"`).

### Tick steps

`scheduler_tick()` runs every registered tick step after the schedules, `reap` and `retry_due`, each
in its own transaction. `register_tick_step(name, step, *, requires=(JobType, action))` in
`app/jobs/worker.py` stores a `TickStep(name, step(session, now) -> int, requires)`; a step is skipped
while its handler is not registered, and a failing step is logged by exception class name only and
never stops the others. Two are registered:

| Step | Requires | What it does |
| --- | --- | --- |
| `notification_retry` | `alert_expiry/default` | Enqueues one `alert_expiry/default` job with payload `{"mode": "retry_failed"}` (priority 100, `max_attempts=1`, `scheduled_reason="retry"`) when failed expiry rows created on the current UTC day are due and no `alert_expiry` job is queued or running |
| `deploy_sweep` | `deploy/default` | Cancels paused deploy jobs whose `paused_at` is older than `deploy.pause_timeout_hours` (rows `skipped`/`pause_expired`, `deploy.pause_expired` audit) and marks leftover `pending` rows of terminal deploy jobs `skipped`/`job_ended` |

### Worker process

Compose starts the worker with `python -m app.jobs.worker` (the `worker` service). Settings come from
the `DB_*` environment plus the file secrets in `/run/secrets`. Unlike the CLI, the worker entry point
hard-codes that secret directory. Relevant knobs:

| Setting | Default | Meaning |
| --- | --- | --- |
| `WORKER_CONCURRENCY` | 4 | slots, i.e. maximum concurrently running jobs |
| `MAX_PARALLEL_JOBS` | 2 | cap on `discover`/`scan` jobs among those slots; the rest stay queued |
| `ansible_ssh_key` (secret) | absent | `ssh_available`; without it `discover` and `deploy` are never claimed |
| `known_hosts` → `/etc/ssh/ssh_known_hosts` (`SSH_KNOWN_HOSTS`) | `/etc/ssh/ssh_known_hosts` | pinned SSH host keys; a missing file fails every `discover`/`deploy` with `config_invalid` before any connection |
| `ansible_vault_password` (secret) | absent | optional Ansible Vault password; reaches the child as `CERT_DASHBOARD_VAULT_PASSWORD` plus `ANSIBLE_VAULT_PASSWORD_FILE=app/ansible/vault_client.py` |
| `inventory_git_token` (secret) | absent | optional HTTPS Git token; reaches `git` through `app/ansible/git_askpass.py` (username `x-access-token`), never stored in `.git/config` |
| `smtp_password` (secret) | absent | the SMTP password; worker-only, read from `/run/secrets` (the web profile never loads it). Absent means no AUTH is attempted |
| `DASHBOARD_URL` (environment) | empty | optional absolute `http(s)` base URL that alert and digest e-mails put in front of dashboard paths; without it the mails carry relative paths such as `/certificates/42`. A URL with credentials, a query or a fragment refuses startup |

Job timeouts are fixed per type: `scan` 1800 s, `discover` 1800 s, `alert_expiry` 300 s, `digest`
300 s, `cleanup` 600 s. A deploy timeout is computed per claim by the callback registered with
`register_timeout(JobType.DEPLOY, …)`: distinct `server_id`s still `pending` at or after
`resume_from_batch` × `deploy.host_timeout_seconds` + 900 s. `release_claim` clears `timeout_at`, so
a paused or requeued deploy is never reaped.

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

Discovery and deploy are claimable only by a worker with `ansible_ssh_key` (Plan 1's `_SSH_TYPES`).
Discovery shares the two-job `MAX_PARALLEL_JOBS` cap with scans; a deploy job takes an ordinary free
slot and is serialized instead by `deploy:global` (one deploy at a time) and `deploy.concurrency`
(hosts per batch). A deploy job also holds `inventory:pull`; a paused deploy holds no claim, no slot,
no lock and no `timeout_at`, so it is never reaped. At startup the worker writes one `worker.start`
audit row with the worker id and four presence booleans (`ssh_key_present`, `known_hosts_present`,
`vault_password_present`, `inventory_token_present`) and never a value; the web enables or disables
the discovery/deploy controls from the newest row of a worker with a fresh heartbeat.

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

## TLS scanning and the background trust recheck

`app/services/scans.py` owns observation, classification, payload validation and on-demand requests;
`app/jobs/handlers/scan.py` (`scan/default`) and `app/jobs/handlers/trust_recheck.py`
(`scan/trust_recheck`) are the worker side. The web process only enqueues scan and recheck work and
never opens a target connection; endpoint administration (create, expectation, activation) is
synchronous in the web request, as described under *Web entry points* below.

**Observation.** `observe_endpoint(host, port, sni, timeout_seconds)` opens one TCP connection and one
TLS handshake with SNI = `sni or host` and accepts any chain — it inspects, it never validates trust —
then hashes the leaf DER with SHA-256. `scan.timeout_seconds` (default 10, range 1–60) is the
connect/read deadline. The observation keeps the TLS version, CN, issuer CN, `not_after`, chain length
and elapsed milliseconds.

**Classification** (`classify_observation`, in this order): `unreachable` when no leaf was served (DNS
failure, refused, reset, any timeout including a silent peer during the handshake); `error` when the
handshake/protocol failed or a served leaf did not parse (its SHA-256 over the raw DER is still
recorded); `expired` when the served `not_after` is in the past; `ok` when the served fingerprint
equals the endpoint's expected certificate; `mismatch` otherwise — an endpoint with no expectation
reports `mismatch` until one is set.

**Nothing observed is imported or trusted.** A scan writes only `scan_result` rows and
`endpoint.last_scan_at`/`last_scan_status`; `certificate`, `private_key`, `trust_anchor` and every
`chain_status` are untouched. `chain_status` changes only through Plan 1's `recheck_chain_statuses`.
`scan_result` rows are deleted after 90 days by the existing cleanup handler
(`SCAN_RESULT_RETENTION`), independent of `retention.days`.

**`scan/default` payloads** (`validate_scan_payload`; anything else is a `validation` failure):

| Payload | Meaning |
| --- | --- |
| `{}` (also `{"action": "default"}`) | every active endpoint; what the daily schedule and *Scan all* send |
| `{"endpoint_ids": [1, 2, …]}` | 1–1000 unique positive ids, sorted by the validator |
| `{"certificate_id": N}` | active endpoints whose expectation is certificate `N`, resolved at run time |

The two selector keys are mutually exclusive. Inactive endpoints are never scanned and are counted as
`skipped_inactive`; the target's expectation is snapshotted into each result, so changing the
expectation later never rewrites history.

**Retries touch only unreachable endpoints.** The result of an attempt is
`{scanned, ok, mismatch, expired, unreachable, error, skipped_inactive}` plus one `scan.run` audit row
(`target_type='job'`, details `source`, `attempt`, counts). If at least one endpoint is `unreachable`
and `attempt < max_attempts`, the handler commits every result and then fails the job with retryable
`transient_network`; the queue's 30 s and then 120 s retries re-run it, and an attempt after the first
scans **only** the endpoints whose `last_scan_status` is still `unreachable`. The third attempt succeeds
with counts even when endpoints remain unreachable, so a flapping endpoint leaves up to three history
rows and never blocks the job. `source` is `scheduled` when `job.requested_by` is NULL and `manual`
otherwise, so a retry keeps the original source.

**Concurrency and slots.** Observations run in a `ThreadPoolExecutor` capped at `SCAN_CONCURRENCY` (20)
connections, after the resolving transaction is closed; each result is committed in its own short
transaction so partial work survives a crash. Scan-type jobs (including the trust recheck) are capped at
`MAX_PARALLEL_JOBS` (2) of the worker's four slots. `endpoint.last_scan_at`/`last_scan_status` advance
only when the new `checked_at` is not older than the stored one, so two concurrent jobs cannot regress
an endpoint.

**Web entry points** (all CSRF-protected and audited, `app/web/scans.py`). Two of them only enqueue
work: `POST /certificates/{id}/scan` (payload `{"certificate_id": id}`, priority 200 — the certificate
detail page's *Scan now*) and `POST /scans/run` with `scope=all` or `scope=endpoint` + `endpoint_id`
(priority 200). The three management forms are **not** enqueue-only: `POST /scans/endpoints` (create,
`endpoint.create`), `POST /scans/{id}/expectation` (`certificate_id`, or `use_observed=1` when the
served fingerprint is already in inventory, `endpoint.update`) and `POST /scans/{id}/active`
(`active=true|false`) call `create_endpoint` / `set_expectation` / `expect_observed` /
`set_endpoint_active` in `app/services/endpoints.py`, which stage the row change and its audit row on
the web session; `_transact` commits both before the response, so a successful form redirects to the
already-updated page and a 422 changes and audits nothing. Endpoints are never deleted.

**Background trust recheck.** `scan/trust_recheck` runs `recheck_chain_statuses(db, now)` at the job's
UTC clock so an expiring intermediate is noticed without an operator; changed statuses get Plan 1's
`certificate.chain_check` audits. It is scheduled under key `trust_recheck`, which reuses
`scan.daily_at`/`scan.enabled` (no new setting), and Settings → Trust anchors adds *Recheck now*
(`POST /settings/trust-anchors/recheck`, priority 200). Anchor upload/delete/toggle keep their
synchronous recheck. As a `scan`-type job it counts against the two-job cap.

**§7.7 inventory refresh is not a Plan 2 job.** Plan 2 Contract decision 15 placed it in Plan 3 as the
preflight of every `discover`/`deploy` job, together with *Test pull*; Plan 3 implements it in
`app/services/inventory.py` and `app/jobs/handlers/{ansible_context,test_pull}.py` (see *Inventory and
Test pull* above). `scan/import_pull` is unchanged (it still writes no `scan_result`); the manual
endpoint expectation it upserts is scanned by `scan/default` like any other endpoint.

## Expiry alerts, the notification ledger and the digest

`app/services/alerts.py` evaluates and renders expiry mail, `app/services/notifications.py` owns the
`notification_log` ledger, `app/jobs/handlers/expiry.py` is `alert_expiry/default`, and
`app/services/digest.py` + `app/jobs/handlers/digest.py` produce the daily digest.

**Which certificates get a mail.** `due_expiry_alerts` looks at active certificates whose `not_after`
is within `max(alert.thresholds_days)` days (default `[60, 30, 14, 7, 1, 0]`; at most 10 distinct
values, 0–365). The smallest crossed threshold `T` wins, and the mail is skipped when a `sent` expiry
row already exists for that certificate and `T` on **any** day — so the 30-day alert fires once even
across reruns, queue retries or the next day's run, and larger thresholds are implicitly consumed.
`dedupe_key = expiry:<certificate_id>:<threshold>:<UTC run date>`.

**Recipients.** `certificate.owner_email` first, then `alert.recipients`, deduplicated; an empty owner
falls back to the team list only, and no recipient at all records a `no_recipients` row instead of
silently dropping the alert. The message lists CN, SAN count, issuer, serial, `not_after` in
`ui.timezone` **and** UTC, the days remaining (or "has expired"), the active bindings (capped at 50
with "+N more"), the newest non-cancelled renewal state, and links to the certificate and renewal.

**The ledger** (`notification_log`) is the delivery record and the idempotency key:

| Field | Semantics |
| --- | --- |
| `dedupe_key` (unique) | `expiry:<certificate>:<threshold>:<UTC date>` or `digest:<UTC date>` |
| `status`, `attempts` | `failed` + `0` on insert; at most `MAX_NOTIFICATION_ATTEMPTS` (3) attempts |
| `sent_at` | set only on a successful send, NULL otherwise |
| `last_attempt_at` | set on every attempt, including failures |
| `next_attempt_at` | backoff after a retryable failure: 30 s after attempt 1, 120 s after attempt 2, then NULL |
| `error` | `"<code>: <message>"` from the fixed SMTP text table, redacted and bounded to 500 characters |

`open_notification` inserts `ON CONFLICT (dedupe_key) DO NOTHING` and then locks the row
`FOR UPDATE SKIP LOCKED`; it returns the row only while it is still attemptable (not `sent`, fewer than
three attempts, `next_attempt_at` NULL or due), so concurrent schedulers and workers cannot send twice.
The send happens **while the row lock is held** and is committed together with the attempt:
**delivery is at-least-once** — a worker crash between SMTP acceptance and that commit can resend the
same mail once on the retry. A failed row is retried only on the UTC day it was created; the next day's
evaluation creates the next day's key.

**Retry sweep.** The `notification_retry` tick step (see *Tick steps*) queues one
`alert_expiry/default` job with payload `{"mode": "retry_failed"}`, priority 100, `max_attempts=1`; that
mode re-attempts due rows for the current day and never fails the job for SMTP reasons. Digest rows
rely on the job-level retry instead (one row per job).

**Job outcome.** The expiry job succeeds when at least one message was delivered or nothing needed
sending. It fails only when it attempted at least one send and delivered none: retryable
`smtp_transient` if any failure was transient, otherwise the mapped non-retryable class. `no_recipients`
and `smtp_not_configured` rows are recorded for Settings and the digest but are not send attempts.

**Digest** (`digest/default`, schedule key `digest`, 07:30 UTC, `alert.digest_enabled`, priority 50).
"Since the last digest" is the `sent_at` of the newest sent digest row, or 24 hours before now when no
digest has ever been sent; *new* is decided against the state at that cutoff, not by looking only at
rows inside the window. Each section gets a heading only when it has content or a count: expiring within
7 days; already expired; new TLS mismatches (with the current mismatch count, so the heading appears
even when nothing is new); unknown certificates found by discovery; servers whose last discovery
failed, never ran or is older than 48 h; jobs failed in the last 24 hours;
rolled-back hosts in the last 24 hours (a failed rollback says "needs manual attention"); failed
notifications in the last 24 hours. Every list is capped at `DIGEST_LIST_LIMIT` (50) and says
"showing 50 of 55"; totals are never capped. The mail always states the inventory revision —
"none recorded" until a discover/deploy job has written one, then the newest succeeded result's
`inventory_rev` and date. **A digest is sent even when there is nothing to report** ("Nothing
to report. This mail is the daily heartbeat of the alerting path."), `dedupe_key = digest:<UTC date>`
makes a second successful run of the same day a no-op. The digest is addressed to the team list only
(`resolve_recipients(None, addresses)` in `app/jobs/handlers/digest.py`; unlike expiry alerts there is
no `certificate.owner_email` fallback), so an empty `alert.recipients` records a failed
`no_recipients` row instead of sending. The job result carries counts only, never the dedupe key.

**`binding.match_state` audit producer.** `app/services/bindings.py` provides
`binding_state(binding)` and `audit_binding_state(db, binding, previous, actor, *, job_id, now)`, which
writes one metadata-only `binding.match_state` audit row (`from_state`, `from_fingerprint`, `was_active`,
`to_state`, `on_disk_fingerprint`, `is_active`, `server_id`, `job_id` — never `notes` or paths) when a
binding is inserted or its `(match_state, on_disk_fingerprint, is_active)` triple changes, and nothing
when the same triple is seen again. Plan 2 ships the producer and the digest section that reads it;
Plan 3's discovery reconciliation is its only caller, so *Unknown certificates found by discovery*
stays empty until the first discovery has reconciled a host.

## SMTP delivery and the test send

Mail is worker-only. `app/services/smtp.py` is the single transport; the web process never loads
`smtp_password` and never opens an SMTP or TLS-inspection connection — it only enqueues the job.

**Settings** (all in the 32-key allowlist; no new key): `smtp.host`, `smtp.port` (empty means the
default port for the security mode: 587 for `starttls`, 465 for `ssl`, 25 for `none`), `smtp.security`
(`starttls`/`ssl`/`none`), `smtp.from`, `smtp.username` and `smtp.tls_verify`. The password is the
worker file secret `smtp_password`; it is absent by default, and absent means no AUTH is attempted.
AUTH runs only when `smtp.username` is non-empty **and** the secret exists, and only over `starttls` or
`ssl` — a username with plaintext `none` fails with `smtp_not_configured` before anything is sent, and
a `starttls` server that does not offer the extension fails with `smtp_tls` ("STARTTLS not offered by
the server") rather than downgrading. `smtp.tls_verify=true` (the default) verifies against the system
store; `false` disables verification, which Settings marks "unsafe: TLS certificate verification
disabled — mail credentials and content can be intercepted." and which raises the
`smtp_tls_unverified` warning.

**Session and outcomes.** One session per job, connected lazily, with a 30-second per-command timeout
(`SMTP_TIMEOUT_SECONDS`) and at most one reconnect after a server disconnect. `From` is `smtp.from`,
`Reply-To` is `alert.recipients` when non-empty, and every message carries its own `Message-ID` and
`Date`. Failures are **code-only by design**: `SmtpStep` is `(step, code)` where `step` is one of
`connect`, `ehlo`, `starttls`, `auth`, `mail`, `rcpt`, `data`, `quit` and `code` is the integer reply
code (200–599) or NULL, and `SendOutcome.message` comes from a closed table such as `451 at rcpt`,
`connection failed (ECONNREFUSED)`, `timed out at data`, `TLS handshake or certificate verification
failed`, `STARTTLS not offered by the server` or `no recipients`. No SMTP reply text, exception text,
SSL reason or AUTH challenge is kept, logged or re-raised — a relay that echoes a credential in a reply
line cannot leak it, and `redact()` plus truncation run afterwards only as a second barrier. Outcome
codes are `sent`, `smtp_not_configured`, `no_recipients`, `smtp_transient` (connect/DNS/timeout/
disconnect or any 4xx), `smtp_rejected` (other 5xx), `smtp_auth` (530/534/535 or AUTH unsupported) and
`smtp_tls`; only `smtp_transient` is retryable, and the job class mapping is
`smtp_transient → smtp_transient`, `smtp_auth → auth`, everything else → `config_invalid`.

**Test send.** `POST /settings/smtp/test` enqueues `alert_expiry/smtp_test` with payload
`{"action": "smtp_test"}`, priority 200 and `max_attempts=1` (it is never retried). The recipient is the
requesting user's e-mail, read from `job.requested_by` at run time; the message is fixed and no
`notification_log` row is written. The SMTP tab renders the newest test job — status, finished time,
and either an ordered list of steps with reply codes or the fixed failure text plus the steps reached,
such as `535 at auth; connect 220, ehlo 250, starttls 220, auth 535` — and
`GET /settings/smtp/test/{job_id}` returns the same block for htmx polling every 2 s while the job is
queued or running.

**Signals.** `smtp_health` (one query) reports `consecutive_failures` (failed ledger rows since the
newest `sent` row), `last_error`, `last_success_at` and `last_test`; test sends are jobs, never ledger
rows, so they never count as failures. Settings → Status renders that panel and the warnings
`smtp_failing` (at least one consecutive failure) and `smtp_tls_unverified`; Settings → Alerts lists the
50 newest failed notifications with attempts and the next attempt. See
[`operations.md`](operations.md#10-alerts-digest-and-scanning) for the operator view.

## Server discovery and certificate deployment

Plan 3 adds the worker-side Ansible path and the operator screens. The operator procedures —
inventory settings, worker credentials, the sudo rule, the deploy flow, recovery and the §10.4
real-host runbook — are in [`operations.md` §11–§12](operations.md#11-discovery-and-deployment);
this section is the module and test map.

**Modules.** `app/ansible/runner.py` wraps `ansible-runner` with `build_env` (a child environment
built from scratch), event parsing and host classification; `staging.py` writes secret files to the
tmpfs with `0600`/`O_NOFOLLOW`; `vault_client.py` and `git_askpass.py` are the two executable helpers
that print a secret from their own environment. `parse_nginx.py` and `parse_apache.py` produce
`ParsedBinding` candidates, `discovery.py` assembles the §6.2 documents (D1/D2), `deploy.py` stages
per-host material and parses the playbook outcome. The playbooks are
`app/ansible/playbooks/{discover.yml,deploy.yml}`, with `tasks/*.yml` and
`files/{apache_dump.py,prune_backups.py}`. `app/jobs/locks.py` owns the PostgreSQL advisory locks
(`deploy:global`, `deploy:enqueue`, `inventory:pull`, `deploy:<hostname>`), and the services are
`inventory.py` (checkout/listing), `discovery.py` (reconciliation), `deploy.py` (rollout, file-write
planning, preview, start and controls — the coverage-gated module, importing nothing from
`app/ansible`), `deploy_runtime.py` (worker revalidation, outcomes, sweep, timeout) and
`deploy_views.py` (read models). Handlers: `ansible_context.py` (job lock session, staging,
`known_hosts`, clock and audit hook), `test_pull.py`, `discover.py` and `deploy.py`.

**Inventory and Test pull.** `refresh_checkout` fetches `+<ref or HEAD>:refs/cert-dashboard/fetch`
with `--no-tags`, then `git reset --hard` and `git clean -ffdx`; `last_pull.json` records `rev`,
`rev_date` and `pulled_at`. A pull inside 60 s of the previous one is a no-op; a failed pull keeps the
last good checkout while it is younger than 24 h and the job reports `inventory_warning`, otherwise
the job fails `transient_network`. `list_inventory` runs `ansible-inventory -i <path> --list`, reads
only `ansible_host` and `inventory.webserver_var`, and never logs or stores stdout/stderr. Git runs
with list argv, `GIT_ALLOW_PROTOCOL=https:ssh:file`, `GIT_CONFIG_NOSYSTEM=1`,
`GIT_TERMINAL_PROMPT=0`, an empty credential helper, a 120 s timeout and — only when a key is
configured — `GIT_SSH_COMMAND` with `StrictHostKeyChecking=yes` and the pinned `known_hosts`. The
four settings are `inventory.repo_url`, `inventory.ref`, `inventory.path` and
`inventory.webserver_var`; *Test pull* enqueues `discover/test_pull` and runs the pull plus
`--list` only, with no SSH to a target.

**Discovery jobs.** `discover/default` payloads are `{}` (whole inventory; schedule and *Discover
all*), `{"hosts": [...]}` (1–500 names) or `{"groups": [...]}` (1–50 names), validated against
`[A-Za-z0-9_.-]{1,253}` so `--limit` can never carry Ansible pattern syntax. Priority 200 on demand,
100 from the `discovery` schedule (`discovery.nightly_at`, default 03:00 UTC; `discovery.enabled`).
Each targeted server gets one `job_host` row; a host result is `succeeded` or `failed` with reasons
`unreachable`, `auth`, `dump_failed`, `dump_too_large`, `parse_failed` or `host_timeout` and a
`precheck` dump summary (`webserver`, `binaries`, `config_files` ≤ 200, `bindings`, `warnings`,
`parse_suspected`, `dump_bytes`, `dump_sha256`). Unreachable hosts are retried alone — 3 attempts,
30/120 s — and an SSH authentication failure (`auth`) is never retried; the message tells the
operator to check `known_hosts` and the deploy key. A host that previously had bindings and now
yields zero is `parse_suspected`: nothing is deactivated. Discovery is read-only on the target
(`become` only to read); raw dumps and per-host documents stay on the worker's artifacts volume
(`<artifacts>/<job_id>/discovery/<hostname>.json`, `0600`, removed by the 30-day cleanup), the UI
shows only the summary, and `discovery.run` is audited once per attempt.

**Parsers and the D1–D3 rules.** nginx is parsed from `nginx -T` by a tokenizer that follows
`# configuration file <path>:` markers and the block stack; Apache from the collector's JSON
document and `apachectl -S` vhosts. Certificate contents are transported with
`openssl crl2pkcs7 -nocrl -certfile <path> | openssl pkcs7 -print_certs` under `no_log: true`,
because `openssl x509 -in` reads only the first certificate of a bundle. Chain roles follow operator
decision D1: every certificate file is parsed on its own and a file is a chain only when its
certificate verifies the previous signature (`app/crypto/chain.py`); a same-issuer RSA+ECDSA pair is
two bindings; unreadable or incomplete chains are not used and the binding carries the fixed
`chain_diagnostic`. Key hashes are the SHA-256 of the DER `SubjectPublicKeyInfo` (D2), the same value
as `private_key.public_key_sha256`. Apache reads the union of the `apachectl -S` files, the main
config and the recursive `Include`/`IncludeOptional` tree (≤ 500 files, 16 MiB, depth 16), and
nginx's included files are attributed through the `nginx -T` markers (D3). The operator-facing
reproduction commands are in
[`operations.md` §11.6](operations.md#116-how-the-checks-work-d1-d2-d3-and-what-to-look-at-on-a-host).

**Reconciliation.** Bindings are upserted by
`(server_id, webserver, config_file, port, vhost_name, cert_path)` under the server row lock.
`match_state` is `matched` (fingerprint and key hash agree), `key_mismatch`, `unknown`,
`missing_file` or the binding is deactivated (`is_active=false`) when it disappears from the dump;
every transition goes through `audit_binding_state` in the same per-server transaction. Servers are
created from inventory hosts and deactivated when they leave the inventory (bindings and derived
endpoints deactivated, never deleted). Each binding gets a derived endpoint from
`(connection_address, port, verify_sni(vhost_name, vhost_names))`; a `matched` binding sets the
expected certificate, an `unknown` one leaves the expectation empty. A host that previously had
bindings and now yields zero is not reconciled (see above).

**Deploy planning.** `preview_deploy` resolves the targets (active bindings of active servers of the
renewed certificate, or an explicit selection), plans the batches and derives each host's writes;
several bindings sharing a path produce one write, and the same path needed with different content is
a `FileConflict` that blocks the start. The preview is advisory and carries `plan_sha256`; the POST
must echo it and confirm the sentence naming the host count and the canary. Guardrails refuse a start
with a reason: missing key or key version, expired/not-yet-valid/revoked certificate, no target, every
binding already on the new fingerprint, a deploy already `queued`/`running`/`paused`, or a chain that
is not `trusted` without an audited override. One deploy at a time is enforced by
`pg_advisory_xact_lock(hashtext('deploy:enqueue'))` in the web process and `deploy:global` in the
worker. The trust override is audited as `deploy.chain_override` and never bypasses key presence and
match, leaf validity, binding state, drift or the config test.

**Rollout and host execution.** Canary first, then batches of
`max(1, ceil(total_servers × deploy.batch_percent / 100))` (integer `-(-total * percent // 100)`),
`deploy.concurrency` hosts at a time. After a successful canary the job pauses by default
(`deploy.pause_after_canary`), releases its claim, slot and locks, and waits; *Continue* requeues at
batch 1 and re-checks the trust gate and every host's drift; a forgotten pause is cancelled by the
`deploy_sweep` tick step after `deploy.pause_timeout_hours` (default 24). The first failed host stops
the rollout: in-flight hosts finish, unstarted rows become `skipped` (`rollout_stopped`); a host whose
`deploy:<hostname>` lock is taken is `skipped` (`locked`) and does not stop it. `deploy.yml` runs once
per host with file **paths** and a JSON `targets` array only: preflight (drift versus
`old_fingerprint`/`new_fingerprint`, free space, baseline config test, staged-key SPKI match), backup
to `/var/backups/cert-dashboard/<job_id>/<absolute path>` (root `0700`, key backups `0600`,
certificate backups `old_mode & 0o644`, `manifest.json`, refuse to proceed if a backup is missing),
atomic write (temp file with final mode, then `mv`), `restorecon` when present, config test, reload,
on-target verify (3 attempts, 2 s apart) and, on any failure from the first write through
verification, a **single-attempt** rollback that restores every manifest path. A failed rollback or a
host timeout is marked *needs manual attention*; a successful rollback is `rolled_back`. Re-runs are
idempotent (a file already at the new fingerprint is not rewritten), pruning keeps the newest backup
of each path and `deploy.backup_retention_days` `0` keeps everything. Deploy jobs are never retried
automatically; *Retry host* creates a new audited job (`deploy.retry_host`, canary-only). The renewal
is advanced to `deployed` only by the `on_success` hook after a **succeeded** job with at least one
succeeded binding row carrying the new fingerprint.

**Screens and locks.** The start screen (`GET /deploy`, `GET /deploy/preview`, `POST /deploy`), the
job screen (`GET /deploy/{job_id}`, `GET /jobs/{job_id}/progress`, `GET /deploy/{job_id}/report.json`)
and the three controls (`continue`, `cancel`, `retry`) live in `app/web/deploy.py`; discovery actions
are `POST /servers/discover` and `POST /servers/{id}/discover` in `app/web/servers.py`. All are
CSRF-protected, POST→303 and htmx-aware; the web process only reads the database, computes previews
and enqueues.

### Playbook static tests and coverage gates

`tests/unit/test_playbooks_static.py` reads both committed playbooks and enforces the contracts the
integration tests cannot see: `ansible-playbook --syntax-check`; every task uses a fully qualified
`ansible.builtin.*` module from the allowlist (`command`, `shell`, `stat`, `copy`, `set_fact`,
`set_stats`, `fail`, `assert`, `include_tasks`, `slurp`, `file`, `script`, `find`, `debug`) and no
network module (`get_url`, `uri`, `apt`, `dnf`, `package`, `pip`, `git`); every task whose arguments
mention key paths, the dump or certificate extraction is `no_log: true`; every `command`/`shell` task
has `timeout: 60` or less; `discover.yml` writes only to the controller and has exactly one
target-side `script`; `deploy.yml` obeys the rescue-coverage rule — every task that changes a live
path or service is inside the main `block`, whose `rescue` includes `tasks/rollback.yml` for every
write step, `rollback.yml`'s own `rescue` only records `rollback_error` (no retry), and pruning runs
only after `verified` and only under `{{ backup_root }}`. CI enforces 85 % coverage on
`app/ansible/parse_*` and `app/services/deploy.py` (and on `app/crypto`, `app/services/renewals.py`),
70 % overall.

### Local gate and known-flaky tests

The `ssh-targets` profile is CI-only (see *SSH targets* under *Test fixtures* for the build step,
the services and the fixture API): built once by the CI setup step, then started with
`up -d --wait --no-build --pull never`. Locally there is no Docker: the gate stays
`uv run ruff check .` plus `uv run pytest -q tests/unit` (and `-k 'not test_topology'` on a
Docker-less machine), and the SSH-target, Testcontainers and acceptance tests run only in GitHub CI.

Two tests have a documented history of environment-sensitive failures because they measure target
reload or wall clock rather than behaviour: the parametrized
`tests/integration/test_scan_targets.py::test_real_webserver_scan_reports_ok_then_mismatch_then_unreachable`
(a reload race, hardened in PR #40) and the smoke ceilings in
`tests/unit/test_parse_chain.py` (hardened to count signature verifications in PR #65). If one of
them fails on a loaded runner, re-run the failed CI job once (`gh run rerun <run-id> --failed`) and
record both run URLs on the card; a second failure is a regression, not a flake. Do not loosen the
assertions to make a run green.

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
| `closed_port`, `set_setting`, `disable_schedules` | a port nothing listens on, a settings patch, and the helper that turns named schedules off for a test that ticks the worker |
| `smtp_server` (in `tests/conftest.py`), `configure_smtp` | in-process `CaptureServer` instances (see below) and the settings/SMTP setup that points the worker at one |
| `expiring` | a certificate issued by the session CA with a chosen number of days to expiry and unique CN |
| `scan_world`, `server_map`, `count_statements` | seeded endpoints/servers/bindings for the Scans, Servers and Bindings tests, and the SQL-statement counter that proves the query count does not grow with rows |
| `ssh_targets`, `fresh_targets`, `runner_secrets` | the CI-only SSH-enabled nginx/Apache stack (`ssh-targets` profile), the per-test reset, and the client key plus pinned `known_hosts` as `RunnerSecrets` |
| `inventory_repo` | a local bare `file://` inventory repository with `hosts.yml`, optional vaulted `group_vars`, `.head`, `.head_date` and `.commit(files)`; it writes the `inventory.*` rows directly because the settings validator accepts only `https`/`ssh`/scp URLs |
| `ansible_worker` | `make_worker` with the fixture SSH key, `known_hosts_file`, `inventory_root` and `key_staging_dir` |
| `deploy_world`, `deploy_material`, `deploy_ready` | seeded certificate/renewal/bindings and preview state, staged public/key material, and a job-ready deploy fixture with the queue and Ansible context |
| `acceptance_stack`, `staging_restore` | the §10.4 acceptance scenario (web app and one Ansible worker over the same private database, SMTP capture, inventory served over SSH) and the `pg_dump -Fc`/`pg_restore` restore drill |

`tests/fixtures/` holds the shared generators and harnesses: `ca.py` (`FixtureCA.issue`),
`certificates.py` (`generate_certificates`), `smtp_capture.py` (below), `targets/` (the
`ssh-targets` images and committed webserver configurations), `ssh_targets.py` (the `TargetStack`
API used by assertions), `git_inventory.py` (the bare inventory repository), `ansible/` (the
local-connection probe playbook) and the PFX child stubs above. Fixtures stay in memory or in
`tmp_path`; nothing is written to the repository.

### Test targets and the SMTP capture server

`tests/fixtures/smtp_capture.py` is an `aiosmtpd`-based **dev-only** capture server. In-process it backs
the `smtp_server` fixture: it binds a free loopback port, scripts replies by recipient local part
(`tempfail…` → `451 4.3.0`, `reject…` → `550 5.1.1`), accepts per-verb `replies=` overrides that can echo
the AUTH password the client sent (the hostile-relay case), supports STARTTLS and implicit TLS, and
counts connections. From the shell it runs the same module as a service:

```sh
uv run python -m tests.fixtures.smtp_capture --listen 127.0.0.1:1025 --spool /tmp/mail
uv run python -m tests.fixtures.smtp_capture --dump /tmp/mail   # JSON array of the .eml files
```

`docker-compose.test.yml` defines three services under the profile `targets`:

| Service | Image | Shape |
| --- | --- | --- |
| `tls-nginx` | `nginx:1.28-alpine`, pinned by `@sha256:` digest | committed config mounted read-only, `${TLS_TARGET_DIR:-./secrets/test/tls-targets}/tls-nginx:/etc/certs:ro`, `127.0.0.1::8443` |
| `tls-apache` | `httpd:2.4-alpine`, pinned by `@sha256:` digest | committed config, `${TLS_TARGET_DIR…}/tls-apache:/etc/certs:ro`, `127.0.0.1::8443` |
| `smtp` | the `cert-dashboard:test` image already built | UID 10001, `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, `tmpfs: [/spool]`, `python -m tests.fixtures.smtp_capture --listen 0.0.0.0:1025 --spool /spool`, `127.0.0.1::1025` |

The session-scoped `compose_targets` fixture writes a throwaway fixture CA, its leaves (key files `0600`)
and a dummy file for every declared secret into a temporary directory, then runs
`docker compose -p certdash-targets-<uuid> -f docker-compose.test.yml --profile targets up -d --wait
--pull never tls-nginx tls-apache smtp` with `TLS_TARGET_DIR`/`TEST_SECRETS_DIR` pointing there. It
exposes `.address(service)`, `.serve(service, cert, key, chain)` (rewrite the files, reload
`nginx -s reload` / `httpd -k graceful`, restart first if the service was stopped), `.stop(service)` and
`.messages()` (reads the spool through `docker compose exec`), and always tears the project down with
`down -v`.

CI pulls the pinned images before pytest —
`docker compose -f docker-compose.test.yml --profile targets pull tls-nginx tls-apache` next to the
existing `db` pull — and the tests then start the profile with `--pull never`, so nothing is fetched
during a test run. Two things follow for developers: the integration suite needs Docker (it runs in CI,
not on a Docker-less laptop), and `docker compose -f docker-compose.test.yml --profile targets config
--quiet` must stay green when the profile is rendered.

`tests/integration/test_scan_targets.py` is the end-to-end case: it scans a real nginx and a real Apache
target through `ok → mismatch → unreachable` and sends one test e-mail to the `smtp` service.

### SSH targets

Plan 3's discovery and deployment tests run Ansible against real `sshd` + nginx/Apache containers. They are
**CI-only** (no Docker on a laptop or in the Hermes container); the local gate is `uv run ruff check .` and
`uv run pytest -q tests/unit`, which also checks the compose topology and the pure fixture helpers.

| Service | Inventory host | Groups | `webserver_type` | TLS port | Vhosts |
| --- | --- | --- | --- | --- | --- |
| `ssh-nginx-1` | `web01.example.internal` | `canary_ring` | `nginx` | 18443 | `www` and `legacy` (both use `/etc/nginx/ssl/www.crt`; keys `www.key` / `legacy.key`) |
| `ssh-nginx-2` | `web02.example.internal` | `ring_a` | *(absent: auto-detected)* | 18444 | `www` |
| `ssh-apache` | `web03.example.internal` | `ring_a` | `apache` | 18445 | `www` with a chain file, plus a plain `:80` vhost |

The images come from `tests/fixtures/targets/Dockerfile` (`debian:bookworm-slim` pinned by digest,
`openssh-server sudo python3 openssl git procps` plus `nginx` or `apache2`; packages follow the pinned base at
build time). User `cdeploy` (uid 2000, no password) logs in with a key only and may `sudo` to root without a
password — the dedicated privilege-escalation rule of §6.4. The compose services (`profiles: [ssh-targets]`,
`init: true`, a dedicated `ssh-targets` bridge network, no secrets, one read-only `/fixture` bind) publish SSH on a
random `127.0.0.1` port and TLS on the **same** port inside and outside the container, so a binding discovered
on a target is also reachable from the runner. `entrypoint.sh` runs `target-reset` and then `sshd -D -e` in the
foreground; `target-reset` rebuilds the committed config tree (`/etc/nginx` or `/etc/apache2`, TLS dirs
included), the backup tree and the webserver, so files a test added are removed.

CI builds the images once, in a setup step after the target pull and before pytest —
`docker compose -f docker-compose.test.yml --profile ssh-targets build ssh-nginx-1 ssh-apache` — and the tests
start them with `up -d --wait --no-build --pull never`; nothing is downloaded during a test run and every
connection goes to `127.0.0.1`.

Use the fixtures from `tests/integration/conftest.py`: `ssh_targets` (session; generates the host keys, client
key and the "old" leaf, starts the stack, writes a pinned `known_hosts` and always runs `down -v`),
`fresh_targets` (function; resets all three targets — request it in every test that reads or mutates them) and
`runner_secrets` (the client key and `known_hosts` as `RunnerSecrets`). `tests/fixtures/ssh_targets.py` holds the
`TargetStack` API (`inventory_file`, `exec`, `read`, `stat`, `put`, `served_fingerprint`, `signal_webserver`,
`backups`, `unchanged_since_reset`, `mark_baseline`, `stop`/`start`, …); assertions on a target always go through
`docker compose exec` as root, never through the code under test. A restarted target gets a new random SSH port,
so use `ssh_targets.start(service)`, which rewrites `known_hosts`.

`tests/integration/test_ssh_targets.py` proves the harness: Ansible reaches every target over pinned SSH with
`become`, a forged or unknown host key and a wrong client key are `auth`, a stopped target is
`transient_network`, the targets serve the old certificate on their fixed ports and `target-reset` restores the
initial state exactly.

## Linux deployment secrets

Provision canonical files beneath `/etc/cert-dashboard/secrets` through the
operator's normal secure process: `master_key`, `session_secret`, `db_password`,
and a distinct `db_owner_password`. Never commit them. Worker credentials `ansible_ssh_key`, `ansible_vault_password`, `inventory_git_token`, `smtp_password`
are optional; mount only the ones provisioned using the credentials override. Discovery and
deployment additionally need `known_hosts`, mounted at `/etc/ssh/ssh_known_hosts`
(`SSH_KNOWN_HOSTS`): a missing file fails those jobs `config_invalid` before any connection, and an
unpinned host is refused rather than trusted. The `ANSIBLE_SSH_ARGS` value in
`docker-compose.credentials.yml` **is no longer read**: `build_env` in `app/ansible/runner.py`
constructs the child environment from scratch with its own stricter
`-o StrictHostKeyChecking=yes -o UserKnownHostsFile=<known_hosts> -o IdentitiesOnly=yes
-o BatchMode=yes -o ControlMaster=auto -o ControlPersist=60s`. Change host-key checking in the file,
never in that variable.
`smtp_password` is what lets the worker authenticate to the relay for expiry alerts and the digest:
without it no AUTH is attempted at all, and a relay that requires authentication rejects the mail with
`smtp_auth`. `DASHBOARD_URL` is not a secret: it is a plain worker environment value (absolute
`http(s)`, no credentials, query or fragment) that alert and digest mails put in front of dashboard
paths, and an invalid value refuses worker startup.

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
