# Cert Dashboard — Design Spec

| Field | Value |
| --- | --- |
| Status | Draft for review |
| Date | 2026-10-19 |
| Scope | v1 (single internal deployment) |
| Audience | Implementers, reviewers, the operating admins |
| Repo | Private GitHub repo (`cert-dashboard`) |

This document specifies a self-hosted dashboard for SSL/TLS certificates that ACME cannot renew. It is a design document only: it defines behaviour, data, interfaces, and operations. It is the implementation contract for v1.

Anything not fixed by an approved decision is written down as an **Assumption** and can be changed during review. There are no open questions hidden in this document.

---

## 1. Goal & users

### 1.1 Problem

The team runs TLS on roughly 50-500 nginx and Apache servers with a few hundred certificates issued by commercial CAs (DigiCert, Sectigo) and an internal Microsoft ADCS. These certificates cannot be renewed over ACME: renewal goes through a CA portal, a human downloads the issued certificate, and someone edits files by hand on each server.

The consequences we are fixing:

- Expiry dates live in spreadsheets and memory; a missed renewal means an outage.
- Private keys are scattered on servers and admin laptops with no inventory.
- Nobody has a reliable answer to "which vhost on which server uses which certificate".
- Certificates get replaced by hand, one server at a time, with no verification and no rollback.
- A renewed certificate can silently fail to be installed somewhere, and nobody notices until it expires.

### 1.2 Goal

One internal web application that is the source of truth for every non-ACME certificate and key, warns before expiry, walks an admin through a manual CA renewal, and deploys renewed certificates to many servers safely with automatic rollback.

### 1.3 Users

| User | Description | Needs |
| --- | --- | --- |
| Certificate admin | 2-10 infrastructure engineers, internal network | Inventory, renewal guidance, safe bulk deploy, audit trail |
| Team recipient | Distribution list that receives expiry and digest mail | Warning mail, no login |

**v1 has no roles.** Every authenticated user is a full admin. RBAC arrives with LDAP (Section 12).

### 1.4 Success criteria

- Zero unplanned certificate expiries for certificates present in the inventory.
- Any admin can answer "where is this certificate used, and what expires next" in under a minute.
- A renewal of one certificate across 100 hosts is one guided flow, not 100 manual edits.
- Every deploy either verifies the new fingerprint on the target or rolls back automatically.
- Every state-changing action is attributable to a user in an append-only audit log.

### 1.5 Scale targets

| Dimension | Target |
| --- | --- |
| Certificates | up to ~500 |
| Servers | 50-500 |
| Bindings (vhost to cert) | up to ~5,000 |
| Endpoints scanned | up to ~1,000 |
| Concurrent interactive users | ~10 |
| Concurrent deploys | 1 job at a time, 5 hosts in parallel within a batch |

---

## 2. Scope

### 2.1 In scope for v1

1. **Inventory** of certificates: subject, SANs, issuer, serial, validity, SHA-256 fingerprint, PEM, chain, owner/team, notes, status, renewal lineage.
2. **Encrypted private key storage** in PostgreSQL, including import and generation.
3. **Email expiry alerts** over SMTP at 60/30/14/7/1/0 days, to the certificate owner and a team list.
4. **Guided manual-CA renewal**: generate key + CSR, hand the CSR to the user for the CA portal, accept the issued certificate, validate the key match, build the chain, expose downloads (PEM, chain, PFX).
5. **Live TLS scanning** of registered `host:port` endpoints, daily and on demand, flagging served certificate differs from inventory.
6. **Import** by PEM/CRT/PFX upload, or by pulling the served chain from a `host:port`.
7. **Server and binding map**: every nginx/Apache vhost mapped to its certificate, chain, and key file paths, with on-disk owner, mode, and fingerprint.
8. **Discovery** over the existing Ansible inventory that reports the real on-disk state of every vhost.
9. **Bulk deploy** of a renewed certificate with a canary host, percentage batches, per-host verification, automatic rollback, and live progress.
10. **Local accounts** (argon2id) with optional TOTP 2FA, behind a pluggable auth backend interface.
11. **Audit log**, append-only.
12. **Users & settings screens** for SMTP, alert thresholds, and inventory repository configuration.

### 2.2 Out of scope for v1

- CA API integration (DigiCert/Sectigo/ADCS APIs). Renewal is manual through the CA portal.
- IIS, F5, HAProxy, Traefik, Kubernetes ingress, or any target other than nginx and Apache on Linux reached over SSH.
- Network/CIDR discovery. Servers come only from the Ansible inventory.
- CSV import.
- Roles/RBAC. Every user is an admin.
- Teams/Slack/PagerDuty alerting.
- Automatic renewal of any kind.
- Editing nginx/Apache configuration. The dashboard replaces certificate files only; it never rewrites vhost config.
- ACME, Let's Encrypt, certbot, or any HTTP-01/DNS-01 flow.
- High availability for the dashboard itself. It is a single-instance internal tool.
- Multi-tenancy. One organization per deployment.

### 2.3 Explicit non-goals

- The dashboard is not a CA and never signs anything.
- The dashboard is not configuration management. It does not create vhosts, and a binding it cannot find is reported, not fixed.
- The dashboard validates certificate paths to configured trust anchors, but does not query the CA for issuance or revocation status. OCSP/CRL checks remain outside v1.

---

## 3. Architecture

### 3.1 Component overview

```
                    admin browser (internal network)
                              |  HTTPS (terminated by front proxy)
                              v
                 +-------------------------------+
                 |  web  (FastAPI + Jinja2/htmx) |   enqueues jobs only
                 |  - UI, forms, auth, sessions  |
                 |  - read/write DB              |
                 |  - never runs Ansible         |
                 +---------------+---------------+
                                 |
                        +--------v--------+
                        |  db  PostgreSQL |
                        |  - data         |
                        |  - job queue    |
                        +--------^--------+
                                 |
                 +---------------+---------------+
                 |  worker                        |
                 |  - job scheduler               |
                 |  - ansible-runner (SSH)        |
                 |  - TLS scans                   |
                 |  - SMTP alerts                 |
                 |  - git pull of inventory repo  |
                 +---------------+---------------+
                                 | SSH (Ansible)
                                 v
                 50-500 nginx / Apache servers
```

Three containers, one image:

| Container | Command | Responsibility |
| --- | --- | --- |
| `web` | `uvicorn app.main:app` | Server-rendered UI and JSON endpoints, auth, sessions, validation, job enqueue, read models, downloads |
| `worker` | `python -m app.jobs.worker` | Scheduler tick, job claim/execute, ansible-runner, TLS scans, SMTP, inventory git pull, master-key rotation CLI |
| `db` | `postgres:16` | All persistence, including the job queue |

**Assumption:** PostgreSQL 16 (any 14+ works; the queue relies only on `FOR UPDATE SKIP LOCKED`).

The split is a security and blast-radius boundary: the internet-facing-ish web process holds no SSH credentials, and only the worker mounts the Ansible SSH key and the inventory checkout.

### 3.2 Why PostgreSQL as the queue

The workload is low-volume (single-digit jobs per hour, bursts of one deploy job with many hosts). A queue table with `SKIP LOCKED` is sufficient, transactional with the rest of the data, and removes Redis/Celery from the operational surface.

Claim query, executed by each idle worker slot:

```sql
UPDATE job
SET status = 'running',
    locked_by = $1,
    locked_at = now(),
    started_at = now(),
    attempt = attempt + 1
WHERE id = (
  SELECT id FROM job
  WHERE status = 'queued'
    AND run_after <= now()
  ORDER BY priority DESC, run_after ASC, created_at ASC
  FOR UPDATE SKIP LOCKED
  LIMIT 1
)
RETURNING *;
```

Properties:

- Exactly one worker claims a row; `SKIP LOCKED` prevents head-of-line blocking.
- `locked_by` identifies the worker instance (hostname + pid + boot id).
- A reaper marks `running` jobs whose `timeout_at` has passed as `failed` with reason `timeout` and releases their hosts.
- Retries are explicit: `attempt`, `max_attempts`, `run_after` (exponential backoff), and a `retryable` flag on the error classification.
- Jobs are never deleted; a retention job prunes finished jobs older than 90 days (and their `job_host` rows) while keeping audit records.

`priority` values: deploy = 300, on-demand discovery/scan = 200, scheduled = 100, digest = 50, cleanup = 10.

**Assumption:** one worker container with a concurrency of 4 job slots (`WORKER_CONCURRENCY=4`). Additional worker replicas are supported but not required; per-host advisory locks (3.6) make concurrent deploys safe.

### 3.3 Deployment topology

`docker-compose.yml` services:

| Service | Image | Volumes | Secrets |
| --- | --- | --- | --- |
| `db` | pinned `postgres:16-bookworm` (UID/GID 999) | `pgdata:/var/lib/postgresql/data` | `db_owner_password`, `db_password` |
| `web` | built from `./Dockerfile` | none | `master_key`, `db_password`, `session_secret` |
| `worker` | same image, different command | `inventory:/srv/inventory`, `artifacts:/srv/artifacts`, tmpfs `/run/cert-keys` | `master_key`, `db_password`, `ansible_ssh_key`, `ansible_vault_password` (optional), `inventory_git_token` (optional), `smtp_password` (optional) |

The worker's `/run/cert-keys` is a **tmpfs mount**, never a volume: `tmpfs` with `size=16m`, `mode=0700`, `uid=10001`, `gid=10001`, `noexec`, `nosuid`, `nodev`. It holds decrypted keys only for the duration of a deploy host run (5.2) and is wiped at worker startup. Nothing under `/srv/artifacts` ever contains key material.

- Only `web` publishes a port, and only to the internal front proxy. `db` is unreachable from outside the compose network.
- One `Dockerfile`, multi-stage, non-root user `app` (uid 10001), pinned base image digest, `PYTHONUNBUFFERED=1`, no build toolchain in the runtime layer.
- Health checks: `web` on `GET /healthz`; `worker` by heartbeat freshness (3.8); `db` by `pg_isready`.
- `restart: unless-stopped` on all three.
- Compose file contains environment variables and secret *names*, never secret values.

### 3.4 Configuration and secrets

Configuration is environment variables plus files under `/run/secrets/`. Precedence: Docker secret file > environment variable > code default.

| Secret file | Required | Used by | Content |
| --- | --- | --- | --- |
| `master_key` | yes | web, worker | JSON keyring, see 5.1 |
| `db_password` | yes | web, worker, db bootstrap | Runtime app_role password; shared file owner 10001:999, mode 0440 |
| `db_owner_password` | yes | db, one-shot migration only | Distinct owner password; owner 999:999, mode 0400; never mounted into normal web/worker |
| `session_secret` | yes | web | 32+ random bytes, HMAC for session-bound values |
| `ansible_ssh_key` | yes (worker) | worker | Private SSH key for Ansible |
| `ansible_vault_password` | no | worker | Password for the inventory's vaulted group_vars |
| `inventory_git_token` | no | worker | Read-only token if the repo is not cloned with a deploy key |
| `smtp_password` | no | worker | SMTP auth password; absent means unauthenticated relay |

Rules:

1. No secret value is ever written to the database, logs, job payloads, or the UI.
2. Secret files are read at startup into memory and never re-read per request (rotation = restart, Section 11).
3. The app refuses to start if a required secret is missing, empty, or malformed, and prints a remediation hint (Section 9.2).
4. `web` does not mount `ansible_ssh_key` at all.
5. Start-up logs print secret *presence and fingerprint metadata only* (e.g. keyring version and SHA-256 of the file), never contents.
6. Compose file-backed secrets are read-only bind mounts preserving host ownership/modes; do not specify ignored mode/uid/gid remapping. `/etc/cert-dashboard/secrets` is root:root 0711. App/worker secret files are 10001:10001 0400; db_owner_password is 999:999 0400; shared db_password is 10001:999 0440. `scripts/install-secrets.sh` applies these permissions to existing canonical files without reading/copying values. Verify postgres UID/GID 999 in the pinned Debian image.
7. The dedicated one-shot migrate service runs as 999:999 with DB-only settings and only db_owner_password mapped to /run/secrets/db_password; it inherits no web configuration or application secrets. Runtime app_role owns no schema/tables and cannot assume the owner role.

### 3.5 Code layout

```
app/
  main.py              FastAPI app factory, routers, middleware, error handlers
  config.py            env + secret file loader, typed settings
  db.py                engine, session factory, transaction helpers
  models/              SQLAlchemy 2.0 declarative models (one module per table)
  migrations/          Alembic revisions
  auth/
    base.py            AuthBackend protocol, AuthResult dataclasses
    local.py           argon2id + TOTP backend (v1)
    ldap.py            present as a stub returning "not implemented" (v2)
    sessions.py        server-side sessions, CSRF
  crypto/
    keyring.py         master keyring load, versioned AES-256-GCM wrap/unwrap
    keys.py            RSA/ECDSA generation, public key fingerprints
    csr.py             CSR build and validation
    chain.py           chain ordering and validation, PEM assembly
    trust.py           offline PolicyBuilder/Store path validation
    pfx.py             PKCS#12 build (and PKCS#12 import)
    parse.py           PEM/DER/PFX parsing, fingerprint, SAN extraction
  services/
    certificates.py    inventory CRUD, dedupe, lineage
    renewals.py        renewal state machine
    discovery.py       diff of discovery output into server/binding
    deploy.py          rollout planning, batching, host scheduling
    scans.py           TLS scan engine
    alerts.py          expiry evaluation, digests, SMTP
    audit.py           append-only audit writer
    trust_anchors.py   uploaded roots, in-memory public bundle, chain rechecks
  jobs/
    worker.py          scheduler tick, claim loop, reaper
    queue.py           enqueue/claim/complete primitives
    handlers/          one module per job type
  ansible/
    runner.py          ansible-runner wrapper, event parsing
    parse_nginx.py     `nginx -T` parser
    parse_apache.py    vhost dump parser
    playbooks/
      discover.yml
      deploy.yml
  templates/           Jinja2 + htmx partials
  static/
  cli.py               bootstrap-admin, generate-master-key, rotate-master-key, verify-key
tests/
  unit/ integration/ fixtures/
docker-compose.yml
docker-compose.test.yml
Dockerfile
pyproject.toml
```

Parsers live in Python on the worker, not in Jinja/Ansible templates, so they are unit-testable against captured dumps (Section 10).

### 3.6 Concurrency and locking

- One deploy job at a time is enforced by a global advisory lock keyed on the constant `deploy:global`, taken by the worker for the job's duration. A **paused** canary job holds no lock, so its lock is re-acquired on resume; if another deploy took it in the meantime, the resumed job simply waits in `queued` until the lock is free (it is never dropped or failed for this).
- Per-host serialization uses `pg_try_advisory_lock(hashtext('deploy:' || hostname))`; if the lock is held, the host is marked `skipped` with reason `locked`, protecting against two operators targeting the same server.
- Discovery and scan jobs may run in parallel with each other, capped at `MAX_PARALLEL_JOBS` (default 2) per worker.
- Inventory git pull uses its own lock (`inventory:pull`) and is a no-op if a pull completed less than 60 seconds ago.

### 3.7 Non-functional targets

| Area | Target |
| --- | --- |
| Page render (p95) | < 300 ms for lists at 5,000 bindings, server-side pagination + indexes |
| Job claim latency | < 2 s from enqueue to start |
| Discovery, 100 hosts | < 5 min with `forks=20` |
| TLS scan, 500 endpoints | < 10 min with 20 concurrent connections, 10 s timeout |
| Alert evaluation | < 60 s for 500 certificates |
| Deploy, 100 hosts | < 15 min at batch size 10 and 5 concurrent hosts |
| Availability | Business-hours best effort; the dashboard being down never affects served TLS |

### 3.8 Worker liveness

The worker upserts a `worker_heartbeat` row every 30 seconds (`worker_id`, `started_at`, `last_seen_at`, `current_job_id`). `web` shows a red banner and the settings screen shows worker state when the newest heartbeat is older than 5 minutes. `/healthz` returns `{"web":"ok","worker":"ok|stale","db":"ok"}`.

### 3.9 Request flow examples

**Enqueue a deploy:** the operator submits the deploy form; `web` validates the certificate is `issued` and unexpired, resolves the affected bindings, writes `job` + `job_host` rows in one transaction, writes an `audit_log` row, and redirects to the job page. `web` never invokes Ansible.

**Job execution:** the worker claims the job, takes locks, runs `deploy.yml` per host in a bounded thread pool, writes `job_host` state as it goes, and on completion updates `job`, writes audit rows, and (on failure) leaves the failure visible in the UI and the digest.

**Downloads:** `web` reads the certificate PEM from the DB for PEM/chain downloads. PFX export requires password re-entry, decrypts the key in memory inside `web`, builds the PKCS#12 in memory, streams it, and writes a `key_export` audit row. The plaintext key never touches disk.

---

## 4. Data model

PostgreSQL, SQLAlchemy 2.0 models, Alembic migrations. Table names use the singular form from the brief. All tables carry `created_at`/`updated_at` (`timestamptz`, UTC) unless noted. IDs are `bigserial` except `job`, `job_host`, `renewal`, `audit_log`, and `user_session`, which use UUIDs to make URLs and logs non-enumerable.

**Assumption:** all timestamps stored in UTC; the UI renders in the browser's local timezone and emails state the timezone explicitly.

### 4.1 ERD

```
user 1---* user_session
user 1---* renewal (actor)
user 1---* audit_log
private_key 1---* certificate (key_id)
certificate 1---* certificate (renews_id, lineage)
certificate 1---* renewal (previous / new)
certificate 1---* binding (certificate_id, nullable until matched)
private_key 1---* binding (via certificate)
server 1---* binding
server 1---* endpoint
endpoint 1---* scan_result
binding 1---* job_host (target binding)
job 1---* job_host
certificate 1---* notification_log
```

### 4.2 Enumerations

| Enum | Values |
| --- | --- |
| `certificate_status` | `active`, `superseded`, `revoked` |
| `chain_status` | `trusted`, `incomplete`, `untrusted_root`, `unchecked` |
| `trust_anchor_source` | `public_bundle`, `uploaded` |
| `private_key_type` | `rsa`, `ecdsa` |
| `renewal_state` | `draft`, `csr_generated`, `submitted`, `issued`, `deployed`, `done`, `cancelled` |
| `webserver_type` | `nginx`, `apache` |
| `job_type` | `discover`, `deploy`, `scan`, `alert_expiry`, `digest`, `cleanup` |
| `job_status` | `queued`, `running`, `paused`, `succeeded`, `failed`, `cancelled` |
| `job_host_status` | `pending`, `running`, `succeeded`, `failed`, `rolled_back`, `skipped` |
| `scan_status` | `ok`, `mismatch`, `expired`, `unreachable`, `error` |
| `endpoint_source` | `manual`, `discovery` |
| `notification_status` | `sent`, `failed` |
| `auth_backend` | `local`, `ldap` |

`cancelled` on `renewal_state` is an addition beyond the brief: an operator must be able to abandon a draft without deleting history. `expired` on `scan_status` is a derived convenience value, stored so the UI can filter without recomputing.

### 4.3 `certificate`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigserial PK | |
| `common_name` | text not null | First CN, or the first SAN if the CN is empty (modern certificates) |
| `subject_dn` | text not null | Full RFC 4514 subject |
| `sans` | text[] not null default `{}` | DNS, IP, email, URI entries as strings, normalized to lowercase for DNS |
| `issuer_dn` | text not null | |
| `issuer_cn` | text not null | Denormalized for filtering |
| `serial` | text not null | Hex, lowercase, no leading zeros |
| `not_before` | timestamptz not null | |
| `not_after` | timestamptz not null | |
| `sha256_fingerprint` | char(64) not null | SHA-256 of the DER encoding, lowercase hex |
| `pem` | text not null | Leaf certificate PEM |
| `chain_pem` | text not null default '' | Intermediates, root excluded, see 4.4 |
| `chain_status` | `chain_status` not null default `unchecked` | Persisted offline path assessment, see 5.8 |
| `key_id` | bigint null FK `private_key(id)` | Null for imported public-only certificates |
| `owner_name` | text null | Human or team label |
| `owner_email` | text null | Alert recipient for this certificate |
| `team` | text null | Free-form group used for filtering and digests |
| `notes` | text null | |
| `status` | `certificate_status` not null default `active` | |
| `renews_id` | bigint null FK `certificate(id)` | The certificate this one replaces (lineage) |
| `imported_from` | text not null | `upload_pem`, `upload_pfx`, `pull_endpoint`, `renewal`, `discovery` |
| `created_by` | bigint null FK `user(id)` | |

Indexes and constraints:

- `unique (sha256_fingerprint)` — the dedupe key for import and discovery matching.
- `unique (issuer_dn, serial)` — catches the same certificate with different encodings.
- `index (not_after)` — expiry queries and screens.
- `index (status, not_after)`.
- `check (not_after > not_before)`.
- GIN index on `sans` for "which certificates cover this name" lookups.
- `check (key_id is not null or imported_from in ('upload_pem','upload_pfx','pull_endpoint'))` — a renewal-produced certificate must have a key.

`renews_id` forms a chain; cycles are prevented in application code (`services.certificates`) and validated on write.

### 4.4 Chain storage

`chain_pem` holds the supplied intermediates, root excluded, in leaf-to-root order where links can be established. Roots are excluded from certificate/chain/PFX downloads; uploaded trusted roots are separate `trust_anchor` rows, not part of `chain_pem`.

1. Parse every block; reject non-certificate blocks and malformed data.
2. Order known issuer/subject links and verify their signatures. Reject a supplied issuer claiming a link whose signature is invalid. Keep unresolved components in deterministic issuer-topological/fingerprint order with an incomplete-path diagnostic, rather than inventing a missing issuer.
3. Drop duplicates and self-signed roots from `chain_pem` with audit notes. Retain roots temporarily in memory as untrusted diagnostic candidates; they do not become trusted merely because a bundle contains them.
4. Assess the path using §5.8, the pinned certifi bundle when enabled, and uploaded anchors. Persist `certificate.chain_status`. Missing/untrusted/expired intermediate paths are warnings on both import and issued-certificate upload; they do not block inventory or renewal issuance. Malformed public material, wrong keys/CSR identity, or an invalid issued leaf validity window still block.
5. A chain/anchor/public-bundle setting change recomputes affected statuses through the service in §5.8. No AIA, trust-store download, or other network fetching occurs.

### 4.5 `private_key`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigserial PK | |
| `key_type` | `private_key_type` not null | |
| `key_size` | int not null | 2048/3072/4096 for RSA; 256/384 for ECDSA (curve strength) |
| `curve` | text null | `prime256v1` or `secp384r1` for ECDSA |
| `ciphertext` | bytea not null | AES-256-GCM ciphertext of the PEM-encoded private key |
| `nonce` | bytea not null | 12 random bytes, unique per encryption operation |
| `aad` | text not null | Context string, see 5.2 |
| `master_key_version` | int not null | Which keyring entry encrypted this row |
| `public_key_sha256` | char(64) not null | SHA-256 of the DER `SubjectPublicKeyInfo` — matching key to certificate |
| `public_key_pem` | text not null | Safe to store and display |
| `created_by` | bigint null FK `user(id)` | |
| `origin` | text not null | `generated`, `imported_pfx`, `imported_pem` |

Constraints: `unique (public_key_sha256)`, `index (master_key_version)`, `check (octet_length(nonce) = 12)`, `check (master_key_version >= 1)`.

`public_key_sha256` is how the app proves a key matches a certificate without decrypting it: the certificate's public key hashed the same way must be equal. It is also the fallback identity when a certificate is re-imported.

### 4.6 `renewal`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `certificate_id` | bigint null FK `certificate(id)` | The new certificate, set on `issued` |
| `previous_certificate_id` | bigint null FK `certificate(id)` | The certificate being replaced |
| `state` | `renewal_state` not null default `draft` | |
| `common_name` | text not null | Copied from the source certificate, editable in `draft` |
| `sans` | text[] not null | Copied, editable in `draft` |
| `key_id` | bigint not null FK `private_key(id)` | Generated at `csr_generated` |
| `csr_pem` | text null | |
| `csr_sha256` | char(64) null | Shown to the operator to compare with the CA portal |
| `ca_name` | text null | Free text, e.g. `DigiCert`, `Sectigo`, `ADCS` |
| `ca_order_reference` | text null | Operator-entered order/ticket number |
| `issued_chain_pem` | text null | Uploaded chain, validated |
| `state_changed_at` | timestamptz not null | |
| `created_by`, `submitted_by`, `issued_by`, `deployed_by` | bigint null FK `user(id)` | |
| `notes` | text null | |

State machine (enforced in `services.renewals`, one transition per request, each transition audited):

```
draft --generate_csr--> csr_generated --mark_submitted--> submitted
      --attach_issued_certificate--> issued --deploy--> deployed --finalize--> done
any non-terminal --> cancelled    (draft, csr_generated, submitted, issued)
```

Transition rules:

- `draft -> csr_generated`: requires key generation; CN/SANs frozen afterwards.
- `csr_generated -> submitted`: requires `ca_order_reference` (Assumption: an order reference is mandatory so the audit trail links to the CA).
- `submitted -> issued`: the uploaded leaf must parse, must match `csr_pem` (public key and subject/SANs), must match `key_id` by public key hash, and must not be expired. A chain is optional. Path failures (including missing intermediates or an untrusted self-signed issuer) persist a non-trusted chain_status and show warnings; they do not block this transition. Parse/key/CSR/leaf-validity checks remain mandatory.
- `issued -> deployed`: at least one successful deploy job covering the certificate; automatically advanced by the deploy handler.
- `deployed -> done`: manual confirmation by an admin that the old certificate is no longer needed anywhere.
- Any transition to `cancelled` keeps the row and the generated key (the key is not deleted; deleting keys is not exposed in the UI).
- Regressing a state is not allowed by the API. A mistaken transition is corrected by cancelling and creating a new renewal.

### 4.7 `server`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigserial PK | |
| `hostname` | text not null unique | Inventory hostname as Ansible sees it |
| `display_name` | text null | |
| `ansible_groups` | text[] not null default `{}` | From the inventory |
| `webserver` | `webserver_type` null | Auto-detected, or from inventory variable `webserver_type` |
| `connection_address` | text null | When it differs from `hostname` |
| `inventory_source` | text not null | Repo ref and inventory path that produced this row |
| `last_discovery_at` | timestamptz null | |
| `last_discovery_status` | text null | `ok`, `failed`, `unreachable` |
| `is_active` | boolean not null default true | Set false when the host disappears from the inventory; never deleted, so history survives |
| `notes` | text null | |

### 4.8 `binding`

One row per certificate-consuming directive in a vhost.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigserial PK | |
| `server_id` | bigint not null FK `server(id)` | |
| `webserver` | `webserver_type` not null | |
| `vhost_name` | text not null | `server_name` (first name) or Apache `ServerName`; `default` if none |
| `vhost_names` | text[] not null | All names in the vhost |
| `port` | int not null | 443 by default |
| `config_file` | text not null | Absolute path of the file containing the directive |
| `cert_path` | text not null | `ssl_certificate` / `SSLCertificateFile` |
| `chain_path` | text null | `SSLCertificateChainFile` or an extra `ssl_certificate` entry |
| `key_path` | text not null | `ssl_certificate_key` / `SSLCertificateKeyFile` |
| `cert_owner`, `cert_group`, `cert_mode` | text/text/int | From `stat` at discovery |
| `key_owner`, `key_group`, `key_mode` | text/text/int | From `stat` at discovery |
| `on_disk_fingerprint` | char(64) null | SHA-256 of the certificate at `cert_path` |
| `on_disk_key_public_sha256` | char(64) null | Public key hash of the key at `key_path` |
| `certificate_id` | bigint null FK `certificate(id)` | Matched by fingerprint |
| `match_state` | text not null | `matched`, `unknown`, `key_mismatch`, `missing_file` |
| `last_seen_at` | timestamptz not null | Last discovery that observed this binding |
| `is_active` | boolean not null default true | False when a binding disappears from a config |

Constraints: `unique (server_id, cert_path)`; `index (certificate_id)`; `index (server_id, is_active)`; `index (match_state)`.

`key_mismatch` means the certificate at `cert_path` does not correspond to the key at `key_path` — a real misconfiguration that must be surfaced loudly and must block any deploy touching that vhost.

Bindings are never hard-deleted by discovery: a binding missing from the latest dump becomes `is_active = false` with a "removed from config" note, so history and the audit trail remain intact.

### 4.9 `endpoint`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigserial PK | |
| `host` | text not null | DNS name or IP reachable from the worker |
| `port` | int not null default 443 | |
| `sni` | text null | Defaults to `host` |
| `source` | `endpoint_source` not null | |
| `server_id` | bigint null FK `server(id)` | Set when derived from a binding |
| `binding_id` | bigint null FK `binding(id)` | Set when derived from a binding |
| `expected_certificate_id` | bigint null FK `certificate(id)` | What should be served |
| `is_active` | boolean not null default true | |
| `last_scan_at` | timestamptz null | |
| `last_scan_status` | `scan_status` null | |

Constraints: unique index on `(host, port, coalesce(sni, host))`.

Endpoint creation: manual (UI form), automatic per discovered binding with a TLS port (one endpoint per `vhost_name:port`), and automatic on import-by-pull. Removing a binding deactivates its derived endpoints rather than deleting them.

### 4.10 `scan_result`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigserial PK | |
| `endpoint_id` | bigint not null FK `endpoint(id)` | |
| `status` | `scan_status` not null | |
| `observed_fingerprint` | char(64) null | |
| `observed_common_name` | text null | |
| `observed_issuer_cn` | text null | |
| `observed_not_after` | timestamptz null | |
| `observed_chain_length` | int null | |
| `expected_certificate_id` | bigint null FK `certificate(id)` | Snapshot of the expectation at scan time |
| `tls_version` | text null | Negotiated version |
| `error` | text null | Sanitized network error |
| `source` | text not null | `scheduled`, `manual` |
| `checked_at` | timestamptz not null default now() | |

Indexes: `index (endpoint_id, checked_at desc)`, `index (status, checked_at desc)`. Retention: 90 days per endpoint, pruned by the cleanup job.

`status` rules: `ok` = fingerprint equals the expected certificate; `mismatch` = a certificate is served but differs; `expired` = served certificate's `not_after` is in the past; `unreachable` = TCP/TLS failure; `error` = TLS succeeded but the handshake/certificate could not be processed. When `expected_certificate_id` is null the status is `ok` or `mismatch` against the inventory match, never `ok` by default (an endpoint with no expectation reports `mismatch` until an expectation is set — Assumption: endpoints created from a binding always get an expectation).

### 4.11 `job` and `job_host`

`job`:

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `type` | `job_type` not null | |
| `status` | `job_status` not null default `queued` | |
| `priority` | int not null | See 3.2 |
| `payload` | jsonb not null | Type-specific input, never contains secrets |
| `requested_by` | bigint null FK `user(id)` | Null for scheduled jobs |
| `scheduled_reason` | text null | `manual`, `nightly`, `daily`, `retry` |
| `attempt` | int not null default 0 | |
| `max_attempts` | int not null default 3 | 1 for deploy |
| `run_after` | timestamptz not null | Backoff target |
| `timeout_at` | timestamptz null | Set when claimed |
| `locked_by` | text null | |
| `locked_at` | timestamptz null | |
| `started_at`, `finished_at` | timestamptz null | |
| `error_class` | text null | `transient_network`, `config_invalid`, `auth`, `timeout`, `internal`, `validation` |
| `error_message` | text null | Sanitized |
| `result` | jsonb null | Summary counts, batch plan, `inventory_rev` |
| `resume_from_batch` | int not null default 0 | First batch to run on the next claim; set to 1 by a canary pause |
| `paused_at` | timestamptz null | When the job entered `paused`; drives the 24 h auto-cancel sweep |
| `ansible_artifact_dir` | text null | Path under the artifacts volume (never contains key material) |

`job_host` (one row per host a job touches; empty for non-host jobs):

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `job_id` | uuid not null FK `job(id)` on delete cascade | |
| `server_id` | bigint not null FK `server(id)` | |
| `binding_id` | bigint null FK `binding(id)` | For deploys |
| `batch_no` | int not null default 0 | 0 = canary |
| `status` | `job_host_status` not null default `pending` | |
| `started_at`, `finished_at` | timestamptz null | |
| `old_fingerprint` | char(64) null | On-disk fingerprint before the change |
| `new_fingerprint` | char(64) null | Expected and then verified fingerprint |
| `ansible_return_code` | int null | |
| `log_excerpt` | text null | Last ~200 lines, secret-scrubbed |
| `error_message` | text null | |
| `rolled_back` | boolean not null default false | |
| `rollback_error` | text null | |
| `precheck` | jsonb null | Drift check, disk space, config test result |

Constraints: `unique (job_id, server_id, binding_id)`; `index (job_id, status)`; `index (job_id, batch_no)`.

**Assumption:** `job_host` carries `binding_id`, so a single host with several affected vhosts gets several `job_host` rows (one per binding) that are executed as one Ansible run per host, updating all rows for that host together.

### 4.12 `user`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigserial PK | |
| `username` | citext not null unique | |
| `email` | citext not null | Used for alerts if the user owns certificates |
| `display_name` | text null | |
| `auth_backend` | `auth_backend` not null default `local` | |
| `password_hash` | text null | argon2id; null for LDAP-only users (v2) |
| `totp_secret_ciphertext` | bytea null | Encrypted like private keys (5.x) |
| `totp_secret_nonce` | bytea null | |
| `totp_secret_version` | int null | Master key version |
| `totp_enabled` | boolean not null default false | |
| `totp_confirmed_at` | timestamptz null | |
| `totp_last_used_step` | bigint null | Last accepted TOTP time step, for single-use enforcement |
| `recovery_codes` | text[] not null default `{}` | argon2id hashes, one per code, removed when used |
| `is_active` | boolean not null default true | |
| `failed_attempts` | int not null default 0 | |
| `locked_until` | timestamptz null | |
| `last_login_at` | timestamptz null | |
| `must_change_password` | boolean not null default false | |

### 4.13 `user_session`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | char(64) PK | 32 random bytes, hex; the cookie value |
| `user_id` | bigint not null FK `user(id)` on delete cascade | |
| `csrf_token` | char(64) not null | |
| `created_at`, `last_seen_at`, `expires_at` | timestamptz not null | |
| `ip`, `user_agent` | text null | |
| `revoked_at` | timestamptz null | |

Sessions: idle timeout 8 hours, absolute lifetime 24 hours (`Assumption`), rotated on login and on privilege-relevant change, deleted by the cleanup job.

### 4.14 `app_setting`

| Column | Type | Notes |
| --- | --- | --- |
| `key` | text PK | e.g. `smtp.host` |
| `value` | jsonb not null | |
| `updated_at` | timestamptz not null | |
| `updated_by` | bigint null FK `user(id)` | |

Known keys: `trust.include_public_bundle` (default `true`), `smtp.host`, `smtp.port`, `smtp.security` (`starttls`/`ssl`/`none`), `smtp.from`, `smtp.username`, `alert.thresholds_days` (default `[60,30,14,7,1,0]`), `alert.recipients` (team list), `alert.digest_enabled`, `inventory.repo_url`, `inventory.ref` (branch/tag), `inventory.path`, `inventory.webserver_var`, `deploy.batch_percent` (default 10), `deploy.pause_after_canary` (default true), `deploy.pause_timeout_hours` (default 24), `deploy.backup_retention_days` (default 30, `0` = keep forever), `deploy.concurrency` (default 5), `scan.timeout_seconds` (default 10), `scan.daily_at` (default `02:00`), `discovery.nightly_at` (default `03:00`), `digest.daily_at` (default `07:30`), `expiry_check.daily_at` (default `07:00`), `ui.timezone` (display default), `retention.days` (run/job retention, default 90).

Secrets are never stored here: SMTP password comes from the `smtp_password` secret file.

### 4.15 `notification_log`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigserial PK | |
| `certificate_id` | bigint null FK `certificate(id)` | Null for digest rows |
| `kind` | text not null | `expiry`, `digest` |
| `threshold_days` | int null | 60/30/14/7/1/0 |
| `recipients` | text[] not null | Resolved at send time |
| `status` | `notification_status` not null | |
| `error` | text null | |
| `sent_at` | timestamptz not null default now() | |
| `dedupe_key` | text not null unique | e.g. `expiry:42:30:2026-11-01` |

The `dedupe_key` makes alerting idempotent: one email per certificate, threshold, and day, regardless of how often the check runs. A failed send keeps its row and is retried on the next scheduler tick (row updated to `sent` on success), up to 3 attempts total; after that the row stays `failed`, the failure is shown in the digest and on the Settings Status panel, and the next day's key takes over.

### 4.16 `audit_log`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `actor_user_id` | bigint null FK `user(id)` | Null for `system` |
| `actor_label` | text not null | Username snapshot, or `system`/`worker:<id>` |
| `action` | text not null | Dotted verb, e.g. `certificate.import`, `key.export`, `deploy.start` |
| `target_type` | text not null | `certificate`, `job`, `user`, ... |
| `target_id` | text null | |
| `details` | jsonb not null default `{}` | Never contains secrets, keys, or passwords |
| `ip` | inet null | |
| `user_agent` | text null | |
| `created_at` | timestamptz not null default now() | |

Append-only enforcement, in the migration:

```sql
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM app_role;
CREATE RULE audit_log_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE audit_log_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;
```

The application role has `INSERT` and `SELECT` only. The audit list screen is read-only and paginated/filterable; there is no purge action in v1 (retention is a DBA task).

Audited actions include: login success/failure, logout, 2FA enable/disable, user create/deactivate, certificate create/import/update/status change, chain/leaf upload, renewal transition, CSR generation, key export, PFX export, deploy start/cancel, rollback, discovery run, scan run, settings change, master key rotation, admin bootstrap, `trust_anchor.add`, `trust_anchor.remove`, and `certificate.chain_check` (status/validation time only).

### 4.17 Migrations and seed data

- Alembic, one revision per change, `upgrade` only in production (no destructive auto-migrations on start; a `migrate` step runs in the deploy pipeline).
- Seed: nothing except a bootstrap admin created by `python -m app.cli bootstrap-admin --username ... --email ...` (prompts for the password, or reads `BOOTSTRAP_ADMIN_PASSWORD` once). Default settings rows are inserted by the first migration.
- Every table has `created_at`; mutable tables have `updated_at` maintained by a trigger.

### 4.18 `trust_anchor`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigserial PK | |
| `subject` | text not null | RFC 4514 subject |
| `sha256_fingerprint` | char(64) not null unique | Lowercase SHA-256 of DER |
| `pem` | text not null | One internal root CA certificate |
| `source` | `trust_anchor_source` not null default `uploaded` | Enum includes `public_bundle`/`uploaded`; only uploaded anchors are persisted |
| `notes` | text null | Operator context |
| `created_by` | bigint null FK `user(id)` | Uploading admin |
| `created_at` | timestamptz not null default now() | Immutable; removal is audited |

This table, its enum, `certificate.chain_status`, and the public-bundle setting are created by the single initial v1 migration. Certifi is pinned in the lock file and loaded into memory; its public roots are never copied into this table. Add rejects anything except a single PEM root with BasicConstraints `CA:TRUE`, matching issuer/subject, and a valid self-signature (and CA-signing usage if KeyUsage is present). Deduplicate by fingerprint. Delete removes the uploaded anchor and recomputes statuses in the same transaction; audit `trust_anchor.add/remove` records actor/fingerprint/subject/notes, not private material. Anchors contain public certificates only.

---

## 5. Key handling & security

### 5.1 Master keyring

The master key never lives in the database. It is supplied as the Docker secret `master_key`, a JSON document:

```json
{"active": 2, "keys": {"1": "<base64, 32 bytes>", "2": "<base64, 32 bytes>"}}
```

- `keys` maps version number to a 32-byte AES-256 key. `active` names the version used for all new encryption.
- At most two versions are kept: the active one and the previous one, which exists only during a rotation window.
- Startup validation: valid JSON, 32-byte decoded keys, `active` present in `keys`, max 16 versions parsed, no duplicate keys. Any failure aborts start-up.
- Versions are monotonically increasing integers; the app never reuses a version number.
- Generate with `python -m app.cli generate-master-key --version 1` (which calls `os.urandom(32)` and prints the JSON plus its SHA-256 for verification).

### 5.2 Encryption of private keys and TOTP secrets

- Algorithm: AES-256-GCM, 12-byte random nonce per encryption operation, 16-byte authentication tag appended to the ciphertext (the `cryptography` library's default `AESGCM` layout).
- Associated data (`aad`) is a context string that binds the ciphertext to its row and purpose: `private_key:<id>:<master_key_version>` and `user:<id>:totp:<master_key_version>`. Because the AAD contains the row id, the writer inserts the row first to obtain the id, encrypts, and sets the ciphertext in the same transaction; a rollback leaves no half-encrypted row. Copying ciphertext into a row with a different id (a manual data fix, or a re-insert with a new sequence) invalidates it by design, so key material cannot silently migrate between rows. A plain database restore keeps the ids and therefore still decrypts.
- Plaintext is the PEM-encoded unencrypted key (`TraditionalOpenSSL`/PKCS#8 without a passphrase) or the base32 TOTP secret; it exists only in memory for the duration of the operation.
- `master_key_version` is stored per row so a rotation can find stale rows: `SELECT count(*) FROM private_key WHERE master_key_version <> $active`. Every version referenced by a row must still be present in the keyring; removing a version that rows still reference makes those rows unreadable, which the Status panel warns about before rotation completes.
- Decryption failures (wrong key, tampered row, wrong AAD) raise a single `KeyUnwrapError` that the UI reports as "key material cannot be decrypted with the configured master key" and that the audit log records. The app never falls back to a different version silently and never returns partial plaintext.
- Plaintext keys are never logged, never placed in job payloads, and never passed to Ansible as extra-vars, environment variables, or `ansible-runner` artifacts. The one exception is Ansible needing a key file at a path: the worker decrypts in memory and stages the key as a `0600` file inside a **tmpfs-only** staging directory (`/run/cert-keys`, see 3.3), passes *only the path* to the playbook, and deletes the file in a `finally` block. Nothing is written to the persistent artifacts volume or any other on-disk location; the tmpfs also disappears on container stop. The worker wipes `/run/cert-keys` on startup so a crash cannot leave a key behind for the next run. This is assumption A10.
- Attempts to log a key-shaped string are blocked by a logging filter that redacts `-----BEGIN ... PRIVATE KEY-----` blocks and long base64 runs.

### 5.3 Key generation, matching, and export

- Generation: RSA 2048/3072/4096 (`public_exponent=65537`) or ECDSA P-256 (`secp256r1`/`prime256v1`) / P-384 (`secp384r1`). Default RSA 2048 for compatibility with the CA portals in use; the UI states the trade-off.
- CSR: SANs from the renewal's CN/SANs, `subject` with CN only, SHA-256 signature. The CSR and its SHA-256 are displayed so the operator can compare them with the CA portal.
- Key/certificate matching is always by `public_key_sha256` (SHA-256 of the DER `SubjectPublicKeyInfo`). Uploaded issued certificates whose public key does not match the renewal's key are rejected, with the two fingerprints shown.
- Export:
  - PEM leaf, chain, full chain (leaf+chain), and PFX are offered from the certificate detail screen.
  - PEM/chain downloads need no re-authentication beyond the session (they contain no private material).
  - **PFX export requires password re-entry** (the user's own password, or an admin re-auth), a user-chosen PFX password of at least 12 characters, and is audited as `key.export` with the certificate id, user, IP, and the PFX password *never* recorded.
  - Requesting the private key in PEM form (needed for exceptional cases) is **not exposed in v1**; the only way to obtain the key is a PFX with a user-chosen password. `Assumption`: if a PEM key export is needed later it becomes an explicitly audited, re-authenticated action.
  - PFX builds: PKCS#12, leaf + chain + key, `BestAvailableEncryption(pfx_password)`, no MAC-iteration weakening, friendly name = CN.

### 5.4 Authentication and sessions

`auth/base.py` defines the pluggable interface that LDAP will implement in v2:

```python
class AuthBackend(Protocol):
    name: str
    def authenticate(self, username: str, password: str) -> AuthResult: ...
    def lookup(self, username: str) -> UserRecord | None: ...
    def supports_password_change(self) -> bool: ...
```

`AuthResult` is `Success(user_key, display_name, email)` or `Failure(reason)` where reason is one of `invalid_credentials`, `locked`, `inactive`, `backend_unavailable`, `not_supported`. `web` selects the backend by `user.auth_backend` (local in v1) and renders the same login form for all backends. An LDAP backend is selected by configuration and must not change the login flow or the session model.

Local backend:

- Passwords: argon2id with `time_cost=3`, `memory_cost=64 MiB`, `parallelism=4`, 16-byte salt, and rehash-on-login when parameters change. Minimum 12 characters, checked against a small top-1000 list; no forced periodic rotation (`Assumption`: NIST-style guidance).
- 2FA: TOTP, RFC 6238, SHA-1, 6 digits, 30-second step, ±1 step window, single-use enforcement by storing `last_used_step` on the user (column added in the same migration as `totp_*`). Enrollment shows the secret once and 10 single-use recovery codes stored as argon2 hashes (`Assumption`: recovery codes are in scope because all admins share one account model).
- Lockout: 10 consecutive failures lock the account for 15 minutes; every failure and lockout is audited.
- Login rate limit: 5 attempts per minute per source IP, enforced in `web` with a Postgres-backed counter table (`Assumption`: a table rather than in-memory state, so restarts do not reset throttling).
- Sessions: opaque 32-byte random id in a cookie named `cd_session`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, host-only. Server-side state in `user_session`; a stolen cookie can be revoked. CSRF: a per-session token in a `csrf_token` form field and the `X-CSRF-Token` header for htmx requests; all non-GET requests are rejected without it. Cookie is invalidated on logout, on password change, and on 2FA change.
- Password change and 2FA management live in the user menu; an admin can reset another user's password from Users (audited, sets `must_change_password`).

### 5.5 Authorization model

v1: all authenticated, active users are admins. There is no per-object permission. Every mutating endpoint requires a valid session and CSRF token; every mutating action writes an audit row. Unauthenticated requests to any route except `/login`, `/healthz`, and static assets are redirected to `/login` (HTML) or answered `401` (JSON). The auth layer exposes `require_user` and `require_admin`; in v1 both are the same check, so introducing roles later only changes `require_admin`.

### 5.6 Threat model (concise)

| Threat | Impact | Mitigation |
| --- | --- | --- |
| Database dump leaked | Certificates readable; private keys are ciphertext | AES-256-GCM with a master key held outside the DB; GCM authenticates as well as encrypts |
| Master key leaked without DB | No certificates to combine, keys useless alone | Key and DB backups are stored separately (Section 11) |
| Web container compromised | Full admin session, but no SSH access | Web holds no Ansible SSH key, has no inventory checkout, and cannot run jobs directly |
| Worker container compromised | SSH to managed servers, can decrypt keys | Worker has no public port; runs as non-root; plaintext key files live only on its private volume and are deleted after use |
| Malicious insider | Mass deploy or key theft | Argon2id, optional TOTP, mandatory re-auth for PFX export, append-only audit, canary-first rollout |
| Log exfiltration | Indirect secret leak | `no_log` on all key tasks, redaction logging filter, no secrets in payloads or error messages |
| Wrong certificate deployed | Outage at the vhost | Key-match validation, drift precheck, configtest, live fingerprint verification, automatic rollback |
| Replay/CSRF | Unauthorized state change on a logged-in admin | SameSite=Lax, per-session CSRF token, POST-only mutations |
| Brute force | Account takeover | Lockout, IP rate limit, optional TOTP, argon2id cost |

### 5.7 Transport and network posture

- The app is served over HTTPS by an internal front proxy (nginx) that terminates TLS; `web` listens on plain HTTP inside the compose network only. `Assumption`: the proxy is operated by the platform team and is out of this repo; the compose file binds `web` to `127.0.0.1` so nothing is exposed by default.
- Ansible connects over SSH with a dedicated key, dedicated user, and `StrictHostKeyChecking=yes` against a `known_hosts` file baked into the worker image at build time (or mounted). Host key changes fail the job rather than being accepted.
- No outbound internet access is required except SMTP, the CA portals (browser side only), and the inventory Git remote.
- `db` accepts connections only from the compose network, with a strong password from a secret.

### 5.8 Offline trust-anchor path validation

Use `cryptography.x509.verification.PolicyBuilder` and `Store`: build leaf → supplied/stored intermediates → a configured anchor at an explicit UTC `validation_time` (current time for import/recheck/deploy, never backdated to bypass expiry). Include the pinned certifi bundle only when `trust.include_public_bundle=true` (default); merge it in memory with uploaded roots. Verification enforces signatures, CA constraints, and the validity of the leaf and intermediates; choose the server identity from the certificate's DNS/IP SANs consistently. No network, AIA, OCSP, or CRL checks run.

Persist one `certificate.chain_status`:

- `trusted`: PolicyBuilder verifies a path to an enabled anchor at validation_time.
- `untrusted_root`: no trusted path, but a cryptographically connected path reaches a supplied/known self-signed root not in the enabled anchor set. An uploaded bundle's root is diagnostic, not an automatic trust grant.
- `incomplete`: no valid path (including a missing intermediate, an expired intermediate, or another policy failure); show the missing issuer/policy diagnostic. When no terminal root is available, do not guess it is a root: use incomplete.
- `unchecked`: no assessment has run yet; never treat it as trusted.

Import and issued upload display non-trusted results inline and on certificate detail but continue after their existing parse/key/CSR/leaf-validity gates pass. Recompute on chain changes, anchor add/remove, and public-bundle toggle through `recheck_chain_statuses(db, validation_time, diagnostic_roots=())`; when removing an anchor, retain the removed public root in memory for that recheck's untrusted-root diagnosis. The cached status reflects the last assessment; a later assessment may report incomplete if a formerly supplied untrusted root is no longer available. Each changed persisted status gets a metadata-only certificate.chain_check audit with validation_time.

Plan 1 performs these rechecks synchronously (at most ~500 certificates). Plan 2 may move the same service into a registered background recheck action; no additional v1 job enum/table is required. Plan 3 revalidates at current time before deploy and requires trusted unless an admin explicitly supplies a required reason for an audited `deploy.chain_override` (certificate, previous status, actor, job, reason). A trust override never bypasses key/leaf-validity/drift/config-test guardrails.

---

## 6. Discovery & deploy (Ansible)

### 6.1 Inventory source

The team's existing static inventory repository (INI or YAML inventory plus `group_vars`/`host_vars`) is the only source of servers.

- The worker clones it read-only into `/srv/inventory` (persistent volume) using `inventory.repo_url` and `inventory.ref`, authenticated by `inventory_git_token` or a deploy key supplied as part of `ansible_ssh_key` configuration. `Assumption`: the token is a read-only deploy token; the dashboard never pushes.
- Refresh rules: a pull runs before every discovery job and before every deploy job, and nightly before the scheduled discovery. A pull uses `git fetch` + `git reset --hard origin/<ref>` on a clean checkout. A pull failure does not destroy the previous checkout: a failed fetch keeps the last good revision, records `inventory_rev` in the job result, and fails the job if the checkout is older than 24 hours.
- The worker records the resolved commit SHA for every discovery and deploy (`server.inventory_source`, `job.result.inventory_rev`) so the state of a binding is always traceable to an inventory revision.
- The webserver type per host comes from the inventory variable named by `inventory.webserver_var` (default `webserver_type`) with values `nginx`/`apache`. When absent, discovery auto-detects by testing for `nginx -v` and `apachectl -v` and records `server.webserver`.
- Vaulted variables are decrypted with `ansible_vault_password` when present; the password is passed to `ansible-runner` as an environment variable inside the process, never as a CLI argument (so it does not appear in `ps`).

**Assumption:** inventory hostnames are resolvable from the worker and SSH is already working for an existing playbook; the dashboard does not provision SSH access or users.

### 6.2 `discover.yml`

Runs on the target group (whole inventory by default). Per host:

1. Auto-detect the webserver and its binary paths if the inventory variable is missing.
2. Capture the full configuration dump:
   - nginx: `nginx -T` (stderr+stdout, because `-T` writes the dump to stderr on older versions), which includes `# configuration file <path>:` markers.
   - Apache: `apachectl -t -D DUMP_VHOSTS` plus a concatenation of every file the dump references (each with a file marker) using `apachectl -S` output to determine the file list; when the file list cannot be derived, fall back to a recursive read of `Include`d paths from the main config.
3. For every certificate path found, `stat` it (owner, group, mode, size, mtime, exists) and compute its fingerprint with `openssl x509 -noout -fingerprint -sha256 -in <path>` (`Assumption`: `openssl` is present on every target; it is present on all supported distributions with nginx or Apache from packages).
4. For every key path, `stat` it and compute `openssl pkey -in <path> -pubout | openssl dgst -sha256`. This task is `no_log: true`; only the resulting hash leaves the host. If the key is passphrase-protected, record `key_unreadable: true` and skip the hash.
5. Emit one JSON document per host:

```json
{
  "hostname": "web01.example.internal",
  "webserver": "nginx",
  "collected_at": "2026-10-19T03:00:12Z",
  "bindings": [
    {
      "webserver": "nginx",
      "vhost_name": "www.example.com",
      "vhost_names": ["www.example.com", "example.com"],
      "port": 443,
      "config_file": "/etc/nginx/conf.d/www.conf",
      "cert_path": "/etc/nginx/ssl/www.example.com.crt",
      "chain_path": "/etc/nginx/ssl/www.example.com.chain.pem",
      "key_path": "/etc/nginx/ssl/www.example.com.key",
      "cert_owner": "root", "cert_group": "root", "cert_mode": "0644",
      "key_owner": "root", "key_group": "root", "key_mode": "0600",
      "cert_exists": true,
      "cert_fingerprint": "9f2a...e1",
      "key_public_sha256": "77be...40",
      "key_unreadable": false
    }
  ],
  "errors": []
}
```

6. `ansible-runner` returns one such document per host (`artifacts/<job_id>/<host>/stdout`, parsed as JSON events). The worker parses `nginx -T` and the Apache dumps in `app/ansible/parse_nginx.py` / `parse_apache.py` into this schema, so the parsers are unit-tested rather than trusted in production (Section 10).
7. Discovery is read-only. It never writes files, never reloads services, and never uses `become` beyond what reading root-owned files requires.

Parsing rules (nginx):

- Split the dump on `# configuration file <path>:` markers to attribute directives to files.
- Track `server { ... }` blocks, `listen` (port and `ssl` flag), `server_name`, `ssl_certificate`, `ssl_certificate_key`.
- Resolve relative paths against the prefix `/etc/nginx` (paths in nginx are relative to the prefix).
- A `server` block with more than one `ssl_certificate` is an RSA+ECDSA pair; the first is `cert_path`, the second is `chain_path` when its certificate's issuer matches the first's issuer, otherwise both are recorded as separate bindings.
- `include`d files are expanded by `nginx -T` itself, so no manual include resolution is needed.

Parsing rules (Apache):

- `apachectl -S` gives vhost → file → `ServerName` → port.
- `SSLCertificateFile`, `SSLCertificateKeyFile`, `SSLCertificateChainFile` are extracted from the defining `<VirtualHost>` block; a global-level directive is recorded as binding `vhost_name = "default"`.
- Multiple `SSLCertificateFile` entries in one vhost (a chain written as several files) are concatenated into `chain_path` per the issuer-matching rule above.

### 6.3 Discovery reconciliation

`services.discovery` turns a discovery dump into state changes, in one transaction per server:

| Situation | Result |
| --- | --- |
| Binding seen, on-disk fingerprint matches a `certificate` row and the key hash matches that certificate's key | `match_state = matched`, `certificate_id` set |
| Binding seen, fingerprint matches no certificate | `match_state = unknown`, `certificate_id = null`; the certificate is listed under "Unknown certificates on servers" (its PEM is not imported automatically) |
| Binding seen, certificate found but the key at `key_path` hashes differently | `match_state = key_mismatch`; flagged everywhere and blocks deploys for that binding |
| Binding seen, file missing or unreadable | `match_state = missing_file`, recorded with the error |
| Binding seen before, absent now | `is_active = false`, note `removed from config at <date>` |
| Binding appears for the first time | Inserted; an endpoint is auto-created if the port is a TLS port |
| Host missing from inventory | `server.is_active = false`; bindings deactivated, never deleted |
| Host missing from the dump but present in inventory | `server.last_discovery_status = failed` with the Ansible error; previous bindings are kept and marked stale rather than deleted |

Unknown certificates are deliberately not auto-imported: the dashboard cannot know which chain to attach, and an auto-import would fill the inventory with certificates nobody owns. They are listed on the Overview and in the digest as "unknown certificates on servers", each with an "Import as certificate" action that accepts the pasted or uploaded leaf PEM. Nothing is fetched from the target automatically.

### 6.4 `deploy.yml`

Executed **once per host**, not once per binding, so rollback is host-atomic. Inputs (Ansible extra-vars): `cert_pem_path`, `chain_pem_path`, `key_pem_path` (file *paths* only), plus a JSON `targets` array: one entry per binding with `cert_path`, `chain_path`, `key_path`, and the expected previous fingerprints. Certificate and chain paths point into the artifact directory; `key_pem_path` points into the tmpfs staging directory `/run/cert-keys` (5.2, 3.3). No extra-var, environment variable, `ansible-runner` artifact, or log line ever carries key content — only the path.

Steps:

1. **Preflight**
   - `stat` the current certificate files: if a binding's on-disk fingerprint differs from the discovery snapshot in the job, abort the host with `drift_detected` (no changes made).
   - Check free space on the filesystem holding each target path (require at least 2× the size of the files being written plus a 10 MB margin).
   - Run the current config test (`nginx -t` / `apachectl configtest`). If it already fails, abort without changes — a bad baseline makes rollback meaningless.
   - Verify the new leaf's public key hash matches the new key's hash (defence in depth; the app already did this).
2. **Back up** every affected file to `/var/backups/cert-dashboard/<job_id>/<absolute path with directories>`, because the backups contain the old private keys. The root directory is created `root:root` with mode `0700` (and re-asserted on every run), each backup file keeps the original owner/group, the key backup is `0600` and the certificate backups are no more permissive than `0644`. Write a `manifest.json` with original fingerprints and metadata. Refuse to proceed if any backup is missing. After a successful host run, prune this host's `/var/backups/cert-dashboard/*` directories older than `deploy.backup_retention_days` (default 30, `0` = keep forever), always keeping the most recent backup that contains each path, so a rollback target is never pruned away.
3. **Write** each new file: copy to a temporary file in the same directory, set owner/group/mode (key `0600`, cert `0644` unless the old file had a stricter mode, in which case keep the stricter one), then atomically `mv` over the target. The private key task is `no_log: true`, and the destination mode is set before the content is written.
4. **Label**, when SELinux is enabled: `restorecon` the changed paths so the web server can still read them (`Assumption`: enforcing-mode SELinux exists on some targets; `restorecon` is a no-op otherwise).
5. **Config test**: `nginx -t` / `apachectl configtest`. On failure → rollback (step 8).
6. **Reload**: `nginx -s reload` (or `systemctl reload nginx`) / `apachectl graceful`. A reload exit code != 0 → rollback.
7. **Verify the served certificate**: from the target, `openssl s_client -connect 127.0.0.1:<port> -servername <vhost_name> -showcerts`, take the leaf, compute SHA-256, compare with the new fingerprint. Also record the observed chain length. A mismatch or handshake failure → rollback. Verification is retried up to 3 times with 2-second spacing to allow a slow reload. `Assumption`: an on-target check is authoritative because the worker may not resolve every internal vhost name; when the endpoint is reachable from the worker, an additional check is recorded in `job_host.precheck` but does not trigger a rollback (a load balancer in front can legitimately serve another node's certificate).
8. **Rollback** on any failure at steps 5-7: restore every file from the backup with its original metadata, re-run the config test, reload, verify the old fingerprint is served again, set `rolled_back = true`, and report `failed` with the original error and the rollback outcome. If the rollback itself fails, report `rolled_back = false` with `rollback_error`, write a `deploy.rollback_failed` audit row, and surface the host as **needs manual attention** in the UI and the digest. The dashboard never retries a rollback automatically beyond the single attempt.
9. **Idempotency**: if the on-disk fingerprint already equals the new fingerprint, skip writing and still run config test, reload, and verify. A re-run of the same job is safe.
10. **Result**: a JSON object per host with `status`, per-binding old/new fingerprints, `rolled_back`, `verify`, backup path, and a redacted log excerpt. The backup stays on the host for manual recovery and is pruned by step 2's `deploy.backup_retention_days` policy (default 30 days, `0` = keep forever), never by the dashboard's own cleanup job, which does not touch target hosts.

Notes:

- Only certificate, chain, and key files are ever written. vhost configuration, `ssl_protocols`, and anything else are untouched.
- `become: true` with a dedicated privilege-escalation rule; the SSH key is mounted only in the worker.
- All tasks that touch key material use `no_log: true`; the `ansible-runner` event parser additionally drops `no_log` task output from `log_excerpt`.
- A host's rows in `job_host` are updated as one unit after that host's Ansible run finishes.

### 6.5 Rollout planning and batching

Triggered from the Deploy screen with: certificate, optional server filter (groups/hosts), batch percent, pause-after-canary, and an optional deploy window.

Planning (`services.deploy.plan`):

Before resolving targets, revalidate the certificate path at current UTC time (§5.8). Require `chain_status=trusted` or an explicit, reasoned, audited deploy.chain_override; repeat at execution if trust changed after preview.

1. Resolve target bindings: all active bindings whose `certificate_id` is the certificate being replaced (`renews_id` of the new certificate), or the explicit selection the operator made. Exclude bindings with `match_state` in `key_mismatch`, `missing_file`; include `unknown` only if the operator explicitly overrides, which is audited.
2. Group bindings by `server_id`; a server appears once.
3. Order: canary = the single server the operator picked (default: the first server of the smallest affected group, so the blast radius is minimal). Remaining servers are ordered round-robin across Ansible groups, then by hostname, which spreads a batch across failure domains.
4. Batch size = `max(1, ceil(total_servers * batch_percent / 100))`, with `batch_percent` default 10 (1-100). Batch 0 is the canary.
5. Write `job` (type `deploy`) and `job_host` rows with `batch_no`, all `pending`.

Execution:

- Canary batch (batch 0) runs first. When `pause_after_canary` is true (default) and the canary succeeded, the job moves to status `paused` and **releases its claim**: no worker thread is held, no advisory lock is kept, and the reaper does not treat it as running. `job.resume_from_batch` is set to 1. The UI shows "Canary succeeded — continue?" with **Continue** and **Cancel**.
  - **Continue** sets the job back to `queued` with `resume_from_batch = 1` (marked `scheduled_reason = manual`), and a worker claims it normally and resumes at batch 1. Continue is audited.
  - **Cancel** marks the remaining `job_host` rows `skipped` and the job `cancelled`, like any other cancel.
  - A paused job **auto-cancels after 24 hours** (`deploy.pause_timeout_hours`, configurable) by the scheduler sweep, writing a `deploy.pause_expired` audit row and marking the remaining hosts `skipped`. This prevents a forgotten approval from sitting forever and, critically, prevents a stale authorized deploy from resuming days later against servers whose state may have changed.
  - Resuming re-runs the preflight drift check per host (6.4 step 1), so a host that changed while the job was paused is aborted rather than overwritten.
- Subsequent batches run when the previous batch completed with zero failures. **The first failed host stops the rollout**: in-flight hosts in the current batch are allowed to finish (each self-rolls-back on its own failure), and all remaining `job_host` rows are marked `skipped` with reason `rollout_stopped`. The job status becomes `failed`.
- Within a batch, hosts run with a bounded concurrency of `deploy.concurrency` (default 5) via a thread pool; each host is one `ansible-runner` invocation with its own timeout (`Assumption`: 10 minutes per host, configurable).
- Per-host `advisory lock` from 3.6; a locked host is `skipped`, not failed, and does not stop the rollout.
- **Cancel**: an operator may cancel a running deploy. In-flight hosts finish or roll back; pending hosts are `skipped`. Cancel is audited.
- **Rollback is automatic per host only.** There is no job-level "roll back the previous batch" action in v1; the operator re-deploys the previous certificate through the same flow, which is itself canary-first and verified (`Assumption`: this is deliberate, to avoid untested automated mass rollback).
- Live progress: the Deploy screen polls `GET /jobs/{id}/progress` every 2 seconds via htmx and renders batch totals, per-host rows, and per-host log excerpts.

### 6.6 Deploy preview

Before enqueueing, the Deploy screen shows a preview computed from the database (last discovery):

- Per host: binding count, vhost names, absolute file paths, current certificate CN/fingerprint/expiry, new certificate CN/fingerprint/expiry, the actions to be taken (`write cert`, `write chain`, `write key`), and the on-disk owner/mode that will be preserved.
- Totals: hosts, bindings, files, groups, batch plan with sizes.
- Warnings: hosts where the current certificate is not the one being replaced, bindings with `drift` potential (last discovery older than 24 hours), shortened validity on the new certificate, and `key_mismatch`/`missing_file` bindings excluded from the plan.

The preview is advisory; the deploy itself re-checks drift on the host.

### 6.7 Timeouts and failures in Ansible runs

- Per host run timeout: 10 minutes; per task timeout where a command can hang (`nginx -t`, reload) 60 seconds.
- `ansible-runner` is used with a small, explicit environment: `ANSIBLE_HOST_KEY_CHECKING=True`, `ANSIBLE_STDOUT_CALLBACK=json` is not used (the runner's event stream is consumed directly), `ANSIBLE_NOCOLOR=True`, and `no_log` respected.
- An unreachable host is classified `transient_network` and retried **only for discovery and scans** (up to 3 attempts, 30/120/300 seconds backoff). Deploy hosts are never retried automatically: a partial deploy requires a human decision.
- SSH authentication failure is classified `auth`, never retried, and shown with a hint to check `known_hosts` and the deploy key.

---

## 7. Background jobs & alerts

### 7.1 Scheduler

A single scheduler loop runs inside the worker (`app/jobs/worker.py`), guarded by `pg_try_advisory_lock('scheduler')` so extra worker replicas do not double-schedule:

- Every 30 seconds: write heartbeat, enqueue due scheduled jobs, reap timed-out jobs, retry eligible failed jobs, and auto-cancel `paused` deploy jobs whose `paused_at` is older than `deploy.pause_timeout_hours` (default 24).
- Due checks compare `last_run_at` (from `app_setting`-adjacent `scheduler_state` rows, one per schedule key) against the configured daily time in UTC. A schedule that was missed while the worker was down runs once on startup if it is more than 30 minutes late and less than 12 hours late; older misses are skipped and logged.
- Schedules and defaults:

| Schedule | Time (UTC) | Job | Notes |
| --- | --- | --- | --- |
| Endpoint scan | 02:00 daily | `scan` (all active endpoints) | Also on demand per endpoint or globally |
| Discovery | 03:00 nightly | `discover` (whole inventory) | Inventory pull first; also on demand per group/host |
| Expiry check | 07:00 daily | `alert_expiry` | Sends notifications for crossed thresholds |
| Digest | 07:30 daily | `digest` | Mismatches, unknown certs, failed jobs, 7-day expiries |
| Cleanup | 04:00 daily | `cleanup` | Jobs > 90 days, scan results > 90 days, expired sessions, `/srv/artifacts` entries > 30 days (never the tmpfs key staging dir, which is wiped on every worker start) |

Times are configurable in Settings and stored in `app_setting`. `Assumption`: no per-certificate schedules in v1.

### 7.2 Job lifecycle

`queued → running → succeeded | failed | cancelled`, with `attempt` increments on each claim. Deploy jobs may additionally take `running → paused → queued` (canary approval, 6.5); a `paused` job holds no claim and no lock, so it is invisible to the reaper and to the claim query.

- Timeouts per type: discover 30 min, deploy 10 min/host (job timeout = sum of remaining hosts + 15 min), scan 30 min, alert 5 min, digest 5 min, cleanup 10 min. `timeout_at` is cleared when a job is paused and recomputed on resume, so a canary pause can never be mistaken for a hang.
- Retries by type: `discover` and `scan` — 3 attempts, backoff 30/120/300 s, only for `transient_network`; `alert_expiry` and `digest` — 3 attempts for SMTP `4xx`/timeout only; `deploy` — max 1 attempt, never retried automatically (a retry is a new job with a new audit entry); `cleanup` — 2 attempts.
- Non-retryable always: `auth`, `validation`, `config_invalid`, `key_unwrap`, `internal`.
- Every terminal state writes a `job.*` audit row and, for deploys, per-host results into `job_host`.
- On worker crash, the reaper marks the job `failed` with `error_class = timeout` after `timeout_at`, releases advisory locks (connection close releases them), and records which hosts were in `running` state as `failed` with `worker_lost` so the UI does not show phantom progress.

### 7.3 TLS endpoint scanning

For each active endpoint: open a TCP connection to `host:port` with a 10-second connect/read timeout, perform a TLS handshake with SNI = `sni or host`, accept any chain (no verification against trust stores — we inspect, we do not validate trust in v1), take the leaf DER, compute SHA-256.

Classification:

- Fingerprint equals `expected_certificate_id`'s fingerprint → `ok`.
- A certificate is served, `expected_certificate_id` is set, fingerprints differ → `mismatch`.
- Served certificate `not_after` < now → `expired` (takes precedence over `mismatch` in the UI ordering but both are stored as one status; the row keeps the observed fields so both facts are visible).
- TCP timeout/refused/DNS failure → `unreachable`.
- Handshake/protocol/parse failure → `error`.
- Also recorded: negotiated TLS version, observed CN/issuer/not_after/chain length, and the elapsed time.

Concurrency: 20 in-flight connections in a thread pool, per-endpoint ordering preserved. A scan job stores one `scan_result` per endpoint and updates `endpoint.last_scan_at`/`last_scan_status`.

Mismatches and unreachable endpoints are listed on the Scan screen; a *new* mismatch (transition from `ok` to `mismatch`, or first observation) is included in the daily digest immediately, and repeated mismatches appear in the digest as a count (`Assumption`: no immediate email per mismatch, to avoid alert storms during a planned maintenance window; the digest is the single daily channel and the UI is the live channel).

### 7.4 Expiry alerts

Daily at 07:00 UTC:

1. Select certificates with `status = 'active'` and `not_after` in the future or past within the 60-day window.
2. For each threshold in `alert.thresholds_days` (`60, 30, 14, 7, 1, 0`), if `not_after - now <= threshold days` and the notification was not already sent for that certificate+threshold+day, send one email.
3. One email per certificate per run even if several thresholds cross on the same day: the smallest crossed threshold wins, and the email lists the crossing reason ("expires in 7 days"). The other thresholds are marked as consumed for that day only, so they do not fire later.
4. Recipients: `certificate.owner_email` plus `alert.recipients` (team list), deduplicated, with the owner first. Empty owner falls back to the team list only.
5. Content: CN, SAN count, issuer, serial, `not_after` (with timezone), days remaining, the servers/vhosts currently using it (active bindings), the renewal state (so an already-issued-but-not-deployed certificate is obvious), and a link to the certificate and its renewal. Text and a minimal HTML alternative.
6. `notification_log` records the outcome; failures retry up to 3 times with backoff and are shown on the Settings screen.
7. `0` days means "expires today / has expired" and is sent once; an already-expired certificate is included in every digest until it is replaced or marked `superseded`/`revoked`.
8. Owned-by-nobody certificates (no owner email and empty team list) produce a Settings warning instead of silent loss.

`Assumption`: no per-user opt-out and no maintenance-window suppression in v1; a certificate can be snoozed by editing its owner email, which is audited.

### 7.5 Daily digest

One email at 07:30 UTC containing:

- Expiring within 7 days and already expired (count + table).
- New TLS mismatches since the last digest, plus the current mismatch count.
- Unknown certificates found by discovery since the last digest.
- Servers whose last discovery failed or is older than 48 hours.
- Jobs failed or rolled back in the last 24 hours.
- Inventory revision currently deployed and its age.

A digest is sent even when there is nothing to report: a daily heartbeat mail is how the team learns that the alerting path still works (`Assumption`).

### 7.6 SMTP

- Configured in Settings: host, port, `starttls`/`ssl`/`none`, from address, username; the password comes from the `smtp_password` secret (absent means no AUTH).
- TLS certificate verification is on by default; a `smtp.tls_verify` setting exists for internal relays with private CAs (`Assumption`, off by default and clearly marked unsafe).
- A "Send test email" button on the Settings screen sends a fixed message to the current user and reports the SMTP conversation result (with the password redacted).
- Messages use a dedicated `Message-ID` and `Date` header; the `From` is `smtp.from`; replies go to the team list.
- Send failures never fail the whole expiry job when at least one mail was delivered; per-certificate failures are recorded and retried.

### 7.7 Inventory refresh job

Part of every `discover` and `deploy` job's preflight rather than a separate user-visible job type: `git fetch` + `git reset --hard origin/<ref>`, capture `rev` and `rev_date`, fail the job if the pull fails and the local checkout is older than 24 hours. The nightly discovery also triggers a pull. Pull results appear in the job log and the Settings screen shows the current revision.

---

## 8. Screens

Server-rendered Jinja2 with htmx for partial updates. Every list has server-side pagination, sorting, and filters encoded in the query string, so a view can be bookmarked. Forms post normally and work with JavaScript disabled; htmx only adds in-place updates and progress polling. Navigation: Overview, Certificates, Servers, Deploy, Scans, Audit, Settings.

### 8.1 Login (`/login`, `/login/2fa`)

- Username + password, then the TOTP step when enabled. Generic error text (`invalid credentials`) that does not reveal whether the account exists; lockout and rate-limit messages are distinct but generic.
- "Forgot password" is not available (internal tool, no email-based reset); the screen says to contact another admin.
- First-run: if no active user exists, `/login` redirects to a bootstrap hint and the CLI command is required. The UI never creates the first admin.

### 8.2 Overview (`/`)

- Counters by expiry bucket: expired, < 7 days, < 30 days, < 60 days, total active; each counter links to the filtered certificate list.
- TLS health: endpoints ok / mismatch / unreachable; unknown certificates on servers; bindings whose key does not match.
- Recent jobs (last 10) with type, target summary, status, duration, actor, and a link; a failed/rolled-back job is visually distinct.
- Renewals in flight: state and age, so a stalled `submitted` renewal is visible.
- Worker/SMTP/inventory status strip: last heartbeat, last inventory pull revision and age, last digest time.
- Empty state: a short setup checklist (set SMTP, set inventory repo, run discovery, import a certificate).

### 8.3 Certificates list (`/certificates`)

Columns: CN, SAN count, issuer CN, `not_after` (with a colour-coded days-remaining chip), owner/team, status, source (renewed/imported), key present, bindings count.

Filters: search (CN/SAN/serial/fingerprint), status, expiry bucket, issuer, team, owner, has-key, has-bindings, renewal state. Bulk actions: none except "export list as JSON" (`Assumption`: no CSV, per scope).

### 8.4 Certificate detail (`/certificates/{id}`)

- Header: CN, SANs, issuer, serial, validity, fingerprint, status, lineage breadcrumb (previous/next certificate via `renews_id`), owner/team, notes.
- Key panel: key type/size, public key fingerprint, created date, "key present" badge, master key version (not the key).
- Downloads: leaf PEM, chain PEM, full chain PEM; PFX with re-auth and a user-chosen password. Every download is audited.
- Bindings panel: servers, vhosts, ports, file paths, on-disk fingerprints, match state; a mismatch is a red row with the reason.
- Endpoints panel: expected vs observed certificate, last scan status and time, "Scan now" button.
- History panel: renewal lineage timeline (each certificate and each state transition with actor and time) plus related audit entries.
- Actions: edit owner/team/notes, mark `superseded`/`revoked` (with a required reason), start renewal, deploy this certificate, import a chain.
- Validation panel always shows chain_status and the last path-assessment diagnostics. Incomplete/untrusted_root/unchecked display a warning naming the missing issuer, expired intermediate, or untrusted root, with a link to Settings → Trust anchors. These warnings do not block import/issued upload; deploy requires trusted or an audited override.

### 8.5 Renewal wizard (`/renewals/new?from={cert_id}`, `/renewals/{id}`)

Steps, one screen each, state persisted so the operator can leave and come back:

1. **Basics** — source certificate, CN and SANs prefilled and editable (read-only after CSR generation), key algorithm and size, CA name, notes.
2. **CSR** — generated on submit; shows the CSR PEM, its SHA-256, and copy/download buttons plus a checklist for the CA portal ("order a certificate, paste this CSR, complete validation, download the certificate and any intermediate"). The CSR hash is displayed on later steps too, so the operator can prove they submitted the right request.
3. **Submitted** — order reference (required), date; the state becomes `submitted` and the certificate detail shows "issued externally, awaiting upload".
4. **Upload issued certificate** — paste or upload the leaf and optional chain (PEM/CRT; PFX is not accepted here because the key must be the one the app generated). Validation runs immediately: parse, public-key match against `key_id`, CSR subject/SAN match, validity window, and trust-anchor path assessment. Trust warnings do not block issued upload; parse/key/CSR/leaf-validity errors do. Diagnostics are shown per check, so the operator knows to re-download from the CA or fetch a missing intermediate. Files passing the blocking checks are stored as a `certificate` row with `renews_id = previous_certificate_id` and their assessed chain_status, including non-trusted warnings.
5. **Ready to deploy** — a summary plus a "Deploy" button that opens the Deploy screen preloaded with this certificate and the bindings of the previous one.
6. **Done** — after a successful deploy: mark `done`; options to keep the previous certificate as `superseded` (default) or `revoked` if the CA revoked it.

Re-entry points: each step is a URL, and the wizard shows the current state, so a half-finished renewal is always resumable. Cancelling asks for a reason and is audited.

### 8.6 Servers / bindings map (`/servers`, `/servers/{id}`, `/bindings`)

- Servers list: hostname, groups, webserver, binding count, last discovery time/status, current mismatch count. Filter by group/hostname.
- Server detail: bindings table (vhost, port, config file, cert/chain/key paths with owner/mode, on-disk fingerprint, matched certificate, match state), discovery history (time, status, duration, inventory revision, error), and actions: run discovery for this host, view the last raw dump summary, open an endpoint scan.
- Bindings view (`/bindings`) is the cross-server table: filter by certificate, server, group, webserver, match state, vhost name. This is the "where is this certificate used" answer, and the filter result is exportable as JSON.
- A binding row with `key_mismatch` or `missing_file` has a persistent warning badge and a link to the fix instructions (the app does not fix them).

### 8.7 Deploy (`/deploy`, `/deploy/{job_id}`)

Start screen:

- Certificate picker (defaults to issued renewals), optional target filter (groups/hosts), batch percent, pause-after-canary toggle, and the computed preview (Section 6.6) including a per-host table of what will change. Enqueue requires a confirmation describing the host count and the canary host by name.
- Guardrails: cannot start if the certificate has no key, is expired, is `revoked`, is already deployed everywhere, or if a deploy job is currently `running` or `paused` (the UI says which one and offers to open it).

Job screen (live, polls `/jobs/{id}/progress` every 2 s):

- Header: certificate, actor, started, elapsed, rollout phase (`canary`, `batch 3/10`, `paused`, `stopped`, `done`), totals (succeeded/failed/rolled back/skipped/pending).
- Batch accordion with per-host rows: hostname, bindings, status, old → new fingerprint (abbreviated with the full value on hover), duration, rollback indicator, expandable redacted log excerpt, copyable backup path.
- Controls: **Continue** (only while `paused`, shows the time left before the 24 h auto-cancel), Cancel job, retry a single host as a **new** job (with a required reason; audited), download the full per-host report as JSON.
- A paused job is visually distinct and shows "waiting for approval since <time>"; while paused it holds no worker and the banner states that resuming re-checks drift on every host.
- Failure banner: the reason for stopping, the first failed host, and whether its files were restored.

### 8.8 Scan results (`/scans`)

- Current state per endpoint: host, port, SNI, expected certificate, observed CN/issuer/not_after, status, last checked.
- Filter by status, server, certificate, group; "Scan now" for one endpoint or a bulk "Scan all".
- History drawer per endpoint: last 20 results with the observed fingerprint, so a flapping endpoint is visible.
- Mismatch detail: which certificate is expected, which is served, and the likely actions (renew/deploy, or update the expectation if the vhost intentionally changed).

### 8.9 Audit log (`/audit`)

- Read-only, newest first, filters: actor, action prefix, target type/id, date range, IP.
- Row expansion shows `details` JSON (already secret-free), IP, and user agent.
- No edit, no delete, no export-to-CSV in v1 (`Assumption`: JSON export only, matching the list endpoints).

### 8.10 Users & settings (`/settings`, `/users`)

- Settings tabs: SMTP (with test send), Alerts (thresholds, recipients, digest on/off), Inventory (repo URL, ref, path, webserver var, "Test pull" button), Deployment (default batch percent, concurrency, pause-after-canary, pause timeout, backup retention days, per-host timeout), Scanning (timeout, daily time), Schedule (daily times), General (display timezone, retention), Trust anchors (include-public-bundle toggle, pinned certifi version, uploaded internal roots), Status (worker heartbeat, keyring version, DB size, queue depth, last runs).
- Dangerous actions are isolated in a "Maintenance" panel with a typed confirmation: rotate master key instructions (the actual rotation is a CLI command, with the UI showing the current state and required steps), prune old jobs.
- Users: list, create (local), edit email/display name, deactivate, reset password, reset 2FA, view last login. Deactivating the last active user is refused. The UI names the auth backend per user and disables password actions for non-local backends.
- Every settings change is audited with the before/after values (excluding secrets, which are not settable here).
- Trust anchors: upload a single PEM internal root (CA:TRUE and self-signed verification), view fingerprint/subject/source/notes, delete with confirmation; audit trust_anchor.add/remove and synchronously recheck stored chain statuses. Public roots are read-only in-memory bundle entries, never uploaded-anchor rows.

---

## 9. Error handling

### 9.1 Principles

1. **Fail closed for security.** Missing master key, unreadable key material, or a failed CSRF/session check stops the operation rather than degrading to plaintext.
2. **Fail safe for deployment.** Any doubt on the target (drift, failed config test, unverified fingerprint) results in restoring the backup and reloading, never in leaving a broken configuration.
3. **Fail loud for humans.** Every failure has a stable error class, a message an operator can act on, a place in the UI, and an audit entry. Nothing is swallowed.
4. **Never leak secrets.** Error messages, logs, job payloads, and audit details are scrubbed by the same redaction filter; Ansible output for key tasks is `no_log`.
5. **Partial work is recorded.** Every host and every renewal step is persisted as it happens, so a crash leaves an accurate, resumable state.

### 9.2 Start-up and configuration errors

| Condition | Behaviour |
| --- | --- |
| `master_key` missing/malformed/wrong length | Process exits non-zero with a message naming the secret and the expected JSON shape; compose restarts and the same message repeats (visible via `docker compose logs web`) |
| `db_password` missing | Same, naming the secret |
| DB unreachable at start | Retry for 60 s with backoff, then exit non-zero (compose restarts) |
| Migration not applied (schema version mismatch) | Refuse to start; print the exact `alembic upgrade head` command |
| `session_secret` missing | Refuse to start (`web` only) |
| `ansible_ssh_key` missing | `worker` starts but marks deploy/discovery unavailable; the UI shows a blocking banner instead of failing jobs one by one |
| SMTP not configured | Alerts are recorded as `failed` with reason `smtp_not_configured`; the Settings screen shows a persistent warning |
| Inventory repo not configured | Discovery cannot run; the button is disabled with the reason |
| Keyring contains a version not referenced by any row | Warning in logs and Status panel, not fatal |

### 9.3 Validation errors (user input)

- All forms validate server-side and re-render with inline messages and the previous input preserved. htmx forms receive a `422` fragment that replaces the form.
- Certificate uploads report *all* validation failures at once (parse error, key mismatch, CN/SAN mismatch, expired), not just the first. Chain trust/completeness failures are separate non-blocking warnings with persisted chain_status.
- Wrong file type (PFX uploaded where PEM is required), oversized files (limit 1 MB per uploaded object), and malformed base64 are explicit messages.
- Importing a certificate whose fingerprint already exists offers "view existing" instead of creating a duplicate.
- A name/path that would escape the artifacts or key-staging directory is rejected.
- Deleting users: deactivation only, with a check that at least one active user remains.

### 9.4 Job failures

- Every job failure sets `error_class` + `error_message`, writes a `job.failed` audit row, appears on the Overview and in the digest, and shows the raw (redacted) Ansible excerpt for host-level jobs.
- Classification drives retry: `transient_network` retried per 7.2; everything else requires a human.
- Poison messages: a payload that fails validation is failed immediately with `validation` and is not retried; the job row shows which payload key was invalid.
- Worker crash: reaper handles it (7.2); hosts left in `running` become `failed` with `worker_lost`, and the Deploy screen tells the operator which hosts need a manual check (files may have been changed but not verified). The recommended remediation is to run discovery for those hosts and decide whether to re-deploy.

### 9.5 Discovery failures

| Failure | Behaviour |
| --- | --- |
| Host unreachable / SSH error | `server.last_discovery_status = failed`, previous bindings kept and marked stale, retried per 7.2 and listed in the digest |
| `nginx -T` / `apachectl -S` fails | Same, with the command's stderr in the job log; nothing is changed |
| Config dump parses but yields zero bindings on a host that previously had some | Treated as suspicious: bindings are **not** deactivated; the job records a `parse_suspected` warning and the host is listed for review (prevents a parser regression from wiping the map) |
| Some files unreadable (permissions) | That binding gets `missing_file` with the error; the rest of the host is processed |
| Inventory pull fails | Job fails if checkout older than 24 h, otherwise proceeds with the last revision and warns |

### 9.6 Deploy failures

| Failure | Host outcome | Rollout |
| --- | --- | --- |
| Drift (on-disk fingerprint ≠ discovery) | `failed`, no changes made | Stops the rollout |
| Missing target file/directory, permissions denied | `failed`, no changes (preflight) | Stops |
| Disk space insufficient | `failed`, no changes (preflight) | Stops |
| Pre-existing config test failure | `failed`, no changes | Stops |
| Write error mid-way | rollback restores all files for the host | Stops if rollback succeeded; rollback failure is escalated |
| `nginx -t` / `configtest` fails after write | rollback, reload, verify old fingerprint | Stops |
| Reload fails | rollback, reload, verify old fingerprint | Stops |
| Served fingerprint ≠ new | rollback, reload, verify old fingerprint | Stops |
| Reload succeeded but verify is slow | up to 3 verify attempts (2 s apart) before rollback | Stops |
| Rollback fails | `rolled_back = false`, `rollback_error`, audit `deploy.rollback_failed`, host flagged **manual intervention required** | Stops; digest highlights it |
| Host locked by another job | `skipped` (not a failure) | Continues |
| Cancelled by operator | in-flight finish/roll back; pending `skipped` | Ended by operator |

Ansible-level errors that are not host-related (playbook syntax, missing collection, key file permissions) fail the job immediately with `internal` and a message pointing at the worker image, without marking hosts as failed.

### 9.7 Dependency failures

- **Database unavailable mid-request:** `web` returns a styled 503 page (HTML) or `{"error":"database_unavailable"}` (JSON) with `Retry-After`; the request is not partially committed (transactions per action). The connection pool retries once.
- **SMTP unavailable:** alerts are recorded `failed`, retried per 7.2; the Settings Status panel shows consecutive failures and the last error.
- **Inventory Git remote unavailable:** see 9.5; the checkout is never left in a dirty or half-reset state (fetch into a temp ref, then reset).
- **CA portal unavailable:** out of scope by design — the operator simply cannot obtain a certificate; the renewal stays `submitted` and shows its age on the Overview so it is noticed.

### 9.8 HTTP error surfaces

- HTML routes: styled `403`, `404`, `422`, `500`, `503` pages with a request id and a link back.
- JSON/htmx endpoints: `{"error": {"class": "...", "message": "...", "request_id": "..."}}`, never a stack trace, never a secret.
- Session expiry during an htmx request returns `401` with `HX-Redirect: /login`, so the browser navigates instead of injecting a login form into a fragment.
- Request id (`X-Request-ID`, generated if absent) is logged with the user id, route, status, and duration; it is shown in the error page so a user report can be correlated with logs.

### 9.9 Logging and observability

- Structured JSON logs to stdout: `ts`, `level`, `logger`, `request_id`/`job_id`, `user_id`, `event`, `duration_ms`, and a `details` object that passes the redaction filter.
- Levels: `INFO` for lifecycle events, `WARNING` for recoverable degradations, `ERROR` for failed operations with the exception class and a redacted traceback.
- No request bodies or form values are logged; certificate PEM is not logged (fingerprint only).
- Security-relevant events (failed logins, lockouts, key exports, rollbacks, master key rotation) are logged and audited.
- Metrics are not exposed as Prometheus in v1 (`Assumption`); the Status panel and the digest are the operational signal, with `docker compose logs` for detail.

---

## 10. Testing strategy

`pytest` for everything; `pytest-asyncio` for async endpoints; `httpx` + FastAPI `TestClient` for HTTP tests. CI runs lint (`ruff`), the test suite, and a Docker image build on every push to the private repo. No browser E2E in v1 (`Assumption`: server-rendered forms are exercised through the test client; htmx behaviour is verified at the endpoint level).

### 10.1 Unit tests

**Crypto (`app/crypto`)**

- RSA 2048/3072/4096 and ECDSA P-256/P-384 key generation: correct type, size, curve, and non-exportable-format errors.
- CSR: subject CN, all SAN types (DNS, IP, email), signature verifies against the generated key, SHA-256 of the CSR matches the stored value, SANs are preserved exactly.
- Key matching: matching key/certificate accepted; a different-but-same-algorithm key rejected; RSA 2048 vs 3072 mismatch rejected; ECDSA curve mismatch rejected.
- AES-256-GCM: encrypt/decrypt round trip; nonce uniqueness across N operations; tampered ciphertext, tampered nonce, wrong AAD, wrong key version all raise `KeyUnwrapError` (never return garbage); ciphertext of the same plaintext differs across calls.
- Master keyring: parse valid/invalid JSON shapes, reject 16-byte keys, reject a missing `active`, round-trip rotation of a batch of rows (data encrypted with v1 decrypts after v2 becomes active; `master_key_version` updated).
- Chain builder: reversed input and duplicate/root removal; unresolved intermediate order reports a diagnostic; a forged supplied issuer link is rejected. Trust: internal root uploaded → trusted; same supplied root absent from anchors → untrusted_root; missing/expired intermediate → incomplete; non-CA/invalid-self-signature anchor rejected. All fixtures are local; certifi access reads its pinned packaged file only.
- PFX build: `pkcs12.load_key_and_certificates` returns the key, leaf, and full chain; the PFX requires the chosen password; the key's public hash matches the certificate after extraction.
- Parsing: PEM/DER/PFX ingestion, fingerprint equals an independently computed SHA-256, SAN extraction with wildcards and IPs, expired certificate detection, self-signed handling, garbage input rejected with a typed error.

**Renewal state machine**

- Every legal transition succeeds and is audited exactly once.
- Every illegal transition (e.g. `draft -> issued`, `done -> submitted`, `cancelled -> csr_generated`) raises a typed `InvalidTransition` and leaves the row unchanged.
- Issued-upload validation: wrong key rejected, wrong CN rejected, wrong SAN set rejected, expired rejected, missing/untrusted/expired-intermediate chain accepted with warning and stored chain_status, duplicate fingerprint rejected. Leaf expiry still blocks issuance.
- `issued -> deployed` only after a succeeded deploy job that included the certificate.

**Rollout planning**

- Canary is exactly one host; the remaining batches are `ceil(total * percent / 100)` in size; the last batch may be smaller.
- Batch sizes for (total, percent) pairs: (1,10), (2,10), (9,10), (10,10), (11,10), (500,10), (100,100).
- Stop-at-first-failure: a failed host in batch N marks all rows in batches > N as `skipped` and stops; a `skipped` host due to a lock does not stop the rollout.
- Deterministic ordering: the same input plan yields the same batch assignment (seeded ordering); hosts spread across groups.
- A host with multiple affected bindings produces one `job_host` per binding but one execution unit.

**Alerts**

- Threshold crossing: a certificate expiring in exactly 29 days triggers the 30-day alert once, and re-running the check the same day sends nothing (dedupe key).
- Multiple thresholds crossed at once produce one email at the smallest threshold.
- Expired certificate is included until its status changes.
- Recipient resolution: owner + team, dedupe, owner-first, empty-owner fallback, fully empty list raises a settings warning.
- SMTP failure is recorded and retried up to 3 times, then left failed.

**Auth**

- argon2id: hash/verify round trip, rehash on parameter change, wrong password rejected, timing not obviously different for unknown users (behavioural test only, no timing assertion).
- Lockout after 10 failures, unlock after 15 minutes, successful login resets the counter.
- TOTP: RFC 6238 test vectors, ±1 step window, rejected reuse of the same step, recovery code single use.
- Sessions: cookie flags, rotation on login, revocation on logout/password change/2FA change, idle and absolute expiry, CSRF rejection without a token and acceptance with one.
- `AuthBackend` contract test run against the local backend and against a fake in-memory backend, proving the interface is implementable by an LDAP backend (no local-only assumptions in `web`).

**Discovery parsing**

- `parse_nginx` over captured `nginx -T` dumps: multiple vhosts, includes, relative paths, RSA+ECDSA dual certificates, `listen 443 ssl` vs `listen 443` plus `ssl`, no-cert vhosts (skipped), duplicate `ssl_certificate` legacy directives.
- `parse_apache` over captured `apachectl -S` + config dumps: multiple vhosts, a global directive, `SSLCertificateChainFile`, several `SSLCertificateFile` chain forms, wildcard `ServerName`, non-TLS vhost excluded.
- Reconciliation table from 6.3 exercised row by row, including the "zero bindings on a previously non-empty host" guard.
- Fixtures are real captured dumps with secrets/hostnames anonymized, stored under `tests/fixtures/`.

**Queue and jobs**

- Claim query under concurrency: N threads claiming M jobs never hand the same job to two workers (Postgres in a container).
- Backoff and `run_after` gating; reaper marks stale `running` jobs failed and releases hosts; attempt limits respected; deploy jobs never retried.
- Per-host advisory lock: a second job skips a locked host and continues.

### 10.2 Integration tests

`docker-compose.test.yml` brings up: Postgres, the app image, an nginx container, and an Apache container, both configured with a test vhost, a self-signed (test CA) certificate, and an SSH server accepting a throwaway key. A fixture generates a test CA, a leaf, a chain, and a key with `cryptography` and installs them into the targets.

Scenarios:

1. **Discover nginx**: run `discover.yml` against the nginx target; assert the binding row (vhost, port, config file, paths, owner, mode, fingerprint) matches the fixture, and the unknown-certificate path is taken when the certificate is not in the inventory.
2. **Discover Apache**: same for `SSLCertificateFile`/`KeyFile`/`ChainFile`.
3. **Import + match**: import the leaf into the inventory, re-run discovery, assert `matched` and `certificate_id` set.
4. **Deploy success**: renew (generate key + CSR, attach a test-CA-issued certificate), deploy to the nginx target; assert the file contents, owner/mode (`0600` on the key), the served fingerprint on `127.0.0.1:443`, the `job_host` status, and that the backup directory holds the previous files.
5. **Deploy rollback on config test failure**: point the new certificate at a deliberately invalid pair (or inject a broken `nginx.conf` include that only `nginx -t` catches); assert all three files are restored byte-for-byte with original metadata, the reload happened, the old fingerprint is served, and `rolled_back = true`.
6. **Deploy rollback on verify failure**: install a config where the reload silently serves the old certificate (e.g. a stale worker process); assert the verify step fails and triggers rollback.
7. **Drift protection**: change the certificate on the target between discovery and deploy; assert the host fails with `drift_detected` and no file is modified.
8. **Idempotent re-deploy**: run the same deploy twice; the second run makes no write and still verifies.
9. **Rollout stop**: 3 targets, batch percent 50; make the second batch fail; assert the third batch is `skipped` and the job is `failed`.
10. **Scan**: start a TLS listener with the test certificate; assert `ok`; replace with a different certificate; assert `mismatch` with the observed fingerprint; stop the listener; assert `unreachable`.
11. **Expiry alert**: set a fixture certificate to expire in 29 days, run the expiry job against a local SMTP capture (e.g. `aiosmtpd` in the test network); assert one message, correct recipients and content, and no second send on re-run.
12. **PFX export**: perform the re-auth and export through the HTTP client; assert the PKCS#12 loads with the chosen password and contains key, leaf, and chain; assert the audit row exists and contains no key material.
13. **Append-only audit**: attempt `UPDATE`/`DELETE` on `audit_log` as the app role; assert it is rejected.
14. **Master key rotation**: encrypt with v1, rotate the keyring to v2, run `rotate-master-key`, assert every row reports v2 and decrypts, then remove v1 from the keyring and assert decryption still works.

### 10.3 Test data and environments

- Fixtures generate a throwaway CA, a root, two intermediates, wildcard and IP-SAN leaves, RSA and ECDSA keys, an expired certificate, and a not-yet-valid certificate — all under `tests/fixtures/certificates/` (generated at session start, not committed).
- Database: a throwaway Postgres container per test session with migrations applied; each test runs in a transaction that is rolled back, except queue/concurrency tests, which use isolated schemas.
- No test reaches the internet; the SMTP target is a local capture server; the Git inventory is a local bare repository created by the fixture.
- CI: `ruff check`, `pytest -q` with coverage, `docker build`, and a `docker compose -f docker-compose.test.yml config` sanity check. Coverage gates: 85% on `app/crypto`, `app/services/renewals.py`, `app/services/deploy.py`, `app/ansible/parse_*`; 70% overall.

### 10.4 Manual acceptance checklist (before first production use)

- Bootstrap an admin, log in, enroll 2FA, log out, log back in with 2FA.
- Add SMTP settings, receive the test email, receive a real expiry alert for a certificate set 7 days out.
- Point at a copy of the real inventory, run discovery, confirm every binding of two real hosts matches reality (spot-check `grep ssl_certificate`).
- Import a real certificate and its key via PFX; export it again as PFX and diff the public material.
- Complete one real renewal end to end with the actual CA portal on one host.
- Deploy that renewal with canary + 100% to two hosts, confirm the served fingerprint and a clean digest.
- Force a rollback on a test host and confirm the operator-facing report is accurate.
- Restore the database and master key into a staging stack and decrypt one key (Section 11.6).

---

## 11. Deployment & operations

### 11.1 Prerequisites

- One internal Linux host (or VM) with Docker Engine and the Compose plugin, 4 vCPU / 8 GB RAM / 50 GB disk (`Assumption`: 8 GB covers Ansible forks, the DB, and artifact retention).
- An internal DNS name and a front proxy that terminates TLS for the dashboard.
- A Git repository containing the static Ansible inventory, readable by a deploy token.
- An SSH key pair trusted by the managed servers, ideally restricted to a dedicated user with sudo rights for file writes and service reloads only.
- Outbound SMTP relay reachability and outbound HTTPS to the inventory Git remote.

### 11.2 First installation

1. Clone the private repo onto the host (deploy key).
2. Provision secret files under `/etc/cert-dashboard/secrets/` (`db_password`, distinct `db_owner_password`, `master_key`, `session_secret`, and optional worker SSH/vault/Git/SMTP credentials). An administrator runs `sh scripts/install-secrets.sh /etc/cert-dashboard/secrets` as root: directory root:root 0711; app secrets 10001:10001 0400; owner password 999:999 0400; shared db_password 10001:999 0440. No runtime copies are created. Generate `master_key` with `docker run --rm cert-dashboard python -m app.cli generate-master-key --version 1` and **immediately** follow 11.6.
3. `docker compose up -d db`, then `docker compose -f docker-compose.yml -f docker-compose.migrate.yml run --rm migrate`.
4. `docker compose run --rm web python -m app.cli bootstrap-admin --username admin --email admin@example.internal` (prompts for the password with confirmation, enforces the 12-character minimum).
5. `docker compose up -d web worker`.
6. Log in, enroll 2FA, configure SMTP, alert recipients, and the inventory repo; press "Test pull" and "Send test email".
7. Run discovery for one group, review the binding map against reality, then run it for the whole inventory.
8. Register endpoints (automatic from bindings) and run one scan.
9. Enable the schedules (they are on by default once the worker runs; confirm the times in Settings).

### 11.3 Routine operations

| Task | Procedure |
| --- | --- |
| Upgrade | Pull the image tag, `docker compose -f docker-compose.yml -f docker-compose.migrate.yml run --rm migrate`, then `docker compose up -d web worker`. Migrations are forward-only; take a DB backup first |
| Roll back an app upgrade | Re-pin the previous image tag and restart. If the migration is not backward compatible, restore the DB backup taken before the upgrade (documented per release in the release notes) |
| Add a server | Add it to the inventory repo, wait for the nightly discovery or press "Discover now"; confirm the server appears and its bindings are matched |
| Remove a server | Remove it from the inventory; the next discovery marks it inactive (history preserved) |
| Add a certificate | Import (upload or pull from `host:port`) or start a renewal; then map its bindings via discovery or manual endpoint entry |
| Rotate the Ansible SSH key | Replace the secret file, `docker compose up -d worker`, then run a discovery to confirm connectivity |
| Rotate the SMTP password | Replace the secret file, restart `worker`, send a test email |
| Change alert thresholds | Settings → Alerts (audited); takes effect at the next expiry check |
| Pause alerting | Disable the digest and expiry schedules in Settings (audited) — intended for planned maintenance windows only |
| Inspect a failed deploy | Deploy screen → job → host row → log excerpt; backups remain at `/var/backups/cert-dashboard/<job_id>/` on the target (root-owned, `0700`, key backups `0600`) |
| Recover a target by hand | Use the backup directory on the host, restore with the original owner/mode, run the config test, reload. Then run discovery so the dashboard's view matches reality |
| Prune host backups early | Set `deploy.backup_retention_days` (default 30, `0` = keep forever); deploy.yml prunes after the next successful host run. Removing a directory by hand is safe once the deploy is confirmed |

### 11.4 Backup and restore of the database

- Nightly `pg_dump -Fc` from a `web` one-shot container to a backup volume, 30 daily copies, 12 weekly (`Assumption`: local retention only; copying off-host is the platform's backup job).
- Restore drill quarterly: `pg_restore` into a staging database, start a staging stack with the **same** `master_key`, open a certificate detail page, and export one PFX.
- A database backup **never** contains the master key, and must never be stored beside it (Section 11.6).

### 11.5 Master key rotation

The keyring supports two live versions so rotation needs no downtime window longer than a restart.

1. Generate version N+1 with the existing keyring as input: `python -m app.cli generate-master-key --version 2 --merge /etc/cert-dashboard/secrets/master_key`. It prints the new keyring JSON (old key retained) and its SHA-256; it does not modify the file.
2. Write the new keyring to the `master_key` secret file, keep a copy of the old file in the backup location (per 11.6), and `docker compose up -d web worker`. New encryptions now use version 2.
3. Run `docker compose run --rm web python -m app.cli rotate-master-key`. It re-encrypts every `private_key` and `user.totp_secret_*` row with a new nonce and the active version, in batches of 100, and prints the remaining count. It is idempotent and resumable.
4. Verify `SELECT count(*) FROM private_key WHERE master_key_version <> 2` returns 0 and the Status panel shows the active version.
5. Remove version 1 from the secret file, restart, and destroy the old key copy **only after** step 4 and a successful PFX export.
6. Rotation triggers: a custodian leaves, the key file may have been exposed, or annually (`Assumption`: annual rotation is the default policy).

### 11.6 Master key backup procedure (critical)

**Losing the master key means every private key in the database is permanently unrecoverable.** Certificates (public material) survive; the keys do not. That means re-keying and re-issuing every certificate through the CA.

Procedure:

1. **Generate** the keyring on the dashboard host with the CLI (11.2 step 2). Do not generate it on a laptop and email it.
2. **Fingerprint it.** Record the SHA-256 of the keyring file and the JSON's `active` version in the operations record (a ticket, not the same place as the key).
3. **Store three copies in two physically separate, access-controlled locations:**
   - Copy A: the Docker secret on the dashboard host (`/etc/cert-dashboard/secrets/master_key`, `0400`, owner `10001:10001`) — the working copy.
   - Copy B: the organization's secret manager (Vault/KeePass/1Password or a sealed envelope in a safe) held by custodian 1.
   - Copy C: a second sealed envelope or secret-manager entry in a different location, held by custodian 2.
   Custodians are named in the operations record; at least two people must be able to produce the key, and neither copy may be stored with the database backups.
4. **Never** commit the key, paste it into a chat, put it in the repo, or include it in a `docker-compose.yml`, image, or CI variable that other pipelines can read.
5. **Verify the backup works** every quarter, and after every rotation: on a staging host, restore the latest `pg_dump` into an empty database, place the *backup* copy of the keyring in a staging secret, start the stack, open a certificate detail page, and export one PFX. Record the date and the operator. A backup that has never been restored is not a backup.
6. **Update all copies together** on rotation: after 11.5 step 4, replace B and C with the new keyring (which still contains the previous version until step 5), re-record the fingerprint, and destroy the superseded copies only after the next restore drill passes.
7. **If the key is lost** (all copies unavailable):
   - Stop key-dependent actions. The UI disables PFX export and deploys that need the key, and shows a blocking banner.
   - Certificates and their public chains remain valid on the servers; nothing breaks immediately.
   - Recovery: generate new keys and CSRs (one renewal per certificate, the wizard supports this), re-issue through the CA, deploy, and treat the old keys as compromised. Plan this work around the earliest expiry date in the inventory, which the dashboard still knows.
   - Record the incident in the ticket system and add an audited note to each affected certificate (`certificate.update`), so the inventory explains why every key was replaced out of band.
8. **If a copy leaks** (without the database): rotate immediately per 11.5 — the old key becomes useless once every row is re-encrypted and the old version is removed. Rotate any credential that could have exposed the DB alongside it.

### 11.7 Security hardening checklist

- `web` published only to `127.0.0.1` (front proxy reaches it over the compose network or the loopback).
- Containers run as non-root `app` (uid 10001), `read_only: true` with `tmpfs` for `/tmp` on `web`; `worker` keeps writable volumes only for `/srv/inventory` and `/srv/artifacts`.
- Decrypted keys exist only on the worker's tmpfs mount `/run/cert-keys` (`mode=0700`, `uid=10001`, `noexec`, `nosuid`, `nodev`, `size=16m`), as `0600` files deleted in a `finally` block and wiped at worker startup. The artifacts volume and container filesystem never hold key material.
- `no-new-privileges: true`, dropped capabilities, explicit memory limits.
- Secrets under `/run/secrets` are read-only file bind mounts retaining host modes: app/worker 10001:10001 0400; db_owner_password 999:999 0400; shared db_password 10001:999 0440. Host directory root:root 0711. Run scripts/install-secrets.sh after provisioning/replacing files; Compose mode remapping is not used outside Swarm. The Debian Postgres image is digest-pinned and its postgres UID/GID 999 verified.
- SSH `known_hosts` pinned; host key changes fail jobs.
- Postgres not exposed; the app DB user is not a superuser and cannot `UPDATE`/`DELETE` on `audit_log`.
- All dashboard access over TLS via the front proxy; HTTP redirects to HTTPS there.
- Dependency updates: pinned versions, `pip-audit` in CI, monthly update pass.
- Log retention: container logs rotated by the Docker daemon (`max-size=50m`, `max-file=5`).

### 11.8 Operational signals

| Signal | Where | Action |
| --- | --- | --- |
| Worker stale (> 5 min) | UI banner, `/healthz` | Check `docker compose ps` and worker logs |
| Job queue depth growing | Status panel | Check for a stuck job, the reaper, and worker logs |
| Discovery failing for many hosts | Digest, job list | Check SSH key, inventory pull, network |
| Consecutive SMTP failures | Status panel, digest absence | Fix Settings/secret; send a test email |
| Deploy rollback | Overview, digest, audit | Inspect the host, the log excerpt, and the backup |
| Disk usage on the dashboard host | Host monitoring | The cleanup job prunes `/srv/artifacts` entries older than 30 days and DB rows older than 90 days; investigate if usage still grows |
| Disk usage on targets (`/var/backups/cert-dashboard`) | Target monitoring | deploy.yml prunes its own backups after `deploy.backup_retention_days` (default 30, `0` = keep forever), always keeping the newest per path; set `0` to disable pruning and review disk manually |

---

## 12. Future work

Ordered by expected value, none of it in v1:

1. **LDAP/AD authentication and roles.** Add `auth/ldap.py` implementing the existing `AuthBackend`, map groups to roles (`viewer`, `operator`, `admin`), and turn `require_admin` into a real permission check. The session and audit models already carry the identity needed.
2. **CA API integration.** Automate submission and download for DigiCert/Sectigo REST APIs and ADCS Web Enrollment, keeping the manual path as a fallback. This turns `submitted -> issued` into a job and adds certificate transparency-style order tracking.
3. **Immediate notification channels.** Teams/Slack webhooks and PagerDuty for expiry, mismatches, and failed rollouts, using the same `notification_log` dedupe model.
4. **More targets.** IIS (WinRM), F5 (iControl REST), HAProxy, Kubernetes `Ingress`/cert-manager secrets. Requires widening `binding` beyond nginx/Apache and a per-target deploy driver interface.
5. **OCSP/CRL checks and CT log monitoring** for revoked-but-served certificates.
6. **Network discovery** in addition to inventory-driven discovery (TLS sweep of a CIDR, then reconciliation into unknown-certificate triage).
7. **Automatic chain completion** by fetching missing intermediates from the certificate's AIA extension, replacing the manual "fetch the intermediate" step.
8. **CSV import/export** for the people who will ask for it, with a dry-run diff.
9. **Job-level rollback** ("undo batch 3") once per-host rollback has a track record, plus scheduled deploy windows and approval gates for large rollouts.
10. **Key custody improvements.** Store the master key in a KMS/HSM (encrypt/decrypt via KMS with the ciphertext in the DB) so the key never exists as a file; optionally issue keys directly in the HSM.
11. **HA and scale.** Multiple web replicas behind the proxy, multiple workers, and moving long Ansible runs to a dedicated runner pool if the host count grows beyond ~500.
12. **Richer reporting.** Certificate inventory export, per-team dashboards, SLA-style metrics (median time from issued to deployed, renewal lead time), and an audit export for compliance.
13. **Config awareness beyond TLS.** Detect vhost-level TLS settings (`ssl_protocols`, `ssl_ciphers`, HSTS) and report weak configurations, without editing them.
14. **Password/identity hardening.** WebAuthn as a second factor, SCIM-style user provisioning once LDAP lands.

---

## Appendix A — Consolidated assumptions

These are the decisions this spec makes where the approved input was silent. Each is intended to be reviewed, and each is cheap to change now and expensive later.

| # | Assumption | Section |
| --- | --- | --- |
| A1 | PostgreSQL 16; any 14+ is acceptable | 3.1 |
| A2 | One worker container, concurrency 4; extra replicas supported | 3.2 |
| A3 | All timestamps stored in UTC; UI renders local; emails state the timezone | 4 |
| A4 | Renewal states add `cancelled`; scan status adds `expired` | 4.2 |
| A5 | `submitted` requires a CA order reference | 4.6 |
| A6 | Chains exclude roots; offline PolicyBuilder/Store path validation uses pinned certifi plus uploaded roots, persists trusted/incomplete/untrusted_root/unchecked; import/issued upload warn, deploy requires trusted or audited override | 4.4, 4.18, 5.8 |
| A7 | Endpoints created from bindings always get an expected certificate | 4.10 |
| A8 | A host with several affected vhosts gets one `job_host` row per binding, executed as one Ansible run | 4.11 |
| A9 | Session idle 8 h, absolute 24 h | 4.13 |
| A10 | Plaintext keys exist only as `0600` files on the worker's tmpfs `/run/cert-keys` (never a volume), deleted after use and wiped at worker startup; Ansible receives paths only | 3.3, 5.2 |
| A11 | No PEM private-key export in v1; PFX only, with re-auth and a user-chosen password | 5.3 |
| A12 | Recovery codes for TOTP; no forced password rotation; 12-character minimum | 5.4 |
| A13 | Login rate limiting is Postgres-backed | 5.4 |
| A14 | HTTPS terminates at an internal front proxy; compose binds `web` to `127.0.0.1` | 5.7 |
| A15 | The inventory Git token is read-only; the dashboard never pushes | 6.1 |
| A16 | `openssl` and `python3` exist on all managed targets | 6.2 |
| A17 | On-target TLS verification is authoritative; worker-side verification is informational | 6.4 |
| A18 | Host backups (which contain old keys) live in a root-owned `0700` dir, key backups `0600`, and deploy.yml prunes them after `deploy.backup_retention_days` (default 30, `0` = keep forever), always keeping the newest per path | 6.4, 11.3 |
| A19 | Deploy pauses after the canary by default; the paused job releases its claim and is resumed by an explicit Continue (or auto-cancelled after `deploy.pause_timeout_hours`, default 24 h) | 6.5, 7.2 |
| A20 | Per-host deploy timeout 10 min; deploy concurrency 5 | 6.5 |
| A21 | No job-level rollback; re-deploy the previous certificate instead | 6.5 |
| A22 | Mismatch emails are aggregated into the daily digest, not sent immediately | 7.3 |
| A23 | Digests are sent even when there is nothing to report | 7.5 |
| A24 | No per-user alert opt-out and no maintenance-window suppression in v1 | 7.4 |
| A25 | No Prometheus metrics in v1; Status panel + digest + logs are the signals | 9.9 |
| A26 | No browser E2E tests in v1 | 10 |
| A27 | 4 vCPU / 8 GB / 50 GB dashboard host; local-only backup retention | 11.1, 11.4 |
| A28 | Annual master key rotation by default | 11.5 |
| A29 | JSON export for lists and audit; no CSV | 8.3, 8.9 |
| A30 | SMTP TLS verification is on by default, with an explicitly unsafe opt-out | 7.6 |

## Appendix B — Glossary

- **Binding** — one vhost's use of a certificate, chain, and key at specific paths on a server.
- **Canary** — the first rollout batch, a single server.
- **Chain** — the ordered intermediate certificates between the leaf and a trusted root.
- **Drift** — the on-disk state of a target differs from what the last discovery recorded.
- **Endpoint** — a `host:port` the dashboard connects to over TLS to observe the served certificate.
- **Keyring** — the versioned set of master keys in the `master_key` secret.
- **Leaf** — the end-entity certificate served to clients.
- **Match state** — how a binding's on-disk certificate relates to the inventory (`matched`, `unknown`, `key_mismatch`, `missing_file`).
- **Public key hash** — SHA-256 of a DER `SubjectPublicKeyInfo`; the identity used to prove a key matches a certificate.
- **Renewal** — the guided manual-CA process from `draft` to `done`.
- **Rollback** — restoring a host's previous certificate files after a failed deploy, then reloading and verifying.
