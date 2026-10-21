# Cert Dashboard — Plan 1: Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an authenticated certificate inventory, encrypted key vault, imports, manual-CA renewal wizard, and audited downloads, with the complete database and extension contracts for scanning and deployment.

**Architecture:** FastAPI renders Jinja2 forms with optional htmx enhancements; transactional services own validation, state changes, and audit writes. PostgreSQL stores application data and a SKIP LOCKED queue consumed by a separate worker; web never invokes Ansible or makes TLS inspection connections. Plans 2–3 register additional handlers and screens against the schema and interfaces defined here.

**Tech Stack:** Python 3.12 (implementation decision; the spec does not pin Python), FastAPI, Jinja2, htmx, SQLAlchemy 2.0, Alembic, psycopg 3, PostgreSQL 16, cryptography, certifi (pinned offline public roots), argon2-cffi, PyOTP, pyOpenSSL (served-chain retrieval), pytest, pytest-asyncio, httpx, Testcontainers, Ruff, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-19-cert-dashboard-design.md` — read alongside this plan; its column tables and validation rules remain normative.

## Global Constraints

- `PostgreSQL 16`; `PostgreSQL, SQLAlchemy 2.0 models, Alembic migrations.` No Redis/Celery.
- Python `3.12`; pin resolved dependency versions (including certifi) in `uv.lock` and the Python base image by digest during scaffold implementation. The Python version and added libraries above are decisions, not quotations from the spec.
- `web`: `uvicorn app.main:app`; `worker`: `python -m app.jobs.worker`; `db`: `postgres:16`; one multi-stage Dockerfile and one application image.
- `Docker secret file > environment variable > code default.` Read secret files once at startup; missing/empty/malformed required secrets stop startup.
- `AES-256-GCM, 12-byte random nonce per encryption operation, 16-byte authentication tag appended to the ciphertext`; decoded master keys are `32-byte`; active plus previous key version only, parser hard cap `max 16 versions parsed`, no duplicate keys.
- AAD is exactly `private_key:<id>:<master_key_version>` or `user:<id>:totp:<master_key_version>`; failures raise `KeyUnwrapError`, with no fallback version.
- `RSA 2048/3072/4096` with `public_exponent=65537`; `ECDSA P-256` / `P-384`; default `RSA 2048`; CSR subject CN only, SANs preserved, `SHA-256` signature.
- Trust: `cryptography.x509.verification.PolicyBuilder` + `Store`, explicit UTC validation time; `trust.include_public_bundle=true`, pinned certifi loaded in memory only, plus uploaded internal CA roots; persisted `chain_status` = `trusted|incomplete|untrusted_root|unchecked`. Import/issued upload warn; Plan 3 deploy requires trusted or an audited reasoned override.
- Matching identity: `SHA-256 of the DER SubjectPublicKeyInfo`; certificate fingerprint: SHA-256 of leaf DER, lowercase hex; roots excluded from stored chains.
- Passwords: `argon2id`, `time_cost=3`, `memory_cost=64 MiB`, `parallelism=4`, `16-byte salt`, minimum `12 characters`, top-1000 denylist, rehash on login.
- TOTP: `RFC 6238, SHA-1, 6 digits, 30-second step, ±1 step window`; single use; `10` recovery codes stored as argon2 hashes.
- Lockout: `10 consecutive failures` / `15 minutes`; rate limit: `5 attempts per minute per source IP`, PostgreSQL-backed.
- Sessions: idle `8 hours`, absolute `24 hours`; `cd_session`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, host-only; per-session `csrf_token` field / `X-CSRF-Token` header; every non-GET requires CSRF.
- Every active authenticated user is an admin; `require_user` and `require_admin` have the same v1 check. No RBAC, CA integration, ACME, CSV, PEM private-key export, or browser E2E.
- Upload limit: `1 MB per uploaded object`; use 1,048,576 bytes as the explicit implementation boundary, including streamed uploads before parsing.
- PFX: `BestAvailableEncryption(pfx_password)`, friendly name = CN, user-chosen password minimum `12 characters`, user password re-entry, audit `key.export`; leaf/chain/full-chain downloads also audited.
- Non-root `app` (`uid 10001`), `read_only: true`; web bind `127.0.0.1`; no public DB/worker ports; read-only file secrets `/run/secrets` preserving host owners/modes: app/worker `10001:10001 0400`, shared db_password `10001:999 0440`, db_owner_password `999:999 0400`; host directory `root:root 0711`. No ignored Compose mode remapping and no runtime copies; scripts/install-secrets.sh applies ownership.
- Worker-only volumes `/srv/inventory`, `/srv/artifacts`; tmpfs `/run/cert-keys`: `size=16m`, `mode=0700`, `uid=10001`, `gid=10001`, `noexec`, `nosuid`, `nodev`; staged keys `0600`, deleted in `finally`, wiped at startup. No key material in artifacts.
- `no-new-privileges: true`, dropped capabilities, explicit memory limits; container log rotation `max-size=50m`, `max-file=5`; pinned SSH `known_hosts`.
- `WORKER_CONCURRENCY=4`, `MAX_PARALLEL_JOBS` default `2`; heartbeat every `30 seconds`, stale after `5 minutes`; claim latency target `< 2 s`.
- Queue priority: deploy `300`, on-demand discovery/scan `200`, scheduled `100`, digest `50`, cleanup `10`; deploy max attempts `1`, never auto-retry.
- UTC persistence (`timestamptz`); browser-local display with configured timezone fallback; append-only audit retained independently of job cleanup.
- Tests use a real throwaway `postgres:16` **Testcontainers** container per pytest session, migrations applied with a separate owner role; app-role transactions roll back per test, queue/concurrency tests use isolated schemas/connections. Never substitute SQLite.
- Fixtures generate root, two intermediates, RSA/ECDSA, wildcard/IP/email/URI SAN, expired and future certificates in memory through `tests/fixtures/certificates.py` at session scope; generated keys/certificates are not committed. Tests never reach the Internet.
- CI: `ruff check`, `pytest -q` with coverage, `pip-audit`, `docker build`, `docker compose -f docker-compose.test.yml config`; `85%` coverage for crypto/renewals (and deploy/parsers when added), `70%` overall.
- Force LF with `.gitattributes` for `*.py *.yml *.yaml *.sh *.j2 *.cfg Dockerfile`; Linux containers must receive LF even from this Windows checkout.

- DNS canonicalization uses locked `idna` with non-transitional UTS #46/STD3; CSR CN is included once in the typed SAN set (1..100 identities), with DNS labels <=63 ASCII bytes and names <=253.

## Review Focus

- Missing/malformed keyring stops startup; a removed version or changed key cannot silently decrypt existing rows (Tasks 1, 4).
- Reversed chains/duplicate roots normalize; missing or expired intermediates and untrusted roots show typed, non-blocking trust diagnostics; uploading a non-CA anchor is rejected (Tasks 6, 6A).
- Wrong PFX passwords and unsupported legacy RC2 encryption produce actionable typed errors without weakening export encryption (Task 7).
- An issued certificate with a different key, subject, SAN set, or validity window leaves the renewal and inventory unchanged (Task 18).
- Garbage, mislabeled, malformed-base64, and oversized uploads show inline failures with no partial certificate/key insert (Tasks 6, 15).

## Contract decisions and test conventions

The detailed `user_session.id char(64)` definition overrides section 4's UUID summary. `renewal.key_id` is nullable only in `draft`/a cancelled draft, with a CHECK requiring it for all other states; key generation occurs on `draft → csr_generated`. To satisfy non-null encrypted columns and row-bound AAD without a half-row insert, reserve a key ID with the table sequence, encrypt, then insert the complete row in the same transaction. Sequence gaps on rollback are harmless.

Runtime DB access is app_role, which owns no tables/schema and cannot assume the migration role. Add a separate db_owner_password secret for db bootstrap and one-shot migrations only; this resolves the spec's implied owner/runtime split without giving web an alternate superuser login. docker-compose.migrate.yml defines a dedicated migrate service with DB-only settings and DB_USER=db_owner; its only secret is db_owner_password mapped to /run/secrets/db_password. It shares the application image and has no ports, a read-only filesystem, all capabilities dropped, and no-new-privileges enabled.

The parser rejects more than 16 key versions before decoding key material; the operational keyring then rejects more than two live versions. A present valid keyring with a missing referenced version starts with a blocking key-dependent-action warning; a missing/malformed secret prevents startup (§9.2 takes precedence over lost-key UI recovery advice). Missing worker SSH credentials allow startup with discovery/deploy unavailable (§9.2 overrides the secret table's blanket requirement).

Initial migrations also include implied support tables `worker_heartbeat`, `scheduler_state`, and `login_rate_limit`, plus `notification_log.attempts/next_attempt_at/last_attempt_at`, `binding.notes`, `scan_result.elapsed_ms`, `user_session.authenticated_at`, and settings absent from §4.14 but required elsewhere (Task 2). The same migration adds trust_anchor, chain_status/trust_anchor_source enums, certificate.chain_status and trust.include_public_bundle=true; there is no follow-up trust migration. This is the entire v1 schema: Plans 2–3 need no tables or columns. Use the spec's table-specific timestamp exceptions; audit/scan rows have `created_at`; mutable notification rows also have trigger-maintained `updated_at` because failed sends are retried in place. notification_log.sent_at is nullable with no default and is set only on success; last_attempt_at records every attempt. Binding identity is UNIQUE NULLS NOT DISTINCT (server_id, webserver, config_file, port, vhost_name, cert_path); job_host identity is UNIQUE NULLS NOT DISTINCT (job_id, server_id, binding_id), including NULL binding IDs.

Test snippets omit standard imports only: import symbols from each task's Interfaces and SQLAlchemy/pytest/cryptography normally. A task that uses a new fixture adds it to the stated `conftest.py`: `db: Session` (app role), `engine: Engine` (app role), `owner_engine: Engine`, `now: datetime` (aware UTC fixed clock), `actor: Actor`, and generated material under `tests/fixtures/certificates/`. `client: TestClient` uses HTTPS base URL; `signed_in: TestClient` also supplies a valid session/CSRF token; clock-dependent services accept `now` explicitly. Tests use real assertions below plus the named matrix, rather than tests that mock the implementation itself.

### Task 1: Runtime configuration and hardened container scaffold

**Files:** Create: `pyproject.toml`, `uv.lock`, `.github/workflows/ci.yml`, `.gitignore`, `.dockerignore`, `.gitattributes`, `Dockerfile`, `docker-compose.yml`, `docker-compose.credentials.yml`, `docker-compose.migrate.yml`, `docker-compose.test.yml`, `app/migrations/init_roles.sh`, `scripts/install-secrets.sh`, `docs/development.md`, `app/static/htmx.min.js`, `app/static/htmx.LICENSE`, `app/__init__.py`, `app/config.py`, `app/crypto/__init__.py`, `app/crypto/keyring.py`. Test: `tests/conftest.py`, `tests/unit/test_config.py`, `tests/unit/test_topology.py`.

**Interfaces:** Consumes: environment `Mapping[str, str]` and secret root `Path`. Produces: `DatabaseSettings` (DB fields only), `load_database_settings(environ: Mapping[str,str], secrets_dir: Path) -> DatabaseSettings` for one-shot migrations; `Settings(DatabaseSettings)` adds the app secrets/profile; `Keyring(active: int, keys: Mapping[int, bytes])`, `load_keyring(raw: bytes) -> Keyring`; `Settings` (DB connection fields, secret bytes, process profile, paths, worker limits); `load_settings(profile: Literal['web','worker','cli'], environ: Mapping[str,str], secrets_dir: Path) -> Settings`; typed `ConfigurationError` with secret name/remediation, never value.

- [x] Write failing tests using generated secret-file fixtures and parsed compose YAML:

```python
def test_secret_precedence_and_profile(secret_files):
    settings = load_settings('web', {'DB_PASSWORD': 'env-value'}, secret_files)
    assert settings.db_password == b'file-value'
    assert settings.worker_concurrency == 4
    (secret_files / 'master_key').unlink()
    with pytest.raises(ConfigurationError, match='master_key'):
        load_settings('web', {}, secret_files)

def test_keyring_rejects_duplicate_versions():
    with pytest.raises(ConfigurationError, match='duplicate'):
        load_keyring(b'{"active":1,"keys":{"1":"x","1":"y"}}')
```

  Also assert empty/16-byte/invalid-base64 keys, missing/non-integer/non-positive active, non-canonical or duplicate normalized version numbers, >16 parsed versions and >2 live versions fail; web needs session_secret of 32+ bytes but no SSH key; missing SSH makes worker capabilities false. Topology tests assert exact mount flags, UID, permissions, secrets per service across base/credentials override, no web SSH/inventory/artifact mounts, no ignored mode keys, and all required LF patterns. Exercise actual Compose secret merging and isolated-container ownership/readability, and verify pg_dump is version 16. The pinned postgres image must report UID/GID 999.
- [x] Run `uv run --no-project --with pytest --with pyyaml pytest tests/unit/test_config.py tests/unit/test_topology.py -q`; expect FAIL because configuration/scaffold is absent. This bootstraps only the test runner; then declare all production/test dependencies and lock them in this task.
- [x] Implement the signatures above in `app/config.py` and `app/crypto/keyring.py`. Use duplicate-preserving JSON parsing; fingerprint metadata only. Container runtime includes Ansible/ansible-runner, git, OpenSSH, OpenSSL, PostgreSQL client for later operations, and locally served htmx/static assets; no compiler toolchain. Pin Python image digest and dependency resolution; web `/tmp` tmpfs, worker `/tmp` tmpfs plus specified key tmpfs, memory limits web 1 GiB/worker 2 GiB/db 2 GiB (implementation allocations). Compose secret source paths point to `/etc/cert-dashboard/secrets/`, not repository values; base compose mounts required web/worker master_key/db_password and web session_secret only. DB also mounts db_owner_password for POSTGRES_PASSWORD_FILE and db_password for init_roles.sh; that init script is committed with Git mode 100755, copied with mode 0755, and bind-mounted read-only so the Postgres entrypoint executes it. It creates app_role using safely quoted psql parameters, with no superuser/role-creation/schema-creation privileges and no secret output. docker-compose.migrate.yml defines a separate one-shot migrate service with only db_owner_password mapped to db_password; normal web/worker never receive it, and migrate never receives master_key/session_secret. Test bootstrap verifies distinct passwords, non-superuser runtime, and no role escalation. Pin the Debian Postgres 16 image by digest, verify postgres UID/GID 999, and copy its matching pg_dump/pg_restore/psql into the application image. The dedicated migrate service runs as 999 with DB-only configuration, a read-only filesystem, no ports, all capabilities dropped, and no-new-privileges enabled; its command is alembic upgrade head. scripts/install-secrets.sh sets canonical host owners/modes without copies; document it in docs/development.md. `docker-compose.credentials.yml` adds worker-only SSH/vault/Git/SMTP file-secret mounts and pinned known_hosts; operators include only credential entries they actually provision. Base worker starts with unavailable SSH capability until that override is enabled. Test compose starts DB and app test image; Plans 2–3 add capture/target services. CI on the private repo runs the Global Constraints checks on Linux with Docker for Testcontainers; coverage gates apply only to modules already implemented. Generate coverage JSON and enforce thresholds with coverage CLI (85% crypto package and renewals module, 70% overall); verify the actual workflow commands against the built artifacts rather than grepping workflow text. No CI secret values or network-dependent application tests.
- [x] Run `uv run pytest tests/unit/test_config.py tests/unit/test_topology.py -q`; expect PASS. Run `docker compose -f docker-compose.test.yml config --quiet`; expect exit 0. Include actual rendered compose inspection in topology tests, with temporary test secrets.
- [x] Commit: `git add pyproject.toml uv.lock .github/workflows/ci.yml .gitignore .dockerignore .gitattributes Dockerfile docker-compose.yml docker-compose.credentials.yml docker-compose.migrate.yml docker-compose.test.yml app/migrations/init_roles.sh scripts/install-secrets.sh docs/development.md app/static/htmx.min.js app/static/htmx.LICENSE app/__init__.py app/config.py app/crypto tests/conftest.py tests/unit/test_config.py tests/unit/test_topology.py`; `git commit -m "build: scaffold hardened runtime and secret loading"`.

### Task 2: Complete v1 schema and real-Postgres migration fixture

**Files:** Create: `app/db.py`, `alembic.ini`, `app/migrations/env.py`, `app/migrations/script.py.mako`, `app/migrations/versions/0001_v1_schema.py`, `app/models/__init__.py`, `app/models/base.py`, `app/models/enums.py`, `app/models/certificate.py`, `app/models/private_key.py`, `app/models/renewal.py`, `app/models/server.py`, `app/models/binding.py`, `app/models/endpoint.py`, `app/models/scan_result.py`, `app/models/job.py`, `app/models/job_host.py`, `app/models/user.py`, `app/models/user_session.py`, `app/models/app_setting.py`, `app/models/notification_log.py`, `app/models/audit_log.py`, `app/models/worker_heartbeat.py`, `app/models/scheduler_state.py`, `app/models/login_rate_limit.py`, `app/models/trust_anchor.py`. Modify: `docker-compose.test.yml`, `Dockerfile`, `.github/workflows/ci.yml`, `uv.lock`, `docs/development.md`, `docs/superpowers/specs/2026-10-19-cert-dashboard-design.md`, `docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`. Test: `tests/integration/conftest.py`, `tests/integration/test_schema.py`, `tests/conftest.py`.

**Interfaces:** Consumes: `load_settings(profile: Literal['web','worker','cli'], environ: Mapping[str,str], secrets_dir: Path) -> Settings` for application startup; `load_database_settings(environ: Mapping[str,str], secrets_dir: Path) -> DatabaseSettings` for the dedicated migrate service and Alembic `env.py` (no application secrets). Produces: ORM classes named for singular tables in PascalCase, `Base.metadata`, all §4.2 Python/PG enums; recursive `JSONValue` alias; `create_session_factory(settings: DatabaseSettings) -> sessionmaker[Session]`; `transaction(factory: sessionmaker[Session]) -> ContextManager[Session]`; `assert_database_ready(engine: Engine, timeout_seconds: int = 60) -> None`.

- [x] Write failing migration/constraint tests against a fresh Testcontainers DB:

```python
def test_entire_v1_schema(engine):
    names = set(inspect(engine).get_table_names()) - {'alembic_version'}
    assert names == {'certificate','private_key','renewal','server','binding',
        'endpoint','scan_result','job','job_host','user','user_session',
        'app_setting','notification_log','audit_log','worker_heartbeat',
        'scheduler_state','login_rate_limit','trust_anchor'}
    assert str(inspect(engine).get_columns('user_session')[0]['type']) == 'CHAR(64)'
    with engine.connect() as conn:
        assert conn.scalar(text("SELECT value FROM app_setting WHERE key='alert.thresholds_days'")) == [60,30,14,7,1,0]
        assert conn.scalar(text("SELECT value FROM app_setting WHERE key='trust.include_public_bundle'")) is True
```

  Add table-driven catalog assertions for **every** column/type/nullability/default/FK/index/CHECK in §4.3–4.16, including fingerprint and issuer+serial uniqueness, GIN SAN index, coalesced endpoint identity, private-key nonce/version checks, directive-level binding uniqueness, NULLS NOT DISTINCT job_host uniqueness (including NULL binding IDs), and enum values. Assert invalid inserts fail, draft renewal accepts NULL key, issued renewal rejects it, `updated_at` changes, app_role is non-superuser, failed notifications keep sent_at NULL and set last_attempt_at, app_role cannot disable owner-owned audit triggers (42501), and every catalog table with updated_at has its enabled BEFORE UPDATE row trigger. Check pg_tables.tableowner is db_owner for audit_log and `alembic check` finds no model drift.
- [x] Run `uv run pytest tests/integration/test_schema.py -q`; expect FAIL because migrations/models are absent.
- [x] Implement §4 completely in the listed files and seed defaults, with `citext` installed by migration owner and app_role granted only runtime access. Add support schemas: `worker_heartbeat(worker_id text PK, started_at, last_seen_at timestamptz, current_job_id uuid NULL FK job ON DELETE SET NULL)`; `scheduler_state(key text PK, last_run_at timestamptz NULL)`; `login_rate_limit(ip inet, window_start timestamptz, attempts int, PK(ip,window_start))`, all with required timestamps. Add notification `attempts int NOT NULL DEFAULT 0`, `next_attempt_at timestamptz NULL`, `last_attempt_at timestamptz NULL`; sent_at is NULLABLE with no default, set only on successful sends, while last_attempt_at is set for each attempt. Use UNIQUE NULLS NOT DISTINCT on binding (server_id, webserver, config_file, port, vhost_name, cert_path) and job_host (job_id, server_id, binding_id); binding `notes text NULL`; scan_result `elapsed_ms int NULL`; user_session `authenticated_at timestamptz NULL` (NULL is MFA-pending, never an admin session). Add trust_anchor exactly per spec §4.18 (unique fingerprint, source enum public_bundle/uploaded, immutable created_at); uploaded rows only, never copy certifi roots. Add certificate.chain_status enum trusted/incomplete/untrusted_root/unchecked NOT NULL DEFAULT unchecked and trust.include_public_bundle=true. Add a partial claim index over priority DESC/run_after/created_at for queued jobs. Seed all §4.14 values, plus `smtp.tls_verify=true`, `inventory.webserver_var='webserver_type'`, `deploy.host_timeout_seconds=600`, `cleanup.daily_at='04:00'`, `expiry_check.enabled=true`, and per-schedule `*.enabled=true` (digest uses `alert.digest_enabled`). Settings for absent SMTP/inventory values are empty/null, not invented credentials. Revoke audit UPDATE/DELETE/TRUNCATE and add BEFORE UPDATE OR DELETE row and BEFORE TRUNCATE statement triggers raising audit_log is append-only (SQLSTATE P0001), including for the owner. No no-op rules: they can bypass privilege checks during query rewriting. Test app-role permission denial and loud owner mutation errors while INSERT works. Runtime startup checks connectivity with a 60-second backoff limit and exact Alembic head; never migrates automatically. Copy alembic.ini into the runtime image and exercise the real Compose migrate service plus alembic check against an isolated throwaway DB without application secrets. All documented migration commands explicitly use --profile migrate.
- [x] Run `uv run pytest tests/integration/test_schema.py -q`; expect PASS, then `uv run alembic check` against migrated test DB; expect no upgrade operations.
- [x] Commit: `git add app/db.py alembic.ini app/migrations app/models tests/conftest.py tests/integration/conftest.py tests/integration/test_schema.py docker-compose.test.yml Dockerfile .github/workflows/ci.yml uv.lock docs/development.md docs/superpowers/specs/2026-10-19-cert-dashboard-design.md docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`; `git commit -m "feat: define complete v1 database and migration contracts"`.

### Task 3: Transactional append-only audit and shared redaction

**Files:** Create: `app/services/__init__.py`, `app/services/audit.py`. Modify: `tests/integration/conftest.py`. Test: `tests/unit/test_redaction.py`, `tests/integration/test_audit.py`.

**Interfaces:** Consumes: `transaction(factory: sessionmaker[Session]) -> ContextManager[Session]`, `AuditLog`, `JSONValue`. Produces: `Actor(user_id: int | None, label: str, ip: str | None = None, user_agent: str | None = None)`; `record(db: Session, actor: Actor, action: str, target_type: str, target_id: str | None, details: Mapping[str, JSONValue]) -> AuditLog`; `redact(value: JSONValue) -> JSONValue`; `SecretRedactionFilter(logging.Filter)`.

- [x] Write failing atomicity and app-role permission tests:

```python
def test_audit_is_append_only(db, actor):
    row = record(db, actor, 'certificate.update', 'certificate', '42', {'notes':'renew'})
    db.flush()
    for sql in ('UPDATE audit_log SET action=\'bad\'', 'DELETE FROM audit_log', 'TRUNCATE audit_log'):
        with pytest.raises(DBAPIError):
            with db.begin_nested():
                db.execute(text(sql))
    assert db.get(AuditLog, row.id).action == 'certificate.update'
```

  Test mutation+audit rollback together, system/actor snapshots, nested password/token/PEM redaction, private-key block and long-base64 log filtering, preserving safe SHA-256 fingerprints; no certificate PEM or form bodies logged.
- [x] Run `uv run pytest tests/unit/test_redaction.py tests/integration/test_audit.py -q`; expect FAIL, missing writer/filter.
- [x] Implement `record` without committing its caller's transaction; audit actions/details are explicit allowlisted fields at each call site, with shared redaction as a second barrier. Never persist passwords, keyring values, TOTP seeds, recovery codes, key material, or export passwords; redact exception messages/tracebacks through the same filter.
- [x] Run `uv run pytest tests/unit/test_redaction.py tests/integration/test_audit.py -q`; expect PASS.
- [x] Commit: `git add app/services tests/unit/test_redaction.py tests/integration/test_audit.py tests/integration/conftest.py docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`; `git commit -m "feat: add transactional append-only audit and secret redaction"`.

### Task 4: Row-bound encryption, key custody, and rotation CLI

**Files:** Modify: `app/crypto/keyring.py`, `app/models/private_key.py`, `app/migrations/versions/0001_v1_schema.py`, `docs/development.md`, `docs/superpowers/specs/2026-10-19-cert-dashboard-design.md`, `docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`. Create: `app/crypto/keys.py`, `app/services/certificates.py`, `app/cli.py`. Test: `tests/unit/test_keyring.py`, `tests/integration/test_key_custody.py`, `tests/integration/test_schema.py`, `tests/integration/test_bootstrap_keyring.py`.

**Interfaces:** Consumes: `load_keyring(raw: bytes) -> Keyring`, `record(db: Session, actor: Actor, action: str, target_type: str, target_id: str | None, details: Mapping[str,JSONValue]) -> AuditLog`, ORM `PrivateKey`/`User`. Produces: `WrappedSecret(ciphertext: bytes, nonce: bytes, version: int)`; `wrap(keyring: Keyring, plaintext: bytes, aad: str) -> WrappedSecret`; `unwrap(keyring: Keyring, wrapped: WrappedSecret, aad: str) -> bytes`; `KeyUnwrapError`; `PrivateKeyObject = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey`; `public_key_sha256(key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey) -> str`; `store_key(db: Session, keyring: Keyring, key: PrivateKeyObject, origin: str, actor: Actor) -> PrivateKey`; `unwrap_key(row: PrivateKey, keyring: Keyring) -> PrivateKeyObject`; `private_key_pem(key: PrivateKeyObject) -> bytes`, `load_private_key(pem: bytes) -> PrivateKeyObject`; `missing_master_key_versions(db: Session, keyring: Keyring) -> set[int]` for metadata-only action gating; `stale_master_key_rows(db: Session, keyring: Keyring) -> int`; `rotate_master_key(db: Session, keyring: Keyring, actor: Actor, batch_size: int = 100) -> int` (remaining stale rows).

- [x] Write failing crypto and persisted-rotation tests:

```python
def test_row_binding_and_tamper(keyring):
    a = wrap(keyring, b'private', 'private_key:7:1')
    b = wrap(keyring, b'private', 'private_key:7:1')
    assert len(a.nonce) == 12 and len(a.ciphertext) == len(b'private') + 16
    assert a.nonce != b.nonce and a.ciphertext != b.ciphertext
    with pytest.raises(KeyUnwrapError):
        unwrap(keyring, a, 'private_key:8:1')
    missing_version = Keyring(active=2, keys={2: os.urandom(32)})
    with pytest.raises(KeyUnwrapError):
        unwrap(missing_version, a, 'private_key:7:1')
```

  Parametrize ciphertext/nonce/AAD/version/wrong-key/missing-version changes, always `KeyUnwrapError`. Persist v1 key+TOTP rows, rotate under v2 in batches of 100, assert both version columns become 2, a second run returns 0, and decrypt with a v2-only keyring. Assert failed rotation is resumable, no plaintext SQL/log/audit, and missing referenced versions are reported without fallback.
- [x] Run `uv run pytest tests/unit/test_keyring.py tests/integration/test_key_custody.py -q`; expect FAIL, wrap/store/rotation absent.
- [x] Implement AESGCM and typed errors in `keyring.py`, unencrypted PKCS#8 serialization and SPKI hashing in `keys.py`, and sequence-reserved/transactional key insertion in `services/certificates.py`; dedupe by public hash with race-safe complete-row insert. `cli.py` exposes `generate-master-key --version N [--merge PATH] [--output PATH]`, `rotate-master-key`, `verify-key --certificate-id ID`. Generation runs without DB/configured secrets, uses `os.urandom(32)`, accepts versions 1..2147483647 and rejects reused/decreasing versions. With --output it exclusively creates a new 0400 file via os.open(O_WRONLY|O_CREAT|O_EXCL), fchmods to exact 0400 despite umask, writes canonical UTF-8 JSON plus LF, fsyncs the file and parent directory, removes only its own partial inode on I/O failure, and prints only SHA-256 plus path; refuse a realpath alias of --merge or any existing output, including hardlinks, and report symlink-resolution failures cleanly. Test the bootstrap docker run command against the runtime image using a UID-10001-owned 0700 host directory, also with --read-only; verify mode/owner/digest and clean up generated copies. Legacy stdout JSON warns on stderr to use --output and never redirect onto --merge. Document hash verification and install -m 0400 -o 10001 -g 10001 before forced recreation. `rotate_master_key` processes at most batch_size locked stale key/TOTP rows in the caller transaction and returns remaining count; the CLI commits each batch and loops, auditing counts only. A fresh final transaction rechecks missing versions/stale key and TOTP counts, failing with metadata only if a late writer leaves any. Test two concurrent rotators (120 keys, batches 25) plus a legacy writer and final pass, reservation rollback without a half row, late-writer rejection, exclusive output/mode/alias protection, and version bounds. Enforce private_key.origin CHECK IN generated/imported_pfx/imported_pem in the unreleased v1 migration and ORM. Version monotonicity is checked against the merged keyring (historical reuse after all evidence is removed cannot be proven). Verify-key emits metadata/success only. Row reads reconstruct canonical AAD from the current row ID/version; a stored AAD cannot authorize a relocated ciphertext. One row-scoped helper releases plaintext references before the next row; failure rolls back the current batch. Report missing versions without blocking public inventory reads. Document §11.5 with forced container recreation for replaced secrets, both key/TOTP zero-count checks, metadata-only verification, and the successful PFX-export gate before retiring the old key. No decrypted private-key or TOTP plaintext is written to disk.
- [x] Run `uv run pytest tests/unit/test_keyring.py tests/integration/test_key_custody.py -q`; expect PASS.
- [x] Commit: `git add app/crypto/keyring.py app/models/private_key.py app/migrations/versions/0001_v1_schema.py app/crypto/keys.py app/services/certificates.py app/cli.py tests/unit/test_keyring.py tests/integration/test_key_custody.py tests/integration/test_schema.py tests/integration/test_bootstrap_keyring.py docs/development.md docs/superpowers/specs/2026-10-19-cert-dashboard-design.md docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`; `git commit -m "feat: encrypt row-bound keys and support master key rotation"`.

### Task 5: Key generation, SPKI matching, and CSR construction

**Files:** Modify: `app/crypto/keys.py`, `pyproject.toml`, `uv.lock`, `docs/superpowers/specs/2026-10-19-cert-dashboard-design.md`, `docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`. Create: `app/crypto/csr.py`. Test: `tests/fixtures/__init__.py`, `tests/fixtures/certificates.py`, `tests/unit/test_keys_csr.py`, `tests/conftest.py`.

**Interfaces:** Consumes: `PrivateKeyObject`, `public_key_sha256(key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey) -> str`. Produces: `KeySpec(kind: Literal['rsa','ecdsa'] = 'rsa', size: int | None = None, curve: str | None = None)`; `generate_key(spec: KeySpec) -> PrivateKeyObject`; `CSRMaterial(pem: str, sha256: str)`; `parse_san(value: str) -> x509.GeneralName`; `canonical_sans(values: Sequence[str]) -> tuple[str,...]`; `build_csr(key: PrivateKeyObject, common_name: str, sans: Sequence[str]) -> CSRMaterial`; `validate_csr(csr_pem: str, common_name: str, sans: Sequence[str], public_hash: str) -> list[str]`.

`KeySpec.size=None` means the default: RSA 2048, or the curve's size for ECDSA; an explicit ECDSA size must equal the curve size.

- [ ] Write failing tests (generated fixtures include named leaf, root, two intermediates and their keys):

```python
@pytest.mark.parametrize('size', [2048,3072,4096])
def test_rsa_csr(size):
    key = generate_key(KeySpec(size=size))
    material = build_csr(key, '*.example.internal', ['*.example.internal','192.0.2.1'])
    csr = x509.load_pem_x509_csr(material.pem.encode())
    assert key.key_size == size and key.public_key().public_numbers().e == 65537
    assert csr.is_signature_valid and csr.signature_hash_algorithm.name == 'sha256'
    assert material.sha256 == hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest()
```

  Add P-256/P-384 curve tests, DNS/IP/email/URI SAN preservation (DNS lowercase and IDNA A-labels; compare typed sets; include CN once), CN-only subject, invalid size/curve, independent SPKI digest comparison, same-algorithm wrong-key and curve/size mismatch assertions. CSR fingerprint means SHA-256 of DER, explicitly resolving the spec's unspecified encoding.
- [ ] Run `uv run pytest tests/unit/test_keys_csr.py -q`; expect FAIL, generation/CSR absent.
- [ ] Implement the signatures in `keys.py`/`csr.py` using cryptography. Accept typed SAN prefixes `DNS:`, `IP:`, `email:`, `URI:`; infer unprefixed DNS/IP, normalize only DNS; append canonical CN to SANs if absent, deduplicating typed identities. Reject empty supplied SAN lists and more than 100 entries, and enforce the final 100-identity limit after CN inclusion. DNS uses the locked idna dependency with non-transitional UTS #46 and STD3 rules (preserve ß as its A-label, never silently map it to ss); reject empty labels, underscores, leading/trailing hyphens, trailing root dots, labels over 63 ASCII bytes, and names over 253 ASCII bytes. A wildcard must be the complete left-most label. CN must be DNS/IP and fit the X.509 64-byte limit; longer valid names remain usable as SANs. IPv4/IPv6 use IPAddress, including CN insertion; reject DNS-encoded IPs during validation, scoped addresses and malformed dotted quads. Email/absolute ASCII URI payloads retain case and type. KeySpec size defaults to None (RSA means 2048); ECDSA derives its size from the curve (default P-256), accepts its matching explicit bit size, and rejects any explicit mismatch. Accept secp256r1/prime256v1/P-256 and secp384r1/P-384 aliases. Validate CSR signature, SHA-256 digest algorithm, CN-only subject, typed SAN set and SPKI identity, returning all fixed diagnostics without echoing input. Generated fixtures stay in memory at session scope. Canonical storage uses unprefixed lowercase DNS/canonical IP and explicit email:/URI: prefixes; comparisons use the same typed canonical set throughout.
- [ ] Run `uv run pytest tests/unit/test_keys_csr.py -q`; expect PASS.
- [ ] Commit: `git add app/crypto/keys.py app/crypto/csr.py tests/fixtures tests/conftest.py tests/unit/test_keys_csr.py pyproject.toml uv.lock docs/superpowers/specs/2026-10-19-cert-dashboard-design.md docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`; `git commit -m "feat: generate supported keys and verifiable CSRs"`.

### Task 6: Certificate parsing and chain normalization

**Files:** Create: `app/crypto/parse.py`, `app/crypto/chain.py`. Test: `tests/unit/test_parse_chain.py`.

**Interfaces:** Consumes: `canonical_sans(values: Sequence[str]) -> tuple[str,...]` and generated cert fixtures. Produces: `ParsedCertificate` (all public §4.3 identity/validity fields, `public_key_sha256: str`, `cert: x509.Certificate`); `parse_certificates(data: bytes) -> list[ParsedCertificate]`; `ParseError`; `ChainResult(pem: str, fingerprints: tuple[str,...], dropped: tuple[str,...], missing_issuer: str | None, diagnostic_roots: tuple[x509.Certificate,...], alternates: tuple[str,...], truncated: bool)`; `order_chain(leaf: x509.Certificate, candidates: Sequence[x509.Certificate]) -> ChainResult`; `fullchain_pem(leaf_pem: str, chain_pem: str) -> str`; typed `ChainError`.

`parse_certificates` rejects truncated or stray PEM blocks, non-whitespace data after the last certificate block, and more than 32 certificates per input (BEGIN markers counted before decoding); leading human-readable text before the first block is allowed. `order_chain` prefers a complete path ending at a supplied root (bounded depth-first search, max depth 16 plus a node budget), falls back to the longest path with the lowest fingerprint sequence, reports `truncated=True` with a `depth-limit`/`budget` note and `missing_issuer=None` when a cap (not absence) ends the search, and returns unchosen same-subject cross-sign fingerprints in `alternates` (note `cross-sign`).

- [ ] Write failing Review Focus tests:

```python
def test_reverse_chain_and_root_removal(certs):
    result = order_chain(certs.leaf, [certs.root, certs.intermediate1,
        certs.intermediate2, certs.root])
    assert result.fingerprints == (certs.intermediate2_fp, certs.intermediate1_fp)
    assert 'root' in result.dropped and 'duplicate' in result.dropped
    missing = order_chain(certs.leaf, [certs.intermediate1])
    assert missing.missing_issuer == certs.intermediate2.subject.rfc4514_string()
    assert result.diagnostic_roots == (certs.root,)

@pytest.mark.parametrize('raw', [b'hello', b'-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----', b'-----BEGIN PRIVATE KEY-----\nAA=='])
def test_garbage_is_typed(raw):
    with pytest.raises(ParseError):
        parse_certificates(raw)
```

  Add DER/PEM independent SHA-256, CN-less SAN fallback, serial normalization, wildcard/IP/email/URI extraction, future/expired times, unrelated issuer, forged signature, non-certificate blocks in chain, ambiguous cross-sign paths, and self-signed leaf tests. A non-root top intermediate may omit its root; verify root signature when supplied before dropping it, never imply trust validation.
- [ ] Run `uv run pytest tests/unit/test_parse_chain.py -q`; expect FAIL, parser/builder absent.
- [ ] Implement in `parse.py` and `chain.py`. Order known issuer-DN/signature links, reject malformed blocks or a forged claimed issuer link, dedupe fingerprints and exclude self-signed roots from stored/output chains with audit notes. Missing links and disconnected components produce missing_issuer diagnostics and deterministic issuer-topological/fingerprint order, not a blocking completeness exception; retain supplied roots in diagnostic_roots in memory only for Task 6A. Do not infer that an absent issuer is a root. Trust/completeness is decided by PolicyBuilder/Store in Task 6A, replacing the prior structural-only assumption. No AIA fetching or revocation checks.
- [ ] Run `uv run pytest tests/unit/test_parse_chain.py -q`; expect PASS.
- [ ] Commit: `git add app/crypto/parse.py app/crypto/chain.py tests/unit/test_parse_chain.py`; `git commit -m "feat: parse certificates and normalize verified chains"`.

### Task 6A: Offline trust-anchor assessment and root-management service

**Files:** Create: `app/crypto/trust.py`, `app/services/trust_anchors.py`. Modify: `tests/fixtures/certificates.py`. Test: `tests/unit/test_trust.py`, `tests/integration/test_trust_anchors.py`.

**Interfaces:** Consumes: Task 2 `TrustAnchor`, `ChainStatus`, `AppSetting`, `Certificate`; `ChainResult` including in-memory diagnostic_roots; Task 3 audit. Produces: `AnchorValidationError(ValueError)`; `ChainAssessment(status: ChainStatus, messages: tuple[str,...], validation_time: datetime)`; `assess_chain(leaf: x509.Certificate, intermediates: Sequence[x509.Certificate], anchors: Sequence[x509.Certificate], validation_time: datetime, diagnostic_roots: Sequence[x509.Certificate] = ()) -> ChainAssessment` in crypto/trust.py; `load_anchors(db: Session) -> tuple[x509.Certificate,...]`; `add_anchor(db: Session, pem: bytes, notes: str | None, actor: Actor, validation_time: datetime) -> TrustAnchor`; `remove_anchor(db: Session, anchor_id: int, actor: Actor, validation_time: datetime) -> None`; `recheck_chain_statuses(db: Session, validation_time: datetime, diagnostic_roots: Sequence[x509.Certificate] = ()) -> dict[str,int]` in services/trust_anchors.py. Service is this task; upload/delete/toggle UI is Task 23.

- [ ] Write failing offline tests using a complete internal chain with serverAuth/CA constraints compatible with the verifier:

```python
def test_internal_anchor_and_missing_paths(certs, now):
    trusted = assess_chain(certs.leaf, certs.intermediates, [certs.root], now)
    assert trusted.status == ChainStatus.trusted
    absent = assess_chain(certs.leaf, certs.intermediates, [], now, [certs.root])
    assert absent.status == ChainStatus.untrusted_root
    missing = assess_chain(certs.leaf, [certs.intermediate1], [certs.root], now)
    assert missing.status == ChainStatus.incomplete

def test_expired_intermediate_and_non_ca_anchor(db, certs, actor, now):
    expired = assess_chain(certs.expired_intermediate_leaf,
        certs.expired_intermediate_chain, [certs.root], now)
    assert expired.status == ChainStatus.incomplete
    assert 'expired_intermediate' in expired.messages
    with pytest.raises(AnchorValidationError, match='CA:TRUE'):
        add_anchor(db, certs.leaf_pem, None, actor, now)
```

  Add valid uploaded root→existing certificate status trusted, removal→untrusted_root using removed root as diagnostic, public-bundle toggle recomputation, duplicates, oversized/non-PEM/multiple/non-self-signed/forged CA rejection, default unchecked, no-path incomplete, validation-time boundary, and audit/transaction rollback assertions. With public bundle off, certifi roots cannot confer trust; enabling it only reads pinned packaged bytes. Assert the bundle is never inserted into trust_anchor and tests never make network calls. `AnchorValidationError` is a typed value error from services/trust_anchors.py; fixture generation remains local.
- [ ] Run `uv run pytest tests/unit/test_trust.py tests/integration/test_trust_anchors.py -q`; expect FAIL, trust APIs absent.
- [ ] Implement the exact signatures above. Use `cryptography.x509.verification.PolicyBuilder().time(validation_time).store(Store(anchors))` and a server verifier, choosing DNS/IP SAN identity (expand a wildcard with a fixed representative label); absent TLS identity is a non-trusted policy diagnostic. An empty enabled anchor set is handled without constructing an invalid empty Store. Map verified paths to trusted; a valid connected path to a supplied/known self-signed non-anchor to untrusted_root; missing issuer, expired intermediate, or policy failure to incomplete. Use stable diagnostic codes plus issuer/root names; never promote a root from the upload automatically. Read certifi.where() locally only when enabled, pin certifi in Task 1's uv.lock, and merge enabled anchors in memory. Validate uploaded CA:TRUE/root self-signature and CA signing usage, fingerprint-dedupe, audit trust_anchor.add/remove, then recheck all ≤500 cached statuses synchronously in the same caller transaction; pass the removed root as diagnostic only. Changed statuses emit certificate.chain_check with validation_time. No new migration/job type here and no network fetching.
- [ ] Run `uv run pytest tests/unit/test_trust.py tests/integration/test_trust_anchors.py -q`; expect PASS.
- [ ] Commit: `git add app/crypto/trust.py app/services/trust_anchors.py tests/fixtures/certificates.py tests/unit/test_trust.py tests/integration/test_trust_anchors.py`; `git commit -m "feat: assess certificate paths against configured trust anchors"`.

### Task 7: PFX import and password-protected construction

**Files:** Create: `app/crypto/pfx.py`. Test: `tests/unit/test_pfx.py`.

**Interfaces:** Consumes: `PrivateKeyObject`, `order_chain(leaf: x509.Certificate, candidates: Sequence[x509.Certificate]) -> ChainResult`. Produces: `PFXMaterial(key: PrivateKeyObject | None, leaf: x509.Certificate, chain: tuple[x509.Certificate,...])`; `read_pfx(data: bytes, password: str | None) -> PFXMaterial`; `build_pfx(key: PrivateKeyObject, leaf: x509.Certificate, chain: Sequence[x509.Certificate], password: str, friendly_name: str) -> bytes`; `PFXError(code: str, message: str)`.

- [ ] Write failing tests:

```python
def test_password_and_contents(certs):
    data = build_pfx(certs.key, certs.leaf, certs.intermediates, 'chosen-pass-123', 'www.example.internal')
    loaded = read_pfx(data, 'chosen-pass-123')
    assert loaded.leaf == certs.leaf and len(loaded.chain) == 2
    assert public_key_sha256(loaded.key.public_key()) == public_key_sha256(certs.key.public_key())
    with pytest.raises(PFXError, match='password'):
        read_pfx(data, 'wrong-password')
```

  Add <12-character export password, mismatched key, no leaf, public-only PFX, malformed data, and an unsupported-algorithm loader exception fixture asserting `code == 'unsupported_encryption'` and an offline modern-PFX re-export hint. Generate/check an RC2 fixture only where the pinned backend supports it: successful import must normalize normally; unsupported RC2 must produce that typed hint. Do not silently enable system legacy providers or weaken new exports.
- [ ] Run `uv run pytest tests/unit/test_pfx.py -q`; expect FAIL, PFX API absent.
- [ ] Implement with cryptography `pkcs12.load_key_and_certificates` and `serialize_key_and_certificates`, `BestAvailableEncryption`, friendly name UTF-8 CN, normalized intermediate-only chain, and in-memory bytes. For keyless bundles choose the unique end-entity certificate from returned certificates; reject zero or multiple candidate leaves with a typed error. Separate wrong-password/corrupt-bundle errors from `UnsupportedAlgorithm` without echoing passwords or promising diagnosis a backend cannot distinguish.
- [ ] Run `uv run pytest tests/unit/test_pfx.py -q`; expect PASS.
- [ ] Commit: `git add app/crypto/pfx.py tests/unit/test_pfx.py`; `git commit -m "feat: import and build password-protected PFX bundles"`.

### Task 8: Pluggable password authentication and account lockout

**Files:** Create: `app/auth/__init__.py`, `app/auth/base.py`, `app/auth/local.py`, `app/auth/ldap.py`, `app/static/common-passwords.txt`. Test: `tests/integration/test_auth_backend.py`.

**Interfaces:** Consumes: `create_session_factory(settings: DatabaseSettings) -> sessionmaker[Session]`, `Actor`, Task 3 `record` contract. Produces: exact §5.4 `AuthBackend` protocol (`name: str`, `authenticate(self, username: str, password: str) -> AuthResult`, `lookup(self, username: str) -> UserRecord | None`, `supports_password_change(self) -> bool`); `Success(user_key: str, display_name: str, email: str)`, `Failure(reason: Literal['invalid_credentials','locked','inactive','backend_unavailable','not_supported'])`, `AuthResult = Success | Failure`; `UserRecord(user_key: str, username: str, display_name: str, email: str, backend: str, is_active: bool)`; `LocalAuthBackend(factory: sessionmaker[Session], clock: Callable[[], datetime])`; `hash_password(password: str) -> str`; `verify_password(encoded: str, password: str) -> bool`.

- [ ] Write failing tests; use the same contract suite against local and a fake backend:

```python
def test_lockout_and_hash_parameters(local_backend, local_user, clock):
    ph = PasswordHasher.from_parameters(extract_parameters(local_user.password_hash))
    assert (ph.time_cost, ph.memory_cost, ph.parallelism, ph.salt_len) == (3,65536,4,16)
    for _ in range(10):
        assert isinstance(local_backend.authenticate('admin', 'wrong'), Failure)
    assert local_backend.authenticate('admin', 'correct-long-pass').reason == 'locked'
    clock.advance(minutes=15)
    assert isinstance(local_backend.authenticate('ADMIN', 'correct-long-pass'), Success)
```

  Assert unknown/inactive/wrong-password behavior uses generic UI text, successful auth resets failures, outdated hashes rehash, concurrent failures do not lose increments, <12/top-1000 passwords are refused, and failure/lockout events persist even when login fails.
- [ ] Run `uv run pytest tests/integration/test_auth_backend.py -q`; expect FAIL, backend absent.
- [ ] Implement local transaction-per-auth with locked user row, dummy argon2 verification for unknown accounts, and audit result. `user_key` is stringified local user ID; web resolves identities through `lookup`, never through password-hash fields. Vendor a reviewed top-1000 password list with provenance/license; no runtime download. `ldap.py` implements the protocol returning `Failure('not_supported')`, not local fallback. Inactive/locked accounts fail before any session grant; future backend outage is `backend_unavailable`.
- [ ] Run `uv run pytest tests/integration/test_auth_backend.py -q`; expect PASS.
- [ ] Commit: `git add app/auth app/static/common-passwords.txt tests/integration/test_auth_backend.py`; `git commit -m "feat: add pluggable argon2 authentication and lockout"`.

### Task 9: Encrypted TOTP enrollment and single-use recovery

**Files:** Modify: `app/auth/local.py`. Test: `tests/integration/test_totp.py`.

**Interfaces:** Consumes: `wrap(keyring: Keyring, plaintext: bytes, aad: str) -> WrappedSecret`, `unwrap(keyring: Keyring, wrapped: WrappedSecret, aad: str) -> bytes`, `Actor`, ORM `User`. Produces: `Enrollment(secret: str, provisioning_uri: str, recovery_codes: tuple[str,...])`; `begin_totp(db: Session, user_id: int, keyring: Keyring, actor: Actor) -> Enrollment`; `confirm_totp(db: Session, user_id: int, code: str, keyring: Keyring, now: datetime, actor: Actor) -> bool`; `consume_second_factor(db: Session, user_id: int, code: str, keyring: Keyring, now: datetime, actor: Actor) -> bool`; `disable_totp(db: Session, user_id: int, actor: Actor) -> None`.

- [ ] Write failing tests with an RFC 6238 SHA-1 vector and DB concurrency:

```python
def test_totp_is_single_use(db, user, keyring, actor):
    enrollment = begin_totp(db, user.id, keyring, actor)
    assert len(enrollment.recovery_codes) == 10
    code = pyotp.TOTP(enrollment.secret).at(59)
    instant = datetime.fromtimestamp(59, timezone.utc)
    assert confirm_totp(db, user.id, code, keyring, instant, actor)
    assert not consume_second_factor(db, user.id, code, keyring, instant, actor)
    assert consume_second_factor(db, user.id, enrollment.recovery_codes[0], keyring, instant, actor)
    assert not consume_second_factor(db, user.id, enrollment.recovery_codes[0], keyring, instant, actor)
```

  Assert ±1 step acceptance, ±2 rejection, two concurrent requests accept a step/code once, encrypted row uses `user:<id>:totp:<version>`, only hashes persist, secret/recovery list shown once, and failed MFA increments the same lockout counter.
- [ ] Run `uv run pytest tests/integration/test_totp.py -q`; expect FAIL, MFA API absent.
- [ ] Implement using PyOTP with explicit SHA-1/digits/interval; lock user row before comparing/updating `totp_last_used_step` or removing a recovery hash, and reject any step <= the last accepted step. Enrollment stays disabled until confirmation, refuses replacing an enabled secret, and revokes existing sessions when enabled/disabled/reset. Reset/enrollment requires current-password re-auth in its caller; recovery success is audited without code content. Pending enrollment secret is encrypted and never re-displayed; restarting enrollment replaces unconfirmed material.
- [ ] Run `uv run pytest tests/integration/test_totp.py -q`; expect PASS.
- [ ] Commit: `git add app/auth/local.py tests/integration/test_totp.py`; `git commit -m "feat: enroll encrypted TOTP with atomic single-use factors"`.

### Task 10: Server sessions, CSRF, and web error foundation

**Files:** Create: `app/auth/sessions.py`, `app/main.py`, `app/templates/base.html.j2`, `app/templates/error.html.j2`, `app/static/app.css`. Test: `tests/integration/test_sessions_http.py`, `tests/integration/conftest.py`.

**Interfaces:** Consumes: `assert_database_ready(engine: Engine, timeout_seconds: int = 60) -> None`, `AuthBackend.authenticate(username: str, password: str) -> AuthResult`, `Settings`, `Actor`, `SecretRedactionFilter`. Produces: `create_app(settings: Settings | None = None) -> FastAPI`, module `app`; `issue_session(db: Session, user_id: int, now: datetime, ip: str, user_agent: str, authenticated: bool = True) -> UserSession`; `resolve_session(db: Session, cookie: str, now: datetime) -> UserSession | None`; `revoke_sessions(db: Session, user_id: int, now: datetime) -> int`; FastAPI `require_user(request: Request) -> UserRecord` and `require_admin(request: Request) -> UserRecord`; `check_csrf(request: Request, session: UserSession | None) -> None`; `allow_login_attempt(db: Session, ip: str, now: datetime) -> bool`.

- [ ] Write failing HTTPS-client tests:

```python
def test_cookie_csrf_and_expiry(client, signed_in, clock):
    cookie = signed_in.cookies.get('cd_session')
    assert len(cookie) == 64
    assert signed_in.post('/_test/protected').status_code == 403
    clock.advance(hours=8, seconds=1)
    response = signed_in.get('/_test/protected', headers={'HX-Request':'true'})
    assert response.status_code == 401 and response.headers['HX-Redirect'] == '/login'
```

  Assert HttpOnly/Secure/SameSite=Lax/Path=/ and no Domain; 24-hour absolute expiry despite activity; login rotation; logout/password/MFA revocation; inactive/pending-MFA sessions cannot authenticate; unknown session is rejected. Sixth IP attempt in the same minute returns 429 across separate DB connections/restarts. Assert header/form CSRF accepted, absent/foreign token denied for every POST including login, HTML redirect vs JSON 401, styled 403/404/422/500/503, DB rollback + Retry-After, request IDs, and no stack trace/secret in error responses.
- [ ] Run `uv run pytest tests/integration/test_sessions_http.py -q`; expect FAIL, HTTP/session foundation absent. Add a minimal test-only protected route for CSRF assertions until Task 11 owns logout.
- [ ] Implement in the listed files using Task 2's `user_session.authenticated_at`: NULL is password-verified/MFA-pending and `require_user` rejects it; pending sessions expire after 10 minutes. Login form uses short-lived HMAC-signed double-submit pre-auth CSRF cookie (10-minute lifetime, same cookie flags); completed login replaces it with session-bound CSRF. CSRF rejects unsafe requests before action dispatch; TOTP completion rotates the pending session. DB rate limit uses atomic upsert per UTC minute. Define test-only GET/POST `/_test/protected` routes and seed `signed_in` sessions directly until Task 11 adds login. Base template defines `title`, `content`, `status_banner`, `scripts` blocks, local htmx, escaped content, timezone formatting, and nav items Overview/Certificates/Servers/Deploy/Scans/Audit/Settings plus Users in user menu; unavailable features render disabled with reasons. Middleware adds structured JSON/request IDs and shared redaction; DB pool retries once, service transactions never replay partially committed mutations. Module-level app=create_app() defers default secret loading to lifespan, so injected-settings tests/imports do not read production secrets. Startup validates secrets/schema and key-version availability; key-dependent errors say “key material cannot be decrypted with the configured master key”.
- [ ] Run `uv run pytest tests/integration/test_sessions_http.py -q`; expect PASS.
- [ ] Commit: `git add app/auth/sessions.py app/main.py app/templates app/static/app.css tests/integration/conftest.py tests/integration/test_sessions_http.py`; `git commit -m "feat: protect web requests with sessions CSRF and typed errors"`. The authenticated-at column must already be committed in Task 2; this task makes no migration.

### Task 11: Login, MFA, bootstrap, and account-security forms

**Files:** Modify: `app/main.py`, `app/cli.py`, `app/auth/local.py`. Create: `app/templates/login.html.j2`, `app/templates/login_2fa.html.j2`, `app/templates/account.html.j2`, `app/templates/bootstrap.html.j2`. Test: `tests/integration/test_login_account.py`.

**Interfaces:** Consumes: `AuthBackend.authenticate(username: str, password: str) -> AuthResult` and the exact MFA/session APIs of Tasks 9–10. Produces: `bootstrap_admin(db: Session, username: str, email: str, password: str, actor: Actor) -> User`; `change_password(db: Session, user_id: int, old_password: str, new_password: str, actor: Actor) -> None`; GET/POST `/login`, `/login/2fa`; POST `/logout`; GET `/account`; POST `/account/password`, `/account/totp/enroll`, `/account/totp/confirm`, `/account/totp/disable`.

- [ ] Write failing tests:

```python
def test_login_does_not_grant_access_before_mfa(client, totp_user, csrf):
    first = client.post('/login', data={'username':'admin','password':'correct-long-pass','csrf_token':csrf}, follow_redirects=False)
    assert first.headers['location'] == '/login/2fa'
    assert client.get('/account', headers={'Accept':'application/json'}).status_code == 401

def test_bootstrap_requires_cli(client):
    response = client.get('/login')
    assert 'python -m app.cli bootstrap-admin' in response.text
    assert 'create first admin' not in response.text.lower()
```

  Test local/fake backend same flow, generic invalid credentials, active MFA replay refusal, `must_change_password` blocking other routes until changed, logout cookie clear, password/TOTP changes revoke all sessions, and prompt-confirmation/min-length/bootstrap audit through CLI runner.
- [ ] Run `uv run pytest tests/integration/test_login_account.py -q`; expect FAIL, routes/CLI absent.
- [ ] Implement in listed files; bootstrap CLI prompts without echo and confirms, or reads `BOOTSTRAP_ADMIN_PASSWORD` once, never logs it, refuses duplicate username. With no active user, /login redirects once to /login?bootstrap=1, which renders the CLI hint without a registration route. User identity/backend choice comes from backend lookup; use a configured default backend for unknown users. A pending MFA cookie has no admin authority; MFA attempts still rate-limit/lockout. Missing password reset points to another admin; no email reset. Account forms work without JavaScript and show enrollment secret/recovery codes once with no-store headers; current-password re-auth is required for password/MFA changes.
- [ ] Run `uv run pytest tests/integration/test_login_account.py tests/integration/test_sessions_http.py -q`; expect PASS.
- [ ] Commit: `git add app/main.py app/cli.py app/auth/local.py app/templates/login.html.j2 app/templates/login_2fa.html.j2 app/templates/account.html.j2 app/templates/bootstrap.html.j2 tests/integration/test_login_account.py`; `git commit -m "feat: expose login MFA and bootstrap account flows"`.

### Task 12: Transactional queue claims, terminal states, and reaper

**Files:** Create: `app/jobs/__init__.py`, `app/jobs/queue.py`. Test: `tests/integration/test_queue.py`.

**Interfaces:** Consumes: `transaction(factory: sessionmaker[Session]) -> ContextManager[Session]`, `JobType`, `Job`, `JobHost`, `Actor`, Task 3 audit contract. Produces: `enqueue(db: Session, job_type: JobType, payload: Mapping[str, JSONValue], actor: Actor, *, priority: int, run_after: datetime, max_attempts: int = 3) -> Job`; `claim(db: Session, worker_id: str, now: datetime, timeout_seconds: Callable[[Session, Job], int], *, eligible_types: frozenset[JobType] | None = None) -> Job | None`; `finish(db: Session, job_id: UUID, worker_id: str, status: Literal['succeeded','failed','cancelled'], now: datetime, *, result: Mapping[str, JSONValue] | None = None, error_class: str | None = None, error_message: str | None = None) -> None`; `reap(db: Session, now: datetime) -> int`; `retry_due(db: Session, now: datetime) -> int`; `JobFailure(error_class: str, message: str, retryable: bool = False)`.

- [ ] Write failing real-DB multi-connection tests:

```python
def test_claims_are_exclusive(queue_factory, seeded_jobs, now):
    def take(worker):
        with queue_factory.begin() as db:
            job = claim(db, worker, now, lambda db, job: 300)
            return job.id if job else None
    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(take, [str(i) for i in range(8)]))
    assert len([i for i in ids if i]) == len(set(i for i in ids if i)) == 8
```

  Pin priority/time/FIFO order, locked-head skip, future run_after exclusion, attempt increment, wrong-owner/late finish rejection after reaping, failed running hosts `worker_lost`, paused exclusion, deploy no retry, transient retry delays 30/120, non-retryable classes, and audit atomicity. Jobs exhausted at attempt 3 never receive a fourth claim.
- [ ] Run `uv run pytest tests/integration/test_queue.py -q`; expect FAIL, queue primitives absent.
- [ ] Implement the spec's single-statement SKIP LOCKED claim order, filtering optional eligible_types and setting timeout in the same transaction. Ownership checks fence stale completions after timeout. Reaper fails running jobs past timeout, clears claim metadata, marks running hosts failed/worker_lost, and records timeout audit; advisory lock cleanup belongs to worker connection lifetime, never pretend SQL clears another live connection's lock. Policies: discover/scan 3 attempts only transient_network; alert/digest 3 only SMTP 4xx/timeout; cleanup 2 retryable operational attempts; deploy 1. Non-retryable auth/validation/config_invalid/key_unwrap/internal. The spec's 30/120/300 delay sequence is capped by 3 **total** attempts, so only 30 and 120 are used; timeout/worker_lost is not automatically retried. No secrets permitted in payloads/results/errors.
- [ ] Run `uv run pytest tests/integration/test_queue.py -q`; expect PASS.
- [ ] Commit: `git add app/jobs tests/integration/test_queue.py`; `git commit -m "feat: add transactional Postgres job queue and timeout reaper"`.

### Task 13: Worker registry, scheduler shell, liveness, and cleanup

**Files:** Create: `app/jobs/worker.py`, `app/jobs/handlers/__init__.py`, `app/jobs/handlers/cleanup.py`. Modify: `app/main.py`, `app/config.py`. Test: `tests/integration/test_worker.py`.

**Interfaces:** Consumes: `claim(db: Session, worker_id: str, now: datetime, timeout_seconds: Callable[[Session,Job],int], *, eligible_types: frozenset[JobType] | None = None) -> Job | None` and remaining Task 12 APIs. Produces: `JobContext(job_id: UUID, worker_id: str, factory: sessionmaker[Session], settings: Settings)`; `JobHandler = Callable[[JobContext, Mapping[str, JSONValue]], Mapping[str, JSONValue]]`; `JobRegistry.register(job_type: JobType, handler: JobHandler, *, action: str = 'default', validator: Callable[[Mapping[str,JSONValue]], dict[str,JSONValue]]) -> None`; `JobRegistry.supports(job_type: JobType, action: str = 'default') -> bool`; `JobRegistry.dispatch(context: JobContext, job: Job) -> Mapping[str,JSONValue]`; `build_registry() -> JobRegistry` in `app/jobs/handlers/__init__.py`; `register_schedule(key: str, job_type: JobType, action: str = 'default') -> None`; `scheduler_tick(factory: sessionmaker[Session], registry: JobRegistry, now: datetime) -> None`; `run_worker(settings: Settings, registry: JobRegistry) -> None`; `cleanup(context: JobContext, payload: Mapping[str,JSONValue]) -> Mapping[str,JSONValue]`.

- [ ] Write failing worker tests with injected clock/handlers and actual DB:

```python
def test_heartbeat_and_cleanup(worker_harness, client, clock):
    worker_harness.tick()
    assert client.get('/healthz').json() == {'web':'ok','worker':'ok','db':'ok'}
    clock.advance(minutes=5, seconds=1)
    assert client.get('/healthz').json()['worker'] == 'stale'
    assert worker_harness.registry.supports(JobType.cleanup)
    assert not worker_harness.registry.supports(JobType.deploy)
```

  Assert two scheduler connections enqueue one daily cleanup, missed run at +31 min/+11 h catches up once and +12 h skips/logs, no unregistered schedule enqueued, invalid payload fails validation without retry, cleanup preserves audit/paused/running jobs, and startup wipes only safe children of `/run/cert-keys` (refuses symlink/path escape). Shutdown stops claims and closes advisory-lock connections; no stale worker may write a reaped job result.
- [ ] Run `uv run pytest tests/integration/test_worker.py -q`; expect FAIL, worker missing.
- [ ] Implement four slots, 0.5-second idle claim poll, 30-second heartbeat/tick, separate scheduler advisory-lock connection and ≤2 discovery/scan slots. Reserve capacity before claim and pass eligible_types so a third discovery/scan job remains queued rather than running while waiting for a semaphore. Test this with actual simultaneous claims. Store worker ID hostname+PID+boot UUID; current_job_id is one representative running slot, never the source of concurrency truth. Timeouts: discover/scan 1800 s, alert/digest 300 s, cleanup 600 s; deploy callback later computes distinct remaining-server count×600+900 s. Registry dispatch is keyed `(type, payload.action or 'default')`; reject duplicate registrations; unknown/poison payload is `validation`. Web and worker both call side-effect-free `build_registry()` for the same capability map; only worker dispatches jobs. Register only cleanup now; later tasks register import_pull. Cleanup at 04:00 UTC removes finished jobs/job_host and scan results >90 days, expired/revoked sessions and stale login counters, artifacts >30 days under a resolved safe root, never audit/target backups/key material. Deletion is retention's explicit exception to “jobs never deleted.” `/healthz` returns stated JSON with 503 for DB unavailable, worker stale flag otherwise; web/banner uses same heartbeat query. Gate absent SSH capability without preventing scans/cleanup.
- [ ] Run `uv run pytest tests/integration/test_worker.py tests/integration/test_queue.py -q`; expect PASS.
- [ ] Commit: `git add app/jobs/worker.py app/jobs/handlers app/main.py app/config.py tests/integration/test_worker.py`; `git commit -m "feat: run registered jobs with scheduler heartbeat and cleanup"`.

### Task 14: Certificate inventory service and lineage invariants

**Files:** Modify: `app/services/certificates.py`. Test: `tests/integration/test_certificates.py`.

**Interfaces:** Consumes: `store_key(db: Session, keyring: Keyring, key: PrivateKeyObject, origin: str, actor: Actor) -> PrivateKey`, `ParsedCertificate`, `ChainResult`, `Actor`. Produces: `CertificateMetadata(owner_name: str | None = None, owner_email: str | None = None, team: str | None = None, notes: str | None = None)`; `ImportResult(certificate: Certificate, created: bool, warnings: tuple[str,...])`; `save_certificate(db: Session, leaf: ParsedCertificate, chain: ChainResult, metadata: CertificateMetadata, actor: Actor, *, source: str, key_id: int | None = None, renews_id: int | None = None) -> ImportResult`; `update_certificate(db: Session, certificate_id: int, metadata: CertificateMetadata, actor: Actor) -> Certificate`; `set_status(db: Session, certificate_id: int, status: CertificateStatus, reason: str, actor: Actor) -> Certificate`; `attach_chain(db: Session, certificate_id: int, chain_data: bytes, actor: Actor) -> Certificate`; `set_lineage(db: Session, certificate_id: int, previous_id: int, actor: Actor) -> None`.

- [ ] Write failing persisted-identity tests:

```python
def test_import_deduplicates(db, certs, actor):
    leaf = parse_certificates(certs.leaf_pem)[0]
    chain = order_chain(certs.leaf, certs.intermediates)
    first = save_certificate(db, leaf, chain, CertificateMetadata(), actor, source='upload_pem')
    again = save_certificate(db, leaf, chain, CertificateMetadata(notes='overwrite?'), actor, source='upload_pem')
    assert first.created and not again.created
    assert again.certificate.id == first.certificate.id
    assert again.certificate.notes is None
```

  Assert same issuer+serial collision, concurrent identical imports converge, mismatched attached key is rejected, keyless renewal/discovery source rejected by CHECK, cycles/self-lineage rejected, metadata/status reason/chain changes audited exactly once, and incomplete chain notes preserve missing issuer diagnostics. An explicit later key import may attach a matching key to an existing public-only certificate with its own audit; duplicates must not silently overwrite ownership/notes.
- [ ] Run `uv run pytest tests/integration/test_certificates.py -q`; expect FAIL, inventory service incomplete.
- [ ] Implement in `services/certificates.py`; use savepoints/uniqueness for race-safe dedupe, row locks for lineage/status/key attachment, and explicit audited duplicate/reuse result. Prevent lineage cycles with a recursive ancestor query under a transaction-scoped lineage advisory lock; a concurrent reverse edge cannot pass both checks. Persist a Task 6A assessment into chain_status on import/chain changes; non-trusted status and issuer/root diagnostics are warnings only, never a trust-based import rejection. Expired public inventory imports are allowed with a warning; renewing/deploying applies stricter validity checks elsewhere. All mutations and their audits share the caller's transaction.
- [ ] Run `uv run pytest tests/integration/test_certificates.py -q`; expect PASS.
- [ ] Commit: `git add app/services/certificates.py tests/integration/test_certificates.py`; `git commit -m "feat: manage deduplicated certificate inventory and lineage"`.

### Task 15: Atomic upload import with inline validation

**Files:** Modify: `app/services/certificates.py`, `app/main.py`. Create: `app/templates/import.html.j2`. Test: `tests/integration/test_upload_import.py`.

**Interfaces:** Consumes: `parse_certificates(data: bytes) -> list[ParsedCertificate]`, `read_pfx(data: bytes, password: str | None) -> PFXMaterial`, exact Task 4/14 custody/inventory contracts. Produces: `UploadInput(data: bytes, format: Literal['pem','crt','pfx'], password: str | None = None, chain_data: bytes | None = None, key_data: bytes | None = None, key_password: str | None = None)`; `ImportValidationError(errors: Mapping[str, tuple[str,...]])`; `import_upload(db: Session, keyring: Keyring, upload: UploadInput, metadata: CertificateMetadata, actor: Actor) -> ImportResult`; GET `/certificates/import`, POST `/certificates/import/upload`.

- [ ] Write failing HTTP tests:

```python
def test_bad_upload_has_no_partial_rows(signed_in, db, csrf):
    before = (db.scalar(select(func.count()).select_from(Certificate)),
              db.scalar(select(func.count()).select_from(PrivateKey)))
    response = signed_in.post('/certificates/import/upload', data={'format':'pem','csrf_token':csrf}, files={'file':('bad.crt', b'not a certificate')})
    assert response.status_code == 422 and 'certificate' in response.text.lower()
    assert before == (db.scalar(select(func.count()).select_from(Certificate)),
                      db.scalar(select(func.count()).select_from(PrivateKey)))
```

  Add a 1,048,577-byte rejection before parsing, exact-limit read, malformed base64, PEM/DER `.crt`, wrong selected format, encrypted PEM key, unsupported private-key algorithm/size, matching PFX key+leaf+chain, public-only import, wrong password, mismatched private key, duplicate “view existing,” and htmx 422 fragment preserving non-secret fields. Assert upload/export passwords and private material never appear in HTML/audit/logs.
- [ ] Run `uv run pytest tests/integration/test_upload_import.py -q`; expect FAIL, import route/service absent.
- [ ] Implement bounded streamed reads for each uploaded object, content parsing independent of filename, PFX only in the import form, optional separate PEM key/chain, aggregate independent blocking errors separately from non-blocking chain-status diagnostics, and transaction after successful blocking validation so no orphan key survives. Reuse `store_key`/`save_certificate`; origin imported_pfx/imported_pem, imported_from upload_pfx/upload_pem. Imported private keys use the same supported RSA sizes/EC curves as generated keys; unsupported keys produce an explicit error, while public-only certificates remain importable. On duplicate, link existing; attaching a supplied matching key to public-only inventory requires an explicit confirmed action. Form re-renders retain owner/team/notes/format, never passwords/file contents; sanitized errors do not echo parsed key data.
- [ ] Run `uv run pytest tests/integration/test_upload_import.py -q`; expect PASS.
- [ ] Commit: `git add app/services/certificates.py app/main.py app/templates/import.html.j2 tests/integration/test_upload_import.py`; `git commit -m "feat: import certificate uploads with atomic validation"`.

### Task 16: Worker-side host:port pull import

**Files:** Create: `app/services/scans.py`, `app/jobs/handlers/import_pull.py`, `app/templates/import_progress.html.j2`. Modify: `app/jobs/handlers/__init__.py`, `app/main.py`, `app/templates/import.html.j2`. Test: `tests/integration/test_pull_import.py`.

**Interfaces:** Consumes: `JobRegistry.register(job_type: JobType, handler: JobHandler, *, action: str = 'default', validator: Callable[[Mapping[str,JSONValue]],dict[str,JSONValue]]) -> None`, Task 12 enqueue and Task 14 inventory contracts. Produces: `PulledChain(der_chain: tuple[bytes,...], tls_version: str)`; `pull_chain(host: str, port: int, sni: str | None, timeout_seconds: int = 10) -> PulledChain`; `validate_pull_payload(payload: Mapping[str,JSONValue]) -> dict[str,JSONValue]`; `import_pull(context: JobContext, payload: Mapping[str,JSONValue]) -> Mapping[str,JSONValue]`; POST `/certificates/import/pull`, GET `/imports/{job_id}` and `/imports/{job_id}/progress`.

- [ ] Write failing integration tests with a local TLS listener serving leaf+intermediates:

```python
def test_pull_import_creates_expectation(worker_harness, signed_in, tls_server, db, csrf):
    response = signed_in.post('/certificates/import/pull', data={'host':tls_server.host,'port':tls_server.port,'sni':'www.example.internal','csrf_token':csrf}, follow_redirects=False)
    assert response.status_code == 303
    worker_harness.run_queued()
    cert = db.scalar(select(Certificate).where(Certificate.imported_from == 'pull_endpoint'))
    endpoint = db.scalar(select(Endpoint).where(Endpoint.port == tls_server.port))
    assert cert.key_id is None and endpoint.expected_certificate_id == cert.id
    assert len(parse_certificates(cert.chain_pem.encode())) == 2
```

  Assert SNI is sent, self-signed/expired server certs import without trust verification (expiry warning), 10-second timeout/DNS/handshake errors sanitize, invalid port/URL/path input fails validation, retry is idempotent, and web request enqueues only (TLS listener connection count stays zero until worker runs).
- [ ] Run `uv run pytest tests/integration/test_pull_import.py -q`; expect FAIL, pull handler missing.
- [ ] Implement `pull_chain` in `services/scans.py` using pyOpenSSL peer-chain access with explicit connect/read deadline, SNI `sni or host`, no trust-store verification; cap returned objects/bytes at the upload limit. Register `(JobType.scan, action='import_pull')` with payload host/port/sni/metadata only; requested_by recovers the actor. Handler imports chain and upserts manual endpoint+expected certificate in one transaction, returns certificate_id/created/warnings. No scan_result is written: endpoint assessment belongs to Plan 2's default scan handler. The import progress page polls every 2 seconds with htmx and has a normal refresh link; shows sanitized job failure or links to imported/existing certificate. Internal host/IP input is intentional; accept host literals only, ports 1–65535, not URLs/CIDRs.
- [ ] Run `uv run pytest tests/integration/test_pull_import.py -q`; expect PASS.
- [ ] Commit: `git add app/services/scans.py app/jobs/handlers app/main.py app/templates/import.html.j2 app/templates/import_progress.html.j2 tests/integration/test_pull_import.py`; `git commit -m "feat: import served chains through worker pull jobs"`.

### Task 17: Certificate list, detail, and expiry-only overview

**Files:** Modify: `app/services/certificates.py`, `app/main.py`. Create: `app/templates/overview.html.j2`, `app/templates/certificates/list.html.j2`, `app/templates/certificates/detail.html.j2`, `app/templates/certificates/edit.html.j2`. Test: `tests/integration/test_inventory_http.py`.

**Interfaces:** Consumes: `update_certificate(db: Session, certificate_id: int, metadata: CertificateMetadata, actor: Actor) -> Certificate` and remaining Task 14 mutations, base template/session guards. Produces: `CertificateFilters(search: str | None = None, status: CertificateStatus | None = None, expiry: Literal['expired','lt7','lt30','lt60'] | None = None, issuer: str | None = None, team: str | None = None, owner: str | None = None, has_key: bool | None = None, has_bindings: bool | None = None, renewal_state: RenewalState | None = None)`; `CertificatePage(items: list[Certificate], total: int, page: int, page_size: int)`; `list_certificates(db: Session, filters: CertificateFilters, page: int = 1, page_size: int = 50, sort: str = 'not_after', now: datetime | None = None) -> CertificatePage`; `expiry_counts(db: Session, now: datetime) -> dict[str,int]`; GET `/`, `/certificates`, `/certificates/export.json`, `/certificates/{id}`; POST `/certificates/{id}/{edit|status|chain}`.

- [ ] Write failing read-model/HTTP tests with exact bucket boundaries:

```python
def test_expiry_buckets_are_disjoint(db, inventory_at_boundaries, now):
    counts = expiry_counts(db, now)
    assert counts == {'expired':1, 'lt7':1, 'lt30':1, 'lt60':1, 'total_active':5}

def test_filters_and_no_secret_panels(signed_in, inventory):
    response = signed_in.get('/certificates?has_key=true&team=infra&sort=not_after&page=1')
    assert response.status_code == 200 and 'infra' in response.text
    assert 'PRIVATE KEY' not in response.text and 'ciphertext' not in response.text
```

  Boundary fixture has active expiries now−1 s, +6 d, +7 d, +30 d, +60 d; superseded/revoked excluded. Also test every filter, whitelisted sorting, pagination limits (1–100), JSON export public field allowlist, empty setup links, escaped notes, required status-change reason, lineage/history/chain-warning/key metadata, and query count independent of row count (no N+1 binding count queries).
- [ ] Run `uv run pytest tests/integration/test_inventory_http.py -q`; expect FAIL, screens/read models absent.
- [ ] Implement in listed files; counts use disjoint expired (<now), <7, 7–<30, 30–<60, plus total active; counter links reproduce these exact ranges. Lists include all §8.3 columns/filters/bookmark queries and JSON export. Detail includes all public certificate fields, key presence/type/size/public fingerprint/version, related audits/renewal lineage, editable metadata/status, chain import, cached chain_status and missing-issuer/expired-intermediate/untrusted-root warnings linking Settings → Trust anchors; read existing bindings/endpoints in empty-ready panels without implementing their later screens/actions. Downloads/renewal buttons connect in Tasks 19–20; Deploy/Scan actions are gated on registered capabilities. Overview contains expiry buckets and setup empty state only; TLS/job/renewal summaries are extension slots for later plans. Datetimes emit UTC machine values plus local display; JSON never serializes ORM objects wholesale.
- [ ] Run `uv run pytest tests/integration/test_inventory_http.py -q`; expect PASS.
- [ ] Commit: `git add app/services/certificates.py app/main.py app/templates/overview.html.j2 app/templates/certificates tests/integration/test_inventory_http.py`; `git commit -m "feat: render searchable certificate inventory and expiry overview"`.

### Task 18: Audited renewal state machine and issued-certificate gate

**Files:** Create: `app/services/renewals.py`. Test: `tests/integration/test_renewals.py`.

**Interfaces:** Consumes: `generate_key(spec: KeySpec) -> PrivateKeyObject`, `build_csr(key: PrivateKeyObject, common_name: str, sans: Sequence[str]) -> CSRMaterial`, exact Tasks 4/6/14 custody/chain/inventory contracts. Produces: `RenewalBasics(common_name: str, sans: tuple[str,...], ca_name: str | None = None, notes: str | None = None)`; `InvalidTransition`; `IssuedValidationError(errors: Mapping[str,tuple[str,...]])`; `create_draft(db: Session, previous_id: int | None, basics: RenewalBasics, actor: Actor, now: datetime) -> Renewal`; `edit_draft(db: Session, renewal_id: UUID, basics: RenewalBasics, actor: Actor, now: datetime) -> Renewal`; `generate_csr(db: Session, renewal_id: UUID, spec: KeySpec, keyring: Keyring, actor: Actor, now: datetime) -> Renewal`; `mark_submitted(db: Session, renewal_id: UUID, order_reference: str, actor: Actor, now: datetime) -> Renewal`; `attach_issued(db: Session, renewal_id: UUID, leaf_data: bytes, chain_data: bytes | None, actor: Actor, now: datetime) -> Renewal`; `mark_deployed(db: Session, renewal_id: UUID, job_id: UUID, actor: Actor, now: datetime) -> Renewal`; `finalize(db: Session, renewal_id: UUID, previous_status: Literal['superseded','revoked'], reason: str, actor: Actor, now: datetime) -> Renewal`; `cancel(db: Session, renewal_id: UUID, reason: str, actor: Actor, now: datetime) -> Renewal`.

- [ ] Write failing state/issued-validation tests; parameterize every legal and illegal transition:

```python
def test_wrong_issued_key_is_atomic(db, submitted_renewal, certs, actor, now):
    rid = submitted_renewal.id
    before = db.scalar(select(func.count()).select_from(Certificate))
    with pytest.raises(IssuedValidationError) as exc:
        attach_issued(db, rid, certs.other_leaf_pem, certs.chain_pem, actor, now)
    assert 'key_match' in exc.value.errors
    assert db.get(Renewal, rid).state == RenewalState.submitted
    assert db.scalar(select(func.count()).select_from(Certificate)) == before
```

  Pin wrong CN/SAN set, RSA/EC mismatch with both public hashes shown, expired/not-yet-valid leaf, invalid CSR signature, PFX rejected, missing intermediate accepted with incomplete warning, expired intermediate accepted with incomplete warning, untrusted root accepted with untrusted_root warning, self-signed leaf, previously stored chain reuse, duplicate leaf (reject here, unlike import), required order reference/reasons, frozen names, cancelled key retention, and one audit per transition. `mark_deployed` rejects queued/failed/unrelated jobs and jobs without any succeeded binding for this new certificate; all illegal transitions leave state/audit count unchanged. Concurrent duplicate transition requests produce one change.
- [ ] Run `uv run pytest tests/integration/test_renewals.py -q`; expect FAIL, state service absent.
- [ ] Implement row-locked transitions in `services/renewals.py`: draft→csr_generated→submitted→issued→deployed→done; cancellation only draft/csr_generated/submitted/issued, never deployed/done/cancelled. CSR generation stores key+CSR/hash atomically and freezes basics. Issued validation accumulates all checks that can run after parsing, matches key **and CSR** SPKI, exact CN/canonical SAN set, `not_before <= now < not_after`, then evaluates supplied/stored intermediates with Task 6A without blocking on non-trusted chain status; inserts new certificate with key_id, imported_from renewal, renews_id previous. `issued_chain_pem` stores the normalized chain and certificate.chain_status stores the assessment; trust warnings are returned for inline rendering, while key/CSR/leaf-validity errors still block. `mark_deployed` is a service hook for Plan 3, not a manual bypass. Finalize requires deployed and explicit confirmation, changes prior status (superseded default, revoked with reason) in the same transaction. No deletion or backward transitions.
- [ ] Run `uv run pytest tests/integration/test_renewals.py -q`; expect PASS.
- [ ] Commit: `git add app/services/renewals.py tests/integration/test_renewals.py`; `git commit -m "feat: enforce audited manual renewal transitions and issuance checks"`.

### Task 19: Resumable manual-CA renewal wizard

**Files:** Modify: `app/main.py`, `app/templates/certificates/detail.html.j2`. Create: `app/templates/renewals/basics.html.j2`, `app/templates/renewals/csr.html.j2`, `app/templates/renewals/submitted.html.j2`, `app/templates/renewals/upload.html.j2`, `app/templates/renewals/ready.html.j2`, `app/templates/renewals/done.html.j2`. Test: `tests/integration/test_renewal_wizard.py`.

**Interfaces:** Consumes: `create_draft(db: Session, previous_id: int | None, basics: RenewalBasics, actor: Actor, now: datetime) -> Renewal` and every exact Task 18 transition signature. Produces: GET/POST `/renewals/new?from={cert_id}`; GET `/renewals/{id}?step={basics|csr|submitted|upload|ready|done}`; POST `/renewals/{id}/{edit|generate-csr|submit|issued|finalize|cancel}`; GET `/renewals/{id}/csr.pem`.

- [ ] Write failing form-only end-to-end tests using a fixture CA to issue from the generated CSR:

```python
def test_wizard_resumes_and_freezes_names(signed_in, wizard, ca):
    renewal = wizard.create_and_generate(common_name='www.example.internal', sans=['www.example.internal'])
    page = signed_in.get(f'/renewals/{renewal.id}?step=csr')
    assert renewal.csr_sha256 in page.text and renewal.csr_pem in page.text
    assert wizard.edit_names(renewal.id, 'other.example.internal').status_code == 422
    assert wizard.submit_order(renewal.id, '').status_code == 422
    assert wizard.submit_order(renewal.id, 'CA-123').status_code == 303
    assert wizard.upload_issued(renewal.id, ca.issue(renewal.csr_pem)).status_code == 303
```

  Define `wizard` fixture as HTTP form helpers adding CSRF and returning ORM rows through a fresh test transaction; `ca.issue` returns valid leaf+chain with matching CSR fields. Assert leave/re-enter each step, CSR download/hash persists later, PFX upload rejected here, all independent blocking errors and non-blocking trust warnings visible, state unchanged on blocking validation failure, cancellation reason required, and no unaudited or manual `issued→deployed` HTTP action exists. Seed a succeeded deploy job only to test final confirmation; this does not simulate actual deployment success.
- [ ] Run `uv run pytest tests/integration/test_renewal_wizard.py -q`; expect FAIL, wizard routes/templates absent.
- [ ] Implement persisted one-transition-per-POST forms, 303 redirects, htmx 422 fragments and non-JS equivalents. Prefill CN/SAN/CA/notes from source; algorithm default RSA 2048 and compatibility trade-off text; display exact CA checklist and CSR hash throughout. Upload accepts pasted/uploaded PEM/CRT plus optional chain, never PFX; server applies Task 18's key/CSR/leaf-validity gate and displays persisted non-trusted chain warnings before showing ready. Ready links `/deploy?certificate_id={id}` only when Plan 3 is registered, otherwise explains deployment is unavailable and leaves `issued` intact. Done requires automatic deployed evidence plus manual confirmation, previous certificate superseded by default; cancellation keeps key/history. CSR download is public-only, audited, safe filename, no-store.
- [ ] Run `uv run pytest tests/integration/test_renewal_wizard.py -q`; expect PASS.
- [ ] Commit: `git add app/main.py app/templates/certificates/detail.html.j2 app/templates/renewals tests/integration/test_renewal_wizard.py`; `git commit -m "feat: guide resumable manual certificate renewals"`.

### Task 20: Audited PEM/chain/PFX downloads

**Files:** Modify: `app/services/certificates.py`, `app/main.py`, `app/templates/certificates/detail.html.j2`. Create: `app/templates/certificates/export_pfx.html.j2`, `docs/operations.md`. Test: `tests/integration/test_downloads.py`.

**Interfaces:** Consumes: `unwrap_key(row: PrivateKey, keyring: Keyring) -> PrivateKeyObject`, `build_pfx(key: PrivateKeyObject, leaf: x509.Certificate, chain: Sequence[x509.Certificate], password: str, friendly_name: str) -> bytes`, Task 8 backend and Task 3 audit contracts. Produces: GET `/certificates/{id}/{leaf.pem|chain.pem|fullchain.pem}`; GET/POST `/certificates/{id}/export.pfx`; `export_pfx(db: Session, certificate_id: int, keyring: Keyring, pfx_password: str, actor: Actor) -> bytes` in `app/services/certificates.py` (caller has just re-authenticated).

- [ ] Write failing HTTP PFX integration tests:

```python
def test_pfx_requires_reauth_and_chosen_password(signed_in, cert_with_key, csrf, db):
    response = signed_in.post(f'/certificates/{cert_with_key.id}/export.pfx', data={
        'password':'correct-long-pass', 'pfx_password':'chosen-pass-123', 'csrf_token':csrf})
    assert response.status_code == 200
    key, leaf, chain = pkcs12.load_key_and_certificates(response.content, b'chosen-pass-123')
    assert leaf.fingerprint(hashes.SHA256()).hex() == cert_with_key.sha256_fingerprint
    assert key is not None and len(chain) == 2
    audit = db.scalar(select(AuditLog).where(AuditLog.action == 'key.export'))
    assert audit.target_id == str(cert_with_key.id)
    assert 'chosen-pass-123' not in json.dumps(audit.details)
```

  Test wrong/missing user password, <12-character PFX password, CSRF/session failures, no-key/missing-version/tampered-key errors, safe CN filenames, exact normalized PEM concatenation, password-required reload, all four download audits, and no temporary-file writes during export (patch file-opening/tempfile APIs to fail for export execution). Responses never return key PEM or ciphertext, including error cases.
- [ ] Run `uv run pytest tests/integration/test_downloads.py -q`; expect FAIL, download routes absent.
- [ ] Implement `export_pfx` in `app/services/certificates.py` and routes above; password re-entry is checked anew for every export against the signed-in user's own backend/username with matching Success.user_key, using the same lockout safeguards, then unwrap/build entirely in memory. Use `key.export` for PFX (not a second invented `pfx.export`), `certificate.download` with format for public material. Sanitize Content-Disposition names, set `Cache-Control: no-store`, prevent accidental framework spooling; missing key versions disable only dependent actions and show exact KeyUnwrapError text. Security failure audit is committed separately after the failed operation rolls back, with metadata only. `docs/operations.md` records installation/migration/bootstrap, canonical secret owners/modes from Global Constraints (bind mounts preserve them), optional worker credentials override and docker compose --profile migrate -f docker-compose.yml -f docker-compose.migrate.yml run --rm migrate with the owner secret, 3-copy/2-location master-key backup, 100-row rotation/verification, and quarterly staging restore+PFX drill from §11. Include the platform's nightly `pg_dump -Fc` backup procedure and 30-daily/12-weekly retention, with key copies stored separately; operational scheduling remains a host responsibility, not a new application job type.
- [ ] Run `uv run pytest tests/integration/test_downloads.py -q`; expect PASS.
- [ ] Commit: `git add app/services/certificates.py app/main.py app/templates/certificates/detail.html.j2 app/templates/certificates/export_pfx.html.j2 tests/integration/test_downloads.py docs/operations.md`; `git commit -m "feat: provide reauthenticated audited certificate downloads"`.

### Task 21: Read-only audit browser and JSON export

**Files:** Modify: `app/services/audit.py`, `app/main.py`. Create: `app/templates/audit.html.j2`. Test: `tests/integration/test_audit_http.py`.

**Interfaces:** Consumes: `require_user(request: Request) -> UserRecord`, `AuditLog`, base template. Produces: `AuditFilters(actor: str | None = None, action_prefix: str | None = None, target_type: str | None = None, target_id: str | None = None, start: datetime | None = None, end: datetime | None = None, ip: str | None = None)`; `list_audit(db: Session, filters: AuditFilters, page: int = 1, page_size: int = 50) -> tuple[list[AuditLog], int]`; GET `/audit` and `/audit/export.json`.

- [ ] Write failing HTTP assertions:

```python
def test_audit_is_filterable_and_read_only(signed_in, audited_changes, csrf):
    page = signed_in.get('/audit?action_prefix=certificate.&target_id=42')
    assert page.status_code == 200 and 'certificate.import' in page.text
    assert 'key.export' not in page.text
    exported = signed_in.get('/audit/export.json?target_id=42').json()
    assert all(row['target_id'] == '42' for row in exported)
    assert signed_in.post('/audit/delete', data={'csrf_token':csrf}).status_code in (404,405)
```

  Add actor/date/IP/target filters, newest-first tie-break by id, pagination, escaped expanded JSON/IP/user-agent, unauthenticated denial, and no CSV/edit/delete/purge controls.
- [ ] Run `uv run pytest tests/integration/test_audit_http.py -q`; expect FAIL, audit view absent.
- [ ] Implement parameterized queries, page size 1–100, query-string filter links and public metadata-only JSON export; reuse append-only writer, never ORM-update/delete audit. Audit export is an authenticated read, with no recursive “audit read of audit read” requirement.
- [ ] Run `uv run pytest tests/integration/test_audit_http.py -q`; expect PASS.
- [ ] Commit: `git add app/services/audit.py app/main.py app/templates/audit.html.j2 tests/integration/test_audit_http.py`; `git commit -m "feat: browse and export immutable audit history"`.

### Task 22: Local user administration and last-admin protection

**Files:** Modify: `app/auth/local.py`, `app/main.py`. Create: `app/templates/users.html.j2`. Test: `tests/integration/test_users_http.py`.

**Interfaces:** Consumes: `hash_password(password: str) -> str`, `revoke_sessions(db: Session, user_id: int, now: datetime) -> int`, Task 9 MFA and Task 3 audit contracts. Produces: `create_user(db: Session, username: str, email: str, display_name: str | None, password: str, actor: Actor) -> User`; `update_user(db: Session, user_id: int, email: str, display_name: str | None, actor: Actor) -> User`; `deactivate_user(db: Session, user_id: int, actor: Actor, now: datetime) -> None`; `reset_password(db: Session, user_id: int, new_password: str, actor: Actor, now: datetime) -> None`; `reset_totp(db: Session, user_id: int, actor: Actor, now: datetime) -> None`; GET `/users`; POST `/users`, `/users/{id}/{edit|deactivate|reset-password|reset-totp}`.

- [ ] Write failing admin safety tests:

```python
def test_last_active_user_cannot_be_deactivated(signed_in, sole_admin, csrf, db):
    response = signed_in.post(f'/users/{sole_admin.id}/deactivate', data={'csrf_token':csrf})
    assert response.status_code == 422
    assert db.get(User, sole_admin.id).is_active
```

  Test two concurrent deactivations preserve one active user, citext duplicate names, 12-character/denylist policy, reset sets must_change_password and revokes sessions, deactivation/MFA reset revoke immediately, LDAP password actions disabled **and** server-refused, no hard-delete route, all changes audited, and no hashes/seeds/recovery codes in list HTML/JSON.
- [ ] Run `uv run pytest tests/integration/test_users_http.py -q`; expect FAIL, admin services/UI absent.
- [ ] Implement in listed files; take a transaction-scoped `users:active` advisory lock before checking/deactivating to prevent concurrent last-user loss. User list shows backend/active/email/display name/last login; local creation is admin-only, first-admin bootstrap remains CLI-only. Password/MFA resets require the acting admin's current-password re-auth and CSRF; never display existing secrets. Temporary reset password is supplied once by the admin and never echoed; user must change it before accessing other screens. Every security change revokes target sessions atomically.
- [ ] Run `uv run pytest tests/integration/test_users_http.py -q`; expect PASS.
- [ ] Commit: `git add app/auth/local.py app/main.py app/templates/users.html.j2 tests/integration/test_users_http.py`; `git commit -m "feat: administer local users with last-admin safeguards"`.

### Task 23: Typed settings, status, and maintenance integration

**Files:** Create: `app/services/settings.py`, `app/templates/settings.html.j2`. Modify: `app/main.py`, `app/templates/base.html.j2`, `docs/operations.md`. Test: `tests/integration/test_settings_http.py`.

**Interfaces:** Consumes: `JobRegistry.supports(job_type: JobType, action: str = 'default') -> bool`, seeded `AppSetting`, `Keyring`, `WorkerHeartbeat`, `Job`, Task 6A add_anchor/remove_anchor/recheck_chain_statuses contracts. Produces: `get_setting(db: Session, key: str) -> JSONValue`; `update_settings(db: Session, changes: Mapping[str,JSONValue], actor: Actor) -> None`; `status_snapshot(db: Session, keyring: Keyring, now: datetime) -> dict[str,JSONValue]`; GET `/settings?tab={name}`; POST `/settings/{smtp|alerts|inventory|deployment|scanning|schedule|general|trust}`; POST `/settings/trust-anchors` (PEM upload), POST `/settings/trust-anchors/{id}/delete` (confirmation); POST `/settings/maintenance/prune` (confirmation `PRUNE OLD JOBS`).

- [ ] Write failing audited settings tests:

```python
def test_settings_secrets_and_ranges(signed_in, csrf, db):
    bad = signed_in.post('/settings/smtp', data={'smtp_password':'secret','csrf_token':csrf})
    assert bad.status_code == 422
    assert db.get(AppSetting, 'smtp_password') is None
    good = signed_in.post('/settings/deployment', data={'batch_percent':'10','concurrency':'5','pause_timeout_hours':'24','backup_retention_days':'0','csrf_token':csrf})
    assert good.status_code == 303
    assert get_setting(db, 'deploy.backup_retention_days') == 0
```

  Assert thresholds default [60,30,14,7,1,0], times UTC HH:MM, valid timezone, positive timeouts/concurrency, batch 1–100, non-negative retention (0 means forever only for target backups), SMTP security enum/TLS verify default true, unsafe warning when false, inventory path cannot escape checkout, secret-bearing repo URLs rejected, unknown keys rejected, and invalid patch changes nothing. Status pins 30-second heartbeat/5-minute stale, referenced missing versions, queue depth, DB size, absent SMTP/inventory warnings, last runs; before/after audit excludes secrets. Trust UI upload accepts only CA:TRUE self-signed PEM, rejects non-CA roots, and shows source/subject/fingerprint/notes plus include-public-bundle=true; upload/delete/toggle rechecks statuses and audits. Missing CSRF/confirmation is rejected. Prune requires exact typed confirmation and enqueues cleanup, never removes audit.
- [ ] Run `uv run pytest tests/integration/test_settings_http.py -q`; expect FAIL, settings UI/service absent.
- [ ] Implement explicit typed allowlist for **all** seeded settings from Task 2; persist each patch+before/after audits in one transaction. Render all §8.10 tabs, including Trust anchors: use Task 6A services for bounded PEM upload/delete and public-bundle toggle, synchronously rechecking within the audited transaction; public roots remain read-only in-memory bundle entries. Non-trusted certificate warnings remain visible but do not block import/issued upload; send-test-email/test-pull/deploy/scan controls are disabled with a precise handler/capability reason until their owning plan registers them. SMTP password is secret-presence metadata only; UI never sets it. Status shows keyring active/file fingerprint, stale/missing versions, heartbeat, database size, queue depth, last job/schedule runs and missing-recipient warnings. Maintenance shows CLI rotation instructions and typed-confirmed enqueue of retention cleanup. No web keyring file edits or key rotation button. Add deployment/backup/restore documentation links; respect secrets restart semantics.
- [ ] Run `uv run pytest tests/integration/test_settings_http.py -q`; expect PASS. Run `uv run ruff check .`, `uv run pytest -q --cov=app --cov-fail-under=70`, `uv run pip-audit`, `docker build -t cert-dashboard:test .`, and `docker compose -f docker-compose.test.yml config --quiet`; expect all PASS. Enforce the 85% crypto-package/renewals-module coverage gates via the CI coverage check configured in Task 1. These verify implemented code only when executing the plan; writing this plan does not claim these checks have run.
- [ ] Commit: `git add app/services/settings.py app/main.py app/templates/settings.html.j2 app/templates/base.html.j2 tests/integration/test_settings_http.py docs/operations.md`; `git commit -m "feat: expose typed settings operational status and maintenance"`.

## Extension points for plans 2-3

- **Schema:** Task 2 creates all v1 tables/enums/columns, defaults, indexes, retention fields, support tables and triggers; later plans add no migrations. Use the exact singular ORM names and mutable/immutable timestamp policy.
- **Trust validation:** reuse Task 6A assess_chain/recheck_chain_statuses; Plan 2 may register `(scan, action='trust_recheck')` for background refresh without a new enum/table. Anchor/public-bundle changes recheck synchronously until that exists. Plan 3 must revalidate at current UTC before preview/execution and require trusted or an explicit required-reason `deploy.chain_override` audit; override never bypasses key/leaf-validity/drift/config-test checks.
- **Job registry:** register `(JobType, action)` handlers with `JobRegistry.register(...)` and schedules with `register_schedule(...)`; enqueue/claim/finish/reaper ownership stays in `app/jobs/queue.py`. `scan/import_pull` is reserved for Task 16; Plan 2 registers `scan/default`, `alert_expiry/default`, `digest/default`; Plan 3 registers `discover/default` and `deploy/default`. Registry validators reject secrets/unknown keys before execution; each screen gates its actions on registry and required capabilities.
- **Worker:** share 4 slots, ≤2 simultaneous discovery/scan jobs, 30-second scheduler/heartbeat, explicit per-type retry/timeout policy and scheduler-state dedupe. Plan 2 fills scan/alert/digest schedules; Plan 3 fills discovery, deploy-timeout calculation and paused-deploy sweeps. It owns global `deploy:global`, per-host `deploy:<hostname>`, `inventory:pull` locks and pause/resume connection lifetimes; no placeholder deployment handler claims success in Plan 1.
- **TLS primitive:** Plan 2 reuses `pull_chain(host, port, sni, timeout_seconds) -> PulledChain` in `app/services/scans.py`, adding assessment/result persistence without changing import provenance or treating observed certificates as automatically trusted/imported.
- **Plan 3 file writes:** deploy writes each distinct file path once per host even when several bindings share it; rollback restores it once.
- **Services:** reuse `save_certificate`, `store_key`, `unwrap_key`, canonical SPKI/SAN/chain helpers and transactional `record`. Discovery reconciles existing server/binding/endpoint rows; deploy calls `mark_deployed(db, renewal_id, job_id, actor, now)` only after real succeeded host evidence. All callers own transactions; no direct route-level ORM state changes bypass services.
- **Settings:** `get_setting`/`update_settings` and preseeded keys are shared; Plan 2 adds SMTP test-send behavior, Plan 3 test-pull behavior. Their real outcome must populate Status; disabled controls are never presented as verified.
- **HTTP/UI:** mount later routes through `create_app`, use `require_user`/`require_admin`, CSRF, common errors/redaction and `base.html.j2` blocks; replace disabled Servers/Deploy/Scans navigation and certificate panels when enabled. Preserve non-JS POST/303 forms, htmx 422 fragments, safe JSON field allowlists, pagination and query-string filters. Overview's expiry counters stay unchanged as later plans fill TLS/jobs/in-flight-renewal/status slots.
- **Tests/operations:** extend `docker-compose.test.yml` with local SMTP/TLS and SSH nginx/Apache targets; retain Testcontainers DB fixtures and no-Internet policy. Real discovery/deploy/manual-CA/provider success remains unverified until the later plans and §10.4 acceptance work run.
