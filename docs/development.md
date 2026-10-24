# Development and container setup

Python 3.12 and uv 0.13.1 run the pinned dependencies in `uv.lock`.

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
foundation, sign-in/MFA flow and account-security forms are implemented. The worker
loop arrives in a later reviewed plan task.
The test Compose app runs unit smoke checks after its owner-only migrate service
completes; the full integration suite runs on the Docker-enabled host.

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
lands on `/account`; there is no `next` parameter, so no open redirect. `POST /logout`
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
version until both stale-row counts are zero and a PFX export succeeds; the PFX
export capability arrives in its later plan task.

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
PostgreSQL session factory and clock before entering TestClient. The app exposes
health/static routes, the `/login`, `/login/2fa`, `/logout` and `/account` routes. No
`/_test` routes ship in production. Reusable session rotation revokes the old ID and
replaces both ID and CSRF token. Pending MFA sessions last at most ten minutes and
confer no admin authority. Authentication completes only after the caller verifies its
factors.

Every non-GET requires session CSRF, or a signed ten-minute double-submit token
before authentication. Bodies are bounded to 4 MiB; multipart parts stay in memory.
Per-file 1 MiB limits remain the upload service's responsibility. Connection
acquisition retries once; request mutations and partially committed work never replay.
