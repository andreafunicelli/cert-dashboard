# Operations runbook

Audience: the administrator who installs, upgrades and backs up the dashboard on one Linux
Docker host. Every command below was cross-checked against `app/cli.py`,
`docker-compose.yml`, `docker-compose.migrate.yml`, `docker-compose.credentials.yml` and
`scripts/install-secrets.sh`. Commands run from the repository checkout on the host
(`docker compose ...`) unless a step says otherwise. Developer setup is in
[`development.md`](development.md); the normative design is spec §11.

Never put a secret value in a ticket, chat, shell history, environment variable, compose
file, image, CI variable or the repository. File secrets are read once at startup.

## 1. Prerequisites

- One internal Linux host or VM with Docker Engine and the Compose plugin, about 4 vCPU,
  8 GB RAM and 50 GB disk.
- An internal DNS name and a front proxy that terminates TLS. `web` is published only on
  `127.0.0.1:8000`; set `TRUSTED_PROXIES` (compose environment, empty by default) to the proxy
  address so client IPs in the audit log are correct.
- Root access on the host for provisioning secrets (the application never elevates).
- Optional, for later plans: an SSH key trusted by the managed servers, a Git token for the
  inventory repository and an SMTP password. They are mounted only through the credentials
  override (section 2.3).

## 2. First installation

### 2.1 Secrets and ownership

Provision these files under `/etc/cert-dashboard/secrets/` (the compose secret sources):

| File | Purpose | Required |
| --- | --- | --- |
| `master_key` | JSON keyring that encrypts private keys and TOTP seeds | yes |
| `session_secret` | at least 32 random bytes that sign sessions and flash cookies | yes |
| `db_password` | password of the runtime role `app_role` (web, worker) | yes |
| `db_owner_password` | password of `db_owner`; distinct from `db_password` | yes |
| `ansible_ssh_key`, `ansible_vault_password`, `inventory_git_token`, `smtp_password` | worker credentials | optional |

Generate the first master key with the built runtime image, as root. The temporary directory
is writable only by UID 10001; stdout shows only the digest and the path, never the keyring:

```sh
set -eu
install -d -m 0711 -o 0 -g 0 /etc/cert-dashboard/secrets
tmp="$(mktemp -d /tmp/cert-dashboard-keyring.XXXXXXXX)"
install -d -m 0700 -o 10001 -g 10001 "$tmp"
metadata="$(docker run --rm -v "$tmp":/out cert-dashboard:local python -m app.cli generate-master-key --version 1 --output /out/master_key.new)"
printf '%s\n' "$metadata"
expected="${metadata%% *}"
expected="${expected#sha256=}"
printf '%s  %s\n' "$expected" "$tmp/master_key.new" | sha256sum --check -
install -m 0400 -o 10001 -g 10001 "$tmp/master_key.new" /etc/cert-dashboard/secrets/master_key
shred -u -- "$tmp/master_key.new"
rmdir -- "$tmp"
```

Install only after the digest check succeeds. Create `session_secret`, `db_password` and
`db_owner_password` with your normal secret process (written straight into the file, never echoed),
then apply the canonical ownership as root. (Use `umask 077` while creating them, for example
`head -c 48 /dev/urandom | base64 -w0 > session_secret`.)

```sh
sh scripts/install-secrets.sh /etc/cert-dashboard/secrets
```

The script changes owners and modes only. It reads no values and creates no copies, and it
refuses symlinks and a missing required file. Compose file secrets are read-only bind mounts
that keep these numeric owners and modes (`mode:` is not remapped outside Swarm):

| Object | Owner | Mode |
| --- | --- | --- |
| Secret directory | `root:root` | `0711` |
| `master_key`, `session_secret` and optional worker credentials | `10001:10001` | `0400` |
| `db_password` (shared by the app and the Postgres init script) | `10001:999` | `0440` |
| `db_owner_password` | `999:999` | `0400` |

Re-run the script after replacing any secret file. **Immediately** do the master-key backup
in section 5.

### 2.2 Database, migration and administrator

1. Start the database: `docker compose up -d db`.
2. Apply the schema with the dedicated one-shot service. It runs as UID 999, mounts only
   `db_owner_password` (as `/run/secrets/db_password`) and never receives `master_key` or
   `session_secret`:

   ```sh
   docker compose --profile migrate -f docker-compose.yml -f docker-compose.migrate.yml run --rm migrate
   ```

3. Create the first administrator. No web route does this. The command prompts twice for the
   password (at least 12 characters, not in the denylist); the password never reaches argv,
   logs or the audit row:

   ```sh
   docker compose run --rm web python -m app.cli bootstrap-admin --username admin --email admin@example.internal
   ```

   Run it interactively (`docker compose run` allocates a terminal); the password exists only
   in your terminal prompt. Do not script it with environment variables or arguments: that
   would expose the secret to shell history, the process list or CI logs.
4. Start the application: `docker compose up -d web worker`.
5. Sign in, enroll two-factor authentication on the Account page and import the first
   certificate. Check the Overview and a certificate detail page. Then open **Settings → Status**
   (section 9): the worker must be `ok`, the keyring file SHA-256 must equal the fingerprint you
   recorded in section 5, and no `missing_key_versions` warning may be shown.

### 2.3 Optional worker credentials

Mount worker-only credentials only after provisioning them (and `/etc/cert-dashboard/known_hosts`,
the pinned SSH host keys). Edit `docker-compose.credentials.yml` first and remove the entries you
do not use, then include it with the base file:

```sh
docker compose -f docker-compose.yml -f docker-compose.credentials.yml up -d worker
```

Strict host key checking is enabled by the override; a changed host key fails the job.

## 3. Routine operations

| Task | Procedure |
| --- | --- |
| Upgrade | Take a database backup (section 4), pull or build the new image tag, run the migrate command from 2.2, then `docker compose up -d web worker`. Migrations are forward-only |
| Roll back an app upgrade | Re-pin the previous image tag and restart. If the migration was not backward compatible, restore the pre-upgrade backup (section 4) |
| Replace a secret | Replace the file, re-run `sh scripts/install-secrets.sh /etc/cert-dashboard/secrets` as root, then `docker compose up -d --force-recreate web worker` (a startup snapshot is read once) |
| Rotate the master key | Section 6 |
| Download certificate material | Certificate detail page: leaf, chain and full-chain PEM downloads are audited as `certificate.download`. Roots are never included |
| Export a private key | Certificate detail page → Export PFX. Only a PFX protected by a password you choose (12–1,024 characters) exists; you re-enter your own password each time; the export is audited as `key.export` without any password; failures are audited as `key.export_failed`. Nothing is written to disk. PEM key export is deliberately not offered |

## 4. Database backup and restore

The database holds encrypted private keys, certificates, users and the append-only audit log.
It does **not** contain the master key, and a dump must never be stored beside it (section 5).

### 4.1 Nightly backup (host responsibility)

Scheduling is the host's job (cron or a systemd timer); the application has no backup job type.
Take a custom-format dump with `pg_dump -Fc` inside the `db` container, over its local socket as
`db_owner`, so no password appears on a command line. Keep 30 daily and 12 weekly copies, then copy
the directory off-host with the platform's own backup job. Example script (run as root from cron,
for instance `15 2 * * *`):

```sh
#!/bin/sh
set -eu
cd /opt/cert-dashboard                  # the repository checkout containing docker-compose.yml
dest=/var/backups/cert-dashboard-db
umask 077
mkdir -p "$dest/daily" "$dest/weekly"
name="cert_dashboard-$(date +%Y%m%d-%H%M%S).dump"
docker compose exec -T db pg_dump -Fc -U db_owner -d cert_dashboard > "$dest/daily/$name.partial"
docker compose exec -T db pg_restore --list < "$dest/daily/$name.partial" > /dev/null
mv "$dest/daily/$name.partial" "$dest/daily/$name"
[ "$(date +%u)" = 7 ] && cp "$dest/daily/$name" "$dest/weekly/$name"
find "$dest/daily" -name '*.dump' -mtime +29 -delete     # keep 30 daily
find "$dest/weekly" -name '*.dump' -mtime +83 -delete    # keep 12 weekly
```

`pg_restore --list` proves the archive is readable before it is kept; a dump that fails it is left as
`.partial` and the script stops (and should alert). Take an extra dump immediately before every
upgrade and every master-key rotation.

### 4.2 Quarterly restore drill (staging)

A backup that has never been restored is not a backup. Every quarter, and after every master-key
rotation, on a **staging host** (not the production host):

1. Install the stack as in section 2.1, but place the **backup copy** of the keyring (copy B or C
   from section 5) in the staging `master_key`, never the production file.
2. `docker compose up -d db`, then restore the latest dump into the empty database (the init script
   already created `app_role`):

   ```sh
   docker compose exec -T db pg_restore -U db_owner -d cert_dashboard --no-owner < cert_dashboard-YYYYMMDD-HHMMSS.dump
   ```

   Do not run the migrate service on the restored data unless the dump predates an upgrade you are
   also drilling.
3. `docker compose up -d web`, sign in, check **Settings → Status** (section 9: the keyring file SHA-256
   is the copy you installed and there is no `missing_key_versions` warning), open the detail page of a
   certificate that has a key and **export one PFX**. Open it with the PFX password you chose; the key
   and chain must load.
4. Record the date, the operator, the dump name and the keyring fingerprint in the operations
   record. Tear the staging stack down and destroy its restored data.

If the PFX export fails with "key material cannot be decrypted with the configured master key", the
keyring copy does not match the dump: treat the backup as broken and fix it before the next rotation.

## 5. Master key backup (critical)

**Losing every copy of the master key makes every private key it wrapped permanently
unrecoverable.** Certificates (public material) survive; the wrapped keys do not, and those
certificates must be re-keyed and re-issued through the CA.

1. **Generate** the keyring on the dashboard host with the CLI (2.1). Never on a laptop and never
   sent by e-mail.
2. **Fingerprint** it. Record the SHA-256 of the keyring file (the CLI prints it) and the `active`
   version in the operations record, which is a ticket and not the place where the key is kept.
3. **Keep three copies in two physically separate, access-controlled locations:**
   - Copy A: the working file `/etc/cert-dashboard/secrets/master_key` (`0400`, `10001:10001`).
   - Copy B: the organization's secret manager (or a sealed envelope in a safe), held by custodian 1.
   - Copy C: a second entry or sealed envelope in a different location, held by custodian 2.
   Name the custodians in the operations record. At least two people must be able to produce the
   key. **No copy may be stored with the database backups**, and database backups must not be stored
   beside the key.
4. Never commit the key, paste it in chat or add it to a compose file, image or CI variable.
5. **Verify** the backup every quarter and after each rotation with the restore drill (4.2).
6. **Update all copies together** on rotation: after the verification in 6 step 4, replace B and C
   with the new keyring (it still contains the previous version until step 5), re-record the
   fingerprint, and destroy the superseded copies only after the next restore drill passes.
7. **If the master key is lost or incomplete:** the response depends on the case.
   - *`master_key` missing, unreadable or malformed — or an active version that is not a 32-byte
     key:* the dashboard cannot start. The secret is required, so startup of `web`, `worker` and the
     configuration-dependent CLI commands (`rotate-master-key`, `verify-key`, `bootstrap-admin`)
     aborts with a configuration error (see `docker compose logs web`). Only `generate-master-key`
     still works, because it reads no configured secret. Restore one of the copies above; do not
     generate a new keyring unless every copy of a needed version is gone (last bullet).
   - *The file loads but a referenced version is missing* (a stored key or TOTP seed names a version
     the keyring does not contain): the application starts, shows a persistent banner on every page,
     disables the dependent PFX actions, lists the missing versions in **Settings → Status**, and
     certificates already deployed keep working. This case is **recoverable**: install the keyring
     copy that still holds that version as `/etc/cert-dashboard/secrets/master_key`, keep its owner
     and mode (re-run `scripts/install-secrets.sh`), then
     `docker compose up -d --force-recreate web worker` and confirm the warning is gone. Re-key
     nothing before you have tried this.
   - *Every copy of a needed version is gone:* the rows wrapped under that version are permanently
     unrecoverable — no key you still hold can decrypt them. Treat the old keys as compromised and
     record the incident. Generate a fresh keyring with the recipe in 2.1, choosing a version number
     higher than any the database records (version numbers are never reused), install it with the
     canonical owner and mode, and restart `web` and `worker` so that it is loaded: the renewal
     wizard wraps new keys under the active version, so renewals cannot start until that restart has
     happened. Then generate new keys and CSRs for every affected certificate, re-issue them through
     the CA, and plan the work around the earliest expiry date in the inventory.
8. **If a copy leaks** (without the database): rotate immediately (section 6). The old key becomes
   useless once every row is re-encrypted and the old version is removed.

## 6. Master key rotation

The keyring holds at most two live versions, so rotation needs only a restart. Rotate when a
custodian leaves, when a key copy may have been exposed, and at least annually. Take a database
backup first (4.1).

1. Generate version N+1 into a **new** file, merging the current keyring (the merge source is
   mounted read-only and never modified; never redirect output onto the `--merge` path). As root:

   ```sh
   set -eu
   tmp="$(mktemp -d /tmp/cert-dashboard-keyring.XXXXXXXX)"
   install -d -m 0700 -o 10001 -g 10001 "$tmp"
   docker run --rm -v /etc/cert-dashboard/secrets:/secrets:ro -v "$tmp":/out cert-dashboard:local \
     python -m app.cli generate-master-key --version 2 --merge /secrets/master_key --output /out/master_key.v2.new
   sha256sum "$tmp/master_key.v2.new"
   ```

   The command creates the output `0400` (exclusively) and prints only `sha256=<digest> path=<file>`;
   the digest must equal the `sha256sum` output. It refuses to run when two versions are already live.
2. Store a copy of the old file in the backup location (section 5), then install the verified file
   and reload so that new writes use version 2:

   ```sh
   install -m 0400 -o 10001 -g 10001 "$tmp/master_key.v2.new" /etc/cert-dashboard/secrets/master_key
   shred -u -- "$tmp/master_key.v2.new" && rmdir -- "$tmp"
   docker compose up -d --force-recreate web worker
   ```

3. Re-encrypt every key and TOTP seed. The command works in batches of 100 rows, each batch in its
   own transaction with a counts-only audit, prints `remaining=N` and is idempotent and resumable.
   It exits non-zero, with metadata only, if anything is still on an old version or still refers to
   a missing version:

   ```sh
   docker compose run --rm web python -m app.cli rotate-master-key
   ```

4. Verify that both counts are `0` (the same figures are shown as "Rows not yet on the active version"
   in **Settings → Status** and **Settings → Maintenance**, section 9), then verify one keyed
   certificate (it prints metadata only):

   ```sh
   docker compose exec -T db psql -U db_owner -d cert_dashboard -c "SELECT count(*) FROM private_key WHERE master_key_version <> 2"
   docker compose exec -T db psql -U db_owner -d cert_dashboard -c "SELECT count(*) FROM \"user\" WHERE totp_secret_ciphertext IS NOT NULL AND totp_secret_version IS DISTINCT FROM 2"
   docker compose run --rm web python -m app.cli verify-key --certificate-id ID
   ```

5. Update copies B and C (section 5 step 6). Remove version 1 from the secret file and
   `docker compose up -d --force-recreate web worker` again only after both counts are zero and one
   PFX export succeeded. Destroy the old key copy last, after the next restore drill.

## 7. Security hardening checklist

- `web` listens on `127.0.0.1` only; TLS and HTTP-to-HTTPS redirects live on the front proxy.
- Containers run as non-root (web, worker 10001; migrate 999) with `read_only: true`, dropped
  capabilities and `no-new-privileges`; web and worker use a `noexec` `/tmp`; the worker has a
  private tmpfs for decrypted key material that is never persisted.
- Secrets are read-only bind mounts with the owners and modes in 2.1; run
  `scripts/install-secrets.sh` after provisioning or replacing a file.
- Postgres is not published; the application role cannot update or delete `audit_log`.
- Container logs rotate (`max-size=50m`, `max-file=5`). Pin and update dependencies monthly
  (`pip-audit` runs in CI).
- Keys are exported only as a re-authenticated, password-protected PFX built in memory. Failed
  re-authentication counts toward the account lockout (10 failures, 15 minutes).

## 8. Operational signals

The signals below follow spec §11.8. Rows marked **Plan 1** work in this release; rows marked
**Later plans** depend on features that are not shipped yet and are listed only so you know what
will appear. Do not rely on them today.

| Signal | Availability | Where to look | Response |
| --- | --- | --- | --- |
| Worker stale (no heartbeat for more than 5 minutes) | Plan 1 | Red banner "Worker is not running" on every page (it links to **Settings → Status**); `curl -fsS http://127.0.0.1:8000/healthz` returns `"worker": "stale"` (and `"db": "unavailable"` with HTTP 503 when the database is down); the `worker` container turns `unhealthy` | `docker compose ps`, then `docker compose logs --tail 200 worker`. Restart with `docker compose up -d worker`. A worker that stays stale after a restart usually means the database or a secret file is unreachable: check `docker compose logs db` and the owners and modes in section 2.1 |
| Job queue depth growing or a job stuck | Plan 1 | **Settings → Status** shows queued, running, paused and failed-in-24-hours counts, the last finished job per type and the last scheduled runs. For the oldest waiting rows query the database: `docker compose exec -T db psql -U db_owner -d cert_dashboard -c "SELECT status, type, count(*), min(created_at) FROM job WHERE status IN ('queued','running','paused') GROUP BY 1, 2"` | Many `queued` rows with a fresh heartbeat mean the worker is saturated (four slots) or a job is stuck. Check `docker compose logs worker`. The reaper times out `running` jobs past `timeout_at` and requeues retryable failures every scheduler tick. Failed jobs keep `error_class` and `error_message` (no secrets) in the `job` row |
| Web unavailable | Plan 1 | `curl -fsS http://127.0.0.1:8000/health/live` and `/health/ready`; `docker compose ps` | `/health/live` failing: restart `web`. `/health/ready` failing: the database is unreachable, see `docker compose logs db` |
| Disk usage on the dashboard host | Plan 1 (host monitoring) | `df -h /var/lib/docker /var/backups/cert-dashboard-db`; `docker system df` | Container logs are capped at 50m x 5 files per container. Database dumps are pruned by the script in 4.1. Alert the host monitoring at 80% usage. The application prunes its own data with the `cleanup` job, which runs daily at 04:00 UTC (`cleanup.daily_at`, `cleanup.enabled`): finished jobs older than `retention.days` (90 by default); scan results older than a fixed 90 days (`SCAN_RESULT_RETENTION`, independent of `retention.days`); expired/idle/revoked sessions; login counters older than one day; and artifacts older than 30 days. It never removes audit rows, and **Settings → Maintenance** (section 9.2) queues the same prune on demand |
| Key export failures | Plan 1 | Audit rows `key.export_failed` (for example `SELECT created_at, target_id, details FROM audit_log WHERE action = 'key.export_failed' ORDER BY created_at DESC LIMIT 20`) | `key_unwrap` or a missing master-key version: the secret file does not hold the version used by that certificate; restore the missing copy (section 5) before anything is rotated. `no_key`: the certificate has no stored key (expected for imported certificates without one) |
| Repeated failed re-authentication or lockouts | Plan 1 | Audit rows `auth.login_failed` and `auth.lockout` (for example `SELECT created_at, action, target_id, details, ip FROM audit_log WHERE action IN ('auth.login_failed', 'auth.lockout') ORDER BY created_at DESC LIMIT 50`) | 10 consecutive failures lock an account for 15 minutes; a wrong password at the PFX export form counts toward the same counter. Many failures from one address point at a guessing attempt: block it on the front proxy |
| Discovery failing for many hosts | Later plans | Not available yet | Will appear in the digest and the job list |
| Consecutive SMTP failures | Later plans | Not available yet | Will appear in the status panel and as a missing digest |
| Deploy rollback | Later plans | Not available yet | Will appear on the Overview, in the digest and in the audit log |
| Disk usage on targets (`/var/backups/cert-dashboard`) | Later plans | Not available yet | Deploy backups and their retention arrive with the deploy plan |

## 9. Settings: Trust anchors, Status and Maintenance

The three operational tabs of **Settings** (admin only, CSRF-protected, every change audited) tie the
procedures above together. None of them shows or accepts a secret value.

### 9.1 Status

**Settings → Status** is read-only and is the first place to look after an install (2.2), a restore
drill (4.2), a rotation (6) or an incident (8):

| Panel | What it shows | Use it to |
| --- | --- | --- |
| Warnings | `smtp_not_configured`, `inventory_not_configured`, `no_alert_recipients` (no recipients and an active certificate without an owner e-mail), `missing_key_versions`, `worker_stale` | See at a glance what is unconfigured or broken |
| Worker | State `ok` or `stale`, last heartbeat, 30-second heartbeat, stale after 5 minutes, live worker count (the same rule as `/healthz` and the red page banner) | Confirm a restart of `worker` took effect |
| Queue | Queued, running, paused and failed-in-24-hours job counts; last finished job per type; last scheduled runs | Spot a saturated worker or a failing schedule |
| Keyring | Active version, loaded versions, SHA-256 of the keyring **file**, versions referenced by stored keys or TOTP seeds but missing from the file, rows not yet on the active version | Compare the fingerprint with the operations record (section 5); prove a rotation is finished (6 step 4) |
| Database | Database size | Capacity planning next to the host disk checks in section 8 |

The page banner for a stale worker or an undecryptable key version links here.

### 9.2 Maintenance

**Settings → Maintenance** has no keyring editor and no rotation button: rotation stays a command-line
procedure (section 6) and the panel only repeats its commands with the current keyring state. The
one form on the page queues the retention cleanup (finished jobs past the retention period, old scan
results, expired sessions, old artifacts). It requires the exact, case-sensitive text
`PRUNE OLD JOBS`; anything else is refused with HTTP 422 and nothing is queued. The cleanup runs on
the worker like any other job (`job.enqueue` and `maintenance.prune_requested` are audited) and
**never removes audit rows**.

### 9.3 Trust anchors

**Settings → Trust anchors** lists the internal roots you uploaded and the read-only public bundle
line (pinned certifi version, number of roots, include-public-bundle on or off). Upload one
self-signed CA root as PEM (`CA:TRUE`, certificate-signing key usage, at most 1,048,576 bytes);
leaf certificates, intermediates and non-CA roots are refused. Deleting an anchor requires typing
`DELETE`. Adding or deleting an anchor and toggling the public bundle each recheck every stored
chain status immediately, in the same audited transaction, and show the resulting counts. Chains
that are not trusted remain visible warnings; they never block an import.

### 9.4 Secrets restart semantics

Secret files (`master_key`, `session_secret`, `db_password`, the optional worker credentials) are
read **once at startup** and are never reloaded or editable from the web interface. To change one:
replace the file, run `sh scripts/install-secrets.sh /etc/cert-dashboard/secrets` as root and restart
the services (`docker compose up -d --force-recreate web worker`, see section 3). Until the restart,
**Settings → Status** keeps showing the fingerprint of the keyring file the running process loaded, so
a mismatch with the file on disk means a restart is still pending.
