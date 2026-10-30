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
- An internal SMTP relay for expiry alerts and the daily digest, and at least one recipient address
  (section 10). Without a relay the dashboard still works; it records the failures instead of sending.
- Optional, for later plans: an SSH key trusted by the managed servers and a Git token for the
  inventory repository. They are mounted only through the credentials override (section 2.3).

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

Strict host key checking is enabled by the override; a changed host key fails the job. The same
override is what mounts `smtp_password`: the base file does not, so a relay that needs AUTH requires
this override (section 10.1). To give the mails clickable links, set `DASHBOARD_URL` for the worker as
well — it is an environment value, never a secret:

```sh
DASHBOARD_URL="https://cert-dashboard.example.internal" \
  docker compose -f docker-compose.yml -f docker-compose.credentials.yml up -d worker
```

A `DASHBOARD_URL` that is not an absolute `http(s)` URL without credentials, query or fragment refuses
worker startup (exit code 2). Without it, mails carry relative paths such as `/certificates/42`.

## 3. Routine operations

| Task | Procedure |
| --- | --- |
| Upgrade | Take a database backup (section 4), pull or build the new image tag, run the migrate command from 2.2, then `docker compose up -d web worker`. Migrations are forward-only |
| Roll back an app upgrade | Re-pin the previous image tag and restart. If the migration was not backward compatible, restore the pre-upgrade backup (section 4) |
| Replace a secret | Replace the file, re-run `sh scripts/install-secrets.sh /etc/cert-dashboard/secrets` as root, then `docker compose up -d --force-recreate web worker` (a startup snapshot is read once) |
| Rotate the master key | Section 6 |
| Download certificate material | Certificate detail page: leaf, chain and full-chain PEM downloads are audited as `certificate.download`. Roots are never included |
| Export a private key | Certificate detail page → Export PFX. Only a PFX protected by a password you choose (12–1,024 characters) exists; you re-enter your own password each time; the export is audited as `key.export` without any password; failures are audited as `key.export_failed`. Nothing is written to disk. PEM key export is deliberately not offered |
| Configure or test e-mail | Section 10.1: **Settings → SMTP**, then **Send test email**. The outcome (step names and reply codes) is shown on the same tab |
| Pause alerts, digest or scanning | Section 10.2: clear *Send the daily digest*, *Run the daily expiry check* or *Run the daily scan* in **Settings → Alerts** / **Settings → Scanning**. Manual **Scan now** keeps working |
| Check what the endpoints serve | **Scans** (`/scans`): statuses, history, **Scan now**/**Scan all**, expectations (section 10.4) |

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

**Losing every copy of the master keyring — or of a version that rows still reference — makes
every private key wrapped under that version permanently unrecoverable.** Certificates (public
material) survive; the wrapped keys do not, and those certificates must be re-keyed and re-issued
through the CA.

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
7. **If the master key is lost or incomplete:** decide which case applies before touching a file,
   and never destroy a surviving copy while you work. List the versions the database still needs
   (metadata only; no key material is printed):

   ```sh
   docker compose exec -T db psql -U db_owner -d cert_dashboard -c "SELECT master_key_version FROM private_key UNION SELECT totp_secret_version FROM \"user\" WHERE totp_secret_version IS NOT NULL ORDER BY 1"
   ```

   **Settings → Status → Keyring** shows the installed file's `active_version`, its
   `loaded_versions` and the referenced `missing_versions`. A keyring holds at most two live
   versions and `active` must be one of them; the CLI cannot merge two files, because
   `generate-master-key --merge` takes a single source and only adds one new version. **Any keyring
   you install must contain every referenced version that still exists in some copy, plus a valid
   `active` version.** Never install an older or freshly generated single-version file that drops
   one of them: rows that decrypt today would become unreadable.

   - *`master_key` missing, unreadable or malformed — or an active version that is not a 32-byte
     key:* the dashboard cannot start. The secret is required, so startup of `web`, `worker` and the
     configuration-dependent CLI commands (`rotate-master-key`, `verify-key`, `bootstrap-admin`)
     aborts with a configuration error (see `docker compose logs web`). Only `generate-master-key`
     still works, because it reads no configured secret. Restore one of the copies above and restart
     both services; generate a new keyring only when no copy of a needed version exists (last case).
   - *Partial loss — the file loads but a referenced version is missing from it* (a stored key or
     TOTP seed names a version the keyring does not contain): the application starts, shows a
     persistent banner on every page, disables the dependent PFX actions, lists the missing versions
     in **Settings → Status**, and certificates already deployed keep working. This case is
     **recoverable** while some copy still holds that version. Pick the single copy that contains
     the missing version **and** every other referenced version you can still recover; check it
     without installing it (this prints version numbers only, never key material):

     ```sh
     docker run --rm --user 0 -v /absolute/path/to/candidate:/ring:ro cert-dashboard:local \
       python -c 'import json; d = json.load(open("/ring")); print(d["active"], sorted(map(int, d["keys"])))'
     ```

     Install that file as `/etc/cert-dashboard/secrets/master_key` (`0400`, `10001:10001`; re-run
     `scripts/install-secrets.sh /etc/cert-dashboard/secrets`), then
     `docker compose up -d --force-recreate web worker` and confirm the warning is gone. Keep the
     replaced file as a copy until the next restore drill passes: it may be the only copy of a
     version rows still reference. Do **not** install a copy that holds the missing version but
     lacks a version that is still referenced — that makes other rows unreadable. If no single copy
     contains all recoverable referenced versions, **stop**: install nothing, generate nothing and
     do not hand-merge key material; preserve every copy and reconcile under the custody procedure
     in this section (two custodians, recorded fingerprint, no key sent by chat or e-mail). Once the
     restored ring is running, move new writes onto a fresh version by generating a merged keyring
     into a new file with the commands in section 6 steps 1–2, replacing their example version with
     `--version N`, where **N is higher than every version listed above** (versions are never
     reused); do not reuse the `--version 1` first-install command from 2.1. If it refuses because
     the merge source already holds two live versions, do not delete a version by hand: keep the
     restored ring running (its active version still serves new writes) and complete or re-plan that
     rotation with the custodians first.
   - *A referenced version is lost from every copy, but other versions survive:* the rows wrapped
     under the lost version are permanently unrecoverable — no key you still hold can decrypt them.
     Keep the survivors: install the copy that holds every recoverable referenced version exactly as
     in the partial case, and never replace it with a fresh single-version keyring, which would make
     those rows unreadable too. Treat the lost keys as compromised, record the incident, and plan
     re-keying and re-issuance of the affected certificates through the CA, working back from the
     earliest expiry date in the inventory. To move new writes to a fresh active version, generate
     **merged** from the installed file with a version number higher than every recorded version, as
     above.
   - *Complete loss — no copy of the keyring remains:* every wrapped key is unrecoverable. Generate
     a fresh keyring with a version number higher than every version the database records (the
     maximum of the list above; versions are never reused — do not copy `--version 1` from 2.1),
     install it with the canonical owner and mode, and restart `web` and `worker` so that it is
     loaded: the renewal wizard wraps new keys under the active version, so renewals cannot start
     until that restart has happened. Then generate new keys and CSRs for every certificate that had
     a stored key, re-issue them through the CA, and plan the work around the earliest expiry date
     in the inventory.
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

The signals below follow spec §11.8. Rows marked **Plan 1** and **Plan 2** work in this release; rows
marked **Later plans** depend on features that are not shipped yet and are listed only so you know what
will appear. Do not rely on them today.

| Signal | Availability | Where to look | Response |
| --- | --- | --- | --- |
| Worker stale (no heartbeat for more than 5 minutes) | Plan 1 | Red banner "Worker is not running" on every page (it links to **Settings → Status**); `curl -fsS http://127.0.0.1:8000/healthz` returns `"worker": "stale"` (and `"db": "unavailable"` with HTTP 503 when the database is down); the `worker` container turns `unhealthy` | `docker compose ps`, then `docker compose logs --tail 200 worker`. Restart with `docker compose up -d worker`. A worker that stays stale after a restart usually means the database or a secret file is unreachable: check `docker compose logs db` and the owners and modes in section 2.1 |
| Job queue depth growing or a job stuck | Plan 1 | **Settings → Status** shows queued, running, paused and failed-in-24-hours counts, the last finished job per type and the last scheduled runs. For the oldest waiting rows query the database: `docker compose exec -T db psql -U db_owner -d cert_dashboard -c "SELECT status, type, count(*), min(created_at) FROM job WHERE status IN ('queued','running','paused') GROUP BY 1, 2"` | Many `queued` rows with a fresh heartbeat mean the worker is saturated (four slots) or a job is stuck. Check `docker compose logs worker`. The reaper times out `running` jobs past `timeout_at` and requeues retryable failures every scheduler tick. Failed jobs keep `error_class` and `error_message` (no secrets) in the `job` row |
| Web unavailable | Plan 1 | `curl -fsS http://127.0.0.1:8000/health/live` and `/health/ready`; `docker compose ps` | `/health/live` failing: restart `web`. `/health/ready` failing: the database is unreachable, see `docker compose logs db` |
| Disk usage on the dashboard host | Plan 1 (host monitoring) | `df -h /var/lib/docker /var/backups/cert-dashboard-db`; `docker system df` | Container logs are capped at 50m x 5 files per container. Database dumps are pruned by the script in 4.1. Alert the host monitoring at 80% usage. The application prunes its own data with the `cleanup` job, which runs daily at 04:00 UTC (`cleanup.daily_at`, `cleanup.enabled`): finished jobs older than `retention.days` (90 by default); scan results older than a fixed 90 days (`SCAN_RESULT_RETENTION`, independent of `retention.days`); expired/idle/revoked sessions; login counters older than one day; and artifacts older than 30 days. It never removes audit rows, and **Settings → Maintenance** (section 9.2) queues the same prune on demand |
| Key export failures | Plan 1 | Audit rows `key.export_failed` (for example `SELECT created_at, target_id, details FROM audit_log WHERE action = 'key.export_failed' ORDER BY created_at DESC LIMIT 20`) | `key_unwrap` or a missing master-key version: the secret file does not hold the version used by that certificate; restore the missing copy (section 5) before anything is rotated. `no_key`: the certificate has no stored key (expected for imported certificates without one) |
| Repeated failed re-authentication or lockouts | Plan 1 | Audit rows `auth.login_failed` and `auth.lockout` (for example `SELECT created_at, action, target_id, details, ip FROM audit_log WHERE action IN ('auth.login_failed', 'auth.lockout') ORDER BY created_at DESC LIMIT 50`) | 10 consecutive failures lock an account for 15 minutes; a wrong password at the PFX export form counts toward the same counter. Many failures from one address point at a guessing attempt: block it on the front proxy |
| Endpoints unreachable, mismatching or expired | Plan 2 | **Scans** list (sorted by status, `expired` first), the Overview **TLS health** counters (they link to `/scans?status=…`), and the digest's *New TLS mismatches* section. Query: `docker compose exec -T db psql -U db_owner -d cert_dashboard -c "SELECT last_scan_status, count(*) FROM endpoint WHERE is_active GROUP BY 1"` | `unreachable` for more than one run: check the target's firewall/service, then **Scan now**. `mismatch`: the served certificate is not the expected one — renew and deploy it, import the served certificate, or update the expectation (section 10.4). `expired`: `not_after` has passed; renew (section 3 of the renewal wizard) |
| Scan job failed | Plan 2 | **Overview → Recent jobs**, the job's audit row (`scan.run`), `docker compose logs worker` | While attempts remain, a scan that leaves endpoints unreachable fails retryably (`transient_network`) and the next attempt rescans only those endpoints; the third and final attempt records its counts and **succeeds** even if they are still down, so a host that stays unreachable shows as `unreachable` on the endpoint, not as a failed job. Fix the network path, then **Scan now**. A `validation` failure means the payload was wrong (only the UI and scheduler enqueue scans) |
| Consecutive SMTP failures | Plan 2 | **Settings → Status** SMTP panel (consecutive failures, last error, last success, last test) and the `smtp_failing` warning; **Settings → Alerts** lists the newest failed notifications with attempts and the next attempt; the digest repeats them under *Failed notifications in the last 24 hours* | Fix the relay or credentials (section 10.1), then **Send test email**. Only transient failures (connection, timeout, 4xx reply) are retried automatically: an expiry row twice within its UTC day (30 s, 120 s), then it stays `failed`. AUTH, TLS-verification and permanent-rejection failures are not retried; the next UTC day's evaluation creates a new key and attempts again. Mail delivery is at-least-once, so a duplicate after a crash is possible and needs no action |
| SMTP TLS verification disabled | Plan 2 | `smtp_tls_unverified` warning in **Settings → Status**; the SMTP tab shows the unsafe note | Re-enable `smtp.tls_verify` once the relay presents a certificate the host trusts; while it is off, credentials and mail content can be intercepted |
| Missing or late digest | Plan 2 | **Overview** status strip (**Last digest**) and **Settings → Status** | Check `alert.digest_enabled`, `digest.daily_at` (07:30 UTC) and the digest job in **Overview → Recent jobs**. An empty recipient list is recorded as a failed `no_recipients` row and is not retried; only a transient relay failure (connection, timeout, 4xx reply) retries the job, up to three attempts |
| Discovery failing for many hosts | Later plans | Not available yet | Will appear in the digest and the job list |
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
| Warnings | `smtp_not_configured`, `smtp_failing`, `smtp_tls_unverified`, `inventory_not_configured`, `no_alert_recipients` (no recipients and an active certificate without an owner e-mail), `missing_key_versions`, `worker_stale` | See at a glance what is unconfigured or broken |
| Worker | State `ok` or `stale`, last heartbeat, 30-second heartbeat, stale after 5 minutes, live worker count (the same rule as `/healthz` and the red page banner) | Confirm a restart of `worker` took effect |
| Queue | Queued, running, paused and failed-in-24-hours job counts; last finished job per type; last scheduled runs | Spot a saturated worker or a failing schedule |
| SMTP | Consecutive delivery failures, the newest error, the last successful delivery and the newest test send (status, time, steps) | Prove the relay works after a change, and see why alerts stopped |
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

## 10. Alerts, digest and scanning

This release observes what the registered endpoints actually serve and mails about it. Mail delivery,
the expiry check, the digest, the scan and the trust recheck run on the worker; the web interface only
queues that work and shows the result. Endpoint administration is the exception: adding an endpoint,
setting its expectation and activating or deactivating it are committed synchronously by the web
request together with their audit rows (section 10.4), so the change is visible as soon as the form
returns.

### 10.1 SMTP relay and the test e-mail

The relay is configured in **Settings → SMTP** (admin only, audited, no secret values on the page):

| Field | Note |
| --- | --- |
| Host | empty means SMTP is not configured (`smtp_not_configured`) |
| Port | 1–65535; empty uses the default for the security mode: 587 STARTTLS, 465 SSL/TLS, 25 None |
| Security | STARTTLS, SSL/TLS or None |
| From address | the envelope and `From:` sender |
| Username | optional; AUTH is attempted only when this **and** `smtp_password` exist |
| Verify the SMTP server's TLS certificate | leave on; see the warning below |

Steps:

1. If the relay needs authentication, put the password the relay issued into
   `/etc/cert-dashboard/secrets/smtp_password` with your normal secret process (written straight into
   the file, never echoed, `umask 077`), apply the canonical owner and mode, and mount it through the
   credentials override:

   ```sh
   sh scripts/install-secrets.sh /etc/cert-dashboard/secrets
   docker compose -f docker-compose.yml -f docker-compose.credentials.yml up -d worker
   ```

   The password is typed nowhere else: it lives only in that `0400 10001:10001` file, is read once by
   the worker and is never displayed, stored in the database or written to a log.
2. Fill in the tab, save, then optionally set `DASHBOARD_URL` for the worker (section 2.3) so mail
   links are absolute.
3. Click **Send test email**. The web process queues an `alert_expiry/smtp_test` job for the signed-in
   user's address and reports the outcome on the same tab: status, finish time and the SMTP
   conversation as an ordered list of step names and reply codes (`connect 220`, `ehlo 250`,
   `starttls 220`, `auth 235`, `mail 250`, `rcpt 250`, `data 250`) — or a fixed failure such as
   `451 at rcpt`, with the steps it reached appended
   (`535 at auth; connect 220, ehlo 250, starttls 220, auth 535`). A test send is never retried and
   writes no delivery record.
4. Turn on the alerts and the digest (10.2), then watch the first real mail arrive.

Rules the transport enforces, so you do not have to guess:

- **AUTH only over TLS.** A username with Security *None* is refused before anything is sent
  (`smtp_not_configured`); a STARTTLS server that does not offer the extension fails with
  `smtp_tls` instead of falling back to plaintext.
- **Code-only errors by design.** Outcomes are a fixed step name plus the numeric reply code; the
  dashboard never keeps the relay's reply text, exception text or AUTH challenge — a relay that echoes
  a credential cannot leak it. Quote those codes in tickets; they are all you get, and that is
  intentional.
- **No automatic retry for permanent failures.** Only 4xx/timeouts/disconnects retry. `5xx`, AUTH and
  TLS failures are reported once and left for you to fix.
- **`smtp.tls_verify=false` is unsafe.** Settings shows "unsafe: TLS certificate verification disabled
  — mail credentials and content can be intercepted." and **Settings → Status** raises
  `smtp_tls_unverified`. Use it only to get out of a broken relay-certificate situation, then turn it
  back on.
- **Delivery is at-least-once.** The ledger row is locked while the message is sent; a worker crash in
  the narrow window between the relay accepting the mail and the row being committed can resend that
  one message on the retry. A rare duplicate needs no action.

### 10.2 Recipients, thresholds and the daily schedule

**Settings → Alerts** holds the policy: *Alert thresholds (days before expiry)* (default
`60,30,14,7,1,0`; 1–10 distinct values, 0–365), *Recipients* (one address per line, at most 50),
*Send the daily digest* and *Run the daily expiry check*. The certificate's own owner e-mail is put
first and the team list follows, deduplicated; a certificate with no owner uses the team list, and with
no recipient anywhere the attempt is recorded as `no_recipients` instead of being lost silently.

One mail is sent per certificate per run, at the smallest threshold it has crossed, and only once per
certificate and threshold: reruns, queue retries and the next day do not repeat it, apart from the rare
at-least-once duplicate described in 10.1. The first digest
after installation covers the previous 24 hours; later ones start at the previous digest's send time.

The schedules are UTC and changed in **Settings → Schedule** and **Settings → Scanning**:

| What | Default | Setting | Switch |
| --- | --- | --- | --- |
| Endpoint scan and background trust recheck | 02:00 | `scan.daily_at` | `scan.enabled` ("Run the daily scan") |
| Expiry check | 07:00 | `expiry_check.daily_at` | `expiry_check.enabled` ("Run the daily expiry check") |
| Daily digest | 07:30 | `digest.daily_at` | `alert.digest_enabled` ("Send the daily digest") |
| Retention cleanup | 04:00 | `cleanup.daily_at` | `cleanup.enabled` |

To stop the mail temporarily, clear *Send the daily digest* / *Run the daily expiry check*; to stop
scheduled scanning (and the trust recheck with it) clear *Run the daily scan*. Manual **Scan now** /
**Scan all** keep working with the schedule off. Clearing the recipient list does not stop the jobs and
does not silence expiry mail: those alerts still go to each certificate's owner e-mail, and only a
certificate with no owner is recorded as a `no_recipients` row (not sent, not retried). The digest has
no owner fallback, so with the list empty each digest run is a failed `no_recipients` row — visible in
**Settings → Alerts** and counted in **Settings → Status** — instead of a delivered mail.

The digest is sent **even when it has nothing to report** ("Nothing to report. This mail is the daily
heartbeat of the alerting path."), so a missing digest means a delivery or schedule problem, not an
empty inventory. A second successful run on the same UTC day sends nothing.

### 10.3 Reading delivery signals

| Question | Where to look |
| --- | --- |
| Is the relay working now? | **Settings → SMTP → Send test email**, then the outcome on that tab; **Settings → Status → SMTP** repeats the newest test send |
| Why did alerts stop? | **Settings → Status → SMTP** (consecutive failures, newest error, last success) and the `smtp_failing` warning |
| Which messages failed, and will they retry? | **Settings → Alerts** lists the newest 50 failed notifications with attempts (`attempt 1 of 3`) and the next attempt time |
| What did the digest report? | The digest mail itself; **Overview** status strip shows **Last digest** |
| Full delivery history | `docker compose exec -T db psql -U db_owner -d cert_dashboard -c "SELECT kind, status, attempts, sent_at, last_attempt_at, next_attempt_at, error FROM notification_log ORDER BY created_at DESC LIMIT 20"` |

Retries are automatic only for transient failures (connection refused or reset, timeout, 4xx reply).
An expiry row is retried within the UTC day it was created (after 30 s, then 120 s) and then stays
`failed`; the next UTC day's evaluation creates a new row. A digest retries the whole job up to three
attempts. AUTH rejections, TLS verification failures, permanent rejections and `no_recipients` rows (an
ownerless certificate with an empty team list, or a digest with an empty team list) are not retried
automatically: fix the relay or the recipients (10.1), confirm with **Send test
email**, and wait for the next scheduled run — for an expiry row that is the next UTC day's
evaluation, for the digest the next day's 07:30 job. Failures keep showing in the digest's *Failed
notifications in the last 24 hours* section and in **Settings → Status** until they age out.

### 10.4 The Scans screen

**Scans** (`/scans`) is the home of endpoints — the `host:port` (+ optional SNI) pairs whose
certificate the dashboard observes.

- The list shows endpoint, SNI, server, expected and observed certificate, observed expiry, status,
  last check and actions. Filters: status, server, certificate, Ansible group, free-text host/SNI
  search, active/inactive; sorts and 1–100 rows per page are in the query string, so a view is
  bookmarkable. **Export list as JSON** writes the allowlisted row fields (at most 5,000 rows).
- **Statuses:** `ok` (served certificate equals the expectation), `mismatch` (a certificate is served
  but differs — an endpoint with no expectation reports `mismatch` until you set one), `expired`
  (the served certificate is past `not_after`), `unreachable` (connect/DNS/timeout), `error`
  (handshake/protocol/parse), or "not scanned". Ordering puts `expired` first, then `mismatch`,
  `unreachable`, `error`, never-scanned and `ok`.
- **Scan now** (per row) and **Scan all** only queue work: the web process never opens a connection to
  the target, the worker does it (20 in flight, `scan.timeout_seconds` per endpoint, 10 s by default).
  An endpoint that stays unreachable is retried alone, up to three attempts, and never blocks the rest.
- **Add endpoint** takes host, port, SNI (empty = the host), and optionally an expected certificate.
  The host must be a DNS name or IP literal and the port 1–65535; entering an existing endpoint
  identity tells you which row already holds it. The endpoint is written and audited immediately;
  no job is queued. Setting an expectation or activating/deactivating works the same way, so the
  management forms are synchronous — only **Scan now** and **Scan all** queue worker jobs.
  Endpoints are deactivated, never deleted, so their history stays.
- **History** opens the last 20 results of one endpoint. The detail page explains a mismatch with the
  expected and observed certificate and the three usual actions: renew and deploy the certificate,
  import the served certificate from this endpoint (prefilled `/certificates/import`), or update the
  expectation.
- **Set expectation** picks an active certificate from the inventory; *use the observed certificate*
  is offered when the served fingerprint is already in inventory, and otherwise points at the import
  form. Changing an expectation never rewrites past results.
- The certificate detail page has an **Endpoints** panel: every endpoint expecting that certificate,
  with a per-endpoint **Scan now**, a link to its history and an **Add endpoint** button prefilled with
  the certificate.

Scan history is kept for 90 days (`SCAN_RESULT_RETENTION`, removed by the daily cleanup); the endpoint
row and its current status are kept indefinitely.

### 10.5 Servers and Bindings before discovery exists

**Servers** (`/servers`, `/servers/{id}`) and **Bindings** (`/bindings`) are read-only views of the
`server` and `binding` tables: hostnames, Ansible groups, web server, binding counts, last discovery
state, mismatched endpoint counts; per binding the vhost, config and certificate/key/chain paths, the
file owners and octal modes, the on-disk fingerprint, the matched certificate and the match state.
`/bindings/help` explains `key_mismatch` and `missing_file` and states that the dashboard does not fix
them. Both exports omit free-text notes and key material.

This release ships **no discovery job**, so nothing fills those tables: on a fresh installation the
screens are empty, and *Run discovery* / *Last raw dump summary* are disabled with
`handler discover/default not registered (Plan 3)`. Servers and bindings arrive with Plan 3's discovery;
until then endpoints (added by hand on **Scans**, or upserted by a pull import) are how TLS is observed,
and the Overview's unknown-certificate and key-mismatch counters stay at zero unless rows were loaded
outside the application.

### 10.6 Overview slots

The Overview keeps the expiry buckets and adds four read-only slots: **TLS health** (endpoint counters
with links to the matching Scans filters, unknown certificates and key-mismatched bindings linked into
the bindings view), **Recent jobs** (the newest ten with type, summary, status, duration, actor and a
link to the audit trail; pull imports link to their progress page), **Renewals in flight** (renewals in
`draft`, `csr_generated`, `submitted`, `issued` or `deployed`, oldest first, with their age in days) and
the **status strip** (worker state and heartbeat, the inventory revision or "no inventory revision
recorded yet", and the last digest time).

### 10.7 Discovery, deployment and the rest of the operational surface

Plan 3 adds discovery, deployment and *Test pull*; sections 11 and 12 below are their operations
manual and the first-installation acceptance runbook. Everything in section 10 (alerts, digest,
scanning) keeps working unchanged.

## 11. Discovery and deployment

Discovery reads every TLS binding of the inventory's nginx and Apache servers through read-only Ansible
runs; deployment writes issued certificates host-atomically, canary first, with drift protection, a
config test, an on-target verification and an automatic per-host rollback. `web` only reads the
database and enqueues jobs: every Ansible, Git and SSH connection is made by `worker`.

### 11.1 The inventory (Settings → Inventory)

Four settings, all validated on save and all audited (`settings.update`):

| Field | Meaning |
| --- | --- |
| **Repository URL** (`inventory.repo_url`) | `https://host/path`, `ssh://[user@]host/path` or `user@host:path`. No password, token or secret-looking path segment is accepted |
| **Ref** (`inventory.ref`) | Branch, tag or commit; empty = the remote's default branch |
| **Path inside the repository** (`inventory.path`) | Where the Ansible inventory lives, relative and without `..`; empty = the root |
| **Web server variable** (`inventory.webserver_var`) | Inventory variable holding `nginx`/`apache` (default `webserver_type`); absent = auto-detected on the host |

**Test pull** (`Settings → Inventory → Test pull`) runs the whole inventory preparation and
`ansible-inventory --list` **without touching any server**: it shows the resolved revision, the revision
date, the host and group counts and how long the pull took. It is the first thing to press after a
credential change. The button is disabled — with the reason on the tab — while no live worker has
`ansible_ssh_key` or while the repository URL is empty.

The worker keeps a read-only checkout under its `inventory_root` (`/srv/inventory` in the image). Every
`discover`/**Test pull** job refreshes it by fetching into a private ref and only then resetting the
work tree, so a failed fetch never leaves a half-updated checkout; a pull inside 60 s of the previous one
is skipped, and a pull failure keeps the last good revision while that revision is younger than 24 hours
(the job then reports `inventory_warning`). Discovery and deploy results carry `inventory_rev` (40-hex
commit) and `inventory_rev_date`, which is what the Overview's status strip and the digest show.

**Schedules.** *Settings → Schedule* holds `discovery.nightly_at` (default 02:00) and
`discovery.enabled`. The nightly discovery runs the whole inventory at priority 100. On demand:

- **Servers → Discover all** (`POST /servers/discover`, `scope=all`) — the whole inventory, priority 200;
- **Servers → a server → Discover** (`POST /servers/{id}/discover`) — one host;
- **Servers → Discover by group** — one inventory group.

A per-host or per-group discovery needs the `server` row, and only a discovery creates one: on a brand-new
installation the first run is **Discover all** over a one-host inventory, and the remaining hosts are added
afterwards (the staging in section 12.1/12.2). A discovery always syncs the whole inventory into `server`
rows but connects only to the hosts its scope selects.

Discovery and deployment share two worker slots with scans and are claimable only by a worker that has
`ansible_ssh_key` (without it the screens show "Discovery and deploy are unavailable: the worker has no
ansible_ssh_key" and the buttons are disabled). A discovery is read-only: it writes no file on the host
and only becomes `become` to read root-owned configuration, certificates and keys.

### 11.2 Worker credentials (the compose override)

The worker reads these from secret files; mount them with `docker-compose.credentials.yml` (section 2.3)
after provisioning them under `/etc/cert-dashboard/secrets/`:

| Secret / mount | Purpose |
| --- | --- |
| `ansible_ssh_key` | The private key Ansible, `git` and `ssh` use. Passed to the child processes as a `0600` file in `key_staging_dir` (`/run/cert-keys`, tmpfs) and removed in `finally` |
| `known_hosts` → `/etc/ssh/ssh_known_hosts` (`SSH_KNOWN_HOSTS`) | Pinned host keys for the managed servers. A missing file fails every `discover`/`deploy` with `config_invalid` **before** any connection |
| `ansible_vault_password` (optional) | Vault password for vaulted inventory files. Reaches Ansible as `CERT_DASHBOARD_VAULT_PASSWORD` plus `ANSIBLE_VAULT_PASSWORD_FILE` pointing at `app/ansible/vault_client.py`, which prints it and exits non-zero when it is missing |
| `inventory_git_token` (optional) | HTTPS Git token. Reaches `git` as `CERT_DASHBOARD_GIT_TOKEN` through `app/ansible/git_askpass.py` (user `x-access-token`), with `GIT_TERMINAL_PROMPT=0` and an empty credential helper, so nothing lands in `.git/config` |
| `smtp_password` (optional) | Relay AUTH password for alerts and the digest (section 10.1) |

The `ANSIBLE_SSH_ARGS` value in `docker-compose.credentials.yml` **is no longer read**: the runner builds
the child environment from scratch and sets its own, stricter value
(`-o StrictHostKeyChecking=yes -o UserKnownHostsFile=<known_hosts> -o IdentitiesOnly=yes -o BatchMode=yes
-o ControlMaster=auto -o ControlPersist=60s`). Change host key checking in `/etc/ssh/ssh_known_hosts`,
never in that variable. Keep `ANSIBLE_HOST_KEY_CHECKING=True` as a harmless second belt.

The web process never sees any of these files.

### 11.3 The dedicated user and its sudo rule on the targets

Every managed server needs one unprivileged user (the harness uses `cdeploy`, uid 2000, locked password,
home `/home/cdeploy`) whose `authorized_keys` holds the public half of `ansible_ssh_key`, plus a sudo rule
that lets it write certificate material, back it up, run the config test and reload the service. The
baseline this release is tested with is `/etc/sudoers.d/cdeploy` `0440 root:root`:

```
cdeploy ALL=(root) NOPASSWD: ALL
```

A stricter allowlist is possible because the playbook only runs these commands as root (absolute paths
depend on the distribution; check them with `command -v`):

```
Cmnd_Alias CDREAD  = /usr/bin/stat, /usr/bin/openssl, /usr/bin/sha256sum, /usr/bin/find
Cmnd_Alias CDWRITE = /usr/bin/mv -f -- *, /usr/bin/cp -- *, /usr/bin/install *, /usr/bin/chmod *, /usr/bin/chown *, /usr/bin/mkdir *, /usr/bin/rm -f -- *
Cmnd_Alias CDSVC   = /usr/sbin/nginx -t, /usr/sbin/nginx -s reload, /usr/sbin/apachectl configtest, /usr/sbin/apachectl graceful
Cmnd_Alias CDSEL   = /usr/sbin/restorecon -F -- *
cdeploy ALL=(root) NOPASSWD: CDREAD, CDWRITE, CDSVC, CDSEL
```

Reads of configuration, certificates and keys go through the Ansible connection itself (the `become` is
what lets it read `0600` key files), so the allowlist above covers the writes, the service control and the
SELinux relabel. Whatever the rule is, verify it before the first discovery with the commands in
section 12.

### 11.4 The deploy flow

1. **Certificate detail → Deploy** (or **Deploy** in the navigation). The start screen lists issued
   renewals first, then the keyed active certificates. Choose the certificate and, optionally, a group, a
   host, individual bindings (`include_unknown` for `unknown` bindings, audited), a batch percentage, a
   canary, a *not before* time and the pause after the canary.
2. The preview is advisory and computed from the database (§6.6): per host and per binding it shows the
   identity on disk (common name, fingerprint, expiry) against the identity that will be written, the
   batch plan and the writes (`write cert`, `write chain`, `write key`). It carries `plan_sha256`.
3. **Start deploy** must repeat the plan hash and the confirmation sentence naming the host count and the
   canary hostname; a changed plan re-renders the preview with a 422 instead of starting.
4. Guardrails refuse a start (each with its reason on the screen): no key or an unknown key version, an
   expired or not-yet-valid or revoked certificate, no target, every binding already on the new
   fingerprint, an active deploy (`queued`, `running` or `paused`), and a chain that is not `trusted` at
   the current time unless the operator supplies a reason (audited as `deploy.chain_override`; the
   override never bypasses key, validity, drift or config-test checks).
5. The canary runs first. With *pause after canary* the job releases its claim, its slot and its locks and
   waits — but only when another host is still `pending`: a selection that reduces the rollout to the canary
   alone has no later batch, runs to completion and never pauses (a one-host job cannot be Continued).
   **Continue** re-checks the trust gate and every host's drift, **Cancel** stops it; a forgotten pause is
   cancelled automatically after `deploy.pause_timeout_hours` with `deploy.pause_expired`. The
   remaining batches run `deploy.concurrency` hosts at a time; the first failed host stops the rollout and
   the hosts that were never started become `skipped` (`rollout_stopped`).
6. Hosts whose `deploy:<hostname>` lock is taken are `skipped`, not failed, and never stop the rollout.
   Per-host timeout `deploy.host_timeout_seconds` (default 600).
7. A deploy is never retried automatically. **Retry host** on a `failed`, `rolled_back` or `skipped` host
   creates a *new* canary-only job for that host's bindings; it needs a reason and is audited as
   `deploy.retry_host`. The renewal becomes `deployed` only after a **succeeded** job with at least one
   succeeded binding row carrying the new fingerprint.

Reading a failed host's report: the job screen (`/deploy/{job_id}`) shows the host row with its status
(`succeeded`, `rolled_back`, `failed`, `skipped`), the `reason` (`drift_detected`, `verify_failed`,
`config_test_failed`, `permission_denied`, `insufficient_space`, `key_mismatch_preflight`,
`backup_failed`, `write_failed`, `reload_failed`, `unreachable`, `auth`, `host_timeout`, `binding_blocked`,
`not_in_inventory`, `file_conflict`, `internal`), `rollback_error`, `needs_attention` (a failed rollback
or a host timeout) and the backup directory. **Download report** (`/deploy/{job_id}/report.json`) is the
allowlisted per-host JSON; the raw log excerpt stays on the worker's artifacts volume
(`<artifacts>/<job_id>/run`, `0600`, 30 days) and is not served to the browser.

### 11.5 Manual recovery on a host

Every host write is preceded by a backup under `/var/backups/cert-dashboard/<job_id>/<absolute path>`
(the directory tree `0700 root:root`, key backups `0600`, certificate backups `0644` or stricter, with a
`manifest.json`). To recover a host by hand:

```sh
job=<job_id from the job screen>
find "/var/backups/cert-dashboard/$job" -type f | sort          # what was saved, mirrors the absolute path
install -m 0600 -o root -g root "/var/backups/cert-dashboard/$job/etc/nginx/ssl/www.key" /etc/nginx/ssl/www.key
install -m 0644 -o root -g root "/var/backups/cert-dashboard/$job/etc/nginx/ssl/www.crt" /etc/nginx/ssl/www.crt
nginx -t && nginx -s reload                                     # apache2ctl configtest && apache2ctl graceful
```

Then run **Servers → that host → Discover** so the dashboard's view matches reality again. Backups are
pruned by the next successful host run, keeping the newest backup of each path:
`deploy.backup_retention_days` (default 30, `0` = keep forever). Removing one directory by hand is safe
once the deploy is confirmed.

### 11.6 How the checks work (D1, D2, D3) and what to look at on a host

**Chain files are classified by verifying content, never by position (D1).** Each certificate file is
parsed on its own: a file with one certificate is a leaf candidate; a file with several is a bundle whose
first certificate is the leaf and whose later ones are a chain **only if** each one verifies the previous
signature (`issuer`/`subject` **and** the signature, never the names alone); a separate file is the chain
of a leaf only if it really signs that leaf. When the verification is impossible (unreadable file,
incomplete chain, missing issuer) the file is not treated as a chain, stays a certificate of its own, and
the binding shows the incomplete-chain diagnostic. Consequences an operator sees: an nginx binding carries
the **full chain in `cert_path`** and no chain file; an Apache binding with a verified
`SSLCertificateChainFile` carries that path, and the deploy writes the leaf alone to `cert_path` and the
chain to the chain file.

**Key hashes are DER, not PEM (D2).** `on_disk_key_public_sha256` and `private_key.public_key_sha256` are
the SHA-256 of the DER `SubjectPublicKeyInfo`, lowercase hex. To reproduce the comparison on a host, for
the certificate's public key:

```sh
openssl x509 -in /etc/nginx/ssl/www.crt -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
```

and for the private key (as root, on the host, without printing the key):

```sh
openssl pkey -in /etc/nginx/ssl/www.key -pubout -outform DER | sha256sum
```

The two digests must be identical; that value is what the dashboard shows on the binding after a
discovery. A binding is `matched` only when the certificate fingerprint **and** this hash agree.

**TLS directives are read inline and from includes (D3).** nginx is read from `nginx -T`, which already
concatenates every `include`. Apache is read as the union of the files `apachectl -S` names, the main
configuration and a recursive expansion of `Include`/`IncludeOptional` (globs sorted, a directory means
every file below it, cycles cut by real path, depth ≤ 16), and the parser attributes every directive to
the enclosing `<VirtualHost>` even when the directive sits in a file included inside that block. The limits
are 500 files and 16 MiB per host: a host whose dump exceeds them fails with **`dump_too_large`** (the job
row's reason) instead of being silently truncated — split the configuration or exclude the host until it
is under the limit. A global-level TLS directive (outside every vhost) is applied as the default server's
binding on the HTTPS `Listen` port.

**No secret reaches an artifact.** The vault password and the Git token exist only in the child
environment, the SSH and TLS keys only as `0600` files in the tmpfs staging directory, and every stored
text passes the redactor. `tests/integration/test_acceptance.py` searches every artifact and run file of a
full run for the vault password, the SMTP password, the PFX passwords, the `PRIVATE KEY` header and the
staged key bytes.

## 12. "§10.4 acceptance on real hosts" runbook

This is the checklist for the **first real installation**, to be executed against real hosts by the
operator. The automated suite (`tests/integration/test_acceptance.py`) runs the same checklist against
containerised targets with a fixture CA; it proves the code paths but **does not replace this runbook**,
and nothing in this repository claims that the production run below has happened. Record the evidence in
the table at the end of the section and keep it with the installation.

### 12.1 Prerequisites on the target hosts

1. **OS packages**: `openssh-server`, the webserver (`nginx` or `apache2` with `a2enmod ssl`), `sudo`,
   `python3`, `openssl`, `procps` (`pgrep`), `git` where the host also serves the inventory,
   `policycoreutils` only where SELinux is enforcing (`restorecon` is probed and skipped when absent).
2. **Service user and deploy key.** The private key is a secret: create and keep it **outside the repository
   checkout**, in the root-only secret directory of section 2.1, and transfer only its **public half** to the
   targets. As root on the dashboard host:

   ```sh
   install -d -m 0700 /root/cert-dashboard-keygen
   ssh-keygen -t ed25519 -a 100 -N '' -C cert-dashboard-deploy -f /root/cert-dashboard-keygen/ansible_ssh_key
   install -m 0400 -o 10001 -g 10001 /root/cert-dashboard-keygen/ansible_ssh_key /etc/cert-dashboard/secrets/ansible_ssh_key
   install -m 0644 -o root -g root /root/cert-dashboard-keygen/ansible_ssh_key.pub /etc/cert-dashboard/ansible_ssh_key.pub
   shred -u /root/cert-dashboard-keygen/ansible_ssh_key
   shred -u /root/cert-dashboard-keygen/ansible_ssh_key.pub
   rmdir /root/cert-dashboard-keygen
   sh scripts/install-secrets.sh /etc/cert-dashboard/secrets    # re-asserts the canonical owners and modes
   ```

   `/etc/cert-dashboard/secrets/ansible_ssh_key` is what `docker-compose.credentials.yml` mounts into the
   worker (read-only, UID 10001); the private key never appears in the checkout, in a compose file or in a
   `.pub` next to it. Only the public file `/etc/cert-dashboard/ansible_ssh_key.pub` leaves the dashboard
   host. On every target, as root:

   ```sh
   useradd --create-home --shell /bin/bash --uid 2000 cdeploy
   passwd -l cdeploy
   install -d -m 0755 -o root -g root /etc/ssh/authorized_keys
   install -m 0644 -o root -g root ansible_ssh_key.pub /etc/ssh/authorized_keys/cdeploy   # the copied public half
   ssh-keygen -lf /etc/ssh/authorized_keys/cdeploy                                        # compare with the public key you copied
   ```

   `sshd` must accept it: `PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
   `PermitRootLogin no`, `AuthorizedKeysFile /etc/ssh/authorized_keys/%u`.
3. **sudo rule** exactly as in section 11.3 (`/etc/sudoers.d/cdeploy`, `0440 root:root`), validated with
   `visudo -cf /etc/sudoers.d/cdeploy`.
4. **`known_hosts` built from host keys verified out of band.** Never trust `ssh-keyscan` alone: an
   attacker who answers first would be pinned forever. Read each host key from the console, the hypervisor
   or the configuration management system and compare it with the host's own
   `/etc/ssh/ssh_host_ed25519_key.pub`. The entry must name the address SSH **connects to**, not the
   inventory hostname: with the inventory below the worker runs `ssh cdeploy@10.0.0.11` on port 22, so the
   entry is the bare address. A bracketed `[10.0.0.11]:22` would never match — OpenSSH brackets the
   address only for a non-default port — and the first discovery would fail closed with `auth`.

   ```sh
   ssh-keyscan -t ed25519 -p 22 10.0.0.11              # candidate only: compare it byte for byte
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub    # on that host, out of band
   printf '10.0.0.11 ssh-ed25519 %s\n' "<verified key>" >> /etc/cert-dashboard/known_hosts
   ssh-keygen -F 10.0.0.11 -f /etc/cert-dashboard/known_hosts     # must print the entry and exit 0
   ```

   A host reached on a non-default port (`ansible_port: 2222`) is written `[10.0.0.11]:2222` and looked up
   the same way; pin the bare inventory hostname only for a host with **no** `ansible_host`, because that
   is the address the worker then connects to.

   **The inventory Git remote is a second address.** The worker fetches the repository with the same key
   and the same file (`git_environment()` in `app/services/inventory.py` sets `GIT_SSH_COMMAND` with
   `StrictHostKeyChecking=yes`), so pin the Git server too: for
   `ssh://cdeploy@10.0.0.5:2222/srv/inventory.git` the entry is `[10.0.0.5]:2222`, and the bare `10.0.0.5`
   when it listens on 22. An `https://` repository needs no entry; TLS verifies it. Install the file
   root-owned `0644`, mount it at `/etc/ssh/ssh_known_hosts` (section 11.2), then prove every lookup and
   one real connection before the first discovery:

   ```sh
   ssh-keygen -F 10.0.0.11 -f /etc/cert-dashboard/known_hosts          # a target, default port
   ssh-keygen -F '[10.0.0.5]:2222' -f /etc/cert-dashboard/known_hosts   # the Git remote, port 2222
   ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
       -o UserKnownHostsFile=/etc/cert-dashboard/known_hosts \
       -i /etc/cert-dashboard/secrets/ansible_ssh_key cdeploy@10.0.0.11 true
   ```
5. **Inventory repository** (a static Ansible inventory, one file per host or one `hosts.yml`). The
   **first committed revision lists one host only** — that is what makes the first discovery read-only:

   <!-- runbook:first-inventory -->
   ```yaml
   all:
     hosts:
       web01.example.internal:
         ansible_host: 10.0.0.11
         ansible_user: cdeploy
         webserver_type: nginx          # or apache; omit to auto-detect
     children:
       canary_ring:
         hosts:
           web01.example.internal: {}
   ```

   Nothing else may be in this revision: no second host under `all.hosts`, no second host in any group's
   `hosts` (`host_vars/` and `group_vars/` can add variables but never a host). Test pull counts every
   member of `all`, group children included (`app/services/inventory.py`), so a stray group host silently
   widens the first discovery. `tests/integration/test_operations_docs.py` lists this exact block with the
   worker's own `ansible-inventory --list` and asserts one host; `web02` and `web03` arrive in the second
   commit of step 9.

   Hostnames are inventory names, `ansible_host` is the address the worker connects to (the one the
   `known_hosts` entry of item 4 must name), and the groups drive the canary and the batches. Add vaulted
   group variables only if the playbooks need them.

   **Start the repository with only the first host** and add the rest in step 9. A discovery always syncs
   the *whole* inventory into `server` rows but connects **only to the hosts in its scope**
   (`app/jobs/handlers/discover.py`), and **Servers → a server → Discover** needs that row to exist — for
   an unknown hostname `app/web/servers.py` answers 404. A per-host discovery is therefore impossible
   before the very first run, and **Discover all** over the full inventory would already connect to every
   host, which is exactly what the one-host read-only check must rule out. With a one-host inventory,
   **Discover all** is that narrow, read-only run.
6. **Section 2 completed**: secrets provisioned (2.1), schema migrated (2.2 step 2), the first
   administrator created **once** (2.2 step 3), 2FA enrolled (2.2 step 5), the compose credentials
   override installed and `web` and `worker` running:
   `docker compose -f docker-compose.yml -f docker-compose.credentials.yml up -d web worker`. This
   acceptance starts from that installed state and never re-runs the one-time `bootstrap-admin`: on an
   initialized database it exits nonzero and creates nothing.
7. A **test host** of each webserver type you will manage, holding a copy of a real vhost and a real
   certificate/key pair, reachable from the dashboard host on the webserver's TLS port.

### 12.2 Ordered steps, commands and expected results

Steps 1–3 verify the administrator and the 2FA that section 2 created; the one-time `bootstrap-admin` is
not repeated (§12.1 item 6). Steps 6–9 stage the inventory on purpose: the repository lists **one** host for
the read-only check and the rest are added once that check passed (the reason is in 12.1 item 5).
Everything after step 9 needs the full inventory.

| # | Step | Command / action | Expected result |
| --- | --- | --- | --- |
| 1 | Administrator carried from §2.2 step 3 | open `/login`; do **not** re-run `bootstrap-admin` (on an initialized database it exits nonzero and creates nothing) | no bootstrap form on `/login`; the admin created in §2.2 step 3 signs in — its `user_id` is the bootstrap evidence. If this acceptance runs on a fresh database *before* §2.2 step 3, create the admin there **once** and record `created admin user_id=...` |
| 2 | 2FA carried from §2.2 step 5 (enrol here only if it was skipped) | **Account**: either confirm *Two-factor authentication is enabled*, or **Set up two-factor authentication** and confirm with a code | enabled; the recovery codes are shown once — store them |
| 3 | Log out, log back in with 2FA | browser | the second factor is asked and the dashboard opens |
| 4 | SMTP | **Settings → SMTP** (host, port, security, from, optional username), **Send test email** | the relay answers and the message arrives; the tab shows the step list and reply codes |
| 5 | Expiry alert for a certificate 7 days out | issue (or pick) a certificate whose `notAfter` is 7 days away and import it with **Certificates → Import**, format **PEM**, pasting the certificate (public part only); **Settings → Alerts**: at least one recipient, a threshold list containing 7 (default `60,30,14,7,1,0`) and *Run the daily expiry check* ticked; **Settings → Schedule**: set *Expiry check* a few minutes ahead (UTC) | the next scheduler tick (≤ 30 s) enqueues `alert_expiry`; the recipient receives `Certificate <CN> expires in 7 days` and **Settings → Alerts** records the delivery; set the schedule back to 07:00 |
| 6 | Inventory, **first host only** | **Settings → Inventory**: URL, ref, path, web server variable → save, then **Test pull** | resolved revision, revision date, **hosts 1** and the group count; Test pull creates no `server` row, which is why the repository starts with one host |
| 7 | Read-only discovery of **one** host | `touch /tmp/before` on the host, then **Servers → Discover all** (the inventory holds only this host, so the job contacts only it) | the server and its bindings appear; `find /etc /var/backups -newer /tmp/before` on the host prints **nothing** |
| 8 | Spot-check against reality | on the host, the command of §12.2.3 for the webserver that host runs (nginx **or** Apache, never both roots in one command) | every certificate, chain and key path printed is a path **Bindings** shows for that server and no binding path is missing — included files and chain files included (D1, D3) |
| 9 | Full inventory (second commit) | add the remaining hosts as in §12.2.1, commit and push, wait **≥ 60 s after the previous pull** (the worker skips a pull inside 60 s of the last one, §11.1), then **Settings → Inventory → Test pull** and **Servers → Discover all** | Test pull reports **hosts 3** and 2 groups and the revision follows the repository (inside the 60 s window it still reports the first revision — wait and press again); every host `ok`, `bindings_added` > 0 for the new hosts, no `parse_suspected`, no `dump_too_large` |
| 10 | Import a real certificate + key | **Certificates → Import** (PFX with its password, or PEM plus its key) | the detail page shows the key and the chain; `key.import` is audited without key material |
| 11 | Rediscover, then check `matched` (D2) | **Servers → the host that serves that certificate → Discover** (or **Discover all**) | its bindings become `matched`, each with `on_disk_key_public_sha256` equal to the key's `public_key_sha256` (DER, section 11.6); the match state is computed *by discovery*, so right after the import the bindings still show the previous state |
| 12 | Export it again and compare | detail → **Export PFX** (re-enter your password, choose an export password) | the exported PKCS#12 opens and carries the same leaf and public key (`openssl pkcs12 -in export.pfx -nokeys -info`) |
| 13 | Trust | **Settings → Trust anchors**: upload the issuing root | the tab reports the chain recheck and the certificate's chain status becomes `trusted`; if it does not, press **Recheck** and wait for the job |
| 14 | Renewal end to end | **Certificates → detail → Renew**: generate the CSR, download it, order at the CA portal, paste/upload the issued certificate and chain | the renewal reaches `issued`; the new certificate has a key and `renews_id` pointing at the old one |
| 15 | First deploy, canary first | **Deploy**: choose the issued renewal, tick the bindings of **at least two hosts** (a one-host job has no later batch and never pauses), designate the canary host, batch 100%, **pause after canary** on → **Start deploy** | the canary host `succeeded`, the job is `paused`, and the canary serves the new certificate (`openssl s_client -connect <canary>:<port> -servername <vhost> \| openssl x509 -noout -fingerprint -sha256` equals the certificate's SHA-256 fingerprint) |
| 16 | Continue | **Continue** on the job screen | the remaining hosts run; the job is `succeeded`; the renewal is `deployed`; after a **Discover all** every deployed binding is `matched`; the digest is clean (no failed job, no rolled-back host, no mismatch) |
| 17 | Forced rollback drill (test host only) | restore the previous certificate and key (`install` from a copy, `nginx -t && nginx -s reload`), **Discover** that host, then run the block of §12.2.2 (it stops the master and always resumes it) and start the deploy of the same certificate **to that host only** (a one-host job finishes without pausing — expected here); press Enter only when the job screen shows `rolled_back` | the host row is `rolled_back` with reason `verify_failed`, `files_restored` true and no `needs_attention`; after the block the master's `ps` state is no longer `T` and the host serves the previous fingerprint |
| 18 | Manual recovery drill | restore one file from `/var/backups/cert-dashboard/<job_id>/…` as in section 11.5, config test, reload, then **Discover** | the binding is `matched` again and the served fingerprint equals the file's |
| 19 | Restore drill | section 4.2: `pg_restore` into a staging database, start a staging stack with the **same** `master_key`, open a certificate, **Export PFX**, then `python -m app.cli verify-key --certificate-id <id>` in a `web` one-shot container | the key decrypts with the same keyring, `verify-key` prints `verified certificate_id=... public_key_sha256=...`, and the PFX opens |

#### 12.2.1 The second inventory commit (step 9)

The first revision listed one host on purpose; this commit adds the other two, and only now may a
discovery contact them:

<!-- runbook:full-inventory -->
```yaml
all:
  hosts:
    web01.example.internal:
      ansible_host: 10.0.0.11
      ansible_user: cdeploy
      webserver_type: nginx
  children:
    canary_ring:
      hosts:
        web01.example.internal: {}
    ring_a:
      hosts:
        web02.example.internal:
          ansible_host: 10.0.0.12
          ansible_user: cdeploy
          webserver_type: nginx
        web03.example.internal:
          ansible_host: 10.0.0.13
          ansible_user: cdeploy
          webserver_type: apache
```

```sh
git -C <inventory working copy> add hosts.yml
git -C <inventory working copy> commit -m 'inventory: add web02 and web03'
git -C <inventory working copy> push
```

Pin `known_hosts` for every new address exactly as in 12.1 item 4 (`ssh-keygen -F 10.0.0.12 -f
/etc/cert-dashboard/known_hosts` and so on) **before** Test pull: an unpinned address fails the discovery
closed with `auth` on that host.

#### 12.2.2 The forced-rollback drill always resumes the master (step 17)

The deploy must see the suspended webserver, and the master must be resumed even if the deploy errors, a
command fails or the operator interrupts the shell. One root shell on the test host wraps the whole drill
in an `EXIT`/`HUP`/`INT`/`TERM` trap and prints the proof at the end:

```sh
master=$(pgrep -o -f 'nginx: master process' || pgrep -o -x apache2)
[ -n "$master" ] || { echo 'no webserver master found' >&2; exit 1; }
resume() { kill -CONT "$master" 2>/dev/null || true; }
trap 'resume' EXIT HUP INT TERM
kill -STOP "$master"
echo "master $master is stopped: start the deploy, wait for rolled_back, then press Enter here"
read -r _ || true                                   # a trapped signal also ends this wait
resume
trap - EXIT HUP INT TERM
ps -o pid=,stat= -p "$master"                        # state must not be T (stopped)
openssl s_client -connect <host>:<port> -servername <vhost> </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256         # the restored certificate
```

If the shell is killed with `SIGKILL` or the session dies, run `kill -CONT "$master"` from any root shell
before doing anything else: the drill is complete only when `ps` shows the master awake. If it is awake but
still serves the deployed certificate, it resumed with a pending reload — `nginx -t && nginx -s reload`
(Apache: `apache2ctl configtest && apache2ctl graceful`), then check the fingerprint again.

#### 12.2.3 The spot-check command (step 8)

Run it on the host, over the config root of the webserver that host runs — never both roots in one
command, because `grep` exits 2 on a directory that does not exist and the output must stay comparable
with the bindings. `-R` (not `-r`) follows the `sites-enabled`/`conf-enabled` symlinks, so a vhost
enabled by symlink is read as well.

nginx (`webserver_type: nginx`):

<!-- runbook:spot-check-nginx -->
```sh
grep -RE '^[[:space:]]*(ssl_certificate|ssl_certificate_key)[[:space:]]' /etc/nginx
```

Apache (`webserver_type: apache`):

<!-- runbook:spot-check-apache -->
```sh
grep -RE '^[[:space:]]*(SSLCertificateFile|SSLCertificateKeyFile|SSLCertificateChainFile)[[:space:]]' /etc/apache2
```

Under `grep -E` the alternation is a bare `|`: an escaped `\|` matches a literal pipe and prints nothing,
which is why `tests/integration/test_operations_docs.py` runs both commands against a fixture nginx tree
and a fixture Apache tree, inline and in an include. `grep` reads the whole tree, so a directive written
in an included file prints exactly like an inline one (D3, section 11.6).

Every printed path must be a path **Bindings** shows for that server, and no binding path may be missing:
nginx prints the certificate — the **full chain** in `ssl_certificate`, never a separate chain file (D1) —
and its key; Apache prints the leaf in `SSLCertificateFile`, the chain in `SSLCertificateChainFile` when
that file really signs the leaf, and the key. Exit 1 means the root holds no TLS directive, which is
correct only for a host that serves no TLS vhost and must then show no bindings; exit 2 means the root
does not exist, i.e. the wrong `webserver_type` for that host. A directive kept outside the config root
(`include /opt/tls/*.conf;`) needs that path added to the command.

### 12.3 Evidence to record

Fill this table during the run and keep it with the installation record. The automated container run in
`tests/integration/test_acceptance.py` produces the same evidence for its fixture CA; it does not fill
this table.

| Item | Value | Operator | Date |
| --- | --- | --- | --- |
| Bootstrap admin `user_id` and 2FA enabled (from §2.2 steps 3 and 5) | | | |
| `known_hosts` lookups verified (`ssh-keygen -F` for every target and the Git remote) | | | |
| Test pull revision (`inventory_rev`), first host only | | | |
| Discovery job id (single host) | | | |
| Bindings vs `grep` spot-check (host, pairs) | | | |
| Test pull revision and host count (full inventory) | | | |
| Discovery job id (full inventory) | | | |
| Expiry drill: certificate, subject, delivered at, threshold | | | |
| Imported certificate id / fingerprint | | | |
| Post-import rediscovery: `matched` bindings, `on_disk_key_public_sha256` | | | |
| Exported PFX fingerprint (public material equal) | | | |
| Renewal id / new certificate fingerprint | | | |
| Deploy job id (canary + Continue) | | | |
| Served fingerprints per host after the deploy | | | |
| Digest result (failed jobs, rolled-back hosts, mismatches) | | | |
| Forced-rollback outcome (`status`, `reason`, `files_restored`, served fingerprint) | | | |
| Forced rollback: master resumed (`ps` state) and served fingerprint after resume | | | |
| Restore drill: restored database, `verify-key` output, PFX export | | | |

A run is accepted only when every row is filled and every expected result above was observed. Any
deviation is a finding: record it, stop the rollout, and keep the job ids — they are the evidence the
review needs.

