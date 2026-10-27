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

This release observes what the registered endpoints actually serve and mails about it. Everything here
runs on the worker; the web interface only queues the work and shows the result.

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
  identity tells you which row already holds it. Endpoints are deactivated, never deleted, so their
  history stays.
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

### 10.7 Not part of this release

The §7.7 inventory refresh is **not** a Plan 2 job: Plan 2 Contract decision 15 defines it as the
preflight of every `discover`/`deploy` job, so it arrives with Plan 3 together with *Test pull*. The
existing pull import (`scan/import_pull`) is unchanged and writes no scan result. Discovery, inventory
revision and deployment are not available in this release; the disabled controls say so, and
`docs/superpowers/plans/2026-10-25-cert-dashboard-plan-3-discovery-and-deploy.md` is the plan that adds
them.
