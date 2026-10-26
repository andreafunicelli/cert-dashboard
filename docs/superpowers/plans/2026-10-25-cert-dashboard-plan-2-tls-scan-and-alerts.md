# Cert Dashboard — Plan 2: TLS Observation, Scanning and Alerts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Observe what every registered TLS endpoint actually serves, persist classified scan results without ever importing or trusting observed certificates, send idempotent expiry alerts and a daily digest over SMTP, and give operators the Scans, Servers and Bindings screens plus the Overview/Settings signals that depend on them.

**Architecture:** The worker gains registered handlers `scan/default`, `scan/trust_recheck`, `alert_expiry/default`, `alert_expiry/smtp_test` and `digest/default`, and daily schedules for the scan, trust recheck, expiry check and digest, all through Plan 1's `JobRegistry`, `register_schedule` and queue primitives. TLS inspection reuses `pull_chain(...)`; SMTP lives only in the worker (the web process never holds `smtp_password` and never opens SMTP or TLS-inspection connections). `notification_log` is the delivery ledger whose row lock and attempt counters make every send idempotent and bounded. New read-only screens are mounted through `create_app` with the existing session/CSRF/error foundation.

**Tech Stack:** Plan 1's stack unchanged (Python 3.12, FastAPI, Jinja2, htmx, SQLAlchemy 2.0, psycopg 3, PostgreSQL 16, pyOpenSSL, cryptography, pytest, Testcontainers, Ruff). Added: stdlib `smtplib`/`email`/`ssl` for delivery (no new runtime dependency); `aiosmtpd` as a **dev-only** dependency for the local SMTP capture server (spec §10.2 names it); pinned `nginx` and `httpd` images as test-only TLS targets in `docker-compose.test.yml`. These are implementation decisions, not quotations from the spec.

**Spec:** `docs/superpowers/specs/2026-10-19-cert-dashboard-design.md` — read alongside this plan; §4 column tables, §7 job/alert rules, §8.6/§8.8 screens and §9 error rules remain normative. Plan 1 (`docs/superpowers/plans/2026-10-19-cert-dashboard-plan-1-core.md`) Global Constraints, Contract decisions and Extension points remain binding.

## Global Constraints

- Plan 1's Global Constraints apply unchanged. **No new migration, table, column, enum value, index or seeded `app_setting` row**: every setting used here already exists in the 32-key allowlist of `app/services/settings.py` (`scan.*`, `expiry_check.*`, `digest.daily_at`, `alert.*`, `smtp.*`, `ui.timezone`, `retention.days`). No change to key handling, crypto, export, `app/crypto/*`, PFX, renewals, or the (Plan 3) deploy path.
- Scan (§7.3): "open a TCP connection to `host:port` with a 10-second connect/read timeout, perform a TLS handshake with SNI = `sni or host`, accept any chain (no verification against trust stores — we inspect, we do not validate trust in v1), take the leaf DER, compute SHA-256". The timeout is `scan.timeout_seconds` (default 10, range 1–60). "Concurrency: 20 in-flight connections in a thread pool"; "A scan job stores one `scan_result` per endpoint and updates `endpoint.last_scan_at`/`last_scan_status`". Target: 500 endpoints in < 10 min.
- Scan status (§4.10/§7.3): `ok` = fingerprint equals the expected certificate; `mismatch` = a certificate is served but differs, **and** an endpoint without an expectation "reports `mismatch` until an expectation is set"; `expired` = served `not_after` < now and takes precedence; `unreachable` = TCP timeout/refused/DNS failure; `error` = handshake/protocol/parse failure. Record TLS version, observed CN/issuer/not_after/chain length and elapsed time.
- Observed certificates are **never** imported, matched into inventory, or trusted. Scans write only `scan_result` rows and `endpoint.last_scan_*`; `certificate.chain_status` changes only through Plan 1's `recheck_chain_statuses`.
- Schedules (§7.1, UTC defaults): endpoint scan `02:00` (`scan.daily_at`, `scan.enabled`), expiry check `07:00` (`expiry_check.daily_at`, `expiry_check.enabled`), digest `07:30` (`digest.daily_at`, `alert.digest_enabled`); cleanup `04:00` unchanged. Registered with `register_schedule`, deduplicated by the `scheduler_state` row lock, run by the single advisory-lock scheduler on the 30-second tick.
- Worker (§3.2/§3.6/§7.2): `WORKER_CONCURRENCY=4` shared slots; discovery+scan jobs capped at `MAX_PARALLEL_JOBS` (default 2); timeouts scan 1800 s, alert/digest 300 s; priorities on-demand scan 200, scheduled 100, digest 50.
- Retries (§7.2/§6.7): scan 3 attempts, `transient_network` only, backoff 30/120 s (the 300 s step is unreachable under the 3-attempt cap, Plan 1 Task 12); `alert_expiry` and `digest` 3 attempts "for SMTP `4xx`/timeout only" (`smtp_transient`). `auth`, `validation`, `config_invalid`, `key_unwrap`, `internal`, `timeout` never retry.
- Expiry alerts (§7.4): thresholds `alert.thresholds_days` (default `[60,30,14,7,1,0]`); "if `not_after - now <= threshold days` and the notification was not already sent for that certificate+threshold+day, send one email"; "One email per certificate per run ... the smallest crossed threshold wins"; recipients "`certificate.owner_email` plus `alert.recipients` (team list), deduplicated, with the owner first. Empty owner falls back to the team list only"; content CN, SAN count, issuer, serial, `not_after` (with timezone), days remaining, active bindings, renewal state, links; "Text and a minimal HTML alternative"; owned-by-nobody certificates "produce a Settings warning instead of silent loss".
- Ledger (§4.15): `sent_at` "Set only on a successful send; NULL for failed attempts"; `last_attempt_at` "Set on every send attempt, including failures"; `attempts` total; `next_attempt_at` retry backoff; unique `dedupe_key`; "retried on the next scheduler tick ... up to 3 attempts total; after that the row stays `failed`, the failure is shown in the digest and on the Settings Status panel, and the next day's key takes over".
- Digest (§7.5): one email daily with expiring ≤ 7 days and expired, new TLS mismatches since the last digest plus the current mismatch count, unknown certificates found by discovery since the last digest, servers whose last discovery failed or is older than 48 hours, jobs failed or rolled back in the last 24 hours, inventory revision and its age; "A digest is sent even when there is nothing to report".
- SMTP (§7.6/§3.4): host, port, `starttls`/`ssl`/`none`, from, username in Settings; the password comes only from the worker secret `smtp_password` ("absent means no AUTH"); `smtp.tls_verify` defaults to true and its opt-out is "clearly marked unsafe"; dedicated `Message-ID` and `Date`; `From` is `smtp.from`; "replies go to the team list"; "Send failures never fail the whole expiry job when at least one mail was delivered". "Send test email" sends a fixed message to the current user and reports the conversation result "with the password redacted". Because `redact()` does not catch unlabeled short secrets (`app/services/audit.py` module docstring), "redacted" is achieved by construction: persisted or displayed SMTP outcomes contain only fixed step names, numeric reply codes and fixed descriptions, never SMTP peer reply text, exception text or AUTH challenge data (Contract decision 20).
- `web` enqueues only (§3.1): it never opens TLS-inspection or SMTP connections and never loads `smtp_password` (Plan 1's web profile already omits it).
- No secret value in the database, logs, job payloads/results/errors, audit rows, UI or emails (§3.4 rule 1, §9.1.4). Every stored error passes `redact()` and is truncated.
- Lists (§8, §3.7): server-side pagination (page size 1–100, default 50), whitelisted sorts, bookmarkable query-string filters, JSON export of explicitly allowlisted fields; query count independent of row count; p95 < 300 ms at 5,000 bindings. Forms: CSRF, POST→303, htmx 422 fragments, fully usable without JavaScript. Every mutation and its audit row share one transaction.
- Retention: `scan_result` 90 days via the existing cleanup handler; Plan 2 adds no retention rule.
- Tests (§10): real `postgres:16` Testcontainers exactly as Plan 1; "No test reaches the internet; the SMTP target is a local capture server". Test-only target images are pinned by digest and pulled by a CI setup step; tests start them with `--pull never`. Integration tests need Docker and therefore run only in GitHub CI; locally run `uv run ruff check .` and `uv run pytest -q tests/unit`. Coverage gates unchanged (70% overall, 85% `app/crypto` and `app/services/renewals.py`).

## Review Focus

- A scan of an endpoint serving an unknown, self-signed or expired certificate records the observation and leaves `certificate`, `private_key`, `trust_anchor` and every `chain_status` untouched (Tasks 1–2).
- Unreachable endpoints are retried alone, never more than 3 attempts in total, and the job never rescans healthy endpoints on a retry (Task 2).
- A certificate 29 days from expiry receives the 30-day alert exactly once, regardless of reruns, retries or the next day's run; no row ever reaches a fourth attempt; `sent_at` is set only on success (Tasks 6–8).
- `smtp_password` never appears in payloads, results, errors, audit rows, logs, the test-send transcript or HTML — even when a relay echoes it in a reply line, because no peer reply text is ever kept; AUTH is refused over plaintext and STARTTLS never silently downgrades (Tasks 4–5, 8).
- Digest "new" sections compare against the state *before* the cutoff: a mismatch or unknown binding that already existed at the last digest is a repeat, while a transition across the cutoff (`ok → mismatch`, `matched → unknown`, a different unknown certificate on the same binding) is new (Task 9).
- Screens return allowlisted JSON only, keep a constant query count, and gate discovery actions on the Plan 3 handler instead of pretending they work (Tasks 12–16).

## Contract decisions and test conventions

These resolve points the spec leaves open. Each is the smallest choice consistent with §7; the reviewer validates them against the cited sections.

1. **Endpoint outcomes are observations, not job failures (§7.3, §7.2, §6.7).** A scan job records one result per targeted endpoint per attempt. If any targeted endpoint is `unreachable` and `job.attempt < job.max_attempts`, the handler, after committing every result, fails the job with retryable `transient_network`; the queue's retry (30 s, then 120 s) re-runs it and the handler scans **only** the endpoints of its scope whose `last_scan_status` is still `unreachable`. The final attempt succeeds with counts even if endpoints remain unreachable: they stay visible on Scans/Overview. A repeatedly unreachable endpoint therefore shows up to three history rows per job, which is the flapping signal §8.8 asks for.
2. **Classification precedence.** No leaf observed → `unreachable` (pull_chain `transient_network`: DNS, refused, reset, any deadline including a silent peer during the handshake) or `error` (pull_chain `config_invalid`: handshake/protocol failure; or a served leaf that does not parse — its SHA-256 over the raw DER is still recorded). Otherwise `expired` if `not_after < now`, else `ok` if the fingerprint equals the expected certificate's, else `mismatch` (including no expectation). Stored `error` is the already-sanitized `JobFailure.message`.
3. **Scan source** is `scheduled` when `job.requested_by` is NULL and `manual` otherwise, so retries keep the original source. `endpoint.last_scan_at/last_scan_status` advance only when the new `checked_at` is not older than the stored one (two concurrent jobs cannot regress an endpoint). `scan.run` is audited once per attempt with counts (§4.16 lists "scan run").
4. **Scan payloads** for `scan/default`: `{}` (all active endpoints; the schedule and "Scan all"), `{"endpoint_ids": [...]}` (1–1000 unique positive ids) or `{"certificate_id": N}` (active endpoints expecting N, resolved at run time). Inactive endpoints are never scanned (§7.3 "for each active endpoint") and are counted as `skipped_inactive`.
5. **Background trust recheck.** `scan/trust_recheck` (allowed by Plan 1 Extension points and §5.8) runs `recheck_chain_statuses(db, now)` at the job's current UTC time, so expiring intermediates are noticed without an operator action. It is scheduled under key `trust_recheck` reusing `scan.daily_at`/`scan.enabled` (no new setting row), and Settings → Trust anchors gains "Recheck now". Anchor upload/delete/toggle keep their synchronous recheck, as §8.10 requires.
6. **Expiry dedupe.** `dedupe_key = expiry:<certificate_id>:<threshold>:<UTC run date>` (the §4.15 example shape). A candidate is the smallest crossed threshold `T`; it is skipped when any `sent` expiry row exists for `(certificate_id, T)` on any day, which makes "the 30-day alert once" hold across days and makes larger thresholds implicitly consumed. The window is `|not_after − now| ≤ max(thresholds)` days (the spec's "60-day window" generalised to configured thresholds). A failed row retries only on the UTC day it was created; the next day's evaluation creates the next day's key.
7. **Ledger semantics.** `open_notification` inserts the row `ON CONFLICT (dedupe_key) DO NOTHING` (status `failed`, `attempts=0`, all timestamps NULL) and then locks it `FOR UPDATE SKIP LOCKED`; it returns the row only while it is attemptable (not `sent`, `attempts < 3`, `next_attempt_at` NULL or due). `record_attempt` increments `attempts`, sets `last_attempt_at`, and on success sets `status=sent`, `sent_at`, clears `error/next_attempt_at`; on failure keeps `sent_at` NULL, stores `"<code>: <message>"` (redacted, ≤ 500 chars) and sets `next_attempt_at = now + retry_delay_seconds(attempts)` only for retryable codes with `attempts < 3`. The send happens while the row lock is held and is committed with the attempt; a worker crash between SMTP acceptance and commit can resend once (at-least-once delivery, documented).
8. **Failure codes.** `smtp_not_configured` (no `smtp.host`, `smtp.from` or `smtp.security`; or AUTH requested without TLS), `no_recipients`, `smtp_transient` (connect/DNS/timeout/disconnect or any 4xx reply), `smtp_rejected` (5xx other than auth), `smtp_auth` (530/534/535 or AUTH unsupported), `smtp_tls` (STARTTLS unavailable, TLS handshake or certificate verification failure). Only `smtp_transient` is retryable. Job error classes map `smtp_transient → smtp_transient`, `smtp_auth → auth`, everything else → `config_invalid`. Outcome messages follow Contract decision 20 (for example `451 at rcpt`), so the stored ledger error is `smtp_transient: 451 at rcpt`.
9. **Expiry job outcome (§7.6).** The job succeeds when at least one message was delivered or nothing needed sending; when it attempted at least one send and delivered none it fails with `smtp_transient` (retryable) if any failure was transient, otherwise with the mapped non-retryable class. `no_recipients` rows are recorded (Settings/digest visibility) but are not send attempts for this rule.
10. **Notification retry sweep.** Plan 2 adds `register_tick_step(...)` to `app/jobs/worker.py`; the `notification_retry` step enqueues one `alert_expiry` job with payload `{"mode": "retry_failed"}` (priority 100, `max_attempts=1`, `scheduled_reason='retry'`) when due failed expiry rows from today exist and no `alert_expiry` job is queued or running. That mode only re-attempts due rows and never fails for SMTP reasons (the sweep is the retry). Digest rows rely on job-level retry only (one row per job).
11. **Digest window.** "Since the last digest" = `sent_at` of the newest sent digest row, else `now − 24 h`. "New" is decided against the state at that cutoff, never by looking only at rows inside the window (Contract decisions 21 and 22). `dedupe_key = digest:<UTC run date>`; a rerun the same day after success sends nothing. Empty `alert.recipients` records a failed `no_recipients` row. The digest job result contains counts only — never the dedupe key, because the shared redactor treats the token `digest:` as an auth scheme and `finish()` would refuse the result.
12. **SMTP session.** One session per job, lazily connected, per-command timeout 30 s, at most one reconnect after a server disconnect. Default ports 587/465/25 for `starttls`/`ssl`/`none` when `smtp.port` is empty. AUTH happens only when `smtp.username` is non-empty **and** `smtp_password` is present, and only over `starttls`/`ssl` (fail closed). With `smtp.tls_verify=true` the context is `ssl.create_default_context()` (system store); `false` disables verification and Settings shows the unsafe warning. `Reply-To` is `alert.recipients` when non-empty.
13. **Test send is a worker job.** The web process holds no SMTP password, so "Send test email" enqueues `(alert_expiry, action='smtp_test')` with payload `{"action": "smtp_test"}` (priority 200, `max_attempts=1`, never retried); the recipient is the requesting user's e-mail read from `job.requested_by` at run time. Delivered → job `succeeded` with a transcript of fixed step names and reply codes; not delivered → job `failed` with the mapped class and a fixed-text summary (Contract decision 20). The SMTP tab and Status show the newest such job, never a guessed state.
14. **Dashboard links in e-mail.** No base-URL setting exists and the schema is frozen, so the worker reads optional `DASHBOARD_URL` from the environment (`Settings.dashboard_url`; absolute `http(s)` URL without credentials, query or fragment, else `ConfigurationError`). Without it, e-mails show dashboard paths such as `/certificates/42`. E-mails state times in `ui.timezone` **and** UTC.
15. **§7.7 inventory refresh is not a Plan 2 job.** The spec defines it as the preflight of every `discover`/`deploy` job "rather than a separate user-visible job type"; it belongs to Plan 3 together with "Test pull". `scan/import_pull` stays exactly as Task 16 of Plan 1 built it (it still writes no `scan_result`); the endpoints it upserts are scanned by `scan/default` like any other.
16. **Endpoints are managed on the Scans screen.** §4.9 ("manual (UI form)"), §8.8 ("update the expectation if the vhost intentionally changed") and §11.3 ("manual endpoint entry") need a home: `/scans` gets add-endpoint, set-expectation (explicit active certificate, or "use the observed certificate" when its fingerprint is already in inventory) and activate/deactivate forms, audited as `endpoint.create`/`endpoint.update`. Endpoints are never deleted.
17. **Servers "current mismatch count"** (§8.6) = active endpoints linked to the server whose `last_scan_status` is `mismatch`. Server/binding screens are read-only in Plan 2; discovery actions render disabled with `unsupported_reason(registry, "Plan 3", (JobType.DISCOVER, "default"))`.
18. **Module layout.** The spec's `services/alerts.py` is split by responsibility: `services/smtp.py` (transport), `services/notifications.py` (ledger), `services/alerts.py` (expiry), `services/digest.py`; read models in `services/endpoints.py`, `services/servers.py`, `services/overview.py`; handlers one module per concern under `app/jobs/handlers/`. E-mail templates live in `app/templates/email/` and render through a dedicated Jinja environment (HTML autoescaped, text not).
19. **Test harness.** SMTP behaviour is exercised against `tests/fixtures/smtp_capture.py` (aiosmtpd) in-process — scripted replies by recipient local part: `tempfail…` → `451 4.3.0`, `reject…` → `550 5.1.1`, plus per-verb reply overrides that can echo the AUTH password the server received (the hostile-relay case of Contract decision 20) — and the same module runs as the `smtp` compose service. TLS behaviour uses Plan 1's in-process `TLSServer` everywhere, plus real nginx and Apache targets in `docker-compose.test.yml` under profile `targets` for one end-to-end scan test (Task 17). SMTP TLS fixtures are issued with `FixtureCA(datetime.now(UTC))` because OpenSSL verifies against wall-clock time.
20. **SMTP outcomes carry no peer text (§7.6 "with the password redacted", §9.1.4, Plan 1 redaction contract).** `redact()` catches only labeled secrets, PEM, auth schemes, URL credentials and long base64 runs, so a relay that echoes a credential in an unlabeled reply line (`535 5.7.8 incorrect credential <password>`) would leak through any design that keeps reply text. Therefore `SmtpStep` is `(step, code)` only: `step` is one of the fixed names `connect`, `ehlo`, `starttls`, `auth`, `mail`, `rcpt`, `data`, `quit`, and `code` is the integer reply code when it lies in 200–599, else `None`. `SendOutcome.message` comes from a closed table of fixed templates: `"<code> at <step>"` for SMTP replies; `"connection failed (<ERRNO>)"`, where `<ERRNO>` is the stdlib `errno.errorcode` symbol for the integer `errno` (omitted when unknown); `"timed out at <step>"`; `"server closed the connection at <step>"`; `"STARTTLS not offered by the server"`; `"TLS handshake or certificate verification failed"` (plus ` (verify code <n>)` from the integer `ssl.SSLCertVerificationError.verify_code` when present); `"AUTH not offered by the server"`; `"AUTH requires starttls or ssl"`; `"smtp.host, smtp.from or smtp.security is not set"`; `"no recipients"`. Exceptions are caught at the transport boundary and reduced to `(step, code)`; their `str()`, `args`, `smtp_error` bytes, SSL reason strings and AUTH challenge data are never formatted, logged (no `exc_info`, `logger.exception` or traceback) or re-raised, and `set_debuglevel` stays 0. Envelope addresses are not part of steps. `redact()` and truncation still run on every stored error as a second barrier, never as the primary control.
21. **New TLS mismatches (§7.3 "transition from `ok` to `mismatch`, or first observation"; §7.5).** A `scan_result` with `status='mismatch'` and `checked_at > since` is *new* when its predecessor — the same endpoint's previous result that observed a certificate (`status IN ('ok','mismatch','expired')`, ordered by `checked_at, id`) looked up over the **full retained history, not only the window** — is absent or is not `mismatch`. `unreachable`/`error` results observe no certificate, so they neither start nor end a mismatch: `mismatch → unreachable → mismatch` is a repeat, `ok → unreachable → mismatch` is new; `expired → mismatch` is new because a different certificate is now served. A mismatch that existed before the cutoff and is still observed afterwards is a repeat and only contributes to the current count (active endpoints with `last_scan_status='mismatch'`). The section lists each endpoint once (its newest new-mismatch result) with its current status, so a mismatch that appeared and was fixed between two digests is still reported. A predecessor already pruned by the 90-day retention counts as absent.
22. **Unknown certificates found by discovery since the last digest (§7.5, §6.3).** `binding.created_at` cannot express this — reconciliation updates an existing binding from `matched` to `unknown` in place — and the frozen schema has no transition column, so the signal is the append-only audit trail. Plan 2 (Task 9) adds `app/services/bindings.py` with `audit_binding_state(...)`, which writes one `binding.match_state` audit row (`target_type='binding'`, `target_id=str(binding.id)`, details `from_state`, `from_fingerprint`, `was_active`, `to_state`, `on_disk_fingerprint`, `is_active`, `server_id`, `job_id`; metadata only, never `notes` or paths) whenever a binding is inserted or its `(match_state, on_disk_fingerprint, is_active)` triple changes, and writes nothing when the same triple is seen again; for an insertion `from_state` and `from_fingerprint` are NULL and `was_active` is false. **Producer contract for Plan 3:** discovery reconciliation calls `audit_binding_state` for every binding it inserts or updates, in the same per-server transaction as the change (§1 "Every state-changing action is attributable ... in an append-only audit log", §5.5), and no other code path changes those three fields without calling it. A binding is a *new unknown* when (a) it is now active with `match_state='unknown'` and on-disk fingerprint `F`; (b) at least one `binding.match_state` row after `since` has `to_state='unknown'` and `on_disk_fingerprint=F`; and (c) its state at the cutoff was not `(unknown, F, active)`, where the state at the cutoff is the `from_*` values of its earliest audit row after `since` (each row records its predecessor, so this is the full-history predecessor, not a window-only guess). Hence an old `matched` binding reconciled to `unknown` after the cutoff is new; a repeat unknown discovery writes no row and is not new; `unknown → missing_file → unknown` with the same certificate inside the window is a repeat; the same binding now holding a different unknown certificate is new; a binding that became unknown and was matched again before the digest is not listed. The query reads only `action='binding.match_state'` rows after `since`; `audit_log` has no index for it and none is added (frozen schema) — a once-a-day sequential scan is acceptable at v1 scale.

Test conventions are Plan 1's: snippets omit standard imports and import symbols from each task's Interfaces; new fixtures go in the stated `conftest.py`. Shared helpers added to `tests/integration/conftest.py` in Task 2 — `closed_port() -> int`, `set_setting(factory, key, value) -> None`, `disable_schedules(factory, *keys) -> None` (sets `<key>.enabled=false`, `alert.digest_enabled=false` for `digest`) — are reused later. Any test that calls `Worker.tick()` against the shared `web_factory` database disables the schedules it does not exercise so daily jobs cannot pollute its counts; alert and digest tests use the private `queue_factory` database. Integration commands below run in CI; the developer's local gate for every task is `uv run ruff check .` plus `uv run pytest -q tests/unit` (and the task's named unit file).

### Spec coverage map

| Spec | Tasks |
| --- | --- |
| §7.1 scheduler, §7.2 lifecycle | 2 (scan schedule, retries, slot cap), 3, 6 (tick steps), 8, 10 |
| §7.3 TLS scanning, §4.9/§4.10 | 1, 2, 12, 13, 17 |
| §5.8 background recheck | 3 |
| §7.4 expiry alerts, §4.15 | 6, 7, 8, 11 |
| §7.5 digest, §6.3 unknown-certificate signal | 9 (collection), 10 (job and mail) |
| §7.6 SMTP + test send, §9.2/§9.7 SMTP rows | 4, 5, 11 |
| §7.7 inventory refresh | Contract decision 15 (Plan 3) |
| §8.2 Overview TLS/jobs/renewals/status | 16 |
| §8.4 endpoints panel, "Scan now" | 2, 13 |
| §8.6 Servers/Bindings | 14, 15 |
| §8.8 Scan results | 12, 13 |
| §8.10 SMTP test send, Status, alert failures | 5, 11 |
| §10.2 scenarios 10–11, §10.3 local SMTP/TLS | 2, 8, 17 |

### Task 1: Endpoint observation and classified scan results

**Files:** Modify: `app/services/scans.py`. Test: `tests/unit/test_scan_classification.py`, `tests/integration/test_scan_results.py`.

**Size budget:** ≈ 140 production + 230 test lines.

**Interfaces:** Consumes: `pull_chain(host: str, port: int, sni: str | None, timeout_seconds: int = 10) -> PulledChain`, `PulledChain(der_chain: tuple[bytes, ...], tls_version: str)`, `JobFailure(error_class: str, message: str, retryable: bool = False)`, `parse_certificates(data: bytes) -> list[ParsedCertificate]`, ORM `Endpoint`, `ScanResult`, `Certificate`, `ScanStatus`. Produces in `app/services/scans.py`: `ScanObservation(fingerprint: str | None, common_name: str | None, issuer_cn: str | None, not_after: datetime | None, chain_length: int | None, tls_version: str | None, failure: Literal['unreachable','error'] | None, error: str | None, elapsed_ms: int)` (frozen); `observation_from_chain(pulled: PulledChain, elapsed_ms: int) -> ScanObservation`; `observe_endpoint(host: str, port: int, sni: str | None, timeout_seconds: int) -> ScanObservation` (never raises for network/TLS outcomes); `classify_observation(observation: ScanObservation, expected_fingerprint: str | None, now: datetime) -> ScanStatus`; `record_scan(db: Session, endpoint_id: int, observation: ScanObservation, source: Literal['scheduled','manual'], now: datetime) -> ScanResult`.

- [ ] Write failing pure tests in `tests/unit/test_scan_classification.py`:

```python
def observed(fingerprint="a" * 64, not_after=None, failure=None):
    return ScanObservation(fingerprint=fingerprint, common_name="www.example.internal",
        issuer_cn="Fixture Intermediate", not_after=not_after, chain_length=3,
        tls_version="TLSv1.3", failure=failure, error=None, elapsed_ms=4)

def test_classification_precedence(now):
    future, past = now + timedelta(days=30), now - timedelta(seconds=1)
    assert classify_observation(observed(not_after=future), "a" * 64, now) is ScanStatus.OK
    assert classify_observation(observed(not_after=future), "b" * 64, now) is ScanStatus.MISMATCH
    assert classify_observation(observed(not_after=future), None, now) is ScanStatus.MISMATCH
    assert classify_observation(observed(not_after=past), "a" * 64, now) is ScanStatus.EXPIRED
    assert classify_observation(observed(None, failure="unreachable"), "a" * 64, now) is ScanStatus.UNREACHABLE
    assert classify_observation(observed(failure="error"), "a" * 64, now) is ScanStatus.ERROR

def test_observation_from_served_der(certs):
    der = certs.leaf.public_bytes(Encoding.DER)
    chain = (der, *(c.public_bytes(Encoding.DER) for c in certs.intermediates))
    seen = observation_from_chain(PulledChain(chain, "TLSv1.3"), elapsed_ms=7)
    assert seen.fingerprint == hashlib.sha256(der).hexdigest() and seen.chain_length == 3
    assert seen.not_after == certs.leaf.not_valid_after_utc and seen.failure is None
    broken = observation_from_chain(PulledChain((b"\x30\x03junk",), "TLSv1.2"), elapsed_ms=1)
    assert broken.failure == "error" and broken.fingerprint == hashlib.sha256(b"\x30\x03junk").hexdigest()
```

  Also assert fingerprints are lowercase hex, a mixed-case expected fingerprint still matches, `expired` wins over a matching fingerprint, and a missing fingerprint can never classify `ok`.
- [ ] Write failing DB tests in `tests/integration/test_scan_results.py` against Plan 1's `tls_servers`/`pull_certs` listeners and the rollback `db` fixture: `test_record_scan_persists_observation_and_updates_endpoint`, `test_served_certificate_is_never_imported_or_trusted`, `test_unreachable_and_handshake_failures_are_recorded_not_raised` (closed port → `unreachable`; `mode="garbage"` → `error`; `mode="silent"` with timeout 1 → `unreachable`), `test_expired_served_certificate_is_expired_even_when_expected` (leaf from the session `ca` fixture with `not_after=now - timedelta(days=1)`), `test_expectation_is_snapshotted_at_scan_time`, `test_older_result_never_regresses_endpoint_state`.

```python
def test_served_certificate_is_never_imported_or_trusted(db, tls_servers, pull_certs, now):
    server = tls_servers(pull_certs.leaf, pull_certs.leaf_key, pull_certs.intermediates)
    endpoint = Endpoint(host=server.host, port=server.port, sni="www.example.internal", source=EndpointSource.MANUAL)
    db.add(endpoint)
    db.flush()
    counts = [db.scalar(select(func.count()).select_from(model)) for model in (Certificate, PrivateKey, TrustAnchor)]
    result = record_scan(db, endpoint.id, observe_endpoint(server.host, server.port, endpoint.sni, 10), "manual", now)
    assert result.status is ScanStatus.MISMATCH and result.expected_certificate_id is None
    assert result.observed_fingerprint == pull_certs.leaf.fingerprint(hashes.SHA256()).hex()
    assert (result.observed_chain_length, result.source, result.checked_at) == (3, "manual", now)
    assert counts == [db.scalar(select(func.count()).select_from(model)) for model in (Certificate, PrivateKey, TrustAnchor)]
    assert (endpoint.last_scan_status, endpoint.last_scan_at) == (ScanStatus.MISMATCH, now)
```

- [ ] Run `uv run pytest tests/unit/test_scan_classification.py -q` locally and `uv run pytest tests/integration/test_scan_results.py -q` in CI; expect FAIL, the observation API is absent.
- [ ] Implement in `app/services/scans.py`. `observe_endpoint` measures `time.monotonic()` around `pull_chain(host, port, sni, timeout_seconds)` and maps `JobFailure` by class: `transient_network` → `failure='unreachable'`, anything else → `failure='error'`, keeping `exc.message` as `error`; it never lets a `JobFailure` escape. `observation_from_chain` hashes the first DER, parses it with `parse_certificates` for CN/issuer CN/`not_after`, and on `ParseError` keeps the hash with `failure='error'` and a fixed message. `record_scan` locks the endpoint row `FOR UPDATE`, snapshots `expected_certificate_id` and that certificate's fingerprint, classifies, inserts the complete `scan_result` (`checked_at=now`, `elapsed_ms`, `tls_version`), and updates `last_scan_at/last_scan_status` only when `last_scan_at` is NULL or `<= now`. It never reads or writes `certificate` beyond the expected fingerprint and owns no commit.
- [ ] Run the same commands; expect PASS. Locally also run `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [ ] Commit: `git add app/services/scans.py tests/unit/test_scan_classification.py tests/integration/test_scan_results.py`; `git commit -m "feat: observe TLS endpoints and persist classified scan results"`.

### Task 2: `scan/default` job, daily schedule, unreachable retries and "Scan now"

**Files:** Create: `app/jobs/handlers/scan.py`. Modify: `app/services/scans.py`, `app/jobs/handlers/__init__.py`, `app/jobs/worker.py`, `app/web/certificates.py`, `app/templates/certificates/detail.html.j2`, `tests/integration/conftest.py`, `tests/unit/test_job_registry.py`, `tests/unit/test_pull_payload.py`, `tests/integration/test_worker.py`, `tests/integration/test_inventory_http.py`. Test: `tests/unit/test_scan_payload.py`, `tests/integration/test_scan_jobs.py`.

**Size budget:** ≈ 200 production + 330 test lines.

**Interfaces:** Consumes: Task 1 `observe_endpoint`/`record_scan`; `JobRegistry.register(job_type: JobType, handler: JobHandler, *, action: str = 'default', validator: PayloadValidator) -> None`; `register_schedule(key: str, job_type: JobType, action: str = 'default') -> None`; `enqueue(db: Session, job_type: JobType, payload: Mapping[str, JSONValue], actor: Actor, *, priority: int, run_after: datetime, max_attempts: int = 3, scheduled_reason: ScheduledReason | None = None) -> Job`; `get_setting(db: Session, key: str) -> JSONValue`; `record(...)`. Produces in `app/services/scans.py`: `ON_DEMAND_PRIORITY = 200`; `ScanTarget(endpoint_id: int, host: str, port: int, sni: str | None)`; `validate_scan_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]`; `scan_targets(db: Session, payload: Mapping[str, JSONValue], *, only_unreachable: bool = False) -> tuple[list[ScanTarget], int]` (targets, skipped inactive); `ScanRequestError(LookupError)`; `request_scan(db: Session, payload: Mapping[str, JSONValue], actor: Actor, now: datetime) -> Job`. In `app/jobs/handlers/scan.py`: `SCAN_CONCURRENCY = 20`; `scan_endpoints(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]`. Route POST `/certificates/{certificate_id}/scan`. Schedule key `scan`.

- [x] Write failing payload unit tests in `tests/unit/test_scan_payload.py`:

```python
@pytest.mark.parametrize("payload", [{}, {"action": "default"}, {"endpoint_ids": [3, 1]}, {"certificate_id": 7}])
def test_valid_scan_payloads(payload):
    clean = validate_scan_payload(payload)
    assert "action" not in clean and clean.get("endpoint_ids", [1, 3]) == [1, 3]

@pytest.mark.parametrize("payload", [{"endpoint_ids": []}, {"endpoint_ids": [1, 1]}, {"endpoint_ids": [0]},
    {"endpoint_ids": [True]}, {"endpoint_ids": list(range(1, 1002))}, {"certificate_id": "7"},
    {"endpoint_ids": [1], "certificate_id": 2}, {"host": "example.internal"}, {"action": "import_pull"}])
def test_invalid_scan_payloads(payload):
    with pytest.raises(ValueError):
        validate_scan_payload(payload)
```

- [x] Write failing worker tests in `tests/integration/test_scan_jobs.py` (autouse fixture: `disable_schedules(web_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup")`; module helpers `add_endpoint`, `enqueue_scan`, `job_state`, `result_count`):

```python
def test_unreachable_endpoints_are_retried_alone_until_the_last_attempt(
    worker_harness, web_factory, tls_servers, pull_certs, clock
):
    live = tls_servers(pull_certs.leaf, pull_certs.leaf_key, pull_certs.intermediates)
    up = add_endpoint(web_factory, live.host, live.port)
    down = add_endpoint(web_factory, "127.0.0.1", closed_port())
    job_id = enqueue_scan(web_factory, {"endpoint_ids": [up, down]}, clock())
    worker_harness.run_queued()
    assert job_state(web_factory, job_id) == ("failed", "transient_network")
    for delay in (31, 121):
        clock.advance(seconds=delay)
        worker_harness.tick()
        worker_harness.run_queued()
    assert job_state(web_factory, job_id) == ("succeeded", None)
    assert (result_count(web_factory, up), result_count(web_factory, down)) == (1, 3)
```

  Also add `test_scan_job_records_one_result_per_active_endpoint` (result counts by status, `skipped_inactive`, one `scan.run` audit with counts and `source`), `test_scheduled_scan_runs_daily_with_system_source` (re-enable `scan`, tick at 02:00:30 → one queued `scan` job, priority 100, `scheduled_reason='daily'`, payload `{}`; a second tick enqueues nothing; results have `source='scheduled'`), `test_manual_scan_keeps_manual_source_across_retries`, `test_certificate_scope_scans_only_endpoints_expecting_it`, `test_scan_honours_scan_timeout_setting` (`mode="silent"`, `scan.timeout_seconds=1`, elapsed < 5 s), `test_a_third_scan_job_stays_queued_while_two_scans_run` (three silent listeners, timeout 3: first `poll()` starts exactly two jobs, the third stays `queued`, a cleanup job still claims a free slot), `test_bounded_concurrency_never_exceeds_twenty_connections` (25 silent listeners in one job with `scan.timeout_seconds=2`; sampled before the first timeout elapses, exactly 20 listeners have accepted a connection; all 25 have one when the job ends), `test_cert_detail_scan_now_enqueues_on_demand_scan` (POST with CSRF → 303 to `/certificates/{id}#endpoints-panel`, job priority 200 payload `{"certificate_id": id}`, no listener connection before the worker runs; missing CSRF → 403; no active endpoint → 422 with a reason).
- [x] Ticking tests in `tests/integration/test_worker.py` that assert totals across job types must filter by type or `disable_schedules(...)` the new `scan` schedule. Update Plan 1 assertions that encoded the gap: registry now supports `(scan, 'default')` in `tests/unit/test_job_registry.py`, `tests/unit/test_pull_payload.py` and `tests/integration/test_worker.py`; in `tests/integration/test_inventory_http.py` the Scans navigation entry stays disabled with "Available in a later plan" (Task 12 enables it) and the detail "Scan now" control becomes the POST form.
- [x] Run `uv run pytest tests/unit/test_scan_payload.py tests/unit/test_job_registry.py tests/unit/test_pull_payload.py -q` locally and `uv run pytest tests/integration/test_scan_jobs.py tests/integration/test_worker.py tests/integration/test_inventory_http.py -q` in CI; expect FAIL, `scan/default` is not registered.
- [x] Implement. `validate_scan_payload` accepts only the shapes of Contract decision 4, drops `action`, and returns sorted endpoint ids. `scan_endpoints` reads its `Job` row (attempt, max_attempts, requested_by) and `scan.timeout_seconds` in a short transaction, resolves targets (`only_unreachable=job.attempt > 1`) into plain `ScanTarget` values, closes the session, then runs `observe_endpoint` in a `ThreadPoolExecutor(max_workers=min(SCAN_CONCURRENCY, len(targets)))`; each completed observation is committed with `record_scan` in its own `context.factory.begin()` transaction so partial work survives a crash (§9.1.5). It audits `scan.run` (`target_type='job'`, details `source`, `attempt`, counts), returns `{"scanned","ok","mismatch","expired","unreachable","error","skipped_inactive"}`, and raises `JobFailure("transient_network", "<n> of <m> endpoints unreachable; retrying them", retryable=True)` per Contract decision 1. Register `(JobType.SCAN, 'default')` in `build_registry()` and `register_schedule("scan", JobType.SCAN)` beside cleanup in `worker.py`. `request_scan` validates, checks that referenced endpoints/certificate exist (`ScanRequestError` otherwise), and enqueues with `ON_DEMAND_PRIORITY` and `max_attempts=3`; the certificate detail form posts to `/certificates/{id}/scan` and redirects with a flash note. Promote `closed_port`, `set_setting` and `disable_schedules` into `tests/integration/conftest.py`.
- [x] Run the same commands; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [x] Commit: `git add app/services/scans.py app/jobs/handlers app/jobs/worker.py app/web/certificates.py app/templates/certificates/detail.html.j2 tests/unit/test_scan_payload.py tests/unit/test_job_registry.py tests/unit/test_pull_payload.py tests/integration/conftest.py tests/integration/test_scan_jobs.py tests/integration/test_worker.py tests/integration/test_inventory_http.py`; `git commit -m "feat: scan registered endpoints on schedule and on demand"`.

### Task 3: Background trust recheck

**Files:** Create: `app/jobs/handlers/trust_recheck.py`. Modify: `app/jobs/handlers/__init__.py`, `app/jobs/worker.py`, `app/web/settings.py`, `app/templates/settings.html.j2`, `tests/unit/test_job_registry.py`. Test: `tests/integration/test_trust_recheck_job.py`.

**Size budget:** ≈ 80 production + 180 test lines.

**Interfaces:** Consumes: `recheck_chain_statuses(db: Session, validation_time: datetime, diagnostic_roots: Sequence[x509.Certificate] = ()) -> dict[str, int]`, `add_anchor(db: Session, pem: bytes, notes: str | None, actor: Actor, validation_time: datetime) -> TrustAnchor`, `save_certificate(...)`, Task 2 `ON_DEMAND_PRIORITY`. Produces: `TRUST_RECHECK_ACTION = "trust_recheck"`; `validate_trust_recheck_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]` (exactly `{"action": "trust_recheck"}`); `trust_recheck(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]` (status counts plus `validation_time`); schedule key `trust_recheck` with `_TIME_SETTING["trust_recheck"] = "scan.daily_at"` and `_ENABLED_SETTING["trust_recheck"] = "scan.enabled"`; POST `/settings/trust-anchors/recheck`.

- [x] Write failing tests:

```python
def test_background_recheck_notices_an_intermediate_that_expired(queue_factory, make_worker, certs, clock):
    leaf, chain = certs.expired_intermediate_leaf, certs.expired_intermediate_chain
    valid_at = max(leaf.not_valid_before_utc, certs.expired_intermediate.not_valid_before_utc) + timedelta(seconds=1)
    assert valid_at < certs.expired_intermediate.not_valid_after_utc < clock()
    certificate_id = save_with_root_anchor(queue_factory, leaf, chain, certs.root, validation_time=valid_at)
    assert chain_status(queue_factory, certificate_id) == "trusted"
    enqueue_recheck(queue_factory, clock())
    make_worker(queue_factory).run_queued()
    assert chain_status(queue_factory, certificate_id) == "incomplete"
    assert last_audit(queue_factory, "certificate", certificate_id).details["validation_time"] == clock().isoformat()
```

  Also add `test_trust_recheck_is_scheduled_with_the_scan_time_and_flag` (private `queue_factory` + `make_worker`: a tick at 02:00:30 enqueues both `{}` and `{"action": "trust_recheck"}` scan jobs; with `scan.enabled=false` the next day enqueues neither), `test_recheck_now_button_requires_csrf_and_enqueues` (Trust anchors tab shows the button enabled; POST without CSRF → 403; with CSRF → 303 and one queued job priority 200), `test_trust_recheck_never_touches_endpoints_or_scan_results`, and a unit assertion in `tests/unit/test_job_registry.py` that the registry supports `(scan, 'trust_recheck')` and the payload validator rejects extra keys.
- [x] Run `uv run pytest tests/unit/test_job_registry.py -q` locally and `uv run pytest tests/integration/test_trust_recheck_job.py -q` in CI; expect FAIL, the action is unregistered.
- [x] Implement. The handler opens one transaction and calls `recheck_chain_statuses(db, context.clock())`; changed statuses get Plan 1's `certificate.chain_check` audits. Anchor upload/delete/toggle stay synchronous (Contract decision 5). The button is gated with `unsupported_reason(registry, "Plan 2", (JobType.SCAN, "trust_recheck"))`. As a `scan`-type job it counts against the two-job discovery/scan cap.
- [x] Run the same commands; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [x] Commit: `git add app/jobs/handlers app/jobs/worker.py app/web/settings.py app/templates/settings.html.j2 tests/unit/test_job_registry.py tests/integration/test_trust_recheck_job.py`; `git commit -m "feat: recheck certificate trust paths in the background"`.

### Task 4: SMTP transport with typed outcomes and a local capture server

**Files:** Create: `app/services/smtp.py`, `tests/fixtures/smtp_capture.py`. Modify: `pyproject.toml`, `uv.lock` (dev group `aiosmtpd`), `tests/conftest.py`. Test: `tests/unit/test_smtp_transport.py`.

**Size budget:** ≈ 250 production + 340 test/fixture lines.

**Interfaces:** Consumes: `get_setting(db: Session, key: str) -> JSONValue`. Produces in `app/services/smtp.py`: `SMTP_TIMEOUT_SECONDS = 30`; `SmtpConfig(host: str, port: int, security: Literal['starttls','ssl','none'], sender: str, username: str, tls_verify: bool, reply_to: tuple[str, ...])` (frozen); `load_smtp_config(db: Session) -> SmtpConfig | None` (None = `smtp_not_configured`); `SmtpStepName = Literal['connect','ehlo','starttls','auth','mail','rcpt','data','quit']`; `SmtpStep(step: SmtpStepName, code: int | None)` (frozen; no text field by design, Contract decision 20); `SendOutcome(delivered: bool, code: Literal['sent','smtp_not_configured','no_recipients','smtp_transient','smtp_rejected','smtp_auth','smtp_tls'], message: str, retryable: bool, steps: tuple[SmtpStep, ...] = ())` (`message` always from the fixed template table); `outcome_message(kind: str, *, step: SmtpStepName | None = None, code: int | None = None, errno_value: int | None = None, verify_code: int | None = None) -> str` (the only constructor of outcome text); `job_error_class(code: str) -> str`; `smtp_tls_context(verify: bool) -> ssl.SSLContext`; `build_message(config: SmtpConfig, recipients: Sequence[str], subject: str, text: str, html: str | None, now: datetime) -> EmailMessage`; `open_smtp(config: SmtpConfig, password: bytes | None, *, context: ssl.SSLContext | None = None, timeout_seconds: int = SMTP_TIMEOUT_SECONDS) -> SmtpSession` (context manager); `SmtpSession.send(message: EmailMessage) -> SendOutcome`; `SmtpSession.steps: tuple[SmtpStep, ...]`. In `tests/fixtures/smtp_capture.py`: `CaptureServer(*, port: int | None = None, tls: TLSMaterial | None = None, implicit_tls: bool = False, password: str | None = None, replies: Mapping[str, str] | None = None)` (`port=None` binds a free loopback port; `replies` overrides the reply line per verb `AUTH`/`MAIL`/`RCPT`/`DATA`, where `{password}` is replaced by the password the client actually sent, to emulate a relay that echoes credentials) with `.port`, `.connections`, `.messages: list[EmailMessage]`, `.close()`, and a `main()` CLI (`--listen HOST:PORT --spool DIR`, `--dump DIR`). In `tests/conftest.py`: `smtp_server` factory fixture and `tls_material` (`FixtureCA(datetime.now(UTC))` leaf for `127.0.0.1` with `server_context()`/`client_context()`).

- [x] Write failing loopback tests (no Docker; they also run in the CI unit-container smoke):

```python
def test_tempfail_is_transient_and_reject_is_permanent(smtp_server, now):
    capture = smtp_server()
    config = SmtpConfig("127.0.0.1", capture.port, "none", "dashboard@example.test", "", True, ())
    with open_smtp(config, None) as session:
        ok = session.send(build_message(config, ["team@example.test"], "s", "body", None, now))
        soft = session.send(build_message(config, ["tempfail@example.test"], "s", "body", None, now))
        hard = session.send(build_message(config, ["reject@example.test"], "s", "body", None, now))
    assert ok.delivered and ok.code == "sent"
    assert (soft.code, soft.retryable, soft.message) == ("smtp_transient", True, "451 at rcpt")
    assert (hard.code, hard.retryable, hard.message) == ("smtp_rejected", False, "550 at rcpt")
    assert [message["To"] for message in capture.messages] == ["team@example.test"]

def test_relay_echoing_the_password_never_leaks_it(smtp_server, tls_material, now, caplog):
    secret = "fixture-smtp-password-123"  # unlabeled, short: redact() alone would not catch it
    capture = smtp_server(tls=tls_material, password="another-password", replies={
        "AUTH": "535 5.7.8 PEER-TEXT-CANARY incorrect credential {password}"})
    config = SmtpConfig("127.0.0.1", capture.port, "starttls", "dashboard@example.test", "mailer", True, ())
    with open_smtp(config, secret.encode(), context=tls_material.client_context()) as session:
        denied = session.send(build_message(config, ["team@example.test"], "s", "b", None, now))
        steps = session.steps
    plain = replace(config, security="none")
    with open_smtp(plain, secret.encode()) as session:
        refused = session.send(build_message(plain, ["team@example.test"], "s", "b", None, now))
    assert (denied.code, denied.retryable, denied.message) == ("smtp_auth", False, "535 at auth")
    assert refused.code == "smtp_not_configured" and capture.connections == 1
    assert [(step.step, step.code) for step in steps][-1] == ("auth", 535)
    leaked = repr(denied) + repr(refused) + repr(steps) + caplog.text
    assert secret not in leaked and "PEER-TEXT-CANARY" not in leaked and "incorrect credential" not in leaked
```

  Also add `test_starttls_delivery_with_a_verified_fixture_ca`, `test_untrusted_server_certificate_is_smtp_tls_and_not_retried` (default `smtp_tls_context(True)`; message is exactly the fixed TLS template, no certificate subject or OpenSSL reason text), `test_missing_starttls_never_downgrades`, `test_implicit_tls_on_ssl_security`, `test_unverified_context_is_explicit` (`smtp_tls_context(False)` has `verify_mode == CERT_NONE` and `check_hostname is False`), `test_unreachable_server_is_transient` (closed port → `connection failed (ECONNREFUSED)`), `test_server_disconnect_reconnects_once`, `test_message_headers` (`Message-ID`, `Date`, `From`, `To`, `Reply-To` from team list, `multipart/alternative` text+HTML), `test_peer_text_in_every_reply_position_is_discarded` (parametrized over `MAIL`/`RCPT`/`DATA` overrides carrying `PEER-TEXT-CANARY`: the canary is absent from the outcome, steps and `caplog`; the codes are kept), `test_steps_are_fixed_names_and_reply_codes_only` (every `SmtpStep` field set is exactly `{step, code}`, `step` is in `SmtpStepName`, `code` is an `int` in 200–599 or `None`; no EHLO extension lines, addresses or text), `test_outcome_messages_come_from_the_fixed_table` (pure: `outcome_message` for every kind, unknown kinds raise `ValueError`, an unknown errno renders `connection failed`), `test_load_smtp_config_defaults_ports_and_reports_unconfigured` (pure, with a stub `get_setting` mapping).
- [x] Run `uv run pytest tests/unit/test_smtp_transport.py -q`; expect FAIL, transport and capture fixture absent.
- [x] Add `aiosmtpd` to the dev dependency group and lock it (`uv lock`); `uv run pip-audit` must stay clean. Implement `smtp.py` with `smtplib.SMTP`/`SMTP_SSL` per Contract decisions 8, 12 and 20: lazy connect on first `send`, `starttls(context=...)` required when security is `starttls` (absent extension → `smtp_tls`), `login` only under TLS with a username and password, then the low-level `mail`/`rcpt`/`data` calls with explicit envelope recipients so every step yields its own reply code (delivered when at least one `RCPT` is accepted and `DATA` returns 250; when every `RCPT` is refused the outcome takes the first refusal's code), and one reconnect after `SMTPServerDisconnected`. Map `socket.timeout`/`OSError`/`SMTPConnectError`/4xx → `smtp_transient`; `SMTPAuthenticationError`/`SMTPNotSupportedError` on AUTH → `smtp_auth`; `ssl.SSLError` → `smtp_tls`; other 5xx → `smtp_rejected`. Each exception is converted at the boundary into `SmtpStep(step, code)` plus an `outcome_message(...)` built only from the integer `smtp_code`, the integer `errno`/`verify_code` and the step name; reply text, `str(exc)`, `exc.args` and `smtp_error` are discarded unread, nothing is logged with `exc_info`, and no exception escapes `send`. The password is decoded only inside the `login` call and never formatted into text, logs or exceptions; `set_debuglevel` stays 0. `build_message` uses `email.message.EmailMessage`, `make_msgid(domain=<sender domain>)`, `formatdate(now.timestamp(), usegmt=True)`. The capture server binds a free loopback port, scripts replies by recipient local part and by `replies=` verb overrides (Contract decision 19; aiosmtpd `AuthResult(success=False, handled=False, message=...)` for AUTH and handler return strings for `MAIL`/`RCPT`/`DATA`), supports STARTTLS/implicit TLS and AUTH via aiosmtpd, counts connections, and in CLI mode writes each message as an `.eml` file under `--spool`.
- [x] Run `uv run pytest tests/unit/test_smtp_transport.py -q`; expect PASS. Run `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [x] Commit: `git add app/services/smtp.py tests/fixtures/smtp_capture.py tests/conftest.py tests/unit/test_smtp_transport.py pyproject.toml uv.lock`; `git commit -m "feat: deliver mail over SMTP with typed code-only outcomes"`.

### Task 5: SMTP "Send test email" through the worker

**Files:** Create: `app/jobs/handlers/smtp_test.py`. Modify: `app/jobs/handlers/__init__.py`, `app/services/smtp.py`, `app/web/settings.py`, `app/templates/settings.html.j2`, `tests/integration/conftest.py`, `tests/integration/test_settings_http.py`. Test: `tests/integration/test_smtp_test_send.py`.

**Size budget:** ≈ 150 production + 230 test lines.

**Interfaces:** Consumes: Task 4 `load_smtp_config`, `open_smtp`, `smtp_tls_context`, `job_error_class`; `enqueue`, `JobFailure`, `User`. Produces: `SMTP_TEST_ACTION = "smtp_test"`; `validate_smtp_test_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]`; `smtp_test(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]` (`{"delivered": True, "recipient": str, "steps": [{"step": SmtpStepName, "code": int | None}, ...]}` — fixed names and integers only); `test_message(config: SmtpConfig, recipient: str, now: datetime) -> EmailMessage` and `transcript_summary(steps: Sequence[SmtpStep]) -> str` (e.g. `connect 220, ehlo 250, starttls 220, auth 535`; built only from `SmtpStep` fields) in `app/services/smtp.py`; `latest_smtp_test(db: Session) -> dict[str, JSONValue] | None` in `app/web/settings.py`; POST `/settings/smtp/test` (declared before `/settings/{tab}`); GET `/settings/smtp/test/{job_id}` (htmx fragment, polls every 2 s while queued/running). Integration fixture `configure_smtp(factory, capture, *, security='none', recipients=(), tls_verify=True, username='')`.

- [x] Write failing tests:

```python
def test_test_email_is_sent_by_the_worker_to_the_signed_in_user(signed_in, worker_harness, web_factory, web_user, smtp_server):
    capture = smtp_server()
    configure_smtp(web_factory, capture)
    response = signed_in.post("/settings/smtp/test", data={"csrf_token": signed_in.fixture_csrf}, follow_redirects=False)
    assert response.status_code == 303 and capture.connections == 0
    worker_harness.run_queued()
    [message] = capture.messages
    assert message["To"] == web_user.email and message["Subject"] == "Cert Dashboard test email"
    page = signed_in.get(response.headers["location"]).text
    assert "Delivered" in page and "250" in page
```

  Also add `test_failed_test_email_reports_the_real_reply_and_is_never_retried` (user e-mail `tempfail@example.test` → job `failed`, class `smtp_transient`, `max_attempts=1`, a later tick does not requeue it, page shows `451 at rcpt`), `test_relay_echoing_the_password_never_leaks_through_the_test_send` (`make_worker(web_factory, smtp_password=b"fixture-smtp-password-123")` — an unlabeled value `redact()` would not catch — capture requiring STARTTLS+AUTH whose `replies={"AUTH": "535 5.7.8 PEER-TEXT-CANARY incorrect credential {password}"}` echoes the received password, `smtp.tls_verify=false`; the job fails `auth` and its message starts with `535 at auth; connect 220` and ends with `auth 535`; neither the password nor `PEER-TEXT-CANARY` appears in the job payload, result, `error_message`, any audit row's details, the SMTP tab and Status HTML, the htmx fragment or `caplog`), `test_smtp_password_never_reaches_payload_result_audit_logs_or_page` (successful AUTH: same searches, steps are exactly `{step, code}` dicts), `test_unsafe_tls_warning_is_visible_when_verification_is_off`, `test_test_send_requires_csrf_and_sign_in`, `test_unconfigured_smtp_fails_with_config_invalid_and_says_why`. Update `tests/integration/test_settings_http.py`: the button is enabled once `(alert_expiry, 'smtp_test')` is registered, and the old "handler alert_expiry/default, digest/default not registered (Plan 2)" expectation is replaced.
- [x] Run `uv run pytest tests/integration/test_smtp_test_send.py tests/integration/test_settings_http.py -q` in CI; expect FAIL, test send unavailable.
- [x] Implement per Contract decision 13. The web route enqueues `{"action": "smtp_test"}` with `ON_DEMAND_PRIORITY`, `max_attempts=1`; the handler resolves the requester's e-mail (no requester → `validation`), builds `test_message` (fixed subject and body, no settings values beyond `From`), sends once, and returns the code-only steps or raises `JobFailure(job_error_class(outcome.code), f"{outcome.message}; {transcript_summary(outcome.steps)}")` (both parts fixed text per Contract decision 20). Gate the button on `unsupported_reason(registry, "Plan 2", (JobType.ALERT_EXPIRY, "smtp_test"))`. The SMTP tab renders the newest `smtp_test` job (status, finished time, steps or error). No `notification_log` row is written for a test.
- [x] Run the same command; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [x] Commit: `git add app/jobs/handlers app/services/smtp.py app/web/settings.py app/templates/settings.html.j2 tests/integration/conftest.py tests/integration/test_settings_http.py tests/integration/test_smtp_test_send.py`; `git commit -m "feat: send SMTP test mail from the worker and report the outcome"`.

### Task 6: Notification ledger and scheduler tick steps

**Files:** Create: `app/services/notifications.py`. Modify: `app/jobs/worker.py`. Test: `tests/unit/test_notification_backoff.py`, `tests/integration/test_notifications.py`.

**Size budget:** ≈ 150 production + 250 test lines.

**Interfaces:** Consumes: `NotificationLog`, `NotificationStatus`, Task 4 `SendOutcome`, `retry_delay_seconds(attempt: int) -> int`, `enqueue`, `SYSTEM_ACTOR`. Produces in `app/services/notifications.py`: `MAX_NOTIFICATION_ATTEMPTS = 3`; `next_attempt_after(attempts: int, now: datetime, retryable: bool) -> datetime | None`; `open_notification(db: Session, *, kind: Literal['expiry','digest'], dedupe_key: str, certificate_id: int | None, threshold_days: int | None, recipients: Sequence[str], now: datetime) -> NotificationLog | None`; `record_attempt(db: Session, row: NotificationLog, outcome: SendOutcome, now: datetime) -> NotificationLog`; `due_retries(db: Session, kind: Literal['expiry','digest'], now: datetime) -> list[NotificationLog]`; `enqueue_notification_retry(db: Session, now: datetime) -> int`. In `app/jobs/worker.py`: `TickStep(name: str, step: Callable[[Session, datetime], int], requires: tuple[JobType, str])`; `TICK_STEPS: dict[str, TickStep]`; `register_tick_step(name: str, step: Callable[[Session, datetime], int], *, requires: tuple[JobType, str]) -> None`; `scheduler_tick` runs registered steps after reap/retry, each in its own transaction, skipping steps whose `requires` is not in the registry and logging failures by class name only.

- [x] Write failing tests:

```python
def test_failed_attempts_back_off_then_stop_at_three(db, previous_certificate, now):
    def attempt(when):
        return open_notification(db, kind="expiry", dedupe_key="expiry:%d:30:2026-10-19" % previous_certificate.id,
            certificate_id=previous_certificate.id, threshold_days=30, recipients=["a@example.test"], now=when)
    transient = SendOutcome(False, "smtp_transient", "451 at rcpt", True)
    row = record_attempt(db, attempt(now), transient, now)
    assert (row.status, row.attempts, row.sent_at, row.last_attempt_at) == ("failed", 1, None, now)
    assert row.next_attempt_at == now + timedelta(seconds=30)
    assert attempt(now + timedelta(seconds=29)) is None
    second = now + timedelta(seconds=30)
    row = record_attempt(db, attempt(second), transient, second)
    assert row.next_attempt_at == second + timedelta(seconds=120)
    third = second + timedelta(seconds=120)
    row = record_attempt(db, attempt(third), transient, third)
    assert (row.attempts, row.next_attempt_at, row.sent_at) == (3, None, None)
    assert attempt(third + timedelta(days=1)) is None
```

  Also add `test_success_sets_sent_at_with_last_attempt_at`, `test_permanent_failure_is_not_rescheduled`, `test_sent_row_is_never_reopened`, `test_concurrent_open_returns_the_row_to_one_session_only` (two `queue_factory` sessions; the second gets `None` while the first holds the lock), `test_error_text_is_redacted_and_bounded`, `test_tick_step_enqueues_one_retry_job_for_due_expiry_rows` (custom registry with a stub `alert_expiry/default`; due row from today → one queued job `{"mode": "retry_failed"}`, priority 100, `scheduled_reason='retry'`, `max_attempts=1`; a second tick adds nothing while it is queued; a due row created yesterday enqueues nothing), `test_tick_steps_are_skipped_without_their_handler`, `test_failing_tick_step_does_not_stop_other_steps`. Unit: `next_attempt_after` ladder (1 → +30 s, 2 → +120 s, 3 → None, non-retryable → None).
- [x] Run `uv run pytest tests/unit/test_notification_backoff.py -q` locally and `uv run pytest tests/integration/test_notifications.py tests/integration/test_worker.py -q` in CI; expect FAIL, ledger and tick steps absent.
- [x] Implement per Contract decisions 7 and 10. `due_retries` selects `status='failed' AND attempts BETWEEN 1 AND 2 AND next_attempt_at <= now AND created_at >= <UTC midnight of now>` ordered by id `FOR UPDATE SKIP LOCKED`. Register `register_tick_step("notification_retry", enqueue_notification_retry, requires=(JobType.ALERT_EXPIRY, "default"))` at module level in `worker.py` (inert until Task 8 registers the handler). Plan 3 reuses `register_tick_step` for its paused-deploy sweep.
- [x] Run the same commands; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [x] Commit: `git add app/services/notifications.py app/jobs/worker.py tests/unit/test_notification_backoff.py tests/integration/test_notifications.py`; `git commit -m "feat: track bounded notification attempts and sweep due retries"`.

### Task 7: Expiry evaluation, recipients and message rendering

**Files:** Create: `app/services/alerts.py`, `app/templates/email/expiry.txt.j2`, `app/templates/email/expiry.html.j2`. Modify: `app/config.py`, `docker-compose.yml`, `tests/unit/test_config.py`. Test: `tests/unit/test_expiry_rules.py`, `tests/integration/test_expiry_evaluation.py`.

**Size budget:** ≈ 220 production + 260 test lines.

**Interfaces:** Consumes: ORM `Certificate`, `Binding`, `Server`, `Renewal`, `NotificationLog`; `get_setting`; `ui.timezone` validated with `ZoneInfo` and falling back to UTC (the same rule as `app.web.common.display_timezone`, re-implemented in the service so services never import web modules). Produces in `app/services/alerts.py`: `ExpiryCandidate(certificate_id: int, threshold_days: int, days_remaining: int, dedupe_key: str, recipients: tuple[str, ...])`; `crossed_threshold(not_after: datetime, now: datetime, thresholds: Sequence[int]) -> int | None`; `expiry_dedupe_key(certificate_id: int, threshold_days: int, now: datetime) -> str`; `resolve_recipients(owner_email: str | None, team: Sequence[str]) -> tuple[str, ...]`; `due_expiry_alerts(db: Session, now: datetime) -> list[ExpiryCandidate]`; `RenderedMail(subject: str, text: str, html: str)`; `email_environment() -> jinja2.Environment`; `render_expiry(db: Session, candidate: ExpiryCandidate, now: datetime, base_url: str | None) -> RenderedMail`. In `app/config.py`: `Settings.dashboard_url: str | None = None`, loaded from `DASHBOARD_URL`.

- [x] Write failing pure tests in `tests/unit/test_expiry_rules.py`:

```python
@pytest.mark.parametrize(("remaining", "expected"), [
    (timedelta(days=61), None), (timedelta(days=60), 60), (timedelta(days=29), 30),
    (timedelta(days=6, hours=23), 7), (timedelta(hours=5), 1), (timedelta(0), 0), (-timedelta(days=3), 0)])
def test_smallest_crossed_threshold_wins(now, remaining, expected):
    assert crossed_threshold(now + remaining, now, [60, 30, 14, 7, 1, 0]) == expected

def test_recipients_are_owner_first_and_deduplicated():
    assert resolve_recipients("Owner@Example.test", ["team@example.test", "owner@example.test"]) == (
        "Owner@Example.test", "team@example.test")
    assert resolve_recipients(None, ["team@example.test"]) == ("team@example.test",)
    assert resolve_recipients("", []) == ()

def test_dedupe_key_uses_the_utc_run_date(now):
    assert expiry_dedupe_key(42, 30, now.astimezone(ZoneInfo("Pacific/Kiritimati"))) == "expiry:42:30:2026-10-19"
```

  Also unit-test `DASHBOARD_URL` loading in `tests/unit/test_config.py` (empty → None; `https://certs.example.internal/` accepted; userinfo, query, fragment, non-http scheme → `ConfigurationError` naming the variable, never echoing the value).
- [x] Write failing DB tests in `tests/integration/test_expiry_evaluation.py`: `test_due_alerts_cover_the_window_and_skip_already_sent_thresholds` (active certificates at 29 d → 30, 6 d → 7, −3 d → 0, 90 d excluded, −90 d excluded, superseded/revoked excluded; a `sent` row for `(cert, 30)` on an earlier day suppresses it, a `failed` one does not), `test_rendered_expiry_contains_every_required_fact` (CN, SAN count, issuer, serial, `not_after` in `ui.timezone` and UTC, "expires in 29 days", active bindings `host vhost:port`, renewal state of the newest non-cancelled renewal, `<base_url>/certificates/<id>` and `/renewals/<id>` links), `test_rendering_escapes_html_and_works_without_base_url` (CN/notes with `<script>` escaped in HTML; relative paths without `DASHBOARD_URL`), `test_owner_and_team_resolution_uses_alert_recipients`.
- [x] Run `uv run pytest tests/unit/test_expiry_rules.py tests/unit/test_config.py -q` locally and `uv run pytest tests/integration/test_expiry_evaluation.py -q` in CI; expect FAIL, alert evaluation absent.
- [x] Implement per Contract decisions 6 and 14. `crossed_threshold` returns the minimum `T` with `not_after - now <= timedelta(days=T)`. `due_expiry_alerts` uses one query over active certificates in the window plus one anti-join on sent expiry rows (no per-certificate queries) and attaches resolved recipients. Days remaining displayed = `floor((not_after - now) / 1 day)`, "has expired" when negative. Bindings list is capped at 50 with "+N more". The text template is plain; the HTML template is minimal, inline-styled and autoescaped. Add `DASHBOARD_URL: ${DASHBOARD_URL:-}` to the worker environment in `docker-compose.yml`.
- [x] Run the same commands; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [x] Commit: `git add app/services/alerts.py app/templates/email app/config.py docker-compose.yml tests/unit/test_expiry_rules.py tests/unit/test_config.py tests/integration/test_expiry_evaluation.py`; `git commit -m "feat: evaluate expiry thresholds and render alert mail"`.

### Task 8: `alert_expiry/default` job — idempotent delivery and retries

**Files:** Create: `app/jobs/handlers/expiry.py`. Modify: `app/jobs/handlers/__init__.py`, `app/jobs/worker.py`, `tests/integration/conftest.py`. Test: `tests/integration/test_expiry_alerts.py`.

**Size budget:** ≈ 130 production + 300 test lines.

**Interfaces:** Consumes: Task 4 transport, Task 6 ledger, Task 7 evaluation/rendering, `RETRY_POLICY`. Produces: `validate_expiry_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]` (`{}` or `{"mode": "retry_failed"}`); `expiry_check(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]` returning `{"evaluated","sent","failed","no_recipients","skipped"}`; registration `(JobType.ALERT_EXPIRY, 'default')`; `register_schedule("expiry_check", JobType.ALERT_EXPIRY)`. Integration fixture `expiring(factory, days, **metadata) -> Certificate` (issued by the session `ca`, unique CN per call).

- [ ] Write failing tests on the private `queue_factory` database with `make_worker(queue_factory)` (spec §10.2 scenario 11):

```python
def test_29_days_out_sends_the_30_day_alert_exactly_once(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture, recipients=["team@example.test"])
    certificate = expiring(queue_factory, days=29, owner_email="owner@example.test")
    worker = make_worker(queue_factory)
    for advance in ({}, {"hours": 1}, {"days": 1}):
        clock.advance(**advance)
        run_expiry(queue_factory, worker, clock())
    [message] = capture.messages
    assert message["To"] == "owner@example.test, team@example.test"
    assert "expires in 29 days" in message.get_body(("plain",)).get_content()
    row = only_notification(queue_factory, certificate.id)
    assert (row.status, row.threshold_days, row.attempts, row.error) == ("sent", 30, 1, None)
    assert row.sent_at == row.last_attempt_at
```

  Also add `test_several_crossed_thresholds_send_one_mail_at_the_smallest`, `test_expired_certificate_gets_the_zero_day_alert_once`, `test_no_recipients_is_recorded_without_sending`, `test_unconfigured_smtp_records_failures_and_fails_the_job_config_invalid` (rows `failed` with `smtp_not_configured`, job not retried), `test_partial_failure_succeeds_the_job_and_the_sweep_retries_the_row` (one owner `tempfail@…`: job `succeeded`; ticks at +31 s and +121 s each enqueue and run one `retry_failed` job; the row ends `failed` with `attempts=3`, `sent_at` NULL and is never attempted again), `test_total_transient_failure_fails_the_job_for_queue_retry` (closed port → job `failed` `smtp_transient`; start the capture on that port, tick +31 s → retry delivers; row `sent`, `attempts=2`), `test_next_days_key_takes_over_after_three_failures`, `test_notification_errors_hold_reply_codes_not_peer_text` (capture with `replies={"RCPT": "451 4.3.0 PEER-TEXT-CANARY fixture-smtp-password-123"}` and the worker's `smtp_password` set to that unlabeled value: `notification_log.error == "smtp_transient: 451 at rcpt"`; the canary and the password are absent from every `notification_log` row, the job `error_message`/result, audit details and `caplog`), `test_scheduled_expiry_check_runs_at_its_daily_time` (07:00:30 tick → priority 100, `scheduled_reason='daily'`; `expiry_check.enabled=false` → nothing).
- [ ] Run `uv run pytest tests/integration/test_expiry_alerts.py tests/integration/test_worker.py -q` in CI; expect FAIL, handler unregistered.
- [ ] Implement per Contract decisions 7–10. The handler loads thresholds/config/candidates in a short transaction, opens one `open_smtp` session (password from `context.settings.smtp_password`, context `smtp_tls_context(config.tls_verify)`), then per candidate opens a transaction: `open_notification` (skip when `None`), `no_recipients`/`smtp_not_configured` outcomes recorded without contacting SMTP, otherwise `render_expiry` + `session.send`, `record_attempt`, commit. Mode `retry_failed` iterates `due_retries(db, 'expiry', now)` and re-renders each row's certificate with its stored threshold and recipients. Apply Contract decision 9 for the job outcome (never in `retry_failed` mode). Results are counts only. The `notification_retry` tick step from Task 6 becomes live once this handler is registered.
- [ ] Run the same command; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [ ] Commit: `git add app/jobs/handlers app/jobs/worker.py tests/integration/conftest.py tests/integration/test_expiry_alerts.py`; `git commit -m "feat: send idempotent expiry alerts with bounded retries"`.

### Task 9: Digest collection — transitions since the last digest

**Files:** Create: `app/services/bindings.py`, `app/services/digest.py`. Modify: `tests/integration/conftest.py`. Test: `tests/integration/test_digest_collect.py`.

**Size budget:** ≈ 220 production + 320 test lines.

**Interfaces:** Consumes: `record(db: Session, actor: Actor, action: str, target_type: str, target_id: str | None, details: Mapping[str, JSONValue]) -> AuditLog`, `Actor`, `SYSTEM_ACTOR`, ORM `Certificate`, `Endpoint`, `ScanResult`, `Binding`, `Server`, `Job`, `JobHost`, `NotificationLog`, `AuditLog`. Produces in `app/services/bindings.py`: `BINDING_STATE_ACTION = "binding.match_state"`; `BindingState(match_state: str, on_disk_fingerprint: str | None, is_active: bool)` (frozen); `binding_state(binding: Binding) -> BindingState`; `audit_binding_state(db: Session, binding: Binding, previous: BindingState | None, actor: Actor, *, job_id: str | None, now: datetime) -> AuditLog | None` (`previous=None` means the binding was just inserted; the binding must be flushed; returns `None` and writes nothing when `binding_state(binding) == previous`; stamps `created_at=now` so audit times share the worker clock with `notification_log.sent_at`). In `app/services/digest.py`: frozen row types `DigestCertificate(id: int, common_name: str, not_after: datetime, days_remaining: int, owner: str | None)`, `DigestEndpoint(id: int, host: str, port: int, sni: str | None, expected_common_name: str | None, observed_common_name: str | None, observed_fingerprint: str | None, previous_status: str | None, current_status: str | None, checked_at: datetime)`, `DigestBinding(binding_id: int, server: str, vhost_name: str, port: int, cert_path: str, on_disk_fingerprint: str | None, previous_state: str | None, found_at: datetime)`, `DigestServer(hostname: str, last_discovery_status: str | None, last_discovery_at: datetime | None)`, `DigestJob(id: str, type: str, error_class: str | None, finished_at: datetime)`, `DigestHost(job_id: str, hostname: str, rolled_back: bool, rollback_error: str | None, finished_at: datetime | None)`, `DigestNotification(kind: str, certificate_id: int | None, threshold_days: int | None, attempts: int, error: str | None, last_attempt_at: datetime | None)`; `DigestData(generated_at: datetime, since: datetime, expiring: list[DigestCertificate], expired: list[DigestCertificate], new_mismatches: list[DigestEndpoint], mismatch_count: int, unknown_certificates: list[DigestBinding], stale_servers: list[DigestServer], failed_jobs: list[DigestJob], rolled_back_hosts: list[DigestHost], failed_notifications: list[DigestNotification], inventory_rev: str | None, inventory_rev_date: datetime | None, totals: dict[str, int])` (`totals` holds the uncapped count per list section); `DIGEST_LIST_LIMIT = 50`; `digest_since(db: Session, now: datetime) -> datetime`; `new_mismatches(db: Session, since: datetime, limit: int = DIGEST_LIST_LIMIT) -> tuple[list[DigestEndpoint], int]`; `new_unknown_bindings(db: Session, since: datetime, limit: int = DIGEST_LIST_LIMIT) -> tuple[list[DigestBinding], int]`; `collect_digest(db: Session, now: datetime) -> DigestData`; `digest_dedupe_key(now: datetime) -> str`. Plain helper functions added to `tests/integration/conftest.py` (reused by Task 10): `add_endpoint`, `add_results(db, endpoint_id, [(checked_at, status), ...])` (inserts `scan_result` rows and sets `endpoint.last_scan_*` to the newest), `add_server`, `add_binding(db, server, vhost, *, match_state, fingerprint, at)` (inserts with `created_at=last_seen_at=at`) and `reconcile(db, binding, *, at, match_state=..., fingerprint=..., is_active=...)`, both of which go through `audit_binding_state` exactly as Plan 3's reconciliation will.

- [ ] Write failing DB tests in `tests/integration/test_digest_collect.py` (rollback `db` fixture; all timestamps explicit):

```python
def test_new_mismatch_predecessor_is_computed_across_the_cutoff(db, now):
    since = now - timedelta(hours=24)
    before, after = since - timedelta(hours=1), since + timedelta(hours=1)
    repeat, flipped, first, blip, healed = (add_endpoint(db, f"{name}.example.internal")
        for name in ("repeat", "flipped", "first", "blip", "healed"))
    add_results(db, repeat, [(before, "mismatch"), (after, "mismatch")])        # mismatch across cutoff: repeat
    add_results(db, flipped, [(before, "ok"), (after, "mismatch")])             # ok -> mismatch across cutoff: new
    add_results(db, first, [(after, "mismatch")])                               # first observation: new
    add_results(db, blip, [(before - timedelta(hours=1), "mismatch"), (before, "unreachable"), (after, "mismatch")])
    add_results(db, healed, [(before, "ok"), (after, "mismatch"), (after + timedelta(hours=1), "ok")])
    items, total = new_mismatches(db, since)
    assert {item.id: item.previous_status for item in items} == {flipped: "ok", first: None, healed: "ok"}
    assert total == 3 and {item.id: item.current_status for item in items}[healed] == "ok"
    assert collect_digest(db, now).mismatch_count == 4  # repeat, flipped, first, blip are mismatching now

def test_unknown_certificates_follow_binding_transitions_across_the_cutoff(db, now):
    since = now - timedelta(hours=24)
    long_ago, after = since - timedelta(days=10), since + timedelta(hours=1)
    server = add_server(db, "web01.example.internal")
    old_matched = add_binding(db, server, "a.example.internal", match_state="matched", fingerprint="a" * 64, at=long_ago)
    old_unknown = add_binding(db, server, "b.example.internal", match_state="unknown", fingerprint="b" * 64, at=long_ago)
    swapped = add_binding(db, server, "c.example.internal", match_state="unknown", fingerprint="c" * 64, at=long_ago)
    reconcile(db, old_matched, match_state="unknown", fingerprint="d" * 64, at=after)  # matched -> unknown: new
    assert reconcile(db, old_unknown, match_state="unknown", fingerprint="b" * 64, at=after) is None  # repeat
    reconcile(db, swapped, match_state="unknown", fingerprint="e" * 64, at=after)      # another unknown cert: new
    fresh = add_binding(db, server, "f.example.internal", match_state="unknown", fingerprint="f" * 64, at=after)
    items, total = new_unknown_bindings(db, since)
    assert {item.binding_id: item.previous_state for item in items} == {
        old_matched.id: "matched", swapped.id: "unknown", fresh.id: None}
    assert total == 3 and all(item.found_at == after for item in items)
    assert old_matched.created_at < since  # creation time alone would have hidden it
```

  Also add `test_unknown_round_trips_inside_the_window_are_not_new` (`unknown → missing_file → unknown` with the same fingerprint after the cutoff is not listed; `matched → unknown → matched` after the cutoff is not listed; a binding deactivated before the cutoff and reactivated as `unknown` after it is listed), `test_audit_binding_state_writes_only_on_change` (insert → one `binding.match_state` row with `from_state` NULL; same triple → `None`, no row; `is_active` flip → row; details keys are exactly `from_state`, `from_fingerprint`, `was_active`, `to_state`, `on_disk_fingerprint`, `is_active`, `server_id`, `job_id`; a `notes` value `password=fixture-secret` is never copied; `created_at == now`), `test_collect_digest_reports_the_seeded_world` (certificates at 3 d and −2 d, superseded/revoked excluded; servers with `last_discovery_status='failed'`, one discovered 49 h ago, one never, one healthy excluded, inactive excluded; a failed scan job and a deploy `job_host` with `rolled_back=true` plus one with `rollback_error` finished in the last 24 h, older ones excluded; a failed expiry row with `attempts=3`; a succeeded discover job whose result holds `inventory_rev`/`inventory_rev_date`; `totals` match the seeded counts), `test_lists_are_capped_but_totals_are_not` (55 new mismatches → 50 items, `totals["new_mismatches"] == 55`), and `test_since_is_the_last_sent_digest_or_24_hours` (no sent digest row → `now − 24 h`; a failed digest row is ignored; the newest sent row's `sent_at` wins).
- [ ] Run `uv run pytest tests/integration/test_digest_collect.py -q` in CI; expect FAIL, collection absent. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [ ] Implement per Contract decisions 11, 21 and 22. Each section is one bounded query (lists capped at `DIGEST_LIST_LIMIT`, totals uncapped):
  - **New mismatches:** `SELECT DISTINCT ON (r.endpoint_id) …` over `scan_result r JOIN endpoint e` (active endpoints) with `r.status = 'mismatch' AND r.checked_at > :since`, and `LEFT JOIN LATERAL (SELECT p.status FROM scan_result p WHERE p.endpoint_id = r.endpoint_id AND p.status IN ('ok','mismatch','expired') AND (p.checked_at, p.id) < (r.checked_at, r.id) ORDER BY p.checked_at DESC, p.id DESC LIMIT 1) prev ON true`, keeping rows where `prev.status IS DISTINCT FROM 'mismatch'`, ordered `r.endpoint_id, r.checked_at DESC, r.id DESC`. The predecessor lookup is deliberately **not** restricted to `checked_at > since`; the outer filter uses `ix_scan_result_status_checked` and the lateral uses `ix_scan_result_endpoint_checked`. `previous_status` is `prev.status`, `current_status` is `endpoint.last_scan_status`; the expected certificate's CN comes from the result's snapshotted `expected_certificate_id`.
  - **Current mismatch count:** active endpoints with `last_scan_status = 'mismatch'`.
  - **Unknown certificates:** one statement grouping `audit_log` rows with `action = 'binding.match_state' AND target_type = 'binding' AND created_at > :since` by `target_id`, joined to `binding b ON b.id::text = target_id` (never casting audit text to an integer) and `server`; keep groups where `b.is_active AND b.match_state = 'unknown'`, `bool_or(details->>'to_state' = 'unknown' AND details->>'on_disk_fingerprint' IS NOT DISTINCT FROM b.on_disk_fingerprint)`, and the earliest row's `from_*` triple (`(array_agg(details ORDER BY created_at))[1]`) is not `('unknown', b.on_disk_fingerprint, true)`; `found_at` is the newest matching row's `created_at`, `previous_state` the earliest row's `from_state`. Reconciliation audits a binding at most once per discovery run, so equal `created_at` values for one binding do not occur.
  - **Stale servers:** active servers with `last_discovery_status IN ('failed','unreachable')` or `last_discovery_at` NULL or older than 48 h. **Failed jobs:** `status = 'failed'` finished in the last 24 h. **Rolled-back hosts:** `job_host` rows with `rolled_back` or `rollback_error` finished in 24 h (rollback failures are flagged "needs manual attention" by the template). **Failed notifications:** `notification_log` rows with `status = 'failed'` and `last_attempt_at` in the last 24 h. **Inventory revision:** result keys `inventory_rev`/`inventory_rev_date` of the newest succeeded `discover`/`deploy` job (written by Plan 3; `None` until then).
  - `audit_binding_state` builds details only from the binding's state fields, `server_id` and `job_id` through `record(...)`, then sets `created_at = now` on the staged row; it never flushes or commits.
- [ ] Run the same commands; expect PASS.
- [ ] Commit: `git add app/services/bindings.py app/services/digest.py tests/integration/conftest.py tests/integration/test_digest_collect.py`; `git commit -m "feat: collect digest sections against the state at the last digest"`.

### Task 10: `digest/default` — the daily digest job and mail

**Files:** Create: `app/jobs/handlers/digest.py`, `app/templates/email/digest.txt.j2`, `app/templates/email/digest.html.j2`. Modify: `app/services/digest.py`, `app/jobs/handlers/__init__.py`, `app/jobs/worker.py`. Test: `tests/unit/test_digest_render.py`, `tests/integration/test_digest.py`.

**Size budget:** ≈ 150 production + 240 test lines.

**Interfaces:** Consumes: Task 9 `collect_digest`, `digest_dedupe_key`, `DigestData`; Tasks 4/6/7 (`load_smtp_config`, `open_smtp`, `smtp_tls_context`, `job_error_class`, `open_notification`, `record_attempt`, `email_environment`, `RenderedMail`, `resolve_recipients`). Produces in `app/services/digest.py`: `render_digest(data: DigestData, timezone_name: str, base_url: str | None) -> RenderedMail`. In `app/jobs/handlers/digest.py`: `validate_digest_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]` (`{}` only); `send_digest(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]` (counts only); registration `(JobType.DIGEST, 'default')`; `register_schedule("digest", JobType.DIGEST)` (time `digest.daily_at`; enabled `alert.digest_enabled`, already mapped in Plan 1's `_ENABLED_SETTING`; priority 50).

- [ ] Write failing tests:

```python
def test_empty_digest_is_still_a_daily_heartbeat(queue_factory, make_worker, smtp_server, clock):
    capture = smtp_server()
    configure_smtp(queue_factory, capture, recipients=["team@example.test"])
    worker = make_worker(queue_factory)
    run_digest(queue_factory, worker, clock())
    run_digest(queue_factory, worker, clock() + timedelta(hours=2))
    [message] = capture.messages
    assert message["Subject"].startswith("Cert Dashboard daily digest")
    text = message.get_body(("plain",)).get_content()
    assert "Nothing to report" in text and "Inventory revision: none recorded" in text
    assert job_results(queue_factory, JobType.DIGEST)[0] == {"delivered": True, "expiring": 0, "expired": 0,
        "new_mismatches": 0, "mismatches": 0, "unknown_certificates": 0, "stale_servers": 0,
        "failed_jobs": 0, "rolled_back_hosts": 0, "failed_notifications": 0}
```

  Also add `test_digest_mail_lists_the_new_and_repeat_signals` (seed through Task 9's helpers: one endpoint `ok → mismatch` after the last sent digest and one mismatching across the cutoff; one old `matched` binding reconciled to `unknown` after the cutoff and one repeat unknown; the mail lists the first of each pair under "New TLS mismatches" / "Unknown certificates found by discovery", shows "Current mismatches: 2", and does not list the repeats), `test_second_digest_uses_the_first_digests_sent_at` (run, advance a day, seed one new transition, run again: only the new transition is listed), `test_transient_failure_retries_the_job_and_reuses_the_days_row` (closed port → `smtp_transient`, retry delivers, one row with `attempts=2`), `test_empty_team_list_records_no_recipients`, `test_disabled_digest_schedule_enqueues_nothing`, `test_scheduled_digest_has_priority_50` (07:30:30 tick → priority 50, `scheduled_reason='daily'`). Unit (`tests/unit/test_digest_render.py`): rendering a hand-built `DigestData` lists every section heading, shows "showing 50 of 55" when a total exceeds its list, escapes HTML in hostnames/CNs, shows times in the display zone and UTC, flags rollback failures as "needs manual attention", and its result counts pass `redact()` unchanged.
- [ ] Run `uv run pytest tests/unit/test_digest_render.py -q` locally and `uv run pytest tests/integration/test_digest.py -q` in CI; expect FAIL, digest job absent.
- [ ] Implement per Contract decisions 7, 8, 11 and 20. The handler collects the data in a short transaction (`collect_digest(db, context.clock())`), renders it with `ui.timezone` and `context.settings.dashboard_url`, then in one transaction opens the day's row (`open_notification(kind='digest', dedupe_key=digest_dedupe_key(now), certificate_id=None, threshold_days=None, recipients=resolve_recipients(None, alert.recipients))`; `None` → nothing to do, result counts with `delivered: False`), records `no_recipients`/`smtp_not_configured` without contacting SMTP, otherwise sends once through `open_smtp`, `record_attempt`, commit. A transient failure raises `JobFailure("smtp_transient", outcome.message, retryable=True)` after the attempt is committed so the queue retries the job; other failures raise the mapped non-retryable class. Result keys are exactly the counts in the test above (from `totals`, never the dedupe key — Contract decision 11). Register the handler and the schedule in `build_registry()`/`worker.py`.
- [ ] Run the same commands; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [ ] Commit: `git add app/services/digest.py app/jobs/handlers app/jobs/worker.py app/templates/email tests/unit/test_digest_render.py tests/integration/test_digest.py`; `git commit -m "feat: send the daily digest with operational sections"`.

### Task 11: Settings — delivery failures and SMTP status

**Files:** Modify: `app/services/settings.py`, `app/web/settings.py`, `app/templates/settings.html.j2`, `tests/integration/test_settings_http.py`. Test: `tests/integration/test_settings_alerts_status.py`.

**Size budget:** ≈ 130 production + 200 test lines.

**Interfaces:** Consumes: `NotificationLog`, `Job`, Task 5 `latest_smtp_test`, `status_snapshot(db: Session, keyring: Keyring, now: datetime, *, keyring_sha256: str | None = None) -> dict[str, JSONValue]`. Produces in `app/services/settings.py`: `NotificationFailureView(id: int, kind: str, certificate_id: int | None, threshold_days: int | None, recipients: tuple[str, ...], attempts: int, last_attempt_at: datetime | None, next_attempt_at: datetime | None, error: str | None)`; `notification_failures(db: Session, limit: int = 50) -> list[NotificationFailureView]`; `smtp_health(db: Session) -> dict[str, JSONValue]` (`consecutive_failures`, `last_error`, `last_success_at`, `last_test`); `status_snapshot` gains key `smtp` and warnings `smtp_failing` (≥ 1 consecutive failure) and `smtp_tls_unverified` (`smtp.tls_verify=false`).

- [ ] Write failing tests:

```python
def test_status_shows_consecutive_failures_and_the_last_error(signed_in, web_factory, now):
    seed_notifications(web_factory, now, ["sent", "failed", "failed"])
    page = signed_in.get("/settings?tab=status").text
    assert "2 consecutive delivery failures" in page and "smtp_transient: 451" in page
    assert "Send a test email" in page

def test_alerts_tab_lists_recent_failures_with_attempts(signed_in, web_factory, now):
    seed_notifications(web_factory, now, ["failed"])
    page = signed_in.get("/settings?tab=alerts").text
    assert "attempt 1 of 3" in page and "next attempt" in page
```

  Also assert `consecutive_failures` resets at the newest `sent` row (ordering by `last_attempt_at DESC, id DESC`), `no_recipients` rows count as failures but `smtp_test` jobs do not, the last test result reflects the newest `smtp_test` job only, failure rows link to the certificate, escaped error text, and the JSON-native snapshot (existing Status assertions in `tests/integration/test_settings_http.py` updated for the new `smtp` key and warnings).
- [ ] Run `uv run pytest tests/integration/test_settings_alerts_status.py tests/integration/test_settings_http.py -q` in CI; expect FAIL, signals absent.
- [ ] Implement as read-only queries (one per panel, bounded); no settings key or mutation is added. Status warning texts: "Recent alert or digest mail could not be delivered." and "SMTP TLS certificate verification is disabled (unsafe)."
- [ ] Run the same command; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [ ] Commit: `git add app/services/settings.py app/web/settings.py app/templates/settings.html.j2 tests/integration/test_settings_http.py tests/integration/test_settings_alerts_status.py`; `git commit -m "feat: show alert delivery failures and SMTP health in settings"`.

### Task 12: Scan results screen (`/scans`)

**Files:** Create: `app/services/endpoints.py`, `app/web/scans.py`, `app/templates/scans/list.html.j2`, `app/templates/scans/detail.html.j2`. Modify: `app/main.py`, `tests/integration/conftest.py`, `tests/integration/test_inventory_http.py`. Test: `tests/integration/test_scans_http.py`.

**Size budget:** ≈ 260 production + 240 test lines.

**Interfaces:** Consumes: Task 2 `request_scan`, `ScanRequestError`; `display_timezone`, `time_tag`, `render_block`, `unsupported_reason`. Produces in `app/services/endpoints.py`: `EndpointFilters(status: ScanStatus | None = None, server_id: int | None = None, certificate_id: int | None = None, group: str | None = None, search: str | None = None, active: bool | None = True)`; `EndpointRow(id: int, host: str, port: int, sni: str | None, source: str, is_active: bool, server: str | None, expected_certificate_id: int | None, expected_common_name: str | None, expected_fingerprint: str | None, status: str | None, checked_at: datetime | None, observed_fingerprint: str | None, observed_common_name: str | None, observed_issuer_cn: str | None, observed_not_after: datetime | None, observed_chain_length: int | None, tls_version: str | None, error: str | None)`; `EndpointPage(items: list[EndpointRow], total: int, page: int, page_size: int)`; `list_endpoints(db: Session, filters: EndpointFilters, page: int = 1, page_size: int = 50, sort: str = 'status') -> EndpointPage`; `EndpointDetail(row: EndpointRow, history: list[ScanResult], observed_certificate_id: int | None)`; `endpoint_detail(db: Session, endpoint_id: int, history_limit: int = 20) -> EndpointDetail`; `export_endpoints(db: Session, filters: EndpointFilters, limit: int = 5000) -> list[dict[str, JSONValue]]`; `ENDPOINT_EXPORT_FIELDS` (exactly the `EndpointRow` field names). Routes GET `/scans`, `/scans/export.json`, `/scans/{endpoint_id}`, `/scans/{endpoint_id}/history` (htmx drawer fragment); POST `/scans/run` (`scope=all|endpoint`, `endpoint_id`). Integration fixtures `count_statements(engine)` and `scan_world`.

- [ ] Write failing tests:

```python
def test_scans_list_filters_paginates_and_exports_allowlisted_fields(signed_in, scan_world):
    page = signed_in.get(f"/scans?status=mismatch&server_id={scan_world.server_id}&sort=host&page=1&page_size=10")
    assert page.status_code == 200
    assert scan_world.mismatch_host in page.text and scan_world.ok_host not in page.text
    exported = signed_in.get("/scans/export.json?status=mismatch").json()
    assert exported and all(set(row) == set(ENDPOINT_EXPORT_FIELDS) for row in exported)
    assert all(row["status"] == "mismatch" for row in exported)

def test_history_shows_the_last_twenty_results_and_explains_a_mismatch(signed_in, scan_world):
    drawer = signed_in.get(f"/scans/{scan_world.mismatch_id}/history", headers={"HX-Request": "true"})
    assert drawer.text.count('class="scan-history-row"') == 20
    detail = signed_in.get(f"/scans/{scan_world.mismatch_id}").text
    assert scan_world.expected_fingerprint in detail and scan_world.served_fingerprint in detail
    assert "Renew and deploy" in detail and "update the expectation" in detail
```

  Also add `test_every_filter_and_sort_is_whitelisted` (status, server, certificate, group via `ansible_groups`, search on host/SNI, `active=all`; unknown sort/page_size 0/101 → 422), `test_list_query_count_is_independent_of_rows` (`count_statements` for 5 vs 50 endpoints), `test_scan_now_and_scan_all_enqueue_without_connecting` (POST scope endpoint → 303 to `/scans/{id}`, scope all → 303 to `/scans`; priority 200; CSRF required; unknown id → 404), `test_scans_navigation_is_enabled_when_the_handler_is_registered` (update the Plan 1 expectation in `tests/integration/test_inventory_http.py`), `test_unreachable_and_error_rows_show_the_sanitized_error`, `test_pages_escape_hostile_values_and_require_sign_in`.
- [ ] Run `uv run pytest tests/integration/test_scans_http.py tests/integration/test_inventory_http.py -q` in CI; expect FAIL, screen absent.
- [ ] Implement. The latest result per endpoint comes from one `LEFT JOIN LATERAL (… ORDER BY checked_at DESC, id DESC LIMIT 1)` (or `DISTINCT ON`) over `ix_scan_result_endpoint_checked`; expected certificate and server are joined, never lazily loaded. Default sort puts `expired`, `mismatch`, `unreachable`, `error` first, then never-scanned, then `ok` (§7.3 "expired takes precedence ... in the UI ordering"). The mismatch explanation names the expected and served certificates, links the served one when its fingerprint is in inventory, and lists the likely actions: renew/deploy, import the served certificate from this endpoint (link to `/certificates/import` with host/port/SNI prefilled), or update the expectation (Task 13). Navigation: `("Scans", "/scans", registry.supports(JobType.SCAN), scan_reason)`. Scan buttons are gated on `(scan, 'default')`.
- [ ] Run the same command; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [ ] Commit: `git add app/services/endpoints.py app/web/scans.py app/templates/scans app/main.py tests/integration/conftest.py tests/integration/test_inventory_http.py tests/integration/test_scans_http.py`; `git commit -m "feat: browse endpoint scan results and history"`.

### Task 13: Endpoint management and the certificate scan panel

**Files:** Modify: `app/services/endpoints.py`, `app/services/scans.py`, `app/services/certificates.py`, `app/web/scans.py`, `app/templates/scans/list.html.j2`, `app/templates/scans/detail.html.j2`, `app/templates/certificates/detail.html.j2`, `tests/integration/test_inventory_http.py`. Test: `tests/integration/test_endpoints_http.py`.

**Size budget:** ≈ 210 production + 260 test lines.

**Interfaces:** Consumes: `canonical_host(value: object) -> str` and the existing SNI rule in `app/services/scans.py`, `record`, Task 12 read models. Produces in `app/services/scans.py`: `EndpointInputError(ValueError)` with `errors: dict[str, str]`; `validate_endpoint_target(host: object, port: object, sni: object) -> tuple[str, int, str | None]`. In `app/services/endpoints.py`: `create_endpoint(db: Session, host: str, port: int, sni: str | None, expected_certificate_id: int | None, actor: Actor) -> Endpoint`; `set_expectation(db: Session, endpoint_id: int, certificate_id: int, actor: Actor) -> Endpoint`; `expect_observed(db: Session, endpoint_id: int, actor: Actor) -> Endpoint`; `set_endpoint_active(db: Session, endpoint_id: int, active: bool, actor: Actor) -> Endpoint`. `EndpointView` gains `id: int`. Routes POST `/scans/endpoints`, `/scans/{endpoint_id}/expectation` (`certificate_id` or `use_observed=1`), `/scans/{endpoint_id}/active` (`active=true|false`).

- [ ] Write failing tests:

```python
def test_update_the_expectation_to_the_observed_certificate(signed_in, web_factory, scan_world):
    response = signed_in.post(f"/scans/{scan_world.mismatch_id}/expectation",
        data={"use_observed": "1", "csrf_token": signed_in.fixture_csrf}, follow_redirects=False)
    assert response.status_code == 303
    endpoint = fetch(web_factory, Endpoint, scan_world.mismatch_id)
    assert endpoint.expected_certificate_id == scan_world.served_certificate_id
    audit = last_audit(web_factory, "endpoint", scan_world.mismatch_id)
    assert audit.action == "endpoint.update" and audit.details["to"] == scan_world.served_certificate_id

def test_manual_endpoint_entry_validates_and_audits(signed_in, web_factory, scan_world):
    bad = signed_in.post("/scans/endpoints", data={"host": "https://x/", "port": "0", "sni": "*.x",
        "csrf_token": signed_in.fixture_csrf}, headers={"HX-Request": "true"})
    assert bad.status_code == 422 and {"host", "port", "sni"} <= set(re.findall(r'data-error="(\w+)"', bad.text))
    good = signed_in.post("/scans/endpoints", data={"host": "API.Example.Internal", "port": "8443", "sni": "",
        "expected_certificate_id": str(scan_world.served_certificate_id), "csrf_token": signed_in.fixture_csrf},
        follow_redirects=False)
    assert good.status_code == 303
    created = endpoint_by(web_factory, "api.example.internal", 8443)
    assert created.source == EndpointSource.MANUAL and created.is_active
```

  Also add `test_use_observed_without_an_inventory_match_offers_import` (422 with an import link, nothing changed), `test_expectation_requires_an_active_certificate`, `test_duplicate_endpoint_identity_links_the_existing_row` (same host/port/coalesced SNI → 422 naming the existing endpoint; the unique index is the arbiter under concurrency), `test_deactivate_and_reactivate_never_delete_history`, `test_certificate_detail_panel_links_history_and_scans_each_endpoint` (rows link to `/scans/{id}`, per-endpoint "Scan now" posts scope endpoint, "Add endpoint" is prefilled with the certificate; update the Plan 1 `Scan now` expectation in `tests/integration/test_inventory_http.py`), `test_every_mutation_requires_csrf_and_is_audited_once`.
- [ ] Run `uv run pytest tests/integration/test_endpoints_http.py tests/integration/test_inventory_http.py -q` in CI; expect FAIL, management forms absent.
- [ ] Implement per Contract decision 16. Validation reuses the pull-import host/SNI rules (host literal or DNS name, ports 1–65535, SNI a DNS name or empty); `sni` equal to the host is stored as NULL so identity matches the coalesced unique index. Mutations lock the endpoint row, audit `endpoint.create`/`endpoint.update` with `{field, from, to}` metadata only, and commit with the change; htmx failures return the form fragment with 422, non-JS posts re-render the page. Expectation changes do not rewrite past `scan_result.expected_certificate_id` snapshots.
- [ ] Run the same command; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [ ] Commit: `git add app/services/endpoints.py app/services/scans.py app/services/certificates.py app/web/scans.py app/templates/scans app/templates/certificates/detail.html.j2 tests/integration/test_inventory_http.py tests/integration/test_endpoints_http.py`; `git commit -m "feat: manage endpoints and their expected certificates"`.

### Task 14: Servers list and server detail (`/servers`, `/servers/{id}`)

**Files:** Create: `app/services/servers.py`, `app/web/servers.py`, `app/templates/servers/list.html.j2`, `app/templates/servers/detail.html.j2`. Modify: `app/main.py`, `tests/integration/conftest.py`, `tests/integration/test_inventory_http.py`. Test: `tests/integration/test_servers_http.py`.

**Size budget:** ≈ 230 production + 220 test lines.

**Interfaces:** Consumes: ORM `Server`, `Binding`, `Endpoint`, `Certificate`, `Job`, `JobHost`; `unsupported_reason`. Produces in `app/services/servers.py`: `ServerFilters(search: str | None = None, group: str | None = None, active: bool | None = True)`; `ServerRow(id: int, hostname: str, display_name: str | None, groups: tuple[str, ...], webserver: str | None, binding_count: int, attention_count: int, last_discovery_at: datetime | None, last_discovery_status: str | None, mismatch_count: int, is_active: bool)`; `ServerPage(items: list[ServerRow], total: int, page: int, page_size: int)`; `list_servers(db: Session, filters: ServerFilters, page: int = 1, page_size: int = 50, sort: str = 'hostname') -> ServerPage`; `BindingRow(id: int, server_id: int, server: str, webserver: str, vhost_name: str, vhost_names: tuple[str, ...], port: int, config_file: str, cert_path: str, chain_path: str | None, key_path: str, cert_owner: str | None, cert_group: str | None, cert_mode: str | None, key_owner: str | None, key_group: str | None, key_mode: str | None, on_disk_fingerprint: str | None, on_disk_key_public_sha256: str | None, certificate_id: int | None, certificate_common_name: str | None, match_state: str, last_seen_at: datetime, is_active: bool)` (modes as octal strings; shared with Task 15); `DiscoveryRun(job_id: str, status: str, started_at: datetime | None, finished_at: datetime | None, duration_seconds: int | None, inventory_rev: str | None, error_message: str | None)`; `ServerDetail(server: ServerRow, connection_address: str | None, inventory_source: str, notes: str | None, bindings: list[BindingRow], discovery_history: list[DiscoveryRun], endpoint_count: int)`; `server_detail(db: Session, server_id: int) -> ServerDetail`; `export_servers(db: Session, filters: ServerFilters, limit: int = 5000) -> list[dict[str, JSONValue]]`; `SERVER_EXPORT_FIELDS` (exactly the `ServerRow` field names). Routes GET `/servers`, `/servers/export.json`, `/servers/{server_id}`. Integration fixture `server_map` (servers, bindings in every `match_state`, endpoints and discover jobs inserted directly, since discovery is Plan 3).

- [ ] Write failing tests:

```python
def test_servers_list_counts_and_filters_without_n_plus_one(signed_in, server_map, count_statements):
    with count_statements() as small:
        assert signed_in.get("/servers?page_size=5").status_code == 200
    with count_statements() as large:
        page = signed_in.get(f"/servers?group={server_map.group}&page_size=50")
    assert small.count == large.count
    web01 = server_map.server("web01.example.internal")
    assert f'data-server-id="{web01.id}"' in page.text
    row = signed_in.get(f"/servers/export.json?search=web01").json()[0]
    assert set(row) == set(SERVER_EXPORT_FIELDS)
    assert (row["binding_count"], row["mismatch_count"]) == (3, 1)
```

  Also add `test_server_detail_shows_paths_owners_modes_and_match_state` (cert/chain/key paths, owner/group/mode rendered octal, on-disk fingerprint, matched certificate link, `key_mismatch`/`missing_file` badges), `test_discovery_history_comes_from_discover_job_hosts` (status, duration, `inventory_rev`, sanitized error; newest first, capped at 20), `test_discovery_actions_are_disabled_with_the_plan3_reason` (buttons disabled with "handler discover/default not registered (Plan 3)"; "Open endpoint scan" links `/scans?server_id=…`), `test_inactive_servers_are_hidden_unless_requested`, `test_servers_navigation_is_enabled` (update the Plan 1 expectation in `tests/integration/test_inventory_http.py`), `test_unknown_server_is_404_and_values_are_escaped`.
- [ ] Run `uv run pytest tests/integration/test_servers_http.py tests/integration/test_inventory_http.py -q` in CI; expect FAIL, screens absent.
- [ ] Implement per Contract decision 17 with grouped aggregate subqueries (binding counts, attention counts, mismatch counts) joined once per page; `group` filters `ansible_groups @> ARRAY[:group]`; sorts whitelisted (`hostname`, `last_discovery_at`, `mismatch_count`, `binding_count`). Navigation Servers is always enabled (the map is read-only); the "last raw dump summary" and discovery buttons are disabled until Plan 3 registers `discover/default`.
- [ ] Run the same command; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [ ] Commit: `git add app/services/servers.py app/web/servers.py app/templates/servers app/main.py tests/integration/conftest.py tests/integration/test_inventory_http.py tests/integration/test_servers_http.py`; `git commit -m "feat: map servers with binding and discovery state"`.

### Task 15: Cross-server bindings view (`/bindings`)

**Files:** Modify: `app/services/servers.py`, `app/web/servers.py`. Create: `app/templates/bindings/list.html.j2`, `app/templates/bindings/help.html.j2`. Test: `tests/integration/test_bindings_http.py`.

**Size budget:** ≈ 170 production + 200 test lines.

**Interfaces:** Consumes: Task 14 `BindingRow`, `server_map`, `count_statements`. Produces: `BindingFilters(certificate_id: int | None = None, server_id: int | None = None, group: str | None = None, webserver: WebserverType | None = None, match_state: Literal['matched','unknown','key_mismatch','missing_file'] | None = None, vhost: str | None = None, active: bool | None = True)`; `BindingPage(items: list[BindingRow], total: int, page: int, page_size: int)`; `list_bindings(db: Session, filters: BindingFilters, page: int = 1, page_size: int = 50, sort: str = 'server') -> BindingPage`; `export_bindings(db: Session, filters: BindingFilters, limit: int = 5000) -> list[dict[str, JSONValue]]`; `BINDING_EXPORT_FIELDS`; routes GET `/bindings`, `/bindings/export.json`, `/bindings/help`.

- [ ] Write failing tests:

```python
def test_where_is_this_certificate_used(signed_in, server_map):
    page = signed_in.get(f"/bindings?certificate_id={server_map.certificate_id}&sort=server")
    assert page.status_code == 200
    assert all(host in page.text for host in server_map.hosts_using_certificate)
    exported = signed_in.get(f"/bindings/export.json?certificate_id={server_map.certificate_id}").json()
    assert {row["server"] for row in exported} == set(server_map.hosts_using_certificate)
    assert all(set(row) == set(BINDING_EXPORT_FIELDS) for row in exported)
    assert all("notes" not in row and "key" not in row for row in exported)
```

  Also add `test_every_binding_filter` (server, group, webserver, match state, vhost substring over `vhost_name`/`vhost_names`, `active=all`; invalid enum values → 422), `test_attention_rows_link_to_fix_instructions` (persistent badge for `key_mismatch`/`missing_file` linking `/bindings/help#key_mismatch` / `#missing_file`; the help page states the app does not fix them and that `key_mismatch` blocks deploys of that vhost), `test_bindings_query_count_is_independent_of_rows`, `test_pagination_limits_and_whitelisted_sorts`, `test_bindings_require_sign_in_and_escape_paths`.
- [ ] Run `uv run pytest tests/integration/test_bindings_http.py -q` in CI; expect FAIL, view absent.
- [ ] Implement with one paginated query joining `server` and `certificate` (no lazy loads), using `ix_binding_certificate_id`, `ix_binding_server_active` and `ix_binding_match_state`. `BINDING_EXPORT_FIELDS`: `id`, `server`, `webserver`, `vhost_name`, `vhost_names`, `port`, `config_file`, `cert_path`, `chain_path`, `key_path`, `cert_owner`, `cert_group`, `cert_mode`, `key_owner`, `key_group`, `key_mode`, `on_disk_fingerprint`, `on_disk_key_public_sha256`, `certificate_id`, `match_state`, `last_seen_at`, `is_active` (public metadata only; free-text `notes` excluded). Modes render and export as octal strings such as `"0600"`.
- [ ] Run the same command; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [ ] Commit: `git add app/services/servers.py app/web/servers.py app/templates/bindings tests/integration/test_bindings_http.py`; `git commit -m "feat: answer where each certificate is used across servers"`.

### Task 16: Overview TLS health, recent jobs, renewals in flight and status strip

**Files:** Create: `app/services/overview.py`. Modify: `app/web/overview.py`, `app/templates/overview.html.j2`. Test: `tests/integration/test_overview_slots.py`.

**Size budget:** ≈ 190 production + 200 test lines.

**Interfaces:** Consumes: `expiry_counts(db: Session, now: datetime) -> dict[str, int]` (unchanged), `worker_liveness(db: Session, now: datetime) -> Literal['ok','stale']`, ORM `Endpoint`, `Binding`, `Job`, `User`, `Renewal`, `NotificationLog`, `WorkerHeartbeat`. Produces: `TLSHealth(ok: int, mismatch: int, expired: int, unreachable: int, error: int, never_scanned: int, unknown_certificates: int, key_mismatch_bindings: int)`; `RecentJob(id: str, type: str, summary: str, status: str, duration_seconds: int | None, actor: str, finished_at: datetime | None, href: str)`; `RenewalInFlight(id: str, common_name: str, state: str, age_days: int)`; `StatusStrip(worker: str, last_heartbeat_at: datetime | None, inventory_rev: str | None, inventory_rev_age_hours: int | None, last_digest_at: datetime | None)`; `OverviewSnapshot(tls: TLSHealth, recent_jobs: list[RecentJob], renewals: list[RenewalInFlight], status: StatusStrip)`; `overview_snapshot(db: Session, now: datetime) -> OverviewSnapshot`; `job_summary(job_type: JobType, payload: Mapping[str, JSONValue]) -> str`.

- [ ] Write failing tests:

```python
def test_overview_snapshot_counts_tls_health_and_recent_work(db, overview_world, now):
    snapshot = overview_snapshot(db, now)
    assert snapshot.tls == TLSHealth(ok=2, mismatch=1, expired=1, unreachable=1, error=0,
        never_scanned=1, unknown_certificates=1, key_mismatch_bindings=1)
    assert [job.status for job in snapshot.recent_jobs][:2] == ["failed", "succeeded"]
    assert len(snapshot.recent_jobs) == 10 and snapshot.recent_jobs[0].href.startswith("/audit?")
    assert [renewal.state for renewal in snapshot.renewals] == ["submitted", "csr_generated"]

def test_job_summaries_never_echo_raw_payloads():
    assert job_summary(JobType.SCAN, {"endpoint_ids": [1, 2, 3]}) == "3 endpoints"
    assert job_summary(JobType.SCAN, {"action": "import_pull", "host": "h", "port": 443, "metadata": {"notes": "x"}}) == "pull h:443"
    assert "notes" not in job_summary(JobType.CLEANUP, {"reason": "manual_prune", "notes": "x"})
```

  Also add `test_overview_page_fills_every_slot_and_links_filters` (TLS counters link `/scans?status=…`, unknown → `/bindings?match_state=unknown`, key mismatch → `/bindings?match_state=key_mismatch`; failed jobs carry a distinct class; import-pull jobs link `/imports/{id}`; renewal rows link `/renewals/{id}` with age; status strip shows heartbeat, "no inventory revision recorded yet" until Plan 3, and the last digest time), `test_expiry_counters_are_unchanged` (Plan 1 Task 17's bucket assertions still pass), `test_overview_query_count_is_constant`.
- [ ] Run `uv run pytest tests/integration/test_overview_slots.py tests/integration/test_inventory_http.py -q` in CI; expect FAIL, slots empty.
- [ ] Implement with one aggregate query per slot. Unknown certificates count distinct `on_disk_fingerprint` of active `unknown` bindings. Recent jobs are the newest 10 by `COALESCE(finished_at, started_at, created_at)` with actor = requester username or `system`; `job_summary` uses a closed per-type allowlist (`endpoint_ids` count, `certificate_id`, import host:port, `mode`, `reason`), never raw payload text. Renewals in flight are states `draft`, `csr_generated`, `submitted`, `issued`, `deployed`, oldest first. Template blocks `tls_health`, `recent_jobs`, `renewals_in_flight`, `status_strip` are filled; the expiry counters block is untouched.
- [ ] Run the same command; expect PASS. Locally `uv run ruff check .` and `uv run pytest -q tests/unit`.
- [ ] Commit: `git add app/services/overview.py app/web/overview.py app/templates/overview.html.j2 tests/integration/test_overview_slots.py`; `git commit -m "feat: fill overview TLS health jobs renewals and status"`.

### Task 17: Local TLS/SMTP targets in the test stack and final verification

**Files:** Modify: `docker-compose.test.yml`, `.github/workflows/ci.yml`, `tests/integration/conftest.py`, `tests/unit/test_topology.py`. Create: `tests/fixtures/targets/nginx.conf`, `tests/fixtures/targets/httpd.conf`. Test: `tests/integration/test_scan_targets.py`.

**Size budget:** ≈ 80 configuration + 260 test/fixture lines.

**Interfaces:** Consumes: Task 2 handler, Task 4 `smtp_capture` CLI, Task 5 test send, `make_worker`. Produces: compose services `tls-nginx`, `tls-apache`, `smtp` under profile `targets`; integration fixture `compose_targets` (session scope) exposing `.address(service) -> tuple[str, int]`, `.serve(service, cert: x509.Certificate, key: PrivateKeyObject, chain: Sequence[x509.Certificate]) -> None` (rewrite files, start the service again if it was stopped, then `nginx -s reload` / `httpd -k graceful`), `.stop(service) -> None`, `.messages() -> list[EmailMessage]` (reads the `smtp` spool through `docker compose exec`).

- [ ] Write failing tests:

```python
@pytest.mark.parametrize("service", ["tls-nginx", "tls-apache"])
def test_real_webserver_scan_reports_ok_then_mismatch_then_unreachable(
    service, compose_targets, queue_factory, make_worker, ca, clock
):
    host, port = compose_targets.address(service)
    first, second = issue_target_pair(ca, clock())
    compose_targets.serve(service, first.cert, first.key, first.chain)
    endpoint_id = endpoint_expecting(queue_factory, host, port, first)
    worker = make_worker(queue_factory)
    statuses = []
    for change in (None, lambda: compose_targets.serve(service, second.cert, second.key, second.chain),
                   lambda: compose_targets.stop(service)):
        if change:
            change()
        run_scan(queue_factory, worker, {"endpoint_ids": [endpoint_id]}, clock())
        statuses.append(latest_status(queue_factory, endpoint_id))
    assert statuses == ["ok", "mismatch", "unreachable"]
```

  Also add `test_compose_smtp_target_receives_the_test_email` (worker test send to the `smtp` service address; `.messages()` holds one message for the requesting user) and in `tests/unit/test_topology.py` `test_test_targets_are_pinned_profiled_and_loopback_only` (only in `docker-compose.test.yml`; profile `targets`; nginx/httpd images pinned `@sha256:`; `smtp` uses `cert-dashboard:test`, user `10001:10001`, `read_only`, `cap_drop: [ALL]`; every published port is `127.0.0.1::<container port>`; no secrets, no `network_mode: host`, no build of external content). Extend the existing `docker compose ... config` assertions to render with `--profile targets`.
- [ ] Run `uv run pytest tests/unit/test_topology.py -q` locally (Docker-dependent cases skip) and `uv run pytest tests/integration/test_scan_targets.py tests/unit/test_topology.py -q` in CI; expect FAIL, targets absent.
- [ ] Implement. `tls-nginx` (official `nginx` image) and `tls-apache` (official `httpd` image), both pinned by digest resolved at implementation time with `docker buildx imagetools inspect`, mount the committed configs read-only and `${TLS_TARGET_DIR:-./secrets/test/tls-targets}/<service>:/etc/certs:ro`, listen on container port 8443 with `ssl_certificate`/`SSLCertificateFile` pointing at a full-chain PEM and key in `/etc/certs`, and publish `127.0.0.1::8443`. `smtp` runs `python -m tests.fixtures.smtp_capture --listen 0.0.0.0:1025 --spool /spool` with `tmpfs: [/spool]` and publishes `127.0.0.1::1025`. The fixture writes throwaway fixture-CA material (key files `0600`) and dummy files for every declared secret into a session temp directory, runs `docker compose -p certdash-targets-<uuid> -f docker-compose.test.yml --profile targets up -d --wait --pull never tls-nginx tls-apache smtp` with `TLS_TARGET_DIR`/`TEST_SECRETS_DIR` pointing there (the Plan 1 topology-test pattern), reads ports with `docker compose port`, and always runs `down -v` at teardown. CI adds `docker compose -f docker-compose.test.yml --profile targets pull tls-nginx tls-apache` next to the existing `db` pull, before pytest; the `smtp` service uses the `cert-dashboard:test` image CI already builds. Tests never pull or reach the Internet.
- [ ] Run the same commands; expect PASS. Final verification for the whole plan: `uv run ruff check .`, `uv run pytest -q --cov=app --cov-report=term-missing --cov-fail-under=70`, the 85% crypto/renewals gates, `uv run pip-audit`, `docker build --target test -t cert-dashboard:test .`, `docker build -t cert-dashboard:local .`, `docker compose -f docker-compose.test.yml config --quiet` and `docker compose -f docker-compose.test.yml --profile targets config --quiet`; expect all PASS in CI (the required `verify` check). Writing this plan does not claim these checks have run.
- [ ] Commit: `git add docker-compose.test.yml .github/workflows/ci.yml tests/fixtures/targets tests/integration/conftest.py tests/integration/test_scan_targets.py tests/unit/test_topology.py`; `git commit -m "test: scan real nginx and apache targets and a compose SMTP capture"`.

## Extension points for plan 3

- **Schema and settings:** still frozen. Plan 3 adds no migration, column, enum value or settings row; `deploy.*`, `discovery.*` and `inventory.*` keys already exist.
- **Worker hooks:** `register_tick_step(name, step, *, requires=(JobType.DEPLOY, "default"))` is the place for the paused-deploy auto-cancel sweep (§6.5/§7.1); `register_timeout(JobType.DEPLOY, ...)` (Plan 1) computes the deploy timeout; `register_schedule("discovery", JobType.DISCOVER)` uses the existing `discovery.nightly_at`/`discovery.enabled` mapping. Discovery jobs share the two-slot cap with `scan/default` and `scan/trust_recheck`.
- **Discovery → scanning:** endpoints derived from bindings must be created with `source='discovery'`, `server_id`, `binding_id` and an expectation (spec A7) through one service, never by raw SQL in handlers; `scan/default` scans them without change. Deactivated bindings deactivate their derived endpoints (§4.9). The worker-side informational verify of §6.4 step 7 may reuse `observe_endpoint(...)`; it must record into `job_host.precheck`, never into a deploy rollback decision.
- **Data the Plan 2 read models already consume:** `server.last_discovery_at/last_discovery_status` (`ok|failed|unreachable`), `binding.match_state` and `on_disk_*`, `job_host` rows of `discover` jobs (discovery history), `job_host.rolled_back/rollback_error` (digest), and `job.result` keys `inventory_rev` (commit SHA string) and `inventory_rev_date` (ISO 8601 UTC) on discover/deploy jobs (digest, Overview status strip). Plan 3 must write exactly these shapes; the screens and digest need no further change.
- **Binding transition audit (the producer contract of Contract decision 22):** discovery reconciliation calls `audit_binding_state(db, binding, previous, actor, job_id=<discover job id>, now=context.clock())` from `app/services/bindings.py` for every binding it inserts (`previous=None`) or updates (`previous=binding_state(binding)` captured before the change), in the same per-server transaction, and at most once per binding per run; no other code changes `match_state`, `on_disk_fingerprint` or `is_active` without it. The digest's "unknown certificates found by discovery since the last digest" depends on exactly this; skipping it silently hides `matched → unknown` transitions.
- **Screens:** Servers/server detail render discovery and "raw dump summary" controls disabled behind `unsupported_reason(registry, "Plan 3", (JobType.DISCOVER, "default"))`; Plan 3 enables them by registering the handler and adding the routes. Settings "Test pull" (Plan 1) and the Deploy screen remain Plan 3's.
- **Alerts:** deploy failures and rollback failures reach operators through the digest sections above; Plan 3 adds no immediate mail (spec A22).
- **Plan 3:** `docs/superpowers/plans/2026-10-25-cert-dashboard-plan-3-discovery-and-deploy.md` (discovery and deployment with Ansible).
- **Open questions (non-blocking, recorded for review):** a configurable base URL for e-mail links would be cleaner as a setting, but the frozen schema forced `DASHBOARD_URL` (Contract decision 14); per-endpoint retry state is derived from `endpoint.last_scan_status` because `scan_result` has no job reference (Contract decision 1); binding transitions are reconstructed from the append-only audit trail because `binding` has no transition column, and the digest reads them with a daily sequential scan because `audit_log` has no `(action, created_at)` index (Contract decision 22) — a future migration could add either.
