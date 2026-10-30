"""Render real templates without importing the app or connecting to a database.

Run: uv run python scripts/render_previews.py
Open docs/ui/previews/*.html directly; assets resolve into the repository.
Fixture forms are illustrative only: do not serve these as application pages.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/ui/previews"


def environment():
    env = Environment(
        loader=FileSystemLoader([ROOT / "app/templates", ROOT / "docs/ui/fixtures"]),
        autoescape=True,
    )
    env.globals.update(
        time_tag=preview_time, expiry_chip=preview_expiry, hostport=lambda host, port: f"{host}:{port}"
    )
    env.filters['datetime'] = lambda value, tz='UTC': value.strftime('%Y-%m-%d %H:%M UTC')
    return env


def preview_time(value, tz="UTC"):
    if not value:
        return "—"
    return Markup('<time datetime="{}">{}</time>').format(
        value.strftime("%Y-%m-%dT%H:%M:%SZ"), value.strftime("%Y-%m-%d %H:%M UTC")
    )


def preview_expiry(value, now):
    days = (value - now).days
    css = (
        "expired"
        if days < 0
        else "critical"
        if days < 7
        else "warning"
        if days < 30
        else "soon"
        if days < 60
        else "ok"
    )
    label = f"Expired {-days} days ago" if days < 0 else f"{days} days"
    return {"css": f"chip-{css}", "label": label}


def fixtures():
    common = {
        "navigation": [
            {"label": label, "url": url, "enabled": True, "reason": ""}
            for label, url in [
                ("Overview", "/"),
                ("Certificates", "/certificates"),
                ("Servers", "/servers"),
                ("Deploy", "/deploy"),
                ("Scans", "/scans"),
                ("Audit", "/audit"),
                ("Settings", "/settings"),
            ]
        ],
        "request": SimpleNamespace(
            url=SimpleNamespace(path="/login"), state=SimpleNamespace(worker_stale=False)
        ),
        "user": None,
        "status_banner": "",
        "capability_banner": "",
        "flash": [],
        "csrf_token": "preview-only-not-a-valid-token",
        "username": "",
        "error": "",
    }
    pages = {
        "login": ("login.html.j2", {}),
        "login-error": ("login.html.j2", {"username": "operator", "error": "Invalid credentials."}),
        "login-2fa": ("login_2fa.html.j2", {}),
        "login-2fa-error": ("login_2fa.html.j2", {"error": "Invalid code."}),
        "bootstrap": ("bootstrap.html.j2", {}),
        "shell": (
            "shell.html.j2",
            {
                "request": SimpleNamespace(
                    url=SimpleNamespace(path="/"), state=SimpleNamespace(worker_stale=True)
                ),
                "user": SimpleNamespace(display_name="Fixture operator"),
                "status_banner": "Key material cannot be decrypted with the configured master key.",
                "capability_banner": "Discovery and deploy are unavailable: the worker has no known_hosts file.",
                "flash": ["Inventory refresh completed. No changes were made."],
            },
        ),
    }
    for status, message in [
        (403, "Access denied."),
        (404, "Page not found."),
        (500, "An unexpected error occurred."),
    ]:
        pages[f"error-{status}"] = (
            "error.html.j2",
            {
                "status": status,
                "message": message,
                "request_id": "fixture-request-0001",
            },
        )
    pages.update(inventory_fixtures())
    pages.update(operations_fixtures())
    return {name: (template, common | context) for name, (template, context) in pages.items()}


def inventory_fixtures():
    """Explicit, synthetic inventory fixtures; no application import or database."""
    ns = SimpleNamespace
    now = datetime(2026, 10, 30, 12, tzinfo=UTC)
    cert = ns(
        id=42,
        common_name="gateway.ops.example.test",
        status=ns(value="active"),
        not_before=now - timedelta(days=300),
        not_after=now + timedelta(days=20),
        sans=[f"DNS:gateway-{n}.ops.example.test" for n in range(40)],
        issuer_cn="Operations Intermediate CA",
        issuer_dn="CN=Operations Intermediate CA,O=Example Operations",
        subject_dn="CN=gateway.ops.example.test," + "OU=Long department name," * 40,
        serial="1234567890abcdef1234567890abcdef",
        sha256_fingerprint="0123456789abcdef" * 4,
        imported_from="upload",
        renews_id=None,
        owner_name="Operations team",
        owner_email="ops@example.test",
        team="Infrastructure",
        notes="Fixture only. Review chain before deployment.",
        key_id=7,
        binding_count=0,
        chain_status=ns(value="incomplete"),
        has_chain=False,
        created_at=now - timedelta(days=300),
        updated_at=now,
    )
    key = ns(
        key_type="rsa",
        key_size=2048,
        curve=None,
        public_key_sha256="abcdef0123456789" * 4,
        created_at=now,
        origin="generated",
        master_key_version=1,
    )
    form = {
        "owner_name": cert.owner_name,
        "owner_email": cert.owner_email,
        "team": cert.team,
        "notes": cert.notes,
    }
    base = {
        "now": now,
        "tz": "UTC",
        "c": cert,
        "cert_id": cert.id,
        "common_name": cert.common_name,
        "cert_status": cert.status,
        "csrf_token": "preview-only-not-a-valid-token",
        "edit_form": form,
        "edit_errors": {},
        "status_options": ["superseded", "revoked"],
        "status_form": {"status": "revoked", "reason": ""},
        "status_errors": {},
        "chain_errors": {},
        "detail": ns(
            certificate=cert,
            previous=None,
            next=[],
            key=key,
            renewals=[],
            bindings=[],
            endpoints=[],
            audit=[],
            diagnostics=ns(status=ns(value="incomplete")),
        ),
        "warnings": ["The issuer certificate is missing from the chain."],
        "recheck_failed": False,
        "recheck_differs": False,
        "trust_warning": True,
        "panel": ns(blocked={"chain": "A trusted chain is required."}, jobs=[]),
        "deploy_supported": True,
        "deploy_reason": "",
        "scan_supported": True,
        "scan_reason": "",
        "scan_error": None,
        "missing_key_versions": [],
        "key_unavailable": "",
        "user": ns(display_name="Fixture operator"),
    }
    states = [cert]
    for index, (status, days) in enumerate(
        [("active", 180), ("active", -3), ("revoked", 10), ("unknown", 10)]
    ):
        states.append(
            ns(
                **(
                    vars(cert)
                    | {
                        "id": index + 50,
                        "common_name": f"{status}-{index}.ops.example.test",
                        "status": ns(value=status),
                        "not_after": now + timedelta(days=days),
                    }
                )
            )
        )
    listing = {
        "values": {},
        "page": ns(items=states, total=len(states), page=1, page_size=50),
        "pages": 1,
        "sort_state": "not_after",
        "statuses": ["active", "superseded", "revoked"],
        "buckets": ["expired", "lt7", "lt30", "lt60"],
        "renewal_states": [],
        "sort_url": lambda column: f"/certificates?sort={column}",
        "page_url": lambda n: f"/certificates?page={n}",
        "export_url": "/certificates/export.json",
    }
    pages = {
        "certificate-list": ("certificates/list.html.j2", base | listing),
        "certificate-detail": ("certificates/detail.html.j2", base),
        "certificate-edit": ("certificates/edit.html.j2", base),
        "certificate-export": ("certificates/export_pfx.html.j2", base | {"error": "", "blocked": ""}),
    }
    steps = [
        {"name": name, "label": label, "url": f"/renewals/fixture-renewal?step={name}"}
        for name, label in [
            ("basics", "Basics"),
            ("csr", "CSR"),
            ("submitted", "Order"),
            ("upload", "Upload"),
            ("ready", "Ready"),
            ("done", "Done"),
        ]
    ]
    renewal = ns(
        id="fixture-renewal",
        common_name=cert.common_name,
        sans=cert.sans,
        ca_name=cert.issuer_cn,
        notes="",
        csr_sha256="abcdef0123456789" * 4,
        ca_order_reference="CA-FIXTURE-42",
        csr_pem="-----BEGIN CERTIFICATE REQUEST-----\n"
        + "FIXTURE-NOT-A-VALID-CSR\n" * 30
        + "-----END CERTIFICATE REQUEST-----",
        state_changed_at=now,
    )
    renewal_base = base | {
        "r": renewal,
        "previous": cert,
        "certificate": cert,
        "steps": steps,
        "errors": {},
        "editable": True,
        "can_cancel": True,
        "source_id": 42,
        "checks": {},
        "form": {
            "common_name": cert.common_name,
            "sans": "\n".join(cert.sans),
            "ca_name": cert.issuer_cn,
            "notes": "",
            "key_algorithm": "rsa-2048",
            "leaf_text": "",
            "chain_text": "",
            "previous_status": "superseded",
            "reason": "",
        },
        "algorithms": [ns(value="rsa-2048", label="RSA 2048 (default)", note="Most compatible.")],
    }
    for step, state in [
        ("basics", "draft"),
        ("csr", "csr_generated"),
        ("submitted", "submitted"),
        ("upload", "submitted"),
        ("ready", "issued"),
        ("done", "deployed"),
    ]:
        context = renewal_base | {"step": step, "state": state}
        if step == "basics":
            context = context | {
                "r": None,
                "state": "new",
                "steps": [item | {"url": None} for item in steps],
                "can_cancel": False,
            }
        pages[f"renewal-{step}"] = (f"renewals/{step}.html.j2", context)
    row = ns(
        id=12,
        host=cert.common_name,
        port=443,
        sni=cert.common_name,
        source="manual",
        server="edge-01",
        status="mismatch",
        is_active=True,
        error="",
        expected_certificate_id=42,
        expected_common_name=cert.common_name,
        expected_fingerprint=cert.sha256_fingerprint,
        checked_at=now,
        observed_common_name="old-gateway.ops.example.test",
        observed_issuer_cn=cert.issuer_cn,
        observed_not_after=now + timedelta(days=2),
        observed_fingerprint="fedcba9876543210" * 4,
        observed_chain_length=2,
        tls_version="TLSv1.3",
    )
    scan = base | {
        "row": row,
        "errors": {},
        "form_certificate": "",
        "certificates": [(42, cert.common_name, cert.not_after)],
        "offer_import": False,
        "import_url": "/certificates/import?host=gateway.ops.example.test&port=443#pull-panel",
    }
    for name, status in [("findings", "mismatch"), ("clear", "ok"), ("failed", "error"), ("unscanned", None)]:
        current = ns(**(vars(row) | {"status": status}))
        if status == "ok":
            current.observed_fingerprint = current.expected_fingerprint
            current.observed_common_name = current.expected_common_name
            current.observed_not_after = cert.not_after
        if status in ("error", None):
            current.observed_fingerprint = current.observed_not_after = current.observed_common_name = None
            current.observed_issuer_cn = current.observed_chain_length = current.tls_version = None
            if status is None:
                current.checked_at = None
            current.error = "TLS handshake failed. Check endpoint connectivity." if status else ""
        context = scan | {
            "row": current,
            "detail": ns(
                row=current,
                observed_certificate_id=None,
                observed_certificate_active=False,
                history=[ns(**(vars(current) | {"status": ns(value=status)}))] if status else [],
            ),
        }
        pages[f"scan-{name}"] = ("scans/detail.html.j2", context)
    pages["scan-list"] = (
        "scans/list.html.j2",
        scan
        | listing
        | {
            "page": ns(items=[row], total=1, page=1, page_size=50),
            "servers": [(1, "edge-01")],
            "statuses": ["ok", "expired", "mismatch", "unreachable", "error"],
            "add_form": {"host": "", "port": "443", "sni": "", "expected_certificate_id": ""},
            "add_errors": {},
            "existing_id": None,
        },
    )
    pages["import"] = (
        "import.html.j2",
        base
        | {
            "form": {"format": "pem"} | form,
            "pull_form": form | {"host": "", "port": "443", "sni": ""},
            "errors": {},
            "pull_errors": {},
            "duplicate": None,
            "from_binding": None,
        },
    )
    pages["import-progress"] = (
        "import_progress.html.j2",
        base
        | {
            "job": ns(
                id="fixture-job",
                endpoint="gateway.ops.example.test:443",
                sni="",
                status="failed",
                polling=False,
                attempt=3,
                max_attempts=3,
                error_message="Connection refused. Check the host and port.",
                certificate_id=None,
                created=False,
            )
        },
    )
    for name, (template, context) in pages.items():
        path = (
            "/renewals/new"
            if name.startswith("renewal-")
            else ("/scans/12" if name.startswith("scan-") else "/certificates")
        )
        if name in ("import", "import-progress"):
            path = "/certificates/import"
        context["request"] = ns(url=ns(path=path), state=ns(worker_stale=False))
    return pages


def operations_fixtures():
    """Synthetic deploy/settings/email data; not captured service or delivery results."""
    ns = SimpleNamespace
    now = datetime(2026, 10, 30, 12, tzinfo=UTC)
    cert = ns(id=42, common_name='gateway.ops.example.test', sha256_fingerprint='a' * 64,
              not_after=now + timedelta(days=180))
    binding = ns(binding_id=12, vhost_name=cert.common_name, port=443, match_state='matched',
                 current_common_name=cert.common_name, current_certificate_id=41,
                 current_fingerprint='b' * 64, current_not_after=now + timedelta(days=2))
    host = ns(hostname='edge-01.example.test', server_id=1, batch_no=0, groups=['edge'], bindings=[binding],
              files=[ns(path='/etc/tls/gateway.pem', action='replace', owner='root', group='root', mode='0640')])
    preview = ns(certificate=cert, chain_status='trusted', totals=ns(hosts=1, bindings=1, files=1, groups=1),
                 batches=[1], hosts=[host], warnings=[], excluded=[], needs_override=False, plan_sha256='c' * 64)
    request = ns(url=ns(path='/deploy'), state=ns(worker_stale=False))
    base = {"preview": preview, "blocked": {}, "errors": {}, "active": None, "notes": {}, "canary": host, "request": request,
                "candidates": [ns(certificate_id=42, common_name=cert.common_name, renewal_id=None,
                               chain_status='trusted', not_after=cert.not_after)],
                "choices": [ns(binding_id=12, hostname=host.hostname, vhost_name=cert.common_name, port=443,
                            cert_path='/etc/tls/gateway.pem', match_state='matched', checked=True)],
                "form": {"certificate_id": '42', "group": '', "host": '', "canary_server_id": '', "not_before": '', "override_reason": ''},
                "confirm": {"certificate_id": 42, "plan_sha256": 'c' * 64, "binding_ids": [12], "include_unknown": '0',
                             "pause_after_canary": '1', "batch_percent": 10, "canary_server_id": 1, "not_before": ''},
                "selection_for": 42, "batch_percent": 10, "pause_after_canary": True, "include_unknown": False,
                "start_reason": '', "deploy_unavailable": '', "tz": 'UTC', "user": ns(display_name='Fixture operator')}
    pages = {'deploy-allowed': ('deploy/start.html.j2', base),
             'deploy-blocked': ('deploy/start.html.j2', base | {
                 'blocked': {'active_deploy': 'Another rollout is active. Finish or cancel it first.'},
                 'active': ns(job_id='fixture-active-job'), 'start_reason': 'Another rollout is active.'})}
    failed = ns(server_id=1, hostname=host.hostname, status='rolled_back', bindings=[cert.common_name + ':443'],
                old_fingerprint='b' * 64, new_fingerprint='a' * 64, duration_seconds=18, rolled_back=True,
                rollback_error=None, needs_attention=False, reason='healthcheck_failed',
                log_excerpt='TLS verification failed after reload; backup restored.',
                backup_dir='/var/backups/cert-dashboard/fixture-job', retryable=True)
    view = ns(job_id='fixture-deploy-job', certificate_id=42, certificate_cn=cert.common_name,
              status='failed', phase='canary', actor='Fixture operator', started_at=now, elapsed_seconds=18,
              totals={"succeeded": 0, "failed": 0, "rolled_back": 1, "skipped": 0, "pending": 0}, batches=[[failed]],
              hosts=[failed], first_failed_host=host.hostname, failure_reason='healthcheck_failed',
              failure_restoration='restored', job_failure_reason=None, inventory_rev='d' * 40,
              polling=False, cancellable=False, paused_at=None)
    for name, status in [('failure', 'failed'), ('paused', 'paused'), ('running', 'running')]:
        current = ns(**(vars(view) | {"status": status, "polling": status == 'running',
                                        "cancellable": status != 'failed', "paused_at": now}))
        if status != 'failed':
            current.hosts = [ns(**(vars(failed) | {"status": 'succeeded', "rolled_back": False, "retryable": False}))]
            current.batches = [current.hosts]
        pages['deploy-' + name] = ('deploy/job.html.j2', {"view": current, "errors": {}, "hours_left": 23,
                                                           "tz": 'UTC', "request": request})
    tabs = [('smtp', 'SMTP'), ('alerts', 'Alerts'), ('inventory', 'Inventory'), ('deployment', 'Deployment'),
            ('scanning', 'Scanning'), ('schedule', 'Schedule'), ('general', 'General'),
            ('trust', 'Trust anchors'), ('status', 'Status'), ('maintenance', 'Maintenance')]
    rows_by_tab = {
        'smtp': [('host', 'Host', 'text', 'smtp.example.test'), ('port', 'Port', 'text', '587'),
                 ('security', 'Security', 'select', 'starttls'), ('from', 'From address', 'text', 'alerts@example.test'),
                 ('username', 'Username', 'text', 'dashboard'), ('tls_verify', 'Verify SMTP TLS certificate', 'checkbox', True)],
        'alerts': [('thresholds_days', 'Alert thresholds (days)', 'text', '7, 30, 60'),
                   ('recipients', 'Recipients', 'textarea', 'ops@example.test'), ('digest_enabled', 'Send daily digest', 'checkbox', True),
                   ('expiry_check_enabled', 'Run expiry check', 'checkbox', True)],
        'inventory': [('repo_url', 'Repository URL', 'text', 'ssh://git@example.test/inventory.git'),
                      ('ref', 'Ref', 'text', 'main'), ('path', 'Path', 'text', 'hosts'), ('webserver_var', 'Web server variable', 'text', 'webserver_type')],
        'deployment': [('batch_percent', 'Batch size (%)', 'text', '10'), ('concurrency', 'Concurrency', 'text', '5'),
                       ('pause_after_canary', 'Pause after canary', 'checkbox', True), ('pause_timeout_hours', 'Pause timeout (hours)', 'text', '24'),
                       ('backup_retention_days', 'Backup retention (days)', 'text', '30'), ('host_timeout_seconds', 'Host timeout (seconds)', 'text', '600')],
        'scanning': [('timeout_seconds', 'Timeout (seconds)', 'text', '10'), ('daily_at', 'Daily scan time', 'text', '02:00'), ('enabled', 'Run daily scan', 'checkbox', True)],
        'schedule': [('discovery_nightly_at', 'Nightly discovery', 'text', '01:00'), ('discovery_enabled', 'Run nightly discovery', 'checkbox', True),
                     ('expiry_check_daily_at', 'Expiry check', 'text', '06:00'), ('digest_daily_at', 'Daily digest', 'text', '07:00'),
                     ('cleanup_daily_at', 'Retention cleanup', 'text', '03:00'), ('cleanup_enabled', 'Run cleanup', 'checkbox', True)],
        'general': [('timezone', 'Display time zone', 'text', 'UTC'), ('retention_days', 'Job retention (days)', 'text', '90')],
    }
    smtp_test = ns(status='failed', job_id='fixture-smtp-job', finished_at=now.isoformat(), requested_at=now.isoformat(),
                   recipient='ops@example.test', steps=[ns(step='connect', code=220), ns(step='auth', code=535)],
                   error_class='SMTPAuthenticationError', error_message='Authentication refused. Check the worker SMTP secret.')
    snapshot = ns(keyring=ns(active_version=1, loaded_versions=[1], file_sha256='e' * 64, missing_versions=[], stale_rows=0),
                  worker=ns(state='healthy', last_seen_at=now.isoformat(), heartbeat_interval_seconds=30, stale_after_seconds=300, workers=1),
                  queue=ns(queued=0, running=1, paused=0, failed_24h=1), warnings=[],
                  smtp=ns(consecutive_failures=1, last_error='Authentication refused', last_success_at=None, last_test=smtp_test), last_runs={}, last_jobs={})
    for tab, label in tabs:
        rows = rows_by_tab.get(tab, [])
        context = {"tab": tab, "tab_label": label, "tabs": [ns(name=n, label=l) for n, l in tabs],
                       "fields": [ns(name=n, label=l, widget=w, hint='', placeholder='', choices=[('none', 'None'), ('starttls', 'STARTTLS'), ('ssl', 'SSL/TLS')]) for n, l, w, v in rows],
                       "values": {n: v for n, l, w, v in rows}, "saved": False, "errors": {}, "disabled": {}, "tls_unsafe": False,
                       "smtp_test": smtp_test, "timezone": 'UTC', "when": lambda value: datetime.fromisoformat(value) if value else None,
                       "failures": [], "max_attempts": 3, "inventory": ns(current_rev=None, worker=ns(reporting=True)), "test_pull": None,
                       "bundle": ns(version='fixture', roots=140, enabled=True), "anchors": [], "max_notes": 1000,
                       "snapshot": snapshot, "warning_text": {}, "db_size": '12 MiB', "next_version": 2, "prune_confirmation": 'PRUNE OLD JOBS',
                       "request": ns(url=ns(path='/settings'), state=ns(worker_stale=False))}
        pages['settings-' + tab] = ('settings.html.j2', context)
    for status in ('queued', 'succeeded'):
        pages['settings-smtp-' + status] = ('settings.html.j2', pages['settings-smtp'][1] | {
            'smtp_test': ns(**(vars(smtp_test) | {"status": status, "error_class": None, "error_message": None}))})
    pages['email-expiry'] = ('email/expiry.html.j2', {"common_name": cert.common_name, "phrase": 'expires in 2 days',
                            "san_count": 2, "issuer": 'Example Operations CA', "serial": '0123456789abcdef',
                            "not_after_local": '2026-11-01 12:00 UTC', "not_after_utc": '2026-11-01 12:00 UTC', "same_zone": True,
                            "renewal_state": None, "notes": 'Synthetic fixture only.', "bindings": [host.hostname + ':443'],
                            "more_bindings": 0, "certificate_url": 'https://dashboard.example.test/certificates/42'})
    pages['email-digest'] = ('email/digest.html.j2', {"since": '2026-10-29 12:00 UTC', "generated": '2026-10-30 12:00 UTC',
                            "sections": [ns(title='Expiring certificates', shown=1, intro='Renew at your CA.',
                                         rows=[ns(url='https://dashboard.example.test/certificates/42', text=cert.common_name + ' expires in 2 days')])],
                            "revision": 'Inventory revision: fixture', "dashboard_url": 'https://dashboard.example.test/'})
    return pages


def render(output=OUTPUT):
    env = environment()
    output.mkdir(parents=True, exist_ok=True)
    for name, (template, context) in fixtures().items():
        html = env.get_template(template).render(context)
        html = html.replace('href="/static/', 'href="../../../app/static/')
        html = html.replace('src="/static/', 'src="../../../app/static/')
        html = "\n".join(line.rstrip() for line in html.splitlines()).rstrip() + "\n"
        (output / f"{name}.html").write_text(html, encoding="utf-8")
        print(f"Rendered {name}.html")


if __name__ == "__main__":
    render()
