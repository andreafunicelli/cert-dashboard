"""Render real templates with fake data; no app import or database connection.

Run: uv run python scripts/render_previews.py
Open docs/ui/previews/*.html directly; assets resolve into the repository.
Fixture forms are illustrative only: do not serve these as application pages.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/ui/previews"


def preview_time_tag(value, tz="UTC"):
    """Fixture-only time helper; all fixture timestamps are UTC."""
    if value is None:
        return "—"
    return Markup('<time datetime="{}">{}</time>').format(value.isoformat(), value.strftime("%Y-%m-%d %H:%M UTC"))


def environment():
    env = Environment(
        loader=FileSystemLoader([ROOT / "app/templates", ROOT / "docs/ui/fixtures"]),
        autoescape=True,
    )
    env.globals["time_tag"] = preview_time_tag
    return env


def operator_fixtures():
    """Explicit fake read models, independent of application/database state."""
    stamp = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
    account = {"username": "operator", "notice": None, "must_change": False, "can_change_password": True,
                   "totp_enabled": True, "totp_pending": False, "enrollment": None, "recovery_remaining": 8}
    counters = [
        {"key": key, "label": label, "count": count, "href": "/certificates?" + query}
        for key, label, count, query in [
            ("expired", "Expired", 2, "expiry=expired&status=active"),
            ("lt7", "Expiring in < 7 days", 3, "expiry=lt7&status=active"),
            ("lt30", "Expiring in < 30 days", 7, "expiry=lt30&status=active"),
            ("lt60", "Expiring in < 60 days", 12, "expiry=lt60&status=active"),
            ("total_active", "Total active", 148, "status=active"),
        ]
    ]
    tls = [{"key": key, "label": label, "count": count, "href": href} for key, label, count, href in [
        ("ok", "OK", 96, "/scans?status=ok"), ("mismatch", "Mismatch", 2, "/scans?status=mismatch"),
        ("expired", "Expired", 1, "/scans?status=expired"),
        ("unreachable", "Unreachable", 1, "/scans?status=unreachable"),
        ("error", "Error", 0, "/scans?status=error"), ("never_scanned", "Never scanned", 4, "/scans"),
        ("unknown_certificates", "Unknown certificates on servers", 1, "/bindings?match_state=unknown"),
        ("key_mismatch_bindings", "Bindings with a key mismatch", 1, "/bindings?match_state=key_mismatch"),
    ]]
    status = {"worker": "stale", "last_heartbeat_at": stamp, "inventory_rev": "abc123def4567890",
                  "inventory_rev_age_hours": 5, "last_digest_at": stamp}
    jobs = [{"id": "fixture-job-1", "type": "scan", "summary": "2 endpoints", "status": "failed",
                 "duration_seconds": 120, "actor": "operator", "finished_at": stamp,
                 "href": "/audit?target_type=job&target_id=fixture-job-1"},
            {"id": "fixture-job-2", "type": "deploy", "summary": "certificate 42 (dry_run)", "status": "succeeded",
                 "duration_seconds": 18, "actor": "operator", "finished_at": stamp, "href": "/deploy/fixture-job-2"}]
    overview = {"counters": counters, "tls_counters": tls, "empty": False, "tz": "UTC",
                    "snapshot": {"status": status, "recent_jobs": jobs,
                                  "renewals": [{"id": "fixture-renewal", "common_name": "api.example.test", "state": "submitted", "age_days": 10}]},
                    "unknown": [{"id": 1, "server_id": 1, "server": "edge.example.test", "vhost_name": "api.example.test",
                                  "port": 443, "on_disk_fingerprint": "a1" * 32}]}
    users = [{"id": number, "username": name, "display_name": name.title(), "email": f"{name}@example.test",
                  "backend": "local" if number != 2 else "ldap", "local": number != 2,
                  "is_active": number != 3, "totp_enabled": number == 1, "must_change": number == 3,
                  "last_login_at": stamp if number != 3 else None, "locked_until": stamp if number == 2 else None}
             for number, name in enumerate(["operator", "directory-admin", "retired-admin"], 1)]
    audit = {"total": 2, "page": 1, "pages": 1, "page_size": 50, "default_page_size": 50, "tz": "UTC", "values": {},
                 "page_url": lambda page: "/audit?" + urlencode({"page": page}), "export_url": "/audit/export.json"}
    events = []
    for action, actor in [("certificate.import", "operator"), ("job.failed", "worker:" + "edge-" * 35)]:
        events.append({"row": {"actor_label": actor, "action": action, "target_type": "certificate", "target_id": "42",
                                    "user_agent": "fixture-browser/1.0 " + "long-agent-" * 30},
                           "utc": "2026-10-19T12:00:00Z", "local": "2026-10-19 12:00 UTC", "ip": "2001:db8::1",
                           "details_json": json.dumps({"common_name": "api.example.test", "path": "/etc/tls/" + "long-path-" * 45,
                                                    "note": "<script>fixture escaping check</script>"}, indent=2)})
    return {
        "overview": ("overview.html.j2", overview),
        "overview-empty": ("overview.html.j2", overview | {"empty": True, "unknown": [],
            "counters": [item | {"count": 0} for item in counters], "tls_counters": [item | {"count": 0} for item in tls],
            "snapshot": {"recent_jobs": [], "renewals": [], "status": {"worker": "stale", "last_heartbeat_at": None,
                "inventory_rev": None, "inventory_rev_age_hours": None, "last_digest_at": None}}}),
        "account": ("account.html.j2", account),
        "account-enrollment": ("account.html.j2", account | {"totp_enabled": False, "totp_pending": True,
            "enrollment": {"secret": "PREVIEW-KEY-NOT-A-REAL-SECRET", "provisioning_uri": "otpauth://totp/preview-only",
                            "recovery_codes": ["PREVIEW-ONLY-CODE-0001", "PREVIEW-ONLY-CODE-0002"]}}),
        "account-required": ("account.html.j2", account | {"must_change": True, "password_error": "New passwords do not match."}),
        "account-directory": ("account.html.j2", account | {"can_change_password": False, "totp_enabled": False}),
        "account-error": ("account.html.j2", account | {"disable_error": "Current password is incorrect."}),
        "users": ("users.html.j2", {"users": users, "current_user_id": 1, "values": {}, "tz": "UTC"}),
        "users-empty": ("users.html.j2", {"users": [], "current_user_id": 1, "values": {}, "tz": "UTC"}),
        "audit": ("audit.html.j2", audit | {"items": events}),
        "audit-empty": ("audit.html.j2", audit | {"items": [], "total": 0}),
    }


def fixtures():
    common = {
        "navigation": [
            {"label": label, "url": url, "enabled": True, "reason": ""}
            for label, url in [
                ("Overview", "/"), ("Certificates", "/certificates"), ("Servers", "/servers"),
                ("Deploy", "/deploy"), ("Scans", "/scans"), ("Audit", "/audit"), ("Settings", "/settings"),
            ]
        ],
        "request": SimpleNamespace(url=SimpleNamespace(path="/login"), state=SimpleNamespace(worker_stale=False)),
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
        "shell": ("shell.html.j2", {
            "request": SimpleNamespace(url=SimpleNamespace(path="/"), state=SimpleNamespace(worker_stale=True)),
            "user": SimpleNamespace(display_name="Fixture operator"),
            "status_banner": "Key material cannot be decrypted with the configured master key.",
            "capability_banner": "Discovery and deploy are unavailable: the worker has no known_hosts file.",
            "flash": ["Inventory refresh completed. No changes were made."],
        }),
    }
    for status, message in [(403, "Access denied."), (404, "Page not found."), (500, "An unexpected error occurred.")]:
        pages[f"error-{status}"] = ("error.html.j2", {
            "status": status, "message": message, "request_id": "fixture-request-0001",
        })
    for name, (template, context) in operator_fixtures().items():
        path = "/" if name.startswith("overview") else "/" + name.split("-")[0]
        pages[name] = (template, context | {
            "request": SimpleNamespace(url=SimpleNamespace(path=path), state=SimpleNamespace(worker_stale=False)),
            "user": SimpleNamespace(display_name="Fixture operator"),
        })
    return {name: (template, common | context) for name, (template, context) in pages.items()}


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
