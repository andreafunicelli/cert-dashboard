"""Render real templates without importing the app or connecting to a database.

Run: uv run python scripts/render_previews.py
Open docs/ui/previews/*.html directly; assets resolve into the repository.
Fixture forms are illustrative only: do not serve these as application pages.
"""

from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/ui/previews"


def environment():
    return Environment(
        loader=FileSystemLoader([ROOT / "app/templates", ROOT / "docs/ui/fixtures"]),
        autoescape=True,
    )


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
    return {name: (template, common | context) for name, (template, context) in pages.items()}


def render():
    env = environment()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, (template, context) in fixtures().items():
        html = env.get_template(template).render(context)
        html = html.replace('href="/static/', 'href="../../../app/static/')
        html = html.replace('src="/static/', 'src="../../../app/static/')
        (OUTPUT / f"{name}.html").write_text(html + "\n", encoding="utf-8")
        print(f"Rendered {name}.html")


if __name__ == "__main__":
    render()
