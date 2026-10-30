"""The §12 acceptance commands of ``docs/operations.md`` stay executable.

The first discovery of a brand-new installation is only read-only if the first committed inventory
revision really contains one host — group membership included, because Test pull and discovery count
every member of ``all`` (``app/services/inventory.py``). This test extracts the two documented revisions
and lists them with the same command the worker uses (``ansible-inventory --list``), so the runbook and
the parser cannot drift apart.

Step 8 spot-checks the discovered bindings against the host's own configuration with ``grep``. That
command is only useful if it really matches the certificate and key directives of both webservers,
inline and in included files (D3): a ``\\|`` inside a ``grep -E`` pattern is a literal pipe, not
alternation, and prints nothing. The same test therefore runs the documented commands against a
fixture nginx tree and a fixture Apache tree.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from app.ansible.runner import RunnerSecrets, build_env
from app.models.enums import WebserverType
from app.services.inventory import InventoryHost, list_inventory

DOCS = Path(__file__).resolve().parents[2] / "docs" / "operations.md"

NGINX_ROOT = "/etc/nginx"
APACHE_ROOT = "/etc/apache2"


def documented_block(marker: str, language: str) -> str:
    """The first fenced block in ``language`` after ``marker`` in the runbook."""
    text = DOCS.read_text(encoding="utf-8")
    start = text.find(marker)
    assert start >= 0, f"docs/operations.md lost its {marker} example"
    match = re.search(rf"```{language}\n(.*?)```", text[start:], re.DOTALL)
    assert match is not None, f"the {marker} marker is not followed by a {language} block"
    return match.group(1)


def documented_inventory(marker: str) -> str:
    """The first fenced YAML block after ``marker`` in the runbook."""
    return documented_block(marker, "yaml")


def listed(tmp_path: Path, yaml_text: str) -> dict[str, InventoryHost]:
    inventory = tmp_path / "inventory"
    inventory.mkdir()
    (inventory / "hosts.yml").write_text(yaml_text, encoding="utf-8")
    run_dir = tmp_path / "run"
    for name in ("home", "tmp", "collections", "cp"):
        (run_dir / name).mkdir(parents=True)
    env = build_env(RunnerSecrets(tmp_path / "ssh_key", tmp_path / "known_hosts"), run_dir)
    hosts = list_inventory(inventory, webserver_var="webserver_type", env=env)
    return {host.hostname: host for host in hosts}


def test_the_first_inventory_revision_lists_exactly_one_host(tmp_path: Path) -> None:
    hosts = listed(tmp_path, documented_inventory("runbook:first-inventory"))
    assert list(hosts) == ["web01.example.internal"], hosts
    assert hosts["web01.example.internal"].connection_address == "10.0.0.11"
    assert hosts["web01.example.internal"].groups == ("canary_ring",)
    assert hosts["web01.example.internal"].webserver is WebserverType.NGINX


def test_the_full_inventory_revision_lists_the_three_documented_hosts(tmp_path: Path) -> None:
    hosts = listed(tmp_path, documented_inventory("runbook:full-inventory"))
    assert sorted(hosts) == ["web01.example.internal", "web02.example.internal", "web03.example.internal"]
    assert hosts["web03.example.internal"].webserver is WebserverType.APACHE


def spot_check(marker: str, documented_root: str, tree: Path) -> list[str]:
    """Run the documented command with ``tree`` in place of ``documented_root``; return its lines."""
    command = documented_block(marker, "sh").strip()
    assert documented_root in command, f"{marker} must grep {documented_root}: {command}"
    completed = subprocess.run(
        ["sh", "-c", command.replace(documented_root, str(tree))],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, (
        f"the documented {marker} command matched nothing (exit {completed.returncode}): "
        f"{command}\n{completed.stderr}"
    )
    return completed.stdout.splitlines()


def printed_paths(lines: list[str]) -> list[str]:
    return sorted(line.split()[-1].rstrip(";") for line in lines)


def test_the_spot_check_commands_grep_only_the_installed_webserver_root() -> None:
    nginx = documented_block("runbook:spot-check-nginx", "sh")
    apache = documented_block("runbook:spot-check-apache", "sh")
    assert NGINX_ROOT in nginx and APACHE_ROOT not in nginx, nginx
    assert APACHE_ROOT in apache and NGINX_ROOT not in apache, apache


def test_the_documented_nginx_spot_check_matches_inline_and_included_directives(tmp_path: Path) -> None:
    tree = tmp_path / "nginx"
    (tree / "snippets").mkdir(parents=True)
    (tree / "sites-enabled").mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate /etc/nginx/ssl/www.crt;\n"
        "    ssl_certificate_key /etc/nginx/ssl/www.key;\n"
        "    include snippets/tls.conf;\n"
        "}\n",
        encoding="utf-8",
    )
    (tree / "snippets" / "tls.conf").write_text(
        "ssl_certificate /etc/nginx/ssl/bundle.crt;\n"
        "ssl_certificate_key /etc/nginx/ssl/bundle.key;\n",
        encoding="utf-8",
    )
    # Debian enables a vhost with a symlink; the target sits outside the grepped root here, so only
    # ``grep -R`` (which follows symlinks) can reach it and ``-r`` would silently miss the vhost.
    vhost = tmp_path / "vhosts" / "www.conf"
    vhost.parent.mkdir()
    vhost.write_text("ssl_certificate /etc/nginx/ssl/vhost.crt;\n", encoding="utf-8")
    (tree / "sites-enabled" / "www.conf").symlink_to(vhost)

    lines = spot_check("runbook:spot-check-nginx", NGINX_ROOT, tree)

    assert printed_paths(lines) == [
        "/etc/nginx/ssl/bundle.crt",
        "/etc/nginx/ssl/bundle.key",
        "/etc/nginx/ssl/vhost.crt",
        "/etc/nginx/ssl/www.crt",
        "/etc/nginx/ssl/www.key",
    ], lines


def test_the_documented_apache_spot_check_matches_inline_and_included_directives(tmp_path: Path) -> None:
    tree = tmp_path / "apache2"
    (tree / "sites-enabled").mkdir(parents=True)
    (tree / "apache2.conf").write_text(
        "<VirtualHost *:443>\n"
        "    SSLEngine on\n"
        "    SSLCertificateFile /etc/ssl/certs/www.crt\n"
        "    SSLCertificateKeyFile /etc/ssl/private/www.key\n"
        "    IncludeOptional sites-enabled/*.conf\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    (tree / "sites-enabled" / "www.conf").write_text(
        "SSLCertificateFile /etc/ssl/certs/leaf.crt\n"
        "SSLCertificateChainFile /etc/ssl/certs/chain.pem\n"
        "SSLCertificateKeyFile /etc/ssl/private/leaf.key\n",
        encoding="utf-8",
    )

    lines = spot_check("runbook:spot-check-apache", APACHE_ROOT, tree)

    assert printed_paths(lines) == [
        "/etc/ssl/certs/chain.pem",
        "/etc/ssl/certs/leaf.crt",
        "/etc/ssl/certs/www.crt",
        "/etc/ssl/private/leaf.key",
        "/etc/ssl/private/www.key",
    ], lines
