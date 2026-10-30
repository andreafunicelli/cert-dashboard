"""The §12 acceptance inventory of ``docs/operations.md`` stays executable: one host first, then three.

The first discovery of a brand-new installation is only read-only if the first committed inventory
revision really contains one host — group membership included, because Test pull and discovery count
every member of ``all`` (``app/services/inventory.py``). This test extracts the two documented revisions
and lists them with the same command the worker uses (``ansible-inventory --list``), so the runbook and
the parser cannot drift apart.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.ansible.runner import RunnerSecrets, build_env
from app.models.enums import WebserverType
from app.services.inventory import InventoryHost, list_inventory

DOCS = Path(__file__).resolve().parents[2] / "docs" / "operations.md"


def documented_inventory(marker: str) -> str:
    """The first fenced YAML block after ``marker`` in the runbook."""
    text = DOCS.read_text(encoding="utf-8")
    start = text.find(marker)
    assert start >= 0, f"docs/operations.md lost its {marker} example"
    match = re.search(r"```yaml\n(.*?)```", text[start:], re.DOTALL)
    assert match is not None, f"the {marker} marker is not followed by a YAML block"
    return match.group(1)


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
