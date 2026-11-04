"""Worker integration for dashboard-managed sources (Slice B contract §7, §9 W; card W).

A user who only manages the dashboard must be able to run discovery and deploy: active manual hosts are
part of every discover/deploy inventory (with or without a repository) and dashboard-trusted host keys
are part of the ``known_hosts`` the worker uses. The stub tests replace only the Ansible *connection*
(``discover_hosts``) and exercise everything around it for real — the rendered YAML inventory,
``ansible-inventory`` of the Git source, the worker, the queue and the database — so they run anywhere
there is a PostgreSQL. The real-target tests at the bottom need the ``ssh-targets`` compose profile and
run in CI only.
"""

import hashlib
import json
import shutil
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.ansible.discovery import HostDiscovery
from app.jobs.handlers import discover as discover_module
from app.jobs.handlers.discover import request_discovery
from app.jobs.queue import SYSTEM_ACTOR
from app.models import AuditLog, Binding, Job, Server, SshHostKey
from app.models.enums import JobStatus, JobType
from tests.integration.conftest import binding_doc, disable_schedules, enqueue_one, host_document, set_setting

MANUAL01, MANUAL02 = "manual01.example.test", "manual02.example.test"
WEB01 = "web01.example.internal"
WWW = "www.example.internal"
LONG_AGO = datetime(2020, 1, 1, tzinfo=UTC)
REVISION = "main:inventory@" + "a" * 40
NO_INVENTORY = "No inventory: add a host in Inventory or configure a repository."


@pytest.fixture(autouse=True)
def isolated(queue_factory):
    """Only the job the test queues itself runs: no schedule may enqueue anything."""
    disable_schedules(queue_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup", "discovery")


# --- helpers ---------------------------------------------------------------------------------------


def add_host(factory, hostname, *, groups=(), address=None, webserver=None, active=True, source="manual", **columns):
    with factory.begin() as db:
        server = Server(
            hostname=hostname,
            ansible_groups=list(groups),
            connection_address=address,
            webserver=webserver,
            inventory_source=source,
            is_active=active,
            **columns,
        )
        db.add(server)
        db.flush()
        return server.id


def add_host_key(factory, host, public_key, key_type="ssh-ed25519"):
    with factory.begin() as db:
        db.add(
            SshHostKey(
                host=host,
                key_type=key_type,
                public_key=public_key,
                fingerprint_sha256="SHA256:" + "a" * 43,
            )
        )


def enqueue_discovery(factory, payload=None):
    with factory.begin() as db:
        return request_discovery(db, payload or {}, SYSTEM_ACTOR, LONG_AGO).id


def job_of(factory, job_id):
    with factory() as db:
        return db.get(Job, job_id)


def job_state(factory, job_id):
    job = job_of(factory, job_id)
    return job.status, job.error_class


def server_of(factory, hostname):
    with factory() as db:
        return db.scalars(select(Server).where(Server.hostname == hostname)).one()


def count_rows(factory, model, *where):
    with factory() as db:
        return db.scalar(select(func.count()).select_from(model).where(*where))


def audits(factory, action, target_id=None):
    with factory() as db:
        query = select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.created_at, AuditLog.id)
        if target_id is not None:
            query = query.where(AuditLog.target_id == str(target_id))
        return list(db.scalars(query))


def ok_host(name, now, *bindings, webserver="nginx"):
    return HostDiscovery(name, "ok", None, None, host_document(name, now, bindings, webserver=webserver), {}, "ok")


class StubRunner:
    """Stands in for ``discover_hosts``: records the context the handler handed it, returns fixed outcomes."""

    def __init__(self):
        self.outcomes = {}
        self.calls = []

    def __call__(self, runner, hostnames, *, webservers, now, timeout_seconds=1500):
        known_hosts = Path(runner.secrets.known_hosts)
        self.calls.append(
            SimpleNamespace(
                hosts=list(hostnames),
                webservers=dict(webservers),
                inventory=runner.inventory,
                known_hosts=known_hosts.read_text() if known_hosts.is_file() else None,
                known_hosts_mode=stat.S_IMODE(known_hosts.stat().st_mode) if known_hosts.is_file() else None,
            )
        )
        return {
            name: self.outcomes[name](name, now) if callable(self.outcomes[name]) else self.outcomes[name]
            for name in hostnames
        }


@pytest.fixture
def stub(monkeypatch):
    runner = StubRunner()
    monkeypatch.setattr(discover_module, "discover_hosts", runner)
    return runner


def stub_ok(stub, *hostnames, binding=WWW):
    for name in hostnames:
        stub.outcomes[name] = lambda host, now: ok_host(host, now, binding_doc(binding))


def publish_inventory(repo, hosts, groups=None):
    document = {
        "all": {
            "hosts": {name: dict(variables) for name, variables in hosts.items()},
            "children": {group: {"hosts": {name: {} for name in names}} for group, names in (groups or {}).items()},
        }
    }
    repo.commit({"inventory/hosts.yml": json.dumps(document)})


# --- manual hosts are a first-class inventory (contract §7.1) ---------------------------------------


def test_manual_only_discovery_uses_the_rendered_inventory(queue_factory, ansible_worker, clock, stub):
    """No repository at all: the job runs against the manual hosts rendered into a YAML inventory."""
    add_host(queue_factory, MANUAL01, groups=("web", "prod"), address="10.0.0.11", webserver="nginx")
    add_host(queue_factory, MANUAL02)  # ungrouped, no address, no webserver
    stub_ok(stub, MANUAL01, MANUAL02)
    worker = ansible_worker(queue_factory)
    job_id = enqueue_discovery(queue_factory)
    worker.run_queued(timeout=120)

    assert job_state(queue_factory, job_id) == (JobStatus.SUCCEEDED, None)
    assert stub.calls[0].hosts == [MANUAL01, MANUAL02]
    assert stub.calls[0].webservers == {MANUAL01: "nginx", MANUAL02: None}
    job = job_of(queue_factory, job_id)
    assert "inventory_rev" not in job.result and "inventory_rev_date" not in job.result
    assert job.result["inventory_source"] == "manual"
    assert job.result["hosts"] == 2 and job.result["ok"] == 2 and job.result["bindings_added"] == 2

    for hostname in (MANUAL01, MANUAL02):
        server = server_of(queue_factory, hostname)
        assert (server.inventory_source, server.is_active, server.last_discovery_status) == ("manual", True, "ok")
    assert count_rows(queue_factory, Binding) == 2

    rendered = Path(job.ansible_artifact_dir) / "run" / "inventory-manual.yml"
    assert rendered.is_file()
    text = rendered.read_text()
    assert f'"{MANUAL01}":' in text and f'"{MANUAL02}"' in text
    assert 'ansible_host: "10.0.0.11"' in text and 'webserver_type: "nginx"' in text


def test_the_connection_defaults_reach_the_inventory(queue_factory, ansible_worker, clock, stub):
    add_host(queue_factory, MANUAL01)
    set_setting(queue_factory, "inventory.manual_ssh_user", "deploy")
    set_setting(queue_factory, "inventory.manual_ssh_port", 2222)
    stub_ok(stub, MANUAL01)
    job_id = enqueue_discovery(queue_factory)
    ansible_worker(queue_factory).run_queued(timeout=120)

    job = job_of(queue_factory, job_id)
    text = (Path(job.ansible_artifact_dir) / "run" / "inventory-manual.yml").read_text()
    assert 'ansible_user: "deploy"' in text and "ansible_port: 2222" in text


def test_a_repository_and_manual_hosts_are_one_union_with_git_authoritative(queue_factory, ansible_worker, inventory_repo, clock, stub):
    repo = inventory_repo(queue_factory, hosts={WEB01: {"webserver_type": "nginx"}}, groups={"ring": [WEB01]})
    add_host(queue_factory, MANUAL01, groups=("web",), address="10.0.0.11")
    stub_ok(stub, MANUAL01, WEB01)
    job_id = enqueue_discovery(queue_factory)
    ansible_worker(queue_factory).run_queued(timeout=120)

    assert job_state(queue_factory, job_id) == (JobStatus.SUCCEEDED, None)
    assert stub.calls[0].hosts == [MANUAL01, WEB01]
    job = job_of(queue_factory, job_id)
    assert job.result["inventory_rev"] == repo.head
    assert server_of(queue_factory, MANUAL01).inventory_source == "manual"
    assert server_of(queue_factory, WEB01).inventory_source == f"main:inventory@{repo.head}"


def test_a_git_listing_adopts_the_matching_manual_row_and_keeps_its_identity(queue_factory, ansible_worker, inventory_repo, clock, stub):
    """Git stays authoritative for a hostname it lists: the manual row becomes a repository row, unchanged otherwise."""
    manual_id = add_host(queue_factory, WEB01, groups=("prod",), address="10.0.0.99", webserver="apache")
    with queue_factory.begin() as db:
        server = db.get(Server, manual_id)
        server.display_name, server.notes = "Web 01", "keep me"
    repo = inventory_repo(queue_factory, hosts={WEB01: {"webserver_type": "nginx"}}, groups={"ring": [WEB01]})
    stub_ok(stub, WEB01)
    job_id = enqueue_discovery(queue_factory)
    ansible_worker(queue_factory).run_queued(timeout=120)

    assert job_state(queue_factory, job_id) == (JobStatus.SUCCEEDED, None)
    assert stub.calls[0].hosts == [WEB01]  # Git's definition, never a second copy
    adopted = server_of(queue_factory, WEB01)
    assert (adopted.id, adopted.display_name, adopted.notes) == (manual_id, "Web 01", "keep me")
    assert adopted.inventory_source == f"main:inventory@{repo.head}"
    assert (adopted.ansible_groups, adopted.connection_address, adopted.webserver) == (["ring"], None, "nginx")
    [update] = [row for row in audits(queue_factory, "server.update", manual_id)]
    assert update.details["inventory_source"] == {"from": "manual", "to": f"main:inventory@{repo.head}"}


def test_a_manual_row_absent_from_git_survives_and_inactive_rows_are_not_rendered(queue_factory, ansible_worker, inventory_repo, clock, stub):
    repo = inventory_repo(queue_factory, hosts={WEB01: {}})
    add_host(queue_factory, MANUAL01)
    add_host(queue_factory, MANUAL02, active=False)
    stub_ok(stub, MANUAL01, WEB01)
    job_id = enqueue_discovery(queue_factory)
    ansible_worker(queue_factory).run_queued(timeout=120)
    assert job_state(queue_factory, job_id) == (JobStatus.SUCCEEDED, None)
    assert stub.calls[0].hosts == [MANUAL01, WEB01]

    # A second run whose Git listing lost nothing still never deactivates the manual row.
    publish_inventory(repo, {WEB01: {}})
    clock.advance(minutes=5)
    enqueue_discovery(queue_factory)
    ansible_worker(queue_factory).run_queued(timeout=120)
    survivor = server_of(queue_factory, MANUAL01)
    assert (survivor.is_active, survivor.inventory_source) == (True, "manual")
    assert not [row for row in audits(queue_factory, "server.deactivate") if row.details.get("hostname") == MANUAL01]
    assert server_of(queue_factory, MANUAL02).is_active is False


# --- no inventory at all (contract §7.2) ------------------------------------------------------------


def test_no_repository_and_no_active_manual_host_fails_config_invalid(queue_factory, ansible_worker, stub):
    job_id = enqueue_discovery(queue_factory)
    ansible_worker(queue_factory).run_queued(timeout=120)
    job = job_of(queue_factory, job_id)
    assert (job.status, job.error_class) == (JobStatus.FAILED, "config_invalid")
    assert job.error_message == NO_INVENTORY
    assert stub.calls == []  # nothing was run


def test_an_inactive_manual_host_alone_is_not_an_inventory(queue_factory, ansible_worker, stub):
    add_host(queue_factory, MANUAL01, active=False)
    job_id = enqueue_discovery(queue_factory)
    ansible_worker(queue_factory).run_queued(timeout=120)
    assert job_of(queue_factory, job_id).error_message == NO_INVENTORY
    assert stub.calls == []


def test_the_web_reasons_and_the_status_warning_follow_the_same_condition(queue_factory):
    from app.crypto.keyring import Keyring
    from app.services.settings import status_snapshot
    from app.web.common import inventory_unconfigured_reason

    keyring = Keyring(1, {1: bytes(range(32))})
    now = datetime(2026, 11, 4, 12, tzinfo=UTC)
    with queue_factory() as db:
        assert inventory_unconfigured_reason(db) == NO_INVENTORY
        assert "inventory_not_configured" in status_snapshot(db, keyring, now)["warnings"]

    # One active manual host is an inventory: the reason clears and the status warning goes away.
    add_host(queue_factory, MANUAL01)
    with queue_factory() as db:
        assert inventory_unconfigured_reason(db) == ""
        assert "inventory_not_configured" not in status_snapshot(db, keyring, now)["warnings"]

    # An inactive manual host is not: only active rows count.
    with queue_factory.begin() as db:
        db.get(Server, server_of(queue_factory, MANUAL01).id).is_active = False
    with queue_factory() as db:
        assert inventory_unconfigured_reason(db) == NO_INVENTORY
        assert "inventory_not_configured" in status_snapshot(db, keyring, now)["warnings"]

    # A repository alone is still an inventory.
    set_setting(queue_factory, "inventory.repo_url", "https://git.example.test/inventory.git")
    with queue_factory() as db:
        assert inventory_unconfigured_reason(db) == ""
        assert "inventory_not_configured" not in status_snapshot(db, keyring, now)["warnings"]


# --- dashboard-trusted host keys (contract §7.4) ----------------------------------------------------


def test_a_dashboard_trusted_host_key_reaches_the_job_known_hosts(queue_factory, ansible_worker, tmp_path, clock, stub):
    add_host(queue_factory, MANUAL01)
    add_host_key(queue_factory, MANUAL01, "AAAAC3NzaC1lZDI1NTE5AAAAIdashboard")
    stub_ok(stub, MANUAL01)
    job_id = enqueue_discovery(queue_factory)
    ansible_worker(queue_factory, known_hosts_file=tmp_path / "absent").run_queued(timeout=120)

    assert job_state(queue_factory, job_id) == (JobStatus.SUCCEEDED, None)
    call = stub.calls[0]
    assert call.known_hosts == f"{MANUAL01} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIdashboard\n"
    assert call.known_hosts_mode == 0o600  # staged 0600, and gone after the job


def test_no_known_hosts_file_and_no_trusted_key_fails_config_invalid(queue_factory, ansible_worker, tmp_path, stub):
    add_host(queue_factory, MANUAL01)
    job_id = enqueue_discovery(queue_factory)
    ansible_worker(queue_factory, known_hosts_file=tmp_path / "absent").run_queued(timeout=120)
    job = job_of(queue_factory, job_id)
    assert (job.status, job.error_class) == (JobStatus.FAILED, "config_invalid")
    assert job.error_message == "SSH known_hosts file is missing"
    assert stub.calls == []


def test_the_capability_banner_accepts_dashboard_trusted_keys(signed_in, web_factory, make_worker, clock, tmp_path):
    """The banner appears only while the mounted file is absent *and* no key is trusted in the dashboard."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from app.jobs.worker import record_worker_start

    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    )
    worker = make_worker(web_factory, ansible_ssh_key=key, known_hosts_file=tmp_path / "absent")
    record_worker_start(web_factory, worker.settings, worker.worker_id, clock())
    worker.tick()

    missing = "Discovery and deploy are unavailable: the worker has no known_hosts file"
    assert missing in signed_in.get("/servers").text
    add_host_key(web_factory, "[127.0.0.1]:2222", "AAAAC3NzaC1lZDI1NTE5AAAAIdashboard")
    assert missing not in signed_in.get("/servers").text


def test_the_mounted_file_is_read_only_and_merged_with_the_table(queue_factory, ansible_worker, tmp_path, clock, stub):
    """Architect checklist case: same host/key in the file and the table, then the row is deleted."""
    add_host(queue_factory, MANUAL01)
    add_host(queue_factory, MANUAL02)
    mounted = tmp_path / "mounted_known_hosts"
    line = f"{MANUAL01} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAImounted"
    mounted.write_text(line + "\n")
    mounted.chmod(0o640)
    mode, digest = stat.S_IMODE(mounted.stat().st_mode), hashlib.sha256(mounted.read_bytes()).hexdigest()
    add_host_key(queue_factory, MANUAL01, "AAAAC3NzaC1lZDI1NTE5AAAAImounted")
    add_host_key(queue_factory, MANUAL02, "AAAAC3NzaC1lZDI1NTE5AAAAdatabase")

    stub_ok(stub, MANUAL01, MANUAL02)
    worker = ansible_worker(queue_factory, known_hosts_file=mounted)
    first = enqueue_discovery(queue_factory)
    worker.run_queued(timeout=120)
    assert job_state(queue_factory, first) == (JobStatus.SUCCEEDED, None)
    # The mounted line comes first, then one line per row: the same key appears twice, which is harmless
    # for ssh and the point of "the mounted file grants trust the dashboard cannot revoke".
    assert stub.calls[0].known_hosts == (
        line + "\n" + line + "\n" + f"{MANUAL02} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAdatabase\n"
    )

    with queue_factory.begin() as db:
        db.query(SshHostKey).filter(SshHostKey.host == MANUAL01).delete()
    clock.advance(minutes=5)
    second = enqueue_discovery(queue_factory)
    worker.run_queued(timeout=120)
    assert job_state(queue_factory, second) == (JobStatus.SUCCEEDED, None)
    # The dashboard stops trusting its row; the mounted file still grants that key, unchanged on disk.
    assert stub.calls[1].known_hosts == line + "\n" + f"{MANUAL02} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAdatabase\n"
    assert (stat.S_IMODE(mounted.stat().st_mode), hashlib.sha256(mounted.read_bytes()).hexdigest()) == (mode, digest)


# --- deploy -----------------------------------------------------------------------------------------


def test_a_deploy_job_prepares_the_manual_only_inventory(queue_factory, ansible_worker, clock):
    """The deploy handler must not refuse a missing repository: it fails later, on its own plan."""
    add_host(queue_factory, MANUAL01)
    payload = {
        "certificate_id": 999999,
        "renewal_id": None,
        "batch_percent": 50,
        "pause_after_canary": False,
        "include_unknown": False,
        "chain_override": False,
        "chain_status_at_plan": "trusted",
        "plan_sha256": "0" * 64,
    }
    job_id = enqueue_one(queue_factory, JobType.DEPLOY, payload, priority=100, max_attempts=1)
    ansible_worker(queue_factory).run_queued(timeout=120)
    job = job_of(queue_factory, job_id)
    assert job.status == JobStatus.FAILED
    assert job.error_message != NO_INVENTORY  # the inventory gate passed
    assert (Path(job.ansible_artifact_dir) / "run" / "inventory-manual.yml").is_file()


# --- real targets (CI only): the SSH connection itself ---------------------------------------------


@pytest.fixture
def short_artifacts():
    """A short ``artifacts_root``: ssh refuses a multiplexing socket path of 108+ bytes."""
    root = Path(tempfile.mkdtemp(prefix="cd-", dir="/tmp"))
    yield root
    shutil.rmtree(root, ignore_errors=True)


def target_host(stack):
    """The ``ssh-targets`` row for ``WEB01``: ``TargetStack.hosts`` is keyed by compose service name."""
    match = next((host for host in stack.hosts.values() if host.inventory_name == WEB01), None)
    assert match is not None, f"{WEB01} is not one of the ssh-targets hosts"
    return match


@pytest.fixture
def targets(queue_factory, ansible_worker, ssh_targets, fresh_targets, short_artifacts):
    """One manual host that *is* a live SSH target, connecting through the D6 global user/port.

    The D6 defaults are global (per-host user/port is out of scope), so a manual-only discovery can only
    reach one target at a time: each target listens on its own random SSH port.
    """
    target = target_host(ssh_targets)
    add_host(
        queue_factory,
        WEB01,
        groups=target.groups,
        address="127.0.0.1",
        webserver=target.webserver,
    )
    set_setting(queue_factory, "inventory.manual_ssh_user", "cdeploy")
    set_setting(queue_factory, "inventory.manual_ssh_port", target.ssh_port)
    return SimpleNamespace(
        factory=queue_factory,
        targets=ssh_targets,
        build_worker=lambda **overrides: ansible_worker(
            queue_factory,
            ansible_ssh_key=ssh_targets.client_key,
            known_hosts_file=ssh_targets.known_hosts,
            artifacts_root=short_artifacts,
            **overrides,
        ),
    )


def test_a_manual_only_discovery_connects_to_a_real_target(targets):
    worker = targets.build_worker()
    job_id = enqueue_discovery(targets.factory, {"hosts": [WEB01]})
    worker.run_queued(timeout=300)
    job = job_of(targets.factory, job_id)
    assert job.status == JobStatus.SUCCEEDED, (job.error_class, job.error_message)
    assert server_of(targets.factory, WEB01).last_discovery_status == "ok"
    assert WWW in {binding.vhost_name for binding in _bindings(targets.factory, WEB01)}


def _bindings(factory, hostname):
    with factory() as db:
        return list(
            db.scalars(
                select(Binding)
                .join(Server, Server.id == Binding.server_id)
                .where(Server.hostname == hostname, Binding.is_active.is_(True))
                .order_by(Binding.id)
            )
        )


def test_a_database_only_host_key_lets_discovery_connect(targets, tmp_path):
    """No mounted known_hosts at all: the dashboard-trusted keys alone must authenticate the targets."""
    target = target_host(targets.targets)
    line = next(line for line in targets.targets.known_hosts.read_text().splitlines() if f":{target.ssh_port} " in line)
    host, key_type, public_key = line.split()[:3]
    add_host_key(targets.factory, host, public_key, key_type)
    worker = targets.build_worker(known_hosts_file=tmp_path / "absent")
    job_id = enqueue_discovery(targets.factory, {"hosts": [WEB01]})
    worker.run_queued(timeout=300)
    job = job_of(targets.factory, job_id)
    assert job.status == JobStatus.SUCCEEDED, (job.error_class, job.error_message)
    assert _bindings(targets.factory, WEB01)


def test_deleting_a_duplicated_trusted_row_does_not_revoke_the_mounted_file(targets):
    """Architect checklist case against a real connection: the mounted file's trust survives the row."""
    target = target_host(targets.targets)
    mounted = targets.targets.known_hosts
    before = (hashlib.sha256(mounted.read_bytes()).hexdigest(), stat.S_IMODE(mounted.stat().st_mode))
    line = next(line for line in mounted.read_text().splitlines() if f":{target.ssh_port} " in line)
    host, key_type, public_key = line.split()[:3]
    add_host_key(targets.factory, host, public_key, key_type)
    worker = targets.build_worker()
    first = enqueue_discovery(targets.factory, {"hosts": [WEB01]})
    worker.run_queued(timeout=300)
    assert job_of(targets.factory, first).status == JobStatus.SUCCEEDED

    with targets.factory.begin() as db:
        db.query(SshHostKey).filter(SshHostKey.host == host).delete()
    second = enqueue_discovery(targets.factory, {"hosts": [WEB01]})
    worker.run_queued(timeout=300)
    assert job_of(targets.factory, second).status == JobStatus.SUCCEEDED
    assert (hashlib.sha256(mounted.read_bytes()).hexdigest(), stat.S_IMODE(mounted.stat().st_mode)) == before
