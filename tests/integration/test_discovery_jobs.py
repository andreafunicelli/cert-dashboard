"""Plan 3 Task 10: the ``discover/default`` job, its nightly schedule, retries and the discovery buttons.

Two kinds of test live here. The ones named in the plan run the real worker against the SSH targets (CI only:
they need Docker). The ``stub`` ones replace only the Ansible run (``discover_hosts``) with prepared outcomes and
exercise everything around it for real: the Git inventory, ``ansible-inventory``, the worker, the queue and the
database. They run anywhere there is a PostgreSQL.
"""

import json
import re
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from sqlalchemy import func, select

from app.ansible.discovery import HostDiscovery
from app.crypto.chain import order_chain
from app.crypto.parse import parse_certificates
from app.jobs.handlers import build_registry
from app.jobs.handlers import discover as discover_module
from app.jobs.handlers.discover import request_discovery
from app.jobs.queue import SYSTEM_ACTOR
from app.jobs.worker import scheduler_tick
from app.models import AuditLog, Binding, Endpoint, Job, JobHost, Server
from app.models.enums import JobStatus, JobType
from app.services.audit import Actor
from app.services.certificates import CertificateMetadata, save_certificate
from tests.fixtures.ssh_targets import new_ed25519
from tests.integration.conftest import binding_doc, disable_schedules, host_document, set_setting

WEB01, WEB02, WEB03 = "web01.example.internal", "web02.example.internal", "web03.example.internal"
WWW = "www.example.internal"
LONG_AGO = datetime(2020, 1, 1, tzinfo=UTC)
RESULT_KEYS = {
    "inventory_rev",
    "inventory_rev_date",
    "inventory_refreshed",
    "hosts",
    "ok",
    "failed",
    "unreachable",
    "bindings_added",
    "bindings_updated",
    "bindings_deactivated",
    "endpoints_created",
    "servers_created",
    "servers_deactivated",
    "parse_suspected",
}


@pytest.fixture(autouse=True)
def isolated(queue_factory):
    """Only the discovery the test queues itself runs: no other schedule may enqueue anything."""
    disable_schedules(queue_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup", "discovery")


# --- helpers ------------------------------------------------------------------------------------


def enqueue_discovery(factory, payload, *, actor=SYSTEM_ACTOR, now=LONG_AGO):
    with factory.begin() as db:
        return request_discovery(db, payload, actor, now).id


def job_state(factory, job_id):
    with factory() as db:
        job = db.get(Job, job_id)
        return job.status, job.error_class


def job_of(factory, job_id):
    with factory() as db:
        return db.get(Job, job_id)


def rows_of(factory, job_id):
    with factory() as db:
        rows = db.execute(
            select(Server.hostname, JobHost).join(Server, Server.id == JobHost.server_id).where(JobHost.job_id == job_id)
        ).all()
    return {hostname: row for hostname, row in rows}


def server_of(factory, hostname):
    with factory() as db:
        return db.scalars(select(Server).where(Server.hostname == hostname)).one()


def binding_by(factory, hostname, vhost):
    with factory() as db:
        return db.scalars(
            select(Binding).join(Server, Server.id == Binding.server_id).where(Server.hostname == hostname, Binding.vhost_name == vhost)
        ).one()


def count_rows(factory, model, *where):
    with factory() as db:
        return db.scalar(select(func.count()).select_from(model).where(*where))


def endpoint_of(factory, binding_id):
    with factory() as db:
        return db.scalars(select(Endpoint).where(Endpoint.binding_id == binding_id)).one()


def audits(factory, action, target_id=None):
    with factory() as db:
        query = select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.created_at, AuditLog.id)
        if target_id is not None:
            query = query.where(AuditLog.target_id == str(target_id))
        return list(db.scalars(query))


def import_public(factory, material, now):
    """Import the target's old certificate (public part only) as the inventory entry of §10.2 scenario 3."""
    leaf = parse_certificates(material.cert_pem)[0]
    chain = order_chain(leaf.cert, list(x509.load_pem_x509_certificates(material.chain_pem)))
    with factory.begin() as db:
        saved = save_certificate(
            db, leaf, chain, CertificateMetadata(owner_name="Ada", team="web"), Actor(None, "tester"),
            source="upload_pem", validation_time=now,
        )  # fmt: skip
        return saved.certificate.id


def publish_inventory(repo, hosts, groups=None):
    document = {
        "all": {
            "hosts": {name: dict(variables) for name, variables in hosts.items()},
            "children": {group: {"hosts": {name: {} for name in names}} for group, names in (groups or {}).items()},
        }
    }
    repo.commit({"inventory/hosts.yml": json.dumps(document)})


def retry_to_the_end(worker, clock, delays=(31, 121)):
    for delay in delays:
        clock.advance(seconds=delay)
        worker.tick()
        worker.run_queued(timeout=300)


# --- stub runner: everything but the Ansible run is real -------------------------------------------


def ok_host(name, now, *bindings, webserver="nginx"):
    summary = {
        "webserver": webserver,
        "binaries": {webserver: "/usr/sbin/" + webserver},
        "config_files": [f"/etc/{webserver}/conf.d/{name}.conf"],
        "bindings": len(bindings),
        "warnings": [],
        "dump_bytes": 1234,
        "dump_sha256": "a" * 64,
    }
    return HostDiscovery(name, "ok", None, None, host_document(name, now, bindings, webserver=webserver), summary, "ok")


def unreachable_host(name):
    return HostDiscovery(name, "unreachable", "unreachable", "UNREACHABLE! host key secret-looking text", None, {}, "excerpt")


def auth_host(name):
    return HostDiscovery(name, "failed", "auth", "Permission denied", None, {}, "auth excerpt")


def failed_host(name, reason, text):
    return HostDiscovery(name, "failed", reason, text, None, {"webserver": "nginx"}, "")


class StubRunner:
    """Stands in for ``discover_hosts``; ``outcomes`` maps hostname -> HostDiscovery or ``f(name, now)``."""

    def __init__(self):
        self.outcomes = {}
        self.calls = []

    def __call__(self, runner, hostnames, *, webservers, now, timeout_seconds=1500):
        self.calls.append(SimpleNamespace(hosts=list(hostnames), webservers=dict(webservers), timeout=timeout_seconds))
        found = {}
        for name in hostnames:
            outcome = self.outcomes[name]
            found[name] = outcome(name, now) if callable(outcome) else outcome
        return found


@pytest.fixture
def stub(monkeypatch):
    runner = StubRunner()
    monkeypatch.setattr(discover_module, "discover_hosts", runner)
    return runner


@pytest.fixture
def stub_world(queue_factory, ansible_worker, inventory_repo, stub, clock):
    hosts = {WEB01: {}, WEB02: {"ansible_host": "192.0.2.12", "webserver_type": "nginx"}, WEB03: {"webserver_type": "apache"}}
    repo = inventory_repo(queue_factory, hosts=hosts, groups={"ring_a": [WEB02, WEB03], "canary_ring": [WEB01]})
    for name in hosts:
        stub.outcomes[name] = lambda host, now: ok_host(host, now, binding_doc(WWW))
    return SimpleNamespace(
        factory=queue_factory, worker=ansible_worker(queue_factory), repo=repo, stub=stub, clock=clock, hosts=hosts
    )


def test_stub_whole_inventory_job_rows_result_and_audit(stub_world):
    world = stub_world
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)

    assert job_state(world.factory, job_id) == (JobStatus.SUCCEEDED, None)
    job = job_of(world.factory, job_id)
    assert (job.priority, job.max_attempts) == (200, 3)
    assert set(job.result) == RESULT_KEYS
    assert job.result["inventory_rev"] == world.repo.head
    assert {key: job.result[key] for key in RESULT_KEYS - {"inventory_rev", "inventory_rev_date", "inventory_refreshed"}} == {
        "hosts": 3, "ok": 3, "failed": 0, "unreachable": 0, "bindings_added": 3, "bindings_updated": 0,
        "bindings_deactivated": 0, "endpoints_created": 3, "servers_created": 3, "servers_deactivated": 0,
        "parse_suspected": [],
    }  # fmt: skip
    assert world.stub.calls[0].hosts == [WEB01, WEB02, WEB03]
    assert world.stub.calls[0].webservers == {WEB01: None, WEB02: "nginx", WEB03: "apache"}
    assert job.ansible_artifact_dir

    rows = rows_of(world.factory, job_id)
    assert set(rows) == {WEB01, WEB02, WEB03}
    for row in rows.values():
        assert (row.status, row.binding_id, row.error_message) == ("succeeded", None, None)
        assert row.started_at and row.finished_at
        assert row.precheck["webserver"] == "nginx" and row.precheck["dump_sha256"] == "a" * 64
        assert row.precheck["parse_suspected"] is False
    [run] = audits(world.factory, "discovery.run", job_id)
    assert run.details["attempt"] == 1 and run.details["hosts"] == 3 and run.details["ok"] == 3
    assert run.details["bindings_added"] == 3 and run.details["source"] == "scheduled"
    server = server_of(world.factory, WEB02)
    assert (server.last_discovery_status, server.connection_address, server.ansible_groups) == ("ok", "192.0.2.12", ["ring_a"])
    assert server.inventory_source == f"main:inventory@{world.repo.head}"
    assert count_rows(world.factory, Server) == 3 and count_rows(world.factory, Binding) == 3


def test_stub_manual_discovery_is_audited_with_the_requesting_user(stub_world, web_user_id):
    job_id = enqueue_discovery(stub_world.factory, {"hosts": [WEB01]}, actor=Actor(web_user_id, "admin"))
    stub_world.worker.run_queued(timeout=120)
    [run] = audits(stub_world.factory, "discovery.run", job_id)
    assert (run.actor_user_id, run.details["source"]) == (web_user_id, "manual")


@pytest.fixture
def web_user_id(queue_factory):
    from tests.integration.conftest import create_login_user

    return create_login_user(queue_factory, "discoverer").id


def test_stub_scope_hosts_groups_and_unknown_names(stub_world):
    world = stub_world
    enqueue_discovery(world.factory, {"hosts": [WEB03, WEB01]})
    world.worker.run_queued(timeout=120)
    assert world.stub.calls[-1].hosts == [WEB01, WEB03]  # inventory order, never payload order
    enqueue_discovery(world.factory, {"groups": ["ring_a"]})
    world.worker.run_queued(timeout=120)
    assert world.stub.calls[-1].hosts == [WEB02, WEB03]
    nothing = enqueue_discovery(world.factory, {"hosts": ["ghost.example.internal"]})
    world.worker.run_queued(timeout=120)
    assert job_state(world.factory, nothing) == (JobStatus.FAILED, "config_invalid")
    assert len(world.stub.calls) == 2  # nothing was run for a scope that matches no inventory host
    assert job_of(world.factory, nothing).result == {"retryable": False}


def test_stub_unreachable_hosts_are_retried_alone(stub_world):
    world = stub_world
    world.stub.outcomes[WEB02] = unreachable_host(WEB02)
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)

    assert job_state(world.factory, job_id) == (JobStatus.FAILED, "transient_network")  # retryable, requeued by a tick
    rows = rows_of(world.factory, job_id)
    assert (rows[WEB01].status, rows[WEB03].status, rows[WEB02].status) == ("succeeded", "succeeded", "failed")
    assert rows[WEB02].error_message.startswith("unreachable: ") and "secret-looking" not in rows[WEB02].error_message
    assert server_of(world.factory, WEB02).last_discovery_status == "unreachable"
    assert count_rows(world.factory, Binding) == 2  # web01 and web03 were committed before the retryable failure
    untouched = rows[WEB01].finished_at

    world.stub.outcomes[WEB02] = lambda host, now: ok_host(host, now, binding_doc(WWW))
    retry_to_the_end(world.worker, world.clock, delays=(31,))
    assert world.stub.calls[-1].hosts == [WEB02]  # only the host whose row is still unreachable
    assert job_state(world.factory, job_id) == (JobStatus.SUCCEEDED, None)
    rows = rows_of(world.factory, job_id)
    assert {row.status for row in rows.values()} == {"succeeded"} and rows[WEB01].finished_at == untouched
    assert rows[WEB02].error_message is None
    result = job_of(world.factory, job_id).result
    assert (result["hosts"], result["ok"], result["unreachable"], result["bindings_added"]) == (3, 3, 0, 3)
    assert result["servers_created"] == 3  # counters add up across the attempts
    assert [a.details["attempt"] for a in audits(world.factory, "discovery.run", job_id)] == [1, 2]
    assert server_of(world.factory, WEB02).last_discovery_status == "ok"


def test_stub_still_unreachable_after_the_last_attempt_succeeds_when_something_was_discovered(stub_world):
    world = stub_world
    world.stub.outcomes[WEB03] = unreachable_host(WEB03)
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)
    retry_to_the_end(world.worker, world.clock)
    assert [call.hosts for call in world.stub.calls] == [[WEB01, WEB02, WEB03], [WEB03], [WEB03]]
    job = job_of(world.factory, job_id)
    assert (job.status, job.attempt) == (JobStatus.SUCCEEDED, 3)
    assert (job.result["ok"], job.result["unreachable"], job.result["hosts"]) == (2, 1, 3)


def test_stub_nothing_discovered_and_all_unreachable_fails_as_transient_network_after_three_attempts(stub_world):
    world = stub_world
    for name in world.hosts:
        world.stub.outcomes[name] = unreachable_host(name)
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)
    retry_to_the_end(world.worker, world.clock)
    job = job_of(world.factory, job_id)
    assert (job.status, job.error_class, job.attempt) == (JobStatus.FAILED, "transient_network", 3)
    assert job.result == {"retryable": False}  # the last attempt is final


def test_stub_auth_failure_is_never_retried(stub_world):
    world = stub_world
    for name in world.hosts:
        world.stub.outcomes[name] = auth_host(name)
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)
    retry_to_the_end(world.worker, world.clock)
    job = job_of(world.factory, job_id)
    assert (job.status, job.error_class, job.attempt) == (JobStatus.FAILED, "auth", 1)
    assert "known_hosts" in job.error_message and len(world.stub.calls) == 1
    assert {server_of(world.factory, name).last_discovery_status for name in world.hosts} == {"failed"}
    rows = rows_of(world.factory, job_id)
    assert all(row.status == "failed" and row.error_message.startswith("auth: ") for row in rows.values())
    assert all("known_hosts" in row.error_message for row in rows.values())


def test_stub_one_auth_failure_among_discovered_hosts_does_not_fail_the_job(stub_world):
    world = stub_world
    world.stub.outcomes[WEB01] = auth_host(WEB01)
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)
    job = job_of(world.factory, job_id)
    assert (job.status, job.attempt) == (JobStatus.SUCCEEDED, 1)
    assert (job.result["ok"], job.result["failed"], job.result["unreachable"]) == (2, 1, 0)


def test_stub_other_host_failures_are_recorded_with_their_fixed_reason(stub_world):
    world = stub_world
    world.stub.outcomes[WEB01] = failed_host(WEB01, "dump_failed", "configuration capture failed")
    world.stub.outcomes[WEB02] = failed_host(WEB02, "parse_failed", "configuration could not be parsed")
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)
    rows = rows_of(world.factory, job_id)
    assert rows[WEB01].error_message == "dump_failed: configuration capture failed"
    assert rows[WEB02].error_message == "parse_failed: configuration could not be parsed"
    assert rows[WEB01].precheck == {"webserver": "nginx"} and rows[WEB03].status == "succeeded"
    assert job_state(world.factory, job_id) == (JobStatus.SUCCEEDED, None)


def test_stub_nothing_discovered_for_other_reasons_fails_without_a_retry(stub_world):
    world = stub_world
    for name in world.hosts:
        world.stub.outcomes[name] = failed_host(name, "dump_failed", "configuration capture failed")
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)
    retry_to_the_end(world.worker, world.clock)
    job = job_of(world.factory, job_id)
    assert (job.status, job.error_class, job.attempt) == (JobStatus.FAILED, "transient_network", 1)
    assert len(world.stub.calls) == 1


def test_stub_zero_binding_dump_is_parse_suspected_and_nothing_is_deactivated(stub_world):
    world = stub_world
    first = enqueue_discovery(world.factory, {"hosts": [WEB02]})
    world.worker.run_queued(timeout=120)
    assert job_state(world.factory, first) == (JobStatus.SUCCEEDED, None)
    world.stub.outcomes[WEB02] = lambda host, now: ok_host(host, now)
    world.clock.advance(minutes=5)
    second = enqueue_discovery(world.factory, {"hosts": [WEB02]})
    world.worker.run_queued(timeout=120)
    assert binding_by(world.factory, WEB02, WWW).is_active is True
    job = job_of(world.factory, second)
    assert (job.status, job.result["parse_suspected"], job.result["bindings_deactivated"]) == (JobStatus.SUCCEEDED, [WEB02], 0)
    assert rows_of(world.factory, second)[WEB02].precheck["parse_suspected"] is True


def test_stub_host_removed_from_inventory_is_deactivated_and_not_discovered(stub_world):
    world = stub_world
    enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)
    remaining = {name: variables for name, variables in world.hosts.items() if name != WEB03}
    publish_inventory(world.repo, remaining)
    world.clock.advance(minutes=5)  # past the 60 s no-op window of the checkout
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)

    assert world.stub.calls[-1].hosts == [WEB01, WEB02]
    removed = server_of(world.factory, WEB03)
    assert removed.is_active is False
    assert binding_by(world.factory, WEB03, WWW).is_active is False
    assert count_rows(world.factory, Binding) == 3 and count_rows(world.factory, Server) == 3  # nothing deleted
    assert job_of(world.factory, job_id).result["servers_deactivated"] == 1
    assert set(rows_of(world.factory, job_id)) == {WEB01, WEB02}
    assert [a.target_id for a in audits(world.factory, "server.deactivate")] == [str(removed.id)]


def test_stub_an_empty_inventory_fails_as_transient_network_and_is_audited(stub_world):
    world = stub_world
    publish_inventory(world.repo, {})
    world.clock.advance(minutes=5)  # past the 60 s no-op window of the checkout
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)
    job = job_of(world.factory, job_id)
    assert (job.status, job.error_class, job.attempt) == (JobStatus.FAILED, "transient_network", 1)
    assert world.stub.calls == [] and rows_of(world.factory, job_id) == {}
    [run] = audits(world.factory, "discovery.run", job_id)
    assert run.details["hosts"] == 0 and run.details["ok"] == 0


def test_stub_an_inventory_hostname_starting_with_a_dash_never_reaches_the_run_limit(stub_world):
    world = stub_world
    unsafe = "-oProxyCommand"
    hosts = {**world.hosts, unsafe: {}}
    publish_inventory(world.repo, hosts, {"ring_a": [WEB02, unsafe]})
    world.stub.outcomes[unsafe] = lambda host, now: ok_host(host, now, binding_doc(WWW))
    world.clock.advance(minutes=5)

    whole = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)
    assert world.stub.calls[-1].hosts == [WEB01, WEB02, WEB03]
    assert unsafe not in rows_of(world.factory, whole)
    assert job_state(world.factory, whole) == (JobStatus.SUCCEEDED, None)

    enqueue_discovery(world.factory, {"groups": ["ring_a"]})
    world.worker.run_queued(timeout=120)
    assert world.stub.calls[-1].hosts == [WEB02]
    assert all(not name.startswith("-") for call in world.stub.calls for name in call.hosts)


def test_stub_a_crashing_run_leaves_no_running_row_behind(stub_world, monkeypatch):
    world = stub_world

    def boom(*_args, **_kwargs):
        raise RuntimeError("runner exploded")

    monkeypatch.setattr(discover_module, "discover_hosts", boom)
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)
    assert job_state(world.factory, job_id) == (JobStatus.FAILED, "internal")
    rows = rows_of(world.factory, job_id)
    assert {row.status for row in rows.values()} == {"failed"} and all(row.finished_at for row in rows.values())
    assert "exploded" not in str(job_of(world.factory, job_id).error_message)


def test_stub_a_host_whose_document_cannot_be_applied_fails_alone(stub_world, monkeypatch):
    world = stub_world
    real = discover_module.reconcile_host

    def selective(db, server_id, document, **kwargs):
        if document["hostname"] == WEB02:
            raise RuntimeError("cannot apply")
        return real(db, server_id, document, **kwargs)

    monkeypatch.setattr(discover_module, "reconcile_host", selective)
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=120)
    rows = rows_of(world.factory, job_id)
    assert (rows[WEB01].status, rows[WEB02].status, rows[WEB03].status) == ("succeeded", "failed", "succeeded")
    assert rows[WEB02].error_message.startswith("parse_failed: ")
    assert server_of(world.factory, WEB02).last_discovery_status == "failed"
    assert job_state(world.factory, job_id) == (JobStatus.SUCCEEDED, None)


def test_stub_the_inventory_without_a_repository_fails_closed(stub_world):
    set_setting(stub_world.factory, "inventory.repo_url", "")
    job_id = enqueue_discovery(stub_world.factory, {})
    stub_world.worker.run_queued(timeout=60)
    assert job_state(stub_world.factory, job_id) == (JobStatus.FAILED, "config_invalid")
    assert stub_world.stub.calls == []


# --- nightly schedule (§7.1) -----------------------------------------------------------------------


def test_nightly_schedule(queue_factory):
    set_setting(queue_factory, "discovery.enabled", True)
    scheduler_tick(queue_factory, build_registry(), datetime(2026, 10, 20, 3, 0, 30, tzinfo=UTC))
    with queue_factory() as db:
        [job] = db.scalars(select(Job).where(Job.type == JobType.DISCOVER)).all()
    assert (job.payload, job.priority, job.scheduled_reason, job.max_attempts) == ({}, 100, "nightly", 3)
    assert job.requested_by is None
    scheduler_tick(queue_factory, build_registry(), datetime(2026, 10, 20, 3, 5, tzinfo=UTC))
    assert count_rows(queue_factory, Job, Job.type == JobType.DISCOVER) == 1  # once per occurrence

    set_setting(queue_factory, "discovery.enabled", False)
    scheduler_tick(queue_factory, build_registry(), datetime(2026, 10, 21, 3, 0, 30, tzinfo=UTC))
    assert count_rows(queue_factory, Job, Job.type == JobType.DISCOVER) == 1


def test_nightly_time_follows_the_setting(queue_factory):
    set_setting(queue_factory, "discovery.enabled", True)
    set_setting(queue_factory, "discovery.nightly_at", "01:30")
    scheduler_tick(queue_factory, build_registry(), datetime(2026, 10, 20, 1, 29, tzinfo=UTC))
    assert count_rows(queue_factory, Job, Job.type == JobType.DISCOVER) == 0
    scheduler_tick(queue_factory, build_registry(), datetime(2026, 10, 20, 1, 30, 30, tzinfo=UTC))
    assert count_rows(queue_factory, Job, Job.type == JobType.DISCOVER) == 1


# --- buttons: the web process only enqueues (§3.1, §8.6) -------------------------------------------


def discovery_jobs(factory):
    with factory() as db:
        return list(db.scalars(select(Job).where(Job.type == JobType.DISCOVER, Job.priority == 200).order_by(Job.created_at, Job.id)))


def post(client, path, token=True, **fields):
    data = {"csrf_token": client.fixture_csrf, **fields} if token else fields
    return client.post(path, data=data, follow_redirects=False)


@pytest.fixture
def clean_discovery_jobs(web_factory):
    with web_factory.begin() as db:
        db.query(Job).filter(Job.type == JobType.DISCOVER).delete()
    disable_schedules(web_factory, "discovery")


def test_discover_buttons_enqueue_without_running_ansible(signed_in, server_map, web_factory, clean_discovery_jobs):
    web01 = server_map.server("web01.example.internal")
    page = signed_in.get(f"/servers/{web01.id}").text
    assert f'action="/servers/{web01.id}/discover"' in page and "discover/default not registered" not in page
    assert 'name="csrf_token"' in page.split('id="actions"', 1)[1]

    assert post(signed_in, f"/servers/{web01.id}/discover", token=False).status_code == 403
    assert discovery_jobs(web_factory) == []
    response = post(signed_in, f"/servers/{web01.id}/discover")
    assert response.status_code == 303 and response.headers["location"] == f"/servers/{web01.id}"
    [job] = discovery_jobs(web_factory)
    assert (job.payload, job.priority, job.max_attempts, job.scheduled_reason) == ({"hosts": [web01.hostname]}, 200, 3, "manual")
    assert job.requested_by is not None and job.status == JobStatus.QUEUED

    listing = signed_in.get("/servers").text
    assert 'action="/servers/discover"' in listing and 'value="all"' in listing and 'value="group"' in listing
    assert post(signed_in, "/servers/discover", token=False, scope="all").status_code == 403
    group = post(signed_in, "/servers/discover", scope="group", group=server_map.group)
    everything = post(signed_in, "/servers/discover", scope="all")
    host = post(signed_in, "/servers/discover", scope="host", hostname=web01.hostname)
    assert {r.status_code for r in (group, everything, host)} == {303}
    jobs = discovery_jobs(web_factory)[1:]
    assert [job.payload for job in jobs] == [{"groups": [server_map.group]}, {}, {"hosts": [web01.hostname]}]
    assert {job.priority for job in jobs} == {200}


def test_discover_buttons_refuse_bad_scopes_unknown_targets_and_inactive_servers(signed_in, server_map, web_factory, clean_discovery_jobs):
    old = server_map.server("old01.example.internal")  # inactive
    refused = {
        422: [
            {"scope": "everything"}, {"scope": "group"}, {"scope": "group", "group": "bad name"}, {"scope": "group", "group": "-x"},
            {"scope": "host"}, {"scope": "host", "hostname": "web01*"}, {"scope": "host", "hostname": old.hostname},
            {"scope": "all", "extra": "x"},
        ],
        404: [{"scope": "group", "group": "no-such-group"}, {"scope": "host", "hostname": "ghost.example.internal"}],
    }
    for status, forms in refused.items():
        for form in forms:
            assert post(signed_in, "/servers/discover", **form).status_code == status, form
    assert post(signed_in, f"/servers/{old.id}/discover").status_code == 422
    assert post(signed_in, "/servers/999999999/discover").status_code == 404
    assert discovery_jobs(web_factory) == []


def test_the_buttons_are_disabled_when_the_handler_is_not_registered(signed_in, server_map, web_factory):
    from app.jobs.worker import JobRegistry

    signed_in.app.state.job_registry = JobRegistry()
    web01 = server_map.server("web01.example.internal")
    page = signed_in.get(f"/servers/{web01.id}").text
    assert "handler discover/default not registered (Plan 3)" in page
    assert f'action="/servers/{web01.id}/discover"' not in page
    assert post(signed_in, f"/servers/{web01.id}/discover").status_code == 409
    assert post(signed_in, "/servers/discover", scope="all").status_code == 409


# --- real targets (CI): §10.2 scenarios 2-3 --------------------------------------------------------


@pytest.fixture
def short_artifacts():
    """A short ``artifacts_root``: ssh refuses a multiplexing socket path of 108+ bytes, and pytest's ``tmp_path``
    is too deep for ``<artifacts>/<job_id>/run/cp/<40-hex hash>`` (production's ``/srv/artifacts`` is not)."""
    root = Path(tempfile.mkdtemp(prefix="cd-", dir="/tmp"))
    yield root
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def targets_world(queue_factory, ansible_worker, inventory_repo, ssh_targets, fresh_targets, clock, short_artifacts):
    repo = inventory_repo(queue_factory, hosts=ssh_targets.inventory_hosts())

    def build_worker(**overrides):
        settings = {
            "ansible_ssh_key": ssh_targets.client_key,
            "known_hosts_file": ssh_targets.known_hosts,
            "artifacts_root": short_artifacts,
        }
        return ansible_worker(queue_factory, **{**settings, **overrides})

    return SimpleNamespace(
        factory=queue_factory, worker=build_worker(), build_worker=build_worker, repo=repo, targets=ssh_targets, clock=clock
    )


def test_discover_unknown_then_import_then_matched(targets_world, now):
    world, targets = targets_world, targets_world.targets
    first = enqueue_discovery(world.factory, {"hosts": [WEB01]})
    world.worker.run_queued(timeout=300)
    assert job_state(world.factory, first) == (JobStatus.SUCCEEDED, None)
    www = binding_by(world.factory, WEB01, WWW)
    assert (www.match_state, www.certificate_id, www.on_disk_fingerprint) == ("unknown", None, targets.old.fingerprint)
    certificate_id = import_public(world.factory, targets.old, now)  # §10.2 scenario 3
    world.clock.advance(minutes=5)
    enqueue_discovery(world.factory, {"hosts": [WEB01]})
    world.worker.run_queued(timeout=300)
    www = binding_by(world.factory, WEB01, WWW)
    assert (www.match_state, www.certificate_id) == ("matched", certificate_id)
    assert endpoint_of(world.factory, www.id).expected_certificate_id == certificate_id
    assert count_rows(world.factory, Binding) == 2 and count_rows(world.factory, Server) == 3


def test_discover_apache_binding_row(targets_world):
    world, targets = targets_world, targets_world.targets
    job_id = enqueue_discovery(world.factory, {"hosts": [WEB03]})
    world.worker.run_queued(timeout=300)
    assert job_state(world.factory, job_id) == (JobStatus.SUCCEEDED, None)
    www = binding_by(world.factory, WEB03, WWW)  # the plain :80 vhost has no binding
    assert (www.webserver, www.port, www.config_file) == ("apache", 18445, "/etc/apache2/sites-enabled/www.conf")
    assert (www.cert_path, www.key_path, www.chain_path) == (
        "/etc/apache2/ssl/www.crt", "/etc/apache2/ssl/www.key", "/etc/apache2/ssl/www.chain.pem",
    )  # fmt: skip
    assert (www.cert_owner, www.cert_group, www.cert_mode, www.key_mode) == ("root", "root", 0o644, 0o600)
    assert (www.on_disk_fingerprint, www.on_disk_key_public_sha256) == (targets.old.fingerprint, targets.old.spki_sha256)
    assert (www.match_state, www.is_active) == ("unknown", True)
    assert count_rows(world.factory, Binding) == 1
    assert targets.unchanged_since_reset("ssh-apache"), targets.last_changes


def test_whole_inventory_job_rows_result_and_audit(targets_world):
    world, targets = targets_world, targets_world.targets
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=300)
    job = job_of(world.factory, job_id)
    assert job.status == JobStatus.SUCCEEDED, (job.error_class, job.error_message)
    assert set(job.result) == RESULT_KEYS and job.result["inventory_rev"] == world.repo.head
    assert (job.result["hosts"], job.result["ok"], job.result["bindings_added"], job.result["servers_created"]) == (3, 3, 4, 3)
    rows = rows_of(world.factory, job_id)
    assert set(rows) == {WEB01, WEB02, WEB03} and all(row.status == "succeeded" for row in rows.values())
    assert [rows[name].precheck["webserver"] for name in (WEB01, WEB02, WEB03)] == ["nginx", "nginx", "apache"]
    assert rows[WEB01].precheck["bindings"] == 2 and "/etc/nginx/conf.d/legacy.conf" in rows[WEB01].precheck["config_files"]
    assert len(audits(world.factory, "discovery.run", job_id)) == 1
    assert all(targets.unchanged_since_reset(service) for service in targets.hosts), targets.last_changes


def test_unreachable_host_is_retried_alone(targets_world):
    world, targets = targets_world, targets_world.targets
    job_id = enqueue_discovery(world.factory, {})
    targets.stop("ssh-nginx-2")
    try:
        world.worker.run_queued(timeout=300)
    finally:
        targets.start("ssh-nginx-2")
    assert job_state(world.factory, job_id) == (JobStatus.FAILED, "transient_network")
    rows = rows_of(world.factory, job_id)
    assert (rows[WEB01].status, rows[WEB03].status, rows[WEB02].status) == ("succeeded", "succeeded", "failed")
    assert rows[WEB02].error_message.startswith("unreachable: ")
    untouched = rows[WEB01].finished_at
    publish_inventory(world.repo, targets.inventory_hosts())  # the restarted target may listen on another port
    retry_to_the_end(world.worker, world.clock, delays=(61,))
    assert job_state(world.factory, job_id) == (JobStatus.SUCCEEDED, None)
    rows = rows_of(world.factory, job_id)
    assert {row.status for row in rows.values()} == {"succeeded"} and rows[WEB01].finished_at == untouched
    assert [a.details["attempt"] for a in audits(world.factory, "discovery.run", job_id)] == [1, 2]
    assert binding_by(world.factory, WEB02, WWW).is_active


def test_auth_failure_is_never_retried(targets_world, tmp_path):
    world, targets = targets_world, targets_world.targets
    forged = tmp_path / "known_hosts_forged"
    forged.write_text("".join(f"[127.0.0.1]:{h.ssh_port} {new_ed25519().public_line}\n" for h in targets.hosts.values()))
    worker = world.build_worker(known_hosts_file=forged)
    job_id = enqueue_discovery(world.factory, {})
    worker.run_queued(timeout=300)
    retry_to_the_end(worker, world.clock)
    job = job_of(world.factory, job_id)
    assert (job.status, job.error_class, job.attempt) == (JobStatus.FAILED, "auth", 1)
    assert "known_hosts" in job.error_message
    assert {server_of(world.factory, name).last_discovery_status for name in (WEB01, WEB02, WEB03)} == {"failed"}
    assert count_rows(world.factory, Binding) == 0


def test_zero_binding_dump_is_parse_suspected(targets_world):
    world, targets = targets_world, targets_world.targets
    enqueue_discovery(world.factory, {"hosts": [WEB02]})
    world.worker.run_queued(timeout=300)
    assert binding_by(world.factory, WEB02, WWW).is_active
    targets.put("ssh-nginx-2", "/etc/nginx/conf.d/www.conf", b"# no vhosts any more\n", mode=0o644)
    world.clock.advance(minutes=5)
    second = enqueue_discovery(world.factory, {"hosts": [WEB02]})
    world.worker.run_queued(timeout=300)
    job = job_of(world.factory, second)
    assert (job.status, job.result["parse_suspected"]) == (JobStatus.SUCCEEDED, [WEB02])
    assert binding_by(world.factory, WEB02, WWW).is_active
    assert rows_of(world.factory, second)[WEB02].precheck["parse_suspected"] is True


def test_host_removed_from_inventory_is_deactivated(targets_world):
    world, targets = targets_world, targets_world.targets
    enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=300)
    hosts = targets.inventory_hosts()
    hosts.pop(WEB03)
    publish_inventory(world.repo, hosts)
    world.clock.advance(minutes=5)
    job_id = enqueue_discovery(world.factory, {})
    world.worker.run_queued(timeout=300)
    assert job_state(world.factory, job_id) == (JobStatus.SUCCEEDED, None)
    assert server_of(world.factory, WEB03).is_active is False
    assert binding_by(world.factory, WEB03, WWW).is_active is False
    assert count_rows(world.factory, Server) == 3 and set(rows_of(world.factory, job_id)) == {WEB01, WEB02}


def test_tls_directives_in_an_included_file_reconcile_to_the_same_matched_binding(targets_world, now):
    """D3 end to end: the parser attributes an include inside the server block to that block."""
    world, targets = targets_world, targets_world.targets
    certificate_id = import_public(world.factory, targets.old, now)
    enqueue_discovery(world.factory, {"hosts": [WEB01]})
    world.worker.run_queued(timeout=300)
    inline = binding_by(world.factory, WEB01, WWW)
    assert (inline.match_state, inline.certificate_id) == ("matched", certificate_id)
    transitions = len(audits(world.factory, "binding.match_state"))

    config = targets.read("ssh-nginx-1", "/etc/nginx/conf.d/www.conf").decode()
    moved, count = re.subn(r"^\s*ssl_certificate_key\s+\S+;\n", "    include snippets/www-key.conf;\n", config, flags=re.MULTILINE)
    assert count == 1
    targets.exec("ssh-nginx-1", "mkdir", "-p", "/etc/nginx/snippets")
    targets.put("ssh-nginx-1", "/etc/nginx/snippets/www-key.conf", b"ssl_certificate_key /etc/nginx/ssl/www.key;\n", mode=0o644)
    targets.put("ssh-nginx-1", "/etc/nginx/conf.d/www.conf", moved.encode(), mode=0o644)
    targets.mark_baseline("ssh-nginx-1")

    world.clock.advance(minutes=5)
    job_id = enqueue_discovery(world.factory, {"hosts": [WEB01]})
    world.worker.run_queued(timeout=300)

    assert job_state(world.factory, job_id) == (JobStatus.SUCCEEDED, None)
    included = binding_by(world.factory, WEB01, WWW)
    assert included.id == inline.id  # the same binding, not a new one
    assert (included.match_state, included.certificate_id, included.key_path) == ("matched", certificate_id, "/etc/nginx/ssl/www.key")
    assert count_rows(world.factory, Binding) == 2
    assert len(audits(world.factory, "binding.match_state")) == transitions  # no state change at all
    assert job_of(world.factory, job_id).result["bindings_added"] == 0
    assert targets.unchanged_since_reset("ssh-nginx-1"), targets.last_changes
