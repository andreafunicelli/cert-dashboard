"""Settings → Inventory "Test pull": a ``discover/test_pull`` job run through ``ansible_job`` (Plan 3 Task 5)."""

import json
import stat
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.jobs.handlers.ansible_context import ansible_job
from app.jobs.locks import INVENTORY_LOCK, AdvisoryLocks
from app.jobs.queue import JobFailure
from app.jobs.worker import JobContext, record_worker_start
from app.models import Job, WorkerHeartbeat
from app.models.enums import JobStatus, JobType
from app.services.inventory import InventoryRevision
from tests.integration.conftest import disable_schedules, set_setting

PATH = "/settings/inventory/test-pull"
HOSTS = {"web01.example.internal": {"ansible_host": "192.0.2.10"}}
NO_REPO = "No inventory repository is configured"
NO_SSH_KEY = "Discovery and deploy are unavailable: no SSH key is configured."
HTTPS_REPO = "HTTPS://git.example.test/inventory.git"
SSH_REPO = "ssh://git@git.example.test/inventory.git"
MISSING_HOST_TRUST = (
    "no trusted SSH host keys: trust them in Infrastructure → SSH keys or mount a known_hosts file"
)
STUBBED_REVISION = InventoryRevision(
    "main:inventory@" + "a" * 40, datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 1, tzinfo=UTC), True, None
)


@pytest.fixture(autouse=True)
def isolated(web_factory):
    """The web database is shared by the module: no jobs, no worker, and no schedule can enqueue one."""
    disable_schedules(web_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup", "discovery")
    with web_factory.begin() as db:
        db.query(Job).delete()
        db.query(WorkerHeartbeat).delete()


def post(signed_in):
    return signed_in.post(PATH, data={"csrf_token": signed_in.fixture_csrf}, follow_redirects=False)


def jobs_of(factory):
    with factory() as db:
        return list(db.scalars(select(Job).where(Job.type == JobType.DISCOVER).order_by(Job.created_at)))


def test_test_pull_reports_the_resolved_revision(signed_in, web_factory, ansible_worker, inventory_repo):
    repo = inventory_repo(web_factory, hosts=HOSTS)
    response = post(signed_in)
    assert response.status_code == 303
    ansible_worker(web_factory).run_queued()
    [job] = jobs_of(web_factory)
    assert (job.priority, job.max_attempts, job.status) == (200, 1, JobStatus.SUCCEEDED)
    assert job.payload == {"action": "test_pull"}
    assert job.result == {
        "inventory_rev": repo.head,
        "inventory_rev_date": repo.head_date,
        "inventory_refreshed": True,
        "hosts": 1,
        "groups": 0,
    }
    page = signed_in.get("/settings?tab=inventory").text
    assert repo.head[:12] in page and "1 host" in page


def test_tab_shows_times_in_the_display_timezone_and_in_utc(signed_in, web_factory, ansible_worker, inventory_repo):
    set_setting(web_factory, "ui.timezone", "Europe/Rome")
    inventory_repo(web_factory, hosts=HOSTS)
    post(signed_in)
    ansible_worker(web_factory).run_queued()
    page = signed_in.get("/settings?tab=inventory").text
    assert "2026-10-19 14:00 CEST" in page and "2026-10-19 12:00 UTC" in page  # the fixture clock is 12:00 UTC


def test_the_fragment_polls_only_while_the_job_is_open(signed_in, web_factory, ansible_worker, inventory_repo):
    inventory_repo(web_factory, hosts=HOSTS)
    post(signed_in)
    [job] = jobs_of(web_factory)
    queued = signed_in.get(f"{PATH}/{job.id}").text
    assert f'hx-get="{PATH}/{job.id}"' in queued and 'hx-trigger="every 2s"' in queued
    ansible_worker(web_factory).run_queued()
    done = signed_in.get(f"{PATH}/{job.id}").text
    assert "hx-trigger" not in done and "Succeeded" in done
    assert signed_in.get(f"{PATH}/00000000-0000-0000-0000-000000000000").status_code == 404


def test_unconfigured_inventory_disables_the_button_and_fails_closed(signed_in, web_factory, ansible_worker):
    set_setting(web_factory, "inventory.repo_url", "")
    page = signed_in.get("/settings?tab=inventory").text
    assert NO_REPO in page and 'action="/settings/inventory/test-pull"' not in page
    post(signed_in)  # forced past the disabled button
    ansible_worker(web_factory).run_queued()
    [job] = jobs_of(web_factory)
    assert (job.status, job.error_class) == (JobStatus.FAILED, "config_invalid")
    assert job.error_message == "inventory repository is not configured"
    assert "inventory repository is not configured" in signed_in.get("/settings?tab=inventory").text


def test_without_an_ssh_worker_the_tab_says_why(signed_in, web_factory, worker_harness, inventory_repo, clock):
    inventory_repo(web_factory, hosts=HOSTS)
    assert 'action="/settings/inventory/test-pull"' in signed_in.get("/settings?tab=inventory").text  # nobody reported yet
    post(signed_in)
    worker_harness.tick()
    record_worker_start(web_factory, worker_harness.settings, worker_harness.worker_id, clock())
    assert worker_harness.run_queued() == 0  # discover jobs are never claimed without the key
    [job] = jobs_of(web_factory)
    assert job.status == JobStatus.QUEUED
    page = signed_in.get("/settings?tab=inventory").text
    assert NO_SSH_KEY in page and 'action="/settings/inventory/test-pull"' not in page
    assert "Queued" in page


def test_staged_secrets_are_removed_after_the_job(signed_in, web_factory, ansible_worker, inventory_repo):
    inventory_repo(web_factory, hosts=HOSTS)
    post(signed_in)
    worker = ansible_worker(web_factory)
    worker.run_queued()
    [job] = jobs_of(web_factory)
    assert job.status == JobStatus.SUCCEEDED
    assert list(worker.settings.key_staging_dir.iterdir()) == []
    artifacts = worker.settings.artifacts_root / str(job.id)
    assert artifacts.is_dir() and stat.S_IMODE(artifacts.stat().st_mode) == 0o700
    assert job.ansible_artifact_dir == str(artifacts)
    assert worker.settings.ansible_ssh_key.decode().strip().splitlines()[0] not in str(job.result)


def test_busy_inventory_lock_uses_the_current_checkout(signed_in, web_factory, ansible_worker, inventory_repo, clock):
    repo = inventory_repo(web_factory, hosts=HOSTS)
    worker = ansible_worker(web_factory)
    post(signed_in)
    worker.run_queued()
    first = repo.head
    repo.commit({"inventory/extra.txt": "a newer revision"})
    assert repo.head != first
    clock.advance(seconds=300)  # past the 60 s no-op window: only the lock keeps the job from pulling
    locks = AdvisoryLocks(web_factory.kw["bind"])
    with locks.session() as session:
        assert session.try_lock(INVENTORY_LOCK, shared=True)  # another job is reading the checkout
        post(signed_in)
        worker.run_queued()
    locks.close()
    newest = jobs_of(web_factory)[-1]
    assert newest.status == JobStatus.SUCCEEDED
    assert newest.result["inventory_rev"] == first and newest.result["inventory_refreshed"] is False


def test_a_pull_in_progress_requeues_the_job_without_a_checkout_read(signed_in, web_factory, ansible_worker, inventory_repo):
    inventory_repo(web_factory, hosts=HOSTS)
    worker = ansible_worker(web_factory)
    post(signed_in)
    locks = AdvisoryLocks(web_factory.kw["bind"])
    with locks.session() as session:
        assert session.try_lock(INVENTORY_LOCK)  # exclusive: a reset may be changing the files right now
        worker.run_queued()
    locks.close()
    [job] = jobs_of(web_factory)
    assert job.status == JobStatus.QUEUED and job.attempt == 0 and job.run_after > worker.clock()


def test_a_missing_known_hosts_file_fails_before_any_connection(signed_in, web_factory, ansible_worker, inventory_repo, tmp_path):
    """A ``file://`` (here) or ``ssh://`` repository still needs host trust: only HTTPS is exempt (§8.2)."""
    inventory_repo(web_factory, hosts=HOSTS)
    post(signed_in)
    ansible_worker(web_factory, known_hosts_file=tmp_path / "absent").run_queued()
    [job] = jobs_of(web_factory)
    assert (job.status, job.error_class) == (JobStatus.FAILED, "config_invalid")
    assert job.error_message == MISSING_HOST_TRUST
    assert MISSING_HOST_TRUST in signed_in.get("/settings?tab=inventory").text  # the Settings result, verbatim


def test_an_https_test_pull_stages_an_empty_known_hosts_file(web_factory, ansible_worker, inventory_repo, tmp_path, monkeypatch):
    """An HTTPS repository is authenticated by TLS: SSH has no host to verify, so the job stages ``b""``.

    CI has no HTTPS Git server, so only the checkout refresh is replaced; the https-vs-ssh rule, the
    staging area and the inventory listing run for real (the job-context layer §8.2 names).
    """
    inventory_repo(web_factory, hosts=HOSTS)  # ref/path/webserver_var; the URL is replaced below
    set_setting(web_factory, "inventory.repo_url", HTTPS_REPO)
    worker = ansible_worker(web_factory, known_hosts_file=tmp_path / "absent")
    checkout = worker.settings.inventory_root / "repo"
    (checkout / "inventory").mkdir(parents=True)
    (checkout / "inventory" / "hosts.yml").write_text(json.dumps({"all": {"hosts": {}}}), encoding="utf-8")
    monkeypatch.setattr(
        "app.jobs.handlers.ansible_context._refresh_inventory", lambda *args, **kwargs: STUBBED_REVISION
    )
    context = JobContext(uuid4(), "b-w2-worker", web_factory, worker.settings)

    with ansible_job(context, require_repository=True) as job:
        staged = job.runner.secrets.known_hosts
        assert staged.is_file() and staged.read_bytes() == b""
        assert stat.S_IMODE(staged.stat().st_mode) == 0o600
        assert job.config is not None and job.config.repo_url == HTTPS_REPO


def test_an_ssh_test_pull_still_fails_closed_without_host_trust(web_factory, ansible_worker, inventory_repo, tmp_path):
    inventory_repo(web_factory, hosts=HOSTS)
    set_setting(web_factory, "inventory.repo_url", SSH_REPO)
    worker = ansible_worker(web_factory, known_hosts_file=tmp_path / "absent")
    context = JobContext(uuid4(), "b-w2-worker", web_factory, worker.settings)

    with pytest.raises(JobFailure) as failure, ansible_job(context, require_repository=True):
        pytest.fail("an ssh repository must not run without host trust")
    assert (failure.value.error_class, failure.value.message) == ("config_invalid", MISSING_HOST_TRUST)


def test_an_inventory_path_outside_the_checkout_is_refused(signed_in, web_factory, ansible_worker, inventory_repo):
    inventory_repo(web_factory, hosts=HOSTS)
    set_setting(web_factory, "inventory.path", "../elsewhere")
    post(signed_in)
    ansible_worker(web_factory).run_queued()
    [job] = jobs_of(web_factory)
    assert (job.status, job.error_class) == (JobStatus.FAILED, "config_invalid")
    assert job.error_message == "inventory path is outside the checkout"


def test_the_checkout_lives_under_the_inventory_root(signed_in, web_factory, ansible_worker, inventory_repo):
    inventory_repo(web_factory, hosts=HOSTS)
    post(signed_in)
    worker = ansible_worker(web_factory)
    worker.run_queued()
    assert (worker.settings.inventory_root / "repo" / ".git").is_dir()
    assert (worker.settings.inventory_root / "repo" / "inventory" / "hosts.yml").is_file()


def test_the_tab_without_any_job_says_nothing_was_tested(signed_in, web_factory, inventory_repo):
    inventory_repo(web_factory, hosts=HOSTS)
    page = signed_in.get("/settings?tab=inventory").text
    assert "No test pull has run yet." in page and "Current revision: unknown" in page


def test_a_failed_test_pull_shows_its_error_and_keeps_the_last_revision(signed_in, web_factory, ansible_worker, inventory_repo):
    repo = inventory_repo(web_factory, hosts=HOSTS)
    worker = ansible_worker(web_factory)
    post(signed_in)
    worker.run_queued()
    set_setting(web_factory, "inventory.path", "no/such/dir")
    post(signed_in)
    worker.run_queued()
    page = signed_in.get("/settings?tab=inventory").text
    assert "Failed" in page and "config_invalid" in page and "inventory could not be read" in page
    assert repo.head[:12] in page  # the current revision is still the newest succeeded result


def test_test_pull_requires_csrf_and_sign_in(client, signed_in, web_factory):
    assert signed_in.post(PATH, follow_redirects=False).status_code == 403
    assert jobs_of(web_factory) == []
    signed_in.cookies.clear()
    assert signed_in.post(PATH, data={"csrf_token": "x"}, follow_redirects=False).status_code in (303, 403)
    assert jobs_of(web_factory) == []
    assert client.get(f"{PATH}/00000000-0000-0000-0000-000000000000", follow_redirects=False).status_code == 303


def test_a_damaged_checkout_is_repaired_and_audited_with_the_job_id(
    signed_in, web_factory, ansible_worker, inventory_repo, clock
):
    from app.models import AuditLog

    repo = inventory_repo(web_factory, hosts=HOSTS)
    worker = ansible_worker(web_factory)
    post(signed_in)
    worker.run_queued()
    (worker.settings.inventory_root / "repo" / ".git" / "last_pull.json").unlink()  # the marker is only a cache
    clock.advance(seconds=300)
    post(signed_in)
    worker.run_queued()
    newest = jobs_of(web_factory)[-1]
    assert newest.status == JobStatus.SUCCEEDED and newest.result["inventory_rev"] == repo.head
    with web_factory() as db:
        audits = db.scalars(select(AuditLog).where(AuditLog.action == "inventory.inconsistent")).all()
    [audit] = [row for row in audits if row.details["job_id"] == str(newest.id)]
    assert audit.details["reason"] == "marker_missing"
