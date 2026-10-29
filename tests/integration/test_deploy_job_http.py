"""Deploy job screen over HTTP (Plan 3 Task 18; spec §8.7, §6.5, §8).

The world is Task 13's database-only deploy world (``deploy_world_factory``): three servers, four ``matched``
bindings of a previous certificate, an issued renewal and the fixture root as a trust anchor. Jobs are really
created through ``start_deploy`` -- guardrails, plan hash and host rows included -- and their ``job_host`` rows
are then written directly, so every phase of a rollout can be shown without running Ansible.
"""

import re
from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, update

from app.models import Binding, Job, JobHost, Server
from app.models.enums import JobHostStatus, JobStatus, JobType, WebserverType
from app.services.audit import Actor
from app.services.deploy import DeployOptions, configure_keyring, preview_deploy, start_deploy
from app.services.deploy_views import REPORT_BINDING_FIELDS, REPORT_HOST_FIELDS
from tests.integration.conftest import (
    audit_actions,
    create_login_user,
    disable_schedules,
    fetch,
)

WEB01, WEB02, WEB03 = "web01.example.internal", "web02.example.internal", "web03.example.internal"
OPERATOR = "deploy-screen-operator"
BACKUP_ROOT = "/var/backups/cert-dashboard"
ACTIVE = (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.PAUSED)

_WORLD: SimpleNamespace | None = None


class DeployJobWorld:
    """Create deploy jobs on the Task 13 world and set their rows to any point of a rollout."""

    def __init__(self, factory, world, actor, clock):
        self.factory, self.world, self.actor, self.clock = factory, world, actor, clock

    # --- jobs -------------------------------------------------------------------------------

    def start(self, *, batch_percent: int = 50, pause_after_canary: bool = False):
        """Enqueue a real deploy job through the guardrails and return its id."""
        self._end_active_jobs()
        options = DeployOptions(
            certificate_id=self.world.new_certificate.id,
            batch_percent=batch_percent,
            pause_after_canary=pause_after_canary,
        )
        with self.factory.begin() as db:
            preview = preview_deploy(db, options, self.clock())
            assert not preview.blocked, preview.blocked
            job = start_deploy(
                db,
                options,
                plan_sha256=preview.plan_sha256,
                confirmed=True,
                override_reason=None,
                actor=self.actor,
                now=self.clock(),
            )
            return job.id

    def running(self, *, batch_no: int = 0, batch_percent: int = 33):
        """A deploy in progress: every earlier batch succeeded, this one is running, the rest pending."""
        job_id = self.start(batch_percent=batch_percent)
        at = self.clock() - timedelta(minutes=5)
        with self.factory.begin() as db:
            for batch in self._batches(db, job_id):
                status = (
                    JobHostStatus.SUCCEEDED if batch < batch_no else JobHostStatus.RUNNING if batch == batch_no else None
                )
                for hostname in self._hosts(db, job_id, batch):
                    if status is not None:
                        self._write(
                            db,
                            job_id,
                            hostname,
                            status.value,
                            started_at=at,
                            finished_at=at + timedelta(seconds=30) if status is JobHostStatus.SUCCEEDED else None,
                            backup=status is JobHostStatus.SUCCEEDED,
                            log_excerpt="ok: [www.example.internal] => {\"changed\": true}" if status is JobHostStatus.SUCCEEDED else None,
                        )
            db.get(Job, job_id).status = JobStatus.RUNNING
            db.get(Job, job_id).started_at = at
        return job_id

    def paused(self, *, paused_at):
        """Canary succeeded, job paused for approval, later batches pending."""
        job_id = self.start(batch_percent=50, pause_after_canary=True)
        started = paused_at - timedelta(minutes=4)
        with self.factory.begin() as db:
            self._write(db, job_id, WEB01, "succeeded", started_at=started, finished_at=started + timedelta(minutes=3))
            job = db.get(Job, job_id)
            job.status = JobStatus.PAUSED
            job.paused_at = paused_at
            job.started_at = started
            job.resume_from_batch = 1
        return job_id

    def stopped(self, *, first_failed: str = WEB02, rolled_back: bool = True):
        """Canary succeeded, the first host of batch 1 failed, the rest of the rollout never ran."""
        job_id = self.start(batch_percent=50, pause_after_canary=False)
        at = self.clock() - timedelta(minutes=10)
        with self.factory.begin() as db:
            self._write(db, job_id, WEB01, "succeeded", started_at=at, finished_at=at + timedelta(seconds=40), backup=True)
            self._write(
                db,
                job_id,
                first_failed,
                "rolled_back" if rolled_back else "failed",
                started_at=at + timedelta(seconds=40),
                finished_at=at + timedelta(seconds=90),
                reason="config_test_failed",
                rolled_back=rolled_back,
                rollback_error=None if rolled_back else "rollback reload failed",
                backup=True,
            )
            for hostname in (WEB03,):
                self._write(db, job_id, hostname, "skipped", reason="rollout_stopped")
            job = db.get(Job, job_id)
            job.status = JobStatus.FAILED
            job.started_at = at
            job.finished_at = at + timedelta(seconds=90)
            job.error_class = "config_invalid"
            job.error_message = f"rollout stopped: {first_failed} failed (config_test_failed)"
        return job_id

    def finished(self, *, status: str = "succeeded"):
        """Every host ran: the job is terminal."""
        job_id = self.start(batch_percent=50, pause_after_canary=False)
        at = self.clock() - timedelta(minutes=10)
        with self.factory.begin() as db:
            for hostname in (WEB01, WEB02, WEB03):
                self._write(db, job_id, hostname, "succeeded", started_at=at, finished_at=at + timedelta(seconds=30), backup=True)
            job = db.get(Job, job_id)
            job.status = JobStatus(status)
            job.started_at = at
            job.finished_at = at + timedelta(seconds=60)
        return job_id

    def cancelled(self):
        """Canary succeeded, then the operator cancelled: the rest never ran."""
        job_id = self.start(batch_percent=50, pause_after_canary=False)
        at = self.clock() - timedelta(minutes=10)
        with self.factory.begin() as db:
            self._write(db, job_id, WEB01, "succeeded", started_at=at, finished_at=at + timedelta(seconds=30))
            for hostname in (WEB02, WEB03):
                self._write(db, job_id, hostname, "skipped", reason="cancelled")
            job = db.get(Job, job_id)
            job.status = JobStatus.CANCELLED
            job.started_at = at
            job.finished_at = at + timedelta(seconds=45)
        return job_id

    def concurrent_stop(self, *, stopper: str = WEB03, later: str = WEB02):
        """A concurrent batch where ``stopper`` failed first and ``later`` failed in flight afterwards.

        web01 succeeded as the canary; web03 and web02 share batch 1 and both fail, web03 first in wall-clock
        time. The handler names the host that stopped the rollout in the job's failure message.
        """
        job_id = self.start(batch_percent=50, pause_after_canary=False)
        at = self.clock() - timedelta(minutes=10)
        with self.factory.begin() as db:
            self._write(db, job_id, WEB01, "succeeded", started_at=at, finished_at=at + timedelta(seconds=30), backup=True)
            self._write(
                db,
                job_id,
                stopper,
                "rolled_back",
                started_at=at + timedelta(seconds=30),
                finished_at=at + timedelta(seconds=50),
                reason="config_test_failed",
                rolled_back=True,
                backup=True,
            )
            self._write(
                db,
                job_id,
                later,
                "rolled_back",
                started_at=at + timedelta(seconds=30),
                finished_at=at + timedelta(seconds=70),
                reason="reload_failed",
                rolled_back=True,
                backup=True,
            )
            job = db.get(Job, job_id)
            job.status = JobStatus.FAILED
            job.started_at = at
            job.finished_at = at + timedelta(seconds=70)
            job.error_class = "config_invalid"
            job.error_message = f"rollout stopped: {stopper} failed (config_test_failed)"
        return job_id

    def pause_now(self, job_id):
        """Turn a running job into the paused one the handler leaves after a successful canary."""
        with self.factory.begin() as db:
            job = db.get(Job, job_id)
            job.status = JobStatus.PAUSED
            job.paused_at = self.clock()
            job.resume_from_batch = 1
        return job_id

    def fail_now(self, job_id, *, stopper: str = WEB02):
        """Turn a running job into the stopped one: ``stopper`` failed and stopped the rollout."""
        at = self.clock() - timedelta(seconds=30)
        with self.factory.begin() as db:
            self._write(
                db,
                job_id,
                stopper,
                "rolled_back",
                started_at=at,
                finished_at=self.clock(),
                reason="config_test_failed",
                rolled_back=True,
                backup=True,
            )
            job = db.get(Job, job_id)
            job.status = JobStatus.FAILED
            job.finished_at = self.clock()
            job.error_class = "config_invalid"
            job.error_message = f"rollout stopped: {stopper} failed (config_test_failed)"
        return job_id

    def terminal_with_pending_rows(self):
        """A job-level gate failure: nothing ran, so its rows are still ``pending``."""
        job_id = self.start(batch_percent=50, pause_after_canary=False)
        with self.factory.begin() as db:
            job = db.get(Job, job_id)
            job.status = JobStatus.FAILED
            job.finished_at = self.clock()
            job.error_class = "config_invalid"
            job.error_message = "certificate trust changed since the deploy was planned; plan it again"
        return job_id

    def job_level_failure(self, *, message: str, error_class: str = "config_invalid", rows: str = "pending"):
        """A job-level refusal: the job failed before any host row could fail.

        ``rows`` is what the handler leaves behind: ``skipped``/``job_failed`` when the execution gate
        refuses the plan (Contract decision 16's ``_gate_failure``) and ``pending`` when the job never
        reached its rows at all (an inventory or worker-level failure).
        """
        job_id = self.start(batch_percent=50, pause_after_canary=False)
        with self.factory.begin() as db:
            if rows == "skipped":
                for hostname in (WEB01, WEB02, WEB03):
                    self._write(db, job_id, hostname, "skipped", reason="job_failed")
            job = db.get(Job, job_id)
            job.status = JobStatus.FAILED
            job.finished_at = self.clock()
            job.error_class = error_class
            job.error_message = message
        return job_id

    def needs_attention(self):
        """A timed-out host: the worker cannot know whether writes started, so the host needs a human."""
        job_id = self.stopped()
        with self.factory.begin() as db:
            self._write(
                db,
                job_id,
                WEB02,
                "failed",
                started_at=self.clock() - timedelta(minutes=5),
                finished_at=self.clock(),
                reason="host_timeout",
                rolled_back=False,
                rollback_error="host timed out; the worker could not verify or restore the host",
            )
        return job_id

    def stopped_internal(self, *, step: str | None):
        """Canary succeeded, then web02 failed ``internal`` at the last step the playbook published.

        ``step`` is the persisted ``precheck.step``: ``None`` writes no evidence at all, exactly like a host
        task that died before recording its run (``_mark_internal``).
        """
        job_id = self.start(batch_percent=50, pause_after_canary=False)
        at = self.clock() - timedelta(minutes=10)
        with self.factory.begin() as db:
            self._write(db, job_id, WEB01, "succeeded", started_at=at, finished_at=at + timedelta(seconds=40), backup=True)
            self._write(
                db,
                job_id,
                WEB02,
                "failed",
                started_at=at + timedelta(seconds=40),
                finished_at=at + timedelta(seconds=90),
                reason="internal",
                step=step,
            )
            self._write(db, job_id, WEB03, "skipped", reason="rollout_stopped")
            job = db.get(Job, job_id)
            job.status = JobStatus.FAILED
            job.started_at = at
            job.finished_at = at + timedelta(seconds=90)
            job.error_class = "internal"
            job.error_message = f"rollout stopped: {WEB02} failed (internal)"
        return job_id

    def stopped_transport(self, *, reason: str, step: str | None):
        """Canary succeeded, then web02 was lost over SSH; the runner publishes no data for a dark host.

        ``step`` is the persisted ``precheck.step``: ``""`` is exactly what ``parse_host_result`` stores for
        a host the runner reported dark (its ``set_stats`` data is discarded), ``None`` is a row with no
        ``precheck`` document at all.
        """
        job_id = self.start(batch_percent=50, pause_after_canary=False)
        at = self.clock() - timedelta(minutes=10)
        with self.factory.begin() as db:
            self._write(db, job_id, WEB01, "succeeded", started_at=at, finished_at=at + timedelta(seconds=40), backup=True)
            self._write(
                db,
                job_id,
                WEB02,
                "failed",
                started_at=at + timedelta(seconds=40),
                finished_at=at + timedelta(seconds=90),
                reason=reason,
                step=step,
            )
            self._write(db, job_id, WEB03, "skipped", reason="rollout_stopped")
            job = db.get(Job, job_id)
            job.status = JobStatus.FAILED
            job.started_at = at
            job.finished_at = at + timedelta(seconds=90)
            job.error_class = "transient_network" if reason == "unreachable" else "auth"
            job.error_message = f"rollout stopped: {WEB02} failed ({reason})"
        return job_id

    def lost_worker(self):
        """The reaper failed a host still ``running`` with ``worker_lost``: the files may have changed."""
        job_id = self.running(batch_no=1, batch_percent=33)
        with self.factory.begin() as db:
            self._write(
                db,
                job_id,
                WEB02,
                "failed",
                started_at=self.clock() - timedelta(minutes=20),
                finished_at=self.clock(),
                reason="worker_lost",
            )
            job = db.get(Job, job_id)
            job.status = JobStatus.FAILED
            job.error_class = "internal"
            job.error_message = "worker lost"
        return job_id

    def bulk(self, hosts: int):
        """A deploy job with ``hosts`` distinct servers, written directly: the progress view's cost test."""
        token = f"bulk{hosts}"
        with self.factory.begin() as db:
            job = Job(
                type=JobType.DEPLOY,
                status=JobStatus.RUNNING,
                priority=300,
                payload={"certificate_id": self.world.new_certificate.id},
                run_after=self.clock(),
                started_at=self.clock(),
                max_attempts=1,
            )
            db.add(job)
            db.flush()
            for index in range(hosts):
                server = Server(
                    hostname=f"{token}-{index:02d}.example.internal",
                    ansible_groups=["ring_a"],
                    webserver=WebserverType.NGINX,
                    inventory_source="main:inventory/hosts.yml@cafebabe",
                )
                db.add(server)
                db.flush()
                binding = Binding(
                    server_id=server.id,
                    webserver=WebserverType.NGINX,
                    vhost_name=f"www-{index:02d}.example.internal",
                    vhost_names=[f"www-{index:02d}.example.internal"],
                    port=443,
                    config_file=f"/etc/nginx/conf.d/www-{index:02d}.conf",
                    cert_path=f"/etc/nginx/ssl/www-{index:02d}.crt",
                    key_path=f"/etc/nginx/ssl/www-{index:02d}.key",
                    on_disk_fingerprint=self.world.old.sha256_fingerprint,
                    certificate_id=self.world.old.id,
                    match_state="matched",
                    last_seen_at=self.clock(),
                )
                db.add(binding)
                db.flush()
                db.add(
                    JobHost(
                        job_id=job.id,
                        server_id=server.id,
                        binding_id=binding.id,
                        batch_no=index,
                        status=JobHostStatus.SUCCEEDED,
                        started_at=self.clock() - timedelta(minutes=1),
                        finished_at=self.clock(),
                        old_fingerprint=self.world.old.sha256_fingerprint,
                        new_fingerprint=self.world.new_certificate.sha256_fingerprint,
                    )
                )
            return job.id

    # --- rows -------------------------------------------------------------------------------

    def _end_active_jobs(self):
        """One deploy at a time: finish whatever an earlier test left queued, running or paused."""
        with self.factory.begin() as db:
            db.execute(
                update(Job)
                .where(Job.type == JobType.DEPLOY, Job.status.in_(ACTIVE))
                .values(status=JobStatus.FAILED, finished_at=self.clock())
            )

    def _rows(self, db, job_id, hostname=None):
        statement = select(JobHost, Server).join(Server, Server.id == JobHost.server_id).where(JobHost.job_id == job_id)
        if hostname is not None:
            statement = statement.where(Server.hostname == hostname)
        return list(db.execute(statement))

    def _batches(self, db, job_id):
        return sorted({row.batch_no for row, _server in self._rows(db, job_id)})

    def _hosts(self, db, job_id, batch_no):
        return [server.hostname for row, server in self._rows(db, job_id) if row.batch_no == batch_no]

    def _write(
        self,
        db,
        job_id,
        hostname,
        status,
        *,
        started_at=None,
        finished_at=None,
        reason=None,
        rolled_back=False,
        rollback_error=None,
        backup=False,
        log_excerpt=None,
        step=None,
    ):
        """Set every row of one host: the deploy writes a host's bindings together."""
        precheck = {"backup_dir": f"{BACKUP_ROOT}/{job_id}"} if backup else {}
        if step is not None:
            precheck = {**precheck, "step": step}
        precheck = precheck or None
        for row, server in self._rows(db, job_id, hostname):
            row.status = JobHostStatus(status)
            row.started_at = started_at
            row.finished_at = finished_at
            row.error_message = f"{reason}: the host stopped the rollout" if reason else None
            row.rolled_back = rolled_back
            row.rollback_error = rollback_error
            row.log_excerpt = log_excerpt
            row.precheck = precheck

    def row(self, job_id, hostname):
        """One host's rows, reloaded in a fresh session."""
        with self.factory() as db:
            return [row for row, _server in self._rows(db, job_id, hostname)]


@pytest.fixture(autouse=True)
def isolated(web_factory):
    """No schedule may enqueue a job while the screen is under test."""
    disable_schedules(web_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup", "discovery")


@pytest.fixture
def deploy_job_world(web_factory, deploy_world_factory, clock, keyring):
    """The Task 13 world, built once per module because ``web_factory`` outlives a test.

    Servers, bindings and certificates carry unique columns, so they are created on the first use and reused;
    every test adds only jobs (no unique column) and finishes whatever deploy an earlier test left active.
    """
    global _WORLD
    configure_keyring(keyring)
    if _WORLD is None:
        operator = create_login_user(web_factory, OPERATOR)
        with web_factory.begin() as db:
            _WORLD = SimpleNamespace(
                world=deploy_world_factory(db, Actor(operator.id, operator.username)),
                actor=Actor(operator.id, operator.username),
            )
    return DeployJobWorld(web_factory, _WORLD.world, _WORLD.actor, clock)


# --- the paused approval banner -----------------------------------------------------------------


def test_paused_job_shows_approval_banner_and_time_left(signed_in, deploy_job_world, clock):
    job_id = deploy_job_world.paused(paused_at=clock() - timedelta(hours=2))
    page = signed_in.get(f"/deploy/{job_id}")
    assert page.status_code == 200
    text = page.text
    assert "Canary succeeded — continue?" in text
    assert "waiting for approval since" in text
    assert "22 hours left before automatic cancellation" in text
    assert "resuming re-checks drift on every host" in text
    progress = signed_in.get(f"/jobs/{job_id}/progress", headers={"HX-Request": "true"})
    assert progress.status_code == 200
    assert 'hx-trigger="every 2s"' not in progress.text  # a paused job stops polling


# --- phases, totals and the per-host rows -------------------------------------------------------


def phase_of(page_text: str) -> str:
    match = re.search(r'data-phase="([^"]+)"', page_text)
    assert match is not None, page_text[:400]
    return match.group(1)


def totals_of(page_text: str) -> dict[str, int]:
    return {name: int(value) for name, value in re.findall(r'data-total="(\w+)"[^>]*>[^<]*<strong>(\d+)</strong>', page_text)}


def test_phase_labels(signed_in, deploy_job_world, clock):
    def phase(job_id):
        page = signed_in.get(f"/deploy/{job_id}")
        assert page.status_code == 200
        return phase_of(page.text)

    assert phase(deploy_job_world.running(batch_no=0)) == "canary"
    assert phase(deploy_job_world.running(batch_no=1, batch_percent=33)) == "batch 2/3"
    assert phase(deploy_job_world.paused(paused_at=clock() - timedelta(hours=1))) == "paused"
    assert phase(deploy_job_world.stopped()) == "stopped"
    assert phase(deploy_job_world.finished()) == "done"
    assert phase(deploy_job_world.cancelled()) == "cancelled"


def test_running_job_polls_and_shows_totals(signed_in, deploy_job_world):
    job_id = deploy_job_world.running(batch_no=1, batch_percent=33)
    page = signed_in.get(f"/deploy/{job_id}")
    assert page.status_code == 200
    text = page.text
    # htmx polls the fragment every two seconds while the job moves.
    assert f'hx-get="/jobs/{job_id}/progress" hx-trigger="every 2s"' in text
    # web01 succeeded, web02 is running (not finished, so counted as pending), web03 is pending.
    assert totals_of(text) == {"succeeded": 1, "failed": 0, "rolled_back": 0, "skipped": 0, "pending": 2}
    old = deploy_job_world.world.old.sha256_fingerprint
    new = deploy_job_world.world.new_certificate.sha256_fingerprint
    # abbreviated fingerprints, full value on hover
    assert f'title="{old}"' in text and f">{old[:12]}…<" in text
    assert f'title="{new}"' in text and f">{new[:12]}…<" in text
    # the backup path is copyable as it stands
    assert f"{BACKUP_ROOT}/{job_id}" in text and 'class="copy-path"' in text
    # the redacted excerpt is expandable, never printed as prose
    assert "<details><summary>Excerpt</summary>" in text and "ok: [www.example.internal]" in text
    assert "running" in text


def test_running_progress_fragment_keeps_polling(signed_in, deploy_job_world):
    job_id = deploy_job_world.running(batch_no=1, batch_percent=33)
    progress = signed_in.get(f"/jobs/{job_id}/progress", headers={"HX-Request": "true"})
    assert progress.status_code == 200
    assert f'hx-get="/jobs/{job_id}/progress" hx-trigger="every 2s"' in progress.text
    assert "ok: [www.example.internal]" in progress.text


def test_poll_fragment_brings_the_paused_state_with_it(signed_in, deploy_job_world):
    """A running job that pauses must arrive with its banner and Continue control, not freeze the first page."""
    job_id = deploy_job_world.running(batch_no=1, batch_percent=33)
    page = signed_in.get(f"/deploy/{job_id}").text
    assert f'hx-get="/jobs/{job_id}/progress" hx-trigger="every 2s"' in page
    assert "Canary succeeded — continue?" not in page

    deploy_job_world.pause_now(job_id)
    fragment = signed_in.get(f"/jobs/{job_id}/progress", headers={"HX-Request": "true"})
    assert fragment.status_code == 200
    text = fragment.text
    assert "<html" not in text
    # header, banner and controls all refresh with the poll, not only the totals table
    assert 'data-job-status="paused"' in text and 'data-phase="paused"' in text
    assert "Canary succeeded — continue?" in text
    assert f'hx-post="/deploy/{job_id}/continue"' in text
    assert 'hx-trigger="every 2s"' not in text  # a paused job stops polling


def test_poll_fragment_brings_the_failure_state_with_it(signed_in, deploy_job_world):
    """A running job that fails must arrive with the failure banner and the retry control."""
    job_id = deploy_job_world.running(batch_no=1, batch_percent=33)
    assert "Rollout stopped" not in signed_in.get(f"/deploy/{job_id}").text

    deploy_job_world.fail_now(job_id, stopper=WEB02)
    fragment = signed_in.get(f"/jobs/{job_id}/progress", headers={"HX-Request": "true"})
    assert fragment.status_code == 200
    text = fragment.text
    assert "<html" not in text
    assert "Rollout stopped" in text and f"The first failed host is <strong>{WEB02}</strong>" in text
    assert f'hx-post="/deploy/{job_id}/hosts/{deploy_job_world.world.servers[WEB02].id}/retry"' in text
    assert 'hx-trigger="every 2s"' not in text  # a stopped job stops polling


# --- the failure banner and the JSON report -----------------------------------------------------


def test_failure_banner_names_the_first_failed_host_and_restoration(signed_in, deploy_job_world):
    job_id = deploy_job_world.stopped(first_failed=WEB02, rolled_back=True)
    page = signed_in.get(f"/deploy/{job_id}")
    assert page.status_code == 200
    text = page.text
    assert "Rollout stopped" in text and WEB02 in text and "files were restored" in text
    report = signed_in.get(f"/deploy/{job_id}/report.json").json()
    assert all(set(host) == set(REPORT_HOST_FIELDS) for host in report["hosts"])
    assert report["job_id"] == str(job_id) and report["status"] == "failed"
    web01 = next(host for host in report["hosts"] if host["hostname"] == WEB01)
    # one entry per binding, with that binding's own old and new fingerprint
    assert [set(binding) for binding in web01["bindings"]] == [set(REPORT_BINDING_FIELDS)] * 2
    assert [binding["vhost_name"] for binding in web01["bindings"]] == [
        "legacy.example.internal",
        "www.example.internal",
    ]
    assert all(binding["old_fingerprint"] == deploy_job_world.world.old.sha256_fingerprint for binding in web01["bindings"])
    assert all(
        binding["new_fingerprint"] == deploy_job_world.world.new_certificate.sha256_fingerprint
        for binding in web01["bindings"]
    )
    # the report never carries the log excerpt or the payload
    assert all("log_excerpt" not in host for host in report["hosts"])
    assert "payload" not in report


def test_failure_banner_says_when_files_could_not_be_restored(signed_in, deploy_job_world):
    job_id = deploy_job_world.stopped(first_failed=WEB02, rolled_back=False)
    text = signed_in.get(f"/deploy/{job_id}").text
    assert "Rollout stopped" in text and WEB02 in text
    assert "files could not be restored" in text


def failure_banner(page_text: str) -> str:
    assert 'data-banner="failure"' in page_text, page_text[:400]
    return page_text.split('data-banner="failure"', 1)[1].split("</section>", 1)[0]


def test_worker_lost_banner_never_claims_nothing_was_written(signed_in, deploy_job_world):
    """§9.4: a reaped host's files may have changed and were never verified — never 'no file was changed'."""
    job_id = deploy_job_world.lost_worker()
    banner = failure_banner(signed_in.get(f"/deploy/{job_id}").text)
    assert WEB02 in banner
    assert "No file was changed" not in banner
    assert "may have been changed" in banner and "manual attention" in banner


@pytest.mark.parametrize(
    "step",
    ["writing", "reloaded", "verified", pytest.param(None, id="no-step-evidence")],
)
def test_internal_after_the_first_write_fails_closed(signed_in, deploy_job_world, step):
    """`internal` is not a pre-write guarantee: a run that reached the write, or published no step at all.

    ``parse_host_result`` maps a ``step='verified'`` run whose per-binding evidence disagrees to
    ``failed``/``internal`` — its files were written. Only a persisted pre-write step proves otherwise.
    """
    job_id = deploy_job_world.stopped_internal(step=step)
    banner = failure_banner(signed_in.get(f"/deploy/{job_id}").text)
    assert WEB02 in banner
    assert "No file was changed" not in banner
    assert "may have been changed" in banner and "manual attention" in banner
    report = signed_in.get(f"/deploy/{job_id}/report.json").json()
    assert report["files_restored"] is None  # tri-state: unknown, never "nothing to restore"
    assert host_of(report, WEB02)["needs_attention"] is True


@pytest.mark.parametrize("step", ["preflight", "backed_up"])
def test_internal_before_the_first_write_keeps_the_no_write_assertion(signed_in, deploy_job_world, step):
    """A run that published only preflight or backup work never touched a live file: the banner says so."""
    job_id = deploy_job_world.stopped_internal(step=step)
    banner = failure_banner(signed_in.get(f"/deploy/{job_id}").text)
    assert WEB02 in banner and "No file was changed" in banner
    assert "may have been changed" not in banner
    report = signed_in.get(f"/deploy/{job_id}/report.json").json()
    assert report["files_restored"] is None
    assert host_of(report, WEB02)["needs_attention"] is False


@pytest.mark.parametrize("reason", ["unreachable", "auth"])
@pytest.mark.parametrize("step", ["", "writing", pytest.param(None, id="no-precheck")])
def test_transport_failure_with_unknown_write_status_never_claims_nothing_was_written(
    signed_in, deploy_job_world, reason, step
):
    """An SSH failure can strike after the first write, and a dark host publishes no step (§9.4).

    ``app/ansible/runner.py`` replaces a dark host's published data with ``{}``, so the row carries no
    evidence that nothing was written; the screen and the report must not assert it.
    """
    job_id = deploy_job_world.stopped_transport(reason=reason, step=step)
    page = signed_in.get(f"/deploy/{job_id}").text
    banner = failure_banner(page)
    assert WEB02 in banner and f"({reason})" in banner
    assert "No file was changed" not in banner
    assert "may have been changed" in banner and "manual attention" in banner
    assert 'data-badge="needs-attention"' in page
    report = signed_in.get(f"/deploy/{job_id}/report.json").json()
    assert report["files_restored"] is None  # tri-state: unknown, never "nothing to restore"
    host = host_of(report, WEB02)
    assert host["needs_attention"] is True and host["reason"] == reason


@pytest.mark.parametrize("reason", ["unreachable", "auth"])
@pytest.mark.parametrize("step", ["preflight", "backed_up"])
def test_transport_failure_with_a_persisted_pre_write_step_keeps_the_no_write_assertion(
    signed_in, deploy_job_world, reason, step
):
    """A persisted ``preflight``/``backed_up`` step is independent proof the run stopped before the write."""
    job_id = deploy_job_world.stopped_transport(reason=reason, step=step)
    page = signed_in.get(f"/deploy/{job_id}").text
    banner = failure_banner(page)
    assert WEB02 in banner and "No file was changed" in banner
    assert "may have been changed" not in banner
    assert 'data-badge="needs-attention"' not in page
    report = signed_in.get(f"/deploy/{job_id}/report.json").json()
    assert report["files_restored"] is None
    assert host_of(report, WEB02)["needs_attention"] is False


def test_failure_banner_names_the_host_that_stopped_the_rollout(signed_in, deploy_job_world):
    """In a concurrent batch the stopper is not the first hostname: web03 failed before web02."""
    job_id = deploy_job_world.concurrent_stop(stopper=WEB03, later=WEB02)
    page = signed_in.get(f"/deploy/{job_id}").text
    assert f"The first failed host is <strong>{WEB03}</strong>" in page
    assert f"The first failed host is <strong>{WEB02}</strong>" not in page
    assert signed_in.get(f"/deploy/{job_id}/report.json").json()["first_failed_host"] == WEB03


@pytest.mark.parametrize("rows", ["pending", "skipped"])
@pytest.mark.parametrize(
    ("message", "error_class", "expected"),
    [
        (
            "certificate trust changed since the deploy was planned; plan it again",
            "config_invalid",
            "No host stopped the rollout: certificate trust changed since the deploy was planned; plan it again.",
        ),
        (
            "Job exceeded its time limit or its worker stopped responding.",
            "timeout",
            "No host stopped the rollout: Job exceeded its time limit or its worker stopped responding.",
        ),
        (
            "the certificate is superseded; only an active certificate can be deployed",
            "config_invalid",
            "No host stopped the rollout: the certificate is superseded; only an active certificate can be deployed.",
        ),
    ],
)
def test_job_level_failure_shows_its_persisted_reason(signed_in, deploy_job_world, rows, message, error_class, expected):
    """§8.7: the banner shows the reason for stopping even when no host row failed.

    A trust/key/inventory refusal stops the job before any host runs, so ``_stopper`` is ``None``; the only
    persisted evidence is the job's own failure. It is an allowlist of the fixed texts this codebase writes,
    rendered verbatim, and it reaches the polled live region with the rest of the banner.
    """
    job_id = deploy_job_world.job_level_failure(message=message, error_class=error_class, rows=rows)
    page = signed_in.get(f"/deploy/{job_id}")
    assert page.status_code == 200
    banner = failure_banner(page.text)
    assert 'data-failure="job"' in banner
    assert expected in banner
    assert "The first failed host is" not in banner  # no host stopped this rollout
    fragment = signed_in.get(f"/jobs/{job_id}/progress", headers={"HX-Request": "true"})
    assert fragment.status_code == 200 and expected in failure_banner(fragment.text)


@pytest.mark.parametrize(
    "message",
    [
        "cannot stage the job secrets: /run/secrets/deploy_key.pem: Permission denied",
        "certificate trust changed since the deploy was planned; plan it again (key=abcd1234)",
        "the inventory was not prepared; token=abcd1234",
    ],
)
def test_job_level_failure_never_echoes_a_non_allowlisted_message(signed_in, deploy_job_world, message):
    """The redaction control: only an exact allowlisted text reaches the screen.

    ``job.error_message`` is redacted when it is persisted, but the screen must not depend on that filter: a
    free-text message (a path, a host's stderr), a known text with anything appended to it, or a message a
    future handler writes is replaced by the class-only fallback and never echoed.
    """
    job_id = deploy_job_world.job_level_failure(message=message, error_class="internal", rows="pending")
    page = signed_in.get(f"/deploy/{job_id}").text
    banner = failure_banner(page)
    assert "No host stopped the rollout: the job itself failed (internal)." in banner
    for leaked in (
        "deploy_key.pem",
        "/run/secrets",
        "cannot stage the job secrets",
        "key=abcd1234",
        "token=abcd1234",
    ):
        assert leaked not in page
    report = signed_in.get(f"/deploy/{job_id}/report.json")
    assert "deploy_key.pem" not in report.text and "abcd1234" not in report.text


def test_a_host_stopped_rollout_keeps_the_host_wording(signed_in, deploy_job_world):
    """A host that stopped the rollout keeps the first-failed-host and restoration wording (§8.7)."""
    banner = failure_banner(signed_in.get(f"/deploy/{deploy_job_world.stopped()}").text)
    assert f"The first failed host is <strong>{WEB02}</strong>" in banner
    assert "files were restored" in banner
    assert "No host stopped the rollout" not in banner


# --- host states that need a human ---------------------------------------------------------------


def host_of(report, hostname):
    return next(host for host in report["hosts"] if host["hostname"] == hostname)


def test_needs_manual_attention_badge(signed_in, deploy_job_world):
    job_id = deploy_job_world.needs_attention()
    text = signed_in.get(f"/deploy/{job_id}").text
    assert 'data-badge="needs-attention"' in text
    host = host_of(signed_in.get(f"/deploy/{job_id}/report.json").json(), WEB02)
    assert host["needs_attention"] is True and "could not verify" in host["rollback_error"]

    # a worker lost mid-run leaves files that may have changed but were never verified
    lost = deploy_job_world.lost_worker()
    assert 'data-badge="needs-attention"' in signed_in.get(f"/deploy/{lost}").text
    assert host_of(signed_in.get(f"/deploy/{lost}/report.json").json(), WEB02)["needs_attention"] is True

    # a clean rollback restored the host: it is not a manual-attention case
    clean = deploy_job_world.stopped(rolled_back=True)
    assert 'data-badge="needs-attention"' not in signed_in.get(f"/deploy/{clean}").text
    assert all(host["needs_attention"] is False for host in signed_in.get(f"/deploy/{clean}/report.json").json()["hosts"])


def test_pending_rows_of_a_terminal_job_render_not_run(signed_in, deploy_job_world):
    job_id = deploy_job_world.terminal_with_pending_rows()
    text = signed_in.get(f"/deploy/{job_id}").text
    # nothing ran, so every host row is still pending: the screen says so instead of showing "pending"
    assert 'data-status="pending"' in text
    assert '<td>not run</td>' in text
    assert ">pending<" not in text
    assert totals_of(text) == {"succeeded": 0, "failed": 0, "rolled_back": 0, "skipped": 0, "pending": 3}
    # a finished job stops polling whatever its rows say
    assert 'hx-trigger="every 2s"' not in text


# --- operator controls --------------------------------------------------------------------------


def csrf(signed_in) -> dict[str, str]:
    return {"csrf_token": signed_in.fixture_csrf}


def test_continue_and_cancel_forms(signed_in, deploy_job_world, clock):
    # Continue is offered only while paused: a running job has no such form and a forced POST is refused
    running = deploy_job_world.running(batch_no=1, batch_percent=33)
    assert f'action="/deploy/{running}/continue"' not in signed_in.get(f"/deploy/{running}").text
    refused = signed_in.post(f"/deploy/{running}/continue", data=csrf(signed_in), headers={"HX-Request": "true"})
    assert refused.status_code == 422 and 'data-error="state"' in refused.text

    paused = deploy_job_world.paused(paused_at=clock() - timedelta(hours=1))
    page = signed_in.get(f"/deploy/{paused}").text
    assert f'action="/deploy/{paused}/continue"' in page and f'action="/deploy/{paused}/cancel"' in page
    assert 'name="csrf_token"' in page
    # every POST needs the session's CSRF token
    assert signed_in.post(f"/deploy/{paused}/continue", data={}).status_code == 403

    resumed = signed_in.post(f"/deploy/{paused}/continue", data=csrf(signed_in), follow_redirects=False)
    assert resumed.status_code == 303 and resumed.headers["location"] == f"/deploy/{paused}"
    job = fetch(deploy_job_world.factory, Job, paused)
    assert job.status == "queued" and job.paused_at is None
    assert "deploy.continue" in audit_actions(deploy_job_world.factory, str(paused))

    # Cancel a paused job: it is cancelled now and nothing stays pending
    cancelled = signed_in.post(f"/deploy/{paused}/cancel", data=csrf(signed_in), follow_redirects=False)
    assert cancelled.status_code == 303 and cancelled.headers["location"] == f"/deploy/{paused}"
    job = fetch(deploy_job_world.factory, Job, paused)
    assert job.status == "cancelled"
    assert all(row.status == "skipped" and row.error_message == "cancelled" for row in deploy_job_world.row(paused, WEB02))
    assert "deploy.cancel" in audit_actions(deploy_job_world.factory, str(paused))


def test_cancel_refusal_is_a_fragment(signed_in, deploy_job_world):
    finished = deploy_job_world.finished()
    # without JavaScript the refusal is the whole page, with the message inline
    refused = signed_in.post(f"/deploy/{finished}/cancel", data=csrf(signed_in))
    assert refused.status_code == 422 and "<html" in refused.text and 'data-error="state"' in refused.text
    # with htmx the refusal replaces the live region the form lives in, and swaps nothing else
    fragment = signed_in.post(f"/deploy/{finished}/cancel", data=csrf(signed_in), headers={"HX-Request": "true"})
    assert fragment.status_code == 422
    assert "<html" not in fragment.text and 'id="deploy-job-live"' in fragment.text
    assert 'data-error="state"' in fragment.text


def live_region(page: str) -> tuple[int, int]:
    """The span of the ``#deploy-job-live`` element (balanced ``<div>`` counting, like a browser parses it)."""
    start = page.index('<div id="deploy-job-live"')
    depth = 0
    for tag in re.finditer(r"<div\b|</div>", page[start:]):
        depth += 1 if tag.group(0) == "<div" else -1
        if depth == 0:
            return start, start + tag.end()
    raise AssertionError("unbalanced #deploy-job-live region")


def after_htmx_swap(page: str, fragment: str) -> str:
    """What the browser shows after htmx answers a refused control: ``hx-target``/``hx-swap="outerHTML"``."""
    start, end = live_region(page)
    return page[:start] + fragment.strip() + page[end:]


def test_refused_control_swaps_visibly_for_htmx(signed_in, deploy_job_world):
    """htmx drops 4xx bodies by default, so the page must opt a 422 into the visible live-region swap.

    A refusal from the control forms is a 422 fragment; without the ``htmx:beforeSwap`` handler the operator
    would see nothing at all. The test runs the swap htmx performs (target selector -> response root) and
    looks for the reason in the resulting document, then keeps the no-JavaScript behaviour intact.
    """
    job_id = deploy_job_world.stopped()
    server_id = deploy_job_world.world.servers[WEB02].id
    page = signed_in.get(f"/deploy/{job_id}").text
    # the page ships the handler the repository's other inline forms use
    assert 'document.body.addEventListener("htmx:beforeSwap"' in page
    assert "event.detail.xhr.status === 422" in page
    assert "event.detail.shouldSwap = true" in page and "event.detail.isError = false" in page
    # the form targets the region the refusal replaces, so the swap lands where the reason is rendered
    assert 'hx-target="#deploy-job-live"' in page
    refusal = signed_in.post(
        f"/deploy/{job_id}/hosts/{server_id}/retry", data=csrf(signed_in), headers={"HX-Request": "true"}
    )
    assert refusal.status_code == 422
    assert refusal.text.lstrip().startswith('<div id="deploy-job-live"')
    message = re.search(r'data-error="reason"[^>]*><p>(.*?)</p>', refusal.text, re.DOTALL)
    assert message is not None and message.group(1).strip()
    shown = after_htmx_swap(page, refusal.text)
    assert 'data-error="reason"' in shown and message.group(1) in shown
    # without JavaScript the same refusal is the whole page with the message inline
    plain = signed_in.post(f"/deploy/{job_id}/hosts/{server_id}/retry", data=csrf(signed_in))
    assert plain.status_code == 422 and "<html" in plain.text and 'data-error="reason"' in plain.text


def test_controls_are_htmx_forms_with_a_no_javascript_fallback(signed_in, deploy_job_world, clock):
    # the retry form first: starting another deploy would finish whatever job is still active
    retry = deploy_job_world.stopped()
    server_id = deploy_job_world.world.servers[WEB02].id
    retry_page = signed_in.get(f"/deploy/{retry}").text
    assert f'action="/deploy/{retry}/hosts/{server_id}/retry"' in retry_page
    assert f'hx-post="/deploy/{retry}/hosts/{server_id}/retry"' in retry_page

    paused = deploy_job_world.paused(paused_at=clock() - timedelta(hours=1))
    text = signed_in.get(f"/deploy/{paused}").text
    for action in (f"/deploy/{paused}/continue", f"/deploy/{paused}/cancel"):
        assert f'action="{action}"' in text  # a browser without JavaScript posts the same form
        assert f'hx-post="{action}"' in text  # htmx posts it too, so a 422 fragment can land
    assert 'hx-target="#deploy-job-live"' in text and 'hx-swap="outerHTML"' in text

    # htmx cannot follow a 303: success answers 200 with HX-Redirect, so the browser reloads the job screen
    htmx_cancel = signed_in.post(f"/deploy/{paused}/cancel", data=csrf(signed_in), headers={"HX-Request": "true"})
    assert htmx_cancel.status_code == 200 and htmx_cancel.headers["HX-Redirect"] == f"/deploy/{paused}"
    assert fetch(deploy_job_world.factory, Job, paused).status == "cancelled"

    # without JavaScript the same POST is a 303 to the job screen
    paused_again = deploy_job_world.paused(paused_at=clock() - timedelta(hours=1))
    plain = signed_in.post(f"/deploy/{paused_again}/cancel", data=csrf(signed_in), follow_redirects=False)
    assert plain.status_code == 303 and plain.headers["location"] == f"/deploy/{paused_again}"


def test_retry_host_is_a_new_job(signed_in, deploy_job_world):
    stopped = deploy_job_world.stopped()
    server_id = deploy_job_world.world.servers[WEB02].id
    page = signed_in.get(f"/deploy/{stopped}").text
    assert f'action="/deploy/{stopped}/hosts/{server_id}/retry"' in page and "Retry host" in page

    # a retry always carries a reason
    refused = signed_in.post(
        f"/deploy/{stopped}/hosts/{server_id}/retry", data=csrf(signed_in), headers={"HX-Request": "true"}
    )
    assert refused.status_code == 422 and 'data-error="reason"' in refused.text

    response = signed_in.post(
        f"/deploy/{stopped}/hosts/{server_id}/retry",
        data={**csrf(signed_in), "reason": "config test failed after the write; the host was restored"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    new_id = UUID(response.headers["location"].rsplit("/", 1)[1])
    new = fetch(deploy_job_world.factory, Job, new_id)
    assert new.payload["retry_of"] == str(stopped) and new.max_attempts == 1
    rows = deploy_job_world.row(new_id, WEB02)
    assert {row.batch_no for row in rows} == {0}  # its own canary, no pause
    assert len(rows) == 1
    actions = audit_actions(deploy_job_world.factory, str(new_id))
    assert "deploy.retry_host" in actions and "deploy.start" in actions
    # the original job is untouched
    original = deploy_job_world.row(stopped, WEB02)
    assert {row.status for row in original} == {"rolled_back"}


# --- cost, leaks and 404s -----------------------------------------------------------------------


def test_progress_query_count_is_constant(signed_in, deploy_job_world, count_statements):
    small = deploy_job_world.bulk(3)
    large = deploy_job_world.bulk(30)
    # one warm-up request: the worker-liveness probe is cached per process, so only steady state is measured
    assert signed_in.get(f"/jobs/{small}/progress", headers={"HX-Request": "true"}).status_code == 200
    with count_statements() as counter:
        assert signed_in.get(f"/jobs/{small}/progress", headers={"HX-Request": "true"}).status_code == 200
    few = counter.count
    with count_statements() as counter:
        assert signed_in.get(f"/jobs/{large}/progress", headers={"HX-Request": "true"}).status_code == 200
    # twenty-seven more hosts cost exactly the same: one query for the job, one for its rows
    assert few == counter.count


def test_report_and_pages_never_show_key_material_or_raw_payload(signed_in, deploy_job_world, clock):
    job_id = deploy_job_world.stopped()
    # What the screen must never echo: payload material and anything outside the allowlist.
    with deploy_job_world.factory.begin() as db:
        job = db.get(Job, job_id)
        job.payload = {
            **job.payload,
            "key_pem": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg",
            "chain_status_at_plan": "untrusted",
        }
        for row, _server in deploy_job_world._rows(db, job_id, WEB02):
            row.log_excerpt = 'fatal: [web02]: FAILED! => {"msg": "certificate and key do not match", "key": "[redacted]"}'
    page = signed_in.get(f"/deploy/{job_id}")
    text = page.text
    assert "BEGIN PRIVATE KEY" not in text
    for payload_key in ("key_pem", "chain_status_at_plan", "plan_sha256"):
        assert payload_key not in text
    # only the stored, already redacted excerpt is rendered
    assert "[redacted]" in text and "<details><summary>Excerpt</summary>" in text
    report = signed_in.get(f"/deploy/{job_id}/report.json")
    assert "BEGIN PRIVATE KEY" not in report.text
    for secret_key in ("key_pem", "log_excerpt", "pem"):
        assert secret_key not in report.text


def test_unknown_or_non_deploy_job_is_404(signed_in, deploy_job_world, clock):
    unknown = uuid4()
    with deploy_job_world.factory.begin() as db:
        job = Job(type=JobType.SCAN, status=JobStatus.QUEUED, priority=300, payload={}, run_after=clock())
        db.add(job)
    for job_id in (unknown, job.id):
        for path in (f"/deploy/{job_id}", f"/jobs/{job_id}/progress", f"/deploy/{job_id}/report.json"):
            assert signed_in.get(path).status_code == 404, path


def test_deploy_navigation_entry_is_enabled(signed_in, deploy_job_world):
    # Task 19 enabled the Deploy navigation entry (before it, the screen was reachable by URL only).
    text = signed_in.get(f"/deploy/{deploy_job_world.finished()}").text
    assert '<a href="/deploy">Deploy</a>' in text
    assert '<span aria-disabled="true" title="handler deploy/default not registered (Plan 3)">Deploy</span>' not in text
