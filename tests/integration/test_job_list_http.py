"""``/deploy/jobs`` over HTTP (spec §8.7): the job list the overview queue links to.

Rows are inserted directly — this is a read model and the list must show every state it can meet, including a
rollout that rolled a host back (a ``job_host`` state, never a job status). The world is built once for the
module, so a page total is an exact number.
"""

import re
import secrets
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.models import Job, JobHost
from app.models.enums import JobHostStatus, JobStatus, JobType
from tests.integration.conftest import add_server, expiring

_WORLD: SimpleNamespace | None = None


def _job(db, kind, status, payload, *, at, done: bool) -> Job:
    job = Job(
        type=kind,
        status=status,
        priority=100,
        payload=payload,
        run_after=at,
        created_at=at,
        started_at=None if status in (JobStatus.QUEUED, JobStatus.CANCELLED) else at,
        finished_at=at if done else None,
    )
    db.add(job)
    db.flush()
    return job


def _host(db, job, server_id, status, *, rolled_back: bool) -> None:
    db.add(
        JobHost(
            job_id=job.id,
            server_id=server_id,
            status=status,
            rolled_back=rolled_back,
            finished_at=job.finished_at,
        )
    )
    db.flush()


def _build(factory, now) -> SimpleNamespace:
    certificate = expiring(factory, 90)
    with factory.begin() as db:
        first, second = (
            add_server(db, f"joblist-a-{secrets.token_hex(3)}.example.test").id,
            add_server(db, f"joblist-b-{secrets.token_hex(3)}.example.test").id,
        )
        deploy = {"certificate_id": certificate.id}

        succeeded = _job(db, JobType.DEPLOY, JobStatus.SUCCEEDED, deploy, at=now - timedelta(hours=1), done=True)
        _host(db, succeeded, first, JobHostStatus.SUCCEEDED, rolled_back=False)
        failed = _job(db, JobType.DEPLOY, JobStatus.FAILED, deploy, at=now - timedelta(hours=2), done=True)
        _host(db, failed, first, JobHostStatus.SUCCEEDED, rolled_back=False)
        _host(db, failed, second, JobHostStatus.FAILED, rolled_back=False)
        rolled_back = _job(db, JobType.DEPLOY, JobStatus.FAILED, deploy, at=now - timedelta(hours=3), done=True)
        _host(db, rolled_back, first, JobHostStatus.SUCCEEDED, rolled_back=False)
        _host(db, rolled_back, second, JobHostStatus.ROLLED_BACK, rolled_back=True)
        running = _job(db, JobType.DEPLOY, JobStatus.RUNNING, deploy, at=now - timedelta(minutes=10), done=False)
        _host(db, running, first, JobHostStatus.RUNNING, rolled_back=False)
        queued = _job(db, JobType.DEPLOY, JobStatus.QUEUED, deploy, at=now - timedelta(minutes=5), done=False)
        _host(db, queued, first, JobHostStatus.PENDING, rolled_back=False)
        scan_running = _job(
            db, JobType.SCAN, JobStatus.RUNNING, {"endpoint_ids": [1]}, at=now - timedelta(minutes=20), done=False
        )
        scan_done = _job(
            db, JobType.SCAN, JobStatus.SUCCEEDED, {"endpoint_ids": [1]}, at=now - timedelta(hours=4), done=True
        )
        cleanup = _job(
            db, JobType.CLEANUP, JobStatus.QUEUED, {"reason": "scheduled"}, at=now - timedelta(hours=6), done=False
        )
        ids = {
            name: str(job.id)
            for name, job in {
                "succeeded": succeeded,
                "failed": failed,
                "rolled_back": rolled_back,
                "running": running,
                "queued": queued,
                "scan_running": scan_running,
                "scan_done": scan_done,
                "cleanup": cleanup,
            }.items()
        }
    return SimpleNamespace(certificate_id=certificate.id, total=len(ids), **ids)


@pytest.fixture
def job_list_world(web_factory, now):
    global _WORLD
    if _WORLD is None:
        _WORLD = _build(web_factory, now)
    return _WORLD


def _row(html: str, job_id: str) -> str:
    """The ``<tr>`` that carries this job id, so a hit in a link of another row cannot pass for a row."""
    start = html.index(f'data-job-id="{job_id}"')
    return html[html.rindex("<tr", 0, start) : html.index("</tr>", start)]


def _ids(html: str) -> list[str]:
    return re.findall(r'data-job-id="([0-9a-f-]+)"', html)


def test_job_list_requires_a_session(client):
    response = client.get("/deploy/jobs", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_job_list_shows_every_job_and_the_host_outcome_of_a_deploy(signed_in, job_list_world):
    page = signed_in.get("/deploy/jobs")
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert f'data-total="{job_list_world.total}"' in page.text
    assert len(_ids(page.text)) == job_list_world.total

    rolled_back = _row(page.text, job_list_world.rolled_back)
    assert 'data-host-total="rolled_back">1</span>' in rolled_back
    assert 'data-host-total="succeeded"' in rolled_back
    assert 'data-outcome="rolled_back"' in rolled_back and 'data-status="failed"' in rolled_back
    assert f'href="/deploy/{job_list_world.rolled_back}"' in rolled_back

    # A non-deploy job has no hosts to report and points at its audit record instead of a deploy screen.
    scan = _row(page.text, job_list_world.scan_done)
    assert "data-host-total" not in scan
    assert f"target_id={job_list_world.scan_done}" in scan


def test_outcome_filters_partition_failed_and_rolled_back(signed_in, job_list_world):
    rolled_back = signed_in.get("/deploy/jobs?outcome=rolled_back")
    assert rolled_back.status_code == 200
    assert _ids(rolled_back.text) == [job_list_world.rolled_back]  # the failed job is not a rolled-back one

    failed = signed_in.get("/deploy/jobs?outcome=failed")
    assert _ids(failed.text) == [job_list_world.failed]


def test_outcome_and_type_filters_select_running_jobs_of_one_kind(signed_in, job_list_world):
    running = signed_in.get("/deploy/jobs?outcome=running")
    assert set(_ids(running.text)) == {job_list_world.running, job_list_world.scan_running}  # a queued one is not running

    deploys = signed_in.get("/deploy/jobs?outcome=running&type=deploy")
    assert _ids(deploys.text) == [job_list_world.running]

    scans = signed_in.get("/deploy/jobs?type=scan")
    assert set(_ids(scans.text)) == {job_list_world.scan_running, job_list_world.scan_done}

    queued = signed_in.get("/deploy/jobs?outcome=queued&type=deploy")
    assert _ids(queued.text) == [job_list_world.queued]


def test_job_list_is_paginated_like_every_other_list(signed_in, job_list_world):
    first = signed_in.get("/deploy/jobs?page_size=3")
    assert first.status_code == 200
    assert f'data-total="{job_list_world.total}"' in first.text
    assert len(_ids(first.text)) == 3
    second = signed_in.get("/deploy/jobs?page_size=3&page=2")
    assert len(_ids(second.text)) == 3
    assert set(_ids(first.text)).isdisjoint(_ids(second.text))
    last = signed_in.get(f"/deploy/jobs?page_size=3&page={-(-job_list_world.total // 3)}")
    assert len(_ids(last.text)) == job_list_world.total % 3


@pytest.mark.parametrize(
    "query",
    ["outcome=bogus", "type=bogus", "page=0", "page_size=0", "page_size=101", "page=x"],
)
def test_job_list_rejects_invalid_query_values(signed_in, query):
    assert signed_in.get(f"/deploy/jobs?{query}").status_code == 422
