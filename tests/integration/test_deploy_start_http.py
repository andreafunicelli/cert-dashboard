"""Deploy start screen over HTTP (Plan 3 Task 19; spec §8.7, §6.6, §5.8 and the §8 form rules).

The world is Task 13's database-only deploy world (``deploy_world_factory``) inside the module's ``web_factory``
database, exactly like the job screen's tests: three servers, four ``matched`` bindings of a previous certificate,
an issued renewal whose new keyed certificate replaces it, and the fixture root as a trust anchor. Two more
lineages are added once, on their own servers, so the main world's default plan stays three hosts whatever order
the tests run in: the D1 pair (two same-issuer certificate files plus one binding with a verified chain file) and
an untrusted lineage (stored without its intermediate) for the §5.8 override.

Every POST goes through the real route: the guardrails, the plan hash, the trust gate and the audit rows are the
ones an operator's browser meets.
"""

import re
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select, update

from app.crypto.chain import order_chain
from app.crypto.parse import parse_certificates
from app.jobs import worker
from app.jobs.worker import record_worker_start
from app.models import AuditLog, Binding, Job, JobHost, Server, WorkerHeartbeat
from app.models.enums import JobStatus, JobType, WebserverType
from app.services.audit import Actor
from app.services.certificates import CertificateMetadata, save_certificate, store_key
from app.services.deploy import configure_keyring
from app.services.overview import job_summary
from tests.integration.conftest import create_login_user, disable_schedules

OPERATOR = "deploy-start-operator"
PAIR_HOST = "pair.example.internal"
UNTRUSTED_HOST = "untrusted.example.internal"
# What reconciliation records on a binding whose separate certificate file could not be verified as the
# chain of the leaf (D1 / operator decision 4): it stays a certificate of its own and carries the diagnostic.
CHAIN_DIAGNOSTIC = "incomplete chain: no configured file holds this leaf's issuer"
NO_SSH_KEY = "Discovery and deploy are unavailable: the worker has no ansible_ssh_key"
ACTIVE = (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.PAUSED)
_WORLD: SimpleNamespace | None = None


def _certificate(db, ca, keyring, actor, now, *, names, renews_id=None, with_chain=True):
    """A keyed leaf the session CA issues, stored with its intermediate or deliberately without it."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = ca.issue(
        public_key=key.public_key(),
        common_name=names[0],
        sans=list(names),
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=200),
    )
    leaf = parse_certificates(pem)[0]
    intermediates = [x509.load_pem_x509_certificate(ca.chain_pem)] if with_chain else []
    key_row = store_key(db, keyring, key, "generated", actor)
    saved = save_certificate(
        db,
        leaf,
        order_chain(leaf.cert, intermediates),
        CertificateMetadata(owner_name="Ada", owner_email="ada@example.test", team="web"),
        actor,
        source="upload_pem",
        key_id=key_row.id,
        renews_id=renews_id,
        validation_time=now,
    )
    return saved.certificate, key_row


def _server(db, hostname, group, now):
    server = Server(
        hostname=hostname,
        ansible_groups=[group],
        webserver=WebserverType.NGINX,
        inventory_source="main:inventory/hosts.yml@cafebabe",
        last_discovery_at=now - timedelta(hours=1),
        last_discovery_status="ok",
    )
    db.add(server)
    db.flush()
    return server


def _binding(db, server, vhost, *, current, current_key, now, cert_path, key_path, chain_path=None, **extra):
    """One active ``matched`` binding of ``current``, with the paths the preview must write."""
    row = Binding(
        server_id=server.id,
        webserver=server.webserver,
        vhost_name=vhost,
        vhost_names=[vhost],
        port=443,
        config_file=f"/etc/nginx/conf.d/{vhost}.conf",
        cert_path=cert_path,
        chain_path=chain_path,
        key_path=key_path,
        cert_owner="root",
        cert_group="root",
        cert_mode=0o644,
        key_owner="root",
        key_group="root",
        key_mode=0o600,
        on_disk_fingerprint=current.sha256_fingerprint,
        on_disk_key_public_sha256=current_key.public_key_sha256,
        certificate_id=current.id,
        match_state="matched",
        last_seen_at=now - timedelta(hours=1),
        **extra,
    )
    db.add(row)
    db.flush()
    return row


def _pair_world(db, ca, keyring, actor, now):
    """D1: two same-issuer certificate files with no chain plus one binding whose chain file is verified.

    A positional or issuer-matching heuristic would make the second file a chain of the first and write a chain
    over a live certificate; the preview must show one ``write cert`` per file and a ``write chain`` only for the
    binding that carries a verified ``chain_path``.
    """
    old, old_key = _certificate(db, ca, keyring, actor, now, names=("rsa.example.internal", "ecdsa.example.internal"))
    new, _key = _certificate(
        db, ca, keyring, actor, now, names=("rsa.example.internal", "ecdsa.example.internal"), renews_id=old.id
    )
    server = _server(db, PAIR_HOST, "ring_b", now)
    bindings = {
        "rsa": _binding(
            db, server, "rsa.example.internal", current=old, current_key=old_key, now=now,
            cert_path="/etc/nginx/ssl/rsa.crt", key_path="/etc/nginx/ssl/rsa.key",
        ),
        "ecdsa": _binding(
            db, server, "ecdsa.example.internal", current=old, current_key=old_key, now=now,
            cert_path="/etc/nginx/ssl/ecdsa.crt", key_path="/etc/nginx/ssl/ecdsa.key",
            notes=CHAIN_DIAGNOSTIC,
        ),
        "chain": _binding(
            db, server, "chain.example.internal", current=old, current_key=old_key, now=now,
            cert_path="/etc/nginx/ssl/chain.crt", key_path="/etc/nginx/ssl/chain.key",
            chain_path="/etc/nginx/ssl/chain.pem",
        ),
    }
    unknown = Binding(
        server_id=server.id,
        webserver=WebserverType.NGINX,
        vhost_name="unknown.example.internal",
        vhost_names=["unknown.example.internal"],
        port=443,
        config_file="/etc/nginx/conf.d/unknown.conf",
        cert_path="/etc/nginx/ssl/unknown.crt",
        key_path="/etc/nginx/ssl/unknown.key",
        cert_owner="root",
        cert_group="root",
        cert_mode=0o644,
        key_owner="root",
        key_group="root",
        key_mode=0o600,
        on_disk_fingerprint="f" * 64,
        match_state="unknown",
        last_seen_at=now - timedelta(hours=1),
    )
    db.add(unknown)
    db.flush()
    return SimpleNamespace(old=old, new=new, server=server, bindings=bindings, unknown=unknown)


def _untrusted_world(db, ca, keyring, actor, now):
    """A lineage whose intermediate is not stored: the chain is ``incomplete``, so §5.8 needs a reason."""
    old, old_key = _certificate(
        db, ca, keyring, actor, now, names=("untrusted.example.internal",), with_chain=False
    )
    new, _key = _certificate(
        db, ca, keyring, actor, now, names=("untrusted.example.internal",), renews_id=old.id, with_chain=False
    )
    server = _server(db, UNTRUSTED_HOST, "ring_c", now)
    binding = _binding(
        db, server, "untrusted.example.internal", current=old, current_key=old_key, now=now,
        cert_path="/etc/nginx/ssl/untrusted.crt", key_path="/etc/nginx/ssl/untrusted.key",
    )
    return SimpleNamespace(old=old, new=new, server=server, binding=binding)


class DeployStartWorld:
    """Create deploys on the module world and keep the database in a known state for each test."""

    def __init__(self, factory, world, clock, actor):
        self.factory, self.world, self.clock, self.actor = factory, world, clock, actor

    def end_active(self):
        """One deploy at a time: finish whatever an earlier test left queued, running or paused."""
        with self.factory.begin() as db:
            db.execute(
                update(Job)
                .where(Job.type == JobType.DEPLOY, Job.status.in_(ACTIVE))
                .values(status=JobStatus.FAILED, finished_at=self.clock())
            )

    def start(self, certificate_id, **overrides):
        """Enqueue a real deploy through the guardrails and return its id (used to create the active deploy)."""
        from app.services.deploy import DeployOptions, preview_deploy, start_deploy

        self.end_active()
        options = DeployOptions(certificate_id=certificate_id, **overrides)
        with self.factory.begin() as db:
            preview = preview_deploy(db, options, self.clock())
            assert not preview.blocked, preview.blocked
            job = start_deploy(
                db,
                options,
                plan_sha256=preview.plan_sha256,
                confirmed=True,
                override_reason="fixture override",
                actor=self.actor,
                now=self.clock(),
            )
            return job.id

    def job(self, job_id):
        with self.factory() as db:
            return db.get(Job, job_id)

    def rows(self, job_id):
        with self.factory() as db:
            return list(db.scalars(select(JobHost).where(JobHost.job_id == job_id)))

    def audits(self, action):
        with self.factory() as db:
            return list(db.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


@pytest.fixture(autouse=True)
def isolated(web_factory):
    """No schedule enqueues anything, no worker has reported, and no deploy is active when a test starts."""
    disable_schedules(web_factory, "scan", "trust_recheck", "expiry_check", "digest", "cleanup", "discovery")
    with web_factory.begin() as db:
        db.query(WorkerHeartbeat).delete()
        db.execute(
            update(Job)
            .where(Job.type == JobType.DEPLOY, Job.status.in_(ACTIVE))
            .values(status=JobStatus.FAILED, finished_at=datetime(2026, 10, 19, 12, 0, tzinfo=UTC))
        )


@pytest.fixture
def start_world(web_factory, deploy_world_factory, clock, keyring, ca):
    """The Task 13 world plus the D1 pair and the untrusted lineage, built once per module."""
    global _WORLD
    configure_keyring(keyring)
    if _WORLD is None:
        operator = create_login_user(web_factory, OPERATOR)
        actor = Actor(operator.id, operator.username)
        with web_factory.begin() as db:
            _WORLD = SimpleNamespace(
                world=deploy_world_factory(db, actor),
                pair=_pair_world(db, ca, keyring, actor, clock()),
                untrusted=_untrusted_world(db, ca, keyring, actor, clock()),
                actor=actor,
            )
    return DeployStartWorld(web_factory, _WORLD, clock, _WORLD.actor)


def plan_hash(page_text):
    """The plan hash the preview wants echoed back by the confirmation POST."""
    match = re.search(r'name="plan_sha256" value="([0-9a-f]{64})"', page_text)
    assert match is not None, page_text[:800]
    return match.group(1)


def post(signed_in, **fields):
    """A refused confirmation: htmx asks for the preview fragment (422), not the whole page."""
    return signed_in.post(
        "/deploy", data={"csrf_token": signed_in.fixture_csrf, **fields}, headers={"HX-Request": "true"}
    )


def submit(signed_in, **fields):
    """A browser confirmation: POST → 303 to the new job's screen."""
    return signed_in.post(
        "/deploy", data={"csrf_token": signed_in.fixture_csrf, **fields}, follow_redirects=False
    )


# --- the §8.7 start screen ----------------------------------------------------------------------


def test_start_screen_previews_and_enqueues_with_confirmation(signed_in, start_world):
    certificate_id = start_world.world.new_certificate.id
    page = signed_in.get(f"/deploy?certificate_id={certificate_id}")
    assert page.status_code == 200
    assert "Deploy to 3 hosts, starting with canary web01.example.internal" in page.text
    assert "/etc/nginx/ssl/www.crt" in page.text and "write cert" in page.text and "write key" in page.text
    assert 'data-batch="0"' in page.text and 'data-batch="1"' in page.text  # 50% of 3 hosts -> 2 batches
    plan = plan_hash(page.text)

    refused = post(signed_in, certificate_id=certificate_id, plan_sha256=plan)
    assert refused.status_code == 422 and 'data-error="confirm"' in refused.text
    assert "<html" not in refused.text  # an htmx fragment, not the whole page

    done = signed_in.post(
        "/deploy",
        data={"certificate_id": certificate_id, "plan_sha256": plan, "confirm": "yes",
              "csrf_token": signed_in.fixture_csrf},
        follow_redirects=False,
    )
    assert done.status_code == 303 and done.headers["location"].startswith("/deploy/")
    job_id = UUID(done.headers["location"].rsplit("/", 1)[1])
    job = start_world.job(job_id)
    assert job.type is JobType.DEPLOY and job.status is JobStatus.QUEUED and job.priority == 300
    assert job.max_attempts == 1
    assert job.payload["certificate_id"] == certificate_id
    assert job.payload["plan_sha256"] == plan and job.payload["chain_override"] is False
    rows = start_world.rows(job_id)
    assert len(rows) == 4 and {row.batch_no for row in rows} == {0, 1, 2}
    assert [audit.action for audit in start_world.audits("deploy.start")][-1] == "deploy.start"


def test_guardrails_are_explained_and_link_the_active_deploy(signed_in, start_world):
    certificate_id = start_world.world.new_certificate.id
    job_id = start_world.start(certificate_id)
    page = signed_in.get(f"/deploy?certificate_id={certificate_id}")
    assert page.status_code == 200
    assert 'data-error="active_deploy"' in page.text
    assert f"deploy job {job_id} is queued" in page.text
    assert f'href="/deploy/{job_id}"' in page.text
    # Nothing can be started while another deploy holds the window.
    assert re.search(r'<button[^>]*data-start-disabled="[^"]*"[^>]*>[^<]*Start deploy', page.text)
    assert 'name="plan_sha256"' in page.text  # the preview is still shown, so the operator can read the plan


def test_override_reason_field_appears_only_when_not_trusted(signed_in, start_world):
    trusted = signed_in.get(f"/deploy?certificate_id={start_world.world.new_certificate.id}")
    assert 'name="override_reason"' not in trusted.text

    certificate_id = start_world.untrusted.new.id
    page = signed_in.get(f"/deploy?certificate_id={certificate_id}")
    assert page.status_code == 200
    assert 'name="override_reason"' in page.text
    assert "incomplete" in page.text and "reason" in page.text
    plan = plan_hash(page.text)

    refused = post(signed_in, certificate_id=certificate_id, plan_sha256=plan, confirm="yes")
    assert refused.status_code == 422 and 'data-error="chain_override"' in refused.text
    assert 'name="override_reason"' in refused.text  # the field is still there to fill in

    done = submit(
        signed_in, certificate_id=certificate_id, plan_sha256=plan, confirm="yes",
        override_reason="root rotation CHG-42, chain imported by the CA portal",
    )
    assert done.status_code == 303
    audit = start_world.audits("deploy.chain_override")[-1]
    assert audit.details["certificate_id"] == certificate_id
    assert audit.details["previous_status"] == "incomplete"
    assert audit.details["reason"] == "root rotation CHG-42, chain imported by the CA portal"
    assert audit.details["job_id"] == done.headers["location"].rsplit("/", 1)[1]


def test_unknown_bindings_and_explicit_selection_through_the_form(signed_in, start_world):
    pair = start_world.pair
    certificate_id = pair.new.id
    page = signed_in.get(f"/deploy?certificate_id={certificate_id}")
    assert page.status_code == 200
    # The unknown binding is listed (so it can be chosen) but unticked, so it is not in the plan.
    assert "unknown certificate" in page.text
    assert 'data-file="/etc/nginx/ssl/unknown.crt"' not in page.text

    # Choosing it without include_unknown is refused with the reason, not silently dropped.
    unknown = pair.unknown.id
    excluded = signed_in.get(f"/deploy?certificate_id={certificate_id}&binding_id={unknown}")
    assert 'data-excluded="unknown.example.internal:443"' in excluded.text
    assert "include unknown bindings" in excluded.text
    assert 'data-file="/etc/nginx/ssl/unknown.crt"' not in excluded.text

    # include_unknown plus the explicit id puts it in the plan, and the audit flag goes with the job.
    included = signed_in.get(f"/deploy?certificate_id={certificate_id}&include_unknown=1&binding_id={unknown}")
    assert 'data-file="/etc/nginx/ssl/unknown.crt"' in included.text
    plan = plan_hash(included.text)
    done = submit(
        signed_in, certificate_id=certificate_id, plan_sha256=plan, confirm="yes",
        include_unknown="1", selection="explicit", binding_id=[unknown],
    )
    assert done.status_code == 303
    job_id = UUID(done.headers["location"].rsplit("/", 1)[1])
    assert start_world.job(job_id).payload["include_unknown"] is True
    assert [audit.action for audit in start_world.audits("deploy.include_unknown")][-1] == "deploy.include_unknown"
    start_world.end_active()  # one deploy at a time: the next half starts from a free window

    # Explicit selection of two matched bindings leaves the third one out of the plan.
    ids = "&".join(f"binding_id={pair.bindings[name].id}" for name in ("rsa", "ecdsa"))
    selected = signed_in.get(f"/deploy?certificate_id={certificate_id}&selection=explicit&{ids}")
    assert "/etc/nginx/ssl/rsa.crt" in selected.text and "/etc/nginx/ssl/ecdsa.crt" in selected.text
    assert 'data-file="/etc/nginx/ssl/chain.crt"' not in selected.text
    assert "Deploy to 1 host, starting with canary pair.example.internal" in selected.text
    assert selected.text.count('name="binding_id" value="') >= 2  # the confirmation carries the selection
    plan = plan_hash(selected.text)
    done = submit(
        signed_in, certificate_id=certificate_id, plan_sha256=plan, confirm="yes",
        selection="explicit", binding_id=[pair.bindings["rsa"].id, pair.bindings["ecdsa"].id],
    )
    assert done.status_code == 303
    rows = start_world.rows(UUID(done.headers["location"].rsplit("/", 1)[1]))
    assert {row.binding_id for row in rows} == {pair.bindings["rsa"].id, pair.bindings["ecdsa"].id}


def test_plan_change_between_preview_and_post_shows_the_new_preview(signed_in, start_world):
    certificate_id = start_world.world.new_certificate.id
    page = signed_in.get(f"/deploy?certificate_id={certificate_id}")
    stale = plan_hash(page.text)
    assert 'data-total="bindings">4<' in page.text  # the world's four bindings

    one = start_world.world.target_bindings[0].id
    changed = post(
        signed_in, certificate_id=certificate_id, plan_sha256=stale, confirm="yes",
        selection="explicit", binding_id=[one],
    )
    assert changed.status_code == 422
    assert 'data-error="plan_changed"' in changed.text
    fresh = plan_hash(changed.text)
    assert fresh != stale
    # The new plan is really shown: one binding, one host, and its own hash to confirm.
    assert 'data-total="bindings">1<' in changed.text
    assert "Deploy to 1 host" in changed.text


def test_navigation_and_panels_are_enabled(signed_in, start_world):
    home = signed_in.get("/").text
    assert '<a href="/deploy">Deploy</a>' in home
    registry = signed_in.app.state.job_registry
    assert registry.supports(JobType.DEPLOY) and registry.supports(JobType.DEPLOY, "default")
    assert worker.TICK_STEPS["deploy_sweep"].requires == (JobType.DEPLOY, "default")
    assert registry.supports(*worker.TICK_STEPS["deploy_sweep"].requires)

    certificate_id = start_world.world.new_certificate.id
    job_id = start_world.start(certificate_id)
    page = signed_in.get(f"/certificates/{certificate_id}").text
    assert f'href="/deploy?certificate_id={certificate_id}"' in page
    panel = re.search(r'<section[^>]*id="deploy-panel".*?</section>', page, re.DOTALL)
    assert panel is not None, page[:1200]
    assert f'href="/deploy/{job_id}"' in panel.group(0)
    assert "deploy job" in panel.group(0) and str(job_id) in panel.group(0)

    renewal_id = start_world.world.renewal.id
    ready = signed_in.get(f"/renewals/{renewal_id}?step=ready").text
    assert f'href="/deploy?certificate_id={certificate_id}"' in ready
    assert "Deployment is not available" not in ready


def test_overview_recent_jobs_link_deploy_jobs(signed_in, start_world):
    certificate_id = start_world.world.new_certificate.id
    job_id = start_world.start(certificate_id)
    page = signed_in.get("/").text
    row = re.search(rf'<tr[^>]*data-job-id="{job_id}".*?</tr>', page, re.DOTALL)
    assert row is not None, page[:1200]
    assert f'href="/deploy/{job_id}"' in row.group(0)
    assert f"certificate {certificate_id}" in row.group(0)
    secret = start_world.job(job_id).payload["plan_sha256"]
    assert secret not in page and "plan_sha256" not in row.group(0)

    assert job_summary(JobType.DEPLOY, {"certificate_id": certificate_id}) == f"certificate {certificate_id}"
    assert job_summary(
        JobType.DEPLOY, {"certificate_id": certificate_id, "plan_sha256": secret, "renewal_id": str(UUID(int=7))}
    ) == f"certificate {certificate_id}"


def test_without_ssh_worker_the_start_button_is_disabled(signed_in, start_world, web_factory, make_worker, clock):
    worker_runtime = make_worker(web_factory)  # no ansible_ssh_key and no known_hosts file
    record_worker_start(web_factory, worker_runtime.settings, worker_runtime.worker_id, clock())
    worker_runtime.tick()

    page = signed_in.get(f"/deploy?certificate_id={start_world.world.new_certificate.id}")
    assert page.status_code == 200
    assert NO_SSH_KEY in page.text
    assert re.search(r'<button[^>]*data-start-disabled="[^"]*"[^>]*>[^<]*Start deploy', page.text)
    assert "disabled" in page.text


def test_start_screen_requires_csrf_and_escapes_values(signed_in, start_world):
    certificate_id = start_world.world.new_certificate.id
    refused = signed_in.post("/deploy", data={"certificate_id": certificate_id, "plan_sha256": "0" * 64})
    assert refused.status_code == 403

    page = signed_in.get(f"/deploy?certificate_id={certificate_id}&group=%3Cscript%3Ealert(1)%3C/script%3E")
    assert page.status_code == 200
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text

    # The untrusted lineage keeps the override field on the refused preview, so a hostile value must be
    # escaped there too.
    hostile = "<script>alert('x')</script>"
    escaped = post(
        signed_in, certificate_id=start_world.untrusted.new.id, plan_sha256="0" * 64, confirm="yes",
        override_reason=hostile,
    )
    assert escaped.status_code == 422
    assert hostile not in escaped.text
    assert "&lt;script&gt;" in escaped.text


def test_times_are_shown_in_the_display_timezone_and_utc(signed_in, start_world, web_factory):
    from zoneinfo import ZoneInfo

    from tests.integration.conftest import set_setting

    certificate = start_world.world.new_certificate
    set_setting(web_factory, "ui.timezone", "Europe/Rome")
    try:
        page = signed_in.get(f"/deploy?certificate_id={certificate.id}")
        iso = certificate.not_after.strftime("%Y-%m-%dT%H:%M:%SZ")
        local = certificate.not_after.astimezone(ZoneInfo("Europe/Rome")).strftime("%Y-%m-%d %H:%M")
        assert f'<time datetime="{iso}">{local} CE' in page.text  # UTC machine value, local display
        assert "Not before (Europe/Rome)" in page.text  # the form says which zone it reads

        job_id = start_world.start(certificate.id)
        panel = signed_in.get(f"/certificates/{certificate.id}").text
        job = start_world.job(job_id)
        created = job.created_at.astimezone(ZoneInfo("Europe/Rome")).strftime("%Y-%m-%d %H:%M")
        assert f"{created} CE" in panel and job.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") in panel
    finally:
        set_setting(web_factory, "ui.timezone", "UTC")


# --- D1: the preview shows exactly what will be written ------------------------------------------


def test_preview_renders_exactly_the_planned_file_writes(signed_in, start_world):
    page = signed_in.get(f"/deploy?certificate_id={start_world.pair.new.id}")
    assert page.status_code == 200
    host = re.search(r'<tr[^>]*data-host="pair.example.internal".*?</tr>', page.text, re.DOTALL)
    assert host is not None, page[:1500]
    section = host.group(0)
    actions = re.findall(r'data-action="(write [a-z]+)"', section)
    # rsa.crt and ecdsa.crt are two certificate files of one issuer with no verified chain: two leaf writes.
    # chain.crt carries a verified chain_path, so it alone gets a chain write.
    assert sorted(actions) == ["write cert", "write cert", "write chain", "write key", "write key", "write key"]
    assert section.count('data-action="write chain"') == 1
    assert "/etc/nginx/ssl/chain.pem" in section
    for path in ("/etc/nginx/ssl/rsa.crt", "/etc/nginx/ssl/ecdsa.crt", "/etc/nginx/ssl/chain.crt"):
        assert f'data-file="{path}"' in section
    assert "root:root" in section and "0644" in section and "0600" in section


def test_preview_shows_the_chain_diagnostic_of_a_binding(signed_in, start_world):
    page = signed_in.get(f"/deploy?certificate_id={start_world.pair.new.id}")
    host = re.search(r'<tr[^>]*data-host="pair.example.internal".*?</tr>', page.text, re.DOTALL)
    assert host is not None, page[:1500]
    binding_id = start_world.pair.bindings["ecdsa"].id
    binding = re.search(rf'<div[^>]*data-binding="{binding_id}".*?</div>', host.group(0), re.DOTALL)
    assert binding is not None, host.group(0)[:1500]
    assert 'data-chain-diagnostic' in binding.group(0)
    assert CHAIN_DIAGNOSTIC in binding.group(0)
    # The binding is still a target: the diagnostic is information, not a silent exclusion.
    assert "/etc/nginx/ssl/ecdsa.crt" in host.group(0)
