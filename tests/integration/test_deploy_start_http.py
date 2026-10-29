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
from html import unescape
from types import SimpleNamespace
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy import select, update

from app.crypto.chain import order_chain
from app.crypto.parse import parse_certificates
from app.jobs import worker
from app.jobs.worker import record_worker_start
from app.models import AuditLog, Binding, Job, JobHost, Server, WorkerHeartbeat
from app.models.enums import JobStatus, JobType, PrivateKeyType, WebserverType
from app.services.audit import Actor
from app.services.certificates import CertificateMetadata, save_certificate, store_key
from app.services.deploy import configure_keyring
from app.services.overview import job_summary
from tests.integration.conftest import create_login_user, disable_schedules

OPERATOR = "deploy-start-operator"
PAIR_HOST = "pair.example.internal"
UNTRUSTED_HOST = "untrusted.example.internal"
BLOCKED_HOST = "blocked.example.internal"
# What reconciliation records on a binding whose separate certificate file could not be verified as the
# chain of the leaf (D1 / operator decision 4): it stays a certificate of its own and carries the diagnostic.
CHAIN_DIAGNOSTIC = "incomplete chain: no configured file holds this leaf's issuer"
NO_SSH_KEY = "Discovery and deploy are unavailable: the worker has no ansible_ssh_key"
ACTIVE = (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.PAUSED)
_WORLD: SimpleNamespace | None = None


def _certificate(db, ca, keyring, actor, now, *, names, renews_id=None, with_chain=True, key_type="ec"):
    """A keyed leaf the session CA issues, stored with its intermediate or deliberately without it."""
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if key_type == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
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


def _binding(
    db, server, vhost, *, current, current_key, now, cert_path, key_path, chain_path=None,
    match_state="matched", on_disk_fingerprint=None, **extra,
):
    """One active binding of ``current``, with the paths the preview must write."""
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
        on_disk_fingerprint=on_disk_fingerprint or current.sha256_fingerprint,
        on_disk_key_public_sha256=current_key.public_key_sha256,
        certificate_id=current.id,
        match_state=match_state,
        last_seen_at=now - timedelta(hours=1),
        **extra,
    )
    db.add(row)
    db.flush()
    return row


def _pair_world(db, ca, keyring, actor, now):
    """D1: a host with a real same-issuer RSA+ECDSA pair plus one binding whose chain file verifies.

    ``rsa_old`` and ``ecdsa_old`` are two distinct certificates signed by the same CA — one with an RSA key,
    one with an EC key — and neither has a chain file. A positional or issuer-matching heuristic would make
    the second certificate a chain of the first and write a chain over a live certificate; the preview must
    show one ``write cert`` per file and a ``write chain`` only for the binding with a verified ``chain_path``.
    """
    rsa_old, rsa_key = _certificate(
        db, ca, keyring, actor, now, names=("rsa.example.internal",), key_type="rsa"
    )
    ecdsa_old, ecdsa_key = _certificate(db, ca, keyring, actor, now, names=("ecdsa.example.internal",))
    pair_new, _pair_key = _certificate(
        db, ca, keyring, actor, now, names=("rsa.example.internal", "ecdsa.example.internal"),
        renews_id=rsa_old.id,
    )
    chain_old, chain_key = _certificate(db, ca, keyring, actor, now, names=("chain.example.internal",))
    chain_new, _chain_key = _certificate(
        db, ca, keyring, actor, now, names=("chain.example.internal",), renews_id=chain_old.id
    )
    server = _server(db, PAIR_HOST, "ring_b", now)
    bindings = {
        "rsa": _binding(
            db, server, "rsa.example.internal", current=rsa_old, current_key=rsa_key, now=now,
            cert_path="/etc/nginx/ssl/rsa.crt", key_path="/etc/nginx/ssl/rsa.key",
        ),
        "ecdsa": _binding(
            db, server, "ecdsa.example.internal", current=ecdsa_old, current_key=ecdsa_key, now=now,
            cert_path="/etc/nginx/ssl/ecdsa.crt", key_path="/etc/nginx/ssl/ecdsa.key",
            notes=CHAIN_DIAGNOSTIC,
        ),
        "chain": _binding(
            db, server, "chain.example.internal", current=chain_old, current_key=chain_key, now=now,
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
    return SimpleNamespace(
        old=rsa_old, rsa_old=rsa_old, ecdsa_old=ecdsa_old, new=pair_new, chain_new=chain_new,
        server=server, bindings=bindings, unknown=unknown, rsa_key=rsa_key, ecdsa_key=ecdsa_key,
    )


def _blocked_world(db, ca, keyring, actor, now):
    """A lineage whose only bindings are excluded from every plan: one ``key_mismatch``, one ``missing_file``.

    Both carry the new fingerprint on disk, so a guardrail that counts them as targets would report
    ``already_deployed`` (or, with different fingerprints, nothing at all) while the authoritative preview
    refuses with ``no_targets``. The panel and the start screen must agree.
    """
    old, old_key = _certificate(db, ca, keyring, actor, now, names=("blocked.example.internal",))
    new, _key = _certificate(
        db, ca, keyring, actor, now, names=("blocked.example.internal",), renews_id=old.id
    )
    server = _server(db, BLOCKED_HOST, "ring_d", now)
    bindings = (
        _binding(
            db, server, "blocked.example.internal", current=old, current_key=old_key, now=now,
            cert_path="/etc/nginx/ssl/blocked.crt", key_path="/etc/nginx/ssl/blocked.key",
            match_state="key_mismatch", on_disk_fingerprint=new.sha256_fingerprint,
        ),
        _binding(
            db, server, "blocked.example.internal", current=old, current_key=old_key, now=now,
            cert_path="/etc/nginx/ssl/missing.crt", key_path="/etc/nginx/ssl/missing.key",
            match_state="missing_file", on_disk_fingerprint=new.sha256_fingerprint,
            notes="certificate missing or unreadable at discovery",
        ),
    )
    return SimpleNamespace(old=old, new=new, server=server, bindings=bindings)


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

    def __init__(self, factory, namespace, clock, actor):
        self.factory, self.clock, self.actor = factory, clock, actor
        self.world = namespace.world
        self.pair = namespace.pair
        self.untrusted = namespace.untrusted
        self.blocked = namespace.blocked

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
                blocked=_blocked_world(db, ca, keyring, actor, clock()),
                actor=actor,
            )
    return DeployStartWorld(web_factory, _WORLD, clock, _WORLD.actor)


def plan_hash(page_text):
    """The plan hash the preview wants echoed back by the confirmation POST."""
    match = re.search(r'name="plan_sha256" value="([0-9a-f]{64})"', page_text)
    assert match is not None, page_text[:800]
    return match.group(1)


def binding_block(host_html: str, binding_id: int) -> str:
    """One binding's rendered block inside a host row, nested elements included."""
    start = host_html.index(f'data-binding="{binding_id}"')
    end = host_html.find('data-binding="', start + 1)
    return host_html[start:] if end == -1 else host_html[start:end]


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
    # §6.6: the operator compares the identity that is on disk with the one that will be written, per
    # binding, before confirming. Today only the totals panel named the new certificate.
    old, new = start_world.world.old, start_world.world.new_certificate
    binding_id = start_world.world.target_bindings[0].id
    host = re.search(r'<tr[^>]*data-host="web01\.example\.internal".*?</tr>', page.text, re.DOTALL)
    assert host is not None, page.text[:2000]
    block = binding_block(host.group(0), binding_id)
    assert "data-identity" in block
    assert f'data-current-cn="{old.common_name}"' in block
    assert f'data-current-fingerprint="{old.sha256_fingerprint}"' in block
    assert f'data-new-cn="{new.common_name}"' in block
    assert f'data-new-fingerprint="{new.sha256_fingerprint}"' in block
    assert f'<time datetime="{old.not_after.strftime("%Y-%m-%dT%H:%M:%SZ")}">' in block
    assert f'<time datetime="{new.not_after.strftime("%Y-%m-%dT%H:%M:%SZ")}">' in block
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


def test_panel_and_start_screen_agree_when_every_binding_is_excluded(signed_in, start_world):
    """§8.4/§8.7: the panel must not promise a deploy the authoritative plan refuses (Contract decision 15)."""
    blocked = start_world.blocked
    page = signed_in.get(f"/certificates/{blocked.new.id}").text
    section = re.search(r'<section[^>]*id="deploy-panel".*?</section>', page, re.DOTALL)
    assert section is not None, page[:1500]
    panel = section.group(0)
    assert 'data-error="no_targets"' in panel
    # The reason is preserved: the operator is told which states kept the bindings out of every plan.
    assert "key_mismatch" in panel and "missing_file" in panel
    assert 'data-error="already_deployed"' not in panel
    assert "data-deploy-ready" not in panel

    start = signed_in.get(f"/deploy?certificate_id={blocked.new.id}")
    assert start.status_code == 200
    assert 'data-error="no_targets"' in start.text
    assert 'data-error="already_deployed"' not in start.text
    assert re.search(r'<button[^>]*data-start-disabled="[^"]*"[^>]*>[^<]*Start deploy', start.text)


def test_changing_the_certificate_recomputes_the_target_choices(signed_in, start_world):
    """The picker must not keep the previous certificate's ticked bindings or its canary server."""
    world, pair = start_world.world, start_world.pair
    stale = world.target_bindings[0].id
    stale_canary = world.servers["web02.example.internal"].id

    fresh = signed_in.get(f"/deploy?certificate_id={pair.new.id}")
    assert f'name="selection_for" value="{pair.new.id}"' in fresh.text
    assert 'data-total="bindings">1<' in fresh.text  # the pair renewal owns one default target
    select = re.search(r'<select[^>]*id="certificate_id"[^>]*>', fresh.text)
    assert select is not None
    # htmx replaces the whole options screen for a certificate change: the server re-renders the checkbox
    # list and the canary choices for the new certificate instead of keeping the previous ones in the DOM.
    assert 'hx-get="/deploy"' in select.group(0) and 'hx-select="#deploy-screen"' in select.group(0)
    assert 'hx-target="#deploy-screen"' in select.group(0)
    assert 'hx-trigger="change consume"' in select.group(0)  # the form does not double-preview it

    # A non-default canary chosen for the old certificate is part of the form the picker includes
    # (``hx-include="#deploy-options"``): it must be kept while the certificate stays the same.
    with_canary = signed_in.get(
        f"/deploy?certificate_id={world.new_certificate.id}&canary_server_id={stale_canary}"
    )
    assert with_canary.status_code == 200
    assert f'<option value="{stale_canary}" selected>' in with_canary.text
    assert 'data-host="web02.example.internal"' in with_canary.text

    # Changing the picker sends the previous certificate's ticked ids *and* its canary server. Neither may
    # survive: the new certificate's plan must still be computed, with its own canary choices and default.
    stale_form = (
        f"certificate_id={pair.new.id}&selection=explicit&selection_for={world.new_certificate.id}"
        f"&binding_id={stale}&canary_server_id={stale_canary}"
        f"&batch_percent=10&pause_after_canary=0&include_unknown=0"
    )
    changed = signed_in.get(f"/deploy?{stale_form}")
    assert changed.status_code == 200
    assert f'name="selection_for" value="{pair.new.id}"' in changed.text
    assert 'data-total="bindings">1<' in changed.text
    assert f'data-host="{PAIR_HOST}"' in changed.text
    assert 'data-host="web01.example.internal"' not in changed.text
    assert f'name="binding_id" value="{pair.bindings["rsa"].id}" checked' in changed.text
    assert f'name="binding_id" value="{stale}"' not in changed.text
    canary = re.search(r'<select[^>]*id="canary_server_id"[^>]*>.*?</select>', changed.text, re.DOTALL)
    assert canary is not None
    assert f'<option value="{pair.server.id}"' in canary.group(0)
    assert f'value="{stale_canary}"' not in canary.group(0)
    assert '<option value="" selected>' in canary.group(0)

    # The htmx preview fragment is the same request: the new plan, not the stale canary's refusal.
    fragment = signed_in.get(f"/deploy/preview?{stale_form}")
    assert fragment.status_code == 200
    assert 'data-total="bindings">1<' in fragment.text
    assert f'data-host="{PAIR_HOST}"' in fragment.text
    assert "not part of the rollout" not in fragment.text


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


def test_preview_renders_two_cert_writes_for_a_same_issuer_rsa_ecdsa_pair(signed_in, start_world):
    pair = start_world.pair
    # A real RSA+ECDSA pair: two distinct certificates from the same CA (same issuer), neither with a chain.
    assert pair.rsa_old.issuer_dn == pair.ecdsa_old.issuer_dn
    assert pair.rsa_key.key_type is PrivateKeyType.RSA and pair.ecdsa_key.key_type is PrivateKeyType.ECDSA
    assert pair.rsa_old.sha256_fingerprint != pair.ecdsa_old.sha256_fingerprint
    ids = "&".join(f"binding_id={pair.bindings[name].id}" for name in ("rsa", "ecdsa"))
    page = signed_in.get(f"/deploy?certificate_id={pair.new.id}&selection=explicit&{ids}")
    assert page.status_code == 200
    host = re.search(rf'<tr[^>]*data-host="{PAIR_HOST}".*?</tr>', page.text, re.DOTALL)
    assert host is not None, page[:2000]
    section = host.group(0)
    actions = re.findall(r'data-action="(write [a-z]+)"', section)
    # Two certificate files of one issuer, neither a verified chain: two leaf writes and no chain write.
    assert sorted(actions) == ["write cert", "write cert", "write key", "write key"]
    assert 'data-action="write chain"' not in section
    for path in ("/etc/nginx/ssl/rsa.crt", "/etc/nginx/ssl/ecdsa.crt"):
        assert f'data-file="{path}"' in section
    assert 'data-file="/etc/nginx/ssl/chain.crt"' not in section
    assert "root:root" in section and "0644" in section and "0600" in section


def test_preview_renders_a_verified_chain_write(signed_in, start_world):
    pair = start_world.pair
    page = signed_in.get(f"/deploy?certificate_id={pair.chain_new.id}")
    assert page.status_code == 200
    host = re.search(rf'<tr[^>]*data-host="{PAIR_HOST}".*?</tr>', page.text, re.DOTALL)
    assert host is not None, page[:2000]
    section = host.group(0)
    actions = re.findall(r'data-action="(write [a-z]+)"', section)
    assert sorted(actions) == ["write cert", "write chain", "write key"]
    for path in ("/etc/nginx/ssl/chain.crt", "/etc/nginx/ssl/chain.pem", "/etc/nginx/ssl/chain.key"):
        assert f'data-file="{path}"' in section


def test_preview_shows_the_chain_diagnostic_of_a_binding(signed_in, start_world):
    pair = start_world.pair
    ids = "&".join(f"binding_id={pair.bindings[name].id}" for name in ("rsa", "ecdsa"))
    page = signed_in.get(f"/deploy?certificate_id={pair.new.id}&selection=explicit&{ids}")
    host = re.search(rf'<tr[^>]*data-host="{PAIR_HOST}".*?</tr>', page.text, re.DOTALL)
    assert host is not None, page[:1500]
    binding_id = pair.bindings["ecdsa"].id
    block = binding_block(host.group(0), binding_id)
    assert "data-chain-diagnostic" in block
    # The page escapes the text (an apostrophe is ``&#39;``); the operator still reads the exact diagnostic.
    assert CHAIN_DIAGNOSTIC in unescape(block)
    # The binding is still a target: the diagnostic is information, not a silent exclusion.
    assert "/etc/nginx/ssl/ecdsa.crt" in host.group(0)
