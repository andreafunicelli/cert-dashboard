"""Deploy preview, guardrails, trust gate and atomic enqueue (Plan 3 Task 13; spec 5.8, 6.5, 6.6, 8.7)."""

import threading
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import func, select

from app.crypto.chain import order_chain
from app.crypto.parse import parse_certificates
from app.models import AuditLog, Binding, Job, JobHost, User
from app.models.enums import (
    CertificateStatus,
    ChainStatus,
    JobHostStatus,
    JobStatus,
    JobType,
    WebserverType,
)
from app.services.audit import Actor
from app.services.certificates import CertificateMetadata, save_certificate, store_key
from app.services.deploy import DEPLOY_PRIORITY, DeployBlocked, DeployOptions, preview_deploy, start_deploy
from app.services.trust_anchors import assess_certificate, remove_anchor


def host_rows(db, job_id):
    return list(
        db.scalars(
            select(JobHost).where(JobHost.job_id == job_id).order_by(JobHost.batch_no, JobHost.binding_id)
        )
    )


def audits(db, target_type, target_id):
    return list(
        db.scalars(
            select(AuditLog)
            .where(AuditLog.target_type == target_type, AuditLog.target_id == target_id)
            .order_by(AuditLog.created_at)
        )
    )


def one_audit(db, action, target_type, target_id):
    """The single audit row of ``action`` for a target (audit ids are random UUIDs, so no ordering)."""
    rows = [row for row in audits(db, target_type, target_id) if row.action == action]
    assert len(rows) == 1, [row.action for row in rows]
    return rows[0]


def refused(action, **kwargs):
    with pytest.raises(DeployBlocked) as info:
        action(**kwargs)
    return info.value


def preview_and_start(db, options, actor, now, **overrides):
    """The screen's flow: compute the preview, echo its hash, confirm and enqueue."""
    preview = preview_deploy(db, options, now)
    fields = {
        "plan_sha256": preview.plan_sha256,
        "confirmed": True,
        "override_reason": None,
        "actor": actor,
        "now": now,
    }
    fields.update(overrides)
    return start_deploy(db, options, **fields), preview


def extra_binding(db, world, now, **overrides):
    """One more active binding of the previous certificate on ``web02`` (default target)."""
    fields = {
        "server_id": world.servers["web02.example.internal"].id,
        "webserver": WebserverType.NGINX,
        "vhost_name": "extra.example.internal",
        "vhost_names": ["extra.example.internal"],
        "port": 443,
        "config_file": "/etc/nginx/conf.d/extra.conf",
        "cert_path": "/etc/nginx/ssl/extra.crt",
        "chain_path": None,
        "key_path": "/etc/nginx/ssl/extra.key",
        "cert_owner": "root",
        "cert_group": "root",
        "cert_mode": 0o644,
        "key_owner": "root",
        "key_group": "root",
        "key_mode": 0o600,
        "on_disk_fingerprint": world.old.sha256_fingerprint,
        "on_disk_key_public_sha256": world.old_key.public_key_sha256,
        "certificate_id": world.old.id,
        "match_state": "matched",
        "last_seen_at": now,
    }
    fields.update(overrides)
    row = Binding(**fields)
    db.add(row)
    db.flush()
    return row


def variant_certificate(db, ca, keyring, actor, now, *, key=True, revoked=False, key_version=None, **validity):
    """A keyed (or keyless) leaf for the guardrail matrix; every one is a fresh certificate."""
    days = {"days_before": 300, "days_after": 100} | validity
    key_obj = ec.generate_private_key(ec.SECP256R1())
    pem = ca.issue(
        public_key=key_obj.public_key(),
        common_name="variant.example.internal",
        sans=["variant.example.internal"],
        not_before=now - timedelta(days=days["days_before"]),
        not_after=now + timedelta(days=days["days_after"]),
    )
    leaf = parse_certificates(pem)[0]
    chain = order_chain(leaf.cert, [x509.load_pem_x509_certificate(ca.chain_pem)])
    key_row = store_key(db, keyring, key_obj, "generated", actor) if key else None
    if key_row is not None and key_version is not None:
        key_row.master_key_version = key_version
        db.flush()
    saved = save_certificate(
        db,
        leaf,
        chain,
        CertificateMetadata(),
        actor,
        source="upload_pem",
        key_id=key_row.id if key_row else None,
        validation_time=now,
    ).certificate
    if revoked:
        saved.status = CertificateStatus.REVOKED
        db.flush()
    return saved


def test_start_writes_the_job_and_every_host_row_in_one_transaction(db, actor, now, deploy_world):
    options = DeployOptions(deploy_world.new_certificate.id)
    preview = preview_deploy(db, options, now)
    assert preview.blocked == {}
    assert preview.totals == {"hosts": 3, "bindings": 4, "files": 8, "groups": 2}
    assert [host.hostname for host in preview.hosts if host.batch_no == 0] == ["web01.example.internal"]
    assert preview.batches == (1, 1, 1)
    job = start_deploy(
        db,
        options,
        plan_sha256=preview.plan_sha256,
        confirmed=True,
        override_reason=None,
        actor=actor,
        now=now,
    )
    rows = host_rows(db, job.id)
    assert (job.priority, job.max_attempts, job.payload["renewal_id"]) == (
        DEPLOY_PRIORITY,
        1,
        str(deploy_world.renewal.id),
    )
    assert {(r.binding_id, r.batch_no, r.status) for r in rows} == {
        (b.id, deploy_world.batch_of[b.server_id], JobHostStatus.PENDING) for b in deploy_world.target_bindings
    }
    assert all(r.old_fingerprint == deploy_world.old.sha256_fingerprint for r in rows)
    assert all(r.new_fingerprint == deploy_world.new_certificate.sha256_fingerprint for r in rows)
    started = one_audit(db, "deploy.start", "job", str(job.id))
    assert started.details == {
        "certificate_id": deploy_world.new_certificate.id,
        "hosts": 3,
        "bindings": 4,
        "canary": "web01.example.internal",
        "batches": [1, 1, 1],
    }


def test_preview_lists_the_file_actions_the_deploy_will_perform(db, now, deploy_world):
    """D1: the writes come only from the stored paths, and a chain write needs a verified chain_path."""
    preview = preview_deploy(db, DeployOptions(deploy_world.new_certificate.id), now)
    by_host = {host.hostname: host for host in preview.hosts}
    apache = by_host["web03.example.internal"]
    assert {(f.path, f.action) for f in apache.files} == {
        ("/etc/apache2/ssl/www.crt", "write cert"),
        ("/etc/apache2/ssl/www.chain.pem", "write chain"),
        ("/etc/apache2/ssl/www.key", "write key"),
    }
    nginx = by_host["web01.example.internal"]
    assert {(f.path, f.action) for f in nginx.files} == {
        ("/etc/nginx/ssl/www.crt", "write cert"),  # one shared full-chain write for both vhosts
        ("/etc/nginx/ssl/www.key", "write key"),
        ("/etc/nginx/ssl/legacy.key", "write key"),
    }
    assert next(f for f in apache.files if f.action == "write key").mode == "0600"
    assert next(f for f in nginx.files if f.action == "write cert").mode == "0644"


def test_a_same_issuer_rsa_ecdsa_pair_is_two_bindings_and_gets_no_chain_write(db, now, deploy_world):
    """D1 operator decision 5: no positional assumption; two certificates stay two bindings."""
    server = deploy_world.servers["web02.example.internal"]
    pair = (
        extra_binding(
            db,
            deploy_world,
            now,
            vhost_name="rsa.example.internal",
            config_file="/etc/nginx/conf.d/rsa.conf",
            cert_path="/etc/nginx/ssl/rsa.crt",
            key_path="/etc/nginx/ssl/rsa.key",
        ),
        extra_binding(
            db,
            deploy_world,
            now,
            vhost_name="ecdsa.example.internal",
            config_file="/etc/nginx/conf.d/ecdsa.conf",
            cert_path="/etc/nginx/ssl/ecdsa.crt",
            key_path="/etc/nginx/ssl/ecdsa.key",
        ),
    )
    assert pair[0].server_id == pair[1].server_id == server.id
    preview = preview_deploy(
        db, DeployOptions(deploy_world.new_certificate.id, binding_ids=(pair[0].id, pair[1].id)), now
    )
    files = preview.hosts[0].files
    assert sorted(f.action for f in files) == ["write cert", "write cert", "write key", "write key"]
    assert {f.path for f in files} == {
        "/etc/nginx/ssl/rsa.crt",
        "/etc/nginx/ssl/ecdsa.crt",
        "/etc/nginx/ssl/rsa.key",
        "/etc/nginx/ssl/ecdsa.key",
    }


def test_a_path_needed_with_two_contents_blocks_the_start(db, actor, now, deploy_world):
    """D1/§6.4: one path may never receive two different contents on one host."""
    deed = extra_binding(
        db,
        deploy_world,
        now,
        vhost_name="conflict-a.example.internal",
        cert_path="/etc/nginx/ssl/shared.pem",
        key_path="/etc/nginx/ssl/a.key",
    )
    borrower = extra_binding(
        db,
        deploy_world,
        now,
        vhost_name="conflict-b.example.internal",
        config_file="/etc/nginx/conf.d/conflict-b.conf",
        cert_path="/etc/nginx/ssl/b.crt",
        key_path="/etc/nginx/ssl/shared.pem",
    )
    options = DeployOptions(deploy_world.new_certificate.id, binding_ids=(deed.id, borrower.id))
    preview = preview_deploy(db, options, now)
    assert "/etc/nginx/ssl/shared.pem" in preview.blocked["file_conflict"]
    error = refused(
        start_deploy,
        db=db,
        options=options,
        plan_sha256=preview.plan_sha256,
        confirmed=True,
        override_reason=None,
        actor=actor,
        now=now,
    )
    assert "file_conflict" in error.reasons and job_count(db) == 0


def test_a_rolled_back_enqueue_leaves_no_job_host_or_audit(queue_factory, deploy_world_factory, now):
    """The ``job``, its ``job_host`` rows and every audit are staged in the caller's transaction."""
    with queue_factory() as db:
        user = User(username="rollback-operator", email="rollback@example.test")
        db.add(user)
        db.flush()
        actor = Actor(user.id, user.username)
        world = deploy_world_factory(db, actor)
        options = DeployOptions(world.new_certificate.id)
        preview = preview_deploy(db, options, now)
        start_deploy(
            db,
            options,
            plan_sha256=preview.plan_sha256,
            confirmed=True,
            override_reason=None,
            actor=actor,
            now=now,
        )
        assert db.scalar(select(func.count()).select_from(Job)) == 1
        db.rollback()
    with queue_factory() as db:
        assert db.scalar(select(func.count()).select_from(Job)) == 0
        assert db.scalar(select(func.count()).select_from(JobHost)) == 0
        assert db.scalar(select(func.count()).select_from(AuditLog)) == 0


def test_untrusted_chain_requires_a_reasoned_audited_override(db, actor, now, deploy_world):
    reason = "the internal root is pending upload; the intermediate is the expected one"
    remove_anchor(db, deploy_world.anchor.id, actor, now)
    options = DeployOptions(deploy_world.new_certificate.id)
    preview = preview_deploy(db, options, now)
    assert preview.blocked == {}
    assert preview.needs_override is True and preview.chain_status != "trusted"
    assert preview.chain_status != ChainStatus.TRUSTED.value

    error = refused(
        start_deploy,
        db=db,
        options=options,
        plan_sha256=preview.plan_sha256,
        confirmed=True,
        override_reason=None,
        actor=actor,
        now=now,
    )
    assert set(error.reasons) == {"chain_override"}

    job = start_deploy(
        db,
        options,
        plan_sha256=preview.plan_sha256,
        confirmed=True,
        override_reason=reason,
        actor=actor,
        now=now,
    )
    assert job.payload["chain_override"] is True
    assert job.payload["chain_status_at_plan"] == preview.chain_status
    override = [row for row in audits(db, "job", str(job.id)) if row.action == "deploy.chain_override"]
    assert len(override) == 1
    assert override[0].details == {
        "certificate_id": deploy_world.new_certificate.id,
        "previous_status": preview.chain_status,
        "job_id": str(job.id),
        "reason": reason,
    }


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("expired", "expired"),
        ("not_yet_valid", "not_yet_valid"),
        ("keyless", "no_key"),
        ("revoked", "revoked"),
        ("key_version", "key_version"),
    ],
)
def test_override_never_bypasses_key_or_validity_guardrails(
    db, ca, keyring, actor, now, deploy_world, case, expected
):
    certificate = variant_certificate(
        db,
        ca,
        keyring,
        actor,
        now,
        key=case != "keyless",
        revoked=case == "revoked",
        key_version=99 if case == "key_version" else None,
        **(
            {"days_before": 400, "days_after": -1}
            if case == "expired"
            else {"days_before": -10, "days_after": 100}
            if case == "not_yet_valid"
            else {}
        ),
    )
    options = DeployOptions(certificate.id, binding_ids=(deploy_world.target_bindings[2].id,))
    preview = preview_deploy(db, options, now)
    assert expected in preview.blocked, preview.blocked
    error = refused(
        start_deploy,
        db=db,
        options=options,
        plan_sha256=preview.plan_sha256,
        confirmed=True,
        override_reason="an operator reason is not a bypass",
        actor=actor,
        now=now,
    )
    assert expected in error.reasons, error.reasons
    assert job_count(db) == 0


def job_count(db):
    return db.scalar(select(func.count()).select_from(Job)) or 0


def test_key_mismatch_and_missing_file_bindings_are_excluded_and_listed(db, actor, now, deploy_world):
    mismatched = extra_binding(
        db, deploy_world, now, vhost_name="mismatch.example.internal", match_state="key_mismatch"
    )
    missing = extra_binding(db, deploy_world, now, vhost_name="missing.example.internal", match_state="missing_file")
    preview = preview_deploy(db, DeployOptions(deploy_world.new_certificate.id), now)
    assert preview.blocked == {}
    assert preview.totals == {"hosts": 3, "bindings": 4, "files": 8, "groups": 2}
    assert {item.binding_id for item in preview.excluded} == {mismatched.id, missing.id}
    assert any("key_mismatch" in warning for warning in preview.warnings)
    assert any("missing_file" in warning for warning in preview.warnings)
    job, _ = preview_and_start(db, DeployOptions(deploy_world.new_certificate.id), actor, now)
    assert {row.binding_id for row in host_rows(db, job.id)} == {
        b.id for b in deploy_world.target_bindings
    }


def test_unknown_bindings_need_the_audited_override(db, actor, now, deploy_world):
    unknown = extra_binding(
        db,
        deploy_world,
        now,
        vhost_name="unknown.example.internal",
        certificate_id=None,
        match_state="unknown",
        on_disk_fingerprint=None,
        on_disk_key_public_sha256=None,
    )
    options = DeployOptions(deploy_world.new_certificate.id, binding_ids=(unknown.id,))
    preview = preview_deploy(db, options, now)
    assert preview.totals == {"hosts": 0, "bindings": 0, "files": 0, "groups": 0}
    assert [item.binding_id for item in preview.excluded] == [unknown.id]
    assert "no_targets" in preview.blocked

    override = DeployOptions(deploy_world.new_certificate.id, binding_ids=(unknown.id,), include_unknown=True)
    job, overridden = preview_and_start(db, override, actor, now)
    assert overridden.totals == {"hosts": 1, "bindings": 1, "files": 2, "groups": 1}
    assert job.payload["include_unknown"] is True
    audited = [row for row in audits(db, "job", str(job.id)) if row.action == "deploy.include_unknown"]
    assert len(audited) == 1 and audited[0].details == {"binding_ids": [unknown.id]}


def test_explicit_selection_and_group_filter(db, now, deploy_world):
    world = deploy_world
    one = preview_deploy(db, DeployOptions(world.new_certificate.id, binding_ids=(world.target_bindings[0].id,)), now)
    assert one.totals == {"hosts": 1, "bindings": 1, "files": 2, "groups": 1}

    ring = preview_deploy(db, DeployOptions(world.new_certificate.id, groups=("ring_a",)), now)
    assert [host.hostname for host in ring.hosts] == ["web02.example.internal", "web03.example.internal"]
    assert ring.totals == {"hosts": 2, "bindings": 2, "files": 5, "groups": 1}

    single = preview_deploy(db, DeployOptions(world.new_certificate.id, hostnames=("web03.example.internal",)), now)
    assert single.totals == {"hosts": 1, "bindings": 1, "files": 3, "groups": 1}

    both = preview_deploy(
        db,
        DeployOptions(world.new_certificate.id, groups=("ring_a",), hostnames=("web01.example.internal",)),
        now,
    )
    assert both.totals["hosts"] == 0 and "no_targets" in both.blocked

    picked = preview_deploy(
        db,
        DeployOptions(world.new_certificate.id, canary_server_id=world.servers["web03.example.internal"].id),
        now,
    )
    assert [host.hostname for host in picked.hosts if host.batch_no == 0] == ["web03.example.internal"]
    assert picked.batches == (1, 1, 1)


def test_already_deployed_everywhere_is_refused(db, actor, now, deploy_world):
    for binding in deploy_world.target_bindings:
        binding.on_disk_fingerprint = deploy_world.new_certificate.sha256_fingerprint
    db.flush()
    options = DeployOptions(deploy_world.new_certificate.id)
    preview = preview_deploy(db, options, now)
    assert "already_deployed" in preview.blocked
    error = refused(
        start_deploy,
        db=db,
        options=options,
        plan_sha256=preview.plan_sha256,
        confirmed=True,
        override_reason=None,
        actor=actor,
        now=now,
    )
    assert "already_deployed" in error.reasons and job_count(db) == 0


def test_one_active_deploy_at_a_time(db, actor, now, deploy_world):
    job, _ = preview_and_start(db, DeployOptions(deploy_world.new_certificate.id), actor, now)
    options = DeployOptions(deploy_world.new_certificate.id)
    for status in (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.PAUSED):
        job.status = status
        db.flush()
        preview = preview_deploy(db, options, now)
        assert "active_deploy" in preview.blocked
        error = refused(
            start_deploy,
            db=db,
            options=options,
            plan_sha256=preview.plan_sha256,
            confirmed=True,
            override_reason=None,
            actor=actor,
            now=now,
        )
        assert "active_deploy" in error.reasons
        assert error.active_job_id == job.id
    assert job_count(db) == 1


def test_two_concurrent_starts_create_one_job(queue_factory, deploy_world_factory, now):
    with queue_factory.begin() as db:
        user = User(username="concurrent-operator", email="concurrent@example.test")
        db.add(user)
        db.flush()
        actor = Actor(user.id, user.username)
        world = deploy_world_factory(db, actor)
        options = DeployOptions(world.new_certificate.id)
        plan_sha256 = preview_deploy(db, options, now).plan_sha256
        certificate_id = world.new_certificate.id

    barrier = threading.Barrier(2)
    created, blocked = [], []

    def attempt():
        barrier.wait(10)
        try:
            with queue_factory.begin() as db:
                job = start_deploy(
                    db,
                    DeployOptions(certificate_id),
                    plan_sha256=plan_sha256,
                    confirmed=True,
                    override_reason=None,
                    actor=Actor(user.id, user.username),
                    now=now,
                )
                created.append(job.id)
        except DeployBlocked as exc:
            blocked.append(exc)

    threads = [threading.Thread(target=attempt, daemon=True) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert len(created) == 1 and len(blocked) == 1
    assert "active_deploy" in blocked[0].reasons
    assert blocked[0].active_job_id == created[0]
    with queue_factory() as db:
        assert db.scalar(select(func.count()).select_from(Job).where(Job.type == JobType.DEPLOY)) == 1
        assert db.scalar(select(func.count()).select_from(JobHost)) == 4


def test_changed_plan_is_refused(db, actor, now, deploy_world):
    options = DeployOptions(deploy_world.new_certificate.id)
    preview = preview_deploy(db, options, now)
    stale = refused(
        start_deploy,
        db=db,
        options=options,
        plan_sha256="0" * 64,
        confirmed=True,
        override_reason=None,
        actor=actor,
        now=now,
    )
    assert set(stale.reasons) == {"plan_changed"}
    unconfirmed = refused(
        start_deploy,
        db=db,
        options=options,
        plan_sha256=preview.plan_sha256,
        confirmed=False,
        override_reason=None,
        actor=actor,
        now=now,
    )
    assert set(unconfirmed.reasons) == {"confirm"}
    extra_binding(db, deploy_world, now, vhost_name="appeared.example.internal")
    changed = refused(
        start_deploy,
        db=db,
        options=options,
        plan_sha256=preview.plan_sha256,
        confirmed=True,
        override_reason=None,
        actor=actor,
        now=now,
    )
    assert set(changed.reasons) == {"plan_changed"}
    assert job_count(db) == 0


def test_preview_warnings(db, now, deploy_world):
    world = deploy_world
    world.servers["web02.example.internal"].last_discovery_at = now - timedelta(hours=25)
    redeployed = world.target_bindings[3]
    redeployed.certificate_id = world.new_certificate.id
    redeployed.on_disk_fingerprint = world.new_certificate.sha256_fingerprint
    db.flush()
    preview = preview_deploy(db, DeployOptions(world.new_certificate.id), now)
    assert preview.blocked == {}
    assert any("not the one being replaced" in warning for warning in preview.warnings)
    assert any("web02.example.internal" in warning and "24 hours" in warning for warning in preview.warnings)
    assert any("expires before" in warning for warning in preview.warnings)
    host = next(item for item in preview.hosts if item.hostname == "web02.example.internal")
    assert any("24 hours" in warning for warning in host.warnings)


def test_not_before_sets_run_after_within_seven_days(db, actor, now, deploy_world):
    later = now + timedelta(hours=2)
    far = preview_deploy(
        db, DeployOptions(deploy_world.new_certificate.id, not_before=now + timedelta(days=8)), now
    )
    assert "not_before" in far.blocked
    options = DeployOptions(deploy_world.new_certificate.id, not_before=later)
    job, preview = preview_and_start(db, options, actor, now)
    assert preview.blocked == {}
    assert job.run_after == later
    assert job.status == JobStatus.QUEUED


def test_assess_certificate_persists_a_changed_status_once(db, now, deploy_world):
    certificate = deploy_world.old
    certificate.chain_status = ChainStatus.UNCHECKED
    db.flush()
    first = assess_certificate(db, certificate.id, now)
    assert first.status is ChainStatus.TRUSTED
    checks = [row for row in audits(db, "certificate", str(certificate.id)) if row.action == "certificate.chain_check"]
    assert len(checks) == 1
    assert assess_certificate(db, certificate.id, now).status is ChainStatus.TRUSTED
    assert len([r for r in audits(db, "certificate", str(certificate.id)) if r.action == "certificate.chain_check"]) == 1
