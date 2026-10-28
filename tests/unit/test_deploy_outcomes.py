"""Host outcome mapping for deploys (Plan 3 Task 14; Contract decision 18, spec 9.6).

``parse_host_result`` is a pure function over a recorded ``RunOutcome``: the playbook publishes a per-host
document through ``set_stats`` and this module turns "how the run ended" plus "what the host published"
into the ``job_host`` status, the ``<reason>: <fixed text>`` error message and the rollback flags. The
success rule is the strict one of Contract decision 18: only ``step == "verified"`` evidence carrying the
new fingerprint for *every* target binding is a success, so a playbook that stops before verification (this
task's) can never be recorded as one.
"""

import shutil
from uuid import UUID

import pytest

from app.ansible.deploy import (
    INTERNAL_TEXT,
    REASON_TEXT,
    TIMEOUT_ROLLBACK_ERROR,
    WRITE_STEPS,
    parse_host_result,
    run_host_deploy,
    stage_material,
)
from app.ansible.runner import HostResult, RunOutcome
from app.services.deploy import DeployTarget

HOST = "web01.example.internal"
OLD = "a" * 64
NEW = "b" * 64
JOB_ID = UUID("5d0c6f0e-6f0a-4a0e-9d58-3c1f0b7a2e11")


def target(
    binding_id=1,
    *,
    new=NEW,
    sni="www.example.internal",
    port=18443,
    chain_path=None,
    cert_path="/etc/nginx/ssl/www.crt",
    key_path="/etc/nginx/ssl/www.key",
) -> DeployTarget:
    return DeployTarget(
        binding_id=binding_id,
        cert_path=cert_path,
        chain_path=chain_path,
        key_path=key_path,
        expected_fingerprint=OLD,
        new_fingerprint=new,
        port=port,
        sni=sni,
    )


def recorded(
    data=None, *, status="failed", host_outcome="ok", rc=2, excerpt="", hostname=HOST
) -> RunOutcome:
    """A ``RunOutcome`` exactly as ``run_playbook`` would hand it back for one host."""
    hosts = {hostname: HostResult(hostname, host_outcome, None, data or {}, excerpt)}
    return RunOutcome(status, rc, hosts, excerpt)


def test_a_preflight_refusal_is_a_clean_failure():
    outcome = parse_host_result(HOST, recorded({"step": "preflight", "reason": "drift_detected"}), [target()])

    assert (outcome.status, outcome.reason, outcome.rolled_back) == ("failed", "drift_detected", False)
    assert outcome.message == f"drift_detected: {REASON_TEXT['drift_detected']}"
    assert outcome.rollback_error is None
    assert outcome.precheck["step"] == "preflight"
    assert outcome.backup_dir is None


def test_every_preflight_and_backup_reason_is_reported_verbatim():
    for reason in (
        "drift_detected",
        "missing_target",
        "permission_denied",
        "insufficient_space",
        "baseline_config_invalid",
        "key_mismatch_preflight",
        "backup_failed",
    ):
        # A key mismatch is only evidence when both DER pipelines actually ran and produced hex (D2).
        published = {"step": "preflight", "reason": reason, "hash_rc": [0, 0]}
        outcome = parse_host_result(HOST, recorded(published), [target()])
        assert (outcome.status, outcome.reason) == ("failed", reason)
        assert outcome.message == f"{reason}: {REASON_TEXT[reason]}"
        assert outcome.rolled_back is False and outcome.rollback_error is None


def test_a_key_mismatch_needs_both_pipelines_to_have_succeeded():
    published = {
        "step": "preflight",
        "reason": "key_mismatch_preflight",
        "hash_rc": [0, 0],
        "hash_stderr": "",
    }
    outcome = parse_host_result(HOST, recorded(published), [target()])

    assert (outcome.status, outcome.reason) == ("failed", "key_mismatch_preflight")
    assert outcome.message == f"key_mismatch_preflight: {REASON_TEXT['key_mismatch_preflight']}"


def test_a_failed_hash_pipeline_is_internal_and_carries_its_diagnostics():
    # rc 127 is "command not found": the pipelines never compared two hashes, so this must never be
    # reported as a key mismatch. The message keeps the exit codes and the public-side stderr so the
    # operator does not need a second run to read the cause.
    published = {
        "step": "preflight",
        "reason": "key_mismatch_preflight",
        "hash_rc": [127, 127],
        "hash_stderr": "openssl: command not found",
    }
    outcome = parse_host_result(HOST, recorded(published), [target()])

    assert (outcome.status, outcome.reason) == ("failed", "internal")
    message = outcome.message or ""
    assert "hash_rc=[127, 127]" in message
    assert "openssl: command not found" in message
    assert outcome.precheck["reason"] == "key_mismatch_preflight"  # kept as evidence


def test_a_module_that_never_ran_is_internal_with_its_module_diagnostics():
    # rc 127 with no command stderr means the module itself never executed (interpreter discovery): the
    # result then carries msg/module_stderr instead of stderr. Still an environment failure, not a mismatch.
    published = {
        "step": "preflight",
        "reason": "key_mismatch_preflight",
        "hash_rc": [127, 127],
        "hash_stderr": "",
        "hash_msg": "MODULE FAILURE",
        "hash_module_stderr": "/usr/bin/python3: not found",
    }
    outcome = parse_host_result(HOST, recorded(published), [target()])

    assert (outcome.status, outcome.reason) == ("failed", "internal")
    message = outcome.message or ""
    assert "hash_rc=[127, 127]" in message
    assert "MODULE FAILURE" in message and "/usr/bin/python3: not found" in message



def test_every_write_step_reason_is_reported_verbatim_when_the_rollback_did_not_run():
    # A failure published *before* the rescue could roll back (or with rollback disabled) is still a
    # plain failure: `rolled_back` is never inferred from the step alone.
    for reason in ("write_failed", "config_test_failed", "reload_failed", "verify_failed"):
        published = {"step": WRITE_STEPS[-1], "reason": reason}
        outcome = parse_host_result(HOST, recorded(published), [target()])
        assert (outcome.status, outcome.reason, outcome.rolled_back) == ("failed", reason, False)


def test_a_backed_up_host_that_ends_without_an_error_is_internal():
    outcome = parse_host_result(
        HOST, recorded({"step": "backed_up", "backup_dir": "/var/backups/cert-dashboard/j"}), [target()]
    )

    assert (outcome.status, outcome.reason) == ("failed", "internal")
    assert outcome.message == f"internal: {INTERNAL_TEXT}"
    assert outcome.precheck["step"] == "backed_up"
    assert outcome.precheck["backup_dir"] == outcome.backup_dir == "/var/backups/cert-dashboard/j"


def test_a_run_without_a_published_result_is_internal():
    outcome = parse_host_result(HOST, recorded({}), [target()])
    assert (outcome.status, outcome.reason, outcome.message) == ("failed", "internal", f"internal: {INTERNAL_TEXT}")


def test_a_host_missing_from_the_run_is_internal():
    outcome = parse_host_result(HOST, RunOutcome("failed", 2, {}, ""), [target()])
    assert (outcome.status, outcome.reason) == ("failed", "internal")


def test_a_runner_timeout_is_a_host_timeout_that_may_have_written_files():
    outcome = parse_host_result(HOST, RunOutcome("timeout", None, {}, "killed"), [target()])

    assert (outcome.status, outcome.reason) == ("failed", "host_timeout")
    assert outcome.rollback_error == TIMEOUT_ROLLBACK_ERROR == "run timed out; files may be partially written"
    assert outcome.rolled_back is False
    assert outcome.return_code is None
    assert outcome.message == f"host_timeout: {REASON_TEXT['host_timeout']}"


def test_an_unreachable_host_and_an_authentication_failure_keep_their_own_reasons():
    unreachable = parse_host_result(HOST, recorded({}, host_outcome="unreachable"), [target()])
    denied = parse_host_result(HOST, recorded({}, host_outcome="auth"), [target()])

    assert (unreachable.status, unreachable.reason) == ("failed", "unreachable")
    assert (denied.status, denied.reason) == ("failed", "auth")


def test_a_successful_rollback_is_rolled_back_with_the_original_reason():
    published = {
        "step": "rolled_back",
        "reason": "reload_failed",
        "rolled_back": True,
        "backup_dir": "/var/backups/cert-dashboard/j",
    }
    outcome = parse_host_result(HOST, recorded(published), [target()])

    assert (outcome.status, outcome.reason, outcome.rolled_back) == ("rolled_back", "reload_failed", True)
    assert outcome.message == f"reload_failed: {REASON_TEXT['reload_failed']}"
    assert outcome.rollback_error is None


def test_a_successful_rollback_is_recognised_from_the_write_steps_and_the_flag():
    # Task 15's playbook publishes the original failure first and then the rollback outcome; both shapes
    # (a still-WRITE_STEPS step with rolled_back set, and the final `rolled_back` step) must map the same.
    for step in (*WRITE_STEPS, "rolled_back"):
        published = {"step": step, "reason": "config_test_failed", "rolled_back": True}
        outcome = parse_host_result(HOST, recorded(published), [target()])
        assert (outcome.status, outcome.reason, outcome.rolled_back) == (
            "rolled_back",
            "config_test_failed",
            True,
        )


def test_a_failed_rollback_is_a_failure_carrying_the_rollback_error():
    published = {
        "step": "rollback_failed",
        "reason": "config_test_failed",
        "rolled_back": False,
        "rollback_error": "reload failed after restore",
    }
    outcome = parse_host_result(HOST, recorded(published), [target()])

    assert (outcome.status, outcome.reason, outcome.rolled_back) == ("failed", "config_test_failed", False)
    assert outcome.rollback_error == "reload failed after restore"
    assert outcome.precheck["step"] == "rollback_failed"


def test_a_rollback_error_wins_over_a_rolled_back_flag():
    published = {"step": "rolled_back", "reason": "verify_failed", "rolled_back": True, "rollback_error": "restore failed"}
    outcome = parse_host_result(HOST, recorded(published), [target()])
    assert (outcome.status, outcome.rolled_back, outcome.rollback_error) == ("failed", False, "restore failed")


def test_an_unknown_reason_never_leaks_into_the_outcome():
    outcome = parse_host_result(HOST, recorded({"step": "preflight", "reason": "certa_problem"}), [target()])
    assert (outcome.status, outcome.reason) == ("failed", "internal")
    assert outcome.precheck["reason"] == "certa_problem"  # kept as evidence, but the stored reason is ours


@pytest.mark.parametrize("reason", sorted(REASON_TEXT))
def test_every_reason_of_the_contract_round_trips_as_reason_colon_fixed_text(reason):
    # Contract decision 18 fixes the vocabulary and the "<reason>: <fixed text>" shape of error_message.
    published = {"step": "preflight", "reason": reason, "hash_rc": [0, 0]}
    outcome = parse_host_result(HOST, recorded(published), [target()])
    assert (outcome.status, outcome.reason) == ("failed", reason)
    assert outcome.message == f"{reason}: {REASON_TEXT[reason]}"
    assert outcome.message.split(": ", 1)[1] == REASON_TEXT[reason]


# --- verified evidence and the success rule ------------------------------------------------------


def verified(binding_id: int, fingerprint: str = NEW) -> dict:
    return {"written": True, "verified": {"fingerprint": fingerprint, "matches": True, "attempts": 1}}


def test_a_host_that_verified_every_binding_succeeded():
    published = {
        "step": "verified",
        "targets": {"1": verified(1), "2": verified(2)},
        "verify": {"attempts": 1, "chain_length": 2},
        "backup_dir": "/var/backups/cert-dashboard/j",
    }
    outcome = parse_host_result(HOST, recorded(published, status="successful", rc=0), [target(1), target(2)])

    assert (outcome.status, outcome.reason, outcome.message, outcome.rolled_back) == ("succeeded", None, None, False)
    assert outcome.verify == {"attempts": 1, "chain_length": 2}
    assert outcome.precheck["step"] == "verified"
    assert outcome.targets[1]["verified"]["fingerprint"] == NEW
    assert outcome.backup_dir == "/var/backups/cert-dashboard/j"


def test_verified_evidence_for_only_one_of_two_bindings_is_internal():
    published = {"step": "verified", "targets": {"1": verified(1)}}
    outcome = parse_host_result(HOST, recorded(published, status="successful", rc=0), [target(1), target(2)])
    assert (outcome.status, outcome.reason) == ("failed", "internal")
    assert outcome.message == f"internal: {INTERNAL_TEXT}"


def test_verified_evidence_carrying_another_fingerprint_is_internal():
    published = {"step": "verified", "targets": {"1": verified(1, OLD), "2": verified(2, OLD)}}
    outcome = parse_host_result(HOST, recorded(published, status="successful", rc=0), [target(1), target(2)])
    assert (outcome.status, outcome.reason) == ("failed", "internal")


def test_the_verified_step_without_per_binding_evidence_is_internal():
    outcome = parse_host_result(HOST, recorded({"step": "verified"}, status="successful", rc=0), [target()])
    assert (outcome.status, outcome.reason) == ("failed", "internal")


def test_an_explicit_negative_verification_is_never_a_success():
    """``matches: false`` is an explicit statement that the host did *not* serve the new leaf.

    A fingerprint next to it proves nothing about the service, so the run is an ``internal`` failure rather
    than a success (Contract decision 18: success needs affirmative verification).
    """
    published = {
        "step": "verified",
        "targets": {
            "1": {**verified(1), "verified": {"fingerprint": NEW, "matches": False, "attempts": 3}},
            "2": {**verified(2), "verified": {"fingerprint": NEW, "matches": False, "attempts": 3}},
        },
    }
    outcome = parse_host_result(HOST, recorded(published, status="successful", rc=0), [target(1), target(2)])
    assert (outcome.status, outcome.reason) == ("failed", "internal")
    assert outcome.message == f"internal: {INTERNAL_TEXT}"


def test_one_binding_with_a_negative_verification_fails_the_whole_host():
    published = {
        "step": "verified",
        "targets": {
            "1": verified(1),
            "2": {**verified(2), "verified": {"fingerprint": NEW, "matches": False, "attempts": 1}},
        },
    }
    outcome = parse_host_result(HOST, recorded(published, status="successful", rc=0), [target(1), target(2)])
    assert (outcome.status, outcome.reason) == ("failed", "internal")


def test_a_verification_record_that_does_not_affirm_a_match_is_internal():
    # No ``matches`` field, or a non-boolean one, is not affirmative evidence: only ``true`` counts.
    for record in (
        {"fingerprint": NEW, "attempts": 1},
        {"fingerprint": NEW, "matches": "true", "attempts": 1},
        {"fingerprint": NEW, "matches": 1, "attempts": 1},
        {"fingerprint": NEW, "matches": None, "attempts": 1},
    ):
        published = {"step": "verified", "targets": {"1": {"written": True, "verified": record}}}
        outcome = parse_host_result(HOST, recorded(published, status="successful", rc=0), [target()])
        assert (outcome.status, outcome.reason) == ("failed", "internal"), record


def test_a_run_without_any_planned_target_cannot_succeed():
    published = {"step": "verified", "targets": {"1": verified(1)}}
    outcome = parse_host_result(HOST, recorded(published, status="successful", rc=0), [])
    assert (outcome.status, outcome.reason) == ("failed", "internal")


def test_every_target_binding_appears_in_the_outcome_even_when_the_host_reported_nothing():
    outcome = parse_host_result(HOST, recorded({"step": "preflight", "reason": "drift_detected"}), [target(1), target(7)])
    assert sorted(outcome.targets) == [1, 7]
    assert outcome.targets[7] == {}


def test_the_return_code_and_the_excerpt_are_carried_over():
    outcome = parse_host_result(
        HOST, recorded({}, rc=9, excerpt="fatal: boom"), [target()]
    )
    assert outcome.return_code == 9
    assert "fatal: boom" in outcome.log_excerpt


# --- material staging ---------------------------------------------------------------------------


def material_certificate(cert_pem: bytes, chain_pem: bytes):
    from types import SimpleNamespace

    return SimpleNamespace(pem=cert_pem.decode(), chain_pem=chain_pem.decode())


def new_material():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return key, key_pem


def test_stage_material_writes_the_public_pems_to_the_artifact_dir(tmp_path):
    from app.ansible.staging import StagingArea

    key, _ = new_material()
    cert_pem, chain_pem = b"CERT\n", b"CHAIN\n"
    with StagingArea(tmp_path / "keys", UUID(int=1)) as staging:
        staged = stage_material(material_certificate(cert_pem, chain_pem), key, tmp_path / "artifacts", staging)

        assert staged.cert_pem.read_bytes() == cert_pem
        assert staged.chain_pem.read_bytes() == chain_pem
        assert staged.fullchain_pem.read_bytes() == cert_pem + chain_pem
        assert {path.name for path in (tmp_path / "artifacts" / "files").iterdir()} == {
            "chain.pem",
            "cert.pem",
            "fullchain.pem",
        }
        assert staged.key_pem.parent == staging.path


def test_stage_material_writes_the_key_only_as_a_0600_pkcs8_file_in_the_staging_area(tmp_path):
    from cryptography.hazmat.primitives import serialization

    from app.ansible.staging import StagingArea
    from app.crypto.keys import public_key_sha256

    key, key_pem = new_material()
    with StagingArea(tmp_path / "keys", UUID(int=2)) as staging:
        staged = stage_material(material_certificate(b"CERT\n", b"CHAIN\n"), key, tmp_path / "artifacts", staging)

        assert staged.key_pem.read_bytes() == key_pem
        assert staged.key_pem.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
        assert staged.key_pem.stat().st_mode & 0o777 == 0o600
        assert staging.path in staged.key_pem.parents
        loaded = serialization.load_pem_private_key(staged.key_pem.read_bytes(), password=None)
        assert public_key_sha256(loaded.public_key()) == public_key_sha256(key.public_key())
        # the public artifact directory never holds key material
        for path in (tmp_path / "artifacts").rglob("*"):
            if path.is_file():
                assert b"PRIVATE KEY" not in path.read_bytes()


# --- the playbook invocation --------------------------------------------------------------------


def fake_material(tmp_path):
    from app.ansible.staging import StagingArea

    key, _ = new_material()
    staging = StagingArea(tmp_path / "keys", UUID(int=3))
    staging.__enter__()
    staged = stage_material(material_certificate(b"CERT\n", b"CHAIN\n"), key, tmp_path / "artifacts", staging)
    return staging, staged


def runner_context(tmp_path):
    from app.ansible.runner import RunnerContext, RunnerSecrets

    return RunnerContext(
        secrets=RunnerSecrets(tmp_path / "ssh_key", tmp_path / "known_hosts"),
        inventory=tmp_path / "inventory.yml",
        run_dir=tmp_path / "run",
        artifact_dir=tmp_path / "artifacts",
    )


def test_run_host_deploy_refuses_a_file_conflict_without_running_ansible(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("app.ansible.deploy.run_playbook", lambda *a, **k: calls.append(a))
    staging, staged = fake_material(tmp_path)
    try:
        conflicting = [
            target(1),
            DeployTarget(
                binding_id=2,
                cert_path="/etc/nginx/ssl/other.crt",
                chain_path=None,
                key_path="/etc/nginx/ssl/www.crt",
                expected_fingerprint=OLD,
                new_fingerprint=NEW,
                port=18443,
                sni="legacy.example.internal",
            ),
        ]
        outcome = run_host_deploy(
            runner_context(tmp_path), HOST, "nginx", conflicting, staged, job_id=JOB_ID, retention_days=30,
            timeout_seconds=600,
        )  # fmt: skip
    finally:
        staging.__exit__(None, None, None)

    assert (outcome.status, outcome.reason) == ("failed", "file_conflict")
    assert outcome.rolled_back is False and outcome.rollback_error is None
    assert calls == []
    assert not (tmp_path / "run").exists()


def test_run_host_deploy_passes_paths_and_json_targets_only(tmp_path, monkeypatch):
    from app.ansible.runner import RunOutcome

    seen = []

    def fake(context, run, *, ident):
        seen.append((context, run, ident))
        return RunOutcome("successful", 0, {HOST: HostResult(HOST, "ok", None, {"step": "backed_up"}, "")}, "")

    monkeypatch.setattr("app.ansible.deploy.run_playbook", fake)
    staging, staged = fake_material(tmp_path)
    try:
        written = len(staged.fullchain_pem.read_bytes()) + 2 * len(staged.key_pem.read_bytes())
        outcome = run_host_deploy(
            runner_context(tmp_path), HOST, "nginx",
            [target(1), target(2, sni="legacy.example.internal", key_path="/etc/nginx/ssl/legacy.key")],
            staged, job_id=JOB_ID, retention_days=30, timeout_seconds=600,
        )  # fmt: skip
    finally:
        staging.__exit__(None, None, None)

    assert outcome.reason == "internal" and outcome.precheck["step"] == "backed_up"
    [(context, run, ident)] = seen
    assert ident == HOST and run.limit == HOST
    assert run.playbook.endswith("app/ansible/playbooks/deploy.yml")
    assert run.timeout_seconds == 600
    extra = run.extravars
    assert extra["job_id"] == str(JOB_ID)
    assert extra["backup_root"] == "/var/backups/cert-dashboard"
    assert extra["backup_retention_days"] == 30
    assert extra["webservers"] == {HOST: "nginx"}
    assert extra["cert_pem_path"] == str(staged.cert_pem)
    assert extra["chain_pem_path"] == str(staged.chain_pem)
    assert extra["fullchain_pem_path"] == str(staged.fullchain_pem)
    assert extra["key_pem_path"] == str(staged.key_pem)
    assert set(extra) == {
        "backup_retention_days",
        "backup_root",
        "cert_pem_path",
        "chain_pem_path",
        "files",
        "fullchain_pem_path",
        "job_id",
        "key_pem_path",
        "openssl_bin",
        "sha256sum_bin",
        "space_required_bytes",
        "targets",
        "webservers",
    }
    files = {entry["path"]: entry for entry in extra["files"]}
    assert {path: entry["kind"] for path, entry in files.items()} == {
        "/etc/nginx/ssl/legacy.key": "key",
        "/etc/nginx/ssl/www.crt": "fullchain",
        "/etc/nginx/ssl/www.key": "key",
    }
    assert {entry["source"] for entry in extra["files"]} == {"fullchain_pem_path", "key_pem_path"}
    assert [entry["binding_id"] for entry in extra["targets"]] == [1, 2]
    assert extra["targets"][0] == {
        "binding_id": 1,
        "cert_path": "/etc/nginx/ssl/www.crt",
        "chain_path": None,
        "key_path": "/etc/nginx/ssl/www.key",
        "expected_fingerprint": OLD,
        "new_fingerprint": NEW,
        "port": 18443,
        "sni": "www.example.internal",
    }
    assert extra["space_required_bytes"] == 2 * written + 10 * 1024 * 1024
    # the preflight binaries are resolved on the controller, never left to an inherited PATH
    assert extra["openssl_bin"] == shutil.which("openssl")
    assert extra["sha256sum_bin"] == shutil.which("sha256sum")
    # nothing secret in the extra-vars
    assert "PRIVATE KEY" not in repr(extra)
    assert context.artifact_dir == tmp_path / "artifacts"


def test_run_host_deploy_refuses_a_target_path_outside_a_normalized_absolute_path(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("app.ansible.deploy.run_playbook", lambda *a, **k: calls.append(a))
    staging, staged = fake_material(tmp_path)
    try:
        escaping = [
            DeployTarget(
                binding_id=1,
                cert_path="/etc/nginx/ssl/../../shadow",
                chain_path=None,
                key_path="/etc/nginx/ssl/www.key",
                expected_fingerprint=OLD,
                new_fingerprint=NEW,
                port=18443,
                sni=None,
            )
        ]
        outcome = run_host_deploy(
            runner_context(tmp_path), HOST, "nginx", escaping, staged, job_id=JOB_ID, retention_days=30,
            timeout_seconds=600,
        )  # fmt: skip
    finally:
        staging.__exit__(None, None, None)
    assert (outcome.status, outcome.reason) == ("failed", "internal")
    assert outcome.message == "internal: invalid target path"
    assert calls == []


@pytest.mark.parametrize("missing", ["openssl", "sha256sum"])
def test_run_host_deploy_reports_a_missing_preflight_tool_without_running_ansible(
    tmp_path, monkeypatch, missing
):
    # An absent binary is an environment failure, never a key mismatch: the run does not start and no
    # backup directory is created (the architect's contract for the D2 preflight).
    from app.ansible import deploy as deploy_module

    calls = []
    monkeypatch.setattr("app.ansible.deploy.run_playbook", lambda *a, **k: calls.append(a))
    real = deploy_module._which
    monkeypatch.setattr(
        "app.ansible.deploy._which", lambda name: None if name == missing else real(name)
    )
    staging, staged = fake_material(tmp_path)
    try:
        outcome = run_host_deploy(
            runner_context(tmp_path), HOST, "nginx", [target()], staged, job_id=JOB_ID,
            retention_days=30, timeout_seconds=600,
        )  # fmt: skip
    finally:
        staging.__exit__(None, None, None)

    assert (outcome.status, outcome.reason) == ("failed", "internal")
    assert outcome.message == f"preflight_tool_missing: {missing}"
    assert outcome.precheck["step"] == "preflight"
    assert calls == []
    assert not (tmp_path / "run").exists()
