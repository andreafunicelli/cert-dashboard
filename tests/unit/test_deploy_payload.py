"""``deploy/default`` payload validation (Plan 3 Task 16, Contract decision 15).

The payload is written by ``start_deploy`` and read back by the worker on every claim. It is the only
thing the handler trusts about the plan, so the validator is deliberately narrow: exactly the Contract
decision 15 keys, the documented value ranges, and nothing else — no ``action``, no ``reason``.
"""

import pytest

from app.jobs.handlers.deploy import validate_deploy_payload

PLAN_SHA = "0123456789abcdef" * 4
RENEWAL_ID = "6f1c1f64-1c2b-4b31-9d6a-9a1f1b2c3d4e"
RETRY_OF = "1f0f6e3a-5f4b-4c1d-9a4e-2b7c1d5e8a90"
_MISSING = object()


def payload(**overrides):
    """The canonical Contract decision 15 payload, with ``overrides`` applied (a key set to ``_MISSING`` is dropped)."""
    base = {
        "certificate_id": 7,
        "renewal_id": RENEWAL_ID,
        "batch_percent": 50,
        "pause_after_canary": False,
        "include_unknown": False,
        "chain_override": False,
        "chain_status_at_plan": "trusted",
        "plan_sha256": PLAN_SHA,
    }
    base.update(overrides)
    return {key: value for key, value in base.items() if value is not _MISSING}


def test_payload_accepts_exactly_the_contract_keys():
    clean = payload()
    assert validate_deploy_payload(clean) == clean


def test_retry_of_is_optional_and_a_uuid_string():
    clean = validate_deploy_payload(payload(retry_of=RETRY_OF))
    assert clean["retry_of"] == RETRY_OF
    assert "retry_of" not in validate_deploy_payload(payload())


def test_renewal_id_may_be_null():
    assert validate_deploy_payload(payload(renewal_id=None))["renewal_id"] is None


@pytest.mark.parametrize(
    "key", ["certificate_id", "renewal_id", "batch_percent", "pause_after_canary", "include_unknown",
            "chain_override", "chain_status_at_plan", "plan_sha256"]
)
def test_every_contract_key_is_required(key):
    with pytest.raises(ValueError):
        validate_deploy_payload(payload(**{key: _MISSING}))


@pytest.mark.parametrize("other", ["reason", "action", "hosts", "canary", "retry"])
def test_other_keys_are_rejected(other):
    with pytest.raises(ValueError):
        validate_deploy_payload(payload(**{other: "x"}))


@pytest.mark.parametrize("value", [0, 101, -1, True, "50", 50.0, None])
def test_batch_percent_must_be_an_integer_between_one_and_hundred(value):
    with pytest.raises(ValueError):
        validate_deploy_payload(payload(batch_percent=value))


@pytest.mark.parametrize("value", [1, 100])
def test_batch_percent_bounds_are_inclusive(value):
    assert validate_deploy_payload(payload(batch_percent=value))["batch_percent"] == value


@pytest.mark.parametrize("value", ["trusted", "incomplete", "untrusted_root", "unchecked"])
def test_chain_status_at_plan_must_be_in_the_enum(value):
    assert validate_deploy_payload(payload(chain_status_at_plan=value))["chain_status_at_plan"] == value


@pytest.mark.parametrize("value", ["bogus", "", None, 1, True])
def test_chain_status_outside_the_enum_is_rejected(value):
    with pytest.raises(ValueError):
        validate_deploy_payload(payload(chain_status_at_plan=value))


@pytest.mark.parametrize("value", ["nope", "", 7, None, "1f0f6e3a-5f4b-4c1d-9a4e"])
def test_retry_of_must_be_a_uuid_string(value):
    with pytest.raises(ValueError):
        validate_deploy_payload(payload(retry_of=value))


@pytest.mark.parametrize("value", ["nope", 7, "", "6F1C1F64-1C2B-4B31-9D6A-9A1F1B2C3D4E"])
def test_renewal_id_must_be_a_uuid_string_or_null(value):
    with pytest.raises(ValueError):
        validate_deploy_payload(payload(renewal_id=value))


@pytest.mark.parametrize("value", [0, -3, True, "7", None])
def test_certificate_id_must_be_a_positive_integer(value):
    with pytest.raises(ValueError):
        validate_deploy_payload(payload(certificate_id=value))


@pytest.mark.parametrize("key", ["pause_after_canary", "include_unknown", "chain_override"])
@pytest.mark.parametrize("value", [0, 1, "false", None])
def test_flags_must_be_booleans(key, value):
    with pytest.raises(ValueError):
        validate_deploy_payload(payload(**{key: value}))


@pytest.mark.parametrize("value", ["", "a" * 63, "A" * 64, "g" * 64, None, 7])
def test_plan_sha256_must_be_lowercase_hex(value):
    with pytest.raises(ValueError):
        validate_deploy_payload(payload(plan_sha256=value))


def test_a_non_mapping_payload_is_rejected():
    with pytest.raises(ValueError):
        validate_deploy_payload(["certificate_id"])  # type: ignore[arg-type]


def test_stopped_reason_comes_from_the_failed_host_run():
    """The rollout's failure class is derived from the *host run*, not from a ``HostOutcome`` directly."""
    from app.jobs.handlers.deploy import _HostRun, _stopped_reason

    assert _stopped_reason(_HostRun("web02.example.internal", "failed", "drift_detected")) == "drift_detected"
    assert _stopped_reason(_HostRun("web02.example.internal", "rolled_back", "config_test_failed")) == (
        "config_test_failed"
    )
    for unreadable in (RuntimeError("boom"), None, _HostRun("web02.example.internal", None, None)):
        assert _stopped_reason(unreadable) == "internal"
