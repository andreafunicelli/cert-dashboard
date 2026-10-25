"""Task 16: pull-import payload contract (shared by the web form and the registry validator)."""

import pytest

from app.jobs.handlers import build_registry
from app.jobs.worker import SCHEDULES
from app.models.enums import JobType
from app.services.scans import PullPayloadError, validate_pull_payload

METADATA = {"owner_name": None, "owner_email": None, "team": None, "notes": None}


def payload(**overrides):
    base = {"action": "import_pull", "host": "www.example.internal", "port": 443, "sni": None}
    return base | overrides


def test_valid_payload_is_normalized_with_complete_metadata():
    clean = validate_pull_payload(payload())
    assert clean == {
        "action": "import_pull",
        "host": "www.example.internal",
        "port": 443,
        "sni": None,
        "metadata": METADATA,
    }


def test_dns_host_and_sni_are_idna_canonicalized():
    clean = validate_pull_payload(payload(host="Bücher.Example", sni="WWW.Bücher.Example"))
    assert clean["host"] == "xn--bcher-kva.example"
    assert clean["sni"] == "www.xn--bcher-kva.example"


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [("192.0.2.10", "192.0.2.10"), ("[2001:db8::10]", "2001:db8::10"), ("2001:DB8::10", "2001:db8::10")],
)
def test_ip_literals_are_accepted_and_brackets_stripped(raw, canonical):
    assert validate_pull_payload(payload(host=raw))["host"] == canonical


def test_single_label_internal_names_are_allowed():
    assert validate_pull_payload(payload(host="vault01"))["host"] == "vault01"


def test_metadata_is_validated_like_inventory_metadata():
    clean = validate_pull_payload(payload(metadata={"owner_name": " Ada ", "notes": "edge"}))
    assert clean["metadata"] == {"owner_name": "Ada", "owner_email": None, "team": None, "notes": "edge"}
    with pytest.raises(PullPayloadError) as caught:
        validate_pull_payload(payload(metadata={"owner_email": "not-an-email"}))
    assert "metadata" in caught.value.errors


@pytest.mark.parametrize(
    "host",
    [
        "https://example.internal",
        "example.internal/path",
        "example.internal:443",
        "user@example.internal",
        "10.0.0.0/24",
        "exa mple.internal",
        " example.internal",
        "example.internal\n",
        "*.example.internal",
        "example.internal.",
        "[example.internal]",
        "[2001:db8::1]:443",
        "[192.0.2.1]",
        "fe80::1%eth0",
        "127.1",
        "0x7f.1",
        "300.1.1.1",
        "",
        "-bad.example",
        "a" * 64 + ".example",
        "x?y.example",
        "x#y.example",
        "x\\y.example",
    ],
)
def test_invalid_hosts_are_rejected(host):
    with pytest.raises(PullPayloadError) as caught:
        validate_pull_payload(payload(host=host))
    assert "host" in caught.value.errors


@pytest.mark.parametrize("port", [0, -1, 65536, "443", 443.0, True, None])
def test_invalid_ports_are_rejected(port):
    with pytest.raises(PullPayloadError) as caught:
        validate_pull_payload(payload(port=port))
    assert "port" in caught.value.errors


@pytest.mark.parametrize("port", [1, 443, 65535])
def test_port_bounds_are_inclusive(port):
    assert validate_pull_payload(payload(port=port))["port"] == port


@pytest.mark.parametrize("sni", ["192.0.2.1", "2001:db8::1", "*.example.internal", "a b.example", "x/y", ""])
def test_invalid_sni_is_rejected(sni):
    with pytest.raises(PullPayloadError) as caught:
        validate_pull_payload(payload(sni=sni))
    assert "sni" in caught.value.errors


@pytest.mark.parametrize(
    "extra", [{"unknown": 1}, {"password": "x"}, {"metadata": {"owner_name": "a", "extra": "b"}}]
)
def test_unknown_keys_are_rejected(extra):
    with pytest.raises(PullPayloadError):
        validate_pull_payload(payload(**extra))


@pytest.mark.parametrize("bad", [{}, {"action": "default"}, {"host": "h.example"}])
def test_wrong_or_incomplete_payloads_are_rejected(bad):
    with pytest.raises(ValueError):
        validate_pull_payload(bad)


def test_payload_error_is_a_value_error_for_the_registry():
    assert issubclass(PullPayloadError, ValueError)


def test_registry_registers_only_the_pull_action_of_scan():
    registry = build_registry()
    assert registry.supports(JobType.SCAN, "import_pull")
    assert not registry.supports(JobType.SCAN)  # scan/default belongs to Plan 2
    assert not any(schedule.job_type is JobType.SCAN for schedule in SCHEDULES.values())
