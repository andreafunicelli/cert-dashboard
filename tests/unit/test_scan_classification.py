"""Plan 2 Task 1: classification of what an endpoint serves (pure logic, no sockets)."""

import hashlib
import re
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from app.jobs.queue import JobFailure
from app.models.enums import ScanStatus
from app.services import scans
from app.services.scans import PulledChain, ScanObservation, classify_observation, observation_from_chain


def observed(fingerprint="a" * 64, not_after=None, failure=None):
    return ScanObservation(
        fingerprint=fingerprint,
        common_name="www.example.internal",
        issuer_cn="Fixture Intermediate",
        not_after=not_after,
        chain_length=3,
        tls_version="TLSv1.3",
        failure=failure,
        error=None,
        elapsed_ms=4,
    )


def test_classification_precedence(now):
    future, past = now + timedelta(days=30), now - timedelta(seconds=1)
    assert classify_observation(observed(not_after=future), "a" * 64, now) is ScanStatus.OK
    assert classify_observation(observed(not_after=future), "b" * 64, now) is ScanStatus.MISMATCH
    assert classify_observation(observed(not_after=future), None, now) is ScanStatus.MISMATCH
    assert classify_observation(observed(not_after=past), "a" * 64, now) is ScanStatus.EXPIRED
    assert classify_observation(observed(None, failure="unreachable"), "a" * 64, now) is ScanStatus.UNREACHABLE
    assert classify_observation(observed(failure="error"), "a" * 64, now) is ScanStatus.ERROR


def test_mixed_case_expected_fingerprint_still_matches(now):
    seen = observed(fingerprint="abcdef" + "0" * 58, not_after=now + timedelta(days=1))
    assert classify_observation(seen, ("ABCDEF" + "0" * 58), now) is ScanStatus.OK


def test_expired_wins_over_matching_fingerprint(now):
    seen = observed(not_after=now - timedelta(days=1))
    assert classify_observation(seen, "a" * 64, now) is ScanStatus.EXPIRED


def test_not_after_equal_to_now_is_not_yet_expired(now):
    assert classify_observation(observed(not_after=now), "a" * 64, now) is ScanStatus.OK


def test_missing_fingerprint_can_never_be_ok(now):
    seen = observed(fingerprint=None, not_after=now + timedelta(days=1))
    assert classify_observation(seen, None, now) is not ScanStatus.OK
    assert classify_observation(seen, "a" * 64, now) is not ScanStatus.OK


def test_observation_from_served_der(certs):
    der = certs.leaf.public_bytes(Encoding.DER)
    chain = (der, *(c.public_bytes(Encoding.DER) for c in certs.intermediates))
    seen = observation_from_chain(PulledChain(chain, "TLSv1.3"), elapsed_ms=7)
    assert seen.fingerprint == hashlib.sha256(der).hexdigest() and seen.chain_length == 3
    assert seen.not_after == certs.leaf.not_valid_after_utc and seen.failure is None
    assert re.fullmatch(r"[0-9a-f]{64}", seen.fingerprint)
    assert (seen.tls_version, seen.elapsed_ms, seen.error) == ("TLSv1.3", 7, None)
    assert seen.common_name == "leaf.example.test" and seen.issuer_cn == "Fixture Intermediate 2"
    broken = observation_from_chain(PulledChain((b"\x30\x03junk",), "TLSv1.2"), elapsed_ms=1)
    assert broken.failure == "error" and broken.fingerprint == hashlib.sha256(b"\x30\x03junk").hexdigest()


def test_unparseable_leaf_keeps_hash_and_a_fixed_message():
    broken = observation_from_chain(PulledChain((b"\x30\x03junk", b"x"), "TLSv1.2"), elapsed_ms=1)
    assert (broken.common_name, broken.issuer_cn, broken.not_after) == (None, None, None)
    assert broken.chain_length == 2 and broken.tls_version == "TLSv1.2"
    assert broken.error == "Served certificate could not be parsed."


@pytest.mark.parametrize(
    ("error_class", "failure"),
    [("transient_network", "unreachable"), ("config_invalid", "error"), ("anything_else", "error")],
)
def test_observe_endpoint_maps_job_failures_without_raising(monkeypatch, error_class, failure):
    seen_args = []

    def failing(host, port, sni, timeout_seconds):
        seen_args.append((host, port, sni, timeout_seconds))
        raise JobFailure(error_class, "h:1 failed: fixed message")

    monkeypatch.setattr(scans, "pull_chain", failing)
    result = scans.observe_endpoint("h", 1, "sni.example", 5)
    assert seen_args == [("h", 1, "sni.example", 5)]
    assert result.failure == failure and result.error == "h:1 failed: fixed message"
    assert result.fingerprint is None and result.chain_length is None and result.elapsed_ms >= 0


def test_observe_endpoint_returns_the_classified_chain(monkeypatch, certs):
    der = certs.leaf.public_bytes(Encoding.DER)
    monkeypatch.setattr(scans, "pull_chain", lambda host, port, sni, timeout_seconds: PulledChain((der,), "TLSv1.3"))
    result = scans.observe_endpoint("h", 1, None, 5)
    assert result.failure is None and result.fingerprint == hashlib.sha256(der).hexdigest()
