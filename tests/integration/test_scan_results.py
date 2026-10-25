"""Plan 2 Task 1: classified scan results (real Postgres, in-process TLS listeners)."""

import socket
from datetime import timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy import delete, func, select
from sqlalchemy.orm import sessionmaker

from app.crypto.parse import parse_certificates
from app.models import Certificate, Endpoint, PrivateKey, ScanResult, TrustAnchor
from app.models.enums import ChainStatus, EndpointSource, ScanStatus
from app.services.scans import ScanObservation, observe_endpoint, record_scan


def _endpoint(db, host, port, **extra):
    endpoint = Endpoint(host=host, port=port, sni="www.example.internal", source=EndpointSource.MANUAL, **extra)
    db.add(endpoint)
    db.flush()
    return endpoint


def _chain_statuses(db):
    return db.execute(select(Certificate.id, Certificate.chain_status).order_by(Certificate.id)).all()


def _inventory(db, cert, chain_status=ChainStatus.UNCHECKED):
    parsed = parse_certificates(cert.public_bytes(Encoding.DER))[0]
    row = Certificate(
        common_name=parsed.common_name,
        subject_dn=parsed.subject_dn,
        sans=list(parsed.sans),
        issuer_dn=parsed.issuer_dn,
        issuer_cn=parsed.issuer_cn,
        serial=parsed.serial,
        not_before=parsed.not_before,
        not_after=parsed.not_after,
        sha256_fingerprint=parsed.sha256_fingerprint,
        pem=parsed.pem,
        chain_status=chain_status,
        imported_from="upload_pem",
    )
    db.add(row)
    db.flush()
    return row


def _counts(db):
    return [db.scalar(select(func.count()).select_from(model)) for model in (Certificate, PrivateKey, TrustAnchor)]


def _closed_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_record_scan_persists_observation_and_updates_endpoint(db, tls_servers, pull_certs, now):
    server = tls_servers(pull_certs.leaf, pull_certs.leaf_key, pull_certs.intermediates)
    expected = _inventory(db, pull_certs.leaf)
    endpoint = _endpoint(db, server.host, server.port, expected_certificate_id=expected.id)
    result = record_scan(db, endpoint.id, observe_endpoint(server.host, server.port, endpoint.sni, 10), "scheduled", now)
    db.refresh(result)
    db.refresh(endpoint)
    assert result.status is ScanStatus.OK and result.error is None
    assert result.endpoint_id == endpoint.id and result.expected_certificate_id == expected.id
    assert result.observed_fingerprint == expected.sha256_fingerprint
    assert (result.observed_common_name, result.observed_issuer_cn) == ("leaf.example.test", "Fixture Intermediate 2")
    assert result.observed_not_after == pull_certs.leaf.not_valid_after_utc
    assert (result.observed_chain_length, result.source, result.checked_at) == (3, "scheduled", now)
    assert result.tls_version.startswith("TLS") and result.elapsed_ms >= 0
    assert (endpoint.last_scan_status, endpoint.last_scan_at) == (ScanStatus.OK, now)
    assert server.seen_server_names == ["www.example.internal"]


def test_served_certificate_is_never_imported_or_trusted(db, tls_servers, pull_certs, now):
    server = tls_servers(pull_certs.leaf, pull_certs.leaf_key, pull_certs.intermediates)
    endpoint = Endpoint(host=server.host, port=server.port, sni="www.example.internal", source=EndpointSource.MANUAL)
    db.add(endpoint)
    db.flush()
    _inventory(db, pull_certs.wildcard, ChainStatus.TRUSTED)  # an unrelated, already-evaluated certificate
    counts, statuses = _counts(db), _chain_statuses(db)
    result = record_scan(db, endpoint.id, observe_endpoint(server.host, server.port, endpoint.sni, 10), "manual", now)
    assert result.status is ScanStatus.MISMATCH and result.expected_certificate_id is None
    assert result.observed_fingerprint == pull_certs.leaf.fingerprint(hashes.SHA256()).hex()
    assert (result.observed_chain_length, result.source, result.checked_at) == (3, "manual", now)
    assert counts == _counts(db) and statuses == _chain_statuses(db)
    assert (endpoint.last_scan_status, endpoint.last_scan_at) == (ScanStatus.MISMATCH, now)


def test_unreachable_and_handshake_failures_are_recorded_not_raised(db, tls_servers, pull_certs, now):
    garbage = tls_servers(pull_certs.leaf, pull_certs.leaf_key, mode="garbage")
    silent = tls_servers(pull_certs.leaf, pull_certs.leaf_key, mode="silent")
    cases = [
        (("127.0.0.1", _closed_port()), ScanStatus.UNREACHABLE, " unreachable: refused"),
        ((garbage.host, garbage.port), ScanStatus.ERROR, ": TLS handshake failed"),
        ((silent.host, silent.port), ScanStatus.UNREACHABLE, " unreachable: timeout"),
    ]
    for (host, port), expected_status, message in cases:
        endpoint = _endpoint(db, host, port)
        result = record_scan(db, endpoint.id, observe_endpoint(host, port, endpoint.sni, 1), "manual", now)
        assert result.status is expected_status
        assert result.observed_fingerprint is None and result.observed_chain_length is None
        assert result.error == f"{host}:{port}{message}"
        assert endpoint.last_scan_status is expected_status


def test_expired_served_certificate_is_expired_even_when_expected(db, ca, tls_servers, now):
    key = ec.generate_private_key(ec.SECP256R1())
    pem = ca.issue(
        public_key=key.public_key(),
        common_name="expired.example.internal",
        sans=["expired.example.internal"],
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1),
    )
    leaf = parse_certificates(pem)[0].cert
    server = tls_servers(leaf, key, [ca.intermediate])
    expected = _inventory(db, leaf)
    endpoint = _endpoint(db, server.host, server.port, expected_certificate_id=expected.id)
    result = record_scan(db, endpoint.id, observe_endpoint(server.host, server.port, endpoint.sni, 10), "scheduled", now)
    assert result.status is ScanStatus.EXPIRED
    assert result.observed_fingerprint == expected.sha256_fingerprint
    assert endpoint.last_scan_status is ScanStatus.EXPIRED


def test_expectation_is_snapshotted_at_scan_time(db, tls_servers, pull_certs, now):
    server = tls_servers(pull_certs.leaf, pull_certs.leaf_key, pull_certs.intermediates)
    served, other = _inventory(db, pull_certs.leaf), _inventory(db, pull_certs.wildcard)
    endpoint = _endpoint(db, server.host, server.port, expected_certificate_id=served.id)
    observation = observe_endpoint(server.host, server.port, endpoint.sni, 10)
    first = record_scan(db, endpoint.id, observation, "scheduled", now)
    endpoint.expected_certificate_id = other.id
    second = record_scan(db, endpoint.id, observation, "manual", now + timedelta(minutes=5))
    db.refresh(first)
    assert (first.status, first.expected_certificate_id) == (ScanStatus.OK, served.id)
    assert (second.status, second.expected_certificate_id) == (ScanStatus.MISMATCH, other.id)
    assert (endpoint.last_scan_status, endpoint.last_scan_at) == (ScanStatus.MISMATCH, now + timedelta(minutes=5))


def test_older_result_never_regresses_endpoint_state(db, now):
    newer = now + timedelta(hours=1)
    endpoint = _endpoint(db, "198.51.100.7", 443, last_scan_at=newer, last_scan_status=ScanStatus.OK)
    stale = ScanObservation(None, None, None, None, None, None, "unreachable", "198.51.100.7:443 unreachable: timeout", 3)
    result = record_scan(db, endpoint.id, stale, "scheduled", now)
    db.refresh(endpoint)
    assert (endpoint.last_scan_at, endpoint.last_scan_status) == (newer, ScanStatus.OK)
    assert result.status is ScanStatus.UNREACHABLE and result.checked_at == now
    assert db.scalar(select(func.count()).select_from(ScanResult).where(ScanResult.endpoint_id == endpoint.id)) == 1


def test_record_scan_refreshes_a_stale_loaded_endpoint_under_the_lock(engine, pull_certs, now):
    """Session A holds an old copy of the endpoint; session B commits newer state first."""
    t1, t3 = now - timedelta(hours=1), now + timedelta(hours=1)
    factory = sessionmaker(engine)
    with factory.begin() as setup:
        stale, fresh = _inventory(setup, pull_certs.wildcard), _inventory(setup, pull_certs.leaf)
        endpoint = _endpoint(
            setup, "198.51.100.8", 443,
            expected_certificate_id=stale.id, last_scan_at=t1, last_scan_status=ScanStatus.MISMATCH,
        )
        endpoint_id, stale_id, fresh_id, fresh_fingerprint = endpoint.id, stale.id, fresh.id, fresh.sha256_fingerprint
    try:
        with factory() as session_a:
            loaded = session_a.get(Endpoint, endpoint_id)  # keep a reference: the identity map is weak
            assert loaded.last_scan_at == t1
            with factory.begin() as session_b:
                newer = session_b.get(Endpoint, endpoint_id)
                newer.expected_certificate_id, newer.last_scan_at, newer.last_scan_status = (
                    fresh_id, t3, ScanStatus.OK,
                )
            observed = ScanObservation(
                fresh_fingerprint, "leaf.example.test", None, now + timedelta(days=30), 1, "TLSv1.3", None, None, 5
            )
            result = record_scan(session_a, endpoint_id, observed, "manual", now)
            result_id = result.id
            assert loaded.last_scan_at == t3  # the very same identity-mapped object was refreshed
            session_a.commit()
        with factory() as check:
            row = check.get(Endpoint, endpoint_id)
            assert (row.last_scan_at, row.last_scan_status) == (t3, ScanStatus.OK)
            stored = check.get(ScanResult, result_id)
            assert (stored.status, stored.expected_certificate_id, stored.checked_at) == (ScanStatus.OK, fresh_id, now)
    finally:
        with factory.begin() as cleanup:
            cleanup.execute(delete(ScanResult).where(ScanResult.endpoint_id == endpoint_id))
            cleanup.execute(delete(Endpoint).where(Endpoint.id == endpoint_id))
            cleanup.execute(delete(Certificate).where(Certificate.id.in_([stale_id, fresh_id])))
