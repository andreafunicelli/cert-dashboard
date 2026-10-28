"""Plan 3 Task 9: §6.3 reconciliation of a discovery document into servers, bindings and endpoints."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import event, func, select

from app.models import AuditLog, Binding, Endpoint, Server
from app.models.enums import EndpointSource, WebserverType
from app.services.discovery import reconcile_host, record_host_failure, sync_inventory_servers
from app.services.endpoints import create_endpoint, set_endpoint_active
from app.services.inventory import InventoryHost
from tests.integration.conftest import (
    JOB_ID,
    add_server,
    binding_doc,
    host_document,
    import_leaf,
    issue_leaf,
)

HOST = "web01.example.internal"
CHAIN_DIAGNOSTIC = "incomplete chain: no configured file holds this leaf's issuer"


def bindings_of(db, server_id):
    return list(db.scalars(select(Binding).where(Binding.server_id == server_id).order_by(Binding.id)))


def by_vhost(db, server_id):
    return {b.vhost_name: b for b in bindings_of(db, server_id)}


def audit_count(db, action):
    return db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == action))


def endpoints_of(db, server_id):
    return list(db.scalars(select(Endpoint).where(Endpoint.server_id == server_id).order_by(Endpoint.id)))


def endpoint_count(db, server_id):
    return len(endpoints_of(db, server_id))


def run(db, server, actor, at, *bindings):
    document = host_document(server.hostname, at, bindings)
    return reconcile_host(db, server.id, document, job_id=JOB_ID, actor=actor, now=at)


def test_reconciliation_table_and_idempotent_rerun(db, actor, now, keyed_certificate):
    server = add_server(db, "web01.example.internal")
    doc = host_document(server.hostname, now, [
        binding_doc("matched.example.internal", fp=keyed_certificate.sha256_fingerprint, key=keyed_certificate.spki),
        binding_doc("unknown.example.internal", fp="d" * 64, key="e" * 64),
        binding_doc("keymm.example.internal", fp=keyed_certificate.sha256_fingerprint, key="f" * 64),
        binding_doc("missing.example.internal", exists=False)])
    first = reconcile_host(db, server.id, doc, job_id=JOB_ID, actor=actor, now=now)
    assert {b.vhost_name: (b.match_state, b.certificate_id) for b in bindings_of(db, server.id)} == {
        "matched.example.internal": ("matched", keyed_certificate.id), "unknown.example.internal": ("unknown", None),
        "keymm.example.internal": ("key_mismatch", keyed_certificate.id), "missing.example.internal": ("missing_file", None)}
    assert (first.added, first.endpoints_created) == (4, 4) and audit_count(db, "binding.match_state") == 4
    again = reconcile_host(db, server.id, doc, job_id=JOB_ID, actor=actor, now=now + timedelta(hours=1))
    assert (again.added, again.updated, again.unchanged) == (0, 0, 4)
    assert audit_count(db, "binding.match_state") == 4 and endpoint_count(db, server.id) == 4
    assert all(b.last_seen_at == now + timedelta(hours=1) for b in bindings_of(db, server.id))


def test_reconciliation_records_what_the_document_says(db, actor, now, keyed_certificate):
    server = add_server(db, HOST)
    entry = binding_doc(
        "www.example.internal", fp=keyed_certificate.sha256_fingerprint, key=keyed_certificate.spki, port=8443,
        chain_path="/etc/ssl/www.chain.pem", vhost_names=["www.example.internal", "example.internal"],
    )
    entry["cert_mode"], entry["key_owner"] = "0640", "www-data"
    run(db, server, actor, now, entry)
    (binding,) = bindings_of(db, server.id)
    assert (binding.webserver, binding.port, binding.chain_path) == (WebserverType.NGINX, 8443, "/etc/ssl/www.chain.pem")
    assert binding.vhost_names == ["www.example.internal", "example.internal"]
    assert (binding.cert_mode, binding.key_mode, binding.key_owner) == (0o640, 0o600, "www-data")
    assert binding.on_disk_fingerprint == keyed_certificate.sha256_fingerprint
    assert binding.on_disk_key_public_sha256 == keyed_certificate.spki
    assert (binding.is_active, binding.notes) == (True, None)
    assert db.get(Server, server.id).last_discovery_status == "ok"


def test_matched_requires_the_certificates_own_spki_hash_in_lowercase_hex(db, actor, now, keyed_certificate):
    """D2: the key hash is compared as the host collector emits it (lowercase hex of the DER SPKI), unchanged."""
    server = add_server(db, HOST)
    fp = keyed_certificate.sha256_fingerprint
    run(
        db, server, actor, now,
        binding_doc("lower.example.internal", fp=fp, key=keyed_certificate.spki),
        binding_doc("upper.example.internal", fp=fp, key=keyed_certificate.spki.upper()),
        binding_doc("colons.example.internal", fp=fp, key=":".join(keyed_certificate.spki[i : i + 2] for i in range(0, 64, 2))),
    )
    states = {name: (b.match_state, b.certificate_id) for name, b in by_vhost(db, server.id).items()}
    assert states == {
        "lower.example.internal": ("matched", keyed_certificate.id),
        "upper.example.internal": ("key_mismatch", keyed_certificate.id),
        "colons.example.internal": ("key_mismatch", keyed_certificate.id),
    }


def test_chain_path_is_stored_as_documented_and_same_issuer_bindings_stay_two(db, actor, now, keyed_certificate):
    """D1: no inference here — an RSA+ECDSA pair of one vhost is two bindings sharing one endpoint."""
    server = add_server(db, HOST)
    rsa = binding_doc("www.example.internal", cert_path="/etc/ssl/www.rsa.pem", key_path="/etc/ssl/www.rsa.key")
    ecdsa = binding_doc("www.example.internal", cert_path="/etc/ssl/www.ecdsa.pem", key_path="/etc/ssl/www.ecdsa.key")
    first = run(db, server, actor, now, rsa, ecdsa)
    found = bindings_of(db, server.id)
    assert [(b.cert_path, b.chain_path) for b in found] == [("/etc/ssl/www.rsa.pem", None), ("/etc/ssl/www.ecdsa.pem", None)]
    assert (first.added, first.endpoints_created) == (2, 1)
    (endpoint,) = endpoints_of(db, server.id)
    assert endpoint.binding_id == found[0].id


def test_chain_diagnostic_is_a_note_joined_with_the_missing_file_note_and_cleared(db, actor, now, keyed_certificate):
    server = add_server(db, HOST)
    fp, spki = keyed_certificate.sha256_fingerprint, keyed_certificate.spki
    run(db, server, actor, now, binding_doc("a.example.internal", fp=fp, key=spki, chain_diagnostic=CHAIN_DIAGNOSTIC),
        binding_doc("b.example.internal", fp=fp, key_unreadable=True, chain_diagnostic=CHAIN_DIAGNOSTIC))
    found = by_vhost(db, server.id)
    assert found["a.example.internal"].notes == CHAIN_DIAGNOSTIC
    assert found["a.example.internal"].match_state == "matched"
    assert found["b.example.internal"].notes == f"{CHAIN_DIAGNOSTIC}; key missing or unreadable at discovery"
    again = run(db, server, actor, now + timedelta(hours=1), binding_doc("a.example.internal", fp=fp, key=spki),
                binding_doc("b.example.internal", fp=fp, key=spki))
    assert (again.updated, again.unchanged) == (2, 0)
    assert [b.notes for b in bindings_of(db, server.id)] == [None, None]


def test_absent_binding_is_deactivated_with_its_endpoint_and_noted(db, actor, now, keyed_certificate):
    server = add_server(db, HOST)
    keep = binding_doc("keep.example.internal")
    gone = binding_doc("gone.example.internal")
    run(db, server, actor, now, keep, gone)
    later = now + timedelta(days=1)
    outcome = run(db, server, actor, later, keep)
    assert (outcome.deactivated, outcome.unchanged) == (1, 1)
    found = by_vhost(db, server.id)
    assert (found["gone.example.internal"].is_active, found["gone.example.internal"].notes) == (
        False, f"removed from config at {later:%Y-%m-%d}")
    assert found["keep.example.internal"].is_active is True
    active = {e.sni: e.is_active for e in endpoints_of(db, server.id)}
    assert active == {"keep.example.internal": True, "gone.example.internal": False}
    transition = db.scalars(
        select(AuditLog).where(AuditLog.action == "binding.match_state", AuditLog.target_id == str(found["gone.example.internal"].id))
        .order_by(AuditLog.created_at.desc())
    ).first()
    assert (transition.details["was_active"], transition.details["is_active"], transition.details["job_id"]) == (True, False, str(JOB_ID))
    again = run(db, server, actor, later + timedelta(days=1), keep)  # an already removed binding keeps its first note
    assert (again.deactivated, again.unchanged) == (0, 1)
    assert by_vhost(db, server.id)["gone.example.internal"].notes == f"removed from config at {later:%Y-%m-%d}"
    assert endpoint_count(db, server.id) == 2  # never deleted


def test_a_binding_that_comes_back_is_active_again_with_its_endpoint(db, actor, now):
    server = add_server(db, HOST)
    run(db, server, actor, now, binding_doc("a.example.internal"))
    run(db, server, actor, now + timedelta(days=1), binding_doc("b.example.internal"))
    back = run(db, server, actor, now + timedelta(days=2), binding_doc("a.example.internal"), binding_doc("b.example.internal"))
    assert (back.updated, back.unchanged, back.added) == (1, 1, 0)
    found = by_vhost(db, server.id)
    assert (found["a.example.internal"].is_active, found["a.example.internal"].notes) == (True, None)
    assert all(e.is_active for e in endpoints_of(db, server.id)) and endpoint_count(db, server.id) == 2


def test_moving_a_directive_into_an_include_changes_identity(db, actor, now):
    server = add_server(db, HOST)
    inline = binding_doc("www.example.internal", config_file="/etc/nginx/conf.d/www.conf")
    run(db, server, actor, now, inline)
    moved = binding_doc("www.example.internal", config_file="/etc/nginx/snippets/tls.conf")
    outcome = run(db, server, actor, now + timedelta(days=1), moved)
    assert (outcome.added, outcome.deactivated) == (1, 1)
    old, new = bindings_of(db, server.id)
    assert (old.config_file, old.is_active, old.notes) == ("/etc/nginx/conf.d/www.conf", False, f"removed from config at {now + timedelta(days=1):%Y-%m-%d}")
    assert (new.config_file, new.is_active) == ("/etc/nginx/snippets/tls.conf", True)
    (endpoint,) = endpoints_of(db, server.id)
    assert (endpoint.is_active, endpoint.binding_id) == (True, new.id)  # the endpoint follows the live binding


def test_zero_bindings_on_a_populated_host_are_suspected_not_deactivated(db, actor, now):
    server = add_server(db, HOST)
    run(db, server, actor, now, binding_doc("a.example.internal"), binding_doc("b.example.internal"))
    outcome = run(db, server, actor, now + timedelta(hours=1))
    assert (outcome.parse_suspected, outcome.deactivated, outcome.added) == (True, 0, 0)
    assert all(b.is_active and b.notes is None for b in bindings_of(db, server.id))
    assert all(e.is_active for e in endpoints_of(db, server.id))
    row = db.get(Server, server.id)
    assert (row.last_discovery_status, row.last_discovery_at) == ("ok", now + timedelta(hours=1))
    assert audit_count(db, "binding.match_state") == 2


def test_zero_bindings_on_an_empty_host_is_not_suspected(db, actor, now):
    server = add_server(db, HOST)
    outcome = run(db, server, actor, now)
    assert (outcome.parse_suspected, outcome.added, outcome.unchanged) == (False, 0, 0)


def test_unknown_becomes_matched_after_import_and_the_endpoint_expectation_follows(db, actor, now, ca, keyring):
    issued = issue_leaf(ca, now)
    server = add_server(db, HOST)
    entry = binding_doc("www.example.internal", fp=issued.fingerprint, key=issued.spki)
    run(db, server, actor, now, entry)
    (binding,) = bindings_of(db, server.id)
    (endpoint,) = endpoints_of(db, server.id)
    assert (binding.match_state, binding.certificate_id, endpoint.expected_certificate_id) == ("unknown", None, None)
    imported = import_leaf(db, issued, keyring, actor, now)
    outcome = run(db, server, actor, now + timedelta(hours=1), entry)
    db.refresh(binding)
    db.refresh(endpoint)
    assert outcome.updated == 1
    assert (binding.match_state, binding.certificate_id) == ("matched", imported.id)
    assert endpoint.expected_certificate_id == imported.id
    transitions = db.scalars(select(AuditLog).where(AuditLog.action == "binding.match_state").order_by(AuditLog.created_at)).all()
    assert [(t.details["from_state"], t.details["to_state"]) for t in transitions] == [(None, "unknown"), ("unknown", "matched")]
    update = db.scalars(select(AuditLog).where(AuditLog.action == "endpoint.update", AuditLog.target_id == str(endpoint.id))).one()
    assert update.details == {"field": "expected_certificate_id", "from": None, "to": imported.id, "source": "discovery"}


def test_passphrase_key_is_missing_file_with_a_fixed_note(db, actor, now, keyed_certificate):
    server = add_server(db, HOST)
    fp, spki = keyed_certificate.sha256_fingerprint, keyed_certificate.spki
    run(db, server, actor, now, binding_doc("www.example.internal", fp=fp, key=spki))
    run(db, server, actor, now + timedelta(hours=1), binding_doc("www.example.internal", fp=fp, key_unreadable=True))
    (binding,) = bindings_of(db, server.id)
    assert (binding.match_state, binding.notes) == ("missing_file", "key missing or unreadable at discovery")
    assert binding.certificate_id == keyed_certificate.id  # kept from the previous state
    assert binding.on_disk_key_public_sha256 is None


def test_missing_certificate_has_its_own_fixed_note(db, actor, now):
    server = add_server(db, HOST)
    run(db, server, actor, now, binding_doc("www.example.internal", exists=False))
    (binding,) = bindings_of(db, server.id)
    assert (binding.match_state, binding.on_disk_fingerprint) == ("missing_file", None)
    assert binding.notes == "certificate missing or unreadable at discovery; key missing or unreadable at discovery"


def test_inventory_sync_inserts_updates_and_deactivates_servers(db, actor, now):
    hosts = [
        InventoryHost("web01.example.internal", ("ring_a", "web"), None, WebserverType.NGINX),
        InventoryHost("web02.example.internal", ("web",), "192.0.2.12", None),
    ]
    first = sync_inventory_servers(db, hosts, "main:inventory@" + "a" * 40, actor, now)
    assert (first.created, first.updated, first.deactivated) == (2, 0, 0)
    web1, web2 = (db.get(Server, first.server_ids[name]) for name in ("web01.example.internal", "web02.example.internal"))
    assert (web1.ansible_groups, web1.connection_address, web1.webserver) == (["ring_a", "web"], None, WebserverType.NGINX)
    assert (web2.connection_address, web2.webserver, web2.is_active) == ("192.0.2.12", None, True)
    assert web1.inventory_source == "main:inventory@" + "a" * 40
    assert audit_count(db, "server.create") == 2
    # Webserver precedence: the inventory variable wins, else the value discovery detected is kept.
    run(db, web2, actor, now, binding_doc("www.example.internal"))
    run(db, web1, actor, now, binding_doc("www.example.internal"))
    db.get(Server, web2.id).webserver = WebserverType.APACHE
    second = sync_inventory_servers(
        db,
        [InventoryHost("web01.example.internal", ("ring_a", "web", "canary"), "10.0.0.5", WebserverType.APACHE),
         InventoryHost("web02.example.internal", ("web",), "192.0.2.12", None)],
        "main:inventory@" + "b" * 40, actor, now + timedelta(days=1),
    )
    assert (second.created, second.updated, second.deactivated) == (0, 2, 0)  # web02: the new inventory_source
    assert (web1.ansible_groups, web1.connection_address, web1.webserver) == (["ring_a", "web", "canary"], "10.0.0.5", WebserverType.APACHE)
    assert (web2.webserver, web2.inventory_source) == (WebserverType.APACHE, "main:inventory@" + "b" * 40)
    # web02 leaves the inventory: server, bindings and derived endpoints go inactive, nothing is deleted.
    third = sync_inventory_servers(
        db, [InventoryHost("web01.example.internal", ("ring_a",), None, None)], "main:inventory@" + "c" * 40, actor, now + timedelta(days=2)
    )
    assert (third.created, third.updated, third.deactivated) == (0, 1, 1)
    assert third.server_ids == {"web01.example.internal": web1.id}
    db.refresh(web2)
    assert web2.is_active is False and web1.is_active is True
    (gone,) = bindings_of(db, web2.id)
    assert gone.is_active is False and gone.notes == f"server removed from inventory at {now + timedelta(days=2):%Y-%m-%d}"
    assert [e.is_active for e in endpoints_of(db, web2.id)] == [False]
    assert all(b.is_active for b in bindings_of(db, web1.id))
    deactivation = db.scalars(select(AuditLog).where(AuditLog.action == "server.deactivate")).one()
    assert deactivation.target_id == str(web2.id)
    back = sync_inventory_servers(
        db, [InventoryHost("web02.example.internal", ("web",), None, None)], "main:inventory@" + "d" * 40, actor, now + timedelta(days=3)
    )
    assert (back.created, back.updated, back.deactivated) == (0, 1, 1)  # web02 returns, web01 leaves
    assert db.get(Server, web2.id).is_active is True and audit_count(db, "server.activate") == 1


def test_failed_host_keeps_bindings_and_records_status(db, actor, now):
    server = add_server(db, HOST)
    run(db, server, actor, now, binding_doc("www.example.internal"))
    before = [(b.id, b.match_state, b.is_active, b.last_seen_at, b.notes) for b in bindings_of(db, server.id)]
    audits = audit_count(db, "binding.match_state")
    record_host_failure(db, server.id, "unreachable", now + timedelta(hours=1))
    row = db.get(Server, server.id)
    assert (row.last_discovery_status, row.last_discovery_at) == ("unreachable", now + timedelta(hours=1))
    record_host_failure(db, server.id, "failed", now + timedelta(hours=2))
    assert db.get(Server, server.id).last_discovery_status == "failed"
    assert [(b.id, b.match_state, b.is_active, b.last_seen_at, b.notes) for b in bindings_of(db, server.id)] == before
    assert audit_count(db, "binding.match_state") == audits and all(e.is_active for e in endpoints_of(db, server.id))


def test_existing_manual_endpoint_is_adopted_not_duplicated(db, actor, now, keyed_certificate):
    server = add_server(db, HOST)
    manual = create_endpoint(db, HOST, 443, "www.example.internal", None, actor)
    outcome = run(db, server, actor, now, binding_doc("www.example.internal", fp=keyed_certificate.sha256_fingerprint, key=keyed_certificate.spki))
    (binding,) = bindings_of(db, server.id)
    assert outcome.endpoints_created == 0
    assert db.scalar(select(func.count()).select_from(Endpoint)) == 1
    db.refresh(manual)
    assert (manual.binding_id, manual.server_id, manual.source) == (binding.id, server.id, EndpointSource.MANUAL)
    assert manual.expected_certificate_id == keyed_certificate.id


def test_endpoint_follows_the_address_the_worker_reaches(db, actor, now):
    server = add_server(db, HOST, connection_address="192.0.2.77")
    run(db, server, actor, now, binding_doc("www.example.internal", port=8443), binding_doc("default", vhost_names=["default"]))
    found = {(e.host, e.port, e.sni, e.source) for e in endpoints_of(db, server.id)}
    assert found == {("192.0.2.77", 8443, "www.example.internal", EndpointSource.DISCOVERY), ("192.0.2.77", 443, None, EndpointSource.DISCOVERY)}


def test_bindings_with_one_endpoint_identity_share_it(db, actor, now):
    server = add_server(db, HOST)
    rsa = binding_doc("www.example.internal", cert_path="/etc/ssl/rsa.pem")
    ecdsa = binding_doc("www.example.internal", cert_path="/etc/ssl/ecdsa.pem")
    wild_a = binding_doc("*.a.example.internal", port=9443)
    wild_b = binding_doc("*.b.example.internal", port=9443)
    first = run(db, server, actor, now, rsa, ecdsa, wild_a, wild_b)
    assert first.endpoints_created == 2
    low = by_vhost(db, server.id)
    rsa_binding, ecdsa_binding = [b for b in bindings_of(db, server.id) if b.vhost_name == "www.example.internal"]
    wild_binding_a = low["*.a.example.internal"]
    wild_binding_b = low["*.b.example.internal"]
    assert {e.binding_id for e in endpoints_of(db, server.id)} == {rsa_binding.id, wild_binding_a.id}
    # Dropping the lower binding of each pair moves the link; the endpoint stays active.
    run(db, server, actor, now + timedelta(hours=1), ecdsa, wild_b)
    after = {e.port: e for e in endpoints_of(db, server.id)}
    assert (after[443].binding_id, after[443].is_active) == (ecdsa_binding.id, True)
    assert (after[9443].binding_id, after[9443].is_active) == (wild_binding_b.id, True)
    # Dropping the last one deactivates the endpoint.
    run(db, server, actor, now + timedelta(hours=2), wild_b)
    assert {e.port: e.is_active for e in endpoints_of(db, server.id)} == {443: False, 9443: True}


def test_audit_details_never_contain_paths_or_notes(db, actor, now, keyed_certificate):
    server = add_server(db, HOST)
    run(db, server, actor, now,
        binding_doc("a.example.internal", exists=False, chain_diagnostic=CHAIN_DIAGNOSTIC),
        binding_doc("b.example.internal", fp=keyed_certificate.sha256_fingerprint, key_unreadable=True),
        binding_doc("c.example.internal"))
    run(db, server, actor, now + timedelta(days=1), binding_doc("c.example.internal"))
    sync_inventory_servers(db, [], "main:inventory@" + "a" * 40, actor, now + timedelta(days=2))
    rows = db.scalars(
        select(AuditLog).where(
            AuditLog.action.like("binding.%") | AuditLog.action.like("endpoint.%") | AuditLog.action.like("server.%")
        )
    ).all()
    assert {row.action for row in rows} >= {"binding.match_state", "endpoint.create", "endpoint.update", "server.deactivate"}
    text = json.dumps([row.details for row in rows])
    for forbidden in ("/etc", ".pem", ".key", "removed from config", "missing or unreadable", "incomplete chain", "removed from inventory"):
        assert forbidden not in text


def test_one_certificate_query_per_host(db, actor, now, keyed_certificate):
    server = add_server(db, HOST)
    entries = [binding_doc(f"v{i}.example.internal", fp=f"{i:x}" * 64, key="a" * 64) for i in range(1, 6)]
    entries.append(binding_doc("m.example.internal", fp=keyed_certificate.sha256_fingerprint, key=keyed_certificate.spki))
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    connection = db.connection()
    event.listen(connection, "before_cursor_execute", capture)
    try:
        run(db, server, actor, now, *entries)
        run(db, server, actor, now + timedelta(hours=1), *entries)
    finally:
        event.remove(connection, "before_cursor_execute", capture)
    certificate_reads = [s for s in statements if "FROM certificate" in s]
    binding_reads = [s for s in statements if "FROM binding" in s and "WHERE binding.server_id =" in s]
    derivation_reads = [s for s in statements if "FROM binding JOIN server" in s]
    assert len(certificate_reads) == 2 and len(binding_reads) == 2  # one of each per host run
    assert len(derivation_reads) == 2  # settling the endpoints is one query per run, not one per endpoint


def test_reconcile_host_owns_no_commit_and_locks_the_server_row(db, actor, now):
    server = add_server(db, HOST)
    statements = []
    connection = db.connection()
    event.listen(connection, "before_cursor_execute", lambda *args: statements.append(args[2]))
    run(db, server, actor, now, binding_doc("www.example.internal"))
    assert any("FOR UPDATE" in s and "FROM server" in s for s in statements)
    assert db.in_transaction()


def test_unknown_server_raises(db, actor, now):
    with pytest.raises(LookupError):
        reconcile_host(db, 999_999, host_document(HOST, now, []), job_id=JOB_ID, actor=actor, now=now)


# --- derived endpoints follow their bindings (review of PR #51) -----------------------------------


def endpoint_states(db, server_id):
    return {(e.host, e.sni): (e.is_active, e.binding_id) for e in endpoints_of(db, server_id)}


def test_a_changed_connection_address_retires_the_old_derived_endpoint(db, actor, now):
    server = add_server(db, HOST, connection_address="192.0.2.10")
    doc = binding_doc("www.example.internal")
    run(db, server, actor, now, doc)
    (binding,) = bindings_of(db, server.id)
    server.connection_address = "192.0.2.11"
    db.flush()
    outcome = run(db, server, actor, now + timedelta(hours=1), doc)
    assert (outcome.endpoints_created, outcome.deactivated) == (1, 0)
    assert endpoint_states(db, server.id) == {
        ("192.0.2.10", "www.example.internal"): (False, binding.id),
        ("192.0.2.11", "www.example.internal"): (True, binding.id),
    }
    retired = next(e for e in endpoints_of(db, server.id) if e.host == "192.0.2.10")
    assert db.scalar(
        select(func.count()).select_from(AuditLog).where(
            AuditLog.action == "endpoint.update", AuditLog.target_id == str(retired.id), AuditLog.details["field"].astext == "is_active"
        )
    ) == 1
    run(db, server, actor, now + timedelta(hours=2), doc)  # stable afterwards: nothing more to retire
    assert audit_count(db, "endpoint.update") == 1 and endpoint_count(db, server.id) == 2


def test_a_changed_server_name_retires_the_old_derived_endpoint(db, actor, now):
    server = add_server(db, HOST)
    run(db, server, actor, now, binding_doc("_", vhost_names=["_", "a.example.internal"]))
    (binding,) = bindings_of(db, server.id)
    run(db, server, actor, now + timedelta(hours=1), binding_doc("_", vhost_names=["_", "b.example.internal"]))
    assert endpoint_states(db, server.id) == {
        (HOST, "a.example.internal"): (False, binding.id),
        (HOST, "b.example.internal"): (True, binding.id),
    }


def test_a_changed_server_name_keeps_an_endpoint_another_active_binding_derives(db, actor, now):
    server = add_server(db, HOST)
    moving = binding_doc("_", cert_path="/etc/ssl/rsa.pem", vhost_names=["_", "a.example.internal"])
    staying = binding_doc("_", cert_path="/etc/ssl/ecdsa.pem", vhost_names=["_", "a.example.internal"])
    run(db, server, actor, now, moving, staying)
    low, high = bindings_of(db, server.id)
    assert endpoint_states(db, server.id) == {(HOST, "a.example.internal"): (True, low.id)}
    moved = binding_doc("_", cert_path="/etc/ssl/rsa.pem", vhost_names=["_", "b.example.internal"])
    run(db, server, actor, now + timedelta(hours=1), moved, staying)
    assert endpoint_states(db, server.id) == {
        (HOST, "a.example.internal"): (True, high.id),  # still scanned, now through the binding that derives it
        (HOST, "b.example.internal"): (True, low.id),
    }


def test_an_operator_pause_survives_an_endpoint_identity_change(db, actor, now):
    server = add_server(db, HOST, connection_address="192.0.2.10")
    doc = binding_doc("www.example.internal")
    run(db, server, actor, now, doc)
    (old,) = endpoints_of(db, server.id)
    set_endpoint_active(db, old.id, False, actor)
    before = audit_count(db, "endpoint.update")
    server.connection_address = "192.0.2.11"
    db.flush()
    run(db, server, actor, now + timedelta(hours=1), doc)
    assert endpoint_states(db, server.id)[("192.0.2.10", "www.example.internal")][0] is False
    assert audit_count(db, "endpoint.update") == before  # the paused endpoint is not touched again


def test_a_shared_endpoint_follows_the_certificate_of_the_binding_that_inherits_it(db, actor, now, ca, keyring, keyed_certificate):
    other = import_leaf(db, issue_leaf(ca, now), keyring, actor, now)
    server = add_server(db, HOST)
    rsa = binding_doc("www.example.internal", cert_path="/etc/ssl/rsa.pem", fp=keyed_certificate.sha256_fingerprint, key=keyed_certificate.spki)
    ecdsa = binding_doc("www.example.internal", cert_path="/etc/ssl/ecdsa.pem", fp=other.sha256_fingerprint, key=other.spki)
    run(db, server, actor, now, rsa, ecdsa)
    (endpoint,) = endpoints_of(db, server.id)
    assert endpoint.expected_certificate_id == keyed_certificate.id
    run(db, server, actor, now + timedelta(hours=1), ecdsa)
    db.refresh(endpoint)
    _, high = bindings_of(db, server.id)
    assert (endpoint.is_active, endpoint.binding_id, endpoint.expected_certificate_id) == (True, high.id, other.id)
    changes = [
        (row.details["from"], row.details["to"])
        for row in db.scalars(
            select(AuditLog).where(
                AuditLog.action == "endpoint.update", AuditLog.target_id == str(endpoint.id),
                AuditLog.details["field"].astext == "expected_certificate_id",
            )
        )
    ]
    assert changes == [(keyed_certificate.id, other.id)]


def test_moving_a_directive_into_an_include_moves_the_expectation_to_the_new_certificate(db, actor, now, ca, keyring, keyed_certificate):
    other = import_leaf(db, issue_leaf(ca, now), keyring, actor, now)
    server = add_server(db, HOST)
    inline = binding_doc("www.example.internal", config_file="/etc/nginx/conf.d/www.conf", fp=keyed_certificate.sha256_fingerprint, key=keyed_certificate.spki)
    run(db, server, actor, now, inline)
    moved = binding_doc("www.example.internal", config_file="/etc/nginx/snippets/tls.conf", fp=other.sha256_fingerprint, key=other.spki)
    run(db, server, actor, now + timedelta(days=1), moved)
    (endpoint,) = endpoints_of(db, server.id)
    _, new = bindings_of(db, server.id)
    assert (endpoint.is_active, endpoint.binding_id, endpoint.expected_certificate_id) == (True, new.id, other.id)


def expectation_changes(db, endpoint):
    return [
        (row.details["from"], row.details["to"])
        for row in db.scalars(
            select(AuditLog)
            .where(
                AuditLog.action == "endpoint.update",
                AuditLog.target_id == str(endpoint.id),
                AuditLog.details["field"].astext == "expected_certificate_id",
            )
            .order_by(AuditLog.id)
        )
    ]


def test_a_matched_binding_turning_unknown_clears_its_endpoint_expectation(db, actor, now, ca, keyed_certificate):
    stranger = issue_leaf(ca, now)  # never imported
    server = add_server(db, HOST)
    known = binding_doc("www.example.internal", fp=keyed_certificate.sha256_fingerprint, key=keyed_certificate.spki)
    run(db, server, actor, now, known)
    (endpoint,) = endpoints_of(db, server.id)
    assert endpoint.expected_certificate_id == keyed_certificate.id
    swapped = binding_doc("www.example.internal", fp=stranger.fingerprint, key=stranger.spki)
    run(db, server, actor, now + timedelta(hours=1), swapped)
    (binding,) = bindings_of(db, server.id)
    db.refresh(endpoint)
    assert (binding.match_state, binding.certificate_id) == ("unknown", None)
    assert endpoint.is_active is True
    assert endpoint.expected_certificate_id is None
    assert expectation_changes(db, endpoint) == [(keyed_certificate.id, None)]


def test_a_shared_endpoint_handed_to_an_unknown_binding_loses_the_removed_expectation(db, actor, now, ca, keyed_certificate):
    stranger = issue_leaf(ca, now)  # never imported
    server = add_server(db, HOST)
    known = binding_doc("www.example.internal", cert_path="/etc/ssl/rsa.pem", fp=keyed_certificate.sha256_fingerprint, key=keyed_certificate.spki)
    unknown = binding_doc("www.example.internal", cert_path="/etc/ssl/ecdsa.pem", fp=stranger.fingerprint, key=stranger.spki)
    run(db, server, actor, now, known, unknown)
    (endpoint,) = endpoints_of(db, server.id)
    assert endpoint.expected_certificate_id == keyed_certificate.id
    run(db, server, actor, now + timedelta(hours=1), unknown)
    db.refresh(endpoint)
    _, heir = bindings_of(db, server.id)
    assert heir.match_state == "unknown"
    assert (endpoint.is_active, endpoint.binding_id, endpoint.expected_certificate_id) == (True, heir.id, None)
    assert expectation_changes(db, endpoint) == [(keyed_certificate.id, None)]


def test_an_operator_expectation_on_an_unknown_bindings_endpoint_survives_rediscovery(db, actor, now, ca, keyed_certificate):
    stranger = issue_leaf(ca, now)  # never imported
    server = add_server(db, HOST)
    entry = binding_doc("www.example.internal", fp=stranger.fingerprint, key=stranger.spki)
    run(db, server, actor, now, entry)
    (endpoint,) = endpoints_of(db, server.id)
    endpoint.expected_certificate_id = keyed_certificate.id  # set by an operator
    db.flush()
    run(db, server, actor, now + timedelta(hours=1), entry)
    db.refresh(endpoint)
    assert endpoint.expected_certificate_id == keyed_certificate.id


# --- aliases: one endpoint identity derived by several inventory servers (operator decision, review round 4) ---

ALIAS = "192.0.2.50"
ALIAS_SNI = "www.example.internal"


def alias_servers(db):
    first = add_server(db, "alias-a.example.internal", connection_address=ALIAS)
    second = add_server(db, "alias-b.example.internal", connection_address=ALIAS)
    return first, second


def alias_endpoint(db):
    return db.scalars(select(Endpoint).where(Endpoint.host == ALIAS)).one()


def endpoint_events(db, endpoint, reason=None, field=None):
    rows = db.scalars(
        select(AuditLog).where(AuditLog.action == "endpoint.update", AuditLog.target_id == str(endpoint.id)).order_by(AuditLog.id)
    )
    return [
        row.details for row in rows
        if (reason is None or row.details.get("reason") == reason) and (field is None or row.details.get("field") == field)
    ]


def leave_inventory(db, actor, at, *remaining):
    hosts = [InventoryHost(server.hostname, (), ALIAS, None) for server in remaining]
    return sync_inventory_servers(db, hosts, "fixture", actor, at)


def test_removing_the_owning_server_hands_a_still_derived_endpoint_to_the_other_server(db, actor, now):
    first, second = alias_servers(db)
    doc = binding_doc(ALIAS_SNI)
    run(db, first, actor, now, doc)
    run(db, second, actor, now, doc)
    endpoint = alias_endpoint(db)
    assert (endpoint.server_id, endpoint.is_active) == (first.id, True)
    leave_inventory(db, actor, now + timedelta(days=1), second)
    db.refresh(endpoint)
    (heir,) = bindings_of(db, second.id)
    assert (endpoint.is_active, endpoint.server_id, endpoint.binding_id) == (True, second.id, heir.id)
    (transfer,) = endpoint_events(db, endpoint, reason="alias_ownership_transfer")
    assert (transfer["previous_server_id"], transfer["new_server_id"]) == (first.id, second.id)
    assert "job_id" in transfer
    assert endpoint_events(db, endpoint, field="is_active") == []
    run(db, second, actor, now + timedelta(days=2), doc)  # stable afterwards: no second transfer
    assert len(endpoint_events(db, endpoint, reason="alias_ownership_transfer")) == 1


def test_an_unknown_heir_of_a_removed_owner_leaves_the_endpoint_active_without_an_expectation(db, actor, now, ca, keyed_certificate):
    stranger = issue_leaf(ca, now)  # never imported
    first, second = alias_servers(db)
    run(db, first, actor, now, binding_doc(ALIAS_SNI, fp=keyed_certificate.sha256_fingerprint, key=keyed_certificate.spki))
    run(db, second, actor, now, binding_doc(ALIAS_SNI, fp=stranger.fingerprint, key=stranger.spki))
    endpoint = alias_endpoint(db)
    assert (endpoint.server_id, endpoint.expected_certificate_id) == (first.id, keyed_certificate.id)
    leave_inventory(db, actor, now + timedelta(days=1), second)
    db.refresh(endpoint)
    assert (endpoint.is_active, endpoint.server_id, endpoint.expected_certificate_id) == (True, second.id, None)
    assert expectation_changes(db, endpoint) == [(keyed_certificate.id, None)]
    assert len(endpoint_events(db, endpoint, reason="alias_ownership_transfer")) == 1


def test_removing_every_deriving_binding_deactivates_the_endpoint_once(db, actor, now):
    first, second = alias_servers(db)
    doc = binding_doc(ALIAS_SNI)
    run(db, first, actor, now, doc)
    run(db, second, actor, now, doc)
    endpoint = alias_endpoint(db)
    leave_inventory(db, actor, now + timedelta(days=1))
    db.refresh(endpoint)
    assert endpoint.is_active is False
    assert [(e["from"], e["to"]) for e in endpoint_events(db, endpoint, field="is_active")] == [(True, False)]
    assert endpoint_events(db, endpoint, reason="alias_ownership_transfer") == []


def test_the_last_binding_of_the_remaining_server_going_away_deactivates_the_endpoint_once(db, actor, now):
    first, second = alias_servers(db)
    doc = binding_doc(ALIAS_SNI)
    run(db, first, actor, now, doc)
    run(db, second, actor, now, doc)
    endpoint = alias_endpoint(db)
    leave_inventory(db, actor, now + timedelta(days=1), second)
    run(db, second, actor, now + timedelta(days=2), binding_doc("other.example.internal"))
    db.refresh(endpoint)
    assert endpoint.is_active is False
    assert [(e["from"], e["to"]) for e in endpoint_events(db, endpoint, field="is_active")] == [(True, False)]
    assert len(endpoint_events(db, endpoint, reason="alias_ownership_transfer")) == 1


def test_a_retired_endpoint_derived_again_by_an_active_binding_is_reactivated_with_an_audit(db, actor, now):
    server = add_server(db, HOST, connection_address="192.0.2.10")
    doc = binding_doc("www.example.internal")
    run(db, server, actor, now, doc)
    (old,) = endpoints_of(db, server.id)
    server.connection_address = "192.0.2.11"
    db.flush()
    run(db, server, actor, now + timedelta(hours=1), doc)
    db.refresh(old)
    assert old.is_active is False
    server.connection_address = "192.0.2.10"  # the binding stays active throughout and derives the old identity again
    db.flush()
    run(db, server, actor, now + timedelta(hours=2), doc)
    db.refresh(old)
    (binding,) = bindings_of(db, server.id)
    assert (old.is_active, old.binding_id) == (True, binding.id)
    (back,) = endpoint_events(db, old, reason="rediscovered_derived")
    assert (back["field"], back["from"], back["to"], back["job_id"]) == ("is_active", False, True, str(JOB_ID))
    run(db, server, actor, now + timedelta(hours=3), doc)
    assert len(endpoint_events(db, old, reason="rediscovered_derived")) == 1


def test_active_derivation_wins_over_an_indistinguishable_operator_pause(db, actor, now):
    # There is no field telling a pause from a reconciliation deactivation: scanning once too often beats once too few.
    server = add_server(db, HOST)
    doc = binding_doc("www.example.internal")
    run(db, server, actor, now, doc)
    (endpoint,) = endpoints_of(db, server.id)
    set_endpoint_active(db, endpoint.id, False, actor)
    run(db, server, actor, now + timedelta(hours=1), doc)
    db.refresh(endpoint)
    assert endpoint.is_active is True
    assert len(endpoint_events(db, endpoint, reason="rediscovered_derived")) == 1


@pytest.mark.parametrize("order", ["lower_server_first", "lower_server_last"])
def test_the_owner_is_the_lowest_server_id_whatever_the_order_documents_arrive_in(db, actor, now, ca, keyring, keyed_certificate, order):
    other = import_leaf(db, issue_leaf(ca, now), keyring, actor, now)
    first, second = alias_servers(db)
    low = binding_doc(ALIAS_SNI, fp=other.sha256_fingerprint, key=other.spki)
    high = binding_doc(ALIAS_SNI, fp=keyed_certificate.sha256_fingerprint, key=keyed_certificate.spki)
    sequence = [(first, low), (second, high)] if order == "lower_server_first" else [(second, high), (first, low)]
    for index, (server, entry) in enumerate(sequence):
        run(db, server, actor, now + timedelta(minutes=index), entry)
    endpoint = alias_endpoint(db)
    (low_binding,) = bindings_of(db, first.id)
    assert (endpoint.is_active, endpoint.server_id, endpoint.binding_id) == (True, first.id, low_binding.id)
    assert endpoint.expected_certificate_id == other.id  # the owner's certificate, never the other server's
    transfers = endpoint_events(db, endpoint, reason="alias_ownership_transfer")
    if order == "lower_server_first":
        assert transfers == []
    else:
        (transfer,) = transfers
        assert (transfer["previous_server_id"], transfer["new_server_id"], transfer["job_id"]) == (second.id, first.id, str(JOB_ID))
    run(db, second, actor, now + timedelta(hours=1), high)  # re-running either side changes nothing
    run(db, first, actor, now + timedelta(hours=1), low)
    db.refresh(endpoint)
    assert (endpoint.server_id, endpoint.expected_certificate_id) == (first.id, other.id)
    assert len(endpoint_events(db, endpoint, reason="alias_ownership_transfer")) == len(transfers)
