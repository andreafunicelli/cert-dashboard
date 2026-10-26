"""Plan 2 Task 13: endpoint management on /scans and the certificate scan panel (real Postgres, real HTTP stack)."""

import re
import secrets

import pytest
from sqlalchemy import func, select

from app.models import AuditLog, Certificate, Endpoint, ScanResult
from app.models.enums import CertificateStatus, EndpointSource, ScanStatus
from app.services.endpoints import DuplicateEndpoint, create_endpoint
from app.services.scans import EndpointInputError
from tests.integration.conftest import add_endpoint, expiring

HX = {"HX-Request": "true"}


def _post(client, path, token=True, headers=None, **fields):
    data = {"csrf_token": client.fixture_csrf, **fields} if token else fields
    return client.post(path, data=data, headers=headers, follow_redirects=False)


def fetch(factory, model, row_id):
    with factory() as db:
        return db.get(model, row_id)


def endpoint_by(factory, host, port):
    with factory() as db:
        return db.scalar(select(Endpoint).where(Endpoint.host == host, Endpoint.port == port))


def audits(factory, target_id, action_prefix="endpoint"):
    with factory() as db:
        return list(
            db.scalars(
                select(AuditLog)
                .where(AuditLog.target_type == "endpoint", AuditLog.target_id == str(target_id))
                .where(AuditLog.action.like(f"{action_prefix}.%"))
                .order_by(AuditLog.created_at)
            )
        )


def last_audit(factory, target_type, target_id):
    with factory() as db:
        return db.scalars(
            select(AuditLog)
            .where(AuditLog.target_type == target_type, AuditLog.target_id == str(target_id))
            .order_by(AuditLog.created_at.desc())
        ).first()


def _unseen_endpoint(web_factory, now):
    """An active endpoint whose newest result served a certificate that is not in the inventory."""
    host = f"unseen-{secrets.token_hex(3)}.example.test"
    with web_factory.begin() as db:
        endpoint_id = add_endpoint(db, host)
        db.add(
            ScanResult(
                endpoint_id=endpoint_id,
                status=ScanStatus.MISMATCH,
                observed_fingerprint=secrets.token_hex(32),
                observed_common_name="rogue.example.test",
                source="scheduled",
                checked_at=now,
            )
        )
    return endpoint_id, host


def test_update_the_expectation_to_the_observed_certificate(signed_in, web_factory, scan_world):
    response = signed_in.post(
        f"/scans/{scan_world.mismatch_id}/expectation",
        data={"use_observed": "1", "csrf_token": signed_in.fixture_csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    endpoint = fetch(web_factory, Endpoint, scan_world.mismatch_id)
    assert endpoint.expected_certificate_id == scan_world.served_certificate_id
    audit = last_audit(web_factory, "endpoint", scan_world.mismatch_id)
    assert audit.action == "endpoint.update" and audit.details["to"] == scan_world.served_certificate_id
    assert audit.details == {
        "field": "expected_certificate_id",
        "from": scan_world.expected_certificate_id,
        "to": scan_world.served_certificate_id,
    }
    with web_factory() as db:  # past snapshots keep the certificate that was expected when they were taken
        snapshots = set(
            db.scalars(select(ScanResult.expected_certificate_id).where(ScanResult.endpoint_id == scan_world.mismatch_id))
        )
        certificates = db.scalar(select(func.count()).select_from(Certificate))
    assert snapshots == {scan_world.expected_certificate_id}
    again = signed_in.post(
        f"/scans/{scan_world.mismatch_id}/expectation",
        data={"certificate_id": str(scan_world.served_certificate_id), "csrf_token": signed_in.fixture_csrf},
        follow_redirects=False,
    )
    assert again.status_code == 303 and len(audits(web_factory, scan_world.mismatch_id)) == 1  # no-op: no audit
    with web_factory() as db:
        assert db.scalar(select(func.count()).select_from(Certificate)) == certificates


def test_manual_endpoint_entry_validates_and_audits(signed_in, web_factory, scan_world):
    bad = signed_in.post(
        "/scans/endpoints",
        data={"host": "https://x/", "port": "0", "sni": "*.x", "csrf_token": signed_in.fixture_csrf},
        headers=HX,
    )
    assert bad.status_code == 422 and {"host", "port", "sni"} <= set(re.findall(r'data-error="(\w+)"', bad.text))
    assert "<html" not in bad.text  # htmx gets the form fragment
    plain = signed_in.post(
        "/scans/endpoints", data={"host": "x y", "port": "70000", "csrf_token": signed_in.fixture_csrf}
    )
    assert plain.status_code == 422 and "<html" in plain.text and 'data-error="host"' in plain.text
    assert 'data-error="port"' in plain.text
    good = signed_in.post(
        "/scans/endpoints",
        data={
            "host": "API.Example.Internal",
            "port": "8443",
            "sni": "",
            "expected_certificate_id": str(scan_world.served_certificate_id),
            "csrf_token": signed_in.fixture_csrf,
        },
        follow_redirects=False,
    )
    assert good.status_code == 303
    created = endpoint_by(web_factory, "api.example.internal", 8443)
    assert created.source == EndpointSource.MANUAL and created.is_active and created.sni is None
    assert created.expected_certificate_id == scan_world.served_certificate_id
    assert good.headers["location"] == f"/scans/{created.id}"
    [audit] = audits(web_factory, created.id)
    assert audit.action == "endpoint.create"
    assert audit.details["to"]["host"] == "api.example.internal" and audit.details["to"]["port"] == 8443


def test_sni_equal_to_the_host_is_stored_as_null_and_a_different_sni_is_kept(signed_in, web_factory):
    same = _post(signed_in, "/scans/endpoints", host="Same.Example.Test", port="443", sni="same.example.test")
    other = _post(signed_in, "/scans/endpoints", host="vhost.example.test", port="443", sni="Name.Example.Test")
    assert same.status_code == other.status_code == 303
    assert endpoint_by(web_factory, "same.example.test", 443).sni is None
    assert endpoint_by(web_factory, "vhost.example.test", 443).sni == "name.example.test"


def test_use_observed_without_an_inventory_match_offers_import(signed_in, web_factory, now):
    endpoint_id, host = _unseen_endpoint(web_factory, now)
    for headers in (None, HX):
        response = _post(signed_in, f"/scans/{endpoint_id}/expectation", headers=headers, use_observed="1")
        assert response.status_code == 422
        assert f"/certificates/import?host={host}&amp;port=443" in response.text
    assert fetch(web_factory, Endpoint, endpoint_id).expected_certificate_id is None
    assert audits(web_factory, endpoint_id) == []
    never = _post(signed_in, f"/scans/{add_endpoint_id(web_factory)}/expectation", use_observed="1")
    assert never.status_code == 422  # nothing observed yet


def add_endpoint_id(web_factory):
    with web_factory.begin() as db:
        return add_endpoint(db, f"fresh-{secrets.token_hex(3)}.example.test")


def test_expectation_requires_an_active_certificate(signed_in, web_factory, scan_world):
    retired = expiring(web_factory, 10)
    with web_factory.begin() as db:
        db.get(Certificate, retired.id).status = CertificateStatus.REVOKED
    target = scan_world.ok_id
    before = fetch(web_factory, Endpoint, target).expected_certificate_id
    for bad in (str(retired.id), "999999999", "", "abc"):
        response = _post(signed_in, f"/scans/{target}/expectation", certificate_id=bad)
        assert response.status_code == 422, bad
    htmx = _post(signed_in, f"/scans/{target}/expectation", headers=HX, certificate_id=str(retired.id))
    assert htmx.status_code == 422 and 'data-error="certificate_id"' in htmx.text and "<html" not in htmx.text
    created = _post(
        signed_in, "/scans/endpoints", host="new.example.test", port="443", expected_certificate_id=str(retired.id)
    )
    assert created.status_code == 422 and endpoint_by(web_factory, "new.example.test", 443) is None
    assert fetch(web_factory, Endpoint, target).expected_certificate_id == before
    assert audits(web_factory, target) == []
    assert _post(signed_in, "/scans/999999999/expectation", use_observed="1").status_code == 404


def test_duplicate_endpoint_identity_links_the_existing_row(signed_in, web_factory, scan_world, db, actor):
    host, sni = scan_world.ok_host, scan_world.ok_sni
    exact = _post(signed_in, "/scans/endpoints", host=host.upper(), port="443", sni=sni)
    assert exact.status_code == 422 and f'href="/scans/{scan_world.ok_id}"' in exact.text
    coalesced = _post(
        signed_in, "/scans/endpoints", headers=HX, host=scan_world.mismatch_host, port="443", sni=scan_world.mismatch_host
    )
    assert coalesced.status_code == 422 and f'href="/scans/{scan_world.mismatch_id}"' in coalesced.text
    with web_factory() as session:
        assert session.scalar(select(func.count()).select_from(Endpoint).where(Endpoint.host == host)) == 1
    # The unique index is the arbiter: the service reports the clash without a racy pre-check.
    first = create_endpoint(db, "race.example.test", 443, None, None, actor)
    with pytest.raises(DuplicateEndpoint) as raised:
        create_endpoint(db, "race.example.test", 443, "race.example.test", None, actor)
    assert raised.value.existing_id == first.id and "host" in raised.value.errors
    with pytest.raises(EndpointInputError):
        create_endpoint(db, "bad host", 443, None, None, actor)


def test_deactivate_and_reactivate_never_delete_history(signed_in, web_factory, scan_world):
    target = scan_world.mismatch_id

    def history():
        with web_factory() as db:
            return db.scalar(select(func.count()).select_from(ScanResult).where(ScanResult.endpoint_id == target))

    before = history()
    off = _post(signed_in, f"/scans/{target}/active", active="false")
    assert off.status_code == 303 and off.headers["location"] == f"/scans/{target}"
    assert not fetch(web_factory, Endpoint, target).is_active
    assert "(inactive)" in signed_in.get("/scans?active=all").text
    assert _post(signed_in, "/scans/run", scope="endpoint", endpoint_id=str(target)).status_code == 422
    assert "Inactive" in signed_in.get(f"/scans/{target}").text
    on = _post(signed_in, f"/scans/{target}/active", active="true")
    assert on.status_code == 303 and fetch(web_factory, Endpoint, target).is_active
    assert history() == before == 25
    updates = audits(web_factory, target)
    assert [a.action for a in updates] == ["endpoint.update"] * 2
    assert [a.details for a in updates] == [
        {"field": "is_active", "from": True, "to": False},
        {"field": "is_active", "from": False, "to": True},
    ]
    assert _post(signed_in, "/scans/999999999/active", active="false").status_code == 404
    for method, path in (("delete", f"/scans/{target}"), ("post", f"/scans/{target}/delete")):
        assert getattr(signed_in, method)(path).status_code in (403, 404, 405)  # no delete route exists
    assert fetch(web_factory, Endpoint, target) is not None


def test_invalid_active_value_rerenders_the_manage_form_without_changes(signed_in, web_factory, scan_world):
    target = scan_world.mismatch_id
    htmx = _post(signed_in, f"/scans/{target}/active", headers=HX, active="maybe")
    assert htmx.status_code == 422 and 'data-error="active"' in htmx.text
    assert 'id="manage-panel"' in htmx.text and "<html" not in htmx.text
    page = _post(signed_in, f"/scans/{target}/active", active="")
    assert page.status_code == 422 and "<html" in page.text and 'data-error="active"' in page.text
    assert fetch(web_factory, Endpoint, target).is_active
    assert audits(web_factory, target) == []
    assert _post(signed_in, "/scans/999999999/active", active="maybe").status_code == 404


def test_observed_certificate_inactive_in_inventory_is_unavailable_not_importable(signed_in, web_factory, now):
    retired = expiring(web_factory, 10)
    with web_factory.begin() as db:
        certificate = db.get(Certificate, retired.id)
        certificate.status = CertificateStatus.REVOKED
        fingerprint, name = certificate.sha256_fingerprint, certificate.common_name
        endpoint_id = add_endpoint(db, f"retired-{secrets.token_hex(3)}.example.test")
        db.add(
            ScanResult(
                endpoint_id=endpoint_id,
                status=ScanStatus.OK,
                observed_fingerprint=fingerprint,
                observed_common_name=name,
                source="scheduled",
                checked_at=now,
            )
        )
    with web_factory() as db:
        certificates_before = db.scalar(select(func.count()).select_from(Certificate))
    page = signed_in.get(f"/scans/{endpoint_id}").text
    assert 'name="use_observed"' not in page  # no enabled success action
    assert "in the inventory but is not active" in page
    assert f'href="/certificates/{retired.id}"' in page
    for headers in (None, HX):
        response = _post(signed_in, f"/scans/{endpoint_id}/expectation", headers=headers, use_observed="1")
        assert response.status_code == 422
        assert "not active" in response.text and "Import the served certificate" not in response.text
    assert fetch(web_factory, Endpoint, endpoint_id).expected_certificate_id is None
    assert audits(web_factory, endpoint_id) == []
    with web_factory() as db:
        assert db.scalar(select(func.count()).select_from(Certificate)) == certificates_before


def test_scans_page_offers_the_management_forms(signed_in, scan_world):
    page = signed_in.get(f"/scans?expected_certificate_id={scan_world.served_certificate_id}")
    assert 'action="/scans/endpoints"' in page.text and 'id="add-endpoint"' in page.text
    assert re.search(rf'<option value="{scan_world.served_certificate_id}" selected', page.text)
    detail = signed_in.get(f"/scans/{scan_world.mismatch_id}").text
    assert f'action="/scans/{scan_world.mismatch_id}/expectation"' in detail
    assert 'name="use_observed" value="1"' in detail
    assert f'action="/scans/{scan_world.mismatch_id}/active"' in detail


def test_certificate_detail_panel_links_history_and_scans_each_endpoint(signed_in, scan_world):
    page = signed_in.get(f"/certificates/{scan_world.expected_certificate_id}").text
    panel = re.search(r'<section[^>]*id="endpoints-panel".*?</section>', page, re.DOTALL).group(0)
    for name in ("mismatch", "expired", "down"):
        assert f'href="/scans/{scan_world.ids[name]}"' in panel
        assert f'href="/scans/{scan_world.ids[name]}#history"' in panel
        assert re.search(
            rf'<form[^>]*method="post" action="/scans/run"[^>]*>\s*<input type="hidden" name="csrf_token" value="[^"]+">\s*'
            rf'<input type="hidden" name="scope" value="endpoint">\s*'
            rf'<input type="hidden" name="endpoint_id" value="{scan_world.ids[name]}">\s*<button type="submit">Scan now</button>',
            panel,
        ), name
    # The inactive endpoint is listed and linked but cannot be scanned.
    assert f'href="/scans/{scan_world.ids["off"]}"' in panel
    assert f'name="endpoint_id" value="{scan_world.ids["off"]}"' not in panel
    assert f'href="/scans?expected_certificate_id={scan_world.expected_certificate_id}#add-endpoint"' in panel
    empty = signed_in.get(f"/certificates/{scan_world.served_certificate_id}").text
    assert "Add endpoint" in empty and "added by a server import" not in empty


def test_every_mutation_requires_csrf_and_is_audited_once(signed_in, web_factory, scan_world):
    target = scan_world.ok_id
    forms = [
        ("/scans/endpoints", {"host": "csrf.example.test", "port": "443"}),
        (f"/scans/{target}/expectation", {"certificate_id": str(scan_world.served_certificate_id)}),
        (f"/scans/{target}/active", {"active": "false"}),
    ]
    for path, fields in forms:
        assert _post(signed_in, path, token=False, **fields).status_code == 403, path
        assert _post(signed_in, path, **{**fields, "csrf_token": "forged"}).status_code == 403, path
    assert endpoint_by(web_factory, "csrf.example.test", 443) is None and audits(web_factory, target) == []
    for path, fields in forms:
        assert _post(signed_in, path, **fields).status_code == 303, path
    created = endpoint_by(web_factory, "csrf.example.test", 443)
    assert [a.action for a in audits(web_factory, created.id)] == ["endpoint.create"]
    assert [a.action for a in audits(web_factory, target)] == ["endpoint.update"] * 2
