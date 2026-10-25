"""Task 17: certificate list, detail and expiry-only overview (real Postgres, real HTTP stack)."""

import re
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from cryptography.hazmat.primitives import serialization
from sqlalchemy import delete, event, select

import app.web.certificates as web_certificates
from app.crypto.chain import order_chain
from app.crypto.parse import parse_certificates
from app.models import (
    AppSetting,
    AuditLog,
    Binding,
    Certificate,
    Endpoint,
    PrivateKey,
    Renewal,
    ScanResult,
    Server,
)
from app.models.enums import (
    CertificateStatus,
    ChainStatus,
    EndpointSource,
    RenewalState,
    ScanStatus,
    WebserverType,
)
from app.services.audit import Actor
from app.services.certificates import (
    CertificateFilters,
    CertificateMetadata,
    diagnose_chain,
    expiry_counts,
    export_certificates,
    list_certificates,
    save_certificate,
)

EXPORT_KEYS = {
    "id",
    "common_name",
    "sans",
    "issuer_cn",
    "serial",
    "not_before",
    "not_after",
    "sha256_fingerprint",
    "status",
    "chain_status",
    "owner_name",
    "owner_email",
    "team",
    "imported_from",
    "renews_id",
    "has_key",
    "binding_count",
}
PLACEHOLDER_PEM = "-----BEGIN CERTIFICATE-----\nZml4dHVyZS1wbGFjZWhvbGRlcg==\n-----END CERTIFICATE-----\n"
ACTOR = Actor(None, "fixture", "192.0.2.1", "fixture-browser")


# --- builders ----------------------------------------------------------------------------------


def _key(session, tag):
    row = PrivateKey(
        key_type="rsa",
        key_size=2048,
        ciphertext=b"fixture-ciphertext-bytes",
        nonce=b"123456789012",
        aad=f"private_key:0:{tag}",
        master_key_version=1,
        public_key_sha256=uuid.uuid4().hex + uuid.uuid4().hex,
        public_key_pem="-----BEGIN PUBLIC KEY-----\nZml4dHVyZQ==\n-----END PUBLIC KEY-----\n",
        origin="imported_pem",
    )
    session.add(row)
    session.flush()
    return row


def _cert(session, common_name, now, *, delta=timedelta(days=20), key=False, **fields):
    not_after = fields.pop("not_after", now + delta)
    row = Certificate(
        common_name=common_name,
        subject_dn=f"CN={common_name}",
        sans=fields.pop("sans", [common_name]),
        issuer_dn=f"CN={fields.get('issuer_cn', 'Fixture CA One')}",
        issuer_cn=fields.pop("issuer_cn", "Fixture CA One"),
        serial=fields.pop("serial", uuid.uuid4().hex),
        not_before=not_after - timedelta(days=90),
        not_after=not_after,
        sha256_fingerprint=fields.pop("sha256_fingerprint", uuid.uuid4().hex + uuid.uuid4().hex),
        pem=PLACEHOLDER_PEM,
        key_id=_key(session, common_name).id if key else None,
        imported_from=fields.pop("imported_from", "upload_pem"),
        **fields,
    )
    session.add(row)
    session.flush()
    return row


def _binding(session, certificate_id, server_id, name, *, active=True, match_state="matched"):
    row = Binding(
        server_id=server_id,
        webserver=WebserverType.NGINX,
        vhost_name=name,
        vhost_names=[name],
        port=443,
        config_file=f"/etc/nginx/{name}.conf",
        cert_path=f"/etc/ssl/{name}.pem",
        key_path=f"/etc/ssl/{name}.key",
        certificate_id=certificate_id,
        match_state=match_state,
        last_seen_at=datetime(2026, 10, 19, tzinfo=UTC),
        is_active=active,
    )
    session.add(row)
    session.flush()
    return row


def _server(session, name=None):
    row = Server(hostname=name or f"srv-{uuid.uuid4().hex[:8]}.example.test", inventory_source="fixture")
    session.add(row)
    session.flush()
    return row


def _build_inventory(session, now):
    """A varied inventory; every distinguishing value is unique so each filter has one right answer."""
    server = _server(session, "web01.example.test")
    www = _cert(
        session,
        "www.infra.example.test",
        now,
        delta=timedelta(days=20),
        key=True,
        sans=["www.infra.example.test", "portal.infra.example.test"],
        serial="aa11bb22",
        sha256_fingerprint="abcdef0123456789" + "0" * 48,
        issuer_cn="Fixture CA One",
        team="infra",
        owner_name="Alice Admin",
        owner_email="alice@example.test",
        notes="<script>alert(1)</script> renew before the audit",
    )
    db = _cert(
        session,
        "db.infra.example.test",
        now,
        delta=timedelta(days=3),
        issuer_cn="Fixture CA Two",
        team="infra",
        owner_name="Bob Builder",
        owner_email="bob@example.test",
    )
    shop = _cert(
        session,
        "shop.sales.example.test",
        now,
        delta=timedelta(days=-2),
        issuer_cn="Fixture CA One",
        team="sales",
        owner_name="Carol",
        owner_email="carol@sales.example.test",
        imported_from="pull_endpoint",
    )
    soon = _cert(session, "mail.ops.example.test", now, delta=timedelta(days=45), key=True, team="ops")
    far = _cert(session, "far.ops.example.test", now, delta=timedelta(days=200), team="ops")
    old = _cert(
        session,
        "old.sales.example.test",
        now,
        delta=timedelta(days=5),
        status=CertificateStatus.SUPERSEDED,
        team="sales",
    )
    bad = _cert(
        session,
        "bad.sales.example.test",
        now,
        delta=timedelta(days=-10),
        status=CertificateStatus.REVOKED,
        team="sales",
    )
    _binding(session, www.id, server.id, "www.infra.example.test")
    _binding(session, www.id, server.id, "portal.infra.example.test")
    _binding(session, www.id, server.id, "retired.infra.example.test", active=False)
    _binding(session, soon.id, server.id, "mail.ops.example.test")
    session.add(
        Renewal(
            previous_certificate_id=www.id,
            state=RenewalState.SUBMITTED,
            common_name=www.common_name,
            sans=list(www.sans),
            key_id=www.key_id,
            state_changed_at=now,
        )
    )
    session.flush()
    return SimpleNamespace(
        www=www.id,
        db=db.id,
        shop=shop.id,
        soon=soon.id,
        far=far.id,
        old=old.id,
        bad=bad.id,
        server=server.id,
        names={
            row.id: row.common_name
            for row in (www, db, shop, soon, far, old, bad)
        },
    )


@pytest.fixture
def db_inventory(db, now):
    return _build_inventory(db, now)


@pytest.fixture(autouse=True)
def _clean_web_inventory(web_factory):
    """The web database is shared by the whole module: start every test from an empty inventory."""
    with web_factory.begin() as session:
        for model in (ScanResult, Endpoint, Binding, Renewal, Certificate, PrivateKey, Server):
            session.execute(delete(model))
        session.execute(delete(AppSetting).where(AppSetting.key == "ui.timezone"))
    yield


@pytest.fixture
def inventory(web_factory, now):
    with web_factory.begin() as session:
        return _build_inventory(session, now)


@pytest.fixture
def inventory_at_boundaries(db, now):
    """Active expiries now-1s, +6d, +7d, +30d, +60d; superseded and revoked rows inside buckets."""
    for index, delta in enumerate(
        [
            timedelta(seconds=-1),
            timedelta(days=6),
            timedelta(days=7),
            timedelta(days=30),
            timedelta(days=60),
        ]
    ):
        _cert(db, f"boundary{index}.example.test", now, delta=delta)
    _cert(db, "gone1.example.test", now, delta=timedelta(days=1), status=CertificateStatus.SUPERSEDED)
    _cert(db, "gone2.example.test", now, delta=timedelta(days=-1), status=CertificateStatus.REVOKED)


@pytest.fixture
def fresh(now):
    from tests.fixtures.certificates import generate_certificates

    return generate_certificates(now)


def _names(page):
    return [row.common_name for row in page.items]


def _real_certificate(web_factory, fresh, now, *, chain=True, **metadata):
    """Persist the fixture leaf (parsed, with real PEM) through the production service."""
    parsed = parse_certificates(fresh.leaf.public_bytes(serialization.Encoding.PEM))[0]
    ordered = order_chain(parsed.cert, list(fresh.intermediates) if chain else [])
    with web_factory.begin() as session:
        result = save_certificate(
            session,
            parsed,
            ordered,
            CertificateMetadata(**metadata),
            ACTOR,
            source="upload_pem",
            validation_time=now,
        )
        return result.certificate.id


def _post(client, path, headers=None, files=None, **fields):
    data = {"csrf_token": client.fixture_csrf, **fields}
    return client.post(path, data=data, files=files, headers=headers, follow_redirects=False)


def _total(html):
    match = re.search(r'data-total="(\d+)"', html)
    assert match, html[:800]
    return int(match.group(1))


def _row_names(html):
    return re.findall(r'data-cn="([^"]+)"', html)


# --- read model: buckets, filters, sorting, pagination ------------------------------------------


def test_expiry_buckets_are_disjoint(db, inventory_at_boundaries, now):
    counts = expiry_counts(db, now)
    assert counts == {"expired": 1, "lt7": 1, "lt30": 1, "lt60": 1, "total_active": 5}


def test_filters_and_no_secret_panels(signed_in, inventory):
    response = signed_in.get("/certificates?has_key=true&team=infra&sort=not_after&page=1")
    assert response.status_code == 200 and "infra" in response.text
    assert "PRIVATE KEY" not in response.text and "ciphertext" not in response.text


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        ({"search": "WWW.infra"}, {"www.infra.example.test"}),
        ({"search": "portal.infra"}, {"www.infra.example.test"}),  # SAN only
        ({"search": "aa11bb"}, {"www.infra.example.test"}),  # serial
        ({"search": "abcdef0123"}, {"www.infra.example.test"}),  # fingerprint prefix
        ({"search": "%"}, set()),  # wildcard characters are literals
        ({"search": "_"}, set()),
        ({"search": "sales.example"}, {"shop.sales.example.test", "old.sales.example.test", "bad.sales.example.test"}),
        ({"status": CertificateStatus.SUPERSEDED}, {"old.sales.example.test"}),
        ({"status": CertificateStatus.REVOKED}, {"bad.sales.example.test"}),
        ({"expiry": "expired"}, {"shop.sales.example.test", "bad.sales.example.test"}),
        ({"expiry": "lt7"}, {"db.infra.example.test", "old.sales.example.test"}),
        ({"expiry": "lt30"}, {"www.infra.example.test"}),
        ({"expiry": "lt60"}, {"mail.ops.example.test"}),
        ({"expiry": "lt7", "status": CertificateStatus.ACTIVE}, {"db.infra.example.test"}),
        ({"issuer": "ca two"}, {"db.infra.example.test"}),
        ({"team": "INFRA"}, {"www.infra.example.test", "db.infra.example.test"}),
        ({"owner": "alice"}, {"www.infra.example.test"}),
        ({"owner": "bob@example"}, {"db.infra.example.test"}),
        ({"has_key": True}, {"www.infra.example.test", "mail.ops.example.test"}),
        (
            {"has_key": False},
            {
                "db.infra.example.test",
                "shop.sales.example.test",
                "far.ops.example.test",
                "old.sales.example.test",
                "bad.sales.example.test",
            },
        ),
        ({"has_bindings": True}, {"www.infra.example.test", "mail.ops.example.test"}),
        ({"renewal_state": RenewalState.SUBMITTED}, {"www.infra.example.test"}),
        ({"renewal_state": RenewalState.ISSUED}, set()),
        ({"team": "infra", "has_key": True}, {"www.infra.example.test"}),
    ],
)
def test_every_filter(db, db_inventory, now, filters, expected):
    page = list_certificates(db, CertificateFilters(**filters), page_size=100, now=now)
    assert set(_names(page)) == expected and page.total == len(expected)


def test_has_bindings_false_excludes_bound_certificates(db, db_inventory, now):
    page = list_certificates(db, CertificateFilters(has_bindings=False), page_size=100, now=now)
    assert "www.infra.example.test" not in _names(page) and "far.ops.example.test" in _names(page)
    assert page.total == 5


def test_binding_count_counts_only_active_bindings(db, db_inventory, now):
    page = list_certificates(db, CertificateFilters(), page_size=100, now=now)
    counts = {row.common_name: row.binding_count for row in page.items}
    assert counts["www.infra.example.test"] == 2 and counts["mail.ops.example.test"] == 1
    assert counts["far.ops.example.test"] == 0


def test_expiry_filter_reproduces_counter_exactly(db, db_inventory, now):
    counts = expiry_counts(db, now)
    for bucket in ("expired", "lt7", "lt30", "lt60"):
        page = list_certificates(
            db, CertificateFilters(expiry=bucket, status=CertificateStatus.ACTIVE), now=now
        )
        assert page.total == counts[bucket], bucket
    active = list_certificates(db, CertificateFilters(status=CertificateStatus.ACTIVE), now=now)
    assert active.total == counts["total_active"]


@pytest.mark.parametrize(
    ("sort", "key", "reverse"),
    [
        ("not_after", lambda row: row.not_after, False),
        ("-not_after", lambda row: row.not_after, True),
        ("common_name", lambda row: row.common_name, False),
        ("-common_name", lambda row: row.common_name, True),
        ("issuer_cn", lambda row: row.issuer_cn, False),
        ("created_at", lambda row: row.created_at, False),
        ("-created_at", lambda row: row.created_at, True),
        ("status", lambda row: ["active", "superseded", "revoked"].index(row.status.value), False),
    ],
)
def test_whitelisted_sorts(db, db_inventory, now, sort, key, reverse):
    rows = list_certificates(db, CertificateFilters(), page_size=100, sort=sort, now=now).items
    assert len(rows) == 7
    keys = [key(row) for row in rows]
    assert keys == sorted(keys, reverse=reverse)


def test_unknown_sort_is_rejected(db, now):
    for sort in ("serial", "pem", "not_after; drop table certificate", "--not_after", ""):
        with pytest.raises(ValueError):
            list_certificates(db, CertificateFilters(), sort=sort, now=now)


def test_paging_is_stable_with_ties_and_reports_total(db, db_inventory, now):
    _cert(db, "tie1.example.test", now, not_after=now + timedelta(days=500))
    _cert(db, "tie2.example.test", now, not_after=now + timedelta(days=500))
    seen = []
    for number in (1, 2, 3, 4, 5):
        page = list_certificates(db, CertificateFilters(), page=number, page_size=2, sort="not_after", now=now)
        assert page.total == 9 and page.page == number and page.page_size == 2
        seen.extend(row.id for row in page.items)
    assert len(seen) == 9 and len(set(seen)) == 9
    assert list_certificates(db, CertificateFilters(), page=6, page_size=2, now=now).items == []


@pytest.mark.parametrize(("page", "size"), [(0, 50), (-1, 50), (1, 0), (1, 101), (1, 5000), (1, 5001)])
def test_service_rejects_bad_paging(db, page, size):
    with pytest.raises(ValueError):
        list_certificates(db, CertificateFilters(), page=page, page_size=size)


def test_service_accepts_the_inclusive_page_size_limits(db, db_inventory, now):
    assert len(list_certificates(db, CertificateFilters(), page_size=1, now=now).items) == 1
    assert list_certificates(db, CertificateFilters(), page_size=100, now=now).page_size == 100


def test_export_service_is_distinct_from_the_page_api_and_capped(db, db_inventory, now):
    everything = export_certificates(db, CertificateFilters(), sort="common_name", now=now)
    assert everything.total == 7 and len(everything.items) == 7
    assert [row.common_name for row in everything.items] == sorted(row.common_name for row in everything.items)
    capped = export_certificates(db, CertificateFilters(), now=now, limit=2)
    assert capped.total == 7 and len(capped.items) == 2
    for bad in (0, 5001):
        with pytest.raises(ValueError):
            export_certificates(db, CertificateFilters(), now=now, limit=bad)


def test_search_input_longer_than_200_characters_is_rejected(db):
    with pytest.raises(ValueError):
        list_certificates(db, CertificateFilters(search="a" * 201))


# --- list screen --------------------------------------------------------------------------------


def test_list_requires_a_session(client):
    assert client.get("/certificates", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/certificates/export.json", follow_redirects=False).status_code == 303


def test_list_shows_all_columns_and_chips(signed_in, inventory):
    page = signed_in.get("/certificates?sort=common_name&page_size=100")
    assert page.status_code == 200 and _total(page.text) == 7
    for text in ("Common name", "SANs", "Issuer", "Expires", "Owner", "Status", "Source", "Key", "Bindings"):
        assert f">{text}<" in page.text, text
    row = re.search(r'<tr data-cn="www.infra.example.test".*?</tr>', page.text, re.DOTALL).group(0)
    assert "Fixture CA One" in row and "Alice Admin" in row and "infra" in row
    assert "20 days" in row and "yes" in row.lower()
    assert f'href="/certificates/{inventory.www}"' in row
    expired = re.search(r'<tr data-cn="shop.sales.example.test".*?</tr>', page.text, re.DOTALL).group(0)
    assert "expired" in expired.lower() and "chip-expired" in expired


def test_list_filters_over_http(signed_in, inventory):
    page = signed_in.get("/certificates?team=infra&has_key=true")
    assert _row_names(page.text) == ["www.infra.example.test"]
    page = signed_in.get("/certificates?status=active&expiry=lt7")
    assert _row_names(page.text) == ["db.infra.example.test"]
    page = signed_in.get("/certificates?renewal_state=submitted")
    assert _row_names(page.text) == ["www.infra.example.test"]
    page = signed_in.get("/certificates?search=portal.infra&owner=alice&issuer=one&has_bindings=true")
    assert _row_names(page.text) == ["www.infra.example.test"]


def test_non_js_filter_form_submits_blank_fields_as_no_filter(signed_in, inventory):
    query = (
        "search=&status=&expiry=&issuer=&team=&owner=&has_key=&has_bindings=&renewal_state="
        "&sort=not_after&page=1&page_size=50"
    )
    page = signed_in.get(f"/certificates?{query}")
    assert page.status_code == 200 and _total(page.text) == 7
    assert '<form method="get" action="/certificates"' in page.text


@pytest.mark.parametrize(
    "query",
    [
        "status=bogus",
        "expiry=lt90",
        "has_key=maybe",
        "has_bindings=2",
        "renewal_state=bogus",
        "sort=serial",
        "sort=pem",
        "page=0",
        "page=abc",
        "page_size=0",
        "page_size=101",
        "page_size=-5",
        "search=" + "a" * 201,
        "team=" + "a" * 201,
    ],
)
def test_invalid_query_values_are_422(signed_in, inventory, query):
    assert signed_in.get(f"/certificates?{query}").status_code == 422
    assert signed_in.get(f"/certificates/export.json?{query}").status_code == 422


def test_page_size_limits_are_inclusive(signed_in, inventory):
    assert signed_in.get("/certificates?page_size=1").status_code == 200
    assert signed_in.get("/certificates?page_size=100").status_code == 200


def test_pagination_links_keep_the_filters_and_sort(signed_in, inventory):
    page = signed_in.get("/certificates?page_size=2&sort=-not_after&status=active")
    assert _total(page.text) == 5 and len(_row_names(page.text)) == 2
    assert "page=2" in page.text and "sort=-not_after" in page.text and "status=active" in page.text
    second = signed_in.get("/certificates?page_size=2&sort=-not_after&status=active&page=3")
    assert len(_row_names(second.text)) == 1
    assert "page=2" in second.text  # previous link


def test_list_query_count_does_not_depend_on_row_count(signed_in, web_factory, now):
    engine = web_factory.kw["bind"]

    def statements():
        seen = []

        def count(conn, cursor, statement, parameters, context, executemany):
            seen.append(statement)

        event.listen(engine, "before_cursor_execute", count)
        try:
            assert signed_in.get("/certificates?page_size=100").status_code == 200
        finally:
            event.remove(engine, "before_cursor_execute", count)
        return len(seen)

    with web_factory.begin() as session:
        server = _server(session)
        for index in range(3):
            row = _cert(session, f"few{index}.example.test", now, key=True)
            _binding(session, row.id, server.id, f"few{index}.example.test")
    signed_in.get("/certificates")  # warm-up: first request on a pooled connection
    few = statements()
    with web_factory.begin() as session:
        server = _server(session)
        for index in range(27):
            row = _cert(session, f"many{index}.example.test", now, key=True)
            _binding(session, row.id, server.id, f"many{index}.example.test")
            _binding(session, row.id, server.id, f"alt{index}.example.test")
    many = statements()
    assert few == many


def test_list_escapes_hostile_values(signed_in, web_factory, now):
    with web_factory.begin() as session:
        _cert(session, "<script>x</script>.example.test", now, team="<img src=x onerror=1>")
    page = signed_in.get("/certificates")
    assert "<script>x</script>" not in page.text and "<img src=x" not in page.text
    assert "&lt;script&gt;" in page.text


# --- JSON export --------------------------------------------------------------------------------


def test_export_uses_an_explicit_allowlist(signed_in, inventory, now):
    response = signed_in.get("/certificates/export.json?sort=common_name")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"] == 'attachment; filename="certificates.json"'
    assert "no-store" in response.headers["cache-control"]
    body = response.json()
    assert body["total"] == 7 and body["truncated"] is False and len(body["certificates"]) == 7
    for item in body["certificates"]:
        assert set(item) == EXPORT_KEYS
    www = next(item for item in body["certificates"] if item["id"] == inventory.www)
    assert www["not_after"] == (now + timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert www["has_key"] is True and www["binding_count"] == 2
    assert www["sans"] == ["www.infra.example.test", "portal.infra.example.test"]
    assert www["team"] == "infra" and www["status"] == "active" and www["chain_status"] == "unchecked"
    for forbidden in ("BEGIN", "PRIVATE", "ciphertext", "key_id", "alert(1)", "renew before"):
        assert forbidden not in response.text


def test_export_applies_the_list_filters_and_sort(signed_in, inventory):
    body = signed_in.get("/certificates/export.json?team=infra&sort=-not_after").json()
    assert [item["common_name"] for item in body["certificates"]] == [
        "www.infra.example.test",
        "db.infra.example.test",
    ]
    assert body["total"] == 2


def test_export_is_capped_and_reports_truncation(signed_in, inventory, monkeypatch):
    monkeypatch.setattr(web_certificates, "EXPORT_LIMIT", 2)
    body = signed_in.get("/certificates/export.json").json()
    assert len(body["certificates"]) == 2 and body["total"] == 7 and body["truncated"] is True


# --- Overview -----------------------------------------------------------------------------------


def test_overview_counters_link_to_the_exact_list_ranges(signed_in, inventory, web_factory, now):
    page = signed_in.get("/")
    assert page.status_code == 200
    with web_factory() as session:
        counts = expiry_counts(session, now)
    assert counts == {"expired": 1, "lt7": 1, "lt30": 1, "lt60": 1, "total_active": 5}
    links = {
        "expired": "/certificates?expiry=expired&amp;status=active",
        "lt7": "/certificates?expiry=lt7&amp;status=active",
        "lt30": "/certificates?expiry=lt30&amp;status=active",
        "lt60": "/certificates?expiry=lt60&amp;status=active",
        "total_active": "/certificates?status=active",
    }
    for name, href in links.items():
        match = re.search(rf'<a[^>]*data-counter="{name}"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', page.text, re.DOTALL)
        assert match, name
        assert match.group(1) == href
        assert str(counts[name]) in match.group(2)
        listed = signed_in.get(match.group(1).replace("&amp;", "&"))
        assert _total(listed.text) == counts[name], name


def test_overview_empty_state_offers_setup_links(signed_in):
    page = signed_in.get("/")
    assert page.status_code == 200 and 'data-empty-state="setup"' in page.text
    assert 'href="/certificates/import"' in page.text
    assert "SMTP" in page.text and "inventory" in page.text.lower()
    assert page.text.count('data-counter="') == 5


def test_overview_hides_the_checklist_once_certificates_exist(signed_in, inventory):
    assert 'data-empty-state="setup"' not in signed_in.get("/").text


def test_overview_has_no_tls_or_job_summaries_yet(signed_in, inventory):
    text = signed_in.get("/").text
    for absent in ("Recent jobs", "TLS health", "Renewals in flight"):
        assert absent not in text


def test_navigation_enables_implemented_areas_only(signed_in):
    text = signed_in.get("/").text
    assert '<a href="/">Overview</a>' in text and '<a href="/certificates">Certificates</a>' in text
    reasons = {
        "Servers": "Available in a later plan",
        "Deploy": "handler deploy/default not registered (Plan 3)",
        "Scans": "handler scan/default not registered (Plan 2)",
    }
    for label, reason in reasons.items():
        assert re.search(rf'<span aria-disabled="true" title="{re.escape(reason)}">{label}</span>', text), label
    assert '<a href="/audit">Audit</a>' in text
    assert '<a href="/settings">Settings</a>' in text


# --- datetimes ----------------------------------------------------------------------------------


def test_datetimes_emit_utc_machine_value_and_local_display(signed_in, inventory, web_factory, now):
    with web_factory.begin() as session:
        session.add(AppSetting(key="ui.timezone", value="Europe/Rome"))
    expected = now + timedelta(days=20)
    page = signed_in.get(f"/certificates/{inventory.www}")
    iso = expected.strftime("%Y-%m-%dT%H:%M:%SZ")
    local = expected.astimezone(ZoneInfo("Europe/Rome")).strftime("%Y-%m-%d %H:%M")
    assert re.search(rf'<time datetime="{iso}"[^>]*>{local} CE', page.text)


def test_unknown_timezone_falls_back_to_utc(signed_in, inventory, web_factory, now):
    with web_factory.begin() as session:
        session.add(AppSetting(key="ui.timezone", value="Mars/Olympus"))
    expected = now + timedelta(days=20)
    page = signed_in.get(f"/certificates/{inventory.www}")
    assert f'>{expected.strftime("%Y-%m-%d %H:%M")} UTC</time>' in page.text


# --- detail -------------------------------------------------------------------------------------


def test_detail_unknown_certificate_is_404(signed_in, inventory):
    assert signed_in.get("/certificates/999999999").status_code == 404
    assert signed_in.get("/certificates/abc").status_code in (404, 422)


def test_detail_shows_public_fields_and_escapes_notes(signed_in, inventory):
    page = signed_in.get(f"/certificates/{inventory.www}")
    assert page.status_code == 200
    for expected in (
        "www.infra.example.test",
        "portal.infra.example.test",
        "Fixture CA One",
        "aa11bb22",
        "abcdef0123456789",
        "Alice Admin",
        "alice@example.test",
        "infra",
        "upload_pem",
        "unchecked",
    ):
        assert expected in page.text, expected
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert "BEGIN CERTIFICATE" not in page.text and "PRIVATE KEY" not in page.text


def test_detail_key_panel_shows_metadata_only(signed_in, inventory, web_factory):
    with web_factory() as session:
        key = session.scalar(select(PrivateKey).join(Certificate, Certificate.key_id == PrivateKey.id).where(
            Certificate.id == inventory.www
        ))
        fingerprint = key.public_key_sha256
    page = signed_in.get(f"/certificates/{inventory.www}")
    panel = re.search(r'<section[^>]*id="key-panel".*?</section>', page.text, re.DOTALL).group(0)
    assert "RSA" in panel and "2048" in panel and fingerprint in panel
    assert "Key present" in panel and "Master key version" in panel
    for secret in ("ciphertext", "fixture-ciphertext-bytes", "private_key:", "nonce", "BEGIN"):
        assert secret not in page.text, secret


def test_detail_without_key_says_so(signed_in, inventory):
    page = signed_in.get(f"/certificates/{inventory.db}")
    panel = re.search(r'<section[^>]*id="key-panel".*?</section>', page.text, re.DOTALL).group(0)
    assert "No private key" in panel


def test_detail_lineage_breadcrumb_links_previous_and_next(signed_in, web_factory, now):
    with web_factory.begin() as session:
        first = _cert(session, "first.example.test", now, status=CertificateStatus.SUPERSEDED)
        second = _cert(session, "second.example.test", now, renews_id=first.id)
        third = _cert(session, "third.example.test", now, renews_id=second.id)
        ids = (first.id, second.id, third.id)
    page = signed_in.get(f"/certificates/{ids[1]}")
    crumbs = re.search(r'<nav[^>]*aria-label="Lineage".*?</nav>', page.text, re.DOTALL).group(0)
    assert f'href="/certificates/{ids[0]}"' in crumbs and "first.example.test" in crumbs
    assert f'href="/certificates/{ids[2]}"' in crumbs and "third.example.test" in crumbs
    root = signed_in.get(f"/certificates/{ids[0]}")
    assert "No previous certificate" in root.text


def test_detail_history_lists_renewals_and_recent_audit_rows(signed_in, inventory, web_factory, now):
    with web_factory.begin() as session:
        for index in range(60):  # only the newest 50 are listed
            session.add(
                AuditLog(
                    actor_label=f"actor-{index:02d}",
                    action="certificate.update",
                    target_type="certificate",
                    target_id=str(inventory.www),
                    details={},
                    created_at=now + timedelta(seconds=index),
                )
            )
        session.add(
            AuditLog(
                actor_label="someone-else",
                action="certificate.update",
                target_type="certificate",
                target_id=str(inventory.db),
                details={},
            )
        )
    page = signed_in.get(f"/certificates/{inventory.www}")
    history = re.search(r'<section[^>]*id="history-panel".*?</section>', page.text, re.DOTALL).group(0)
    assert "submitted" in history  # the renewal row
    assert history.count("certificate.update") == 50
    assert "actor-59" in history and "actor-09" not in history and "someone-else" not in history


def test_detail_bindings_and_endpoints_panels_are_read_only(signed_in, inventory, web_factory):
    with web_factory.begin() as session:
        session.add(
            Endpoint(
                host="www.infra.example.test",
                port=443,
                source=EndpointSource.MANUAL,
                expected_certificate_id=inventory.www,
            )
        )
    page = signed_in.get(f"/certificates/{inventory.www}")
    bindings = re.search(r'<section[^>]*id="bindings-panel".*?</section>', page.text, re.DOTALL).group(0)
    assert "web01.example.test" in bindings and "/etc/ssl/www.infra.example.test.pem" in bindings
    assert "<form" not in bindings and "retired.infra.example.test" in bindings
    endpoints = re.search(r'<section[^>]*id="endpoints-panel".*?</section>', page.text, re.DOTALL).group(0)
    assert "www.infra.example.test:443" in endpoints and "<form" not in endpoints


def _row_for(panel, needle):
    for row in re.findall(r"<tr[^>]*>.*?</tr>", panel, re.DOTALL):
        if needle in row:
            return row
    raise AssertionError(f"no row mentions {needle}")


def test_detail_marks_only_real_binding_mismatches_red(signed_in, inventory, web_factory):
    with web_factory.begin() as session:
        _binding(session, inventory.www, inventory.server, "broken.infra.example.test", match_state="key_mismatch")
        _binding(session, inventory.www, inventory.server, "gone.infra.example.test", match_state="missing_file")
    page = signed_in.get(f"/certificates/{inventory.www}")
    panel = re.search(r'<section[^>]*id="bindings-panel".*?</section>', page.text, re.DOTALL).group(0)
    normal = _row_for(panel, "/etc/ssl/portal.infra.example.test.pem")
    assert "matched" in normal and "row-attention" not in normal
    for name, state in (("broken", "key_mismatch"), ("gone", "missing_file")):
        row = _row_for(panel, f"/etc/ssl/{name}.infra.example.test.pem")
        assert 'class="row-attention"' in row and state in row
    assert "row-attention" not in _row_for(panel, "/etc/ssl/retired.infra.example.test.pem")


def _endpoint(session, certificate_id, host):
    row = Endpoint(host=host, port=443, source=EndpointSource.MANUAL, expected_certificate_id=certificate_id)
    session.add(row)
    session.flush()
    return row


def _scan(session, endpoint, status, checked_at, **fields):
    session.add(ScanResult(endpoint_id=endpoint.id, status=status, source="fixture", checked_at=checked_at, **fields))
    endpoint.last_scan_status = status
    endpoint.last_scan_at = checked_at
    session.flush()


def _endpoints_panel(client, certificate_id):
    page = client.get(f"/certificates/{certificate_id}")
    return re.search(r'<section[^>]*id="endpoints-panel".*?</section>', page.text, re.DOTALL).group(0)


def test_endpoints_panel_shows_expected_against_the_matching_observed_certificate(
    signed_in, inventory, web_factory, now
):
    expected = "abcdef0123456789" + "0" * 48
    with web_factory.begin() as session:
        endpoint = _endpoint(session, inventory.www, "ok.infra.example.test")
        _scan(
            session,
            endpoint,
            ScanStatus.OK,
            now,
            observed_fingerprint=expected,
            observed_common_name="www.infra.example.test",
            observed_issuer_cn="Fixture CA One",
            observed_not_after=now + timedelta(days=20),
        )
    row = _row_for(_endpoints_panel(signed_in, inventory.www), "ok.infra.example.test")
    assert "Expected" in row and "Observed" in row
    assert row.count(expected) >= 2 and "row-attention" not in row


def test_endpoints_panel_flags_an_observed_certificate_that_differs(signed_in, inventory, web_factory, now):
    other = "f" * 64
    with web_factory.begin() as session:
        endpoint = _endpoint(session, inventory.www, "drift.infra.example.test")
        _scan(session, endpoint, ScanStatus.OK, now - timedelta(days=1), observed_fingerprint="1" * 64)
        _scan(
            session,
            endpoint,
            ScanStatus.MISMATCH,
            now,
            observed_fingerprint=other,
            observed_common_name="other.example.test",
            observed_issuer_cn="Rogue CA",
        )
    row = _row_for(_endpoints_panel(signed_in, inventory.www), "drift.infra.example.test")
    assert 'class="row-attention"' in row and "mismatch" in row
    assert other in row and "other.example.test" in row and "Rogue CA" in row  # latest scan only
    assert "1" * 64 not in row
    assert "abcdef0123456789" + "0" * 48 in row  # expected side


SENSITIVE_DIAGNOSTIC = (
    "handshake failed password=SYNTHETIC-SECRET-TOKEN "
    "-----BEGIN PRIVATE KEY-----SYNTHETIC-SECRET-TOKEN-----END PRIVATE KEY----- <b>x</b>"
)


def test_endpoints_panel_without_an_observation_says_so(signed_in, inventory, web_factory, now):
    with web_factory.begin() as session:
        _endpoint(session, inventory.www, "never.infra.example.test")
        down = _endpoint(session, inventory.www, "down.infra.example.test")
        _scan(session, down, ScanStatus.UNREACHABLE, now, error=SENSITIVE_DIAGNOSTIC)
    panel = _endpoints_panel(signed_in, inventory.www)
    never = _row_for(panel, "never.infra.example.test")
    assert "not scanned yet" in never and "row-attention" not in never
    unreachable = _row_for(panel, "down.infra.example.test")
    assert "unreachable" in unreachable and "No certificate observed" in unreachable
    for fragment in ("SYNTHETIC-SECRET-TOKEN", "BEGIN PRIVATE KEY", "handshake failed", "<b>x</b>"):
        assert fragment not in unreachable
        assert fragment not in signed_in.get(f"/certificates/{inventory.www}").text
    assert "<form" not in panel and "<button" not in panel


def test_detail_empty_panels_have_explanatory_text(signed_in, inventory):
    page = signed_in.get(f"/certificates/{inventory.far}")
    assert "No bindings recorded" in page.text and "No endpoints" in page.text


def test_detail_download_and_export_actions_are_live_and_other_buttons_are_placeholders(signed_in, inventory):
    page = signed_in.get(f"/certificates/{inventory.www}")
    # Task 20 replaced the Download placeholder with audited downloads and the PFX export entry.
    assert f'href="/certificates/{inventory.www}/leaf.pem"' in page.text
    assert not re.search(r'<button[^>]*disabled[^>]*>[^<]*Download certificate', page.text)
    assert "Available after Task 20" not in page.text
    # Task 19 enabled the renewal wizard entry point for active certificates.
    assert f'href="/renewals/new?from={inventory.www}"' in page.text
    assert not re.search(r'<button[^>]*disabled[^>]*>[^<]*Renew', page.text)
    reasons = {
        "Deploy": "handler deploy/default not registered (Plan 3)",
        "Scan now": "handler scan/default not registered (Plan 2)",
    }
    for label, reason in reasons.items():
        assert re.search(
            rf'<button type="button" disabled title="{re.escape(reason)}">{label}</button>', page.text
        ), label
    actions = page.text.split('id="actions-panel"', 1)[1].split("</section>", 1)[0]
    assert "Available in a later plan" not in actions


def test_detail_validation_panel_names_missing_issuer_and_links_trust_anchors(
    signed_in, web_factory, fresh, now
):
    certificate_id = _real_certificate(web_factory, fresh, now, chain=False)
    page = signed_in.get(f"/certificates/{certificate_id}")
    panel = re.search(r'<section[^>]*id="validation-panel".*?</section>', page.text, re.DOTALL).group(0)
    assert "incomplete" in panel
    assert "issuer certificate is missing" in panel.lower() and "Fixture Intermediate 2" in panel
    assert 'href="/settings?tab=trust"' in panel
    assert "leaf.example.test" in page.text and "fixture@example.test" in page.text


def test_detail_reports_the_current_assessment_when_the_diagnostic_root_is_gone(
    signed_in, web_factory, fresh, now
):
    """Stored chains omit roots: after import the cached untrusted_root cannot be re-derived (spec 5.8)."""
    certificate_id = _real_certificate(web_factory, fresh, now)
    chain = b"".join(
        cert.public_bytes(serialization.Encoding.PEM) for cert in (*fresh.intermediates, fresh.root)
    )
    response = _post(signed_in, f"/certificates/{certificate_id}/chain", chain_text=chain.decode())
    assert response.status_code == 303
    with web_factory() as session:
        row = session.get(Certificate, certificate_id)
        assert row.chain_status == ChainStatus.UNTRUSTED_ROOT
        diagnostics = diagnose_chain(session, row, now)
    assert diagnostics.status == ChainStatus.INCOMPLETE  # the actual current assessment
    assert "missing_issuer" in diagnostics.messages
    assert not any(message.startswith("root:") or message == "untrusted_root" for message in diagnostics.messages)
    page = signed_in.get(f"/certificates/{certificate_id}")
    panel = re.search(r'<section[^>]*id="validation-panel".*?</section>', page.text, re.DOTALL).group(0)
    assert "cached status (untrusted_root)" in panel and "current assessment (incomplete)" in panel
    assert "not a configured trust anchor" not in panel  # nothing is claimed about a root we cannot see
    assert "issuer certificate is missing" in panel.lower()
    assert 'href="/settings?tab=trust"' in panel


def test_detail_validation_recomputes_at_render_time(signed_in, web_factory, fresh, now):
    certificate_id = _real_certificate(web_factory, fresh, now)
    with web_factory.begin() as session:
        session.get(Certificate, certificate_id).chain_status = ChainStatus.TRUSTED  # stale cache
    page = signed_in.get(f"/certificates/{certificate_id}")
    panel = re.search(r'<section[^>]*id="validation-panel".*?</section>', page.text, re.DOTALL).group(0)
    assert "trusted" in panel and "differs" in panel.lower()


def test_detail_tolerates_an_unparseable_stored_certificate(signed_in, inventory):
    page = signed_in.get(f"/certificates/{inventory.db}")  # placeholder PEM cannot be parsed
    assert page.status_code == 200 and "could not be re-checked" in page.text.lower()


# --- mutations ----------------------------------------------------------------------------------


def _certificate(factory, certificate_id):
    with factory() as session:
        return session.get(Certificate, certificate_id)


def _audits(factory, action, certificate_id):
    with factory() as session:
        return session.scalars(
            select(AuditLog).where(AuditLog.action == action, AuditLog.target_id == str(certificate_id))
        ).all()


def test_edit_page_renders_the_current_values(signed_in, inventory):
    page = signed_in.get(f"/certificates/{inventory.www}/edit")
    assert page.status_code == 200
    assert f'value="{signed_in.fixture_csrf}"' in page.text
    assert 'value="Alice Admin"' in page.text and 'value="infra"' in page.text
    assert f'action="/certificates/{inventory.www}/edit"' in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text


def test_edit_updates_metadata_with_an_audit_row(signed_in, inventory, web_factory):
    response = _post(
        signed_in,
        f"/certificates/{inventory.www}/edit",
        owner_name="Zed",
        owner_email="zed@example.test",
        team="platform",
        notes="rotated",
    )
    assert response.status_code == 303 and response.headers["location"] == f"/certificates/{inventory.www}"
    row = _certificate(web_factory, inventory.www)
    assert (row.owner_name, row.owner_email, row.team, row.notes) == ("Zed", "zed@example.test", "platform", "rotated")
    assert len(_audits(web_factory, "certificate.update", inventory.www)) == 1


def test_edit_rejects_an_invalid_email_and_keeps_the_input(signed_in, inventory, web_factory):
    response = _post(
        signed_in,
        f"/certificates/{inventory.www}/edit",
        owner_name="Zed",
        owner_email="not-an-email",
        team="platform",
        notes="rotated",
    )
    assert response.status_code == 422
    assert "owner_email must be an email address" in response.text
    assert 'value="Zed"' in response.text and 'value="platform"' in response.text
    assert _certificate(web_factory, inventory.www).owner_name == "Alice Admin"
    assert _audits(web_factory, "certificate.update", inventory.www) == []


def test_edit_via_htmx_returns_a_fragment_on_error_and_hx_redirect_on_success(signed_in, inventory):
    headers = {"HX-Request": "true"}
    bad = _post(signed_in, f"/certificates/{inventory.www}/edit", headers, owner_email="nope")
    assert bad.status_code == 422 and "<html" not in bad.text and "owner_email must be" in bad.text
    ok = _post(signed_in, f"/certificates/{inventory.www}/edit", headers, owner_email="ok@example.test")
    assert ok.status_code == 200 and ok.headers["HX-Redirect"] == f"/certificates/{inventory.www}"


def test_edit_unknown_certificate_is_404(signed_in, inventory):
    assert signed_in.get("/certificates/999999999/edit").status_code == 404
    assert _post(signed_in, "/certificates/999999999/edit", team="x").status_code == 404


def test_mutations_require_csrf(signed_in, inventory):
    for action in ("edit", "status", "chain"):
        response = signed_in.post(
            f"/certificates/{inventory.www}/{action}", data={"team": "x"}, follow_redirects=False
        )
        assert response.status_code == 403, action


def test_status_change_requires_a_reason(signed_in, inventory, web_factory):
    path = f"/certificates/{inventory.www}/status"
    for reason in ("", "   "):
        response = _post(signed_in, path, status="superseded", reason=reason)
        assert response.status_code == 422 and "reason" in response.text.lower()
    assert _certificate(web_factory, inventory.www).status == CertificateStatus.ACTIVE
    assert _audits(web_factory, "certificate.status_change", inventory.www) == []


def test_status_change_succeeds_and_is_audited(signed_in, inventory, web_factory):
    response = _post(
        signed_in, f"/certificates/{inventory.www}/status", status="superseded", reason="replaced by 2027 cert"
    )
    assert response.status_code == 303
    assert _certificate(web_factory, inventory.www).status == CertificateStatus.SUPERSEDED
    (audit,) = _audits(web_factory, "certificate.status_change", inventory.www)
    assert audit.details == {"from": "active", "to": "superseded", "reason": "replaced by 2027 cert"}
    assert "superseded" in signed_in.get(f"/certificates/{inventory.www}").text


@pytest.mark.parametrize(
    ("target", "status"), [("revoked", "active"), ("revoked", "bogus"), ("revoked", "superseded"), ("active", "active")]
)
def test_status_change_rejects_illegal_transitions(signed_in, inventory, web_factory, target, status):
    certificate_id = inventory.bad if target == "revoked" else inventory.www
    response = _post(signed_in, f"/certificates/{certificate_id}/status", status=status, reason="because")
    assert response.status_code == 422
    assert _audits(web_factory, "certificate.status_change", certificate_id) == []


def test_status_form_is_hidden_for_revoked_certificates(signed_in, inventory):
    assert f'action="/certificates/{inventory.bad}/status"' not in signed_in.get(
        f"/certificates/{inventory.bad}"
    ).text
    assert f'action="/certificates/{inventory.www}/status"' in signed_in.get(
        f"/certificates/{inventory.www}"
    ).text


def test_status_failure_via_htmx_returns_the_status_fragment(signed_in, inventory):
    response = _post(
        signed_in,
        f"/certificates/{inventory.www}/status",
        {"HX-Request": "true"},
        status="revoked",
        reason="",
    )
    assert response.status_code == 422 and "<html" not in response.text and "reason" in response.text.lower()


def test_chain_import_by_paste_updates_chain_and_status(signed_in, web_factory, fresh, now):
    certificate_id = _real_certificate(web_factory, fresh, now, chain=False)
    assert _certificate(web_factory, certificate_id).chain_pem == ""
    response = _post(
        signed_in, f"/certificates/{certificate_id}/chain", chain_text=fresh.chain_pem.decode()
    )
    assert response.status_code == 303
    row = _certificate(web_factory, certificate_id)
    assert row.chain_pem.count("BEGIN CERTIFICATE") == 2
    assert len(_audits(web_factory, "certificate.chain_upload", certificate_id)) == 1


def test_chain_import_by_file_upload(signed_in, web_factory, fresh, now):
    certificate_id = _real_certificate(web_factory, fresh, now, chain=False)
    response = _post(
        signed_in,
        f"/certificates/{certificate_id}/chain",
        files={"chain_file": ("chain.pem", fresh.chain_pem)},
    )
    assert response.status_code == 303
    assert _certificate(web_factory, certificate_id).chain_pem.count("BEGIN CERTIFICATE") == 2


@pytest.mark.parametrize("fields", [{}, {"chain_text": "   "}, {"chain_text": "not a certificate"}])
def test_chain_import_rejects_empty_or_invalid_input(signed_in, web_factory, fresh, now, fields):
    certificate_id = _real_certificate(web_factory, fresh, now, chain=False)
    response = _post(signed_in, f"/certificates/{certificate_id}/chain", **fields)
    assert response.status_code == 422 and 'data-field="chain"' in response.text
    assert _certificate(web_factory, certificate_id).chain_pem == ""
    assert _audits(web_factory, "certificate.chain_upload", certificate_id) == []


def test_chain_import_rejects_input_over_one_mebibyte(signed_in, web_factory, fresh, now):
    certificate_id = _real_certificate(web_factory, fresh, now, chain=False)
    response = _post(
        signed_in,
        f"/certificates/{certificate_id}/chain",
        files={"chain_file": ("chain.pem", b"x" * (1_048_576 + 1))},
    )
    assert response.status_code == 422 and "1 MiB" in response.text
    assert _audits(web_factory, "certificate.chain_upload", certificate_id) == []


def test_chain_import_unknown_certificate_is_404(signed_in, inventory):
    assert _post(signed_in, "/certificates/999999999/chain", chain_text="x").status_code == 404
