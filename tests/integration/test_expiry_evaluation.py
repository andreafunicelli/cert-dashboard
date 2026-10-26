"""Expiry evaluation, recipients and rendered alert mail (§7.4) against real PostgreSQL."""

import itertools
import re
import uuid
from datetime import timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import event, select

from app.models import AppSetting, Binding, Certificate, NotificationLog, PrivateKey, Renewal, Server
from app.models.enums import CertificateStatus, NotificationStatus, RenewalState, WebserverType
from app.services.alerts import (
    ExpiryCandidate,
    due_expiry_alerts,
    email_environment,
    render_expiry,
)

_counter = itertools.count(1)


def add_cert(db, now, days, *, cn="www.example.test", status=CertificateStatus.ACTIVE, **overrides):
    n = next(_counter)
    values = {
        "common_name": cn,
        "subject_dn": f"CN={cn}",
        "sans": [cn, f"alt{n}.example.test"],
        "issuer_dn": "CN=Fixture CA,O=Example",
        "issuer_cn": "Fixture CA",
        "serial": f"{n:040x}",
        "not_before": now - timedelta(days=300),
        "not_after": now + timedelta(days=days),
        "sha256_fingerprint": f"{n:064x}",
        "pem": "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
        "status": status,
        "imported_from": "upload_pem",
    }
    cert = Certificate(**{**values, **overrides})
    db.add(cert)
    db.flush()
    return cert


def add_log(db, cert, threshold, status, key):
    db.add(
        NotificationLog(
            certificate_id=cert.id,
            kind="expiry",
            threshold_days=threshold,
            recipients=["a@example.test"],
            status=status,
            dedupe_key=key,
        )
    )
    db.flush()


def candidate_for(cert, threshold=30, days=29, recipients=("ada@example.test",)):
    return ExpiryCandidate(cert.id, threshold, days, f"expiry:{cert.id}:{threshold}:2026-10-19", recipients)


def test_due_alerts_cover_the_window_and_skip_already_sent_thresholds(db, now):
    c29 = add_cert(db, now, 29, cn="a.example.test")
    c6 = add_cert(db, now, 6, cn="b.example.test")
    c_past = add_cert(db, now, -3, cn="c.example.test")
    add_cert(db, now, 90, cn="far.example.test")
    add_cert(db, now, -90, cn="long-gone.example.test")
    add_cert(db, now, 5, cn="old.example.test", status=CertificateStatus.SUPERSEDED)
    add_cert(db, now, 5, cn="revoked.example.test", status=CertificateStatus.REVOKED)
    sent_before = add_cert(db, now, 29, cn="sent.example.test")
    add_log(db, sent_before, 30, NotificationStatus.SENT, f"expiry:{sent_before.id}:30:2026-10-18")
    failed_before = add_cert(db, now, 29, cn="failed.example.test")
    add_log(db, failed_before, 30, NotificationStatus.FAILED, f"expiry:{failed_before.id}:30:2026-10-18")
    other_threshold = add_cert(db, now, 29, cn="other.example.test")
    add_log(db, other_threshold, 60, NotificationStatus.SENT, f"expiry:{other_threshold.id}:60:2026-09-01")

    found = {c.certificate_id: c for c in due_expiry_alerts(db, now)}

    assert {cid: c.threshold_days for cid, c in found.items()} == {
        c29.id: 30,
        c6.id: 7,
        c_past.id: 0,
        failed_before.id: 30,
        other_threshold.id: 30,
    }
    assert found[c29.id].days_remaining == 29
    assert found[c6.id].days_remaining == 6
    assert found[c_past.id].days_remaining == -3
    assert found[c29.id].dedupe_key == f"expiry:{c29.id}:30:2026-10-19"


def test_due_alerts_use_a_bounded_number_of_queries(db, now):
    for index in range(6):
        add_cert(db, now, 10 + index, cn=f"bulk{index}.example.test", owner_email="ada@example.test")
    statements = []

    def count(conn, cursor, statement, *args):
        statements.append(statement)

    event.listen(db.get_bind(), "before_cursor_execute", count)
    try:
        assert len(due_expiry_alerts(db, now)) == 6
    finally:
        event.remove(db.get_bind(), "before_cursor_execute", count)
    # settings reads + ONE due-candidate query; never per certificate
    ledger = [s for s in statements if "notification_log" in s]
    assert len(ledger) == 1
    assert re.search(r"NOT\s*\(?\s*EXISTS", ledger[0].upper())
    assert "FROM certificate" in ledger[0]
    assert len([s for s in statements if "FROM certificate" in s]) == 1
    assert len(statements) <= 3


def test_unrelated_sent_history_does_not_suppress_or_get_loaded(db, now):
    cert = add_cert(db, now, 29, cn="a.example.test")
    other = add_cert(db, now, 29, cn="b.example.test")
    add_log(db, cert, 7, NotificationStatus.SENT, f"expiry:{cert.id}:7:2026-10-01")
    add_log(db, cert, 90, NotificationStatus.SENT, f"expiry:{cert.id}:90:2026-09-01")
    add_log(db, other, 30, NotificationStatus.SENT, f"expiry:{other.id}:30:2026-10-18")

    found = {c.certificate_id: c.threshold_days for c in due_expiry_alerts(db, now)}

    assert found == {cert.id: 30}


def test_owner_and_team_resolution_uses_alert_recipients(db, now):
    owned = add_cert(db, now, 20, cn="owned.example.test", owner_email="Ada@Example.test")
    orphan = add_cert(db, now, 20, cn="orphan.example.test", owner_email=None)
    put_setting(db, "alert.recipients", ["team@example.test", "ada@example.test"])

    found = {c.certificate_id: c.recipients for c in due_expiry_alerts(db, now)}

    assert found[owned.id] == ("Ada@Example.test", "team@example.test")
    assert found[orphan.id] == ("team@example.test", "ada@example.test")


def test_candidates_without_any_recipient_are_still_reported_with_empty_recipients(db, now):
    cert = add_cert(db, now, 20, owner_email=None)
    found = {c.certificate_id: c for c in due_expiry_alerts(db, now)}
    assert found[cert.id].recipients == ()


def add_binding(db, cert, hostname, vhost, port=443, active=True):
    server = db.scalar(select(Server).where(Server.hostname == hostname))
    if server is None:
        server = Server(hostname=hostname, inventory_source="manual")
        db.add(server)
        db.flush()
    db.add(
        Binding(
            server_id=server.id,
            webserver=WebserverType.NGINX,
            vhost_name=vhost,
            vhost_names=[vhost],
            port=port,
            config_file=f"/etc/nginx/{vhost}.conf",
            cert_path=f"/etc/ssl/{vhost}.pem",
            key_path=f"/etc/ssl/{vhost}.key",
            certificate_id=cert.id,
            match_state="match",
            last_seen_at=cert.not_before,
            is_active=active,
        )
    )
    db.flush()


def put_setting(db, key, value):
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value))
    else:
        row.value = value
    db.flush()


def add_key(db):
    key = PrivateKey(
        key_type="rsa",
        key_size=2048,
        ciphertext=b"fixture-ciphertext-bytes",
        nonce=b"123456789012",
        aad=f"private_key:0:{uuid.uuid4().hex}",
        master_key_version=1,
        public_key_sha256=uuid.uuid4().hex + uuid.uuid4().hex,
        public_key_pem="-----BEGIN PUBLIC KEY-----\nZml4dHVyZQ==\n-----END PUBLIC KEY-----\n",
        origin="imported_pem",
    )
    db.add(key)
    db.flush()
    return key


def add_renewal(db, cert, state, now, **overrides):
    if state not in (RenewalState.DRAFT, RenewalState.CANCELLED):
        overrides.setdefault("key_id", add_key(db).id)
    renewal = Renewal(
        previous_certificate_id=cert.id,
        state=state,
        common_name=cert.common_name,
        sans=list(cert.sans),
        state_changed_at=now,
        **overrides,
    )
    db.add(renewal)
    db.flush()
    return renewal


def test_rendered_expiry_contains_every_required_fact(db, now):
    put_setting(db, "ui.timezone", "Europe/Rome")
    cert = add_cert(db, now, 29, cn="www.example.test", owner_email="ada@example.test")
    add_binding(db, cert, "web1.example.test", "www")
    add_binding(db, cert, "web2.example.test", "api", port=8443)
    add_binding(db, cert, "gone.example.test", "old", active=False)
    add_renewal(db, cert, RenewalState.DONE, now, created_at=now - timedelta(days=2))
    newest = add_renewal(db, cert, RenewalState.DRAFT, now, created_at=now - timedelta(days=1))
    add_renewal(db, cert, RenewalState.CANCELLED, now, created_at=now)  # newer, but cancelled: ignored

    mail = render_expiry(db, candidate_for(cert), now, "https://certs.example.internal/")

    local = cert.not_after.astimezone(ZoneInfo("Europe/Rome")).strftime("%Y-%m-%d %H:%M")
    utc = cert.not_after.strftime("%Y-%m-%d %H:%M")
    for body in (mail.text, mail.html):
        assert "www.example.test" in body
        assert "Fixture CA" in body
        assert cert.serial in body
        assert local in body and utc in body
        assert "expires in 29 days" in body
        assert "web1.example.test www:443" in body
        assert "web2.example.test api:8443" in body
        assert "gone.example.test" not in body
        assert "draft" in body and "submitted" not in body and "cancelled" not in body
        assert f"https://certs.example.internal/certificates/{cert.id}" in body
        assert f"https://certs.example.internal/renewals/{newest.id}" in body
    assert "2 names" in mail.text or "SANs: 2" in mail.text
    assert "29 days" in mail.subject and "www.example.test" in mail.subject
    assert "\n" not in mail.subject


def test_rendering_states_expired_and_caps_the_binding_list(db, now):
    cert = add_cert(db, now, -3, cn="old.example.test")
    for index in range(53):
        add_binding(db, cert, f"h{index:02d}.example.test", "www")

    mail = render_expiry(db, candidate_for(cert, threshold=0, days=-3), now, None)

    assert "has expired" in mail.text and "has expired" in mail.subject
    assert "+3 more" in mail.text and "+3 more" in mail.html
    assert "h49.example.test" in mail.text and "h50.example.test" not in mail.text


def test_rendering_escapes_html_and_works_without_base_url(db, now):
    cert = add_cert(db, now, 29, cn="<script>alert(1)</script>.example.test", notes="<script>x</script>")
    renewal = add_renewal(db, cert, RenewalState.CSR_GENERATED, now)

    mail = render_expiry(db, candidate_for(cert), now, None)

    assert "<script>" not in mail.html and "&lt;script&gt;" in mail.html
    assert "&lt;script&gt;x&lt;/script&gt;" in mail.html
    assert "<script>x</script>" in mail.text  # the text part is not HTML-escaped
    assert "<script>alert(1)</script>.example.test" in mail.text
    assert f"/certificates/{cert.id}" in mail.text and f"/renewals/{renewal.id}" in mail.text
    assert "://" not in mail.text
    assert f'href="/certificates/{cert.id}"' in mail.html


def test_no_renewal_in_progress_is_stated(db, now):
    cert = add_cert(db, now, 29)
    add_renewal(db, cert, RenewalState.CANCELLED, now)
    mail = render_expiry(db, candidate_for(cert), now, None)
    assert "no renewal" in mail.text.lower()
    assert "/renewals/" not in mail.text


def test_email_environment_escapes_html_templates_only():
    env = email_environment()
    assert env.get_template("expiry.html.j2").environment.autoescape("expiry.html.j2") is True
    assert not env.autoescape("expiry.txt.j2")
