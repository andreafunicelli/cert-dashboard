"""Task 19: resumable manual-CA renewal wizard (real Postgres, real HTTP stack, form-only flows)."""

import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from typing import NamedTuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from sqlalchemy import func, select

import app.web.renewals as web_renewals
from app.crypto.chain import order_chain
from app.crypto.parse import parse_certificates
from app.models import AuditLog, Binding, Certificate, Job, JobHost, PrivateKey, Renewal, Server
from app.models.enums import (
    CertificateStatus,
    JobHostStatus,
    JobStatus,
    JobType,
    RenewalState,
    WebserverType,
)
from app.services.audit import Actor
from app.services.certificates import CertificateMetadata, save_certificate
from app.services.renewals import mark_deployed

ACTOR = Actor(None, "fixture", "192.0.2.1", "fixture-browser")
CHECKLIST = (
    "order a certificate, paste this CSR, complete validation, "
    "download the certificate and any intermediate"
)
HTMX = {"HX-Request": "true"}
ALL_STEPS = ("basics", "csr", "submitted", "upload", "ready", "done")


# --- fixtures ----------------------------------------------------------------------------------


class Issued(NamedTuple):
    leaf: bytes
    chain: bytes


class BundleCA:
    """``issue(csr_pem)`` returns the leaf plus the issuing chain; everything else is the fixture CA."""

    def __init__(self, raw):
        self.raw = raw

    def issue(self, csr_pem, **overrides) -> Issued:
        return Issued(self.raw.issue(csr_pem, **overrides), self.raw.chain_pem)

    def __getattr__(self, name):
        return getattr(self.raw, name)


@pytest.fixture
def ca(ca):
    return BundleCA(ca)


@pytest.fixture
def source(web_factory, ca, now):
    """A committed, active inventory certificate that gets renewed (unique per test)."""
    cn = f"src-{uuid.uuid4().hex[:10]}.example.internal"
    key = ec.generate_private_key(ec.SECP256R1())
    pem = ca.raw.issue(
        public_key=key.public_key(),
        common_name=cn,
        sans=[cn, f"alt.{cn}"],
        not_before=now - timedelta(days=300),
        not_after=now + timedelta(days=20),
    )
    leaf = parse_certificates(pem)[0]
    chain = order_chain(leaf.cert, [x509.load_pem_x509_certificate(ca.raw.chain_pem)])
    metadata = CertificateMetadata(owner_name="Ada", owner_email="ada@example.test", team="web")
    with web_factory.begin() as db:
        row = save_certificate(db, leaf, chain, metadata, ACTOR, source="upload_pem", validation_time=now).certificate
        return SimpleNamespace(id=row.id, common_name=cn, sans=[cn, f"alt.{cn}"], issuer_cn=row.issuer_cn)


def _unique(prefix="www"):
    return f"{prefix}-{uuid.uuid4().hex[:10]}.example.internal"


class Wizard:
    """Form-only HTTP helpers: add the CSRF token and return ORM rows read in a fresh transaction."""

    def __init__(self, client, factory, ca):
        self.client, self.factory, self.ca = client, factory, ca
        self.csrf = client.fixture_csrf

    # -- plumbing
    def post(self, path, data=None, files=None, htmx=False, csrf=True):
        body = dict(data or {})
        if csrf:
            body["csrf_token"] = self.csrf
        return self.client.post(
            path, data=body, files=files, headers=HTMX if htmx else None, follow_redirects=False
        )

    def get(self, renewal_id, step=None, htmx=False):
        suffix = f"?step={step}" if step else ""
        return self.client.get(f"/renewals/{renewal_id}{suffix}", headers=HTMX if htmx else None)

    def row(self, renewal_id) -> Renewal:
        with self.factory() as db:
            return db.get(Renewal, uuid.UUID(str(renewal_id)))

    def count(self, model=Renewal):
        with self.factory() as db:
            return db.scalar(select(func.count()).select_from(model))

    def audits(self, action, renewal_id=None):
        with self.factory() as db:
            stmt = select(AuditLog).where(AuditLog.action == action)
            if renewal_id is not None:
                stmt = stmt.where(AuditLog.target_id == str(renewal_id))
            return list(db.scalars(stmt))

    @staticmethod
    def renewal_id(response) -> str:
        return re.search(r"/renewals/([0-9a-f-]{36})", response.headers["location"]).group(1)

    # -- actions
    def create(self, common_name, sans, source=None, ca_name="TestCA", notes="", htmx=False):
        query = f"?from={source.id}" if source is not None else ""
        data = {"common_name": common_name, "sans": "\n".join(sans), "ca_name": ca_name, "notes": notes}
        return self.post(f"/renewals/new{query}", data, htmx=htmx)

    def create_and_generate(self, common_name, sans, source=None, algorithm="ecdsa-p256") -> Renewal:
        created = self.create(common_name, sans, source)
        assert created.status_code == 303, created.text
        renewal_id = self.renewal_id(created)
        generated = self.generate(renewal_id, algorithm)
        assert generated.status_code == 303, generated.text
        return self.row(renewal_id)

    def edit_names(self, renewal_id, common_name, sans=None, htmx=False):
        sans = sans or [common_name]
        data = {"common_name": common_name, "sans": "\n".join(sans), "ca_name": "TestCA", "notes": ""}
        return self.post(f"/renewals/{renewal_id}/edit", data, htmx=htmx)

    def generate(self, renewal_id, algorithm=None, htmx=False):
        data = {"key_algorithm": algorithm} if algorithm is not None else {}
        return self.post(f"/renewals/{renewal_id}/generate-csr", data, htmx=htmx)

    def submit_order(self, renewal_id, reference, htmx=False):
        return self.post(f"/renewals/{renewal_id}/submit", {"order_reference": reference}, htmx=htmx)

    def upload_issued(self, renewal_id, issued, chain=None, as_files=False, htmx=False):
        leaf, bundled_chain = (issued.leaf, issued.chain) if isinstance(issued, Issued) else (issued, None)
        chain = bundled_chain if chain is None else chain
        if as_files:
            files = {"leaf_file": ("leaf.crt", leaf, "application/x-x509-ca-cert")}
            if chain:
                files["chain_file"] = ("chain.pem", chain, "application/x-pem-file")
            return self.post(f"/renewals/{renewal_id}/issued", {}, files=files, htmx=htmx)
        data = {"leaf_text": leaf.decode("ascii")}
        if chain:
            data["chain_text"] = chain.decode("ascii")
        return self.post(f"/renewals/{renewal_id}/issued", data, htmx=htmx)

    def cancel(self, renewal_id, reason, htmx=False):
        return self.post(f"/renewals/{renewal_id}/cancel", {"reason": reason}, htmx=htmx)

    def finalize(self, renewal_id, confirm=True, previous_status=None, reason="", htmx=False):
        data = {"reason": reason}
        if confirm:
            data["confirm"] = "yes"
        if previous_status is not None:
            data["previous_status"] = previous_status
        return self.post(f"/renewals/{renewal_id}/finalize", data, htmx=htmx)

    # -- journeys
    def submitted(self, source=None, common_name=None, **kwargs) -> Renewal:
        name = common_name or _unique()
        renewal = self.create_and_generate(name, [name], source, **kwargs)
        assert self.submit_order(renewal.id, "CA-123").status_code == 303
        return self.row(renewal.id)

    def issued(self, source=None, common_name=None, **kwargs) -> Renewal:
        renewal = self.submitted(source, common_name, **kwargs)
        response = self.upload_issued(renewal.id, self.ca.issue(renewal.csr_pem))
        assert response.status_code == 303, response.text
        return self.row(renewal.id)

    def deployed(self, now, source=None) -> Renewal:
        """Reach ``deployed`` through the service hook.

        This seeds a succeeded deploy job and host row *only* to exercise the finalize screen; it does
        not simulate a real deployment, and no HTTP action performs this transition.
        """
        renewal = self.issued(source)
        with self.factory.begin() as db:
            certificate = db.get(Certificate, renewal.certificate_id)
            job = Job(
                type=JobType.DEPLOY,
                status=JobStatus.SUCCEEDED,
                priority=300,
                payload={"certificate_id": certificate.id},
                run_after=now,
            )
            server = Server(hostname=f"h-{uuid.uuid4().hex[:10]}.example.test", inventory_source="manual")
            db.add_all([job, server])
            db.flush()
            binding = Binding(
                server_id=server.id,
                webserver=WebserverType.NGINX,
                vhost_name="www",
                vhost_names=["www"],
                port=443,
                config_file="/etc/nginx/www.conf",
                cert_path="/etc/ssl/www.pem",
                key_path="/etc/ssl/www.key",
                certificate_id=certificate.id,
                match_state="match",
                last_seen_at=now,
            )
            db.add(binding)
            db.flush()
            db.add(
                JobHost(
                    job_id=job.id,
                    server_id=server.id,
                    binding_id=binding.id,
                    status=JobHostStatus.SUCCEEDED,
                    new_fingerprint=certificate.sha256_fingerprint,
                )
            )
            db.flush()
            mark_deployed(db, renewal.id, job.id, ACTOR, now)
        return self.row(renewal.id)


@pytest.fixture
def wizard(signed_in, web_factory, ca):
    return Wizard(signed_in, web_factory, ca)


def _step(response):
    """(step, state) the page was rendered for."""
    match = re.search(r'id="renewal-panel"[^>]*data-step="([a-z]+)"[^>]*data-state="([a-z_]+)"', response.text)
    assert match, response.text[:500]
    return match.groups()


def _state(wizard, renewal_id):
    return wizard.row(renewal_id).state


# --- plan test ---------------------------------------------------------------------------------


def test_wizard_resumes_and_freezes_names(signed_in, wizard, ca):
    renewal = wizard.create_and_generate(common_name="www.example.internal", sans=["www.example.internal"])
    page = signed_in.get(f"/renewals/{renewal.id}?step=csr")
    assert renewal.csr_sha256 in page.text and renewal.csr_pem in page.text
    assert wizard.edit_names(renewal.id, "other.example.internal").status_code == 422
    assert wizard.submit_order(renewal.id, "").status_code == 422
    assert wizard.submit_order(renewal.id, "CA-123").status_code == 303
    assert wizard.upload_issued(renewal.id, ca.issue(renewal.csr_pem)).status_code == 303


# --- start / prefill -----------------------------------------------------------------------------


def test_new_form_is_prefilled_from_the_source_and_creates_nothing(signed_in, wizard, source):
    before = wizard.count()
    page = signed_in.get(f"/renewals/new?from={source.id}")
    assert page.status_code == 200 and wizard.count() == before
    assert _step(page) == ("basics", "new")
    assert f'value="{source.common_name}"' in page.text
    assert f"alt.{source.common_name}" in page.text
    assert f'value="{source.issuer_cn}"' in page.text
    assert 'name="csrf_token"' in page.text
    assert re.search(r'<option value="rsa-2048"[^>]*selected', page.text)
    for option in ("rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384"):
        assert f'<option value="{option}"' in page.text
    assert "compatib" in page.text.lower()  # trade-off text accompanies the algorithm choice


def test_post_without_names_creates_the_draft_from_the_source(wizard, source):
    response = wizard.post(f"/renewals/new?from={source.id}")
    assert response.status_code == 303
    assert response.headers["location"].endswith("?step=basics")
    renewal = wizard.row(wizard.renewal_id(response))
    assert renewal.state == RenewalState.DRAFT and renewal.previous_certificate_id == source.id
    assert renewal.common_name == source.common_name
    assert sorted(renewal.sans) == sorted(source.sans)
    assert renewal.ca_name == source.issuer_cn and renewal.notes is None
    assert [a.actor_label for a in wizard.audits("renewal.create", renewal.id)] != []


def test_post_with_edited_names_uses_them(wizard, source):
    new_name = _unique("renamed")
    response = wizard.create(new_name, [new_name, "extra.example.internal"], source, ca_name="Other CA", notes="n")
    renewal = wizard.row(wizard.renewal_id(response))
    assert renewal.common_name == new_name and renewal.ca_name == "Other CA" and renewal.notes == "n"
    assert "extra.example.internal" in renewal.sans


def test_second_start_resumes_the_in_flight_renewal(signed_in, wizard, source):
    first = wizard.post(f"/renewals/new?from={source.id}")
    renewal_id = wizard.renewal_id(first)
    before = wizard.count()
    again = signed_in.get(f"/renewals/new?from={source.id}", follow_redirects=False)
    assert again.status_code == 303 and again.headers["location"].startswith(f"/renewals/{renewal_id}")
    posted = wizard.post(f"/renewals/new?from={source.id}")
    assert posted.status_code == 303 and wizard.renewal_id(posted) == renewal_id
    assert wizard.count() == before


def test_a_cancelled_renewal_does_not_block_a_new_one(wizard, source):
    first = wizard.renewal_id(wizard.post(f"/renewals/new?from={source.id}"))
    assert wizard.cancel(first, "changed my mind").status_code == 303
    second = wizard.post(f"/renewals/new?from={source.id}")
    assert second.status_code == 303 and wizard.renewal_id(second) != first


def test_concurrent_starts_create_one_renewal(web_factory, source, now):
    barrier = Barrier(4)

    def start(_):
        barrier.wait()
        with web_factory.begin() as db:
            renewal, created = web_renewals.start_renewal(db, source.id, None, ACTOR, now)
            return str(renewal.id), created

    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(start, range(4)))
    assert len({renewal_id for renewal_id, _ in results}) == 1
    assert sum(created for _, created in results) == 1


def test_unknown_source_is_404_and_inactive_source_is_refused(signed_in, wizard, source, web_factory):
    assert signed_in.get("/renewals/new?from=99999999").status_code == 404
    assert wizard.post("/renewals/new?from=99999999").status_code == 404
    assert signed_in.get("/renewals/new?from=abc").status_code == 422
    with web_factory.begin() as db:
        db.get(Certificate, source.id).status = CertificateStatus.SUPERSEDED
    before = wizard.count()
    page = signed_in.get(f"/renewals/new?from={source.id}")
    assert page.status_code == 422 and "active" in page.text
    assert wizard.post(f"/renewals/new?from={source.id}").status_code == 422
    assert wizard.count() == before


def test_invalid_basics_report_field_errors_and_create_nothing(wizard):
    before = wizard.count()
    response = wizard.create("not a name!", ["also bad name"])
    assert response.status_code == 422 and wizard.count() == before
    assert 'data-field="common_name"' in response.text
    fragment = wizard.create("not a name!", [""], htmx=True)
    assert fragment.status_code == 422 and "<html" not in fragment.text and 'id="renewal-panel"' in fragment.text
    assert "<html" in response.text


def test_notes_are_escaped(signed_in, wizard):
    name = _unique()
    response = wizard.create(name, [name], notes="<script>alert(1)</script>")
    page = wizard.get(wizard.renewal_id(response), "basics")
    assert "<script>alert(1)</script>" not in page.text and "&lt;script&gt;alert(1)" in page.text


# --- basics / csr --------------------------------------------------------------------------------


def test_draft_names_can_be_edited_until_the_csr_exists(wizard):
    name = _unique()
    renewal_id = wizard.renewal_id(wizard.create(name, [name]))
    new_name = _unique("edited")
    response = wizard.edit_names(renewal_id, new_name, [new_name, "san.example.internal"])
    assert response.status_code == 303 and response.headers["location"] == f"/renewals/{renewal_id}?step=basics"
    row = wizard.row(renewal_id)
    assert row.common_name == new_name and "san.example.internal" in row.sans
    bad = wizard.edit_names(renewal_id, "bad name!")
    assert bad.status_code == 422 and wizard.row(renewal_id).common_name == new_name
    wizard.generate(renewal_id, "ecdsa-p256")
    frozen = wizard.edit_names(renewal_id, _unique("late"))
    assert frozen.status_code == 422 and wizard.row(renewal_id).common_name == new_name


def test_names_are_read_only_after_csr_generation(signed_in, wizard):
    renewal = wizard.create_and_generate(_unique(), [_unique("san")])
    page = signed_in.get(f"/renewals/{renewal.id}?step=csr")
    assert f"/renewals/{renewal.id}/edit" not in page.text
    assert renewal.common_name in page.text


def test_default_algorithm_is_rsa_2048(wizard, web_factory):
    name = _unique()
    renewal_id = wizard.renewal_id(wizard.create(name, [name]))
    assert wizard.generate(renewal_id).status_code == 303
    row = wizard.row(renewal_id)
    with web_factory() as db:
        key = db.get(PrivateKey, row.key_id)
    assert (key.key_type.value, key.key_size) == ("rsa", 2048)
    assert row.state == RenewalState.CSR_GENERATED
    assert wizard.audits("renewal.csr_generated", renewal_id)


@pytest.mark.parametrize(
    ("algorithm", "kind", "size"),
    [("ecdsa-p256", "ecdsa", 256), ("ecdsa-p384", "ecdsa", 384)],
)
def test_ecdsa_algorithms_generate_matching_keys(wizard, web_factory, algorithm, kind, size):
    renewal = wizard.create_and_generate(_unique(), [_unique("san")], algorithm=algorithm)
    with web_factory() as db:
        key = db.get(PrivateKey, renewal.key_id)
    assert (key.key_type.value, key.key_size) == (kind, size)


def test_unknown_algorithm_is_refused_and_state_is_unchanged(wizard):
    name = _unique()
    renewal_id = wizard.renewal_id(wizard.create(name, [name]))
    response = wizard.generate(renewal_id, "des-56")
    assert response.status_code == 422 and 'data-field="key_algorithm"' in response.text
    assert wizard.row(renewal_id).state == RenewalState.DRAFT and wizard.row(renewal_id).csr_pem is None
    fragment = wizard.generate(renewal_id, "des-56", htmx=True)
    assert fragment.status_code == 422 and "<html" not in fragment.text


def test_csr_step_shows_pem_hash_checklist_and_download(signed_in, wizard):
    renewal = wizard.create_and_generate(_unique(), [_unique("san")])
    page = signed_in.get(f"/renewals/{renewal.id}?step=csr")
    assert _step(page) == ("csr", "csr_generated")
    assert "<pre" in page.text and renewal.csr_pem in page.text and renewal.csr_sha256 in page.text
    assert CHECKLIST in page.text
    assert f'href="/renewals/{renewal.id}/csr.pem"' in page.text
    assert "BEGIN PRIVATE KEY" not in page.text


def test_csr_download_headers_audit_and_safe_filename(signed_in, wizard):
    renewal = wizard.create_and_generate("*.example.internal", ["*.example.internal"])
    before = len(wizard.audits("renewal.csr_download", renewal.id))
    response = signed_in.get(f"/renewals/{renewal.id}/csr.pem")
    assert response.status_code == 200 and response.text == renewal.csr_pem
    assert response.headers["content-type"].startswith("application/pkcs10")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == 'attachment; filename="wildcard.example.internal.csr"'
    audits = wizard.audits("renewal.csr_download", renewal.id)
    assert len(audits) == before + 1
    assert renewal.csr_pem not in str(audits[-1].details) and "BEGIN" not in str(audits[-1].details)


def test_csr_download_unavailable_before_generation_and_for_unknown_ids(signed_in, wizard):
    name = _unique()
    renewal_id = wizard.renewal_id(wizard.create(name, [name]))
    assert signed_in.get(f"/renewals/{renewal_id}/csr.pem").status_code == 404
    assert signed_in.get(f"/renewals/{uuid.uuid4()}/csr.pem").status_code == 404
    assert signed_in.get("/renewals/not-a-uuid/csr.pem").status_code == 404


def test_csr_still_downloadable_after_later_steps(signed_in, wizard):
    renewal = wizard.issued()
    response = signed_in.get(f"/renewals/{renewal.id}/csr.pem")
    assert response.status_code == 200 and response.text == renewal.csr_pem


@pytest.mark.parametrize(
    ("common_name", "expected"),
    [
        ("*.example.internal", "wildcard.example.internal.csr"),
        ("host.example.internal", "host.example.internal.csr"),
        ("2001:db8::1", "2001_db8__1.csr"),
        ("a" * 60 + ".example.internal", "a" * 60 + ".example.internal.csr"),
    ],
)
def test_safe_csr_filenames(common_name, expected):
    assert web_renewals.csr_filename(common_name) == expected


def test_safe_csr_filename_is_bounded_and_never_empty():
    assert web_renewals.csr_filename("x" * 400) == "x" * 100 + ".csr"
    assert re.fullmatch(r"[A-Za-z0-9._-]+", web_renewals.csr_filename('"; rm -rf /\r\n'))
    assert web_renewals.csr_filename("") == "renewal.csr"


# --- resumability --------------------------------------------------------------------------------


EXPECTED = {
    "draft": {"default": "basics", "reachable": {"basics"}},
    "csr_generated": {"default": "csr", "reachable": {"csr"}},
    "submitted": {"default": "submitted", "reachable": {"submitted", "upload"}},
    "issued": {"default": "ready", "reachable": {"ready"}},
    "deployed": {"default": "done", "reachable": {"done"}},
    "done": {"default": "done", "reachable": {"done"}},
    "cancelled": {"default": "basics", "reachable": {"basics"}},
}


def _assert_step_matrix(wizard, renewal_id, state):
    expectation = EXPECTED[state]
    row_state = _state(wizard, renewal_id)
    assert row_state.value == state
    default = wizard.get(renewal_id)
    assert default.status_code == 200 and _step(default) == (expectation["default"], state)
    for step in ALL_STEPS:
        page = wizard.get(renewal_id, step)
        assert page.status_code == 200, (state, step)
        shown, shown_state = _step(page)
        assert shown_state == state
        assert shown == (step if step in expectation["reachable"] else expectation["default"]), (state, step)


def test_every_state_is_resumable_by_url_and_unreachable_steps_show_the_current_one(wizard, now, source):
    name = _unique()
    renewal_id = wizard.renewal_id(wizard.create(name, [name]))
    _assert_step_matrix(wizard, renewal_id, "draft")
    wizard.generate(renewal_id, "ecdsa-p256")
    _assert_step_matrix(wizard, renewal_id, "csr_generated")
    wizard.submit_order(renewal_id, "CA-9")
    _assert_step_matrix(wizard, renewal_id, "submitted")
    renewal = wizard.row(renewal_id)
    assert wizard.upload_issued(renewal_id, wizard.ca.issue(renewal.csr_pem)).status_code == 303
    _assert_step_matrix(wizard, renewal_id, "issued")

    cancelled = wizard.renewal_id(wizard.create(_unique(), [_unique("c")]))
    wizard.cancel(cancelled, "not needed")
    _assert_step_matrix(wizard, cancelled, "cancelled")

    deployed = wizard.deployed(now, source)
    _assert_step_matrix(wizard, deployed.id, "deployed")
    assert wizard.finalize(deployed.id).status_code == 303
    _assert_step_matrix(wizard, deployed.id, "done")


def test_each_post_redirects_to_the_step_of_the_new_state(wizard, now):
    name = _unique()
    created = wizard.create(name, [name])
    renewal_id = wizard.renewal_id(created)
    assert created.headers["location"] == f"/renewals/{renewal_id}?step=basics"
    assert wizard.generate(renewal_id, "ecdsa-p256").headers["location"] == f"/renewals/{renewal_id}?step=csr"
    submitted = wizard.submit_order(renewal_id, "CA-1")
    assert submitted.headers["location"] == f"/renewals/{renewal_id}?step=submitted"
    renewal = wizard.row(renewal_id)
    issued = wizard.upload_issued(renewal_id, wizard.ca.issue(renewal.csr_pem))
    assert issued.headers["location"] == f"/renewals/{renewal_id}?step=ready"
    other = wizard.renewal_id(wizard.create(_unique(), [_unique("o")]))
    assert wizard.cancel(other, "stop").headers["location"] == f"/renewals/{other}?step=basics"


def test_csr_hash_is_visible_on_every_later_step(wizard, now, source):
    renewal = wizard.deployed(now, source)
    assert renewal.csr_sha256 in wizard.get(renewal.id, "done").text
    submitted = wizard.submitted()
    for step in ("submitted", "upload"):
        assert submitted.csr_sha256 in wizard.get(submitted.id, step).text
    issued = wizard.issued()
    assert issued.csr_sha256 in wizard.get(issued.id, "ready").text


def test_unknown_step_is_422_and_unknown_renewals_are_404(signed_in, wizard):
    name = _unique()
    renewal_id = wizard.renewal_id(wizard.create(name, [name]))
    assert wizard.get(renewal_id, "bogus").status_code == 422
    assert signed_in.get(f"/renewals/{uuid.uuid4()}").status_code == 404
    assert signed_in.get("/renewals/not-a-uuid").status_code == 404
    missing = wizard.post(f"/renewals/{uuid.uuid4()}/cancel", {"reason": "x"})
    assert missing.status_code == 404


def test_pages_require_a_session(client):
    assert client.get("/renewals/new", follow_redirects=False).status_code in (303, 401)
    assert client.get(f"/renewals/{uuid.uuid4()}", follow_redirects=False).status_code in (303, 401)
    assert client.get(f"/renewals/{uuid.uuid4()}/csr.pem", follow_redirects=False).status_code in (303, 401)


# --- order reference -------------------------------------------------------------------------------


def test_order_reference_is_required_and_state_is_unchanged(wizard):
    renewal = wizard.create_and_generate(_unique(), [_unique("san")])
    for reference in ("", "   "):
        response = wizard.submit_order(renewal.id, reference)
        assert response.status_code == 422 and 'data-field="order_reference"' in response.text
    assert _state(wizard, renewal.id) == RenewalState.CSR_GENERATED
    fragment = wizard.submit_order(renewal.id, "", htmx=True)
    assert fragment.status_code == 422 and "<html" not in fragment.text and 'id="renewal-panel"' in fragment.text
    assert wizard.audits("renewal.submitted", renewal.id) == []


def test_submitted_step_summarises_the_order_and_links_to_upload(signed_in, wizard):
    renewal = wizard.submitted()
    page = signed_in.get(f"/renewals/{renewal.id}?step=submitted")
    assert "CA-123" in page.text and f"/renewals/{renewal.id}?step=upload" in page.text
    assert renewal.csr_sha256 in page.text


def test_submit_from_the_wrong_state_is_422(wizard):
    renewal = wizard.submitted()
    again = wizard.submit_order(renewal.id, "OTHER")
    assert again.status_code == 422 and wizard.row(renewal.id).ca_order_reference == "CA-123"


# --- issued upload -----------------------------------------------------------------------------------


def test_pasted_upload_moves_to_ready_and_creates_the_certificate(wizard, source):
    renewal = wizard.submitted(source)
    before = wizard.count(Certificate)
    response = wizard.upload_issued(renewal.id, wizard.ca.issue(renewal.csr_pem))
    assert response.status_code == 303
    row = wizard.row(renewal.id)
    assert row.state == RenewalState.ISSUED and row.certificate_id is not None
    assert wizard.count(Certificate) == before + 1
    assert wizard.audits("renewal.issued", renewal.id)


def test_file_uploads_for_leaf_and_chain_are_accepted(wizard):
    renewal = wizard.submitted()
    response = wizard.upload_issued(renewal.id, wizard.ca.issue(renewal.csr_pem), as_files=True)
    assert response.status_code == 303 and _state(wizard, renewal.id) == RenewalState.ISSUED
    assert wizard.row(renewal.id).issued_chain_pem


def test_der_leaf_file_is_accepted(wizard):
    renewal = wizard.submitted()
    issued = wizard.ca.issue(renewal.csr_pem)
    der = x509.load_pem_x509_certificate(issued.leaf).public_bytes(serialization.Encoding.DER)
    response = wizard.post(
        f"/renewals/{renewal.id}/issued", {}, files={"leaf_file": ("leaf.cer", der, "application/pkix-cert")}
    )
    assert response.status_code == 303 and _state(wizard, renewal.id) == RenewalState.ISSUED


def test_pfx_upload_is_rejected_and_state_is_unchanged(wizard):
    renewal = wizard.submitted()
    key = ec.generate_private_key(ec.SECP256R1())
    pem = wizard.ca.raw.issue(public_key=key.public_key(), common_name="pfx.example.internal", sans=["pfx.example.internal"])
    pfx = pkcs12.serialize_key_and_certificates(
        b"bundle",
        key,
        x509.load_pem_x509_certificate(pem),
        None,
        serialization.BestAvailableEncryption(b"fixture-pfx-pass"),
    )
    before = wizard.count(Certificate)
    response = wizard.post(
        f"/renewals/{renewal.id}/issued", {}, files={"leaf_file": ("bundle.pfx", pfx, "application/x-pkcs12")}
    )
    assert response.status_code == 422 and "pfx_not_accepted" in response.text
    assert _state(wizard, renewal.id) == RenewalState.SUBMITTED and wizard.count(Certificate) == before


def test_pfx_in_the_chain_upload_is_rejected_with_a_typed_error_and_state_is_unchanged(wizard):
    renewal = wizard.submitted()
    issued = wizard.ca.issue(renewal.csr_pem)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = wizard.ca.raw.issue(public_key=key.public_key(), common_name="pfx.example.internal", sans=["pfx.example.internal"])
    pfx = pkcs12.serialize_key_and_certificates(
        b"bundle",
        key,
        x509.load_pem_x509_certificate(pem),
        None,
        serialization.BestAvailableEncryption(b"fixture-pfx-pass"),
    )
    before = wizard.count(Certificate)
    response = wizard.post(
        f"/renewals/{renewal.id}/issued",
        {"leaf_text": issued.leaf.decode("ascii")},
        files={"chain_file": ("chain.pem", pfx, "application/octet-stream")},
    )
    assert response.status_code == 422 and "pfx_not_accepted" in response.text
    assert _state(wizard, renewal.id) == RenewalState.SUBMITTED and wizard.count(Certificate) == before
    assert not wizard.audits("renewal.issued", renewal.id)


def test_all_independent_blocking_errors_are_reported_together(wizard):
    renewal = wizard.submitted()
    other_key = ec.generate_private_key(ec.SECP256R1())
    now = wizard.ca.raw.now
    bad = wizard.ca.raw.issue(
        public_key=other_key.public_key(),
        common_name="intruder.example.internal",
        sans=["intruder.example.internal"],
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=10),
    )
    before = wizard.count(Certificate)
    response = wizard.upload_issued(renewal.id, bad, chain=wizard.ca.raw.chain_pem)
    assert response.status_code == 422
    for check in ("key_match", "csr_match", "common_name", "sans", "validity"):
        assert f'data-check="{check}"' in response.text, check
    assert "intruder.example.internal" in response.text
    assert _state(wizard, renewal.id) == RenewalState.SUBMITTED and wizard.count(Certificate) == before
    assert wizard.audits("renewal.issued", renewal.id) == []
    fragment = wizard.upload_issued(renewal.id, bad, chain=wizard.ca.raw.chain_pem, htmx=True)
    assert fragment.status_code == 422 and "<html" not in fragment.text and 'data-check="validity"' in fragment.text


def test_unparseable_and_missing_leaf_are_reported(wizard):
    renewal = wizard.submitted()
    garbage = wizard.upload_issued(renewal.id, b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    assert garbage.status_code == 422 and 'data-check="parse"' in garbage.text
    empty = wizard.post(f"/renewals/{renewal.id}/issued", {})
    assert empty.status_code == 422 and 'data-check="parse"' in empty.text
    assert _state(wizard, renewal.id) == RenewalState.SUBMITTED


def test_oversized_inputs_are_rejected_before_parsing(wizard):
    renewal = wizard.submitted()
    huge = b"A" * (1_048_576 + 1)
    leaf = wizard.post(f"/renewals/{renewal.id}/issued", {}, files={"leaf_file": ("big.pem", huge, "text/plain")})
    assert leaf.status_code == 422 and "1,048,576" in leaf.text
    issued = wizard.ca.issue(renewal.csr_pem)
    chain = wizard.post(
        f"/renewals/{renewal.id}/issued",
        {"leaf_text": issued.leaf.decode()},
        files={"chain_file": ("big.pem", huge, "text/plain")},
    )
    assert chain.status_code == 422 and 'data-check="chain"' in chain.text and "1,048,576" in chain.text
    assert _state(wizard, renewal.id) == RenewalState.SUBMITTED


def test_upload_from_the_wrong_state_is_422(wizard):
    renewal = wizard.create_and_generate(_unique(), [_unique("san")])
    response = wizard.upload_issued(renewal.id, wizard.ca.issue(renewal.csr_pem))
    assert response.status_code == 422 and _state(wizard, renewal.id) == RenewalState.CSR_GENERATED


def test_upload_page_has_leaf_and_chain_inputs_and_the_size_limit(signed_in, wizard):
    renewal = wizard.submitted()
    page = signed_in.get(f"/renewals/{renewal.id}?step=upload")
    for field in ("leaf_text", "leaf_file", "chain_text", "chain_file"):
        assert f'name="{field}"' in page.text
    assert "PFX" in page.text and "1 MiB" in page.text
    assert f'action="/renewals/{renewal.id}/issued"' in page.text and 'enctype="multipart/form-data"' in page.text


def test_non_trusted_chain_warnings_are_shown_first_on_the_ready_page(signed_in, wizard):
    renewal = wizard.submitted()
    # No chain at all: the leaf's issuer is missing, which is a warning, never a blocker.
    response = wizard.upload_issued(renewal.id, wizard.ca.issue(renewal.csr_pem), chain=b"")
    assert response.status_code == 303
    page = signed_in.get(response.headers["location"])
    assert _step(page) == ("ready", "issued")
    assert 'data-section="warnings"' in page.text
    assert page.text.index('data-section="warnings"') < page.text.index('id="renewal-summary"')
    warnings = re.search(r'data-section="warnings".*?</section>', page.text, re.DOTALL).group(0)
    assert "issuer" in warnings.lower()
    assert "does not block" in warnings.lower()


def test_ready_page_links_the_deploy_screen_preloaded_with_the_issued_certificate(signed_in, wizard):
    """Plan 3 Task 19 registers deploy/default, so §8.5 step 5 always offers the deploy screen."""
    renewal = wizard.issued()
    page = signed_in.get(f"/renewals/{renewal.id}?step=ready")
    certificate_id = wizard.row(renewal.id).certificate_id
    assert f'href="/deploy?certificate_id={certificate_id}"' in page.text
    assert "Deployment is not available" not in page.text
    assert f'href="/certificates/{certificate_id}"' in page.text


def test_ready_page_deploy_link_matches_the_registry_capability(signed_in, wizard):
    renewal = wizard.issued()
    registry = signed_in.app.state.job_registry
    assert registry.supports(JobType.DEPLOY)
    signed_in.app.state.job_registry = SimpleNamespace(supports=lambda job_type: False)
    try:
        page = signed_in.get(f"/renewals/{renewal.id}?step=ready")
    finally:
        signed_in.app.state.job_registry = registry
    certificate_id = wizard.row(renewal.id).certificate_id
    assert "/deploy?certificate_id=" not in page.text
    assert "Deployment is not available" in page.text
    assert f'href="/certificates/{certificate_id}"' in page.text


# --- cancel --------------------------------------------------------------------------------------------


def test_cancel_requires_a_reason_and_keeps_state_otherwise(wizard):
    renewal = wizard.create_and_generate(_unique(), [_unique("san")])
    for reason in ("", "  "):
        response = wizard.cancel(renewal.id, reason)
        assert response.status_code == 422 and 'data-field="reason"' in response.text
    assert _state(wizard, renewal.id) == RenewalState.CSR_GENERATED
    fragment = wizard.cancel(renewal.id, "", htmx=True)
    assert fragment.status_code == 422 and "<html" not in fragment.text
    assert wizard.audits("renewal.cancelled", renewal.id) == []


@pytest.mark.parametrize("stage", ["draft", "csr_generated", "submitted", "issued"])
def test_cancel_works_from_each_cancellable_state_and_keeps_key_and_history(signed_in, wizard, web_factory, stage):
    name = _unique()
    if stage == "draft":
        renewal_id = wizard.renewal_id(wizard.create(name, [name]))
    elif stage == "csr_generated":
        renewal_id = wizard.create_and_generate(name, [name]).id
    elif stage == "submitted":
        renewal_id = wizard.submitted().id
    else:
        renewal_id = wizard.issued().id
    page = wizard.get(renewal_id)
    assert f'action="/renewals/{renewal_id}/cancel"' in page.text
    before = wizard.row(renewal_id)
    response = wizard.cancel(renewal_id, "Ordered from the wrong CA")
    assert response.status_code == 303 and response.headers["location"].endswith("?step=basics")
    after = wizard.row(renewal_id)
    assert after.state == RenewalState.CANCELLED
    assert (after.key_id, after.csr_pem, after.certificate_id) == (before.key_id, before.csr_pem, before.certificate_id)
    if before.key_id is not None:
        with web_factory() as db:
            assert db.get(PrivateKey, before.key_id) is not None
    cancelled_page = signed_in.get(response.headers["location"])
    assert _step(cancelled_page) == ("basics", "cancelled") and "cancelled" in cancelled_page.text.lower()
    assert "<form" not in cancelled_page.text.split('id="renewal-panel"', 1)[1]
    audit = wizard.audits("renewal.cancelled", renewal_id)
    assert len(audit) == 1 and audit[0].details["reason"] == "Ordered from the wrong CA"


def test_cancelled_renewal_is_read_only(wizard):
    name = _unique()
    renewal_id = wizard.renewal_id(wizard.create(name, [name]))
    wizard.cancel(renewal_id, "no longer needed")
    assert wizard.edit_names(renewal_id, _unique("late")).status_code == 422
    assert wizard.generate(renewal_id, "ecdsa-p256").status_code == 422
    assert wizard.cancel(renewal_id, "again").status_code == 422
    assert _state(wizard, renewal_id) == RenewalState.CANCELLED


# --- finalize / no manual deploy -------------------------------------------------------------------------


def test_no_http_action_marks_a_renewal_deployed(signed_in, wizard, source):
    renewal = wizard.issued(source)
    for path in ("deployed", "mark-deployed", "deploy"):
        response = wizard.post(f"/renewals/{renewal.id}/{path}", {"confirm": "yes"})
        assert response.status_code in (404, 405), path
    assert _state(wizard, renewal.id) == RenewalState.ISSUED
    assert wizard.finalize(renewal.id).status_code == 422  # finalize needs deploy evidence first
    assert _state(wizard, renewal.id) == RenewalState.ISSUED
    page = signed_in.get(f"/renewals/{renewal.id}?step=ready")
    assert "/finalize" not in page.text and "mark_deployed" not in page.text
    assert "mark_deployed" not in Path(web_renewals.__file__).read_text()
    paths = {getattr(route, "path", "") for route in signed_in.app.routes}
    assert not [path for path in paths if path.startswith("/renewals") and "deploy" in path]


def test_done_step_requires_confirmation_and_supersedes_the_previous_certificate(signed_in, wizard, now, source):
    renewal = wizard.deployed(now, source)
    page = signed_in.get(f"/renewals/{renewal.id}?step=done")
    assert _step(page) == ("done", "deployed")
    assert f'action="/renewals/{renewal.id}/finalize"' in page.text
    assert 'name="confirm"' in page.text and 'type="checkbox"' in page.text
    assert re.search(r'name="previous_status"[^>]*value="superseded"[^>]*checked', page.text)
    assert 'value="revoked"' in page.text

    unconfirmed = wizard.finalize(renewal.id, confirm=False)
    assert unconfirmed.status_code == 422 and 'data-field="confirm"' in unconfirmed.text
    assert _state(wizard, renewal.id) == RenewalState.DEPLOYED

    response = wizard.finalize(renewal.id)
    assert response.status_code == 303 and response.headers["location"].endswith("?step=done")
    assert _state(wizard, renewal.id) == RenewalState.DONE
    with wizard.factory() as db:
        assert db.get(Certificate, source.id).status == CertificateStatus.SUPERSEDED
    summary = signed_in.get(response.headers["location"])
    assert _step(summary) == ("done", "done") and "<form" not in summary.text.split('id="renewal-panel"', 1)[1]
    assert wizard.finalize(renewal.id).status_code == 422


def test_revoking_the_previous_certificate_needs_a_reason(wizard, now, source):
    renewal = wizard.deployed(now, source)
    missing = wizard.finalize(renewal.id, previous_status="revoked")
    assert missing.status_code == 422 and 'data-field="reason"' in missing.text
    assert _state(wizard, renewal.id) == RenewalState.DEPLOYED
    bogus = wizard.finalize(renewal.id, previous_status="deleted")
    assert bogus.status_code == 422 and 'data-field="previous_status"' in bogus.text
    ok = wizard.finalize(renewal.id, previous_status="revoked", reason="CA revoked the old certificate")
    assert ok.status_code == 303
    with wizard.factory() as db:
        assert db.get(Certificate, source.id).status == CertificateStatus.REVOKED


# --- CSRF / htmx / audit -----------------------------------------------------------------------------------


def test_every_post_rejects_a_missing_or_wrong_csrf_token(wizard, source):
    name = _unique()
    renewal_id = wizard.renewal_id(wizard.create(name, [name]))
    before = wizard.count()
    paths = [
        f"/renewals/new?from={source.id}",
        "/renewals/new",
        f"/renewals/{renewal_id}/edit",
        f"/renewals/{renewal_id}/generate-csr",
        f"/renewals/{renewal_id}/submit",
        f"/renewals/{renewal_id}/issued",
        f"/renewals/{renewal_id}/finalize",
        f"/renewals/{renewal_id}/cancel",
    ]
    for path in paths:
        assert wizard.client.post(path, data={"reason": "x", "order_reference": "x"}).status_code == 403, path
        wrong = wizard.client.post(path, data={"csrf_token": "wrong", "reason": "x"})
        assert wrong.status_code == 403, path
    assert wizard.count() == before and _state(wizard, renewal_id) == RenewalState.DRAFT


def test_htmx_success_navigates_with_hx_redirect_and_plain_posts_use_303(wizard):
    name = _unique()
    response = wizard.create(name, [name], htmx=True)
    assert response.status_code == 200
    renewal_id = re.search(r"/renewals/([0-9a-f-]{36})", response.headers["HX-Redirect"]).group(1)
    assert response.headers["HX-Redirect"] == f"/renewals/{renewal_id}?step=basics"
    plain = wizard.generate(renewal_id, "ecdsa-p256")
    assert plain.status_code == 303 and "HX-Redirect" not in plain.headers


def test_step_pages_wire_htmx_forms_with_a_panel_target(signed_in, wizard):
    name = _unique()
    renewal_id = wizard.renewal_id(wizard.create(name, [name]))
    page = signed_in.get(f"/renewals/{renewal_id}?step=basics")
    assert 'id="renewal-panel"' in page.text and 'hx-target="#renewal-panel"' in page.text
    assert 'method="post"' in page.text and "htmx:beforeSwap" in page.text  # non-JS forms still work


def test_wizard_audits_record_no_pem_or_secret_material(wizard):
    renewal = wizard.issued()
    with wizard.factory() as db:
        rows = list(db.scalars(select(AuditLog).where(AuditLog.target_id == str(renewal.id))))
    assert {row.action for row in rows} >= {
        "renewal.create",
        "renewal.csr_generated",
        "renewal.submitted",
        "renewal.issued",
    }
    text = str([row.details for row in rows])
    assert "BEGIN" not in text and "PRIVATE" not in text


# --- certificate detail wiring ---------------------------------------------------------------------------------


def test_detail_offers_start_renewal_for_active_certificates(signed_in, source):
    page = signed_in.get(f"/certificates/{source.id}")
    assert f'href="/renewals/new?from={source.id}"' in page.text
    assert not re.search(r"<button[^>]*disabled[^>]*>[^<]*Renew", page.text)


def test_detail_links_to_an_in_flight_renewal(signed_in, wizard, source):
    assert "Continue renewal" not in signed_in.get(f"/certificates/{source.id}").text
    renewal_id = wizard.renewal_id(wizard.post(f"/renewals/new?from={source.id}"))
    page = signed_in.get(f"/certificates/{source.id}")
    assert f'href="/renewals/{renewal_id}"' in page.text and "Continue renewal" in page.text
    wizard.cancel(renewal_id, "done here")
    assert "Continue renewal" not in signed_in.get(f"/certificates/{source.id}").text


def test_detail_does_not_offer_renewal_for_inactive_certificates(signed_in, source, web_factory):
    with web_factory.begin() as db:
        db.get(Certificate, source.id).status = CertificateStatus.REVOKED
    page = signed_in.get(f"/certificates/{source.id}")
    assert f"/renewals/new?from={source.id}" not in page.text
    assert re.search(r"<button[^>]*disabled[^>]*>[^<]*Start renewal", page.text)


# --- gaps: unsaved edits, blank start, wrong-state fragments ----------------------------------------------------


def test_generate_refuses_unsaved_name_edits_but_accepts_the_saved_names(wizard):
    name = _unique()
    renewal_id = wizard.renewal_id(wizard.create(name, [name, "keep.example.internal"]))
    edited = wizard.post(
        f"/renewals/{renewal_id}/generate-csr",
        {"key_algorithm": "ecdsa-p256", "common_name": _unique("other"), "sans": "x.example.internal"},
    )
    assert edited.status_code == 422 and 'data-field="form"' in edited.text and "save" in edited.text.lower()
    blank = wizard.post(f"/renewals/{renewal_id}/generate-csr", {"key_algorithm": "ecdsa-p256", "common_name": ""})
    assert blank.status_code == 422 and wizard.row(renewal_id).state == RenewalState.DRAFT
    same = wizard.post(
        f"/renewals/{renewal_id}/generate-csr",
        {"key_algorithm": "ecdsa-p256", "common_name": name, "sans": f"keep.example.internal\n{name}\n"},
    )
    assert same.status_code == 303 and wizard.row(renewal_id).state == RenewalState.CSR_GENERATED


def test_start_without_a_source_certificate_is_a_blank_form(signed_in, wizard):
    page = signed_in.get("/renewals/new")
    assert page.status_code == 200 and _step(page) == ("basics", "new")
    assert 'action="/renewals/new"' in page.text
    before = wizard.count()
    refused = wizard.post("/renewals/new")
    assert refused.status_code == 422 and 'data-field="common_name"' in refused.text
    assert wizard.count() == before


def test_wrong_state_actions_render_a_fragment_for_htmx(wizard):
    renewal = wizard.issued()
    fragment = wizard.finalize(renewal.id, htmx=True)
    assert fragment.status_code == 422 and "<html" not in fragment.text and 'data-field="form"' in fragment.text
    assert "cannot finalize" in fragment.text
    assert wizard.row(renewal.id).state == RenewalState.ISSUED
