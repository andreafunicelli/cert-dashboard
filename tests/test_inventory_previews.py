"""Repository-only inventory fixture and fragment checks (not runtime image inputs)."""

from copy import deepcopy

from scripts.render_previews import environment, fixtures
from tests.test_ui_previews import Elements


def rendered(name):
    template, context = fixtures()[name]
    return environment().get_template(template).render(context)


def fragment(name, block, **updates):
    source, context = fixtures()[name]
    template = environment().get_template(source)
    return "".join(template.blocks[block](template.new_context(context | updates)))


def test_all_inventory_posts_keep_csrf_and_native_method_action():
    for name in fixtures():
        if name.startswith(("certificate-", "renewal-", "scan-", "import")):
            elements = Elements(rendered(name)).elements
            ids = [a["id"] for _, a in elements if "id" in a]
            assert len(ids) == len(set(ids)), name
            assert all(a["for"] in ids for t, a in elements if t == "label" and "for" in a), name
            for t, a in elements:
                if t == "form":
                    assert a["method"] in ("get", "post") and a["action"].startswith("/"), name
                if t == "input" and a.get("name") == "csrf_token":
                    assert a["type"] == "hidden" and a["value"] == "preview-only-not-a-valid-token"
                if t in ("input", "select", "textarea") and "name" in a:
                    assert a["name"] != "", name


def test_target_named_native_confirmations_wrap_existing_status_chain_and_finalize():
    html = rendered("certificate-detail")
    assert "Change the status of gateway.ops.example.test (#42)" in html
    assert "Replace the stored chain for gateway.ops.example.test (#42)" in html
    for action in ("/certificates/42/status", "/certificates/42/chain"):
        section = html[: html.index(f'action="{action}"')]
        assert section.rfind('<details class="confirmation"') > section.rfind("</details>")
    done = rendered("renewal-done")
    assert "Finalize gateway.ops.example.test and retire gateway.ops.example.test (#42)" in done
    assert 'name="confirm" value="yes" required' in done
    assert 'name="previous_status" value="revoked"' in done
    assert 'action="/renewals/fixture-renewal/finalize"' in done


def test_steps_match_real_six_screen_flow_and_no_future_dead_end_links():
    for index, step in enumerate(("basics", "csr", "submitted", "upload", "ready", "done"), 1):
        html = rendered(f"renewal-{step}")
        assert f'Step <span class="mono">{index}</span> of <span class="mono">6</span>' in html
        assert f'data-step="{step}"' in html and 'aria-current="step"' in html
        assert "Back to certificate" in html
    csr = rendered("renewal-csr")
    assert '?step=ready"' not in csr
    assert 'class="material" id="csr-pem" tabindex="0"' in csr
    assert "data-csr-sha256" in csr


def test_scan_outcomes_and_current_chain_verdict_are_unambiguous():
    for name, label in (
        ("scan-findings", "Findings: mismatch"),
        ("scan-clear", "No findings"),
        ("scan-failed", "Scan failed: error"),
        ("scan-unscanned", "Not scanned"),
    ):
        html = rendered(name)
        assert label in html
    assert "not a complete TLS security audit" in rendered("scan-clear")
    assert "Do not interpret missing observations as a healthy endpoint" in rendered("scan-failed")
    template, context = fixtures()["certificate-detail"]
    context = deepcopy(context)
    context["c"].chain_status.value = "trusted"
    context["detail"].diagnostics.status = None
    html = environment().get_template(template).render(context | {"recheck_failed": True})
    summary = html.split('id="summary-panel"', 1)[1].split("</section>", 1)[0]
    assert "Incomplete chain" in summary and "Trusted chain" not in summary


def test_renewal_ready_never_presents_cached_trust_as_current():
    source, context = fixtures()["renewal-ready"]
    context = deepcopy(context)
    context["certificate"].chain_status.value = "trusted"
    context["warnings"] = ["The issuer certificate is missing from the chain."]
    html = environment().get_template(source).render(context)
    assert "Trusted chain" not in html
    assert "Stored chain assessment" in html and "cached, not a current trust verdict" in html
    assert "The issuer certificate is missing" in html


def test_htmx_error_fragments_render_without_page_or_missing_macros():
    for name, block, updates, expected in [
        (
            "certificate-detail",
            "status_panel",
            {"status_errors": {"form": "Choose a reason."}},
            "Choose a reason.",
        ),
        (
            "certificate-detail",
            "chain_panel",
            {"chain_errors": {"chain": "Missing chain."}},
            "Missing chain.",
        ),
        ("certificate-edit", "metadata_panel", {}, "Save details"),
        (
            "renewal-csr",
            "panel",
            {"errors": {"order_reference": ["Missing reference."]}},
            "Missing reference.",
        ),
        ("renewal-upload", "panel", {"errors": {"parse": ["Invalid certificate."]}}, "Invalid certificate."),
        ("scan-findings", "history", {}, "Findings: mismatch"),
        (
            "scan-findings",
            "manage",
            {"errors": {"certificate_id": "Choose an active certificate."}},
            "Choose an active certificate.",
        ),
        ("import", "upload_panel", {"errors": {"key": ["Invalid key."]}}, "Invalid key."),
        ("import-progress", "status", {}, "The import failed"),
    ]:
        # Metadata is defined in detail, while edit includes that shared partial.
        source = "certificate-detail" if block == "metadata_panel" else name
        html = fragment(source, block, **updates)
        assert expected in html and "<html" not in html and "<script" not in html


def test_list_preserves_filters_hooks_and_right_aligned_counts():
    elements = Elements(rendered("certificate-list")).elements
    names = {a["name"] for t, a in elements if t in ("input", "select") and "name" in a}
    assert names == {
        "search",
        "status",
        "expiry",
        "issuer",
        "team",
        "owner",
        "has_key",
        "has_bindings",
        "renewal_state",
        "sort",
        "page_size",
    }
    html = rendered("certificate-list")
    assert html.count("data-cn=") == 5 and 'data-total="5"' in html
    assert 'class="numeric"' in html and "chip-expired" in html
    for state in ("Valid", "Expiring", "Expired", "Revoked", "Unknown validity"):
        assert state in html
