"""Overview (``/``): expiry buckets, the first-run setup checklist (Task 17) and the TLS health, recent jobs,
renewals in flight and status strip slots (Plan 2 Task 16); the expiry counters are unchanged.
"""

from fastapi import FastAPI, Request

from app.services.certificates import expiry_counts, has_certificates
from app.services.overview import overview_snapshot
from app.services.servers import unknown_bindings
from app.web.common import _render, display_timezone, install_template_helpers

# (counter key, label, list query): the list filter uses exactly the ranges the counters count.
COUNTERS = (
    ("expired", "Expired", "expiry=expired&status=active"),
    ("lt7", "Expiring in < 7 days", "expiry=lt7&status=active"),
    ("lt30", "Expiring in < 30 days", "expiry=lt30&status=active"),
    ("lt60", "Expiring in < 60 days", "expiry=lt60&status=active"),
    ("total_active", "Total active", "status=active"),
)

# (TLSHealth field, label, link): "never scanned" has no scan-status filter, so it opens the whole endpoint list.
TLS_COUNTERS = (
    ("ok", "OK", "/scans?status=ok"),
    ("mismatch", "Mismatch", "/scans?status=mismatch"),
    ("expired", "Expired", "/scans?status=expired"),
    ("unreachable", "Unreachable", "/scans?status=unreachable"),
    ("error", "Error", "/scans?status=error"),
    ("never_scanned", "Never scanned", "/scans"),
    ("unknown_certificates", "Unknown certificates on servers", "/bindings?match_state=unknown"),
    ("key_mismatch_bindings", "Bindings with a key mismatch", "/bindings?match_state=key_mismatch"),
)


def register_overview_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/")
    def overview(request: Request):
        now = request.app.state.clock()
        with request.app.state.factory() as db:
            counts = expiry_counts(db, now)
            empty = not has_certificates(db)
            snapshot = overview_snapshot(db, now)
            unknown = unknown_bindings(db)
            timezone_name = display_timezone(db)
        counters = [
            {"key": key, "label": label, "count": counts[key], "href": f"/certificates?{query}"}
            for key, label, query in COUNTERS
        ]
        tls_counters = [
            {"key": key, "label": label, "count": getattr(snapshot.tls, key), "href": href}
            for key, label, href in TLS_COUNTERS
        ]
        return _render(
            request, "overview.html.j2", counters=counters, empty=empty, snapshot=snapshot,
            tls_counters=tls_counters, unknown=unknown, tz=timezone_name,
        )
