"""Overview (``/``): expiry buckets and the first-run setup checklist (Task 17).

TLS health, recent jobs, renewals in flight and the status strip are extension slots
(empty template blocks) that later plans fill; the expiry counters stay as they are.
"""

from fastapi import FastAPI, Request

from app.services.certificates import expiry_counts, has_certificates
from app.web.common import _render, install_template_helpers

# (counter key, label, list query): the list filter uses exactly the ranges the counters count.
COUNTERS = (
    ("expired", "Expired", "expiry=expired&status=active"),
    ("lt7", "Expiring in < 7 days", "expiry=lt7&status=active"),
    ("lt30", "Expiring in < 30 days", "expiry=lt30&status=active"),
    ("lt60", "Expiring in < 60 days", "expiry=lt60&status=active"),
    ("total_active", "Total active", "status=active"),
)


def register_overview_routes(app: FastAPI) -> None:
    install_template_helpers(app)

    @app.get("/")
    def overview(request: Request):
        with request.app.state.factory() as db:
            counts = expiry_counts(db, request.app.state.clock())
            empty = not has_certificates(db)
        counters = [
            {"key": key, "label": label, "count": counts[key], "href": f"/certificates?{query}"}
            for key, label, query in COUNTERS
        ]
        return _render(request, "overview.html.j2", counters=counters, empty=empty)
