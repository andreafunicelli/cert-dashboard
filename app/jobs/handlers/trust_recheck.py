"""Worker handler for ``scan/trust_recheck``: re-evaluate every stored chain against today's clock.

Time moves trust: an intermediate can expire without any upload or anchor change. The recheck is the
only writer of ``certificate.chain_status`` (observed endpoint certificates are never trusted); it
runs in one transaction and audits only the statuses that changed (``certificate.chain_check``).
"""

from collections.abc import Mapping

from app.jobs.worker import JobContext
from app.models import JSONValue
from app.services.trust_anchors import recheck_chain_statuses

__all__ = ["TRUST_RECHECK_ACTION", "trust_recheck", "validate_trust_recheck_payload"]

TRUST_RECHECK_ACTION = "trust_recheck"


def validate_trust_recheck_payload(payload: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """Accept exactly ``{"action": "trust_recheck"}``; anything else raises ``ValueError``."""
    if not isinstance(payload, Mapping) or dict(payload) != {"action": TRUST_RECHECK_ACTION}:
        raise ValueError("a trust recheck payload is exactly its action")
    return {"action": TRUST_RECHECK_ACTION}


def trust_recheck(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
    now = context.clock()
    with context.factory.begin() as db:
        counts = recheck_chain_statuses(db, now)
    return {**counts, "validation_time": now.isoformat()}
