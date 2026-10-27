from sqlalchemy import select

from app.models import AuditLog
from app.services.inventory import InventoryInconsistency, audit_inconsistency


def test_a_detected_inconsistency_is_committed_as_one_audit_row(web_factory):
    hook = audit_inconsistency(web_factory, job_id="job-7")
    hook(InventoryInconsistency("mismatch", expected="a" * 40, actual="b" * 40))
    with web_factory() as db:
        (row,) = db.scalars(select(AuditLog).where(AuditLog.action == "inventory.inconsistent")).all()
    assert (row.target_type, row.actor_label) == ("inventory", "system")
    assert row.details == {"reason": "mismatch", "expected_rev": "a" * 40, "actual_rev": "b" * 40, "job_id": "job-7"}
