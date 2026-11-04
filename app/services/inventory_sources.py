"""Inventory source vocabulary (Slice B decision D1): manual rows are dashboard-owned.

A host is either *manual* (created in the dashboard, ``inventory_source = 'manual'``) or belongs to
the configured Git inventory, whose marker is the revision triple ``<ref>:<path>@<sha>``. Git stays
authoritative for every hostname it lists; a manual row is adopted on reconciliation. No repository
is required for manual hosts to exist, be discovered or be deployed to.
"""

MANUAL_SOURCE = "manual"


def is_manual(source: str | None) -> bool:
    """True only for the manual marker: every other value is a repository revision."""
    return source == MANUAL_SOURCE
