"""First-run setup state shared by the Overview checklist and the Administration hub (UX spec §5.1).

The read model is deliberately small and constant-cost: one bounded statement per fact, no joins and
no per-row loading. ``setup_status`` therefore answers in at most eight statements whatever the size of
the database; the integration test pins that bound.

Steps 3 and 4 are separate on purpose (UX-02): a configured worker key never hides missing host trust.
A worker that has not reported is not an error here — ``worker_reporting`` lets the caller say
``Worker not reporting`` while the database facts still count.
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.jobs.worker import worker_capabilities
from app.models import Server
from app.services.certificates import has_certificates
from app.services.inventory import has_trusted_host_keys
from app.services.inventory_sources import MANUAL_SOURCE
from app.services.settings import get_setting
from app.services.worker_credentials import SSH_PRIVATE_KEY, credential_configured

STEPS = 6


@dataclass(frozen=True)
class SetupStatus:
    """The six checklist facts; ``host_counts`` is ``(active total, manual, repository)``."""

    certificates: bool
    hosts: bool
    host_counts: tuple[int, int, int]
    ssh_key: bool
    host_trust: bool
    worker_reporting: bool
    smtp: bool
    discovered: bool
    done: int

    @property
    def complete(self) -> bool:
        return self.done == STEPS


def setup_status(db: Session, now: datetime) -> SetupStatus:
    """Read the six setup facts with one statement each (at most eight including worker capabilities)."""
    capabilities = worker_capabilities(db, now)
    certificates = has_certificates(db)
    active_hosts = db.scalar(
        select(func.count()).select_from(Server).where(Server.is_active.is_(True))
    ) or 0
    manual_hosts = db.scalar(
        select(func.count())
        .select_from(Server)
        .where(Server.is_active.is_(True), Server.inventory_source == MANUAL_SOURCE)
    ) or 0
    # A database credential counts live, a mounted file only when the worker reported it as a file.
    ssh_key = credential_configured(db, SSH_PRIVATE_KEY) or (
        capabilities is not None and capabilities.ssh_key_file_present is True
    )
    host_trust = (capabilities is not None and capabilities.known_hosts_present) or has_trusted_host_keys(db)
    smtp = bool(get_setting(db, "smtp.host"))
    discovered = (
        db.scalar(select(Server.id).where(Server.last_discovery_status == "ok").limit(1))
        is not None
    )
    done = sum((certificates, bool(active_hosts), ssh_key, host_trust, smtp, discovered))
    return SetupStatus(
        certificates=certificates,
        hosts=bool(active_hosts),
        host_counts=(active_hosts, manual_hosts, active_hosts - manual_hosts),
        ssh_key=ssh_key,
        host_trust=host_trust,
        worker_reporting=capabilities is not None,
        smtp=smtp,
        discovered=discovered,
        done=done,
    )


def setup_steps(status: SetupStatus) -> list[dict[str, object]]:
    """The six rows the checklist renders, in the order of §2.2."""
    return [
        {
            "label": "Import a certificate",
            "done": status.certificates,
            "href": "/certificates/import",
            "action": "Import a certificate",
        },
        {
            "label": "Add the servers you deploy to",
            "done": status.hosts,
            "href": "/inventory",
            "action": "Add hosts",
            "secondary": ("or connect a Git repository (optional)", "/settings?tab=inventory"),
        },
        {
            "label": "Give the worker its SSH key",
            "done": status.ssh_key,
            "href": "/settings?tab=worker",
            "action": "Configure the SSH key",
            "worker_fact": True,
        },
        {
            "label": "Trust your servers' SSH host keys",
            "done": status.host_trust,
            "href": "/ssh-keys",
            "action": "Trust host keys",
            "worker_fact": True,
        },
        {
            "label": "Configure SMTP for alerts",
            "done": status.smtp,
            "href": "/settings?tab=smtp",
            "action": "Configure SMTP",
        },
        {
            "label": "Run discovery",
            "done": status.discovered,
            "href": "/servers#discovery-actions",
            "action": "Run discovery",
        },
    ]
