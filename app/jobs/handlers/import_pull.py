"""Worker handler for ``scan/import_pull``: fetch a served chain and record it as an expectation.

The network call happens first, outside any database transaction. Everything that changes state
(certificate, endpoint, audit) then commits in one transaction. No ``scan_result`` is written:
assessing an endpoint belongs to Plan 2's default scan handler.
"""

from collections.abc import Mapping

from sqlalchemy import func, literal_column
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.crypto.chain import ChainError, order_chain
from app.crypto.parse import ParseError, parse_certificates
from app.jobs.queue import SYSTEM_ACTOR, JobFailure
from app.jobs.worker import JobContext
from app.models import Endpoint, Job, JSONValue, User
from app.models.enums import EndpointSource
from app.services.audit import Actor, record
from app.services.certificates import CertificateMetadata, save_certificate
from app.services.scans import format_hostport, pull_chain, validate_pull_payload

__all__ = ["PULL_TIMEOUT_SECONDS", "import_pull", "validate_pull_payload"]

PULL_TIMEOUT_SECONDS = 10
SOURCE = "pull_endpoint"


def import_pull(context: JobContext, payload: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
    host, port, sni = str(payload["host"]), int(payload["port"]), payload["sni"]  # type: ignore[arg-type]
    label = format_hostport(host, port)
    pulled = pull_chain(host, port, sni if isinstance(sni, str) else None, PULL_TIMEOUT_SECONDS)
    try:
        served = [parse_certificates(der)[0] for der in pulled.der_chain]
        chain = order_chain(served[0].cert, [item.cert for item in served[1:]])
    except (ParseError, ChainError, IndexError):
        raise JobFailure("config_invalid", f"{label}: served certificate could not be parsed") from None
    metadata = CertificateMetadata(**payload["metadata"])  # type: ignore[arg-type]
    leaf = served[0]

    with context.factory.begin() as db:
        job = db.get(Job, context.job_id)
        user = db.get(User, job.requested_by) if job is not None and job.requested_by is not None else None
        actor = Actor(user.id, user.username) if user is not None else SYSTEM_ACTOR
        result = save_certificate(
            db, leaf, chain, metadata, actor, source=SOURCE, validation_time=context.clock()
        )
        certificate_id = result.certificate.id
        upsert = pg_insert(Endpoint).values(
            host=host,
            port=port,
            sni=sni,
            source=EndpointSource.MANUAL,
            expected_certificate_id=certificate_id,
            is_active=True,
        )
        # The identity is the unique index (host, port, coalesce(sni, host)). A conflicting
        # endpoint (for instance one found by discovery) keeps its source and server links;
        # only its expectation changes.
        row = db.execute(
            upsert.on_conflict_do_update(
                index_elements=[Endpoint.host, Endpoint.port, func.coalesce(Endpoint.sni, Endpoint.host)],
                set_={
                    "expected_certificate_id": upsert.excluded.expected_certificate_id,
                    "updated_at": func.now(),
                },
            ).returning(Endpoint.id, literal_column("(xmax = 0)").label("inserted"))
        ).one()
        record(
            db,
            actor,
            "endpoint.upsert",
            "endpoint",
            str(row.id),
            {
                "host": host,
                "port": port,
                "sni": sni,
                "expected_certificate_id": certificate_id,
                "created": bool(row.inserted),
                "source": "pull_import",
            },
        )
    return {
        "certificate_id": certificate_id,
        "created": result.created,
        "warnings": list(result.warnings),
    }
