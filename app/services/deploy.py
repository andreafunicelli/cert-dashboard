"""Pure deploy planning shared by the web process and the worker (§6.4, §6.5).

Rollout planning (canary + round-robin batches), the stop-at-first-failure batch executor and the
write-once file map. Nothing here touches the database, the network or ``app.ansible``: callers
pass plain values in and get plain values back, so the module is deterministic and unit-testable.

File roles follow D1: a ``chain`` write exists only for a target whose ``chain_path`` is set — the
value discovery recorded after verifying the chain file's signature. ``plan_file_writes`` receives
no issuer or subject data and never infers a chain from paths or ordering.
"""

from collections import defaultdict
from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Literal

UNGROUPED = "ungrouped"


class PlanError(ValueError):
    """The rollout cannot be planned (empty selection, bad percentage, unknown canary)."""


@dataclass(frozen=True)
class PlanServer:
    server_id: int
    hostname: str
    groups: tuple[str, ...]
    binding_ids: tuple[int, ...]


def batch_size(total_servers: int, batch_percent: int) -> int:
    """``max(1, ceil(total * percent / 100))`` in integer arithmetic; total includes the canary."""
    if total_servers < 1:
        raise PlanError("a rollout needs at least one server")
    if not 1 <= batch_percent <= 100:
        raise PlanError("batch_percent must be between 1 and 100")
    return max(1, -(-total_servers * batch_percent // 100))


def rotation_group(server: PlanServer) -> str:
    """The lexicographically smallest Ansible group, ``ungrouped`` when there is none."""
    return min(server.groups, default=UNGROUPED)


def _order(server: PlanServer) -> tuple[str, int]:
    return (server.hostname, server.server_id)


def default_canary(servers: Sequence[PlanServer]) -> PlanServer:
    """First server by hostname of the smallest group (ties by name), counting every membership."""
    if not servers:
        raise PlanError("a rollout needs at least one server")
    members: dict[str, list[PlanServer]] = defaultdict(list)
    for server in servers:
        for group in server.groups or (UNGROUPED,):
            members[group].append(server)
    smallest = min(members, key=lambda group: (len(members[group]), group))
    return min(members[smallest], key=_order)


def plan_batches(
    servers: Sequence[PlanServer], *, canary_server_id: int | None, batch_percent: int
) -> list[list[PlanServer]]:
    """Batch 0 is the canary; the rest are consecutive chunks of ``batch_size`` taken round-robin
    across rotation groups (groups by name, servers by hostname)."""
    if not servers:
        raise PlanError("a rollout needs at least one server")
    if len({server.server_id for server in servers}) != len(servers):
        raise PlanError("a server appears more than once in the rollout")
    size = batch_size(len(servers), batch_percent)
    if canary_server_id is None:
        canary = default_canary(servers)
    else:
        canary = next((s for s in servers if s.server_id == canary_server_id), None)
        if canary is None:
            raise PlanError(f"canary server {canary_server_id} is not part of the rollout")

    queues: dict[str, list[PlanServer]] = defaultdict(list)
    for server in sorted(servers, key=_order):
        if server.server_id != canary.server_id:
            queues[rotation_group(server)].append(server)
    rotation: list[PlanServer] = []
    columns = [queues[group] for group in sorted(queues)]
    for depth in range(max(map(len, columns), default=0)):
        rotation.extend(column[depth] for column in columns if depth < len(column))
    return [[canary], *(rotation[i : i + size] for i in range(0, len(rotation), size))]


@dataclass(frozen=True)
class BatchRun[H, R]:
    """Outcome of one batch: ``results`` in completion order, hosts never submitted, first failure."""

    results: dict[H, R | BaseException]
    not_started: tuple[H, ...]
    stopped_by: H | None


def run_batch[H, R](
    hosts: Sequence[H],
    *,
    concurrency: int,
    run_one: Callable[[H], R],
    failed: Callable[[R], bool],
    should_stop: Callable[[], bool] = lambda: False,
    _executor_factory: Callable[..., ThreadPoolExecutor] = ThreadPoolExecutor,
) -> BatchRun[H, R]:
    """Run ``hosts`` with incremental submission: a host is submitted only while fewer than
    ``concurrency`` futures are unfinished and no failure (a result for which ``failed`` is true, or
    an exception) or stop request was seen. In-flight hosts always finish; the rest are returned in
    ``not_started``. Never ``executor.map`` / submit-all: a queued future would still run after a
    failure."""
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    if len(set(hosts)) != len(hosts):
        raise ValueError("hosts must be unique")
    results: dict[H, R | BaseException] = {}
    stopped_by: H | None = None
    submitted = 0
    in_flight: dict[Future[R], tuple[int, H]] = {}
    halted = False
    with _executor_factory(max_workers=concurrency) as executor:
        while True:
            halted = halted or should_stop()
            while not halted and len(in_flight) < concurrency and submitted < len(hosts):
                host = hosts[submitted]
                in_flight[executor.submit(run_one, host)] = (submitted, host)
                submitted += 1
                halted = should_stop()
            if not in_flight:
                break
            done, _ = wait(in_flight, timeout=None, return_when=FIRST_COMPLETED)
            for future in sorted(done, key=lambda f: in_flight[f][0]):
                _, host = in_flight.pop(future)
                error = future.exception()
                outcome: R | BaseException = error if error is not None else future.result()
                results[host] = outcome
                if error is not None or failed(outcome):  # type: ignore[arg-type]
                    halted = True
                    if stopped_by is None:
                        stopped_by = host
    return BatchRun(results, tuple(hosts[submitted:]), stopped_by)


class FileConflict(ValueError):
    """One path would need two different contents; ``path`` names it."""

    def __init__(self, path: str) -> None:
        super().__init__(f"conflicting writes planned for {path}")
        self.path = path


@dataclass(frozen=True)
class DeployTarget:
    binding_id: int
    cert_path: str
    chain_path: str | None
    key_path: str
    expected_fingerprint: str | None
    new_fingerprint: str
    port: int
    sni: str | None


@dataclass(frozen=True)
class FileWrite:
    path: str
    kind: Literal["leaf", "fullchain", "chain", "key"]
    binding_ids: tuple[int, ...]


def plan_file_writes(targets: Sequence[DeployTarget]) -> tuple[FileWrite, ...]:
    """Map every distinct path to exactly one write, sorted by path.

    ``cert_path`` gets the leaf when the target has an explicit ``chain_path`` (which gets the
    chain), otherwise the full chain; ``key_path`` gets the key. Bindings sharing a path share one
    write; a path needed with different content raises ``FileConflict``.
    """
    planned: dict[str, tuple[str, str | None, set[int]]] = {}

    def need(path: str, kind: str, content: str | None, binding_id: int) -> None:
        # content: the certificate a cert-type file carries (keys follow that certificate's key).
        current = planned.setdefault(path, (kind, content, set()))
        if current[:2] != (kind, content):
            raise FileConflict(path)
        current[2].add(binding_id)

    for target in targets:
        need(target.key_path, "key", target.new_fingerprint, target.binding_id)
        if target.chain_path is None:
            need(target.cert_path, "fullchain", target.new_fingerprint, target.binding_id)
        else:
            need(target.cert_path, "leaf", target.new_fingerprint, target.binding_id)
            need(target.chain_path, "chain", target.new_fingerprint, target.binding_id)
    return tuple(
        FileWrite(path, kind, tuple(sorted(ids)))  # type: ignore[arg-type]
        for path, (kind, _, ids) in sorted(planned.items())
    )
