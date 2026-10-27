"""Postgres advisory locks on dedicated connections (spec 3.6, Plan 3 Contract decision 4).

Session locks live on connections of a private ``NullPool`` engine, never on the application pool:
a deploy holds one connection per host run (``deploy.concurrency`` <= 50), which must not starve
regular queries. Every lock is a non-blocking ``try``; closing the session closes the connection,
so the server releases everything, which is also what happens when a worker dies.
"""

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

DEPLOY_GLOBAL_LOCK = "deploy:global"
DEPLOY_ENQUEUE_LOCK = "deploy:enqueue"
INVENTORY_LOCK = "inventory:pull"

_TRY = {False: "SELECT pg_try_advisory_lock(hashtext(:key))", True: "SELECT pg_try_advisory_lock_shared(hashtext(:key))"}
_UNLOCK = {False: "SELECT pg_advisory_unlock(hashtext(:key))", True: "SELECT pg_advisory_unlock_shared(hashtext(:key))"}


def host_lock_key(hostname: str) -> str:
    return f"deploy:{hostname}"


class LockSession:
    """One dedicated autocommit connection; the advisory locks taken on it die with it."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection
        self.backend_pid: int = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()

    def try_lock(self, key: str, *, shared: bool = False) -> bool:
        """Take ``key`` without waiting; ``False`` when another session holds a conflicting lock."""
        return bool(self._connection.execute(text(_TRY[shared]), {"key": key}).scalar())

    def unlock(self, key: str, *, shared: bool = False) -> None:
        """Release one hold on ``key`` (a key that is not held is a no-op)."""
        self._connection.execute(text(_UNLOCK[shared]), {"key": key})

    def alive(self) -> bool:
        """True while the server-side session (and therefore every lock on it) still exists."""
        try:
            self._connection.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001 - any failure means the session, and its locks, are gone
            return False
        return True

    def close(self) -> None:
        _discard(self._connection)


class AdvisoryLocks:
    """Factory of lock sessions on a private ``NullPool`` engine sharing the application URL."""

    def __init__(self, engine: Engine) -> None:
        self.engine = create_engine(engine.url, poolclass=NullPool, hide_parameters=True)

    @contextmanager
    def session(self) -> Iterator[LockSession]:
        connection = self.engine.connect().execution_options(isolation_level="AUTOCOMMIT")
        try:
            yield LockSession(connection)
        finally:
            _discard(connection)

    def close(self) -> None:
        self.engine.dispose()


def xact_lock(db: Session, key: str) -> None:
    """Block until ``key`` is free, then hold it until the caller's transaction ends."""
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": key})


def _discard(connection: Connection) -> None:
    """Really close a connection (never hand it back anywhere: it may carry an advisory lock)."""
    for step in (connection.invalidate, connection.close):
        try:
            step()
        except Exception:  # noqa: BLE001, S110 - best effort; the server drops dead sessions
            pass
