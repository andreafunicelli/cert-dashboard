"""Advisory locks on dedicated connections (Plan 3 Task 1, spec 3.6)."""

import threading

import pytest
from sqlalchemy import text
from sqlalchemy.pool import NullPool

from app.jobs.locks import (
    DEPLOY_ENQUEUE_LOCK,
    DEPLOY_GLOBAL_LOCK,
    INVENTORY_LOCK,
    AdvisoryLocks,
    host_lock_key,
    xact_lock,
)


@pytest.fixture
def locks(queue_factory):
    helper = AdvisoryLocks(queue_factory.kw["bind"])
    yield helper
    helper.close()


def held(factory, key) -> int:
    """Advisory locks currently granted for ``key`` (any mode), seen from a third connection."""
    with factory() as db:
        return db.scalar(
            text(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted"
                " AND database = (SELECT oid FROM pg_database WHERE datname = current_database())"
                " AND objid::bigint = (hashtext(:key)::bigint & 4294967295)"
            ),
            {"key": key},
        )


def test_the_well_known_keys_and_host_keys():
    assert (DEPLOY_GLOBAL_LOCK, DEPLOY_ENQUEUE_LOCK, INVENTORY_LOCK) == ("deploy:global", "deploy:enqueue", "inventory:pull")
    assert host_lock_key("web01.example.internal") == "deploy:web01.example.internal"


def test_exclusive_excludes_exclusive(locks):
    with locks.session() as first, locks.session() as second:
        assert first.backend_pid != second.backend_pid
        assert first.try_lock(DEPLOY_GLOBAL_LOCK) is True
        assert second.try_lock(DEPLOY_GLOBAL_LOCK) is False
        assert second.try_lock(host_lock_key("web01")) is True  # other keys are independent
        first.unlock(DEPLOY_GLOBAL_LOCK)
        assert second.try_lock(DEPLOY_GLOBAL_LOCK) is True


def test_shared_locks_coexist_and_block_an_exclusive_one(locks):
    with locks.session() as first, locks.session() as second, locks.session() as third:
        assert first.try_lock(INVENTORY_LOCK, shared=True) is True
        assert second.try_lock(INVENTORY_LOCK, shared=True) is True
        assert third.try_lock(INVENTORY_LOCK) is False  # exclusive fails while shared holders exist
        first.unlock(INVENTORY_LOCK, shared=True)
        assert third.try_lock(INVENTORY_LOCK) is False  # one shared holder is left
        second.unlock(INVENTORY_LOCK, shared=True)
        assert third.try_lock(INVENTORY_LOCK) is True
        assert first.try_lock(INVENTORY_LOCK, shared=True) is False  # and an exclusive holder blocks shared


def test_closing_a_session_releases_its_locks(queue_factory, locks):
    with locks.session() as first:
        assert first.try_lock(DEPLOY_GLOBAL_LOCK) and first.try_lock(INVENTORY_LOCK, shared=True)
        assert first.alive() is True
        assert held(queue_factory, DEPLOY_GLOBAL_LOCK) == 1
        pid = first.backend_pid
    assert held(queue_factory, DEPLOY_GLOBAL_LOCK) == 0 and held(queue_factory, INVENTORY_LOCK) == 0
    with queue_factory() as db:
        assert db.scalar(text("SELECT count(*) FROM pg_stat_activity WHERE pid = :pid"), {"pid": pid}) == 0
    with locks.session() as second:
        assert second.try_lock(DEPLOY_GLOBAL_LOCK) is True


def test_a_killed_backend_releases_its_locks_and_is_reported_dead(queue_factory, locks):
    with locks.session() as victim, locks.session() as other:
        assert victim.try_lock(DEPLOY_GLOBAL_LOCK) is True
        with queue_factory.begin() as db:
            db.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": victim.backend_pid})
        assert victim.alive() is False
        assert other.alive() is True
        assert other.try_lock(DEPLOY_GLOBAL_LOCK) is True  # what happens when a worker dies


def test_unlock_of_a_key_that_is_not_held_is_harmless(locks):
    with locks.session() as session:
        session.unlock(DEPLOY_GLOBAL_LOCK)
        session.unlock(INVENTORY_LOCK, shared=True)
        assert session.alive() is True


def test_locks_never_come_from_the_regular_pool(queue_factory, locks):
    engine = queue_factory.kw["bind"]
    before = engine.pool.checkedout()
    with locks.session() as first, locks.session() as second:
        assert first.try_lock(DEPLOY_GLOBAL_LOCK) and second.try_lock(host_lock_key("web01"))
        assert engine.pool.checkedout() == before
    assert engine.pool.checkedout() == before
    assert isinstance(locks.engine.pool, NullPool)
    assert locks.engine is not engine and locks.engine.url == engine.url


def test_xact_lock_serializes_two_transactions_and_is_released_at_commit(queue_factory):
    entered, done, order = threading.Event(), threading.Event(), []

    def second_transaction():
        with queue_factory.begin() as db:
            entered.set()
            xact_lock(db, DEPLOY_ENQUEUE_LOCK)  # blocks until the first transaction ends
            order.append("second")
        done.set()

    with queue_factory.begin() as db:
        xact_lock(db, DEPLOY_ENQUEUE_LOCK)
        worker = threading.Thread(target=second_transaction, daemon=True)
        worker.start()
        assert entered.wait(5)
        assert done.wait(0.5) is False  # still waiting on us
        order.append("first")
    assert done.wait(5)
    worker.join(5)
    assert order == ["first", "second"]
    assert held(queue_factory, DEPLOY_ENQUEUE_LOCK) == 0  # nothing outlives the commits
