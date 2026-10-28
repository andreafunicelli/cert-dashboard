import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor

import pytest

from app.services.deploy import BatchRun, run_batch

WAIT = 5


def test_first_failure_stops_submission_and_lets_the_in_flight_host_finish():
    h1_failed, h2_started = threading.Event(), threading.Event()
    started, active, peak, lock = [], [0], [0], threading.Lock()

    def run_one(host):
        with lock:
            started.append(host)
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        try:
            if host == "h1":
                assert h2_started.wait(WAIT)  # fails while h2 is certainly in flight
                return "failed"
            if host == "h2":
                h2_started.set()
                assert h1_failed.wait(WAIT)  # slow host: still running when h1's failure is seen
                time.sleep(0.2)
            return "succeeded"
        finally:
            with lock:
                active[0] -= 1

    def failed(result):
        if result == "failed":
            h1_failed.set()
        return result == "failed"

    run = run_batch(["h1", "h2", "h3", "h4", "h5"], concurrency=2, run_one=run_one, failed=failed)
    assert sorted(started) == ["h1", "h2"]  # h3-h5 were never submitted, so never started
    assert run.results == {"h1": "failed", "h2": "succeeded"} and run.stopped_by == "h1"
    assert run.not_started == ("h3", "h4", "h5") and peak[0] <= 2


def test_without_failures_every_host_runs_in_plan_order_with_bounded_concurrency():
    started, active, peak, lock = [], [0], [0], threading.Lock()
    two_running = threading.Barrier(2, timeout=WAIT)

    def run_one(host):
        with lock:
            started.append(host)
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        try:
            if host in ("h1", "h2"):
                two_running.wait()  # proves two hosts really run at the same time
            else:
                time.sleep(0.02)
            return host.upper()
        finally:
            with lock:
                active[0] -= 1

    hosts = ["h1", "h2", "h3", "h4", "h5"]
    run = run_batch(hosts, concurrency=2, run_one=run_one, failed=lambda r: False)
    assert started[:2] == ["h1", "h2"] and sorted(started) == hosts
    assert started.index("h3") < started.index("h4") < started.index("h5")
    assert peak[0] == 2
    assert run.not_started == () and run.stopped_by is None
    assert run.results == {h: h.upper() for h in hosts}
    assert isinstance(run, BatchRun)


def test_an_exception_counts_as_a_failure():
    started = []

    def run_one(host):
        started.append(host)
        if host == "h1":
            raise RuntimeError("boom")
        return "ok"

    run = run_batch(["h1", "h2", "h3"], concurrency=1, run_one=run_one, failed=lambda r: False)
    assert started == ["h1"]
    assert isinstance(run.results["h1"], RuntimeError) and str(run.results["h1"]) == "boom"
    assert run.stopped_by == "h1" and run.not_started == ("h2", "h3")


def test_should_stop_prevents_further_submission():
    stop = threading.Event()
    started, lock = [], threading.Lock()
    h2_in_flight = threading.Event()

    def run_one(host):
        with lock:
            started.append(host)
        if host == "h1":
            assert h2_in_flight.wait(WAIT)
            stop.set()
            return "done"
        if host == "h2":
            h2_in_flight.set()
            assert stop.wait(WAIT)
            time.sleep(0.1)
            return "done-late"
        return "unexpected"

    run = run_batch(
        ["h1", "h2", "h3", "h4"],
        concurrency=2,
        run_one=run_one,
        failed=lambda r: False,
        should_stop=stop.is_set,
    )
    assert sorted(started) == ["h1", "h2"]
    assert run.results == {"h1": "done", "h2": "done-late"}
    assert run.not_started == ("h3", "h4") and run.stopped_by is None


def test_should_stop_already_true_starts_nothing():
    run = run_batch(
        ["h1", "h2"],
        concurrency=2,
        run_one=lambda h: pytest.fail("started"),
        failed=lambda r: False,
        should_stop=lambda: True,
    )
    assert run.results == {} and run.not_started == ("h1", "h2") and run.stopped_by is None


def test_concurrency_larger_than_the_batch():
    run = run_batch(["h1", "h2"], concurrency=50, run_one=lambda h: h, failed=lambda r: False)
    assert run.results == {"h1": "h1", "h2": "h2"} and run.not_started == ()


def test_an_empty_batch_runs_nothing():
    run = run_batch([], concurrency=3, run_one=lambda h: pytest.fail("started"), failed=lambda r: True)
    assert run == BatchRun({}, (), None)


@pytest.mark.parametrize("concurrency", [0, -1])
def test_concurrency_below_one_is_rejected(concurrency):
    with pytest.raises(ValueError):
        run_batch(["h1"], concurrency=concurrency, run_one=lambda h: h, failed=lambda r: False)


def test_duplicate_hosts_are_rejected():
    with pytest.raises(ValueError):
        run_batch(["h1", "h1"], concurrency=1, run_one=lambda h: h, failed=lambda r: False)


class _RecordingExecutor(ThreadPoolExecutor):
    """Real pool that records how many submitted futures were unfinished at each submit."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pending_at_submit: list[int] = []
        self.futures: list[Future] = []
        self.map_calls = 0

    def submit(self, fn, /, *args, **kwargs):
        self.pending_at_submit.append(sum(1 for f in self.futures if not f.done()) + 1)
        future = super().submit(fn, *args, **kwargs)
        self.futures.append(future)
        return future

    def map(self, *args, **kwargs):
        self.map_calls += 1
        return super().map(*args, **kwargs)


def test_submit_all_is_never_used():
    created: list[_RecordingExecutor] = []

    def factory(*args, **kwargs):
        executor = _RecordingExecutor(*args, **kwargs)
        created.append(executor)
        return executor

    def run_one(host):
        time.sleep(0.02)
        return host

    hosts = [f"h{i}" for i in range(1, 9)]
    run = run_batch(hosts, concurrency=3, run_one=run_one, failed=lambda r: False, _executor_factory=factory)
    assert list(run.results) and sorted(run.results) == hosts
    (executor,) = created
    assert len(executor.futures) == len(hosts)
    assert max(executor.pending_at_submit) <= 3
    assert executor.map_calls == 0
