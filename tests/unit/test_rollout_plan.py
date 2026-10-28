import itertools
import random

import pytest

from app.services.deploy import (
    PlanError,
    PlanServer,
    batch_size,
    default_canary,
    plan_batches,
    rotation_group,
)


def _names(plan):
    return [[server.hostname for server in batch] for batch in plan]


@pytest.mark.parametrize(
    ("total", "percent", "sizes"),
    [
        (1, 10, [1]),
        (2, 10, [1, 1]),
        (9, 10, [1] * 9),
        (10, 10, [1] * 10),
        (11, 10, [1, 2, 2, 2, 2, 2]),
        (500, 10, [1] + [50] * 9 + [49]),
        (100, 100, [1, 99]),
    ],
)
def test_batch_sizes_match_the_spec_matrix(total, percent, sizes):
    servers = [PlanServer(i, f"web{i:03}.example.internal", ("ring",), (i,)) for i in range(1, total + 1)]
    assert [
        len(batch) for batch in plan_batches(servers, canary_server_id=None, batch_percent=percent)
    ] == sizes


def test_canary_is_the_first_server_of_the_smallest_group_and_batches_spread_across_groups():
    servers = [
        PlanServer(1, "a1", ("alpha",), (1,)),
        PlanServer(2, "a2", ("alpha",), (2,)),
        PlanServer(3, "b1", ("beta",), (3,)),
        PlanServer(4, "b2", ("beta",), (4,)),
        PlanServer(5, "c1", ("gamma",), (5,)),
    ]
    plan = plan_batches(servers, canary_server_id=None, batch_percent=40)
    assert _names(plan) == [["c1"], ["a1", "b1"], ["a2", "b2"]]


@pytest.mark.parametrize(
    ("total", "percent", "expected"),
    [(1, 1, 1), (3, 50, 2), (3, 33, 1), (7, 100, 7), (10, 10, 1), (11, 10, 2), (1000, 1, 10)],
)
def test_batch_size_uses_integer_ceiling(total, percent, expected):
    assert batch_size(total, percent) == expected


@pytest.mark.parametrize("percent", [0, -1, 101, 1000])
def test_batch_percent_outside_one_to_hundred_is_rejected(percent):
    servers = [PlanServer(1, "a", ("g",), (1,))]
    with pytest.raises(PlanError):
        plan_batches(servers, canary_server_id=None, batch_percent=percent)
    with pytest.raises(PlanError):
        batch_size(1, percent)


def test_an_empty_server_list_is_rejected():
    with pytest.raises(PlanError):
        plan_batches([], canary_server_id=None, batch_percent=10)
    with pytest.raises(PlanError):
        default_canary([])
    with pytest.raises(PlanError):
        batch_size(0, 10)


def test_duplicate_server_ids_are_rejected():
    servers = [PlanServer(1, "a", ("g",), (1,)), PlanServer(1, "b", ("g",), (2,))]
    with pytest.raises(PlanError):
        plan_batches(servers, canary_server_id=None, batch_percent=10)


def test_an_explicit_canary_is_honoured_and_removed_from_the_rotation():
    servers = [
        PlanServer(1, "a1", ("alpha",), (1,)),
        PlanServer(2, "a2", ("alpha",), (2,)),
        PlanServer(3, "b1", ("beta",), (3,)),
        PlanServer(4, "b2", ("beta",), (4,)),
        PlanServer(5, "c1", ("gamma",), (5,)),
    ]
    plan = plan_batches(servers, canary_server_id=4, batch_percent=40)
    assert _names(plan) == [["b2"], ["a1", "b1"], ["c1", "a2"]]
    assert sorted(name for batch in _names(plan) for name in batch) == ["a1", "a2", "b1", "b2", "c1"]


def test_an_unknown_canary_is_rejected():
    servers = [PlanServer(1, "a1", ("alpha",), (1,))]
    with pytest.raises(PlanError, match="canary"):
        plan_batches(servers, canary_server_id=99, batch_percent=10)


def test_the_plan_is_independent_of_the_input_order():
    servers = [
        PlanServer(i, f"{group}{i}", (group,), (i,))
        for i, group in enumerate(["alpha", "beta", "alpha", "gamma", "beta", "alpha", "delta"], start=1)
    ]
    expected = _names(plan_batches(servers, canary_server_id=None, batch_percent=30))
    rng = random.Random(7)
    for _ in range(10):
        shuffled = servers[:]
        rng.shuffle(shuffled)
        assert _names(plan_batches(shuffled, canary_server_id=None, batch_percent=30)) == expected
    for perm in itertools.islice(itertools.permutations(servers[:4]), 6):
        assert default_canary(list(perm)) == default_canary(servers[:4])


def test_servers_without_groups_rotate_as_ungrouped():
    server = PlanServer(1, "solo", (), (1,))
    assert rotation_group(server) == "ungrouped"
    servers = [server, PlanServer(2, "z", ("zeta",), (2,)), PlanServer(3, "y", (), (3,))]
    # ungrouped has 2 members, zeta 1 -> zeta is the smallest group and supplies the canary
    assert _names(plan_batches(servers, canary_server_id=None, batch_percent=100)) == [["z"], ["solo", "y"]]


def test_multi_group_servers_rotate_under_their_smallest_group_but_count_in_every_group_for_the_canary():
    multi = PlanServer(1, "m1", ("beta", "alpha"), (1,))
    assert rotation_group(multi) == "alpha"
    servers = [
        multi,
        PlanServer(2, "a2", ("alpha",), (2,)),
        PlanServer(3, "a3", ("alpha",), (3,)),
        PlanServer(4, "b1", ("beta",), (4,)),
    ]
    # beta (m1, b1) has 2 members, alpha (m1, a2, a3) has 3: the canary comes from beta, by hostname
    assert default_canary(servers).hostname == "b1"
    plan = plan_batches(servers, canary_server_id=None, batch_percent=50)
    assert _names(plan) == [["b1"], ["a2", "a3"], ["m1"]]


def test_canary_group_ties_are_broken_by_group_name():
    servers = [PlanServer(1, "z1", ("zulu",), (1,)), PlanServer(2, "a1", ("alpha",), (2,))]
    assert default_canary(servers).hostname == "a1"


def test_a_server_with_several_bindings_is_one_execution_unit():
    servers = [PlanServer(1, "a", ("g",), (10, 11, 12)), PlanServer(2, "b", ("g",), (13,))]
    plan = plan_batches(servers, canary_server_id=None, batch_percent=100)
    assert [len(batch) for batch in plan] == [1, 1]
    assert plan[0][0].binding_ids == (10, 11, 12)


def test_a_single_server_is_just_the_canary_batch():
    servers = [PlanServer(1, "only", ("g",), (1,))]
    assert _names(plan_batches(servers, canary_server_id=1, batch_percent=100)) == [["only"]]


def test_deploy_planning_module_imports_nothing_from_app_ansible():
    import ast
    from pathlib import Path

    tree = ast.parse(Path("app/services/deploy.py").read_text())
    imported = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)] + [
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    ]
    assert not [name for name in imported if name.startswith("app.ansible")]
