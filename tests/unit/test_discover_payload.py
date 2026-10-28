"""``discover/default`` payloads (Plan 3 Task 10, Contract decision 12): names can never carry Ansible pattern syntax."""

import pytest

from app.jobs.handlers.discover import ON_DEMAND_PRIORITY, validate_discover_payload

HOSTS_500 = [f"web{number:03d}.example.internal" for number in range(500)]


def test_the_on_demand_priority_is_200():
    assert ON_DEMAND_PRIORITY == 200


def test_the_empty_payload_means_the_whole_inventory():
    assert validate_discover_payload({}) == {}


def test_hosts_and_groups_are_accepted_as_given():
    assert validate_discover_payload({"hosts": ["web01.example.internal", "db_01"]}) == {
        "hosts": ["web01.example.internal", "db_01"]
    }
    assert validate_discover_payload({"groups": ["ring_a", "canary-ring"]}) == {"groups": ["ring_a", "canary-ring"]}


def test_the_documented_limits_are_inclusive():
    assert validate_discover_payload({"hosts": HOSTS_500}) == {"hosts": HOSTS_500}
    assert validate_discover_payload({"hosts": ["a" * 253]}) == {"hosts": ["a" * 253]}
    groups = [f"group{number}" for number in range(50)]
    assert validate_discover_payload({"groups": groups}) == {"groups": groups}


@pytest.mark.parametrize(
    "payload",
    [
        {"hosts": []},
        {"groups": []},
        {"hosts": ["a", "a"]},
        {"groups": ["g", "g"]},
        {"hosts": [*HOSTS_500, "one-too-many.example.internal"]},
        {"groups": [f"group{number}" for number in range(51)]},
        {"hosts": ["a"], "groups": ["g"]},
        {"hosts": "web01"},
        {"hosts": ["a", 7]},
        {"hosts": [None]},
        {"hosts": ["a" * 254]},
        {"hosts": [""]},
        {"hosts": ["."]},
        {"hosts": [".."]},
        {"hosts": {"web01": True}},
        {"scope": "all"},
        {"hosts": ["web01"], "limit": "all"},
        {"action": "test_pull"},
        {"action": "default"},
    ],
)
def test_malformed_payloads_are_refused(payload):
    with pytest.raises(ValueError):
        validate_discover_payload(payload)


@pytest.mark.parametrize(
    "name",
    ["*", "web*", "!web01", "web01&db01", "web01:db01", "web01,db01", "web 01", " web01", "web01\n", "-web01", "-", "--limit",
     "web01;rm", "web01/../x", "a|b", "~web.*", "[web]", "web01@host", "wéb01"],
)
@pytest.mark.parametrize("key", ["hosts", "groups"])
def test_names_with_pattern_syntax_spaces_or_a_leading_dash_are_refused(key, name):
    with pytest.raises(ValueError):
        validate_discover_payload({key: [name]})
    with pytest.raises(ValueError):
        validate_discover_payload({key: ["fine", name]})


def test_non_mappings_are_refused():
    for payload in (None, [], "hosts", 3):
        with pytest.raises(ValueError):
            validate_discover_payload(payload)  # type: ignore[arg-type]
