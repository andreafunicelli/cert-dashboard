"""The manual-host inventory renderer (Slice B contract §7.1, §7.5; card W).

A repository is optional (decision D1): with no Git inventory the job's inventory is rendered from the
active manual hosts. This renderer is the only place that turns database rows into an Ansible inventory
file, so it is tested directly: the layout Ansible sees, deterministic ordering, and the refusal of any
value that could escape its YAML scalar or look like an option (defence in depth behind the validated
inputs of the Inventory screen).
"""

import pytest

from app.services.inventory_sources import InventoryRenderError, ManualHost, render_inventory


def host(hostname, groups=(), address=None, webserver=None):
    return ManualHost(hostname, tuple(groups), address, webserver)


def render(hosts, **kwargs):
    options = {"webserver_var": "webserver_type", **kwargs}
    return render_inventory(hosts, **options)


def test_a_host_without_groups_is_rendered_under_all_hosts():
    assert render([host("db01.example.test")]) == 'all:\n  hosts:\n    "db01.example.test": {}\n'


def test_a_grouped_host_is_rendered_under_every_group_and_not_under_all():
    assert render([host("web01.example.test", ("web", "prod"))]) == (
        "all:\n"
        "  children:\n"
        '    "prod":\n'
        "      hosts:\n"
        '        "web01.example.test": {}\n'
        '    "web":\n'
        "      hosts:\n"
        '        "web01.example.test": {}\n'
    )


def test_connection_address_becomes_ansible_host_and_webserver_becomes_the_configured_variable():
    text = render([host("web01.example.test", ("web",), "10.0.0.5", "nginx")])
    assert text == (
        "all:\n"
        "  children:\n"
        '    "web":\n'
        "      hosts:\n"
        '        "web01.example.test":\n'
        '          ansible_host: "10.0.0.5"\n'
        '          webserver_type: "nginx"\n'
    )


def test_the_webserver_variable_name_comes_from_the_setting():
    text = render([host("web01.example.test", ())], webserver_var="server_kind")
    assert 'server_kind: "nginx"' not in text  # no webserver recorded: no variable at all
    assert render([host("web01.example.test", (), None, "apache")], webserver_var="server_kind") == (
        "all:\n  hosts:\n    \"web01.example.test\":\n      server_kind: \"apache\"\n"
    )


def test_the_connection_defaults_are_rendered_only_when_set():
    plain = render([host("web01.example.test")])
    assert "ansible_user" not in plain and "ansible_port" not in plain
    configured = render([host("web01.example.test")], ssh_user="deploy", ssh_port=2222)
    assert configured == (
        "all:\n"
        "  hosts:\n"
        '    "web01.example.test":\n'
        '      ansible_port: 2222\n'
        '      ansible_user: "deploy"\n'
    )


def test_the_default_port_is_not_rendered():
    """Ansible's own default is 22; rendering it adds noise and nothing else."""
    assert "ansible_port" not in render([host("web01.example.test")], ssh_port=22)


def test_host_variables_are_ordered_deterministically():
    text = render([host("web01.example.test", ("web",), "10.0.0.5", "nginx")], ssh_user="deploy", ssh_port=2222)
    keys = [
        line.strip().split(":")[0]
        for line in text.splitlines()
        if line.startswith(("          ansible_", "          webserver_"))
    ]
    assert keys == ["ansible_host", "ansible_port", "ansible_user", "webserver_type"]


def test_hosts_and_groups_are_sorted_regardless_of_input_order():
    first = render(
        [
            host("web02.example.test", ("web", "prod")),
            host("db01.example.test", ("data",)),
            host("web01.example.test", ("prod",)),
        ]
    )
    second = render(
        [
            host("web01.example.test", ("prod",)),
            host("db01.example.test", ("data",)),
            host("web02.example.test", ("prod", "web")),
        ]
    )
    assert first == second
    assert first.index('"data"') < first.index('"prod"') < first.index('"web"')
    assert first.index('"web01.example.test"') < first.index('"web02.example.test"')
    assert first.index('"db01.example.test"') < first.index('"web01.example.test"')


def test_no_hosts_is_an_empty_but_valid_document():
    assert render([]) == "{}\n"


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("-bad.example.test", "a leading dash is an option, not a hostname"),
        ("bad host", "whitespace"),
        ("bad\nhost", "newline"),
        ("bad\thost", "tab"),
        ("", "empty"),
    ],
)
def test_unsafe_hostnames_are_refused(value, reason):
    with pytest.raises(InventoryRenderError):
        render([host(value)])


@pytest.mark.parametrize("value", ["bad group", "bad\ngroup", "-all", ""])
def test_unsafe_group_names_are_refused(value):
    with pytest.raises(InventoryRenderError):
        render([host("web01.example.test", (value,))])


@pytest.mark.parametrize("group", ["all", "ungrouped"])
def test_the_ansible_pseudo_groups_are_refused(group):
    """Grouping under ``all``/``ungrouped`` would silently move a host; upstream validation refuses them too."""
    with pytest.raises(InventoryRenderError):
        render([host("web01.example.test", (group,))])


@pytest.mark.parametrize("value", ["1.2.3.4 5", "1.2.3.4\n", "-1.2.3.4", "1.2.3.4\t5"])
def test_unsafe_connection_addresses_are_refused(value):
    with pytest.raises(InventoryRenderError):
        render([host("web01.example.test", (), value)])


@pytest.mark.parametrize("value", ["ngi nx", "nginx\n", "-nginx"])
def test_unsafe_webserver_values_are_refused(value):
    with pytest.raises(InventoryRenderError):
        render([host("web01.example.test", (), None, value)])


@pytest.mark.parametrize("value", ["bad user", "bad\nuser", "-deploy"])
def test_unsafe_ssh_users_are_refused(value):
    with pytest.raises(InventoryRenderError):
        render([host("web01.example.test")], ssh_user=value)


@pytest.mark.parametrize("value", ["bad var", "bad\nvar", "-var"])
def test_unsafe_webserver_variable_names_are_refused(value):
    with pytest.raises(InventoryRenderError):
        render([host("web01.example.test", (), None, "nginx")], webserver_var=value)


@pytest.mark.parametrize("value", [0, 65536, -1, "22", True])
def test_unsafe_ports_are_refused(value):
    with pytest.raises(InventoryRenderError):
        render([host("web01.example.test")], ssh_port=value)


def test_a_duplicated_hostname_is_refused():
    with pytest.raises(InventoryRenderError):
        render([host("web01.example.test"), host("web01.example.test", ("web",))])


def test_a_reserved_ansible_variable_cannot_be_the_webserver_variable():
    with pytest.raises(InventoryRenderError):
        render([host("web01.example.test", (), None, "nginx")], webserver_var="ansible_host")


def test_the_rendered_document_is_read_by_ansible_inventory(tmp_path):
    """The file is not only byte-stable: real ``ansible-inventory`` turns it into the expected hosts."""
    from app.ansible.runner import RunnerSecrets, build_env
    from app.models.enums import WebserverType
    from app.services.inventory import InventoryHost, list_inventory

    inventory = tmp_path / "manual.yml"
    inventory.write_text(
        render(
            [
                host("web01.example.test", ("web", "prod"), "10.0.0.5", "nginx"),
                host("db01.example.test"),
            ],
            ssh_user="deploy",
            ssh_port=2222,
        )
    )
    run_dir = tmp_path / "run"
    for name in ("home", "tmp", "collections", "cp"):
        (run_dir / name).mkdir(parents=True, exist_ok=True)
    secrets = RunnerSecrets(tmp_path / "ssh_key", tmp_path / "known_hosts")
    hosts = list_inventory(inventory, webserver_var="webserver_type", env=build_env(secrets, run_dir))
    assert hosts == [
        InventoryHost("db01.example.test", (), None, None),
        InventoryHost("web01.example.test", ("prod", "web"), "10.0.0.5", WebserverType.NGINX),
    ]


def test_a_rendered_ipv6_literal_stays_a_single_quoted_key():
    text = render([host("2001:db8::1")])
    assert text == 'all:\n  hosts:\n    "2001:db8::1": {}\n'
    assert text.count('"2001:db8::1"') == 1
