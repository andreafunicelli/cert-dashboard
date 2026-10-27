import pytest

from app.ansible.runner import RunnerSecrets, build_env
from app.jobs.queue import JobFailure
from app.models.enums import WebserverType
from app.services.inventory import InventoryConfig, InventoryHost, inventory_source, list_inventory
from tests.fixtures.git_inventory import write_vaulted

YAML_INVENTORY = """\
all:
  children:
    prod:
      children:
        web:
          hosts:
            web01.example.internal:
              ansible_host: 10.0.0.11
            web02.example.internal:
              webserver_type: apache
          vars:
            webserver_type: nginx
    canary_ring:
      hosts:
        web01.example.internal:
  hosts:
    lonely.example.internal:
      webserver_type: iis
"""


def runner_env(tmp_path, password=None):
    run_dir = tmp_path / "run"
    for name in ("home", "tmp", "collections", "cp"):
        (run_dir / name).mkdir(parents=True, exist_ok=True)
    key = tmp_path / "ssh_key"
    key.write_bytes(b"unused")
    secrets = RunnerSecrets(key, tmp_path / "known_hosts", password.encode() if password else None)
    return build_env(secrets, run_dir)


def by_name(hosts):
    return {host.hostname: host for host in hosts}


def test_yaml_inventory_lists_groups_addresses_and_the_webserver_variable(tmp_path):
    inventory = tmp_path / "inventory"
    inventory.mkdir()
    (inventory / "hosts.yml").write_text(YAML_INVENTORY)
    hosts = by_name(list_inventory(inventory, webserver_var="webserver_type", env=runner_env(tmp_path)))
    assert hosts["web01.example.internal"] == InventoryHost(
        "web01.example.internal", ("canary_ring", "prod", "web"), "10.0.0.11", WebserverType.NGINX
    )
    # host_vars-level value overrides the group's; no ansible_host means no connection address.
    assert hosts["web02.example.internal"] == InventoryHost(
        "web02.example.internal", ("prod", "web"), None, WebserverType.APACHE
    )
    assert set(hosts) == {"web01.example.internal", "web02.example.internal", "lonely.example.internal"}


def test_host_vars_files_override_group_vars_files(tmp_path):
    inventory = tmp_path / "inventory"
    (inventory / "group_vars").mkdir(parents=True)
    (inventory / "host_vars").mkdir()
    (inventory / "hosts.yml").write_text(
        "all:\n  children:\n    web:\n      hosts:\n        a.example.internal:\n        b.example.internal:\n"
    )
    (inventory / "group_vars/web.yml").write_text("webserver_type: nginx\n")
    (inventory / "host_vars/b.example.internal.yml").write_text("webserver_type: apache\nansible_host: 192.0.2.7\n")
    hosts = by_name(list_inventory(inventory, webserver_var="webserver_type", env=runner_env(tmp_path)))
    assert hosts["a.example.internal"].webserver == WebserverType.NGINX
    assert hosts["b.example.internal"] == InventoryHost("b.example.internal", ("web",), "192.0.2.7", WebserverType.APACHE)


def test_ini_inventory_and_a_custom_webserver_variable(tmp_path):
    inventory = tmp_path / "inventory"
    inventory.mkdir()
    (inventory / "hosts").write_text(
        "[web]\nweb01.example.internal ansible_host=10.1.1.1 server_kind=apache\nweb02.example.internal\n"
        "[db]\ndb01.example.internal\n"
    )
    hosts = by_name(list_inventory(inventory, webserver_var="server_kind", env=runner_env(tmp_path)))
    assert hosts["web01.example.internal"] == InventoryHost(
        "web01.example.internal", ("web",), "10.1.1.1", WebserverType.APACHE
    )
    assert hosts["web02.example.internal"].webserver is None
    assert hosts["db01.example.internal"].groups == ("db",)


def test_invalid_webserver_values_and_pseudo_groups_are_dropped(tmp_path):
    inventory = tmp_path / "inventory"
    inventory.mkdir()
    (inventory / "hosts.yml").write_text(YAML_INVENTORY)
    hosts = by_name(list_inventory(inventory, webserver_var="webserver_type", env=runner_env(tmp_path)))
    assert hosts["lonely.example.internal"] == InventoryHost("lonely.example.internal", (), None, None)
    assert all(not {"all", "ungrouped"} & set(host.groups) for host in hosts.values())


def test_an_address_equal_to_the_hostname_is_not_a_connection_address(tmp_path):
    inventory = tmp_path / "inventory"
    inventory.mkdir()
    (inventory / "hosts").write_text("[web]\nweb01.example.internal ansible_host=web01.example.internal\n")
    (host,) = list_inventory(inventory, webserver_var="webserver_type", env=runner_env(tmp_path))
    assert host.connection_address is None


def test_vaulted_group_vars_are_decrypted_through_the_vault_client_and_never_returned(tmp_path):
    password, plaintext = "vault-password-canary-7e41", "vaulted-plaintext-canary-0c9b"
    inventory = tmp_path / "inventory"
    (inventory / "group_vars/all").mkdir(parents=True)
    (inventory / "hosts.yml").write_text(YAML_INVENTORY)
    # Only decryptable with the right password, and it carries the webserver variable of a host.
    write_vaulted(inventory / "group_vars/all/vault.yml", {"db_secret": plaintext, "ansible_user": plaintext}, password)
    hosts = list_inventory(inventory, webserver_var="webserver_type", env=runner_env(tmp_path, password))
    assert len(hosts) == 3
    assert plaintext not in repr(hosts) and password not in repr(hosts)


def test_a_wrong_vault_password_fails_closed_without_any_ansible_output(tmp_path):
    password = "vault-password-canary-7e41"
    inventory = tmp_path / "inventory"
    (inventory / "group_vars/all").mkdir(parents=True)
    (inventory / "hosts.yml").write_text(YAML_INVENTORY)
    write_vaulted(inventory / "group_vars/all/vault.yml", {"db_secret": "x"}, password)
    with pytest.raises(JobFailure) as failure:
        list_inventory(inventory, webserver_var="webserver_type", env=runner_env(tmp_path, "wrong-password-canary-11aa"))
    assert (failure.value.error_class, failure.value.message) == ("config_invalid", "inventory could not be read")
    for leaked in ("wrong-password-canary-11aa", "vault", "ERROR", "Decryption", str(tmp_path)):
        assert leaked not in str(failure.value)


def test_a_missing_vault_password_fails_closed(tmp_path):
    inventory = tmp_path / "inventory"
    (inventory / "group_vars/all").mkdir(parents=True)
    (inventory / "hosts.yml").write_text(YAML_INVENTORY)
    write_vaulted(inventory / "group_vars/all/vault.yml", {"db_secret": "x"}, "some-password")
    with pytest.raises(JobFailure) as failure:
        list_inventory(inventory, webserver_var="webserver_type", env=runner_env(tmp_path))
    assert (failure.value.error_class, failure.value.message) == ("config_invalid", "inventory could not be read")


def test_a_missing_inventory_is_unreadable(tmp_path):
    with pytest.raises(JobFailure) as failure:
        list_inventory(tmp_path / "absent", webserver_var="webserver_type", env=runner_env(tmp_path))
    assert (failure.value.error_class, failure.value.message) == ("config_invalid", "inventory could not be read")


def test_an_ansible_cfg_in_the_inventory_is_not_honoured(tmp_path):
    inventory = tmp_path / "inventory"
    inventory.mkdir()
    (inventory / "hosts").write_text("[web]\nweb01.example.internal\n")
    (inventory / "ansible.cfg").write_text("[inventory]\nenable_plugins = script\n")
    assert [h.hostname for h in list_inventory(inventory, webserver_var="webserver_type", env=runner_env(tmp_path))] == [
        "web01.example.internal"
    ]


def test_inventory_source_names_ref_path_and_revision_without_the_url():
    rev = "a" * 40
    config = InventoryConfig("https://git.example.internal/ops/inventory.git", "main", "inventory", "webserver_type")
    assert inventory_source(config, rev) == f"main:inventory@{rev}"
    empty = InventoryConfig("https://git.example.internal/ops/inventory.git", "", "", "webserver_type")
    assert inventory_source(empty, rev) == f"HEAD:.@{rev}"
    assert "git.example.internal" not in inventory_source(config, rev)
