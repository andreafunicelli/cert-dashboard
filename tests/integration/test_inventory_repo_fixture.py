from datetime import timedelta

from app.services.inventory import (
    git_environment,
    inventory_source,
    list_inventory,
    load_inventory_config,
    refresh_checkout,
)


def test_inventory_repo_writes_the_settings_and_serves_a_listable_inventory(web_factory, tmp_path, now, inventory_repo):
    from app.ansible.runner import RunnerSecrets, build_env

    repo = inventory_repo(
        web_factory,
        hosts={"web01.example.internal": {"ansible_host": "127.0.0.1", "webserver_type": "nginx"}},
        groups={"ring_a": ["web01.example.internal"]},
        vault=("fixture-vault-password-3f9a", {"db_secret": "vaulted-canary-77e1"}),
    )
    with web_factory() as db:
        config = load_inventory_config(db)
    assert config is not None and config.repo_url == repo.url and config.path == "inventory"

    env = git_environment(token=None, ssh_key=None, known_hosts=tmp_path / "known_hosts", home=tmp_path / "home")
    checkout = tmp_path / "checkout"
    revision = refresh_checkout(config.repo_url, config.ref, checkout, env=env, now=now)
    assert revision.rev == repo.head and inventory_source(config, revision.rev).startswith("main:inventory@")
    assert refresh_checkout(config.repo_url, config.ref, checkout, env=env, now=now + timedelta(seconds=5)).rev == repo.head

    run_dir = tmp_path / "run"
    for name in ("home", "tmp", "collections", "cp"):
        (run_dir / name).mkdir(parents=True)
    key = tmp_path / "key"
    key.write_bytes(b"unused")
    runner_env = build_env(RunnerSecrets(key, tmp_path / "known_hosts", b"fixture-vault-password-3f9a"), run_dir)
    (host,) = list_inventory(checkout / config.path, webserver_var=config.webserver_var, env=runner_env)
    assert (host.hostname, host.groups, host.connection_address) == ("web01.example.internal", ("ring_a",), "127.0.0.1")
