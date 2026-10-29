"""Static rules for the committed playbooks (Plan 3 Task 8B; Tasks 14–15 add the deploy path).

``discover.yml`` is read-only on the target: only ``ansible.builtin`` modules from an allowlist, no network
module, every task that touches a key path, certificate extraction or the configuration dump is ``no_log``,
every command is bounded, and everything that writes is delegated to the controller.

``deploy.yml`` writes live files as of Task 15, so the Task 14 boundary rule ("nothing outside the backup
tree is written") becomes the **rescue-coverage rule** (Contract decision 17): every task that may replace,
relabel, test or reload a live file or service sits inside the single main ``block`` — directly or through
``tasks/deploy_write.yml`` — and that block's ``rescue`` includes ``tasks/rollback.yml`` for every write
step. ``rollback.yml`` is itself a block whose ``rescue`` only records ``rollback_error``, so the restore is
attempted exactly once. Pruning runs ``files/prune_backups.py`` after the block, only for a ``verified``
host, and touches only ``{{ backup_root }}``. Every task that handles key files is ``no_log: true``.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment

from app.ansible.deploy import WRITE_STEPS
from app.ansible.discovery import CERT_KEY_HASH_COMMAND, KEY_HASH_COMMAND
from app.ansible.runner import PLAYBOOK_DIR

DISCOVER = PLAYBOOK_DIR / "discover.yml"
DEPLOY = PLAYBOOK_DIR / "deploy.yml"
ALLOWED_MODULES = {
    "command", "shell", "stat", "copy", "set_fact", "set_stats", "fail", "assert", "include_tasks", "slurp",
    "file", "script", "find", "debug",
}  # fmt: skip
NETWORK_MODULES = {"get_url", "uri", "apt", "dnf", "package", "pip", "git"}
# Everything that is not a module name on a task.
KEYWORDS = {
    "name", "when", "loop", "loop_control", "register", "become", "become_user", "become_method", "no_log",
    "timeout", "delegate_to", "delegate_facts", "changed_when", "failed_when", "ignore_errors", "vars", "args",
    "tags", "block", "rescue", "always", "environment", "run_once", "check_mode", "diff", "until", "retries",
    "delay", "notify", "throttle", "any_errors_fatal", "ignore_unreachable", "remote_user", "connection",
}  # fmt: skip
# A task whose arguments mention one of these touches key paths, certificate extraction or the dump.
SENSITIVE = ("key_paths", "pkey", "pkcs7", "nginx_dump", "apache_dump", "/dumps/", "/certs/")


def walk(tasks: list[dict], base: Path = PLAYBOOK_DIR, *, follow_includes: bool = True) -> list[dict]:
    """Every task (``block`` containers excluded), following their sections and literal ``include_tasks`` files."""
    found: list[dict] = []
    for task in tasks:
        if "block" not in task:
            found.append(task)
        for section in ("block", "rescue", "always"):
            found.extend(walk(task.get(section) or [], base, follow_includes=follow_includes))
        include = task.get("ansible.builtin.include_tasks")
        if follow_includes and include is not None:
            name = include if isinstance(include, str) else include["file"]
            assert "{{" not in name, "include_tasks must name a literal file"
            found.extend(walk(yaml.safe_load((base / name).read_text(encoding="utf-8")), base))
    return found


def tasks_of(playbook: Path) -> list[dict]:
    plays = yaml.safe_load(playbook.read_text(encoding="utf-8"))
    return [task for play in plays for task in walk(play.get("tasks") or [])]


def module_of(task: dict) -> str:
    modules = [key for key in task if key not in KEYWORDS]
    assert len(modules) == 1, f"{task.get('name')}: expected exactly one module, found {modules}"
    return modules[0]


def label(task: dict) -> str:
    return str(task.get("name") or module_of(task))


def mentions(task: dict, needles: tuple[str, ...]) -> bool:
    text = yaml.safe_dump({k: v for k, v in task.items() if k not in {"name", "no_log"}})
    return any(needle in text for needle in needles)


@pytest.fixture(scope="module")
def discover_tasks() -> list[dict]:
    return tasks_of(DISCOVER)


def test_discover_playbook_passes_the_ansible_syntax_check(tmp_path):
    binary = Path(sys.executable).parent / "ansible-playbook"
    if not binary.exists():
        pytest.skip("ansible-playbook is not installed next to the interpreter")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "tmp"),
        "ANSIBLE_COLLECTIONS_PATH": str(tmp_path / "collections"),
        "ANSIBLE_NOCOLOR": "True",
    }
    done = subprocess.run(
        [str(binary), "--syntax-check", "-i", "localhost,", str(DISCOVER)],
        env=env, capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stdout + done.stderr


def test_every_task_is_a_fully_qualified_allowlisted_builtin_module(discover_tasks):
    assert discover_tasks
    for task in discover_tasks:
        if "block" in task:
            continue
        module = module_of(task)
        assert module.startswith("ansible.builtin."), f"{label(task)}: {module} is not fully qualified"
        assert module.removeprefix("ansible.builtin.") in ALLOWED_MODULES, f"{label(task)}: {module} not allowed"


def test_no_network_module_is_used_anywhere(discover_tasks):
    used = {module_of(task).rpartition(".")[2] for task in discover_tasks if "block" not in task}
    assert not used & NETWORK_MODULES
    text = DISCOVER.read_text(encoding="utf-8")
    for module in NETWORK_MODULES:
        assert f"ansible.builtin.{module}" not in text


def test_tasks_touching_keys_certificates_or_the_dump_are_no_log(discover_tasks):
    sensitive = [task for task in discover_tasks if "block" not in task and mentions(task, SENSITIVE)]
    assert len(sensitive) >= 6  # the stat/key-hash/extraction/copy/dump/script tasks at least
    for task in sensitive:
        assert task.get("no_log") is True, f"{label(task)} must be no_log: true"


def test_every_command_and_shell_task_is_bounded_to_60_seconds(discover_tasks):
    commands = [task for task in discover_tasks if module_of(task) in {"ansible.builtin.command", "ansible.builtin.shell"}]
    assert commands
    for task in commands:
        assert 0 < task.get("timeout", 10**6) <= 60, f"{label(task)} needs timeout <= 60"


def test_nothing_is_written_on_the_target(discover_tasks):
    writers = [task for task in discover_tasks if module_of(task) in {"ansible.builtin.copy", "ansible.builtin.file"}]
    assert writers
    for task in writers:
        assert task.get("delegate_to") == "localhost", f"{label(task)} must run on the controller"
        assert task.get("become") is False, f"{label(task)} must not use become"
        # the worker's user has no passwd home: the controller-side temp directory must be named, not `~`
        assert task["vars"]["ansible_remote_tmp"] == "{{ lookup('ansible.builtin.env', 'HOME') }}/.ansible/tmp"


def test_exactly_one_target_side_script_task_runs_the_apache_collector(discover_tasks):
    scripts = [task for task in discover_tasks if module_of(task) == "ansible.builtin.script"]
    assert len(scripts) == 1
    [script] = scripts
    command = script["ansible.builtin.script"]
    command = command if isinstance(command, str) else command["cmd"]
    assert command.split()[0] == "files/apache_dump.py"
    assert script.get("no_log") is True and script.get("become") is True and script.get("timeout") == 60
    assert not script.get("delegate_to")
    assert (PLAYBOOK_DIR / "files" / "apache_dump.py").is_file()


def test_the_key_hash_task_runs_the_d2_command_under_pipefail(discover_tasks):
    [task] = [t for t in discover_tasks if "-outform DER" in yaml.safe_dump(t)]
    command = task["ansible.builtin.shell"]
    command = command if isinstance(command, str) else command["cmd"]
    assert "-outform DER" in command and "sha256sum" in command and "-passin pass:" in command
    # one source of truth: the playbook line is KEY_HASH_COMMAND with the loop item in place of {path}
    expected = "set -o pipefail; " + KEY_HASH_COMMAND.format(path="{{ item | quote }}")
    assert command.strip() == expected
    assert task["args"]["executable"] == "/bin/bash"
    assert task["loop"] == "{{ key_paths }}"
    assert task["no_log"] is True and task["become"] is True and task["timeout"] == 60


def test_certificates_are_extracted_without_reading_key_material_out(discover_tasks):
    extract = [t for t in discover_tasks if "pkcs7 -print_certs" in yaml.safe_dump(t)]
    [task] = extract
    command = task["ansible.builtin.shell"]
    command = command if isinstance(command, str) else command["cmd"]
    assert "openssl crl2pkcs7 -nocrl -certfile {{ item | quote }} | openssl pkcs7 -print_certs" in command
    assert command.startswith("set -o pipefail;")
    assert task["loop"] == "{{ cert_paths }}"  # certificate paths only, never a key path
    assert "key_paths" not in yaml.safe_dump(task)
    assert task["no_log"] is True and task["become"] is True and task["timeout"] == 60


def test_certificate_contents_travel_to_the_controller_as_a_0600_file_per_path(discover_tasks):
    [task] = [t for t in discover_tasks if module_of(t) == "ansible.builtin.copy" and "/certs/" in yaml.safe_dump(t)]
    args = task["ansible.builtin.copy"]
    assert str(args["mode"]) == "0600"
    assert args["dest"].endswith("/certs/{{ inventory_hostname }}/{{ item.item | hash('sha256') }}.pem")
    assert task["delegate_to"] == "localhost" and task["become"] is False and task["no_log"] is True


def test_the_dump_is_written_to_the_controller_with_0600(discover_tasks):
    copies = [t for t in discover_tasks if module_of(t) == "ansible.builtin.copy" and "/dumps/" in yaml.safe_dump(t)]
    assert {t["ansible.builtin.copy"]["dest"].rpartition(".")[2] for t in copies} == {"txt", "json"}
    for task in copies:
        assert str(task["ansible.builtin.copy"]["mode"]) == "0600"
        assert task["ansible.builtin.copy"]["dest"].startswith("{{ artifact_dir }}/dumps/{{ inventory_hostname }}.")


# --- deploy.yml: the write path and its single-attempt rollback (Plan 3 Tasks 14–15) -------------

# Any task that handles the whole file map (key paths included), the backup manifest or the write and
# restore plans is censored: every one of them names key files, and most of them carry content.
DEPLOY_SENSITIVE = (
    "key_pem_path", "key_paths", "key_stat", "file_paths", "manifest_files", "restore_entries",
    "write_entries", "written_files", "written_paths", "source_path",
)  # fmt: skip
# A command that moves a file into place, relabels it, re-tests the configuration or reloads the webserver
# may change what the host serves: every one of them belongs inside the main block (§6.4 steps 3–7).
LIVE_COMMANDS = ("mv", "restorecon", "reload", "graceful", "configtest")
LIVE_TOKENS = ("'-t'",)
# The subset that replaces or relabels a live path: only these must come after `deploy_step=writing`.
REPLACING_COMMANDS = ("mv", "restorecon")
BACKUP_PREFIX = "{{ backup_root }}"
DEPLOY_WRITE = PLAYBOOK_DIR / "tasks" / "deploy_write.yml"
ROLLBACK = PLAYBOOK_DIR / "tasks" / "rollback.yml"
# Contract decisions 17–18: the progress a host publishes, and the rollback outcomes.
EXPECTED_STEPS = {
    "preflight", "backed_up", "writing", "written", "labelled", "config_tested", "reloaded",
    "verified", "rolled_back", "rollback_failed",
}  # fmt: skip


@pytest.fixture(scope="module")
def deploy_tasks() -> list[dict]:
    return tasks_of(DEPLOY)


@pytest.fixture(scope="module")
def deploy_play() -> dict:
    [play] = yaml.safe_load(DEPLOY.read_text(encoding="utf-8"))
    return play


def include_path(task: dict) -> str | None:
    """The literal file an ``include_tasks`` task names, or ``None`` for any other task."""
    include = task.get("ansible.builtin.include_tasks")
    if include is None:
        return None
    return include if isinstance(include, str) else include["file"]


def changes_live_state(task: dict) -> bool:
    """True for a task that may replace, relabel, re-test or reload a live file or service (§6.4 steps 3–7)."""
    if writes_live_file(task):
        return True
    module = module_of(task)
    if module in {"ansible.builtin.command", "ansible.builtin.shell"}:
        text = yaml.safe_dump(task[module])
        return any(re.search(rf"\b{word}\b", text) for word in LIVE_COMMANDS) or any(
            token in text for token in LIVE_TOKENS
        )
    return False


def writes_live_file(task: dict) -> bool:
    """True for a task that replaces or relabels a live path (§6.4 steps 3–4), unlike a read or a test."""
    module = module_of(task)
    if module in {"ansible.builtin.file", "ansible.builtin.copy"}:
        args = task[module]
        target = args.get("dest") or args.get("path")
        return not str(target).startswith(BACKUP_PREFIX)
    if module in {"ansible.builtin.command", "ansible.builtin.shell"}:
        text = yaml.safe_dump(task[module])
        return any(re.search(rf"\b{word}\b", text) for word in REPLACING_COMMANDS)
    return False


def assignments_of(task: dict) -> dict:
    """The mapping a ``set_fact`` task assigns, or an empty mapping for any other task."""
    if module_of(task) != "ansible.builtin.set_fact":
        return {}
    arguments = task["ansible.builtin.set_fact"]
    return arguments if isinstance(arguments, dict) else {}


def test_deploy_playbook_passes_the_ansible_syntax_check(tmp_path):
    binary = Path(sys.executable).parent / "ansible-playbook"
    if not binary.exists():
        pytest.skip("ansible-playbook is not installed next to the interpreter")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "tmp"),
        "ANSIBLE_COLLECTIONS_PATH": str(tmp_path / "collections"),
        "ANSIBLE_NOCOLOR": "True",
    }
    done = subprocess.run(
        [str(binary), "--syntax-check", "-i", "localhost,", str(DEPLOY)],
        env=env, capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stdout + done.stderr


def test_deploy_every_task_is_a_fully_qualified_allowlisted_builtin_module(deploy_tasks):
    assert deploy_tasks
    for task in deploy_tasks:
        module = module_of(task)
        assert module.startswith("ansible.builtin."), f"{label(task)}: {module} is not fully qualified"
        assert module.removeprefix("ansible.builtin.") in ALLOWED_MODULES, f"{label(task)}: {module} not allowed"


def test_deploy_uses_no_network_module(deploy_tasks):
    used = {module_of(task).rpartition(".")[2] for task in deploy_tasks}
    assert not used & NETWORK_MODULES
    text = DEPLOY.read_text(encoding="utf-8")
    for module in NETWORK_MODULES:
        assert f"ansible.builtin.{module}" not in text


def test_deploy_never_delegates_and_never_hides_a_failure(deploy_tasks):
    for task in deploy_tasks:
        assert "delegate_to" not in task, f"{label(task)} must not delegate"
        assert "ignore_errors" not in task, f"{label(task)} must not ignore errors"


def test_deploy_tasks_touching_key_material_are_no_log(deploy_tasks):
    sensitive = [task for task in deploy_tasks if mentions(task, DEPLOY_SENSITIVE)]
    # stat/plan/mark/backup/write/restore of the file map at least
    assert len(sensitive) >= 8
    for task in sensitive:
        assert task.get("no_log") is True, f"{label(task)} must be no_log: true"


def test_deploy_every_command_and_shell_task_is_bounded_to_60_seconds(deploy_tasks):
    commands = [t for t in deploy_tasks if module_of(t) in {"ansible.builtin.command", "ansible.builtin.shell"}]
    assert commands
    for task in commands:
        assert 0 < task.get("timeout", 10**6) <= 60, f"{label(task)} needs timeout <= 60"


def test_every_live_changing_task_sits_inside_the_block_whose_rescue_is_the_rollback(deploy_play):
    """The rescue-coverage rule (Contract decision 17), replacing Task 14's backup-only boundary.

    A write, label, config test or reload that escaped the block would have no rollback behind it, which is
    exactly the state this plan forbids at every commit. Nothing before the block (preflight, backup) or
    after it (pruning) may change a live file, and the rescue may reach a live change only through
    ``tasks/rollback.yml``.
    """
    blocks = [task for task in deploy_play["tasks"] if "block" in task]
    assert len(blocks) == 1, "deploy.yml keeps exactly one block: its rescue is the only rollback"
    [main] = blocks
    inside = walk(main.get("block") or [])
    writes = [task for task in inside if changes_live_state(task)]
    # the three write steps of every changed path, the label, the config test, the reload
    assert len(writes) >= 7, "the write, label, config-test and reload tasks must be inside the block"
    assert "tasks/deploy_write.yml" in [include_path(task) for task in inside]
    for task in deploy_play["tasks"]:
        if task is main:
            continue
        assert [t for t in walk([task]) if changes_live_state(t)] == [], f"{label(task)} is outside the block"
    rescue = walk(main.get("rescue") or [], follow_includes=False)
    assert [task for task in rescue if changes_live_state(task)] == []
    assert [task for task in walk(main.get("always") or []) if changes_live_state(task)] == []


def test_the_rescue_includes_the_rollback_for_every_write_step(deploy_play):
    [main] = [task for task in deploy_play["tasks"] if "block" in task]
    rescue = walk(main["rescue"], follow_includes=False)
    [rollback] = [task for task in rescue if include_path(task) == "tasks/rollback.yml"]
    when = rollback.get("when")
    text = " ".join(when) if isinstance(when, list) else str(when)
    assert "deploy_step" in text and "write_steps" in text
    # one source of truth for the steps a failure may have changed a live file in
    assert deploy_play["vars"]["write_steps"] == list(WRITE_STEPS)
    # the failure is recorded first, the rollback is the last thing the rescue does
    assert label(rescue[-1]) == label(rollback)
    assert label(rescue[-2]) == "Record why this host stopped"


def test_the_writing_step_is_published_before_the_first_write(deploy_play):
    flat = walk(deploy_play["tasks"])
    writing = [index for index, task in enumerate(flat) if assignments_of(task).get("deploy_step") == "writing"]
    writes = [index for index, task in enumerate(flat) if writes_live_file(task)]
    assert len(writing) == 1, "deploy_step=writing is set exactly once"
    assert writes and writing[0] < writes[0], "deploy_step=writing must precede the first live write"


def test_a_stale_temporary_file_is_removed_before_the_empty_temp_file_is_created():
    """Contract decision 17: the temp file is *created* empty, so a leftover from a killed run is removed.

    ``ansible.builtin.file: state=touch`` never empties a file that already exists: an interrupted attempt
    that left content in ``.cert-dashboard.tmp`` or ``.cert-dashboard.restore.tmp`` would carry it into the
    next write or restore, silently breaking "empty with the final mode before any content". Both paths make
    the temp path absent first, then create it empty with the final owner, group and mode, fill it and rename.
    """
    for playbook in (DEPLOY_WRITE, ROLLBACK):
        tasks = walk(yaml.safe_load(playbook.read_text(encoding="utf-8")))
        temps = [task for task in tasks if "{{ item.temp }}" in yaml.safe_dump(task)]
        assert [module_of(task) for task in temps] == [
            "ansible.builtin.file",  # remove a stale temp: touch would keep its content
            "ansible.builtin.file",  # create it empty with the final owner, group and mode
            "ansible.builtin.copy",  # fill it
            "ansible.builtin.command",  # rename it into place
        ], f"{playbook.name}: {[label(task) for task in temps]}"
        remove, create, fill, _rename = temps
        assert remove["ansible.builtin.file"] == {"path": "{{ item.temp }}", "state": "absent"}
        assert create["ansible.builtin.file"]["state"] == "touch"
        assert create["ansible.builtin.file"]["mode"] == "{{ item.mode }}"
        assert remove["loop"] == create["loop"] and remove.get("loop_control") == create.get("loop_control")
        assert remove.get("when") == create.get("when"), "the same entries, never a different set"
        for task in (remove, create, fill):
            assert task.get("no_log") is True, f"{label(task)} names the key temp files and must be no_log: true"
            assert task.get("become") is True, f"{label(task)} must run as root"


def test_the_rollback_is_one_block_that_restores_every_manifest_path():
    """A single attempt at restoring *every* manifest path, then test, reload and verify the old leaf."""
    [task] = yaml.safe_load(ROLLBACK.read_text(encoding="utf-8"))
    assert "block" in task and task.get("rescue")
    assert not task.get("always")
    rescue = walk(task["rescue"], follow_includes=False)
    assert rescue and all(module_of(item) == "ansible.builtin.set_fact" for item in rescue)
    dumped = yaml.safe_dump(rescue)
    assert "include_tasks" not in dumped and "until" not in dumped, "the rescue only records, it retries nothing"
    # Contract decision 17: the fixed texts the rollback publishes when it fails.
    for text in (
        "restore failed",
        "config test failed after restore",
        "reload failed after restore",
        "old certificate not served after restore",
    ):
        assert text in dumped
    body = walk(task["block"])
    plan = yaml.safe_dump(body)
    assert "manifest_files" in plan and "dict2items" in plan, "every manifest path, not only the written ones"
    assert ".cert-dashboard.restore.tmp" in plan
    restores = [item for item in body if item.get("loop") == "{{ restore_entries }}"]
    assert len(restores) >= 3, "create, fill and rename every restore file"
    assert all(item.get("no_log") is True for item in restores)
    # exactly one restore attempt: one atomic rename task in the block, and retries only on the verification
    renames = [item for item in body if module_of(item) == "ansible.builtin.command" and "mv" in yaml.safe_dump(item)]
    assert len(renames) == 1 and renames[0]["loop"] == "{{ restore_entries }}"
    assert len([item for item in body if "retries" in item]) == 1
    # the restored bytes come from the job's backup, with the original owner/group/mode
    [copy] = [item for item in body if module_of(item) == "ansible.builtin.copy"]
    assert copy["ansible.builtin.copy"]["remote_src"] is True
    assert copy["ansible.builtin.copy"]["mode"] == "{{ item.mode }}"
    assert copy["ansible.builtin.copy"]["owner"] == "{{ item.owner }}"
    assert copy["ansible.builtin.copy"]["group"] == "{{ item.group }}"


def test_the_rollback_attempts_the_restore_once_even_when_it_fails(deploy_tasks):
    """A rollback failure must never trigger another restore: one rename task, no retry, one include."""
    renames = [
        task
        for task in deploy_tasks
        if module_of(task) == "ansible.builtin.command" and "mv" in yaml.safe_dump(task)
    ]
    assert len(renames) == 2, "one rename per write step and one per restore, never more"
    assert not any("retries" in task for task in renames)
    includes = [task for task in deploy_tasks if include_path(task) == "tasks/rollback.yml"]
    assert len(includes) == 1


def test_the_prune_runs_only_after_a_verified_host_and_only_under_the_backup_root(deploy_play):
    tasks = deploy_play["tasks"]
    assert len(tasks) == 2, "one block plus the prune that runs after it"
    [main, prune] = tasks
    assert "block" in main and module_of(prune) == "ansible.builtin.script"
    command = prune["ansible.builtin.script"]
    command = command if isinstance(command, str) else command["cmd"]
    assert command.split()[0] == "files/prune_backups.py"
    assert f"--root {BACKUP_PREFIX}" in command, "the pruner only ever walks the backup root"
    assert "/var/backups" not in command and "{{ job_id }}" not in command
    assert "--retention-days {{ backup_retention_days" in command
    assert prune.get("become") is True and 0 < prune.get("timeout", 10**6) <= 60
    text = str(prune.get("when"))
    assert "deploy_step" in text and "verified" in text
    assert (PLAYBOOK_DIR / "files" / "prune_backups.py").is_file()


def test_deploy_certificate_backup_mode_is_the_bitwise_mask_of_the_original(deploy_tasks):
    """Contract decision 17 / Task 14: the copy keeps exactly ``original & 0o644``.

    Jinja has no bitwise operator, so the committed expression is rendered here: an executable bit (0500), a
    group-write bit (0620) and a full 0711 all lose what 0644 does not allow, while the modes that already fit
    it (0640, 0600, 0644) survive unchanged. Digit clamping would let 0500 and 0620 through untouched.
    """
    [task] = [t for t in deploy_tasks if t.get("name") == "Back up the certificate files"]
    assert str(task["ansible.builtin.copy"]["mode"]) == "{{ backup_mode }}"
    template = Environment().from_string(task["vars"]["backup_mode"])
    for original, expected in {
        0o500: 0o400, 0o620: 0o600, 0o711: 0o600, 0o777: 0o644, 0o664: 0o644,
        0o640: 0o640, 0o600: 0o600, 0o644: 0o644, 0o000: 0o000,
    }.items():  # fmt: skip
        rendered = template.render(old_mode=f"{original:04o}").strip()
        assert int(rendered, 8) == expected == original & 0o644, f"{original:04o} -> {rendered}"


def test_the_written_mode_is_the_bitmask_of_the_original_and_0600_for_keys(deploy_tasks):
    """Contract decision 17: certificate and chain files get ``old_mode & 0o644``, keys exactly ``0600``."""
    [task] = [t for t in deploy_tasks if t.get("name") == "Plan every write from the backup manifest"]
    template = Environment().from_string(task["vars"]["certificate_mode"])
    for original in (0o500, 0o620, 0o711, 0o777, 0o664, 0o640, 0o600, 0o644):
        rendered = template.render(old_mode=f"{original:04o}").strip()
        assert int(rendered, 8) == original & 0o644, f"{original:04o} -> {rendered}"
    planned = yaml.safe_dump(task["ansible.builtin.set_fact"])
    assert "'0600'" in planned and "item.item.kind == 'key'" in planned
    # the owner, group and mode are the ones the current file has (recorded by the backup phase)
    assert "manifest_entry.owner" in planned and "manifest_entry.group" in planned
    assert "manifest_entry.mode" in yaml.safe_dump(task["vars"])


def test_deploy_publishes_one_per_host_result(deploy_tasks):
    publishers = [t for t in deploy_tasks if module_of(t) == "ansible.builtin.set_stats"]
    assert len(publishers) == 1
    text = yaml.safe_dump(publishers[0])
    assert "cert_dashboard" in text
    for published in (
        "deploy_step", "deploy_reason", "backup_dir", "rolled_back", "rollback_error", "files", "targets", "verify",
    ):  # fmt: skip
        assert published in text


def test_deploy_only_ever_marks_the_steps_it_performs(deploy_tasks):
    # `parse_host_result` grants success only on `step == "verified"`; every other value is either progress
    # or the rollback outcome (Contract decisions 17–18).
    steps = {
        arguments["deploy_step"]
        for task in deploy_tasks
        if (arguments := assignments_of(task)) and "deploy_step" in arguments
    }
    assert steps == EXPECTED_STEPS


def test_the_verification_retries_three_times_two_seconds_apart(deploy_tasks):
    """§6.4 step 7 / step 8: the same 3 × 2 s rule for the new leaf and for the restored old one."""
    verifies = [
        task
        for task in deploy_tasks
        if module_of(task) == "ansible.builtin.shell" and "s_client" in yaml.safe_dump(task)
    ]
    assert len(verifies) == 2, "one verification of the new leaf, one of the restored old leaf"
    for task in verifies:
        # §6.4 step 7: three attempts, two seconds apart — `retries` is the count minus the first run.
        assert task["retries"] == 2, "three attempts: the first run plus two retries"
        assert task["delay"] == 2 and task["timeout"] <= 60
        assert task["loop"] == "{{ targets }}" and task.get("no_log") is True
        assert "-showcerts" in yaml.safe_dump(task["ansible.builtin.shell"])
    # the retry loop must never abort the play by itself: the published evidence decides
    assert all(task.get("failed_when") is False for task in verifies)


# The two preflight binaries are resolved on the controller (run_host_deploy's `shutil.which`) and passed
# as extra-vars: the playbook must never depend on an inherited PATH, and a manual run keeps the defaults.
OPENSSL_BIN = "{{ openssl_bin | default('openssl') }}"
SHA256SUM_BIN = "{{ sha256sum_bin | default('sha256sum') }}"


def with_resolved_tools(command: str) -> str:
    """Task 8A's pipeline with its two binaries replaced by the resolved extra-vars."""
    return command.replace("openssl", OPENSSL_BIN).replace("sha256sum", SHA256SUM_BIN)


def test_deploy_preflight_hashes_both_sides_of_the_key_match_in_der(deploy_tasks):
    def command_of(task):
        raw = task["ansible.builtin.shell"]
        return (raw if isinstance(raw, str) else raw["cmd"]).strip()

    hashes = [task for task in deploy_tasks if "-outform DER" in yaml.safe_dump(task)]
    assert len(hashes) == 2
    [cert_task] = [t for t in hashes if " x509 " in command_of(t)]
    [key_task] = [t for t in hashes if " x509 " not in command_of(t)]

    # one source of truth: each line is Task 8A's D2 template with the staged path in place of {path} and
    # the two binaries resolved instead of inherited from PATH
    assert command_of(cert_task) == with_resolved_tools(
        "set -o pipefail; " + CERT_KEY_HASH_COMMAND.format(path="{{ cert_pem_path | quote }}")
    )
    assert command_of(key_task) == with_resolved_tools(
        "set -o pipefail; " + KEY_HASH_COMMAND.format(path="{{ key_pem_path | quote }}")
    )
    for task in hashes:
        command = command_of(task)
        # the staged material lives on the worker: the hashes are computed there, without delegate_to
        assert task["connection"] == "local", f"{label(task)} must run on the controller"
        assert task["become"] is False, f"{label(task)} must not become root on the controller"
        assert task["args"]["executable"] == "/bin/bash", f"{label(task)} needs pipefail"
        assert task["timeout"] == 60 and task.get("no_log") is True, f"{label(task)} must be bounded and censored"
        assert task.get("changed_when") is False and task.get("failed_when") is False
        assert task["register"] in {"new_leaf_key_hash", "new_key_key_hash"}
        # D2: the identity is SHA-256 of the DER SubjectPublicKeyInfo on both sides
        assert "-outform DER" in command
        # neither binary may be invoked bare, and no other binary may be named
        assert OPENSSL_BIN in command and SHA256SUM_BIN in command
        assert "openssl" not in command.replace(OPENSSL_BIN, "").replace(SHA256SUM_BIN, "")
        # the module of a controller-side task runs on the worker: no interpreter discovery from PATH
        assert task["vars"]["ansible_python_interpreter"] == "{{ ansible_playbook_python }}"
    # the private key is unencrypted in the tmpfs staging area, and its hash task stays censored
    assert "-passin pass:" in command_of(key_task)
    assert key_task["no_log"] is True and cert_task["no_log"] is True


def test_deploy_compares_the_two_hashes_as_lowercase_hex(deploy_tasks):
    related = [
        task
        for task in deploy_tasks
        if module_of(task) != "ansible.builtin.shell" and "new_leaf_key" in yaml.safe_dump(task)
    ]
    assert related
    text = yaml.safe_dump(related)
    assert "| lower" in text  # the stored identity is lowercase hex, like public_key_sha256
    assert "split" in text  # sha256sum's "  -" suffix is dropped
    assert "rc" in text  # a failed pipeline is a mismatch, never a match of two empty hashes
    assert "| length == 64" in text  # and an empty hash can never equal another empty hash
    assert "key_mismatch_preflight" in text
