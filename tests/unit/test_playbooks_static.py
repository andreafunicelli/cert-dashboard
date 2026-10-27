"""Static rules for the committed playbooks (Plan 3 Task 8B; Task 14 extends this file for ``deploy.yml``).

``discover.yml`` is read-only on the target: only ``ansible.builtin`` modules from an allowlist, no network
module, every task that touches a key path, certificate extraction or the configuration dump is ``no_log``,
every command is bounded, and everything that writes is delegated to the controller.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from app.ansible.discovery import KEY_HASH_COMMAND
from app.ansible.runner import PLAYBOOK_DIR

DISCOVER = PLAYBOOK_DIR / "discover.yml"
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


def walk(tasks: list[dict], base: Path = PLAYBOOK_DIR) -> list[dict]:
    """Every task (``block`` containers excluded), following their sections and literal ``include_tasks`` files."""
    found: list[dict] = []
    for task in tasks:
        if "block" not in task:
            found.append(task)
        for section in ("block", "rescue", "always"):
            found.extend(walk(task.get(section) or [], base))
        include = task.get("ansible.builtin.include_tasks")
        if include is not None:
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
