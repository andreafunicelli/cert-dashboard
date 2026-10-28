"""Static rules for the committed playbooks (Plan 3 Task 8B; Task 14 adds ``deploy.yml``).

``discover.yml`` is read-only on the target: only ``ansible.builtin`` modules from an allowlist, no network
module, every task that touches a key path, certificate extraction or the configuration dump is ``no_log``,
every command is bounded, and everything that writes is delegated to the controller.

``deploy.yml`` is fail-safe by construction (Task 14): it stops after the backup, so its only writers are
``file``/``copy`` tasks under ``{{ backup_root }}``, no ``command``/``shell`` may move, copy, install, relabel
or reload anything, and the two leaf/key hash tasks compute the D2 DER pipelines on the controller where the
staged material lives.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

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


# --- deploy.yml: preflight and backup only (Plan 3 Task 14) --------------------------------------

# Any task that handles the whole file map (key paths included) or a key path directly is censored.
DEPLOY_SENSITIVE = ("key_pem_path", "key_paths", "key_stat", "file_paths")
# A preflight/backup-only playbook may read, stat, hash and copy files into the backup tree; it may never
# move, copy, relabel or reload anything on the target (§6.4 steps 3–7 belong to Task 15).
FORBIDDEN_COMMANDS = ("mv", "cp", "install", "restorecon", "reload", "graceful", "systemctl")
BACKUP_PREFIX = "{{ backup_root }}"


@pytest.fixture(scope="module")
def deploy_tasks() -> list[dict]:
    return tasks_of(DEPLOY)


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
    # stat/split/hash/backup/verify of the file map at least
    assert len(sensitive) >= 5
    for task in sensitive:
        assert task.get("no_log") is True, f"{label(task)} must be no_log: true"


def test_deploy_every_command_and_shell_task_is_bounded_to_60_seconds(deploy_tasks):
    commands = [t for t in deploy_tasks if module_of(t) in {"ansible.builtin.command", "ansible.builtin.shell"}]
    assert commands
    for task in commands:
        assert 0 < task.get("timeout", 10**6) <= 60, f"{label(task)} needs timeout <= 60"


def test_deploy_writes_only_inside_the_backup_tree(deploy_tasks):
    writers = [t for t in deploy_tasks if module_of(t) in {"ansible.builtin.file", "ansible.builtin.copy"}]
    assert writers
    for task in writers:
        args = task[module_of(task)]
        assert isinstance(args, dict), f"{label(task)} must use the module's argument mapping"
        target = args.get("dest") or args.get("path")
        assert isinstance(target, str), f"{label(task)} has no dest/path"
        assert target.startswith(BACKUP_PREFIX), f"{label(task)} writes outside {BACKUP_PREFIX}: {target}"


def test_deploy_never_moves_copies_labels_or_reloads_through_a_command(deploy_tasks):
    for task in deploy_tasks:
        if module_of(task) not in {"ansible.builtin.command", "ansible.builtin.shell"}:
            continue
        text = yaml.safe_dump(task[module_of(task)])
        for word in FORBIDDEN_COMMANDS:
            assert not re.search(rf"\b{word}\b", text), f"{label(task)} runs {word}"


def test_deploy_has_no_target_side_script_task(deploy_tasks):
    assert [t for t in deploy_tasks if module_of(t) == "ansible.builtin.script"] == []


def test_deploy_publishes_one_per_host_result(deploy_tasks):
    publishers = [t for t in deploy_tasks if module_of(t) == "ansible.builtin.set_stats"]
    assert len(publishers) == 1
    text = yaml.safe_dump(publishers[0])
    assert "cert_dashboard" in text
    for published in ("deploy_step", "deploy_reason", "backup_dir"):
        assert published in text


def test_deploy_only_ever_marks_the_steps_it_performs(deploy_tasks):
    # `parse_host_result` grants success only on `step == "verified"`; a playbook that can only ever
    # publish `preflight` and `backed_up` therefore cannot be recorded as a successful deploy.
    assignments = [
        task["ansible.builtin.set_fact"]["deploy_step"]
        for task in deploy_tasks
        if module_of(task) == "ansible.builtin.set_fact"
        and isinstance(task["ansible.builtin.set_fact"], dict)
        and "deploy_step" in task["ansible.builtin.set_fact"]
    ]
    assert assignments
    assert set(assignments) == {"preflight", "backed_up"}


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
