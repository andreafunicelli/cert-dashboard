"""Retention of the on-target deploy backups (Plan 3 Task 14; spec 6.4 step 2, Contract decision 17).

``files/prune_backups.py`` runs on the target through ``ansible.builtin.script`` (Task 15), so it is a
standalone stdlib script: the tests load it by path and exercise the pure ``prune_plan`` plus the
``main()`` entry point over a temporary backup tree.
"""

import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "app" / "ansible" / "playbooks" / "files" / "prune_backups.py"
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


def load_script():
    spec = importlib.util.spec_from_file_location("prune_backups_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manifest(*paths: str, days_ago: float = 0, job_id: str = "job") -> dict:
    """A manifest as the playbook writes it, ``days_ago`` days before ``NOW``."""
    created = (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "job_id": job_id,
        "created_at": created,
        "files": {path: {"sha256": "a" * 64, "fingerprint": None, "owner": "root", "group": "root",
                         "mode": "0644", "size": 10} for path in paths},
    }


def test_directories_past_retention_are_removed_when_every_path_is_superseded():
    script = load_script()
    manifests = {
        "old": manifest("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", days_ago=40),
        "fresh": manifest("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", days_ago=2),
    }
    assert script.prune_plan(manifests, NOW, 30) == ["old"]


def test_a_directory_holding_the_newest_backup_of_some_path_is_kept():
    script = load_script()
    manifests = {
        "old": manifest("/etc/nginx/ssl/www.crt", "/etc/apache2/ssl/www.chain.pem", days_ago=90),
        "fresh": manifest("/etc/nginx/ssl/www.crt", days_ago=1),
    }
    # www.crt is superseded, but nothing newer holds the chain file: the whole directory survives.
    assert script.prune_plan(manifests, NOW, 30) == []


def test_the_newest_backup_of_each_path_is_kept_and_only_the_others_are_removed():
    script = load_script()
    manifests = {
        "oldest": manifest("/etc/ssl/www.crt", days_ago=60),
        "middle": manifest("/etc/ssl/www.crt", "/etc/ssl/www.key", days_ago=40),
        "newest": manifest("/etc/ssl/www.crt", "/etc/ssl/www.key", days_ago=1),
    }
    assert script.prune_plan(manifests, NOW, 30) == ["middle", "oldest"]


def test_a_fresh_directory_is_never_removed():
    script = load_script()
    manifests = {
        "recent": manifest("/etc/ssl/www.crt", days_ago=29),
        "newer": manifest("/etc/ssl/www.crt", days_ago=1),
    }
    assert script.prune_plan(manifests, NOW, 30) == []


def test_retention_zero_removes_nothing():
    script = load_script()
    manifests = {f"job-{days}": manifest("/etc/ssl/www.crt", days_ago=days) for days in (400, 900)}
    assert script.prune_plan(manifests, NOW, 0) == []
    assert script.prune_plan(manifests, NOW, -1) == []


def test_malformed_manifests_are_never_removed():
    script = load_script()
    superseding = manifest("/etc/ssl/www.crt", days_ago=1)
    manifests = {
        "not-a-mapping": "garbage",  # type: ignore[dict-item]
        "no-created-at": {"files": {"/etc/ssl/www.crt": {}}},
        "bad-created-at": {**manifest("/etc/ssl/www.crt", days_ago=90), "created_at": "yesterday"},
        "no-files": {"job_id": "x", "created_at": "2026-01-01T00:00:00Z"},
        "files-not-a-mapping": {**manifest(days_ago=90), "files": ["/etc/ssl/www.crt"]},
        "non-string-path": {**manifest(days_ago=90), "files": {1: {}}},
        "empty-files": {**manifest(days_ago=90), "files": {}},
        "fresh": superseding,
    }
    assert script.prune_plan(manifests, NOW, 30) == []


def test_a_manifest_whose_file_metadata_is_malformed_is_never_removed():
    """Task 14: only a manifest with the full per-file metadata shape may authorise a removal.

    A manifest whose ``files`` mapping carries path *names* but not the metadata object the playbook writes
    is not a usable index: its age says nothing about what the directory actually holds, so it is kept.
    """
    script = load_script()
    old = manifest("/etc/ssl/www.crt", days_ago=90)
    manifests = {
        "entry-is-a-string": {**old, "job_id": "string-entry", "files": {"/etc/ssl/www.crt": "not metadata"}},
        "entry-is-null": {**old, "job_id": "null-entry", "files": {"/etc/ssl/www.crt": None}},
        "metadata-keys-missing": {
            **old, "job_id": "short-entry",
            "files": {"/etc/ssl/www.crt": {"sha256": "a" * 64, "owner": "root"}},
        },
        "metadata-types-wrong": {
            **old, "job_id": "typed-entry",
            "files": {"/etc/ssl/www.crt": {
                "sha256": 1, "fingerprint": "", "owner": "root", "group": "root", "mode": "0644", "size": 10}},
        },
        "fresh": manifest("/etc/ssl/www.crt", days_ago=1),
    }
    assert script.prune_plan(manifests, NOW, 30) == []


def test_a_manifest_missing_its_job_id_header_is_never_removed():
    """Task 14: the manifest header is ``{job_id, created_at, files}``; a document without it is malformed.

    Without the job id the directory cannot be attributed to a deploy, so its age alone must not authorise a
    removal -- the same safe reading as an unreadable or unshaped manifest.
    """
    script = load_script()
    old = manifest("/etc/ssl/www.crt", days_ago=90)
    manifests = {
        "old-missing-job-id": {key: value for key, value in old.items() if key != "job_id"},
        "job-id-empty": {**old, "job_id": ""},
        "job-id-not-a-string": {**old, "job_id": 123},
        "fresh": manifest("/etc/ssl/www.crt", days_ago=1),
    }
    assert script.prune_plan(manifests, NOW, 30) == []


def test_a_naive_created_at_is_read_as_utc():
    script = load_script()
    manifests = {
        "old": {**manifest("/etc/ssl/www.crt", days_ago=40), "created_at": "2026-09-18T12:00:00"},
        "fresh": manifest("/etc/ssl/www.crt", days_ago=1),
    }
    assert script.prune_plan(manifests, NOW, 30) == ["old"]


def test_session_directories_that_are_not_manifests_are_left_alone(tmp_path):
    script = load_script()
    root = tmp_path / "cert-dashboard"
    old = root / "old"
    fresh = root / "fresh"
    for directory, days in ((old, 40), (fresh, 1)):
        directory.mkdir(parents=True)
        (directory / "manifest.json").write_text(json.dumps(manifest("/etc/ssl/www.crt", days_ago=days)))
    (root / "not-a-job").mkdir()  # no manifest at all: never removed
    code = script.main(["--root", str(root), "--retention-days", "30", "--now", NOW.isoformat()])
    assert code == 0
    assert not old.exists() and fresh.is_dir() and (root / "not-a-job").is_dir()


def test_main_reports_what_it_removed_as_one_json_document(tmp_path, capsys):
    script = load_script()
    root = tmp_path / "cert-dashboard"
    for name, days in (("old", 40), ("fresh", 1)):
        (root / name).mkdir(parents=True)
        (root / name / "manifest.json").write_text(json.dumps(manifest("/etc/ssl/www.crt", days_ago=days)))
    assert script.main(["--root", str(root), "--retention-days", "30", "--now", NOW.isoformat()]) == 0
    report = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert report == {"removed": ["old"], "kept": ["fresh"]}


def test_main_never_leaves_the_backup_root_and_refuses_a_missing_one(tmp_path):
    script = load_script()
    missing = tmp_path / "not-there"
    assert script.main(["--root", str(missing), "--retention-days", "30"]) == 2
    assert not missing.exists()
    # a root that is a file, not a directory, is refused the same way
    file_root = tmp_path / "file"
    file_root.write_text("x")
    assert script.main(["--root", str(file_root), "--retention-days", "30"]) == 2
    assert file_root.read_text() == "x"
