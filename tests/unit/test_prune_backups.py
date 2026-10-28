"""Retention of the on-target deploy backups (Plan 3 Task 14; spec 6.4 step 2, Contract decision 17).

``files/prune_backups.py`` runs on the target through ``ansible.builtin.script`` (Task 15), so it is a
standalone stdlib script: the tests load it by path and exercise the pure ``prune_plan`` plus the
``main()`` entry point over a temporary backup tree.

Every manifest is keyed by the directory that holds it, exactly like the ``<job_id>/manifest.json`` layout
``deploy_backup.yml`` writes, and the fixtures stamp the matching ``job_id``: a document whose header names
another directory is malformed, like any other manifest the playbook could not have produced.
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
    """A manifest as the playbook writes it, ``days_ago`` days before ``NOW``, stamped ``job_id``."""
    created = (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "job_id": job_id,
        "created_at": created,
        "files": {path: {"sha256": "a" * 64, "fingerprint": "", "owner": "root", "group": "root",
                         "mode": "0644", "size": 10} for path in paths},
    }


def entry(document: dict, path: str, **metadata) -> dict:
    """``document`` with ``path``'s metadata overridden: ``None`` removes a field, anything else sets it."""
    record = dict(document["files"][path])
    for field, value in metadata.items():
        if value is None:
            record.pop(field, None)
        else:
            record[field] = value
    return {**document, "files": {path: record}}


def test_directories_past_retention_are_removed_when_every_path_is_superseded():
    script = load_script()
    manifests = {
        "old": manifest("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", days_ago=40, job_id="old"),
        "fresh": manifest("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", days_ago=2, job_id="fresh"),
    }
    assert script.prune_plan(manifests, NOW, 30) == ["old"]


def test_a_directory_holding_the_newest_backup_of_some_path_is_kept():
    script = load_script()
    manifests = {
        "old": manifest("/etc/nginx/ssl/www.crt", "/etc/apache2/ssl/www.chain.pem", days_ago=90, job_id="old"),
        "fresh": manifest("/etc/nginx/ssl/www.crt", days_ago=1, job_id="fresh"),
    }
    # www.crt is superseded, but nothing newer holds the chain file: the whole directory survives.
    assert script.prune_plan(manifests, NOW, 30) == []


def test_the_newest_backup_of_each_path_is_kept_and_only_the_others_are_removed():
    script = load_script()
    manifests = {
        "oldest": manifest("/etc/ssl/www.crt", days_ago=60, job_id="oldest"),
        "middle": manifest("/etc/ssl/www.crt", "/etc/ssl/www.key", days_ago=40, job_id="middle"),
        "newest": manifest("/etc/ssl/www.crt", "/etc/ssl/www.key", days_ago=1, job_id="newest"),
    }
    assert script.prune_plan(manifests, NOW, 30) == ["middle", "oldest"]


def test_a_fresh_directory_is_never_removed():
    script = load_script()
    manifests = {
        "recent": manifest("/etc/ssl/www.crt", days_ago=29, job_id="recent"),
        "newer": manifest("/etc/ssl/www.crt", days_ago=1, job_id="newer"),
    }
    assert script.prune_plan(manifests, NOW, 30) == []


def test_retention_zero_removes_nothing():
    script = load_script()
    manifests = {
        f"job-{days}": manifest("/etc/ssl/www.crt", days_ago=days, job_id=f"job-{days}") for days in (400, 900)
    }
    assert script.prune_plan(manifests, NOW, 0) == []
    assert script.prune_plan(manifests, NOW, -1) == []


def test_malformed_manifests_are_never_removed():
    script = load_script()
    manifests = {
        "not-a-mapping": "garbage",  # type: ignore[dict-item]
        "no-created-at": {"job_id": "no-created-at", "files": {"/etc/ssl/www.crt": {}}},
        "bad-created-at": {
            **manifest("/etc/ssl/www.crt", days_ago=90, job_id="bad-created-at"), "created_at": "yesterday"},
        "no-files": {"job_id": "no-files", "created_at": "2026-01-01T00:00:00Z"},
        "files-not-a-mapping": {
            **manifest(days_ago=90, job_id="files-not-a-mapping"), "files": ["/etc/ssl/www.crt"]},
        "non-string-path": {**manifest(days_ago=90, job_id="non-string-path"), "files": {1: {}}},
        "empty-files": {**manifest(days_ago=90, job_id="empty-files"), "files": {}},
        "fresh": manifest("/etc/ssl/www.crt", days_ago=1, job_id="fresh"),
    }
    assert script.prune_plan(manifests, NOW, 30) == []


def test_a_manifest_whose_file_metadata_is_malformed_is_never_removed():
    """Task 14: only a manifest with the full per-file metadata shape may authorise a removal.

    A manifest whose ``files`` mapping carries path *names* but not the metadata object the playbook writes
    is not a usable index: its age says nothing about what the directory actually holds, so it is kept.
    """
    script = load_script()
    old = manifest("/etc/ssl/www.crt", days_ago=90, job_id="old")
    manifests = {
        "entry-is-a-string": {
            **old, "job_id": "entry-is-a-string", "files": {"/etc/ssl/www.crt": "not metadata"}},
        "entry-is-null": {**old, "job_id": "entry-is-null", "files": {"/etc/ssl/www.crt": None}},
        "metadata-keys-missing": {
            **old, "job_id": "metadata-keys-missing",
            "files": {"/etc/ssl/www.crt": {"sha256": "a" * 64, "owner": "root"}},
        },
        "metadata-types-wrong": {
            **old, "job_id": "metadata-types-wrong",
            "files": {"/etc/ssl/www.crt": {
                "sha256": 1, "fingerprint": "", "owner": "root", "group": "root", "mode": "0644", "size": 10}},
        },
        "fresh": manifest("/etc/ssl/www.crt", days_ago=1, job_id="fresh"),
    }
    assert script.prune_plan(manifests, NOW, 30) == []


def test_a_manifest_whose_metadata_values_are_impossible_is_never_removed():
    """Task 14: only the values ``deploy_backup.yml`` can write may authorise an irreversible removal.

    The playbook records ``stat.checksum`` (64 lowercase hex digits), an empty-or-hex ``path_fingerprints``
    entry, a string owner/group, the octal ``stat.mode`` (``%04o``) and a non-negative size. A document
    carrying anything else -- an empty or truncated checksum, a mode that is not an octal file mode -- was
    not produced by the backup task, so its ``created_at`` does not describe the directory: keep it.
    """
    script = load_script()
    path = "/etc/ssl/www.crt"
    old = manifest(path, days_ago=90, job_id="old")
    impossible = {
        "empty-sha256": {"sha256": ""},
        "truncated-sha256": {"sha256": "a" * 63},
        "non-hex-sha256": {"sha256": "g" * 64},
        "upper-case-sha256": {"sha256": "A" * 64},
        "mode-not-octal": {"mode": "not-an-octal-mode"},
        "mode-without-leading-zero": {"mode": "644"},
        "mode-not-octal-digits": {"mode": "0899"},
        "fingerprint-truncated": {"fingerprint": "f" * 63},
        "fingerprint-not-hex": {"fingerprint": "not-a-fingerprint"},
        "missing-fingerprint": {"fingerprint": None},
        "negative-size": {"size": -1},
        "boolean-size": {"size": True},
    }
    manifests = {name: {**entry(old, path, **metadata), "job_id": name} for name, metadata in impossible.items()}
    manifests["fresh"] = manifest(path, days_ago=1, job_id="fresh")
    assert script.prune_plan(manifests, NOW, 30) == []


def test_a_manifest_missing_its_job_id_header_is_never_removed():
    """Task 14: the manifest header is ``{job_id, created_at, files}``; a document without it is malformed.

    Without the job id the directory cannot be attributed to a deploy, so its age alone must not authorise a
    removal -- the same safe reading as an unreadable or unshaped manifest.
    """
    script = load_script()
    old = manifest("/etc/ssl/www.crt", days_ago=90, job_id="old")
    manifests = {
        "old-missing-job-id": {key: value for key, value in old.items() if key != "job_id"},
        "job-id-empty": {**old, "job_id": ""},
        "job-id-not-a-string": {**old, "job_id": 123},
        "fresh": manifest("/etc/ssl/www.crt", days_ago=1, job_id="fresh"),
    }
    assert script.prune_plan(manifests, NOW, 30) == []


def test_a_manifest_whose_job_id_disagrees_with_its_directory_is_never_removed():
    """Task 14 layout: ``<job_id>/manifest.json``; a header naming another directory is malformed.

    ``job_id`` is the identity of the directory, not a free-form label: a manifest that names a different
    job cannot be trusted to describe the files this directory holds, so its age authorises nothing.
    """
    script = load_script()
    manifests = {
        "old-directory": manifest("/etc/ssl/www.crt", days_ago=90, job_id="different-job"),
        "fresh": manifest("/etc/ssl/www.crt", days_ago=1, job_id="fresh"),
    }
    assert script.prune_plan(manifests, NOW, 30) == []


def test_a_naive_created_at_is_read_as_utc():
    script = load_script()
    manifests = {
        "old": {**manifest("/etc/ssl/www.crt", days_ago=40, job_id="old"), "created_at": "2026-09-18T12:00:00"},
        "fresh": manifest("/etc/ssl/www.crt", days_ago=1, job_id="fresh"),
    }
    assert script.prune_plan(manifests, NOW, 30) == ["old"]


def test_session_directories_that_are_not_manifests_are_left_alone(tmp_path):
    script = load_script()
    root = tmp_path / "cert-dashboard"
    old = root / "old"
    fresh = root / "fresh"
    for directory, days in ((old, 40), (fresh, 1)):
        directory.mkdir(parents=True)
        (directory / "manifest.json").write_text(
            json.dumps(manifest("/etc/ssl/www.crt", days_ago=days, job_id=directory.name)))
    (root / "not-a-job").mkdir()  # no manifest at all: never removed
    code = script.main(["--root", str(root), "--retention-days", "30", "--now", NOW.isoformat()])
    assert code == 0
    assert not old.exists() and fresh.is_dir() and (root / "not-a-job").is_dir()


def test_main_reports_what_it_removed_as_one_json_document(tmp_path, capsys):
    script = load_script()
    root = tmp_path / "cert-dashboard"
    for name, days in (("old", 40), ("fresh", 1)):
        (root / name).mkdir(parents=True)
        (root / name / "manifest.json").write_text(
            json.dumps(manifest("/etc/ssl/www.crt", days_ago=days, job_id=name)))
    assert script.main(["--root", str(root), "--retention-days", "30", "--now", NOW.isoformat()]) == 0
    report = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert report == {"removed": ["old"], "kept": ["fresh"]}


def test_main_removes_only_the_directories_whose_manifest_names_them(tmp_path, capsys):
    """End-to-end: the ``<job_id>/manifest.json`` layout decides what ``main`` may delete."""
    script = load_script()
    root = tmp_path / "cert-dashboard"
    for name, job_id, days in (("old", "old", 40), ("mismatched", "another-job", 40), ("fresh", "fresh", 1)):
        (root / name).mkdir(parents=True)
        (root / name / "manifest.json").write_text(
            json.dumps(manifest("/etc/ssl/www.crt", days_ago=days, job_id=job_id)))
    assert script.main(["--root", str(root), "--retention-days", "30", "--now", NOW.isoformat()]) == 0
    report = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert report == {"removed": ["old"], "kept": ["fresh", "mismatched"]}
    assert not (root / "old").exists()
    assert (root / "fresh").is_dir() and (root / "mismatched").is_dir()


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
