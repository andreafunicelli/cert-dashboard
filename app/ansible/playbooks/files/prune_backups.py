"""Prune old deploy backups under /var/backups/cert-dashboard (spec 6.4 step 2, Contract decision 17).

Runs on the *target* through ``ansible.builtin.script`` after a verified host run (Task 15), so this file
uses the standard library only and never imports the dashboard. ``prune_plan`` is pure: it takes the
``{directory: manifest document}`` mapping the caller read, and returns the directory names to remove.

Rules (§6.4):
  * ``retention_days == 0`` keeps everything (0 means "keep forever"); negative values are treated the same.
  * the layout is ``<backup_root>/<job_id>/manifest.json`` and the header must name the directory that holds
    it: a document whose ``job_id`` disagrees with its directory, or that has no ``job_id``/``created_at``/
    ``files`` header at all, describes an unknown backup and is never removed;
  * every ``files`` entry must be the metadata object ``deploy_backup.yml`` writes
    (``sha256``/``fingerprint``/``owner``/``group``/``mode``/``size``) *with values that task can produce*: a
    64-digit lowercase hex checksum, an empty-or-hex fingerprint, a string owner/group, an octal file mode
    (``stat.mode`` is ``"0644"``) and a non-negative size. A path name alone, or a checksum/mode no ``stat``
    can yield, is not a usable index -- and the safe reading of an unusable backup index is "unknown origin,
    unknown age, unknown content, keep it";
  * the newest backup of *every* path is always kept, so a rollback target is never pruned away. A
    directory therefore survives when at least one of its paths has no newer backup elsewhere.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

BACKUP_ROOT = "/var/backups/cert-dashboard"
MANIFEST_NAME = "manifest.json"
# The per-file metadata object ``deploy_backup.yml`` writes into ``manifest.json`` (spec 6.4 step 2).
METADATA_FIELDS = ("sha256", "fingerprint", "owner", "group", "mode", "size")
# What the playbook's ``stat`` results look like: ``checksum`` is a bare SHA-256, ``mode`` is ``"%04o"``
# ("0644", "4755"). Both are validated as values, not just as Python types: a checksum or a mode that
# ``stat`` cannot produce means the manifest was not written by the backup task.
SHA256_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
FILE_MODE_PATTERN = re.compile(r"\A[0-7]{4}\Z")
EXIT_OK = 0
EXIT_REFUSED = 2


def _created_at(document: Mapping[str, object]) -> datetime | None:
    """The manifest timestamp as an aware UTC datetime, or ``None`` when it is missing or unparsable."""
    raw = document.get("created_at")
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    # The playbook writes ``%Y-%m-%dT%H:%M:%SZ``; a naive stamp is read as UTC rather than dropped.
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _sha256_ok(value: object) -> bool:
    """True when ``value`` is a bare lowercase SHA-256 digest, the only form ``stat.checksum`` has."""
    return isinstance(value, str) and SHA256_PATTERN.match(value) is not None


def _fingerprint_ok(value: object) -> bool:
    """True for the values ``path_fingerprints`` holds: a SHA-256 of a serving certificate, or no entry ("")."""
    return isinstance(value, str) and (value == "" or _sha256_ok(value))


def _metadata_ok(entry: object) -> bool:
    """True when one ``files`` value has the metadata object shape ``deploy_backup.yml`` writes.

    A path name alone does not describe what a backup directory holds, so a manifest whose ``files`` values
    are not the ``{sha256, fingerprint, owner, group, mode, size}`` object is not a usable index and its
    directory is never a removal candidate (same safe reading as an unreadable manifest). The values are
    checked too, not only their Python types: an empty or truncated checksum and a mode that is not an octal
    file mode cannot come from the ``stat`` result the backup task records, so such a document is malformed
    and its age authorises nothing.
    """
    if not isinstance(entry, Mapping) or any(field not in entry for field in METADATA_FIELDS):
        return False
    if not _sha256_ok(entry["sha256"]):
        return False
    if not _fingerprint_ok(entry["fingerprint"]):
        return False
    if not all(isinstance(entry[field], str) for field in ("owner", "group")):
        return False
    mode = entry["mode"]
    if not (isinstance(mode, str) and FILE_MODE_PATTERN.match(mode) is not None):
        return False
    size = entry["size"]
    return isinstance(size, int) and not isinstance(size, bool) and size >= 0


def _paths(document: Mapping[str, object]) -> tuple[str, ...] | None:
    """The manifest's file paths, or ``None`` when the document is not a usable manifest."""
    files = document.get("files")
    if not isinstance(files, Mapping) or not files:
        return None
    if not all(isinstance(path, str) and path.startswith("/") for path in files):
        return None
    if not all(_metadata_ok(entry) for entry in files.values()):
        return None
    return tuple(files)


def _job_id_ok(directory: str, document: Mapping[str, object]) -> bool:
    """True when the manifest header names the directory that holds it, as ``deploy_backup.yml`` writes it.

    The layout is ``<backup_root>/<job_id>/manifest.json`` and the playbook writes the same ``job_id`` into
    the header, so the identity can be checked instead of assumed. A document without one cannot be
    attributed to a deploy, and one naming another directory does not describe these files: either way its
    timestamp says nothing about the backup, so the directory is kept like every other malformed manifest.
    """
    job_id = document.get("job_id")
    return isinstance(job_id, str) and job_id == directory


def _usable(directory: str, document: object) -> tuple[datetime, tuple[str, ...]] | None:
    if not isinstance(document, Mapping):
        return None
    if not _job_id_ok(directory, document):
        return None
    created = _created_at(document)
    paths = _paths(document)
    if created is None or paths is None:
        return None
    return created, paths


def prune_plan(manifests: Mapping[str, Mapping[str, object]], now: datetime, retention_days: int) -> list[str]:
    """Directory names to remove, sorted; every malformed manifest and every newest-per-path is kept."""
    if retention_days <= 0:
        return []
    usable = {
        name: entry for name, document in manifests.items() if (entry := _usable(name, document)) is not None
    }
    newest: dict[str, tuple[datetime, str]] = {}
    for name, (created, paths) in usable.items():
        for path in paths:
            best = newest.get(path)
            if best is None or (created, name) > best:
                newest[path] = (created, name)
    protected = {name for _, name in newest.values()}
    cutoff = now - timedelta(days=retention_days)
    return sorted(
        name
        for name, (created, _) in usable.items()
        if created < cutoff and name not in protected
    )


def read_manifests(root: Path) -> tuple[dict[str, object], list[str]]:
    """``{job directory: parsed manifest}`` plus the names whose ``manifest.json`` could not be read."""
    manifests: dict[str, object] = {}
    unreadable: list[str] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or entry.is_symlink():
            continue
        try:
            manifests[entry.name] = json.loads((entry / MANIFEST_NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            unreadable.append(entry.name)
    return manifests, unreadable


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Remove deploy backups past their retention.")
    parser.add_argument("--root", default=BACKUP_ROOT)
    parser.add_argument("--retention-days", type=int, default=30)
    parser.add_argument("--now", default=None, help="ISO 8601 UTC instant; defaults to the wall clock")
    args = parser.parse_args(argv)

    root = Path(args.root)
    # Fail closed: a wrong or empty --root must never walk (and delete) anything outside the backup tree.
    if not root.is_dir() or root.is_symlink():
        print(json.dumps({"removed": [], "kept": [], "error": "backup root is not a directory"}))
        return EXIT_REFUSED
    try:
        now = datetime.fromisoformat(args.now) if args.now else datetime.now(UTC)
    except ValueError:
        print(json.dumps({"removed": [], "kept": [], "error": "invalid --now"}))
        return EXIT_REFUSED
    now = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)

    manifests, unreadable = read_manifests(root)
    removals = prune_plan(manifests, now, args.retention_days)  # type: ignore[arg-type]
    removed: list[str] = []
    for name in removals:
        try:
            shutil.rmtree(root / name)
        except OSError as error:  # a failed removal must never fail the deploy that already succeeded
            unreadable.append(f"{name}: {error.strerror or 'remove failed'}")
        else:
            removed.append(name)
    kept = sorted(set(manifests) - set(removed)) + sorted(set(unreadable) - set(manifests))
    print(json.dumps({"removed": removed, "kept": kept}))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
