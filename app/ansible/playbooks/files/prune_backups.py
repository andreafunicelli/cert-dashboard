"""Prune old deploy backups under /var/backups/cert-dashboard (spec 6.4 step 2, Contract decision 17).

Runs on the *target* through ``ansible.builtin.script`` after a verified host run (Task 15), so this file
uses the standard library only and never imports the dashboard. ``prune_plan`` is pure: it takes the
``{directory: manifest document}`` mapping the caller read, and returns the directory names to remove.

Rules (§6.4):
  * ``retention_days == 0`` keeps everything (0 means "keep forever"); negative values are treated the same.
  * a directory is a candidate only when its ``manifest.json`` parses into ``created_at`` and a ``files``
    mapping of absolute paths, each carrying the metadata object the playbook writes
    (``sha256``/``fingerprint``/``owner``/``group``/``mode``/``size``) -- anything malformed is left
    untouched, because the safe reading of an unreadable backup index is "unknown age, unknown content,
    keep it";
  * the newest backup of *every* path is always kept, so a rollback target is never pruned away. A
    directory therefore survives when at least one of its paths has no newer backup elsewhere.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

BACKUP_ROOT = "/var/backups/cert-dashboard"
MANIFEST_NAME = "manifest.json"
# The per-file metadata object ``deploy_backup.yml`` writes into ``manifest.json`` (spec 6.4 step 2).
METADATA_FIELDS = ("sha256", "fingerprint", "owner", "group", "mode", "size")
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


def _metadata_ok(entry: object) -> bool:
    """True when one ``files`` value has the metadata object shape ``deploy_backup.yml`` writes.

    A path name alone does not describe what a backup directory holds, so a manifest whose ``files`` values
    are not the ``{sha256, fingerprint, owner, group, mode, size}`` object is not a usable index and its
    directory is never a removal candidate (same safe reading as an unreadable manifest).
    """
    if not isinstance(entry, Mapping) or any(field not in entry for field in METADATA_FIELDS):
        return False
    if not all(isinstance(entry[field], str) for field in ("sha256", "owner", "group", "mode")):
        return False
    fingerprint = entry["fingerprint"]
    if fingerprint is not None and not isinstance(fingerprint, str):
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


def _usable(document: object) -> tuple[datetime, tuple[str, ...]] | None:
    if not isinstance(document, Mapping):
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
    usable = {name: entry for name, document in manifests.items() if (entry := _usable(document)) is not None}
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
