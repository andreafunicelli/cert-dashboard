"""Local Git inventory fixtures: a bare ``file://`` repository, commits to it, and vaulted vars files.

Real ``git`` and ``ansible-vault`` only; no network. Commit identity and dates are fixed so revisions
are reproducible, and the environment is built from scratch so the developer's git config never leaks in.
"""

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

_COMMIT_DATE = "2026-10-19T12:00:00+00:00"


def _git_env(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ["PATH"],
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }


@dataclass
class InventoryRepo:
    """A bare repository (``path``) plus the working clone used to commit to it."""

    path: Path
    work: Path
    _count: int = field(default=0, repr=False)

    @property
    def url(self) -> str:
        return f"file://{self.path}"

    def _git(self, *args: str, cwd: Path | None = None) -> str:
        env = _git_env(self.work.parent)
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = _COMMIT_DATE
        done = subprocess.run(
            ["git", *args], cwd=cwd or self.work, env=env, check=True, capture_output=True, text=True, timeout=60
        )
        return done.stdout.strip()

    @property
    def head(self) -> str:
        """The commit the bare repository's default branch (HEAD) points at."""
        return self._git("rev-parse", "HEAD", cwd=self.path)

    @property
    def head_date(self) -> str:
        """The commit date of ``head`` as ISO 8601 UTC with an explicit offset (git >= 2.45 prints ``Z``)."""
        return datetime.fromisoformat(self._git("log", "-1", "--format=%cI", "HEAD", cwd=self.path)).astimezone(UTC).isoformat()

    def commit(self, files: dict[str, str], *, branch: str = "main") -> str:
        """Write ``files`` (path -> text; ``None`` is not supported) on ``branch`` and push; returns the SHA."""
        existing = self._git("branch", "--list", branch)
        if not existing:
            self._git("checkout", "-q", "-b", branch)
        else:
            self._git("checkout", "-q", branch)
        for name, content in files.items():
            target = self.work / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        self._count += 1
        self._git("add", "-A")
        self._git("commit", "-q", "--allow-empty", "-m", f"fixture commit {self._count}")
        self._git("push", "-q", "origin", f"{branch}:{branch}")
        return self._git("rev-parse", "HEAD")

    def tag(self, name: str, *, annotated: bool = False) -> str:
        """Tag the working clone's HEAD and push the tag; returns the tag's object name."""
        if annotated:
            self._git("tag", "-a", "-m", f"tag {name}", name)
        else:
            self._git("tag", name)
        self._git("push", "-q", "origin", f"refs/tags/{name}")
        return self._git("rev-parse", name)

    def set_default_branch(self, branch: str) -> None:
        self._git("symbolic-ref", "HEAD", f"refs/heads/{branch}", cwd=self.path)


def make_bare_repo(path: Path, files: dict[str, str]) -> InventoryRepo:
    """A bare repository at ``path`` (default branch ``main``) whose first commit holds ``files``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    work = path.parent / f"{path.name}.work"
    env = _git_env(path.parent)
    subprocess.run(
        ["git", "init", "-q", "--bare", "--initial-branch=main", str(path)], env=env, check=True, timeout=60
    )
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(work)], env=env, check=True, timeout=60)
    subprocess.run(["git", "remote", "add", "origin", str(path)], cwd=work, env=env, check=True, timeout=60)
    repo = InventoryRepo(path, work)
    repo.commit(files)
    return repo


def write_vaulted(path: Path, mapping: dict, password: str) -> None:
    """Write ``mapping`` as an ``ansible-vault`` encrypted vars file at ``path``."""
    # A subprocess with its own HOME keeps ansible's import-time directory creation out of the caller.
    scratch = path.parent / f"{path.name}.vault-scratch"
    scratch.mkdir()
    password_file = scratch / "password"
    password_file.write_text(password)
    path.write_text(json.dumps(mapping))
    env = {"PATH": os.environ["PATH"], "HOME": str(scratch), "ANSIBLE_LOCAL_TEMP": str(scratch / "tmp")}
    binary = Path(sys.executable).parent / "ansible-vault"
    subprocess.run(
        [str(binary), "encrypt", "--vault-password-file", str(password_file), str(path)],
        env=env,
        check=True,
        capture_output=True,
        timeout=60,
    )
    shutil.rmtree(scratch)
