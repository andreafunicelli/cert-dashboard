"""Per-job tmpfs staging of secret files (SSH key, TLS private key) passed to Ansible by path only."""

from __future__ import annotations

import contextlib
import errno
import os
from pathlib import Path
from types import TracebackType
from typing import Self
from uuid import UUID


class StagingError(Exception):
    """Staging refused or failed; the message never contains file content."""


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class StagingArea:
    """`<root>/<job_id>` (0700) holding 0600 files; every entry is removed on exit."""

    def __init__(self, root: Path, job_id: UUID) -> None:
        self._root = Path(root)
        self._name = str(job_id)
        self.path = self._root / self._name
        self._root_fd: int | None = None
        self._dir_fd: int | None = None

    def __enter__(self) -> Self:
        try:
            self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._root_fd = os.open(self._root, _DIR_FLAGS)  # O_NOFOLLOW: a symlinked root fails
            os.mkdir(self._name, 0o700, dir_fd=self._root_fd)
            self._dir_fd = os.open(self._name, _DIR_FLAGS, dir_fd=self._root_fd)
            os.fchmod(self._dir_fd, 0o700)  # independent of the umask
        except OSError as exc:
            self._close()
            raise StagingError(
                f"cannot create the staging directory ({errno.errorcode.get(exc.errno or 0, 'error')})"
            ) from None
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self._remove()

    def write(self, name: str, data: bytes) -> Path:
        """Create `name` exclusively with mode 0600 and return its path."""
        if self._dir_fd is None:
            raise StagingError("staging area is not open")
        if not name or name in {".", ".."} or "/" in name or "\0" in name:
            raise StagingError("invalid staging file name")
        try:
            fd = os.open(name, _FILE_FLAGS, 0o600, dir_fd=self._dir_fd)
        except OSError as exc:
            raise StagingError(
                f"cannot create the staging file ({errno.errorcode.get(exc.errno or 0, 'error')})"
            ) from None
        try:
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(data)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(name, dir_fd=self._dir_fd)
            raise StagingError("cannot write the staging file") from None
        return self.path / name

    def _remove(self) -> None:
        try:
            if self._dir_fd is not None and self._root_fd is not None:
                for entry in os.listdir(self._dir_fd):
                    with contextlib.suppress(OSError):
                        os.unlink(entry, dir_fd=self._dir_fd)
                with contextlib.suppress(OSError):
                    os.rmdir(self._name, dir_fd=self._root_fd)
        finally:
            self._close()

    def _close(self) -> None:
        for fd in (self._dir_fd, self._root_fd):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
        self._dir_fd = self._root_fd = None
