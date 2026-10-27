import os
import stat
from pathlib import Path
from uuid import uuid4

import pytest

from app.ansible.staging import StagingArea, StagingError


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_directory_is_private_and_files_are_owner_only(tmp_path):
    with StagingArea(tmp_path / "keys", uuid4()) as area:
        written = area.write("ssh_key", b"key-bytes")
        assert area.path.parent == tmp_path / "keys"
        assert _mode(area.path) == 0o700
        assert written == area.path / "ssh_key"
        assert _mode(written) == 0o600
        assert written.read_bytes() == b"key-bytes"


def test_modes_do_not_depend_on_the_umask(tmp_path):
    previous = os.umask(0o000)
    try:
        with StagingArea(tmp_path / "keys", uuid4()) as area:
            written = area.write("k", b"x")
            assert _mode(area.path) == 0o700
            assert _mode(written) == 0o600
    finally:
        os.umask(previous)


def test_existing_names_are_refused_not_overwritten(tmp_path):
    with StagingArea(tmp_path / "keys", uuid4()) as area:
        area.write("ssh_key", b"first")
        with pytest.raises(StagingError):
            area.write("ssh_key", b"second")
        assert (area.path / "ssh_key").read_bytes() == b"first"


@pytest.mark.parametrize("name", ["a/b", "../escape", "..", ".", "", "nul\0byte", "/abs"])
def test_unsafe_names_are_refused(tmp_path, name):
    with StagingArea(tmp_path / "keys", uuid4()) as area, pytest.raises(StagingError):
        area.write(name, b"x")
    assert not (tmp_path / "escape").exists()


def test_a_symlink_inside_the_area_is_never_followed(tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep")
    with StagingArea(tmp_path / "keys", uuid4()) as area:
        (area.path / "link").symlink_to(victim)
        with pytest.raises(StagingError):
            area.write("link", b"overwrite")
    assert victim.read_bytes() == b"keep"


def test_a_symlinked_root_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "keys").symlink_to(real)
    with pytest.raises(StagingError), StagingArea(tmp_path / "keys", uuid4()):
        pass
    assert list(real.iterdir()) == []


def test_an_existing_job_directory_is_refused(tmp_path):
    job_id = uuid4()
    (tmp_path / "keys" / str(job_id)).mkdir(parents=True)
    with pytest.raises(StagingError), StagingArea(tmp_path / "keys", job_id):
        pass


def test_directory_is_removed_on_normal_exit(tmp_path):
    with StagingArea(tmp_path / "keys", uuid4()) as area:
        area.write("ssh_key", b"x")
        path = area.path
    assert not path.exists()
    assert list((tmp_path / "keys").iterdir()) == []


def test_directory_is_removed_when_the_body_raises(tmp_path):
    with pytest.raises(RuntimeError, match="boom"), StagingArea(tmp_path / "keys", uuid4()) as area:
        area.write("ssh_key", b"x")
        path = area.path
        raise RuntimeError("boom")
    assert not path.exists()


def test_writing_after_exit_is_refused(tmp_path):
    with StagingArea(tmp_path / "keys", uuid4()) as area:
        pass
    with pytest.raises(StagingError):
        area.write("late", b"x")
