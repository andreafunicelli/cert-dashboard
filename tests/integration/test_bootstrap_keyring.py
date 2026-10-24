import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("docker") is None, reason="Host Docker CLI required")
@pytest.mark.parametrize("read_only", [False, True])
def test_documented_bootstrap_uses_runtime_uid_and_only_prints_digest(read_only):
    if subprocess.run(["sudo", "-n", "true"], check=False, capture_output=True).returncode != 0:
        pytest.skip("Passwordless sudo required for the bootstrap ownership check")
    if (
        subprocess.run(
            ["docker", "image", "inspect", "cert-dashboard:local"], check=False, capture_output=True
        ).returncode
        != 0
    ):
        pytest.skip("cert-dashboard:local image required; build it first")

    def run(*args):
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30)

    # Keep the UID-10001 directory outside pytest's UID-1000-only ancestor dirs.
    directory = Path(tempfile.mkdtemp(prefix="certdash-bootstrap-"))
    generated = directory / "master_key.new"
    installed = directory / "installed"
    try:
        run("sudo", "-n", "install", "-d", "-m", "0700", "-o", "10001", "-g", "10001", str(directory))
        run("docker", "tag", "cert-dashboard:local", "cert-dashboard")
        flags = ["--read-only"] if read_only else []
        result = run(
            "docker",
            "run",
            "--rm",
            *flags,
            "-v",
            f"{directory}:/out",
            "cert-dashboard",
            "python",
            "-m",
            "app.cli",
            "generate-master-key",
            "--version",
            "1",
            "--output",
            "/out/master_key.new",
        )
        digest = run("sudo", "-n", "sha256sum", str(generated)).stdout.split()[0]
        assert result.stdout == f"sha256={digest} path=/out/master_key.new\n"
        assert not result.stderr
        assert run("sudo", "-n", "stat", "-c", "%a:%u:%g", str(directory)).stdout.strip() == "700:10001:10001"
        assert run("sudo", "-n", "stat", "-c", "%a:%u:%g", str(generated)).stdout.strip() == "400:10001:10001"
        run(
            "sudo",
            "-n",
            "install",
            "-m",
            "0400",
            "-o",
            "10001",
            "-g",
            "10001",
            str(generated),
            str(installed),
        )
        assert run("sudo", "-n", "sha256sum", str(installed)).stdout.split()[0] == digest
        assert run("sudo", "-n", "stat", "-c", "%a:%u:%g", str(installed)).stdout.strip() == "400:10001:10001"
    finally:
        for path in (generated, installed):
            exists = subprocess.run(
                ["sudo", "-n", "test", "-e", str(path)], check=False, capture_output=True, timeout=10
            )
            if exists.returncode == 0:
                run("sudo", "-n", "shred", "-u", "--", str(path))
        run("sudo", "-n", "rmdir", "--", str(directory))
