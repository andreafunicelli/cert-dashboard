"""Collector tests: every case builds an Apache tree under ``tmp_path`` and a fake ``apachectl``."""

import ast
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "app" / "ansible" / "playbooks" / "files" / "apache_dump.py"
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "dumps"

WWW_VHOST = """\
<VirtualHost *:443>
    ServerName www.example.com
    SSLEngine on
    SSLCertificateFile ssl/www.crt
    SSLCertificateKeyFile ssl/www.key
</VirtualHost>
"""


def make_apache_tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text.replace("{root}", str(root)))
    return root


def fake_apachectl(
    tmp_path: Path,
    root: Path,
    s_files: list[Path],
    *,
    s_rc: int = 0,
    config_file: str = "apache2.conf",
    s_extra: str = "",
    v_ok: bool = True,
) -> str:
    """A shell script that prints canned ``-V`` / ``-S`` output referencing the tree."""
    lines = ["VirtualHost configuration:"]
    for n, path in enumerate(s_files, start=1):
        lines.append(f"*:443                  vhost{n}.example.com ({path}:{n})")
    lines += [f'ServerRoot: "{root}"', 'Main DocumentRoot: "/var/www/html"', s_extra]
    ctl_dir = tmp_path / "ctl"
    ctl_dir.mkdir(exist_ok=True)
    (ctl_dir / "s.out").write_text("\n".join(lines) + "\n")
    v_out = (
        "Server version: Apache/2.4.57 (Debian)\n"
        f' -D HTTPD_ROOT="{root}"\n'
        f' -D SERVER_CONFIG_FILE="{config_file}"\n'
    )
    (ctl_dir / "v.out").write_text(v_out if v_ok else "")
    ctl = ctl_dir / "apachectl"
    ctl.write_text(
        "#!/bin/sh\n"
        f'case "$1" in\n  -V) cat "{ctl_dir}/v.out"; exit {0 if v_ok else 1};;\n'
        f'  -S) cat "{ctl_dir}/s.out"; exit {s_rc};;\nesac\nexit 64\n'
    )
    ctl.chmod(0o755)
    return str(ctl)


def tree_snapshot(base: Path) -> dict[str, tuple[int, int, int, int]]:
    snapshot = {}
    for directory, dirs, names in os.walk(base):
        for name in dirs + names:
            path = Path(directory) / name
            st = path.lstat()
            snapshot[str(path)] = (st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode)
    st = base.lstat()
    snapshot[str(base)] = (st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode)
    return snapshot


def make_read_only(base: Path) -> None:
    for directory, dirs, names in os.walk(base):
        for name in dirs + names:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(path.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def run_script(ctl: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--ctl", ctl], capture_output=True, text=True, timeout=60, check=False
    )


def run_collector(ctl: str) -> dict:
    done = run_script(ctl)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


GLOBAL_TLS_FILES = {
    "apache2.conf": "ServerRoot {root}\nIncludeOptional conf-enabled/*.conf\nIncludeOptional sites-enabled/*.conf\n",
    "conf-enabled/zz-global-tls.conf": "SSLCertificateFile ssl/global.crt\nSSLCertificateKeyFile ssl/global.key\n",
    "sites-enabled/www.conf": WWW_VHOST,
    "ports.conf": "Listen 80\nListen 443 https\n",
}


def global_tls_tree(tmp_path: Path) -> tuple[Path, str]:
    root = make_apache_tree(tmp_path / "etc/apache2", GLOBAL_TLS_FILES)
    ctl = fake_apachectl(tmp_path, root, [root / "sites-enabled/www.conf"])  # -S names only the vhost file
    return root, ctl


def test_globally_included_tls_config_missing_from_S_is_collected_read_only(tmp_path):
    root, ctl = global_tls_tree(tmp_path)
    make_read_only(tmp_path)
    before = tree_snapshot(tmp_path)  # taken after chmod a-w, which is the test's own change
    document = run_collector(ctl)
    assert document["files_from_s"] == [str(root / "sites-enabled/www.conf")]
    assert str(root / "conf-enabled/zz-global-tls.conf") in document["files_from_includes"]
    assert f"# configuration file {root}/conf-enabled/zz-global-tls.conf:" in document["config"]
    assert "SSLCertificateFile ssl/global.crt" in document["config"]
    assert (document["s_rc"], document["server_root"], document["config_file"]) == (
        0,
        str(root),
        str(root / "apache2.conf"),
    )
    assert set(document) == {
        "s_rc",
        "s_output",
        "server_root",
        "config_file",
        "files_from_s",
        "files_from_includes",
        "warnings",
        "config",
    }
    assert tree_snapshot(tmp_path) == before  # nothing created, changed or removed


FALLBACK_WARNING = "apachectl -S unavailable; vhosts derived from the configuration files"


def test_failed_S_falls_back_to_the_walk_only(tmp_path):
    root = make_apache_tree(
        tmp_path / "etc/apache2",
        {"apache2.conf": "IncludeOptional sites-enabled/*.conf\n", "sites-enabled/www.conf": WWW_VHOST},
    )
    ctl = fake_apachectl(tmp_path, root, [root / "sites-enabled/www.conf"], s_rc=1)
    document = run_collector(ctl)
    assert document["s_rc"] == 1 and document["files_from_s"] == []
    assert FALLBACK_WARNING in document["warnings"]
    assert document["files_from_includes"] == [str(root / "sites-enabled/www.conf")]
    assert "<VirtualHost *:443>" in document["config"]


def test_S_without_any_file_also_falls_back_to_the_walk(tmp_path):
    root = make_apache_tree(
        tmp_path / "etc/apache2",
        {"apache2.conf": "Include sites/www.conf\n", "sites/www.conf": WWW_VHOST},
    )
    document = run_collector(fake_apachectl(tmp_path, root, []))
    assert (document["s_rc"], document["files_from_s"]) == (0, [])
    assert FALLBACK_WARNING in document["warnings"]
    assert "<VirtualHost *:443>" in document["config"]


def test_successful_S_with_files_has_no_fallback_warning(tmp_path):
    _root, ctl = global_tls_tree(tmp_path)
    assert FALLBACK_WARNING not in run_collector(ctl)["warnings"]


def test_include_semantics(tmp_path):
    root = make_apache_tree(
        tmp_path / "etc/apache2",
        {
            "apache2.conf": (
                "# Include commented-out.conf\n"
                'include "dir with space/a b.conf"\n'
                "INCLUDEOPTIONAL conf.d\n"
                "IncludeOptional missing-optional/*.conf\n"
                "Include missing-required.conf\n"
                "Include ${APACHE_LOG_DIR}/x.conf\n"
                "ServerRoot {root}/alt\n"
                "Include rel.conf\n"
                "ServerRoot sub\n"
                "Include nested.conf\n"
            ),
            "dir with space/a b.conf": "# quoted\n",
            "conf.d/b.conf": "# b\n",
            "conf.d/a.conf": "# a\n",
            "conf.d/sub/c.conf": "# c\n",
            "conf.d/z.txt": "# z\n",
            "rel.conf": "# resolved against HTTPD_ROOT: must not be read\n",
            "alt/rel.conf": "# resolved against the ServerRoot directive\n",
            "alt/sub/nested.conf": "# a relative ServerRoot extends the previous one\n",
        },
    )
    document = run_collector(fake_apachectl(tmp_path, root, []))
    assert document["files_from_includes"] == [
        str(root / "dir with space/a b.conf"),
        str(root / "conf.d/a.conf"),
        str(root / "conf.d/b.conf"),
        str(root / "conf.d/sub/c.conf"),
        str(root / "conf.d/z.txt"),
        str(root / "alt/rel.conf"),
        str(root / "alt/sub/nested.conf"),
    ]
    warnings = [w for w in document["warnings"] if w != FALLBACK_WARNING]
    assert len(warnings) == 2
    assert "missing-required.conf" in warnings[0] and str(root / "apache2.conf") in warnings[0]
    assert "${APACHE_LOG_DIR}/x.conf" in warnings[1]
    assert "commented-out" not in "".join(document["warnings"])


def test_relative_include_before_any_serverroot_resolves_against_httpd_root(tmp_path):
    root = make_apache_tree(
        tmp_path / "etc/apache2", {"apache2.conf": "Include one.conf\n", "one.conf": "# one\n"}
    )
    document = run_collector(fake_apachectl(tmp_path, root, []))
    assert document["files_from_includes"] == [str(root / "one.conf")]


def test_without_V_the_server_root_comes_from_S_and_the_S_files_are_still_walked(tmp_path):
    root = make_apache_tree(
        tmp_path / "etc/apache2",
        {"sites/www.conf": "Include extra.conf\n" + WWW_VHOST, "extra.conf": "# extra\n"},
    )
    document = run_collector(fake_apachectl(tmp_path, root, [root / "sites/www.conf"], v_ok=False))
    assert (document["server_root"], document["config_file"]) == (str(root), "")
    assert document["files_from_includes"] == [str(root / "extra.conf")]
    assert any("apachectl -V" in warning for warning in document["warnings"])
    assert f"# configuration file {root}/sites/www.conf:" in document["config"]


def markers(document: dict) -> list[str]:
    return [
        line[len("# configuration file ") : -1]
        for line in document["config"].splitlines()
        if line.startswith("# configuration file ") and line.endswith(":")
    ]


def test_includes_inside_a_virtualhost_of_an_S_only_file_are_followed(tmp_path):
    root = make_apache_tree(
        tmp_path / "etc/apache2",
        {
            "apache2.conf": "ServerRoot {root}\nListen 443 https\n",  # does not reach the sites file
            "sites/www.conf": "<VirtualHost *:443>\n    ServerName www.example.com\n    SSLEngine on\n"
            "    SSLCertificateFile ssl/www.crt\n    Include tls/www-key.conf\n"
            "    IncludeOptional tls.d/*.conf\n</VirtualHost>\n",
            "tls/www-key.conf": "SSLCertificateKeyFile ssl/www.key\n",
            "tls.d/10-chain.conf": "SSLCertificateChainFile ssl/chain.pem\n",
            "tls.d/20-ca.conf": "SSLCACertificateFile ssl/ca.pem\n",
        },
    )
    document = run_collector(fake_apachectl(tmp_path, root, [root / "sites/www.conf"]))
    assert document["files_from_s"] == [str(root / "sites/www.conf")]
    assert document["files_from_includes"] == [
        str(root / "tls/www-key.conf"),
        str(root / "tls.d/10-chain.conf"),
        str(root / "tls.d/20-ca.conf"),
    ]
    assert markers(document) == [
        str(root / "apache2.conf"),
        str(root / "sites/www.conf"),
        str(root / "tls/www-key.conf"),
        str(root / "tls.d/10-chain.conf"),
        str(root / "tls.d/20-ca.conf"),
    ]
    assert "SSLCertificateKeyFile ssl/www.key" in document["config"]
    assert FALLBACK_WARNING not in document["warnings"]


def test_each_file_once_in_walk_order_then_remaining_S_files(tmp_path):
    root = make_apache_tree(
        tmp_path / "etc/apache2",
        {
            "apache2.conf": "Include a.conf\nInclude c.conf\nInclude a.conf\n",
            "a.conf": "Include b.conf\n",
            "b.conf": "# b\n",
            "c.conf": "# c\n",
            "x.conf": "Include y.conf\n",  # listed by -S, never reached by the main configuration
            "y.conf": "# y\n",
        },
    )
    s_files = [root / "c.conf", root / "x.conf", root / "a.conf"]
    document = run_collector(fake_apachectl(tmp_path, root, s_files))
    assert document["files_from_s"] == [str(path) for path in s_files]
    assert document["files_from_includes"] == [
        str(root / name) for name in ("a.conf", "b.conf", "c.conf", "y.conf")
    ]
    assert markers(document) == [
        str(root / name) for name in ("apache2.conf", "a.conf", "b.conf", "c.conf", "x.conf", "y.conf")
    ]


def non_fallback(document: dict) -> list[str]:
    return [warning for warning in document["warnings"] if warning != FALLBACK_WARNING]


def test_cycles_and_limits(tmp_path):
    # a <-> b include cycle (and a symlink to a): each file is visited once, by real path
    cycle = make_apache_tree(
        tmp_path / "cycle/etc/apache2",
        {
            "apache2.conf": "Include a.conf\nInclude link.conf\n",
            "a.conf": "Include b.conf\n",
            "b.conf": "Include a.conf\nInclude apache2.conf\n",
        },
    )
    (cycle / "link.conf").symlink_to(cycle / "a.conf")
    document = run_collector(fake_apachectl(tmp_path / "cycle", cycle, []))
    assert document["files_from_includes"] == [str(cycle / "a.conf"), str(cycle / "b.conf")]
    assert markers(document) == [str(cycle / name) for name in ("apache2.conf", "a.conf", "b.conf")]
    assert non_fallback(document) == []

    # MAX_DEPTH = 16: the file at depth 17 is not read and the cut is reported
    chain = {"apache2.conf": "Include d1.conf\n"}
    chain.update({f"d{n}.conf": f"Include d{n + 1}.conf\n" for n in range(1, 17)})
    chain["d17.conf"] = "# too deep\n"
    deep = make_apache_tree(tmp_path / "deep/etc/apache2", chain)
    document = run_collector(fake_apachectl(tmp_path / "deep", deep, []))
    assert document["files_from_includes"] == [str(deep / f"d{n}.conf") for n in range(1, 17)]
    [warning] = non_fallback(document)
    assert "depth" in warning and str(deep / "d17.conf") in warning


def test_S_file_too_deep_in_the_include_chain_is_still_collected_as_a_root(tmp_path):
    chain = {"apache2.conf": "Include d1.conf\n"}
    chain.update({f"d{n}.conf": f"Include d{n + 1}.conf\n" for n in range(1, 17)})
    chain["d17.conf"] = "SSLCertificateFile ssl/deep.crt\n"
    deep = make_apache_tree(tmp_path / "deep/etc/apache2", chain)
    ctl = fake_apachectl(tmp_path / "deep", deep, [deep / "d17.conf"])
    document = run_collector(ctl)
    d17 = str(deep / "d17.conf")
    assert f"# configuration file {d17}:\nSSLCertificateFile ssl/deep.crt\n" in document["config"]
    assert document["files_from_s"] == [d17]
    assert document["files_from_includes"] == [str(deep / f"d{n}.conf") for n in range(1, 17)]
    [warning] = non_fallback(document)
    assert "depth 17" in warning and d17 in warning
    assert markers(document).count(d17) == 1


def too_many_files_tree(base: Path, extra: int) -> tuple[Path, str]:
    files = {"apache2.conf": "IncludeOptional conf.d/*.conf\n"}
    files.update({f"conf.d/{n:04d}.conf": "# f\n" for n in range(499 + extra)})
    root = make_apache_tree(base / "etc/apache2", files)
    return root, fake_apachectl(base, root, [])


def test_exactly_max_files_is_accepted(tmp_path):
    _root, ctl = too_many_files_tree(tmp_path, 0)
    document = run_collector(ctl)
    assert len(markers(document)) == 500


def test_more_than_max_files_fails_with_dump_too_large(tmp_path):
    _root, ctl = too_many_files_tree(tmp_path, 1)
    done = run_script(ctl)
    assert done.returncode == 3
    assert json.loads(done.stdout) == {"error": "dump_too_large"}


def test_more_than_max_bytes_fails_with_dump_too_large(tmp_path):
    big = "#" * (16 * 1024 * 1024 - len("Include big.conf\n") + 1)
    root = make_apache_tree(tmp_path / "etc/apache2", {"apache2.conf": "Include big.conf\n", "big.conf": big})
    done = run_script(fake_apachectl(tmp_path, root, []))
    assert done.returncode == 3
    assert json.loads(done.stdout) == {"error": "dump_too_large"}


def test_exactly_max_bytes_is_accepted(tmp_path):
    big = "#" * (16 * 1024 * 1024 - len("Include big.conf\n"))
    root = make_apache_tree(tmp_path / "etc/apache2", {"apache2.conf": "Include big.conf\n", "big.conf": big})
    document = run_collector(fake_apachectl(tmp_path, root, []))
    assert document["files_from_includes"] == [str(root / "big.conf")]


ALLOWED_IMPORTS = {"argparse", "glob", "json", "os", "re", "subprocess", "sys"}
MUTATING_OS = {
    "remove", "unlink", "rename", "replace", "mkdir", "makedirs", "rmdir", "removedirs", "chmod", "chown",
    "lchown", "symlink", "link", "truncate", "utime", "open", "write", "system", "popen", "mkfifo", "mknod",
}  # fmt: skip


def read_only_violations(source: str) -> list[str]:
    """Static proof that the collector can only read: the checks the plan's AST test lists, plus recursion."""
    tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [f"import {a.name}" for a in node.names if a.name not in ALLOWED_IMPORTS]
        elif isinstance(node, ast.ImportFrom) and node.module not in ALLOWED_IMPORTS:
            found.append(f"from {node.module} import ...")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "os" and node.attr in MUTATING_OS:
                found.append(f"os.{node.attr}")
            if node.value.id == "subprocess" and node.attr not in {"run", "PIPE", "STDOUT", "TimeoutExpired"}:
                found.append(f"subprocess.{node.attr}")
            if node.value.id == "sys" and node.attr in {"stdout", "stderr"}:
                found.append(f"sys.{node.attr}")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "open":
                mode = node.args[1] if len(node.args) > 1 else None
                if (
                    not (isinstance(mode, ast.Constant) and mode.value == "rb")
                    or len(node.args) != 2
                    or node.keywords
                ):
                    found.append("open() not called with a literal 'rb'")
            if (
                isinstance(func, ast.Name)
                and func.id == "print"
                and any(keyword.arg == "file" for keyword in node.keywords)
            ):
                found.append("print(file=...)")
            if isinstance(func, ast.Attribute) and func.attr in {
                "write",
                "writelines",
                "write_text",
                "write_bytes",
            }:
                found.append(f".{func.attr}()")
            if isinstance(func, ast.Name) and func.id in {"exec", "eval", "__import__", "compile"}:
                found.append(f"{func.id}()")
        elif isinstance(node, ast.FunctionDef):
            for call in ast.walk(node):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == node.name
                ):
                    found.append(f"{node.name}() is recursive")
    found += subprocess_violations(tree)
    return found


def subprocess_violations(tree: ast.AST) -> list[str]:
    """``subprocess.run`` appears once, in ``_run(ctl, flag)``, with ``[ctl, flag]``, timeout=25, stderr=STDOUT."""
    found = []
    runs = [
        (fn, call)
        for fn in ast.walk(tree)
        if isinstance(fn, ast.FunctionDef)
        for call in ast.walk(fn)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "run"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "subprocess"
    ]
    if len(runs) != 1 or runs[0][0].name != "_run":
        return ["subprocess.run outside _run or more than once"]
    (_fn, call), keywords = runs[0], {kw.arg: kw.value for kw in runs[0][1].keywords}
    argv = call.args[0] if call.args else None
    if not (
        isinstance(argv, ast.List)
        and [e.id for e in argv.elts if isinstance(e, ast.Name)] == ["ctl", "flag"]
        and len(argv.elts) == 2
        and len(call.args) == 1
    ):
        found.append("subprocess argv is not exactly [ctl, flag]")
    if not (isinstance(keywords.get("timeout"), ast.Constant) and keywords["timeout"].value == 25):
        found.append("subprocess timeout is not 25")
    if not (isinstance(keywords.get("stderr"), ast.Attribute) and keywords["stderr"].attr == "STDOUT"):
        found.append("subprocess stderr is not STDOUT")
    if set(keywords) - {"stdout", "stderr", "timeout", "check"}:
        found.append("subprocess has unexpected keywords (shell, env, cwd, ...)")
    for other in ast.walk(tree):
        if isinstance(other, ast.Call) and isinstance(other.func, ast.Name) and other.func.id == "_run":
            ctl, flag = other.args
            if not (isinstance(ctl, ast.Name) and ctl.id == "ctl" and isinstance(flag, ast.Constant)):
                found.append("_run called with something other than ctl and a literal flag")
            elif flag.value not in {"-S", "-V"}:
                found.append(f"_run called with {flag.value}")
    return found


def test_collector_source_is_read_only():
    assert read_only_violations(SCRIPT.read_text()) == []


def test_the_read_only_checker_flags_each_kind_of_violation():
    bad = (
        "import os, shutil, subprocess, sys\n"
        "from app.db import x\n"
        "def f(ctl):\n"
        "    open('x', 'w')\n"
        "    open('x')\n"
        "    os.remove('x')\n"
        "    os.open('x', 0)\n"
        "    sys.stdout.write('x')\n"
        "    subprocess.Popen(['rm'])\n"
        "    f(ctl)\n"
        "def _run(ctl, flag):\n"
        "    subprocess.run(['rm', flag], shell=True, timeout=5)\n"
        "_run(ctl, '-X')\n"
    )
    violations = read_only_violations(bad)
    for expected in (
        "import shutil",
        "from app.db import ...",
        "open() not called with a literal 'rb'",
        "os.remove",
        "os.open",
        "sys.stdout",
        ".write()",
        "subprocess.Popen",
        "f() is recursive",
        "subprocess argv is not exactly [ctl, flag]",
        "subprocess timeout is not 25",
        "subprocess stderr is not STDOUT",
        "subprocess has unexpected keywords (shell, env, cwd, ...)",
        "_run called with -X",
    ):
        assert expected in violations, expected
    assert read_only_violations("def g():\n    subprocess.run(['x'])\n") == [
        "subprocess.run outside _run or more than once"
    ]


def vhost(*body: str) -> str:
    lines = [
        "<VirtualHost *:443>",
        "    ServerName www.example.com",
        "    SSLEngine on",
        *body,
        "</VirtualHost>",
    ]
    return "\n".join(lines) + "\n"


MAIN = "ServerRoot {root}\nIncludeOptional sites-enabled/*.conf\n"
# D3 cases a-d: TLS inline in the vhost, in a relative include, in a glob include, split inline/included.
RECORDED = {
    "apache_vhost_inline.json": {
        "apache2.conf": MAIN,
        "sites-enabled/www.conf": vhost(
            "    SSLCertificateFile ssl/www.crt", "    SSLCertificateKeyFile ssl/www.key"
        ),
    },
    "apache_include_relative.json": {
        "apache2.conf": "ServerRoot {root}\n",  # the sites file is reached through -S only
        "sites-enabled/www.conf": vhost("    Include tls/www.conf"),
        "tls/www.conf": "SSLCertificateFile ssl/www.crt\nSSLCertificateKeyFile ssl/www.key\n",
    },
    "apache_include_glob.json": {
        "apache2.conf": "ServerRoot {root}\n",
        "sites-enabled/www.conf": vhost("    IncludeOptional tls.d/*.conf"),
        "tls.d/10-cert.conf": "SSLCertificateFile ssl/www.crt\n",
        "tls.d/20-key.conf": "SSLCertificateKeyFile ssl/www.key\n",
    },
    "apache_include_split.json": {
        "apache2.conf": "ServerRoot {root}\n",
        "sites-enabled/www.conf": vhost("    SSLCertificateFile ssl/www.crt", "    Include tls/key.conf"),
        "tls/key.conf": "SSLCertificateKeyFile ssl/www.key\n",
    },
    "apache_global_include.json": GLOBAL_TLS_FILES,  # the first collector test's fixture tree
}


def test_committed_collector_documents_match_a_fresh_recording(tmp_path):
    """The parser's fixtures are real collector output, paths normalized to ``/etc/apache2``.

    Run with ``UPDATE_APACHE_FIXTURES=1`` to re-record them after an intended change.
    """
    for name, files in RECORDED.items():
        base = tmp_path / name
        root = make_apache_tree(base / "etc/apache2", files)
        document = run_collector(fake_apachectl(base, root, [root / "sites-enabled/www.conf"]))
        recorded = json.loads(json.dumps(document).replace(str(root), "/etc/apache2"))
        if os.environ.get("UPDATE_APACHE_FIXTURES"):
            (FIXTURES / name).write_text(json.dumps(recorded, indent=2) + "\n")
        assert json.loads((FIXTURES / name).read_text()) == recorded, name
        assert str(tmp_path) not in (FIXTURES / name).read_text()


def test_continued_include_line_and_unreadable_file_warning(tmp_path):
    root = make_apache_tree(
        tmp_path / "etc/apache2",
        {
            "apache2.conf": 'Include \\\n    "cont.conf"\nInclude locked.conf\n',
            "cont.conf": "# cont\n",
            "locked.conf": "# x\n",
        },
    )
    (root / "locked.conf").chmod(0)
    document = run_collector(fake_apachectl(tmp_path, root, []))
    assert document["files_from_includes"] == [str(root / "cont.conf")] + (
        [str(root / "locked.conf")] if os.access(root / "locked.conf", os.R_OK) else []  # running as root
    )
    if not os.access(root / "locked.conf", os.R_OK):
        assert any(f"cannot read {root}/locked.conf" in warning for warning in document["warnings"])


def load_collector():
    spec = importlib.util.spec_from_file_location("apache_dump_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_parse_v_reads_httpd_root_and_server_config_file():
    module = load_collector()
    output = (
        "Server version: Apache/2.4.57 (Debian)\n"
        ' -D HTTPD_ROOT="/etc/apache2"\n'
        ' -D SUEXEC_BIN="/usr/lib/apache2/suexec"\n'
        ' -D SERVER_CONFIG_FILE="apache2.conf"\n'
    )
    assert module.parse_v(output) == ("/etc/apache2", "apache2.conf")
    assert module.parse_v("") == ("", "")


def test_files_from_s_takes_every_file_line_pair_once_in_order():
    module = load_collector()
    output = (
        "VirtualHost configuration:\n"
        "*:443                  is a NameVirtualHost\n"
        "         default server a.example.com (/etc/httpd/conf.d/ssl.conf:56)\n"
        "         port 443 namevhost a.example.com (/etc/httpd/conf.d/ssl.conf:56)\n"
        "                 alias www.a.example.com\n"
        "         port 443 namevhost b.example.com (/etc/httpd/conf.d/my site:b.conf:3)\n"
        'ServerRoot: "/etc/httpd"\n'
    )
    assert module.files_from_s(output) == ["/etc/httpd/conf.d/ssl.conf", "/etc/httpd/conf.d/my site:b.conf"]


def test_main_prints_the_document_in_process_and_exits_zero_when_S_fails(tmp_path, capsys):
    root = make_apache_tree(tmp_path / "etc/apache2", {"apache2.conf": "# empty\n"})
    module = load_collector()
    assert module.main(["--ctl", fake_apachectl(tmp_path, root, [], s_rc=1)]) == 0
    document = json.loads(capsys.readouterr().out)
    assert (document["s_rc"], document["files_from_s"]) == (1, [])
    assert module.walk_includes(str(root / "apache2.conf"), str(root)) == ([str(root / "apache2.conf")], [])
