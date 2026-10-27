"""Read-only Apache configuration collector for cert-dashboard discovery.

Runs ``<apachectl> -S`` and ``<apachectl> -V``, then reads the union of the files ``-S`` names and the
recursive ``Include``/``IncludeOptional`` tree of the main configuration (continuing from every ``-S`` file
the main tree did not reach, so includes inside vhost files are followed too), and prints one JSON document.
Standard library only; it never creates, changes or removes a file.
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys

MAX_FILES = 500
MAX_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 16


class DumpTooLarge(Exception):
    """The configuration exceeds the file-count or byte limit; it is never truncated silently."""


S_UNAVAILABLE = "apachectl -S unavailable; vhosts derived from the configuration files"

_S_FILE = re.compile(r"\((.+):\d+\)\s*$")
_S_ROOT = re.compile(r'^ServerRoot:\s*"(.*)"\s*$', re.MULTILINE)
_V_VALUE = re.compile(r'^\s*-D\s+(HTTPD_ROOT|SERVER_CONFIG_FILE)="([^"]*)"\s*$')
_DIRECTIVE = re.compile(r"^\s*(include|includeoptional|serverroot)\s+(\S.*?)\s*$", re.IGNORECASE)
_MAGIC = re.compile(r"[*?\[]")


def parse_v(output: "str") -> "tuple[str, str]":
    values = {}
    for line in output.splitlines():
        match = _V_VALUE.match(line)
        if match:
            values[match.group(1)] = match.group(2)
    return values.get("HTTPD_ROOT", ""), values.get("SERVER_CONFIG_FILE", "")


def files_from_s(output: "str") -> "list[str]":
    files = []
    for line in output.splitlines():
        match = _S_FILE.search(line)
        if match and match.group(1) not in files:
            files.append(match.group(1))
    return files


def _logical_lines(text):
    """Physical lines with backslash continuations joined."""
    joined, pending = [], ""
    for line in text.splitlines():
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        joined.append(pending + line)
        pending = ""
    if pending:
        joined.append(pending)
    return joined


def _argument(rest):
    if rest[0] in "\"'":
        end = rest.find(rest[0], 1)
        return rest[1:] if end < 0 else rest[1:end]
    return rest.split()[0]


def _directives(text):
    """``(name, argument)`` of every Include / IncludeOptional / ServerRoot line, comments excluded."""
    found = []
    for line in _logical_lines(text):
        match = _DIRECTIVE.match(line)
        if match:
            found.append((match.group(1).lower(), _argument(match.group(2))))
    return found


def _files_below(directory):
    found = []
    for current, _dirs, names in os.walk(directory):
        found.extend(os.path.join(current, name) for name in names)
    return sorted(found)


def _expand(pattern):
    """Files an Include target stands for: wildcard matches sorted, a directory meaning every file below it."""
    matches = sorted(glob.glob(pattern)) if _MAGIC.search(pattern) else [pattern] * os.path.exists(pattern)
    files = []
    for match in matches:
        files.extend(_files_below(match) if os.path.isdir(match) else [match])
    return matches, files


def _walk(roots, server_root):
    """Visit ``roots`` in order, following includes depth-first with an explicit stack.

    Returns ``(order, contents, via_include, warnings)``; every file is read once, by real path.
    Work items are ``(kind, value, flag, origin, depth)``; includes are expanded in place, so a later
    ``ServerRoot`` only affects the includes that follow it. Raises ``DumpTooLarge`` past the limits.
    """
    order, contents, via_include, warnings, seen = [], {}, set(), [], set()
    base, total = server_root, 0
    stack = [("file", root, False, "", 0) for root in reversed(roots)]
    while stack:
        kind, value, flag, origin, depth = stack.pop()
        if kind == "serverroot":
            base = os.path.normpath(os.path.join(base, value))
        elif kind == "include":
            name = "IncludeOptional" if flag else "Include"
            if "${" in value:
                warnings.append(f"{name} path has an unresolved variable: {value} (in {origin})")
                continue
            matches, files = _expand(os.path.normpath(os.path.join(base, value)))
            if not matches and not flag:
                warnings.append(f"{name} target not found: {value} (in {origin})")
            stack.extend(("file", path, True, origin, depth + 1) for path in reversed(files))
        else:
            real = os.path.realpath(value)
            if real in seen or not os.path.isfile(value):
                continue
            seen.add(real)
            if depth > MAX_DEPTH:
                warnings.append(
                    f"include depth {depth} exceeds {MAX_DEPTH}; not reading {value} (from {origin})"
                )
                continue
            if len(order) >= MAX_FILES:
                raise DumpTooLarge(f"more than {MAX_FILES} files")
            try:
                with open(value, "rb") as handle:
                    data = handle.read(MAX_BYTES - total + 1)
            except OSError as error:
                warnings.append(f"cannot read {value}: {error.strerror}")
                continue
            total += len(data)
            if total > MAX_BYTES:
                raise DumpTooLarge(f"more than {MAX_BYTES} bytes")
            text = data.decode("utf-8", "replace")
            order.append(value)
            contents[value] = text
            if flag:
                via_include.add(value)
            for name, argument in reversed(_directives(text)):
                if name == "serverroot":
                    stack.append(("serverroot", argument, False, value, depth))
                else:
                    stack.append(("include", argument, name == "includeoptional", value, depth))
    return order, contents, via_include, warnings


def walk_includes(main_config: "str", server_root: "str") -> "tuple[list[str], list[str]]":
    order, _contents, _via, warnings = _walk([main_config], server_root)
    return order, warnings


def _run(ctl, flag):
    try:
        done = subprocess.run(
            [ctl, flag], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=25, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return done.returncode, done.stdout.decode("utf-8", "replace")


def collect(ctl: "str") -> "dict[str, object]":
    warnings = []
    _v_rc, v_output = _run(ctl, "-V")
    s_rc, s_output = _run(ctl, "-S")
    server_root, config_name = parse_v(v_output)
    if not server_root:
        root_line = _S_ROOT.search(s_output)
        server_root = root_line.group(1) if root_line else ""
    config_file = os.path.join(server_root, config_name) if config_name else ""
    if not config_name:
        warnings.append("apachectl -V did not report SERVER_CONFIG_FILE; main configuration not read")
    s_files = [os.path.join(server_root, path) for path in files_from_s(s_output)] if s_rc == 0 else []
    if not s_files:
        warnings.append(S_UNAVAILABLE)
    roots = ([config_file] if config_file else []) + s_files
    order, contents, via_include, walk_warnings = _walk(roots, server_root)
    config = "".join(f"# configuration file {path}:\n{contents[path]}\n" for path in order)
    return {
        "s_rc": s_rc,
        "s_output": s_output,
        "server_root": server_root,
        "config_file": config_file,
        "files_from_s": s_files,
        "files_from_includes": [path for path in order if path in via_include],
        "warnings": warnings + walk_warnings,
        "config": config,
    }


def main(argv=None) -> "int":
    parser = argparse.ArgumentParser(description="Read-only Apache configuration collector")
    parser.add_argument("--ctl", required=True, help="path of apachectl / apache2ctl")
    args = parser.parse_args(argv)
    try:
        document = collect(args.ctl)
    except DumpTooLarge:
        print(json.dumps({"error": "dump_too_large"}))
        return 3
    print(json.dumps(document))
    return 0


if __name__ == "__main__":
    sys.exit(main())
