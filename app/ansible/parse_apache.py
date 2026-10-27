"""Parser for the Apache collector document (§6.2, Plan 3 Contract decision 9 as amended by D1/D3).

The collector (``playbooks/files/apache_dump.py``) concatenates every configuration file after a
``# configuration file <path>:`` marker and leaves ``Include``/``IncludeOptional`` in the parent. The
parser therefore expands each include against the marker sections, in the including context, so a
directive found in an included file belongs to the enclosing ``<VirtualHost>`` and a global-level
directive becomes the server default. ``apachectl -S`` only supplies the vhost → ``(file, line)`` →
port map; the directives always come from the configuration text.

The parser never decides which certificate file is a leaf or a chain (D1): ``chain_path`` is the
``SSLCertificateChainFile`` *candidate* and extra ``SSLCertificateFile`` entries stay in ``cert_paths``.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from app.ansible.parsed import ParsedBinding, ParseError, ParseResult, WebserverType

MARKER = "# configuration file "
FALLBACK_WARNING = "apachectl -S unavailable; vhosts derived from the configuration files"
DEFAULT_PORT = 443
MAX_INCLUDE_DEPTH = 16
MAX_BLOCK_DEPTH = 32
MAX_INCLUDE_EXPANSIONS = 5000

_INCLUDES = frozenset({"include", "includeoptional"})
_GLOB_CHARS = "*?["
_DISPLAY = {
    "sslcertificatefile": "SSLCertificateFile",
    "sslcertificatekeyfile": "SSLCertificateKeyFile",
    "sslcertificatechainfile": "SSLCertificateChainFile",
}
_STATUS_LOCATION = re.compile(r"\((?P<file>[^()]+):(?P<line>\d+)\)\s*$")
_STATUS_ROOT = re.compile(r'^ServerRoot:\s*"?(?P<root>[^"]*?)"?\s*$')


@dataclass(frozen=True, slots=True)
class ApacheDump:
    """``vhosts`` = ``apachectl -S`` output (or ``""``); ``config`` = the marker-delimited files."""

    vhosts: str
    config: str
    warnings: tuple[str, ...] = ()

    @classmethod
    def from_collector(cls, document: Mapping[str, object]) -> ApacheDump:
        s_rc, s_output = document.get("s_rc"), document.get("s_output")
        config, warnings = document.get("config"), document.get("warnings")
        if (
            not isinstance(s_rc, int)
            or not isinstance(s_output, str)
            or not isinstance(config, str)
            or not isinstance(warnings, list)
            or not all(isinstance(w, str) for w in warnings)
        ):
            raise ParseError("not an Apache collector document")
        return cls(s_output if s_rc == 0 else "", config, tuple(warnings))


def parse_apache(dump: ApacheDump) -> ParseResult:
    files = _split_files(dump.config)
    if not files:
        noise = bool(dump.config.strip())
        notes = ("no configuration file markers found in the dump",) if noise else ()
        return ParseResult((), (), _unique([*dump.warnings, *notes]))
    return _Parser(dump, files).run()


# -- lexing ----------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Item:
    kind: str  # "dir", "open" or "close"
    name: str  # lower-case directive / section name
    args: list[str]
    line: int  # first physical line of the logical line
    end: int  # last physical line (the number apachectl reports for a continued line)


@dataclass(slots=True)
class _Node:
    name: str
    args: list[str]
    file: str
    line: int
    end: int
    root: str  # ServerRoot in effect where the node was read
    children: list[_Node] | None = None


def _split_files(config: str) -> dict[str, str]:
    """Attribute lines to files by the ``# configuration file <path>:`` markers (first = main config)."""
    chunks: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in config.splitlines():
        if line.startswith(MARKER) and line.rstrip().endswith(":"):
            current = chunks.setdefault(line[len(MARKER) :].rstrip()[:-1].strip(), [])
        elif current is not None:
            current.append(line)
    return {path: "\n".join(lines) for path, lines in chunks.items()}


def _words(text: str, where: str) -> list[str]:
    """Whitespace-separated words; ``"…"`` and ``'…'`` group (backslash escapes the quote)."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
        elif ch in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != ch:
                if text[j] == "\\" and j + 1 < n and text[j + 1] in "\"'\\":
                    j += 1
                buf.append(text[j])
                j += 1
            if j >= n:
                raise ParseError(f"{where}: unterminated quoted string")
            out.append("".join(buf))
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace():
                j += 1
            out.append(text[i:j])
            i = j
    return out


def _logical_lines(text: str) -> Iterator[tuple[int, int, str]]:
    """``(first line, last line, text)`` with ``\\`` continuations joined."""
    parts: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not parts:
            start = number
        if raw.endswith("\\"):
            parts.append(raw[:-1])
            continue
        parts.append(raw)
        yield start, number, "".join(parts)
        parts = []
    if parts:
        yield start, start + len(parts) - 1, "".join(parts)


def _lex(text: str, path: str) -> list[_Item]:
    items: list[_Item] = []
    for start, end, line in _logical_lines(text):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        where = f"{path}:{start}"
        if s.startswith("<"):
            if not s.endswith(">"):
                raise ParseError(f"{where}: malformed section tag")
            if s.startswith("</"):
                items.append(_Item("close", s[2:-1].strip().lower(), [], start, end))
                continue
            words = _words(s[1:-1], where)
            if not words:
                raise ParseError(f"{where}: malformed section tag")
            items.append(_Item("open", words[0].lower(), words[1:], start, end))
        else:
            words = _words(s, where)
            items.append(_Item("dir", words[0].lower(), words[1:], start, end))
    return items


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _port(address: str) -> int | None:
    """Port of ``443``, ``*:443``, ``[::]:443``, ``10.0.0.1:8443``; None when the address names none."""
    if address.startswith("["):
        rest = address.partition("]")[2]
        text = rest[1:] if rest.startswith(":") else ""
    elif ":" in address:
        text = address.rpartition(":")[2]
    else:
        text = address
    return int(text) if text.isdigit() and 0 < int(text) < 65536 else None


def _host(value: str) -> str:
    """A ``ServerName`` without scheme, path and port."""
    value = value.split("://", 1)[-1].split("/", 1)[0]
    head, _, tail = value.rpartition(":")
    return head if head and tail.isdigit() else value


# -- apachectl -S ----------------------------------------------------------------------------------


@dataclass(slots=True)
class _Entry:
    port: int | None
    name: str
    file: str
    line: int
    aliases: list[str] = field(default_factory=list)
    claimed: bool = False


def _parse_status(text: str) -> tuple[list[_Entry], str | None]:
    """Vhost entries (``port N namevhost`` / ``addr:port name`` / ``default server`` lines) and ServerRoot."""
    entries: dict[tuple[int | None, str, int], _Entry] = {}
    root: str | None = None
    address_port: int | None = None
    last: _Entry | None = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if match := _STATUS_ROOT.match(raw):
            root = match["root"]
            continue
        location = _STATUS_LOCATION.search(raw)
        if location is None:
            if stripped.startswith("alias ") and last is not None:
                last.aliases.append(stripped[6:].strip())
            elif stripped.endswith("is a NameVirtualHost"):
                address_port = _port(stripped.split()[0])
            continue
        head = raw[: location.start()].split()
        if head[:2] == ["default", "server"] and len(head) == 3:
            port, name = address_port, head[2]
        elif head[:1] == ["port"] and len(head) == 4 and head[2] == "namevhost":
            port, name = _port(head[1]), head[3]
        elif len(head) == 2:
            port, name = _port(head[0]), head[1]
        else:
            continue
        key = (port, location["file"], int(location["line"]))
        last = entries.setdefault(key, _Entry(port, name, location["file"], int(location["line"])))
    return list(entries.values()), root


# -- configuration semantics -----------------------------------------------------------------------


@dataclass(slots=True)
class _Scope:
    """TLS-relevant directives found in one ``<VirtualHost>`` or at global level."""

    certs: list[_Node] = field(default_factory=list)
    keys: list[_Node] = field(default_factory=list)
    chains: list[_Node] = field(default_factory=list)
    engine: bool | None = None
    names: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    listens: list[tuple[int | None, bool]] = field(default_factory=list)
    _seen: set[tuple[str, str, int]] = field(default_factory=set)

    def take(self, node: _Node) -> None:
        if not node.args:
            return
        name, first = node.name, node.args[0]
        if name in _DISPLAY:
            # one directive line reached through several include paths counts once
            if (key := (name, node.file, node.line)) in self._seen:
                return
            self._seen.add(key)
            {
                "sslcertificatefile": self.certs,
                "sslcertificatekeyfile": self.keys,
                "sslcertificatechainfile": self.chains,
            }[name].append(node)
        elif name == "sslengine":
            self.engine = first.lower() == "on"
        elif name == "servername":
            self.names.append(_host(first))
        elif name == "serveralias":
            self.aliases.extend(_host(a) for a in node.args)
        elif name == "listen":
            self.listens.append((_port(first), len(node.args) > 1 and node.args[1].lower() == "https"))


def _scan(nodes: list[_Node], scope: _Scope, vhosts: list[_Node] | None) -> None:
    """Feed the directives of *nodes* to *scope*, descending into every section except ``VirtualHost``."""
    stack = [iter(nodes)]
    while stack:
        for node in stack[-1]:
            if node.children is None:
                scope.take(node)
            elif node.name == "virtualhost":
                if vhosts is not None:
                    vhosts.append(node)
            else:
                stack.append(iter(node.children))
                break
        else:
            stack.pop()


def _glob_match(pattern: list[str], parts: list[str]) -> bool:
    return len(pattern) == len(parts) and all(fnmatchcase(p, g) for p, g in zip(parts, pattern, strict=True))


class _Parser:
    def __init__(self, dump: ApacheDump, files: dict[str, str]) -> None:
        self.dump = dump
        self.files = files
        self.main = next(iter(files))
        self.items = {path: _lex(text, path) for path, text in files.items()}
        self.entries, header_root = _parse_status(dump.vhosts)
        self.initial_root = self._normalize(
            header_root or self._first_server_root() or posixpath.dirname(self.main)
        )
        self.warnings: list[str] = []
        self._root = self.initial_root
        self._stack: list[str] = []
        self._reached: set[str] = set()
        self._expansions = 0
        self._matches_cache: dict[tuple[str, str], tuple[str, list[str]]] = {}

    @staticmethod
    def _normalize(root: str) -> str:
        return root.rstrip("/") or "/"

    def _first_server_root(self) -> str | None:
        for items in self.items.values():
            for item in items:
                if item.kind == "dir" and item.name == "serverroot" and item.args:
                    return item.args[0]
        return None

    # -- include expansion -----------------------------------------------------------------------

    def run(self) -> ParseResult:
        referenced = self._referenced()
        # Main configuration first, then files nothing includes, then whatever is still unreached
        # (include cycles); every root is parsed at global context.
        order = [self.main, *(p for p in self.files if p not in referenced), *self.files]
        roots: list[list[_Node]] = []
        for path in order:
            if path not in self._reached:
                self._root = self.initial_root
                top: list[_Node] = []
                self._expand(path, top, 0)
                roots.append(top)

        scope, vhosts = _Scope(), []
        for top in roots:
            _scan(top, scope, vhosts)
        self._global = scope
        by_location: dict[tuple[str, int], list[_Entry]] = {}
        for entry in self.entries:
            by_location.setdefault((entry.file, entry.line), []).append(entry)
        self._by_location = by_location

        bindings: list[ParsedBinding] = []
        seen: set[tuple[str, int]] = set()
        for node in vhosts:
            if (node.file, node.line) not in seen:
                seen.add((node.file, node.line))
                bindings.extend(self._vhost(node))
        if default := self._default():
            bindings.append(default)
        for entry in self.entries:
            if not entry.claimed:
                reason = (
                    "no matching <VirtualHost> section"
                    if entry.file in self.files
                    else "file not in the dump"
                )
                self.warnings.append(
                    f"{entry.file}:{entry.line}: vhost {entry.name} listed by apachectl -S; {reason}; skipped"
                )
        notes = [FALLBACK_WARNING] if not self.entries else []
        return ParseResult(
            tuple(bindings), tuple(self.files), _unique([*self.dump.warnings, *self.warnings, *notes])
        )

    def _referenced(self) -> set[str]:
        """Files some other file includes, resolved against the initial ServerRoot (ordering hint only)."""
        out: set[str] = set()
        for path, items in self.items.items():
            for item in items:
                if item.kind == "dir" and item.name in _INCLUDES and len(item.args) == 1:
                    out.update(m for m in self._matches(item.args[0], self.initial_root)[1] if m != path)
        return out

    def _matches(self, arg: str, root: str) -> tuple[str, list[str]]:
        """``(normalized pattern, matching dumped files in sorted order)`` for an Include argument."""
        key = (arg, root)
        if key not in self._matches_cache:
            pattern = posixpath.normpath(arg if arg.startswith("/") else posixpath.join(root, arg))
            if any(c in pattern for c in _GLOB_CHARS):
                segments = pattern.split("/")
                found = sorted(p for p in self.files if _glob_match(segments, p.split("/")))
            elif pattern in self.files:
                found = [pattern]
            else:  # a directory: every file below it, in sorted order
                found = sorted(p for p in self.files if p.startswith(pattern.rstrip("/") + "/"))
            self._matches_cache[key] = (pattern, found)
        return self._matches_cache[key]

    def _expand(self, path: str, target: list[_Node], base: int) -> None:
        """Append the top-level nodes of *path* to *target* (the including context)."""
        self._reached.add(path)
        self._stack.append(path)
        stack = [target]
        open_names: list[str] = []
        for item in self.items[path]:
            if item.kind == "dir":
                if item.name in _INCLUDES:
                    self._include(item, stack[-1], path, base + len(stack) - 1)
                    continue
                if item.name == "serverroot" and item.args:
                    self._root = self._normalize(item.args[0])
                stack[-1].append(_Node(item.name, item.args, path, item.line, item.end, self._root))
            elif item.kind == "open":
                if base + len(stack) > MAX_BLOCK_DEPTH:
                    raise ParseError(f"{path}:{item.line}: sections nested deeper than {MAX_BLOCK_DEPTH}")
                children: list[_Node] = []
                stack[-1].append(_Node(item.name, item.args, path, item.line, item.end, self._root, children))
                stack.append(children)
                open_names.append(item.name)
            else:
                if not open_names or open_names[-1] != item.name:
                    raise ParseError(f"{path}:{item.line}: unexpected </{item.name}>")
                open_names.pop()
                stack.pop()
        if open_names:
            raise ParseError(f"{path}: <{open_names[-1]}> is not closed")
        self._stack.pop()

    def _include(self, item: _Item, target: list[_Node], from_file: str, base: int) -> None:
        if len(item.args) != 1:
            return
        where = f"{from_file}:{item.line}"
        if "$" in item.args[0]:
            self.warnings.append(f"{where}: {item.name} {item.args[0]}: unresolved variable; skipped")
            return
        pattern, matches = self._matches(item.args[0], self._root)
        if not matches and item.name == "include":
            self.warnings.append(f"{where}: Include {pattern}: file not in the dump")
        for match in matches:
            if match in self._stack:
                cycle = " -> ".join([*self._stack, match])
                self.warnings.append(f"{where}: include {match} skipped: include cycle ({cycle})")
            elif len(self._stack) - 1 >= MAX_INCLUDE_DEPTH:
                self.warnings.append(
                    f"{where}: include {match} skipped: include depth exceeds {MAX_INCLUDE_DEPTH}"
                )
            else:
                self._expansions += 1
                if self._expansions > MAX_INCLUDE_EXPANSIONS:
                    raise ParseError(f"too many include expansions (more than {MAX_INCLUDE_EXPANSIONS})")
                self._expand(match, target, base)

    # -- bindings --------------------------------------------------------------------------------

    def _vhost(self, node: _Node) -> list[ParsedBinding]:
        scope = _Scope()
        _scan(node.children or [], scope, None)
        section_ports = [_port(a) for a in node.args]
        entries = self._by_location.get((node.file, node.end)) or self._by_location.get(
            (node.file, node.line)
        )
        if not entries and scope.names:
            # no (file, line) match: fall back, within the same dumped file, to the ServerName and a port
            entries = [
                e
                for e in self.entries
                if e.file == node.file
                and e.name == scope.names[0]
                and (e.port in section_ports or all(p is None for p in section_ports))
            ]
        for entry in entries or ():
            entry.claimed = True
        ports = _unique_ints(e.port for e in entries or ()) or _unique_ints(
            p or DEFAULT_PORT for p in section_ports or [None]
        )
        if scope.names:
            names = _unique([scope.names[0], *scope.aliases])
        elif entries:
            names = _unique([entries[0].name, *entries[0].aliases, *scope.aliases])
        else:
            names = _unique(scope.aliases)
        vhost_name = names[0] if names else "default"
        engine = self._global.engine if scope.engine is None else scope.engine
        if not engine:
            return []
        out: list[ParsedBinding] = []
        for port in ports:
            where = f"{node.file}: vhost {vhost_name} port {port}"
            certs = scope.certs or self._global.certs
            if not certs:
                self.warnings.append(f"{where}: SSLEngine on without SSLCertificateFile; skipped")
                continue
            binding = self._binding(
                where, vhost_name, names, port, certs, scope.keys or self._global.keys,
                scope.chains or self._global.chains,
            )  # fmt: skip
            if binding:
                out.append(binding)
        return out

    def _default(self) -> ParsedBinding | None:
        g = self._global
        if not g.certs:
            return None
        port = next((p for p, https in g.listens if https and p), DEFAULT_PORT)
        return self._binding(f"{g.certs[0].file}: default", "default", (), port, g.certs, g.keys, g.chains)

    def _binding(
        self,
        where: str,
        vhost_name: str,
        names: Iterable[str],
        port: int,
        certs: list[_Node],
        keys: list[_Node],
        chains: list[_Node],
    ) -> ParsedBinding | None:
        if len(keys) > len(certs):
            self.warnings.append(
                f"{where}: {len(keys)} SSLCertificateKeyFile but {len(certs)} SSLCertificateFile; keeping all"
            )
        chain_nodes = chains[-1:]  # only the last SSLCertificateChainFile takes effect
        for d in (*certs, *keys, *chain_nodes):
            if "$" in d.args[0] or d.args[0].startswith(("data:", "engine:", "pkcs11:")):
                self.warnings.append(
                    f"{where}: {_DISPLAY[d.name]} {d.args[0]} is not a plain file path; skipped"
                )
                return None
        return ParsedBinding(
            WebserverType.APACHE,
            vhost_name,
            tuple(names),
            port,
            certs[0].file,  # the file holding the certificate directive that produced the binding
            tuple(_path(d) for d in certs),
            tuple(_path(d) for d in keys),
            _path(chain_nodes[0]) if chain_nodes else None,
            tuple(d.file for d in certs),
        )


def _unique_ints(values: Iterable[int | None]) -> list[int]:
    return list(dict.fromkeys(v for v in values if v is not None))


def _path(node: _Node) -> str:
    value = node.args[0]
    return value if value.startswith("/") else posixpath.normpath(posixpath.join(node.root, value))
