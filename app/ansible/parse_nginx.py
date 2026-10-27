"""Parser for ``nginx -T`` dumps (§6.2, Plan 3 Contract decision 9 as amended by D1/D3).

``nginx -T`` prints every configuration file after a ``# configuration file <path>:`` marker and keeps
the ``include`` directive in the parent. The parser therefore starts from the first marker (the main
configuration) and splices the token stream of each included file at the ``include`` position, so a
directive found in an included file belongs to the block that included it. Processing is a single
tokenizer pass per file plus a block stack; no regular expression ever runs over a block.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from app.ansible.parsed import ParsedBinding, ParseError, ParseResult
from app.models.enums import WebserverType

NGINX_PREFIX = "/etc/nginx"

MARKER = "# configuration file "
MAX_INCLUDE_DEPTH = 16
MAX_BLOCK_DEPTH = 32
MAX_INCLUDE_EXPANSIONS = 5000

_WHITESPACE = " \t\r\n\f\v"
_PUNCTUATION = ";{}"
_ESCAPES = {'"': '"', "'": "'", "\\": "\\", "t": "\t", "r": "\r", "n": "\n"}
_UNSUPPORTED_BLOCKS = frozenset({"stream", "mail"})


@dataclass(slots=True)
class _Node:
    name: str
    args: list[str]
    file: str
    children: list[_Node] | None = None


@dataclass(slots=True)
class _Scope:
    """TLS-relevant directives found directly in one ``http`` or ``server`` block."""

    certs: list[_Node] = field(default_factory=list)
    keys: list[_Node] = field(default_factory=list)
    ssl_on: bool | None = None

    def take(self, d: _Node) -> bool:
        """Record *d* when it is one of the TLS directives; True if it was."""
        if not d.args:
            return False
        if d.name == "ssl_certificate":
            self.certs.append(d)
        elif d.name == "ssl_certificate_key":
            self.keys.append(d)
        elif d.name == "ssl":
            self.ssl_on = d.args[0].lower() == "on"
        else:
            return False
        return True


def parse_nginx(dump: str, prefix: str = NGINX_PREFIX) -> ParseResult:
    files = _split_files(dump)
    if not files:
        noise = bool(dump.strip())
        return ParseResult((), (), ("no configuration file markers found in the dump",) if noise else ())
    parser = _Parser(files, prefix.rstrip("/") or "/")
    return parser.run()


def _split_files(dump: str) -> dict[str, str]:
    """Attribute dump lines to files by the ``# configuration file <path>:`` markers."""
    chunks: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in dump.splitlines():
        if line.startswith(MARKER) and line.rstrip().endswith(":"):
            path = line[len(MARKER) :].rstrip()[:-1].strip()
            current = chunks.setdefault(path, [])
        elif current is not None:
            current.append(line)
    return {path: "\n".join(lines) for path, lines in chunks.items()}


def _unescape(raw: str) -> str:
    if "\\" not in raw:
        return raw
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch == "\\" and i + 1 < n and raw[i + 1] in _ESCAPES:
            out.append(_ESCAPES[raw[i + 1]])
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _tokenize(text: str, path: str) -> list[tuple[str, str]]:
    """Words (quotes removed), ``{``, ``}`` and ``;``; comments are dropped."""
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in _WHITESPACE:
            i += 1
        elif ch == "#":
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
        elif ch in _PUNCTUATION:
            tokens.append((ch, ch))
            i += 1
        elif ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise ParseError(f"{path}: unterminated quoted string")
            tokens.append(("word", _unescape(text[i + 1 : j])))
            i = j + 1
        else:
            j = i
            while j < n and text[j] not in _WHITESPACE and text[j] not in _PUNCTUATION:
                if text[j] == "\\":
                    j += 2
                elif text[j] == "$" and text[j + 1 : j + 2] == "{":
                    end = text.find("}", j)
                    j = n if end < 0 else end + 1
                else:
                    j += 1
            tokens.append(("word", _unescape(text[i : min(j, n)])))
            i = j
    return tokens


class _Parser:
    def __init__(self, files: dict[str, str], prefix: str) -> None:
        self.files = files
        self.prefix = prefix
        self.warnings: list[str] = []
        self._tokens: dict[str, list[tuple[str, str]]] = {}
        self._stack: list[str] = []
        self._reached: set[str] = set()
        self._expansions = 0
        self._segments = {path: path.split("/") for path in files}

    def run(self) -> ParseResult:
        main = next(iter(self.files))
        root: list[_Node] = []
        self._expand_file(main, root, 0)
        bindings: list[ParsedBinding] = []
        for node in root:
            if node.name == "http" and node.children is not None:
                bindings.extend(self._http(node))
            elif node.name in _UNSUPPORTED_BLOCKS:
                self.warnings.extend(
                    f"{server.file}: {node.name} server skipped (only http servers are supported)"
                    for server in node.children or ()
                    if server.name == "server"
                )
        self.warnings.extend(
            f"{path}: not reached from the main configuration; skipped"
            for path in self.files
            if path not in self._reached
        )
        return ParseResult(tuple(bindings), tuple(self.files), tuple(self.warnings))

    # -- tree building ---------------------------------------------------------------------------

    def _expand_file(self, path: str, target: list[_Node], depth: int) -> None:
        """Parse *path* and append its top-level nodes to *target* (the including context)."""
        self._reached.add(path)
        self._stack.append(path)
        tokens = self._tokens.get(path)
        if tokens is None:
            tokens = self._tokens[path] = _tokenize(self.files[path], path)
        stack = [target]
        owners: list[_Node] = []
        words: list[str] = []
        for kind, value in tokens:
            if kind == "word":
                words.append(value)
            elif kind == ";":
                if not words:
                    raise ParseError(f"{path}: unexpected ';'")
                if words[0] == "include":
                    self._include(words[1:], stack[-1], path, depth + len(stack) - 1)
                else:
                    stack[-1].append(_Node(words[0], words[1:], path))
                words = []
            elif kind == "{":
                if not words:
                    raise ParseError(f"{path}: unexpected '{{'")
                if depth + len(stack) > MAX_BLOCK_DEPTH:
                    raise ParseError(f"{path}: blocks nested deeper than {MAX_BLOCK_DEPTH}")
                node = _Node(words[0], words[1:], path, [])
                stack[-1].append(node)
                owners.append(node)
                stack.append(node.children)  # type: ignore[arg-type]
                words = []
            else:  # "}"
                if words:
                    raise ParseError(f"{path}: directive '{words[0]}' is not terminated by ';'")
                if len(stack) == 1:
                    raise ParseError(f"{path}: unexpected '}}'")
                stack.pop()
                owners.pop()
        if len(stack) > 1:
            raise ParseError(f"{path}: unexpected end of file, expecting '}}'")
        if words:
            raise ParseError(f"{path}: directive '{words[0]}' is not terminated by ';'")
        self._stack.pop()

    def _include(self, args: list[str], target: list[_Node], from_file: str, depth: int) -> None:
        if len(args) != 1:
            return
        pattern = args[0]
        if not pattern.startswith("/"):
            pattern = posixpath.join(self.prefix, pattern)
        pattern = posixpath.normpath(pattern)
        is_glob = any(c in pattern for c in "*?[")
        matches = self._glob(pattern) if is_glob else [pattern] if pattern in self.files else []
        if not matches and not is_glob:
            self.warnings.append(f"{from_file}: include {pattern}: file not in the dump")
        for match in matches:
            if match in self._stack:
                cycle = " -> ".join([*self._stack, match])
                self.warnings.append(f"{from_file}: include {match} skipped: include cycle ({cycle})")
            elif len(self._stack) - 1 >= MAX_INCLUDE_DEPTH:
                self.warnings.append(
                    f"{from_file}: include {match} skipped: include depth exceeds {MAX_INCLUDE_DEPTH}"
                )
            else:
                self._expansions += 1
                if self._expansions > MAX_INCLUDE_EXPANSIONS:
                    raise ParseError(f"too many include expansions (more than {MAX_INCLUDE_EXPANSIONS})")
                self._expand_file(match, target, depth)

    def _glob(self, pattern: str) -> list[str]:
        """Dumped files matching *pattern* segment by segment (``*`` never crosses ``/``), sorted."""
        parts = pattern.split("/")
        return sorted(
            path
            for path, segments in self._segments.items()
            if len(segments) == len(parts)
            and all(fnmatchcase(seg, pat) for seg, pat in zip(segments, parts, strict=True))
        )

    # -- semantics -------------------------------------------------------------------------------

    def _http(self, http: _Node) -> list[ParsedBinding]:
        inherited = _Scope()
        for d in http.children or ():
            inherited.take(d)
        out: list[ParsedBinding] = []
        for child in http.children or ():
            if child.name == "server" and child.children is not None:
                out.extend(self._server(child, inherited))
        return out

    def _server(self, server: _Node, inherited: _Scope) -> list[ParsedBinding]:
        scope = _Scope()
        listens: list[tuple[int, bool]] = []
        names: list[str] = []
        for d in server.children or ():
            if not scope.take(d) and d.args:
                if d.name == "server_name":
                    names.extend(d.args)
                elif d.name == "listen":
                    port = _listen_port(d.args[0])
                    if port is not None:
                        listens.append((port, "ssl" in d.args[1:]))
        legacy = inherited.ssl_on if scope.ssl_on is None else scope.ssl_on
        ports: list[int] = []
        for port, ssl in listens:
            if (ssl or legacy) and port not in ports:
                ports.append(port)
        if not ports:
            return []
        vhost_names = tuple(n for n in names if n != "")
        vhost_name = next((n for n in vhost_names if n != "_"), "default")
        # nginx inherits each array directive from the enclosing level only when the server sets none.
        cert_nodes = scope.certs or inherited.certs
        key_nodes = scope.keys or inherited.keys
        where = f"{server.file}: server {vhost_name}"
        if not cert_nodes:
            self.warnings.append(f"{where}: no ssl_certificate; skipped")
            return []
        if len(cert_nodes) != len(key_nodes):
            self.warnings.append(
                f"{where}: {len(cert_nodes)} ssl_certificate but {len(key_nodes)} ssl_certificate_key; skipped"
            )
            return []
        for d in (*cert_nodes, *key_nodes):
            if "$" in d.args[0] or d.args[0].startswith(("data:", "engine:")):
                self.warnings.append(f"{where}: {d.name} {d.args[0]} is not a plain file path; skipped")
                return []
        certs = tuple(self._path(d.args[0]) for d in cert_nodes)
        keys = tuple(self._path(d.args[0]) for d in key_nodes)
        # config_file: the file holding the certificate directive that produced the binding.
        config_file = cert_nodes[0].file
        return [
            ParsedBinding(WebserverType.NGINX, vhost_name, vhost_names, port, config_file, certs, keys, None)
            for port in ports
        ]

    def _path(self, value: str) -> str:
        return value if value.startswith("/") else posixpath.normpath(posixpath.join(self.prefix, value))


def _listen_port(address: str) -> int | None:
    """Port of a ``listen`` address (``443``, ``*:443``, ``[::]:443``, ``10.0.0.1:8443``); None for unix sockets."""
    if address.startswith("unix:"):
        return None
    if address.startswith("["):
        _, _, rest = address.partition("]")
        port_text = rest[1:] if rest.startswith(":") else ""
    elif ":" in address:
        port_text = address.rpartition(":")[2]
    elif address.isdigit():
        port_text = address
    else:
        port_text = ""
    if not port_text:
        return 80
    return int(port_text) if port_text.isdigit() and 0 < int(port_text) < 65536 else None
