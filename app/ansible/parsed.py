"""Result types shared by the webserver configuration parsers (Plan 3, Contract decision 9)."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import WebserverType


class ParseError(ValueError):
    """The dump is not a well-formed configuration (unbalanced braces, unterminated quote, ...)."""


@dataclass(frozen=True, slots=True)
class ParsedBinding:
    """One TLS vhost/port candidate; ``discovery.py`` turns candidates into final bindings.

    ``cert_paths``/``key_paths`` are positional: entry *i* of each belongs together. The parsers never
    decide which certificate file is a leaf or a chain (D1); ``chain_path`` is only set when the
    configuration names one explicitly (Apache ``SSLCertificateChainFile``).
    """

    webserver: WebserverType
    vhost_name: str
    vhost_names: tuple[str, ...]
    port: int
    config_file: str
    cert_paths: tuple[str, ...]
    key_paths: tuple[str, ...]
    chain_path: str | None


@dataclass(frozen=True, slots=True)
class ParseResult:
    bindings: tuple[ParsedBinding, ...]
    config_files: tuple[str, ...]
    warnings: tuple[str, ...]
