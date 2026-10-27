"""Result types shared by the webserver configuration parsers (Plan 3, Contract decision 9)."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import WebserverType

__all__ = ["ParseError", "ParseResult", "ParsedBinding", "WebserverType"]


class ParseError(ValueError):
    """The dump is not a well-formed configuration (unbalanced braces, unterminated quote, ...)."""


@dataclass(frozen=True, slots=True)
class ParsedBinding:
    """One TLS vhost/port candidate; ``discovery.py`` turns candidates into final bindings.

    ``cert_paths``/``key_paths`` are positional: entry *i* of each belongs together;
    ``key_paths`` may be shorter (a certificate without its own ``SSLCertificateKeyFile``: Apache allows the key
    inside the certificate file; Task 8A decides). The parsers never
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
    # Optional provenance, positional with ``cert_paths``: the configuration file holding each certificate
    # directive (Apache vhosts can mix inline and included directives). Empty when the parser does not
    # report it; ``config_file`` is the file of the first certificate directive.
    cert_files: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ParseResult:
    bindings: tuple[ParsedBinding, ...]
    config_files: tuple[str, ...]
    warnings: tuple[str, ...]
