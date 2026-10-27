import dataclasses
import json
from pathlib import Path

import pytest

from app.ansible.parse_apache import ApacheDump, parse_apache
from app.ansible.parsed import ParseError
from app.models.enums import WebserverType

DUMPS = Path(__file__).resolve().parent.parent / "fixtures" / "dumps"
ROOT = "/etc/apache2"
SITES = f"{ROOT}/sites-enabled"
FALLBACK_WARNING = "apachectl -S unavailable; vhosts derived from the configuration files"


def read_dump(name: str) -> str:
    return (DUMPS / name).read_text()


def collector_dump(name: str) -> ApacheDump:
    return ApacheDump.from_collector(json.loads(read_dump(name)))


def config(*files: tuple[str, str]) -> str:
    """Concatenated configuration: the first file is the main one, as the collector emits it."""
    return "".join(f"# configuration file {path}:\n{body}\n" for path, body in files)


def status(*entries: tuple[str, str, str, int], root: str = ROOT) -> str:
    """``apachectl -S`` output: one ``addr:port name (file:line)`` line per ``(addr:port, name, file, line)``."""
    lines = ["VirtualHost configuration:"]
    lines += [f"{addr:<22} {name} ({path}:{line})" for addr, name, path, line in entries]
    lines += [f'ServerRoot: "{root}"', 'Main DocumentRoot: "/var/www/html"']
    return "\n".join(lines) + "\n"


def vhost(*body: str, address: str = "*:443", name: str = "www.example.com") -> str:
    head = [f"<VirtualHost {address}>"] + ([f"    ServerName {name}"] if name else [])
    return "\n".join([*head, "    SSLEngine on", *body, "</VirtualHost>"]) + "\n"


TLS = ("    SSLCertificateFile ssl/www.crt", "    SSLCertificateKeyFile ssl/www.key")
WWW = f"{SITES}/www.conf"
WWW_S = status(("*:443", "www.example.com", WWW, 1))


def one_vhost(*body: str, **kw: str) -> ApacheDump:
    return ApacheDump(
        WWW_S, config((f"{ROOT}/apache2.conf", "ServerRoot /etc/apache2\n"), (WWW, vhost(*body, **kw)))
    )


def only(result):
    [binding] = result.bindings
    return binding


# -- the plan's fixture-driven cases ---------------------------------------------------------------


def test_vhosts_directives_and_chain_files():
    result = parse_apache(ApacheDump(read_dump("apache_S.txt"), read_dump("apache_config.txt")))
    by_name = {(b.vhost_name, b.port): b for b in result.bindings}
    www = by_name[("www.example.com", 443)]
    assert www.vhost_names == ("www.example.com", "example.com", "*.cdn.example.com")
    assert www.config_file == "/etc/apache2/sites-enabled/www.conf"
    assert (www.cert_paths, www.key_paths, www.chain_path) == (
        ("/etc/apache2/ssl/www.crt",),
        ("/etc/apache2/ssl/www.key",),
        "/etc/apache2/ssl/www.chain.pem",
    )
    assert ("www.example.com", 80) not in by_name  # SSLEngine off / non-TLS vhost excluded
    assert by_name[("shop.example.com", 443)].cert_paths == (
        "/etc/apache2/ssl/shop.crt",
        "/etc/apache2/ssl/shop-int.crt",
    )


def test_fixture_result_lists_files_and_has_no_warnings_or_extra_bindings():
    result = parse_apache(ApacheDump(read_dump("apache_S.txt"), read_dump("apache_config.txt")))
    assert len(result.bindings) == 2 and result.warnings == ()
    assert result.config_files == (
        f"{ROOT}/apache2.conf",
        f"{SITES}/shop.conf",
        f"{SITES}/www.conf",
    )


def test_extra_certificates_stay_positional_with_their_keys_and_chain_is_only_a_candidate():
    result = parse_apache(ApacheDump(read_dump("apache_S.txt"), read_dump("apache_config.txt")))
    shop = next(b for b in result.bindings if b.vhost_name == "shop.example.com")
    assert shop.key_paths == ("/etc/apache2/ssl/shop.key", "/etc/apache2/ssl/shop-int.key")
    assert shop.chain_path is None  # a second SSLCertificateFile is never promoted to a chain (D1)
    assert shop.webserver is WebserverType.APACHE
    with pytest.raises(dataclasses.FrozenInstanceError):
        shop.port = 1  # type: ignore[misc]


def test_global_directive_on_the_listen_https_port_becomes_the_default_binding():
    result = parse_apache(ApacheDump("", read_dump("apache_global.txt")))
    by_name = {b.vhost_name: b for b in result.bindings}
    default = by_name["default"]
    assert (default.port, default.config_file) == (8443, f"{ROOT}/conf.d/00-tls-default.conf")
    assert (default.cert_paths, default.key_paths) == (
        (f"{ROOT}/ssl/default.crt",),
        (f"{ROOT}/ssl/default.key",),
    )
    assert default.chain_path == f"{ROOT}/ssl/default.chain.pem"
    # a TLS vhost without its own certificate inherits the global one (config file of the directive)
    inheriting = by_name["www.example.com"]
    assert (inheriting.port, inheriting.config_file) == (8443, default.config_file)
    assert inheriting.cert_paths == default.cert_paths


def test_default_binding_falls_back_to_443_without_listen_https():
    files = config(
        (
            f"{ROOT}/apache2.conf",
            "Listen 80\nListen 443\nSSLCertificateFile /s/g.crt\nSSLCertificateKeyFile /s/g.key\n",
        )
    )
    [default] = parse_apache(ApacheDump("", files)).bindings
    assert (default.vhost_name, default.vhost_names, default.port) == ("default", (), 443)
    assert default.config_file == f"{ROOT}/apache2.conf"


def test_collector_document_with_a_global_include_yields_the_default_and_the_vhost_binding():
    result = parse_apache(collector_dump("apache_global_include.json"))
    by_name = {b.vhost_name: b for b in result.bindings}
    assert set(by_name) == {"default", "www.example.com"}
    default = by_name["default"]
    assert (default.port, default.config_file) == (443, f"{ROOT}/conf-enabled/zz-global-tls.conf")
    assert default.cert_paths == (f"{ROOT}/ssl/global.crt",)
    assert by_name["www.example.com"].cert_paths == (f"{ROOT}/ssl/www.crt",)
    assert result.warnings == ()


def test_from_collector_keeps_s_output_only_when_s_succeeded_and_carries_warnings():
    document = json.loads(read_dump("apache_vhost_inline.json"))
    ok = ApacheDump.from_collector(document)
    assert ok.vhosts == document["s_output"] and ok.config == document["config"] and ok.warnings == ()
    failed = ApacheDump.from_collector({**document, "s_rc": 1, "warnings": ["w1", FALLBACK_WARNING]})
    assert failed.vhosts == "" and failed.warnings == ("w1", FALLBACK_WARNING)
    result = parse_apache(failed)
    assert result.warnings == ("w1", FALLBACK_WARNING)  # the parser's own walk-only warning is not repeated
    assert only(result).vhost_name == "www.example.com"


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"s_rc": 0, "s_output": "", "config": 5, "warnings": []},
        {"s_rc": 0, "s_output": "", "config": "", "warnings": "x"},
    ],
)
def test_from_collector_rejects_a_malformed_document(document):
    with pytest.raises(ParseError):
        ApacheDump.from_collector(document)


def test_failed_S_derives_vhosts_from_the_sections_and_warns():
    result = parse_apache(ApacheDump("", read_dump("apache_config.txt")))
    by_name = {(b.vhost_name, b.port): b for b in result.bindings}
    assert set(by_name) == {("www.example.com", 443), ("shop.example.com", 443)}
    assert result.warnings == (FALLBACK_WARNING,)


def test_walk_only_section_address_gives_the_port_else_443():
    for address, port in (("*:8443", 8443), ("[::]:9443", 9443), ("10.0.0.5", 443), ("_default_:*", 443)):
        dump = ApacheDump("", config((WWW, vhost(*TLS, address=address))))
        assert only(parse_apache(dump)).port == port, address


def test_multi_address_section_gives_one_binding_per_distinct_port():
    dump = ApacheDump("", config((WWW, vhost(*TLS, address="*:443 [::]:443 *:8443"))))
    assert [b.port for b in parse_apache(dump).bindings] == [443, 8443]


# -- ServerRoot, nesting, continuation, case -------------------------------------------------------


def test_relative_paths_resolve_against_the_server_root_of_the_S_header():
    path = "/opt/httpd/conf/vhosts/www.conf"
    S = status(("*:443", "www.example.com", path, 1), root="/opt/httpd")
    dump = ApacheDump(
        S,
        config(
            (path, vhost("    SSLCertificateFile ssl/../ssl/a.crt", "    SSLCertificateKeyFile /abs/a.key"))
        ),
    )
    binding = only(parse_apache(dump))
    assert (binding.cert_paths, binding.key_paths) == (("/opt/httpd/ssl/a.crt",), ("/abs/a.key",))


def test_server_root_directive_is_used_without_S_and_a_later_one_changes_later_paths():
    main = 'ServerRoot "/srv/a"\nInclude vh.conf\nServerRoot /srv/b\nInclude vh2.conf\n'
    files = config(
        ("/srv/a/httpd.conf", main),
        ("/srv/a/vh.conf", vhost(*TLS)),
        ("/srv/b/vh2.conf", vhost(*TLS, address="*:444")),
    )
    paths = {b.port: b.cert_paths for b in parse_apache(ApacheDump("", files)).bindings}
    assert paths == {443: ("/srv/a/ssl/www.crt",), 444: ("/srv/b/ssl/www.crt",)}


def test_server_root_defaults_to_the_directory_of_the_main_configuration():
    files = config(("/etc/httpd/httpd.conf", "Include vh.conf\n"), ("/etc/httpd/vh.conf", vhost(*TLS)))
    assert only(parse_apache(ApacheDump("", files))).cert_paths == ("/etc/httpd/ssl/www.crt",)


def test_ifmodule_and_directory_nesting_inside_a_vhost_is_flattened():
    body = (
        "    <IfModule mod_ssl.c>",
        "        <IfModule !mod_foo.c>",
        "            SSLCertificateFile ssl/www.crt",
        "        </IfModule>",
        "        SSLCertificateKeyFile ssl/www.key",
        "    </IfModule>",
        '    <Directory "/var/www">',
        "        Require all granted",
        "    </Directory>",
    )
    assert only(parse_apache(one_vhost(*body))).cert_paths == (f"{ROOT}/ssl/www.crt",)


def test_vhost_nested_in_a_global_ifmodule_is_found():
    inner = "<IfModule mod_ssl.c>\n" + vhost(*TLS) + "</IfModule>\n"
    assert only(parse_apache(ApacheDump(WWW_S, config((WWW, inner))))).vhost_name == "www.example.com"


def test_directive_names_are_case_insensitive_and_values_keep_their_case():
    body = (
        "    sslcertificatefile ssl/Www.CRT",
        "    SSLCERTIFICATEKEYFILE ssl/Www.KEY",
        "    SSLcertificatechainfile ssl/Chain.pem",
    )
    text = (
        "<virtualhost *:443>\nservername WWW.example.com\nsslengine ON\n"
        + "\n".join(body)
        + "\n</VIRTUALHOST>\n"
    )
    binding = only(parse_apache(ApacheDump(WWW_S, config((WWW, text)))))
    assert binding.vhost_name == "WWW.example.com"
    assert (binding.cert_paths, binding.key_paths, binding.chain_path) == (
        (f"{ROOT}/ssl/Www.CRT",),
        (f"{ROOT}/ssl/Www.KEY",),
        f"{ROOT}/ssl/Chain.pem",
    )


def test_backslash_continuations_join_lines_but_keep_the_vhost_line_number():
    text = (
        "# top comment\n"
        "<VirtualHost *:443>\n"  # line 2
        "    ServerName www.example.com\n"
        "    ServerAlias a.example.com \\\n"
        "                b.example.com\n"
        "    SSLEngine on\n"
        "    SSLCertificateFile \\\n"
        '        "ssl/www.crt"\n'
        "    SSLCertificateKeyFile ssl/www.key\n"
        "</VirtualHost>\n"
    )
    S = status(("*:443", "www.example.com", WWW, 2))
    binding = only(parse_apache(ApacheDump(S, config((WWW, text)))))
    assert binding.vhost_names == ("www.example.com", "a.example.com", "b.example.com")
    assert binding.cert_paths == (f"{ROOT}/ssl/www.crt",)


def test_comments_quotes_and_servername_forms():
    text = (
        "<VirtualHost *:443>\n"
        "    # SSLEngine off\n"
        "    ServerName https://Wild.example.com:443\n"
        "    ServerAlias *.example.com 'other host'\n"
        "    SSLEngine on\n"
        '    SSLCertificateFile "/my certs/a b.crt"\n'
        "    SSLCertificateKeyFile '/my certs/a b.key'\n"
        "</VirtualHost>\n"
    )
    binding = only(parse_apache(ApacheDump(WWW_S, config((WWW, text)))))
    assert binding.vhost_name == "Wild.example.com"
    assert binding.vhost_names == ("Wild.example.com", "*.example.com", "other host")
    assert (binding.cert_paths, binding.key_paths) == (("/my certs/a b.crt",), ("/my certs/a b.key",))


def test_wildcard_server_name_is_the_vhost_name():
    binding = only(parse_apache(one_vhost(*TLS, name="*.example.com")))
    assert (binding.vhost_name, binding.vhost_names) == ("*.example.com", ("*.example.com",))


def test_server_name_is_taken_from_the_S_entry_when_the_section_has_none():
    S = status(("*:443", "from-S.example.com", WWW, 1))
    binding = only(parse_apache(ApacheDump(S, config((WWW, vhost(*TLS, name=""))))))
    assert binding.vhost_name == "from-S.example.com"
    nameless = only(parse_apache(ApacheDump("", config((WWW, vhost(*TLS, name=""))))))
    assert (nameless.vhost_name, nameless.vhost_names) == ("default", ())


# -- apachectl -S mapping --------------------------------------------------------------------------


def test_two_vhosts_in_one_file_are_matched_by_their_S_line_numbers():
    text = vhost(
        "    SSLCertificateFile ssl/a.crt",
        "    SSLCertificateKeyFile ssl/a.key",
        address="*",
        name="a.example.com",
    )
    text += vhost(
        "    SSLCertificateFile ssl/b.crt",
        "    SSLCertificateKeyFile ssl/b.key",
        address="*",
        name="b.example.com",
    )
    S = status(("*:443", "a.example.com", WWW, 1), ("*:8443", "b.example.com", WWW, 7))
    result = parse_apache(ApacheDump(S, config((WWW, text))))
    got = {(b.vhost_name, b.port): b.cert_paths for b in result.bindings}
    assert got == {
        ("a.example.com", 443): (f"{ROOT}/ssl/a.crt",),
        ("b.example.com", 8443): (f"{ROOT}/ssl/b.crt",),
    }


def test_S_entry_falls_back_to_server_name_and_port_when_the_line_does_not_match():
    S = status(("*:8443", "www.example.com", WWW, 99))
    binding = only(parse_apache(ApacheDump(S, config((WWW, vhost(*TLS, address="*"))))))
    assert binding.port == 8443


def test_a_section_unknown_to_S_keeps_its_own_address_ports():
    S = status(("*:80", "other.example.com", f"{SITES}/other.conf", 1))
    result = parse_apache(ApacheDump(S, config((WWW, vhost(*TLS)))))
    assert only(result).port == 443
    assert any("other.conf" in w and "not in the dump" in w for w in result.warnings)


def test_S_vhost_whose_file_is_missing_is_skipped_with_a_warning():
    S = status(("*:443", "www.example.com", WWW, 1), ("*:443", "gone.example.com", f"{SITES}/gone.conf", 1))
    result = parse_apache(ApacheDump(S, config((WWW, vhost(*TLS)))))
    assert [b.vhost_name for b in result.bindings] == ["www.example.com"]
    assert result.warnings == (
        f"{SITES}/gone.conf:1: vhost gone.example.com listed by apachectl -S; file not in the dump; skipped",
    )


def test_S_vhost_without_a_section_at_that_line_is_skipped_with_a_warning():
    S = status(("*:443", "ghost.example.com", WWW, 1))
    result = parse_apache(ApacheDump(S, config((WWW, "# nothing here\n"))))
    assert result.bindings == ()
    assert result.warnings == (
        f"{WWW}:1: vhost ghost.example.com listed by apachectl -S; no matching <VirtualHost> section; skipped",
    )


def test_default_server_line_and_aliases_of_the_S_output_are_understood():
    S = (
        "VirtualHost configuration:\n"
        "*:443                  is a NameVirtualHost\n"
        f"         default server a.example.com ({WWW}:1)\n"
        f"         port 443 namevhost a.example.com ({WWW}:1)\n"
        "                 alias alias.example.com\n"
        'ServerRoot: "/etc/apache2"\n'
    )
    binding = only(parse_apache(ApacheDump(S, config((WWW, vhost(*TLS, name=""))))))
    assert (binding.vhost_name, binding.vhost_names, binding.port) == (
        "a.example.com",
        ("a.example.com", "alias.example.com"),
        443,
    )


# -- warnings and refusals -------------------------------------------------------------------------


def test_ssl_engine_on_without_a_certificate_warns_and_is_skipped():
    result = parse_apache(one_vhost())
    assert result.bindings == ()
    assert result.warnings == (
        f"{WWW}: vhost www.example.com port 443: SSLEngine on without SSLCertificateFile; skipped",
    )


def test_certificate_and_key_count_mismatch_warns_and_is_skipped():
    result = parse_apache(one_vhost("    SSLCertificateFile ssl/a.crt"))
    assert result.bindings == ()
    assert "1 SSLCertificateFile but 0 SSLCertificateKeyFile" in result.warnings[0]


def test_non_plain_certificate_path_warns_and_is_skipped():
    result = parse_apache(
        one_vhost("    SSLCertificateFile ${CERT_DIR}/a.crt", "    SSLCertificateKeyFile ssl/a.key")
    )
    assert result.bindings == () and "not a plain file path" in result.warnings[0]


def test_certificate_directives_without_ssl_engine_are_not_a_binding():
    text = "<VirtualHost *:443>\nServerName www.example.com\n" + "\n".join(TLS) + "\n</VirtualHost>\n"
    result = parse_apache(ApacheDump(WWW_S, config((WWW, text))))
    assert result.bindings == () and result.warnings == ()


def test_global_ssl_engine_on_is_inherited_and_a_vhost_can_turn_it_off():
    main = "SSLEngine on\nSSLCertificateFile ssl/g.crt\nSSLCertificateKeyFile ssl/g.key\nInclude vh.conf\n"
    off = "<VirtualHost *:444>\nServerName off.example.com\nSSLEngine off\n</VirtualHost>\n"
    files = config((f"{ROOT}/apache2.conf", main), (f"{ROOT}/vh.conf", vhost() + off))
    result = parse_apache(ApacheDump("", files))
    assert sorted((b.vhost_name, b.port) for b in result.bindings) == [
        ("default", 443),
        ("www.example.com", 443),
    ]


def test_a_vhost_own_certificate_replaces_the_inherited_one():
    main = "SSLCertificateFile ssl/g.crt\nSSLCertificateKeyFile ssl/g.key\nSSLCertificateChainFile ssl/g.chain\nInclude vh.conf\n"
    files = config((f"{ROOT}/apache2.conf", main), (f"{ROOT}/vh.conf", vhost(*TLS)))
    by_name = {b.vhost_name: b for b in parse_apache(ApacheDump("", files)).bindings}
    assert by_name["www.example.com"].cert_paths == (f"{ROOT}/ssl/www.crt",)
    assert by_name["www.example.com"].chain_path == f"{ROOT}/ssl/g.chain"


def test_global_certificate_without_a_key_warns_and_gives_no_default():
    result = parse_apache(ApacheDump("", config((f"{ROOT}/apache2.conf", "SSLCertificateFile ssl/g.crt\n"))))
    assert result.bindings == () and "default" in result.warnings[0]


@pytest.mark.parametrize(
    "text",
    [
        "<VirtualHost *:443>\nSSLEngine on\n",
        "</VirtualHost>\n",
        "<VirtualHost *:443>\n</IfModule>\n",
        "<VirtualHost *:443\n</VirtualHost>\n",
        'ServerName "unterminated\n',
    ],
)
def test_malformed_configuration_raises_parse_error(text):
    with pytest.raises(ParseError):
        parse_apache(ApacheDump("", config((WWW, text))))


def test_sections_nested_too_deep_raise_parse_error():
    text = "<IfModule a>\n" * 40 + "</IfModule>\n" * 40
    with pytest.raises(ParseError, match="nested deeper"):
        parse_apache(ApacheDump("", config((WWW, text))))


def test_empty_dump_gives_no_bindings_and_text_without_markers_warns():
    empty = parse_apache(ApacheDump("", ""))
    assert (empty.bindings, empty.config_files, empty.warnings) == ((), (), ())
    noisy = parse_apache(ApacheDump("", "AH00526: syntax error\n"))
    assert noisy.bindings == () and "no configuration file markers" in noisy.warnings[0]


# -- D3: includes ----------------------------------------------------------------------------------


def test_d3_a_tls_inline_in_the_vhost():
    binding = only(parse_apache(collector_dump("apache_vhost_inline.json")))
    assert (binding.vhost_name, binding.port, binding.config_file) == ("www.example.com", 443, WWW)
    assert (binding.cert_paths, binding.key_paths) == ((f"{ROOT}/ssl/www.crt",), (f"{ROOT}/ssl/www.key",))


def test_d3_b_tls_in_a_relative_include_inside_the_vhost():
    result = parse_apache(collector_dump("apache_include_relative.json"))
    binding = only(result)  # the snippet is not also a global default binding
    assert (binding.vhost_name, binding.port, binding.config_file) == (
        "www.example.com",
        443,
        f"{ROOT}/tls/www.conf",
    )
    assert (binding.cert_paths, binding.key_paths) == ((f"{ROOT}/ssl/www.crt",), (f"{ROOT}/ssl/www.key",))
    assert result.warnings == ()


def test_d3_c_tls_in_a_glob_include_inside_the_vhost():
    binding = only(parse_apache(collector_dump("apache_include_glob.json")))
    assert (binding.vhost_name, binding.config_file) == ("www.example.com", f"{ROOT}/tls.d/10-cert.conf")
    assert (binding.cert_paths, binding.key_paths) == ((f"{ROOT}/ssl/www.crt",), (f"{ROOT}/ssl/www.key",))


def test_d3_d_certificate_inline_and_key_included():
    binding = only(parse_apache(collector_dump("apache_include_split.json")))
    assert binding.config_file == WWW  # the file with the certificate directive
    assert (binding.cert_paths, binding.key_paths) == ((f"{ROOT}/ssl/www.crt",), (f"{ROOT}/ssl/www.key",))


def test_d3_d_key_inline_and_certificate_included():
    files = config(
        (f"{ROOT}/apache2.conf", "ServerRoot /etc/apache2\n"),
        (WWW, vhost("    SSLCertificateKeyFile ssl/www.key", "    Include tls/cert.conf")),
        (f"{ROOT}/tls/cert.conf", "SSLCertificateFile ssl/www.crt\n"),
    )
    binding = only(parse_apache(ApacheDump(WWW_S, files)))
    assert binding.config_file == f"{ROOT}/tls/cert.conf"
    assert (binding.cert_paths, binding.key_paths) == ((f"{ROOT}/ssl/www.crt",), (f"{ROOT}/ssl/www.key",))


def test_a_snippet_listed_before_its_includer_is_still_not_a_global_directive():
    files = config(
        (f"{ROOT}/apache2.conf", "ServerRoot /etc/apache2\n"),
        (f"{ROOT}/tls/all.conf", "\n".join(TLS) + "\n"),
        (WWW, vhost("    Include tls/all.conf")),
    )
    binding = only(parse_apache(ApacheDump(WWW_S, files)))
    assert binding.vhost_name == "www.example.com" and binding.config_file == f"{ROOT}/tls/all.conf"


def test_the_same_snippet_included_by_two_vhosts_belongs_to_each():
    snippet = (f"{ROOT}/tls/all.conf", "\n".join(TLS) + "\n")
    files = config(
        (f"{ROOT}/apache2.conf", "Include a.conf\nInclude b.conf\n"),
        (f"{ROOT}/a.conf", vhost("    Include tls/all.conf", name="a.example.com")),
        (f"{ROOT}/b.conf", vhost("    Include tls/all.conf", name="b.example.com", address="*:444")),
        snippet,
    )
    result = parse_apache(ApacheDump("", files))
    assert sorted((b.vhost_name, b.port) for b in result.bindings) == [
        ("a.example.com", 443),
        ("b.example.com", 444),
    ]


def test_include_forms_directory_quoted_path_case_and_optional_or_missing():
    main = (
        'ServerRoot "/etc/apache2"\n'
        'INCLUDEOPTIONAL "my sites/*.conf"\n'
        "include vhosts.d\n"
        "IncludeOptional absent/*.conf\n"
        "IncludeOptional absent.conf\n"
        "Include missing.conf\n"
        "Include ${APACHE_CONF}/x.conf\n"
    )
    files = config(
        (f"{ROOT}/apache2.conf", main),
        (f"{ROOT}/my sites/a.conf", vhost(*TLS, name="quoted.example.com")),
        (f"{ROOT}/vhosts.d/b.conf", vhost(*TLS, name="b.example.com", address="*:444")),
        (f"{ROOT}/vhosts.d/sub/c.conf", vhost(*TLS, name="c.example.com", address="*:445")),
    )
    result = parse_apache(ApacheDump("", files))
    assert [b.vhost_name for b in result.bindings] == ["quoted.example.com", "b.example.com", "c.example.com"]
    assert any("missing.conf" in w and "not in the dump" in w for w in result.warnings)
    assert sum("absent" in w for w in result.warnings) == 0


def test_includes_are_expanded_in_sorted_glob_order_and_a_vhost_keeps_its_own_line():
    files = config(
        (f"{ROOT}/apache2.conf", "Include sites/*.conf\n"),
        (f"{ROOT}/sites/20-b.conf", "# b\n" + vhost(*TLS, name="b.example.com", address="*:444")),
        (f"{ROOT}/sites/10-a.conf", vhost(*TLS, name="a.example.com")),
    )
    S = status(
        ("*:443", "a.example.com", f"{ROOT}/sites/10-a.conf", 1),
        ("*:444", "b.example.com", f"{ROOT}/sites/20-b.conf", 2),
    )
    result = parse_apache(ApacheDump(S, files))
    assert [(b.vhost_name, b.port, b.config_file) for b in result.bindings] == [
        ("a.example.com", 443, f"{ROOT}/sites/10-a.conf"),
        ("b.example.com", 444, f"{ROOT}/sites/20-b.conf"),
    ]
    assert result.warnings == ()


def test_a_vhost_reached_twice_is_produced_once():
    files = config(
        (f"{ROOT}/apache2.conf", "Include sites/*.conf\nInclude sites/a.conf\n"),
        (f"{ROOT}/sites/a.conf", vhost(*TLS)),
    )
    assert len(parse_apache(ApacheDump("", files)).bindings) == 1


def test_a_global_directive_reached_twice_is_counted_once():
    files = config(
        (f"{ROOT}/apache2.conf", "Include g.conf\nInclude g.conf\n"),
        (f"{ROOT}/g.conf", "\n".join(TLS) + "\n"),
    )
    assert only(parse_apache(ApacheDump("", files))).vhost_name == "default"


def test_include_cycles_are_cut_with_a_warning():
    files = config(
        (f"{ROOT}/apache2.conf", "Include a.conf\n"),
        (f"{ROOT}/a.conf", "Include b.conf\n" + vhost(*TLS)),
        (f"{ROOT}/b.conf", "Include a.conf\nInclude apache2.conf\n"),
    )
    result = parse_apache(ApacheDump("", files))
    assert len(result.bindings) == 1
    assert len([w for w in result.warnings if "include cycle" in w]) == 2


def test_include_depth_is_limited_to_sixteen_levels_with_a_warning():
    chain = [(f"{ROOT}/f{n}.conf", f"Include f{n + 1}.conf\n") for n in range(20)]
    chain[16] = (chain[16][0], vhost(*TLS, name="last.example.com", address="*:444") + "Include f17.conf\n")
    chain[18] = (chain[18][0], vhost(*TLS, name="far.example.com"))
    result = parse_apache(ApacheDump("", config(*chain)))
    assert any("f17.conf skipped: include depth exceeds 16" in w for w in result.warnings)
    # f16 is reached at depth 16 (allowed); f17 and below are cut from main's tree but, being in the dump,
    # are still parsed standalone, so nothing the collector gathered is silently lost.
    assert sorted(b.vhost_name for b in result.bindings) == ["far.example.com", "last.example.com"]


def test_a_file_unreached_from_the_main_configuration_is_parsed_standalone_at_global_level():
    files = config(
        (f"{ROOT}/apache2.conf", "ServerRoot /etc/apache2\n"),
        (WWW, vhost(*TLS)),
        (f"{ROOT}/stray.conf", "\n".join(TLS) + "\n"),
    )
    by_name = {b.vhost_name for b in parse_apache(ApacheDump(WWW_S, files)).bindings}
    assert by_name == {"www.example.com", "default"}


def test_a_cycle_of_files_unreachable_from_main_is_still_parsed_once():
    files = config(
        (f"{ROOT}/apache2.conf", "# empty\n"),
        (f"{ROOT}/a.conf", "Include b.conf\n"),
        (f"{ROOT}/b.conf", "Include a.conf\n" + vhost(*TLS)),
    )
    assert len(parse_apache(ApacheDump("", files)).bindings) == 1


def test_include_expansion_explosion_raises_parse_error():
    many = "".join("Include b.conf\n" for _ in range(100))
    files = config(
        (f"{ROOT}/apache2.conf", many),
        (f"{ROOT}/b.conf", "".join("Include c.conf\n" for _ in range(100))),
        (f"{ROOT}/c.conf", "# leaf\n"),
    )
    with pytest.raises(ParseError, match="too many include expansions"):
        parse_apache(ApacheDump("", files))


def test_include_inside_a_section_of_an_included_file_nests_in_the_right_block():
    files = config(
        (f"{ROOT}/apache2.conf", "<IfModule ssl_module>\nInclude vh.conf\n</IfModule>\n"),
        (
            f"{ROOT}/vh.conf",
            "<VirtualHost *:443>\nServerName x.example.com\nSSLEngine on\nInclude tls.conf\n</VirtualHost>\n",
        ),
        (f"{ROOT}/tls.conf", "<IfModule ssl_module>\n" + "\n".join(TLS) + "\n</IfModule>\n"),
    )
    binding = only(parse_apache(ApacheDump("", files)))
    assert (binding.vhost_name, binding.config_file) == ("x.example.com", f"{ROOT}/tls.conf")
