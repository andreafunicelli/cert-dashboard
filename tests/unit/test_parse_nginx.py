from pathlib import Path

import pytest

from app.ansible import parse_nginx as parse_nginx_module
from app.ansible.parse_nginx import parse_nginx
from app.ansible.parsed import ParseError, ParseResult
from app.models.enums import WebserverType

DUMPS = Path(__file__).resolve().parent.parent / "fixtures" / "dumps"


def read_dump(name: str) -> str:
    return (DUMPS / name).read_text()


def test_server_blocks_listen_forms_and_relative_paths():
    result = parse_nginx(read_dump("nginx_multi.txt"))
    by_name = {(b.vhost_name, b.port): b for b in result.bindings}
    www = by_name[("www.example.com", 443)]
    assert (
        www.vhost_names == ("www.example.com", "example.com")
        and www.config_file == "/etc/nginx/conf.d/www.conf"
    )
    assert (www.cert_paths, www.key_paths) == (("/etc/nginx/ssl/www.crt",), ("/etc/nginx/ssl/www.key",))
    api = by_name[("api.example.com", 8443)]
    assert api.cert_paths == ("/etc/nginx/ssl/api-rsa.crt", "/etc/nginx/ssl/api-ecdsa.crt")
    assert api.key_paths == ("/etc/nginx/ssl/api-rsa.key", "/etc/nginx/ssl/api-ecdsa.key")
    assert ("plain.example.com", 80) not in by_name and ("www.example.com", 80) not in by_name
    assert (
        "/etc/nginx/nginx.conf" in result.config_files and "/etc/nginx/conf.d/www.conf" in result.config_files
    )


def test_binding_is_a_frozen_nginx_candidate_without_a_chain():
    result = parse_nginx(read_dump("nginx_multi.txt"))
    api = next(b for b in result.bindings if b.vhost_name == "api.example.com")
    assert api.webserver is WebserverType.NGINX
    assert api.chain_path is None
    with pytest.raises(AttributeError):
        api.port = 1  # type: ignore[misc]


def dump(*files: tuple[str, str]) -> str:
    """Build `nginx -T` output: the first file is the main configuration."""
    parts = [
        "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok",
        "nginx: configuration file /etc/nginx/nginx.conf test is successful",
    ]
    for path, body in files:
        parts += [f"# configuration file {path}:", body]
    return "\n".join(parts) + "\n"


def one_server(body: str, *, http: str = "") -> str:
    return dump(
        ("/etc/nginx/nginx.conf", "events {}\nhttp {\n" + http + "\nserver {\n" + body + "\n}\n}\n"),
    )


def test_legacy_ssl_on_makes_every_listener_tls_and_keeps_positional_pairing():
    result = parse_nginx(read_dump("nginx_legacy_ssl_on.txt"))
    by_port = {b.port: b for b in result.bindings}
    assert sorted(by_port) == [443, 8443]  # unix: skipped, `ssl off` cleartext server is not TLS
    legacy = by_port[8443]
    assert legacy.vhost_name == "legacy.example.com"
    assert legacy.cert_paths == ("/etc/nginx/ssl/legacy-a.crt", "/etc/nginx/ssl/legacy-b.crt")
    assert legacy.key_paths == ("/etc/nginx/ssl/legacy-a.key", "/etc/nginx/ssl/legacy-b.key")
    assert result.warnings == ()


def test_listen_443_without_ssl_flag_and_without_ssl_on_is_not_tls():
    body = "listen 443;\nserver_name a.example.com;\nssl_certificate /c.crt;\nssl_certificate_key /c.key;"
    assert parse_nginx(one_server(body)).bindings == ()


def test_ipv4_and_ipv6_listeners_on_the_same_port_give_one_binding():
    body = "listen 443 ssl;\nlisten [::]:443 ssl;\nlisten *:443 ssl;\nssl_certificate /c.crt;\nssl_certificate_key /c.key;"
    (binding,) = parse_nginx(one_server(body)).bindings
    assert binding.port == 443


def test_address_forms_with_flags_give_their_ports():
    body = (
        "listen 127.0.0.1:8443 ssl http2;\nlisten [::1]:9443 ssl;\nlisten unix:/run/x.sock ssl;\n"
        "ssl_certificate /c.crt;\nssl_certificate_key /c.key;"
    )
    assert [b.port for b in parse_nginx(one_server(body)).bindings] == [8443, 9443]


def test_server_name_underscore_or_missing_is_default_and_empty_names_are_dropped():
    cert = "\nssl_certificate /c.crt;\nssl_certificate_key /c.key;"
    (underscore,) = parse_nginx(one_server("listen 443 ssl;\nserver_name _;" + cert)).bindings
    assert (underscore.vhost_name, underscore.vhost_names) == ("default", ("_",))
    (nameless,) = parse_nginx(one_server("listen 443 ssl;" + cert)).bindings
    assert (nameless.vhost_name, nameless.vhost_names) == ("default", ())
    (mixed,) = parse_nginx(one_server('listen 443 ssl;\nserver_name _ "" real.example.com;' + cert)).bindings
    assert (mixed.vhost_name, mixed.vhost_names) == ("real.example.com", ("_", "real.example.com"))


def test_quoted_paths_keep_spaces_and_hashes_and_comments_are_ignored():
    body = (
        "listen 443 ssl; # trailing comment ssl_certificate /nope.crt;\n"
        '# ssl_certificate /commented.crt;\nssl_certificate "/etc/ssl/my certs/a#1.crt";\n'
        "ssl_certificate_key '/etc/ssl/my certs/a#1.key';"
    )
    (binding,) = parse_nginx(one_server(body)).bindings
    assert binding.cert_paths == ("/etc/ssl/my certs/a#1.crt",)
    assert binding.key_paths == ("/etc/ssl/my certs/a#1.key",)


def test_http_level_certificate_is_inherited_with_the_file_of_the_directive():
    result = parse_nginx(read_dump("nginx_inherited.txt"))
    by_name = {b.vhost_name: b for b in result.bindings}
    inherited = by_name["inherits.example.com"]
    assert inherited.cert_paths == ("/etc/nginx/ssl/default.crt",)
    assert inherited.key_paths == ("/etc/nginx/ssl/default.key",)
    assert inherited.config_file == "/etc/nginx/nginx.conf"
    own = by_name["own.example.com"]
    assert (own.cert_paths, own.config_file) == (("/etc/nginx/ssl/own.crt",), "/etc/nginx/conf.d/own.conf")


def test_stream_servers_are_skipped_with_a_warning():
    result = parse_nginx(read_dump("nginx_inherited.txt"))
    assert {b.vhost_name for b in result.bindings} == {"inherits.example.com", "own.example.com"}
    assert result.warnings == (
        "/etc/nginx/nginx.conf: stream server skipped (only http servers are supported)",
    )


def test_mismatched_certificate_and_key_counts_warn_and_skip_the_block():
    body = "listen 443 ssl;\nserver_name bad.example.com;\nssl_certificate /a.crt;\nssl_certificate /b.crt;\nssl_certificate_key /a.key;"
    result = parse_nginx(one_server(body))
    assert result.bindings == ()
    assert result.warnings == (
        "/etc/nginx/nginx.conf: server bad.example.com: 2 ssl_certificate but 1 ssl_certificate_key; skipped",
    )


def test_tls_listener_without_any_certificate_warns_and_is_skipped():
    result = parse_nginx(one_server("listen 443 ssl;\nserver_name nocert.example.com;"))
    assert result.bindings == ()
    assert result.warnings == (
        "/etc/nginx/nginx.conf: server nocert.example.com: no ssl_certificate; skipped",
    )


@pytest.mark.parametrize("path", ["$ssl_server_name.crt", "data:$cert_pem", "engine:pkcs11:abc"])
def test_paths_that_are_not_plain_files_warn_and_skip(path):
    body = (
        f"listen 443 ssl;\nserver_name v.example.com;\nssl_certificate {path};\nssl_certificate_key /c.key;"
    )
    result = parse_nginx(one_server(body))
    assert result.bindings == ()
    assert result.warnings == (
        f"/etc/nginx/nginx.conf: server v.example.com: ssl_certificate {path} is not a plain file path; skipped",
    )


@pytest.mark.parametrize(
    "text",
    [
        "events {}\nhttp {\nserver {\nlisten 443 ssl;\n}\n",
        "events {}\nhttp {\n}\n}\n",
        "events {}\nhttp {\nlisten 443\n}",
        "http {\nroot 'unterminated;\n}",
        "http { ; }",
        "{ }",
    ],
)
def test_malformed_configuration_raises_parse_error(text):
    with pytest.raises(ParseError):
        parse_nginx(dump(("/etc/nginx/nginx.conf", text)))


def test_empty_and_marker_less_dumps_have_no_bindings():
    assert parse_nginx("") == ParseResult((), (), ())
    result = parse_nginx('nginx: [emerg] open() "/etc/nginx/nginx.conf" failed\n')
    assert result.bindings == () and result.config_files == ()
    assert result.warnings == ("no configuration file markers found in the dump",)


def test_a_dump_without_http_block_has_no_bindings():
    result = parse_nginx(dump(("/etc/nginx/nginx.conf", "events {}\n")))
    assert result.bindings == () and result.config_files == ("/etc/nginx/nginx.conf",)


def test_prefix_resolves_relative_paths():
    body = "listen 443 ssl;\nssl_certificate ssl/a.crt;\nssl_certificate_key ../keys/a.key;"
    (binding,) = parse_nginx(one_server(body), prefix="/usr/local/nginx/conf/").bindings
    assert binding.cert_paths == ("/usr/local/nginx/conf/ssl/a.crt",)
    assert binding.key_paths == ("/usr/local/nginx/keys/a.key",)


def by_name(result):
    return {b.vhost_name: b for b in result.bindings}


CERT_KEY = "ssl_certificate /c.crt; ssl_certificate_key /c.key;"


def test_d3a_tls_inline_in_the_server_block_is_attributed_to_the_vhost_file():
    main = "events {}\nhttp {\ninclude v.conf;\n}"
    vhost = "server { listen 443 ssl; server_name inline.example.com; " + CERT_KEY + " }"
    result = parse_nginx(dump(("/etc/nginx/nginx.conf", main), ("/etc/nginx/v.conf", vhost)))
    (binding,) = result.bindings
    assert binding.config_file == "/etc/nginx/v.conf"
    assert (binding.cert_paths, binding.key_paths) == (("/c.crt",), ("/c.key",))


def test_d3b_include_by_relative_path_inside_server_attributes_directives_to_that_server():
    result = parse_nginx(read_dump("nginx_include_relative.txt"))
    (binding,) = result.bindings
    assert (binding.vhost_name, binding.port) == ("www.example.com", 443)
    assert binding.cert_paths == ("/etc/nginx/ssl/www.crt",)
    assert binding.key_paths == ("/etc/nginx/ssl/www.key",)
    assert binding.config_file == "/etc/nginx/snippets/www-tls.conf"
    assert result.warnings == ()
    assert "/etc/nginx/snippets/www-tls.conf" in result.config_files


def test_d3c_include_glob_inside_server_expands_matches_in_sorted_order():
    result = parse_nginx(read_dump("nginx_include_glob.txt"))
    app = by_name(result)["app.example.com"]
    assert app.cert_paths == ("/etc/nginx/ssl/app-rsa.crt", "/etc/nginx/ssl/app-ecdsa.crt")
    assert app.key_paths == ("/etc/nginx/ssl/app-rsa.key", "/etc/nginx/ssl/app-ecdsa.key")
    assert app.config_file == "/etc/nginx/tls.d/app-a.conf"


def test_d3c_http_level_glob_include_applies_a_global_default_to_servers_without_their_own():
    result = parse_nginx(read_dump("nginx_include_glob.txt"))
    other = by_name(result)["other.example.com"]
    assert other.cert_paths == ("/etc/nginx/ssl/default.crt",)
    assert other.key_paths == ("/etc/nginx/ssl/default.key",)
    assert other.config_file == "/etc/nginx/conf.d/10-tls-default.conf"
    assert set(by_name(result)) == {"app.example.com", "other.example.com"}  # readme.txt is not *.conf


def test_glob_star_does_not_cross_directory_separators():
    main = "events {}\nhttp {\ninclude conf.d/*.conf;\n}"
    nested = "server { listen 443 ssl; server_name n.example.com; " + CERT_KEY + " }"
    result = parse_nginx(dump(("/etc/nginx/nginx.conf", main), ("/etc/nginx/conf.d/sub/n.conf", nested)))
    assert result.bindings == ()
    assert result.warnings == (
        "/etc/nginx/conf.d/sub/n.conf: not reached from the main configuration; skipped",
    )


def test_d3d_certificate_inline_and_key_included_and_the_reverse_give_one_binding_each():
    result = parse_nginx(read_dump("nginx_include_split.txt"))
    named = by_name(result)
    a = named["cert-inline.example.com"]
    assert (a.cert_paths, a.key_paths) == (("/etc/nginx/ssl/split-a.crt",), ("/etc/nginx/ssl/split-a.key",))
    assert a.config_file == "/etc/nginx/conf.d/cert-inline.conf"
    b = named["key-inline.example.com"]
    assert (b.cert_paths, b.key_paths) == (("/etc/nginx/ssl/split-b.crt",), ("/etc/nginx/ssl/split-b.key",))
    assert b.config_file == "/etc/nginx/snippets/split-b-cert.conf"
    assert len(result.bindings) == 2 and result.warnings == ()


def test_a_snippet_included_by_two_servers_is_applied_to_each():
    main = "events {}\nhttp {\ninclude s.conf;\n}"
    servers = (
        "server { listen 443 ssl; server_name one.example.com; include snippets/tls.conf; }\n"
        "server { listen 8443 ssl; server_name two.example.com; include snippets/tls.conf; }"
    )
    result = parse_nginx(
        dump(
            ("/etc/nginx/nginx.conf", main),
            ("/etc/nginx/s.conf", servers),
            ("/etc/nginx/snippets/tls.conf", CERT_KEY),
        )
    )
    assert {(b.vhost_name, b.port) for b in result.bindings} == {
        ("one.example.com", 443),
        ("two.example.com", 8443),
    }
    assert {b.config_file for b in result.bindings} == {"/etc/nginx/snippets/tls.conf"}


def test_include_cycles_are_cut_with_a_warning():
    a = "events {}\nhttp {\ninclude b.conf;\n}"
    b = "server { listen 443 ssl; " + CERT_KEY + " }\ninclude nginx.conf;"
    result = parse_nginx(dump(("/etc/nginx/nginx.conf", a), ("/etc/nginx/b.conf", b)))
    assert len(result.bindings) == 1
    cycle = "/etc/nginx/nginx.conf -> /etc/nginx/b.conf -> /etc/nginx/nginx.conf"
    assert result.warnings == (
        f"/etc/nginx/b.conf: include /etc/nginx/nginx.conf skipped: include cycle ({cycle})",
    )


def chain_of_includes(levels: int) -> str:
    """Main file includes f1, f1 includes f2, ... ; the last file holds a TLS server."""
    files = [("/etc/nginx/nginx.conf", "events {}\nhttp {\ninclude f1.conf;\n}")]
    for i in range(1, levels + 1):
        body = f"include f{i + 1}.conf;" if i < levels else "server { listen 443 ssl; " + CERT_KEY + " }"
        files.append((f"/etc/nginx/f{i}.conf", body))
    return dump(*files)


def test_exactly_sixteen_nested_includes_are_followed():
    result = parse_nginx(chain_of_includes(16))
    assert len(result.bindings) == 1 and result.warnings == ()


def test_include_depth_beyond_sixteen_is_cut_with_a_warning():
    result = parse_nginx(chain_of_includes(18))
    assert result.bindings == ()
    assert any("f17.conf" in w and "include depth" in w for w in result.warnings)
    assert any(w.startswith("/etc/nginx/f18.conf: not reached") for w in result.warnings)


def test_non_glob_include_naming_no_dumped_file_warns_but_a_glob_with_no_match_does_not():
    main = "events {}\nhttp {\ninclude missing.conf;\ninclude none/*.conf;\n}"
    result = parse_nginx(dump(("/etc/nginx/nginx.conf", main)))
    assert result.warnings == (
        "/etc/nginx/nginx.conf: include /etc/nginx/missing.conf: file not in the dump",
    )


def test_files_never_reached_from_the_main_configuration_are_reported_and_skipped():
    stray = "server { listen 443 ssl; server_name stray.example.com; " + CERT_KEY + " }"
    result = parse_nginx(
        dump(("/etc/nginx/nginx.conf", "events {}\nhttp {}\n"), ("/etc/nginx/stray.conf", stray))
    )
    assert result.bindings == ()
    assert result.warnings == ("/etc/nginx/stray.conf: not reached from the main configuration; skipped",)
    assert result.config_files == ("/etc/nginx/nginx.conf", "/etc/nginx/stray.conf")


def test_rsa_and_ecdsa_certificates_with_one_issuer_stay_two_positional_entries_without_a_chain():
    body = (
        "listen 443 ssl;\nssl_certificate /e/rsa.crt;\nssl_certificate_key /e/rsa.key;\n"
        "ssl_certificate /e/ecdsa.crt;\nssl_certificate_key /e/ecdsa.key;"
    )
    (binding,) = parse_nginx(one_server(body)).bindings
    assert binding.cert_paths == ("/e/rsa.crt", "/e/ecdsa.crt") and binding.chain_path is None


def test_pathological_include_fan_out_is_bounded():
    files = [("/etc/nginx/nginx.conf", "events {}\nhttp {\ninclude f1.conf;\n}")]
    for i in range(1, 16):
        files.append((f"/etc/nginx/f{i}.conf", f"include f{i + 1}.conf;\ninclude f{i + 1}.conf;"))
    files.append(("/etc/nginx/f16.conf", ""))
    with pytest.raises(ParseError, match="too many include expansions"):
        parse_nginx(dump(*files))


def test_blocks_nested_beyond_the_limit_raise_parse_error():
    text = "events {}\n" + "a {\n" * 40 + "}\n" * 40
    with pytest.raises(ParseError, match="nested deeper"):
        parse_nginx(dump(("/etc/nginx/nginx.conf", text)))


def test_escapes_variables_and_crlf_line_endings_are_tokenized_like_nginx():
    body = (
        "listen 443 ssl;\r\nserver_name a.example.com;\r\n"
        'ssl_certificate "/etc/ssl/q\\"uote.crt";\r\nssl_certificate_key /etc/ssl/sp\\ ace.key;\r\n'
        "set $x a${y}b;\r\n"
    )
    (binding,) = parse_nginx(one_server(body)).bindings
    assert binding.cert_paths == ('/etc/ssl/q"uote.crt',) and binding.key_paths == (
        "/etc/ssl/sp\\ ace.key",
    )  # nginx keeps `\ ` verbatim


def test_a_file_dumped_twice_is_read_as_one_concatenated_file():
    first = "events {}\nhttp {\ninclude v.conf;\n}"
    result = parse_nginx(
        dump(
            ("/etc/nginx/nginx.conf", first),
            ("/etc/nginx/v.conf", "server { listen 443 ssl; server_name a.example.com; " + CERT_KEY + " }"),
            ("/etc/nginx/v.conf", "server { listen 8443 ssl; server_name b.example.com; " + CERT_KEY + " }"),
        )
    )
    assert {b.vhost_name for b in result.bindings} == {"a.example.com", "b.example.com"}
    assert result.config_files == ("/etc/nginx/nginx.conf", "/etc/nginx/v.conf")


def test_large_dumps_parse_in_linear_time():
    servers = "\n".join(
        f"server {{ listen 443 ssl; server_name h{i}.example.com; {CERT_KEY} }}" for i in range(5000)
    )
    result = parse_nginx(dump(("/etc/nginx/nginx.conf", "events {}\nhttp {\n" + servers + "\n}")))
    assert len(result.bindings) == 5000


def _count_fnmatch(monkeypatch):
    calls = []
    real = parse_nginx_module.fnmatchcase

    def counting(name, pat):
        calls.append(name)
        return real(name, pat)

    monkeypatch.setattr(parse_nginx_module, "fnmatchcase", counting)
    return calls


def test_unmatched_glob_includes_do_not_rescan_every_dumped_file(monkeypatch):
    n = 1500
    includes = "\n".join(f"include conf.d/x{i}-*.conf;" for i in range(n))
    files = [("/etc/nginx/nginx.conf", "events {}\nhttp {\n" + includes + "\n}")]
    files += [(f"/etc/nginx/conf.d/f{i}.conf", "") for i in range(n)]
    calls = _count_fnmatch(monkeypatch)
    result = parse_nginx(dump(*files))
    assert len(calls) < 10 * n  # a full rescan per glob would be n * n = 2.25M comparisons
    assert result.bindings == ()
    assert not any("include" in w for w in result.warnings)  # unmatched globs stay silent


def test_glob_expansion_stays_sorted_and_scoped_to_the_matching_prefix(monkeypatch):
    files = [
        ("/etc/nginx/nginx.conf", "events {}\nhttp {\ninclude conf.d/b*.conf;\n}"),
        ("/etc/nginx/conf.d/b2.conf", "server { listen 443 ssl; server_name two.example.com; " + CERT_KEY + " }"),
        ("/etc/nginx/conf.d/a1.conf", "server { listen 443 ssl; server_name other.example.com; " + CERT_KEY + " }"),
        ("/etc/nginx/conf.d/b1.conf", "server { listen 8443 ssl; server_name one.example.com; " + CERT_KEY + " }"),
        ("/etc/nginx/conf.d/c1.conf", "server { listen 443 ssl; server_name three.example.com; " + CERT_KEY + " }"),
    ]
    calls = _count_fnmatch(monkeypatch)
    result = parse_nginx(dump(*files))
    assert [b.vhost_name for b in result.bindings] == ["one.example.com", "two.example.com"]
    assert sorted(calls) == ["b1.conf", "b2.conf"]


def test_unmatched_globs_sharing_a_basename_prefix_hit_the_glob_work_budget(monkeypatch):
    n = 1200
    includes = "\n".join(f"include conf.d/f*-missing-{i}.conf;" for i in range(n))
    files = [("/etc/nginx/nginx.conf", "events {}\nhttp {\n" + includes + "\n}")]
    files += [(f"/etc/nginx/conf.d/f{i}.conf", "") for i in range(n)]
    calls = _count_fnmatch(monkeypatch)
    with pytest.raises(ParseError, match="glob matching"):
        parse_nginx(dump(*files))
    # n * n = 1.44M comparisons without a budget; the budget is linear in the number of dumped files
    assert len(calls) <= parse_nginx_module.GLOB_WORK_PER_FILE * (n + 1) + parse_nginx_module.GLOB_WORK_BASE + n


def test_ordinary_shared_prefix_globs_stay_within_the_glob_work_budget():
    n = 300
    includes = "\n".join(f"include conf.d/f*-{i % 3}.conf;" for i in range(30))
    files = [("/etc/nginx/nginx.conf", "events {}\nhttp {\n" + includes + "\n}")]
    files += [(f"/etc/nginx/conf.d/f{i}-{i % 3}.conf", "") for i in range(n)]
    assert parse_nginx(dump(*files)).bindings == ()
