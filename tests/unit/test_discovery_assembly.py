"""Task 8A: parser candidates + per-path facts -> section 6.2 bindings (D1: file roles by signature)."""

import json
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.ansible.discovery import PathFacts, assemble_bindings
from app.ansible.parsed import ParsedBinding
from app.crypto.keys import public_key_sha256
from app.models.enums import WebserverType

NOW = datetime(2026, 10, 19, tzinfo=UTC)
INCOMPLETE = "incomplete chain: no configured file holds this leaf's issuer"
BUNDLE_BROKEN = "bundle certificates after the leaf do not form a verified chain"
CHAIN_NOT_VERIFYING = "chain file does not verify the leaf; not used as chain"
CHAIN_UNREADABLE = "chain file unreadable; not used as chain"


# ---------------------------------------------------------------- certificate helpers


class Issued:
    def __init__(self, cert: x509.Certificate, key):
        self.cert = cert
        self.key = key

    @property
    def pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def fingerprint(self) -> str:
        return self.cert.fingerprint(hashes.SHA256()).hex()


def issue(cn: str, parent: Issued | None = None, *, key=None, ca: bool = False, issuer_cn: str | None = None):
    """Issue ``cn``; ``parent=None`` is self-signed. ``issuer_cn`` forges the issuer DN (signature stays real)."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    signer = parent.key if parent else key
    issuer = parent.cert.subject if parent else subject
    if issuer_cn is not None:
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(signer, hashes.SHA256())
    )
    return Issued(cert, key)


def pem_of(*certs: Issued) -> str:
    return "".join(c.pem for c in certs)


# ---------------------------------------------------------------- facts / parser helpers


def cert_facts(path: str, *certs: Issued, mode: str = "0644", **overrides) -> PathFacts:
    values = {
        "path": path,
        "exists": True,
        "readable": True,
        "owner": "root",
        "group": "root",
        "mode": mode,
        "size": 1000,
        "mtime": "2026-10-19T00:00:00Z",
        "fingerprint": certs[0].fingerprint if certs else None,
        "subject": None,
        "issuer": None,
        "key_public_sha256": None,
        "key_unreadable": False,
        "certificates_pem": pem_of(*certs) if certs else None,
    }
    values.update(overrides)
    return PathFacts(**values)


def key_facts(path: str, key=None, *, mode: str = "0600", **overrides) -> PathFacts:
    values = {
        "path": path,
        "exists": True,
        "readable": True,
        "owner": "root",
        "group": "ssl-cert",
        "mode": mode,
        "size": 300,
        "mtime": "2026-10-19T00:00:00Z",
        "fingerprint": None,
        "subject": None,
        "issuer": None,
        "key_public_sha256": public_key_sha256(key.public_key()) if key is not None else None,
        "key_unreadable": False,
        "certificates_pem": None,
    }
    values.update(overrides)
    return PathFacts(**values)


def missing_facts(path: str) -> PathFacts:
    return PathFacts(path, False, False, None, None, None, None, None, None, None, None, None, False, None)


def by_path(*facts: PathFacts) -> dict[str, PathFacts]:
    return {f.path: f for f in facts}


def nginx(cert_paths, key_paths, *, name="www.example.internal", port=443, config_file="/etc/nginx/conf.d/a.conf"):
    return ParsedBinding(
        WebserverType.NGINX, name, (name,), port, config_file, tuple(cert_paths), tuple(key_paths), None
    )


def apache(cert_paths, key_paths=(), chain=None, *, name="www.example.internal", port=443, cert_files=()):
    return ParsedBinding(
        WebserverType.APACHE,
        name,
        (name,),
        port,
        "/etc/apache2/sites-enabled/a.conf",
        tuple(cert_paths),
        tuple(key_paths),
        chain,
        tuple(cert_files),
    )


# ---------------------------------------------------------------- positional pairs and facts


def test_positional_pairs_become_separate_bindings():
    ca = issue("Test CA", ca=True)
    rsa_leaf = issue("www", ca, key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    ec_leaf = issue("www", ca)
    parsed = [nginx(["/c/rsa.crt", "/c/ec.crt"], ["/k/rsa.key", "/k/ec.key"])]
    facts = by_path(
        cert_facts("/c/rsa.crt", rsa_leaf),
        cert_facts("/c/ec.crt", ec_leaf),
        key_facts("/k/rsa.key", rsa_leaf.key),
        key_facts("/k/ec.key", ec_leaf.key),
    )

    bindings = assemble_bindings(parsed, facts)

    assert [(b["cert_path"], b["key_path"], b["chain_path"]) for b in bindings] == [
        ("/c/rsa.crt", "/k/rsa.key", None),
        ("/c/ec.crt", "/k/ec.key", None),
    ]
    assert [b["cert_fingerprint"] for b in bindings] == [rsa_leaf.fingerprint, ec_leaf.fingerprint]
    assert [b["key_public_sha256"] for b in bindings] == [
        public_key_sha256(rsa_leaf.key.public_key()),
        public_key_sha256(ec_leaf.key.public_key()),
    ]


def test_binding_carries_the_parser_fields_and_the_facts_of_each_path():
    leaf = issue("www")
    parsed = [
        nginx(["/c/www.crt"], ["/k/www.key"], name="www.example.internal", port=18443, config_file="/etc/nginx/x.conf")
    ]
    facts = by_path(
        cert_facts("/c/www.crt", leaf, owner="root", group="wheel", mode="0644"),
        key_facts("/k/www.key", leaf.key, mode="0600"),
    )

    (binding,) = assemble_bindings(parsed, facts)

    assert binding["webserver"] == "nginx"
    assert (binding["vhost_name"], binding["vhost_names"], binding["port"]) == (
        "www.example.internal",
        ["www.example.internal"],
        18443,
    )
    assert binding["config_file"] == "/etc/nginx/x.conf"
    assert (binding["cert_exists"], binding["cert_owner"], binding["cert_group"], binding["cert_mode"]) == (
        True,
        "root",
        "wheel",
        "0644",
    )
    assert (binding["key_exists"], binding["key_owner"], binding["key_group"], binding["key_mode"]) == (
        True,
        "root",
        "ssl-cert",
        "0600",
    )
    assert binding["key_unreadable"] is False
    assert binding["chain_diagnostic"] is None
    json.dumps(binding)  # plain JSON values only


def test_modes_are_octal_strings_and_fingerprints_lowercase_hex_without_colons():
    leaf = issue("www")
    colon_upper = ":".join(f"{b:02X}" for b in bytes.fromhex(leaf.fingerprint))
    parsed = [nginx(["/c/www.crt"], ["/k/www.key"])]
    facts = by_path(
        cert_facts("/c/www.crt", leaf, mode="644", fingerprint=colon_upper),
        key_facts("/k/www.key", leaf.key, mode="600"),
    )

    (binding,) = assemble_bindings(parsed, facts)

    assert binding["cert_mode"] == "0644" and binding["key_mode"] == "0600"
    assert binding["cert_fingerprint"] == leaf.fingerprint


def test_key_hash_is_lowercased_and_an_unreadable_key_reports_no_hash():
    leaf = issue("www")
    parsed = [nginx(["/c/www.crt"], ["/k/www.key"])]
    upper = key_facts("/k/www.key", leaf.key, key_public_sha256=public_key_sha256(leaf.key.public_key()).upper())
    unreadable = key_facts("/k/www.key", None, key_unreadable=True, readable=True)

    (hashed,) = assemble_bindings(parsed, by_path(cert_facts("/c/www.crt", leaf), upper))
    (locked,) = assemble_bindings(parsed, by_path(cert_facts("/c/www.crt", leaf), unreadable))

    assert hashed["key_public_sha256"] == public_key_sha256(leaf.key.public_key())
    assert hashed["key_unreadable"] is False
    assert locked["key_unreadable"] is True and locked["key_public_sha256"] is None
    assert locked["key_exists"] is True


def test_missing_facts_behave_as_not_existing():
    parsed = [nginx(["/c/gone.crt"], ["/k/gone.key"])]

    (absent,) = assemble_bindings(parsed, {})
    (reported,) = assemble_bindings(parsed, by_path(missing_facts("/c/gone.crt"), missing_facts("/k/gone.key")))

    for binding in (absent, reported):
        assert binding["cert_exists"] is False and binding["key_exists"] is False
        assert binding["cert_fingerprint"] is None and binding["key_public_sha256"] is None
        assert binding["cert_mode"] is None and binding["cert_owner"] is None
        assert binding["key_unreadable"] is False
        assert binding["chain_diagnostic"] is None


# ---------------------------------------------------------------- D1: file roles by signature


def test_single_certificate_file_is_one_binding_and_reports_the_missing_issuer():
    root = issue("Root", ca=True)
    leaf = issue("www", root)
    parsed = [nginx(["/c/www.crt"], ["/k/www.key"])]
    facts = by_path(cert_facts("/c/www.crt", leaf), key_facts("/k/www.key", leaf.key))

    (binding,) = assemble_bindings(parsed, facts)

    assert binding["chain_path"] is None
    # the leaf is not self-signed and no configured file holds its issuer
    assert binding["chain_diagnostic"] == INCOMPLETE


def test_self_signed_single_file_has_no_diagnostic():
    leaf = issue("self")
    parsed = [nginx(["/c/self.crt"], ["/k/self.key"])]

    (binding,) = assemble_bindings(parsed, by_path(cert_facts("/c/self.crt", leaf), key_facts("/k/self.key", leaf.key)))

    assert binding["chain_path"] is None and binding["chain_diagnostic"] is None


def test_bundle_leaf_plus_chain_stays_in_cert_path_without_diagnostic():
    root = issue("Root", ca=True)
    inter = issue("Intermediate", root, ca=True)
    leaf = issue("www", inter)
    parsed = [nginx(["/c/fullchain.pem"], ["/k/www.key"])]
    facts = by_path(cert_facts("/c/fullchain.pem", leaf, inter, root), key_facts("/k/www.key", leaf.key))

    (binding,) = assemble_bindings(parsed, facts)

    assert binding["cert_path"] == "/c/fullchain.pem"
    assert binding["chain_path"] is None
    assert binding["chain_diagnostic"] is None
    assert binding["cert_fingerprint"] == leaf.fingerprint


def test_rsa_and_ecdsa_certificates_of_one_issuer_are_two_bindings_not_cert_plus_chain():
    ca = issue("Shared CA", ca=True)
    rsa_leaf = issue("www", ca, key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    ec_leaf = issue("www", ca)
    parsed = [apache(["/c/rsa.crt", "/c/ec.crt"], ["/k/rsa.key", "/k/ec.key"])]
    facts = by_path(
        cert_facts("/c/rsa.crt", rsa_leaf),
        cert_facts("/c/ec.crt", ec_leaf),
        key_facts("/k/rsa.key", rsa_leaf.key),
        key_facts("/k/ec.key", ec_leaf.key),
    )

    bindings = assemble_bindings(parsed, facts)

    assert [(b["cert_path"], b["key_path"], b["chain_path"]) for b in bindings] == [
        ("/c/rsa.crt", "/k/rsa.key", None),
        ("/c/ec.crt", "/k/ec.key", None),
    ]
    assert all(b["chain_diagnostic"] == INCOMPLETE for b in bindings)


def test_chain_file_with_the_root_included_is_accepted_as_chain_path():
    root = issue("Root", ca=True)
    inter = issue("Intermediate", root, ca=True)
    leaf = issue("www", inter)
    parsed = [apache(["/c/www.crt"], ["/k/www.key"], chain="/c/chain.pem")]
    facts = by_path(
        cert_facts("/c/www.crt", leaf),
        cert_facts("/c/chain.pem", inter, root),
        key_facts("/k/www.key", leaf.key),
    )

    (binding,) = assemble_bindings(parsed, facts)

    assert binding["chain_path"] == "/c/chain.pem"
    assert binding["chain_diagnostic"] is None
    assert binding["cert_fingerprint"] == leaf.fingerprint  # the chain never replaces the leaf


def test_chain_file_holding_only_the_root_that_signed_the_leaf_is_accepted():
    root = issue("Root", ca=True)
    leaf = issue("www", root)
    parsed = [apache(["/c/www.crt"], ["/k/www.key"], chain="/c/root.pem")]
    facts = by_path(cert_facts("/c/www.crt", leaf), cert_facts("/c/root.pem", root), key_facts("/k/www.key", leaf.key))

    (binding,) = assemble_bindings(parsed, facts)

    assert binding["chain_path"] == "/c/root.pem" and binding["chain_diagnostic"] is None


def test_unreadable_chain_file_is_not_a_chain_and_is_diagnosed():
    root = issue("Root", ca=True)
    leaf = issue("www", root)
    parsed = [apache(["/c/www.crt"], ["/k/www.key"], chain="/c/chain.pem")]
    for chain_facts in (
        missing_facts("/c/chain.pem"),
        cert_facts("/c/chain.pem", root, readable=False, certificates_pem=None),
        cert_facts("/c/chain.pem", root, certificates_pem="not a certificate"),
    ):
        facts = by_path(cert_facts("/c/www.crt", leaf), chain_facts, key_facts("/k/www.key", leaf.key))

        (binding,) = assemble_bindings(parsed, facts)

        assert binding["chain_path"] is None
        assert CHAIN_UNREADABLE in binding["chain_diagnostic"]
        assert INCOMPLETE in binding["chain_diagnostic"]


def test_incomplete_chain_is_diagnosed_when_the_issuer_is_in_no_file():
    root = issue("Root", ca=True)
    inter = issue("Intermediate", root, ca=True)
    leaf = issue("www", inter)
    other = issue("Other CA", ca=True)
    parsed = [apache(["/c/www.crt"], ["/k/www.key"], chain="/c/chain.pem")]
    facts = by_path(
        cert_facts("/c/www.crt", leaf), cert_facts("/c/chain.pem", other), key_facts("/k/www.key", leaf.key)
    )

    (binding,) = assemble_bindings(parsed, facts)

    assert binding["chain_path"] is None
    assert binding["chain_diagnostic"] == f"{INCOMPLETE}; {CHAIN_NOT_VERIFYING}"


def test_forged_issuer_with_equal_dn_but_invalid_signature_is_not_a_chain():
    real_ca = issue("Test CA", ca=True)
    forged_ca = issue("Test CA", ca=True)  # same DN, different key
    leaf = issue("www", real_ca)
    parsed = [apache(["/c/www.crt"], ["/k/www.key"], chain="/c/chain.pem")]
    facts = by_path(
        cert_facts("/c/www.crt", leaf), cert_facts("/c/chain.pem", forged_ca), key_facts("/k/www.key", leaf.key)
    )

    (binding,) = assemble_bindings(parsed, facts)

    assert binding["chain_path"] is None
    assert CHAIN_NOT_VERIFYING in binding["chain_diagnostic"]


def test_forged_issuer_inside_a_bundle_is_not_a_chain():
    real_ca = issue("Test CA", ca=True)
    forged_ca = issue("Test CA", ca=True)
    leaf = issue("www", real_ca)
    parsed = [nginx(["/c/bundle.pem"], ["/k/www.key"])]
    facts = by_path(cert_facts("/c/bundle.pem", leaf, forged_ca), key_facts("/k/www.key", leaf.key))

    (binding,) = assemble_bindings(parsed, facts)

    assert binding["chain_diagnostic"] == f"{INCOMPLETE}; {BUNDLE_BROKEN}"


def test_bundle_with_an_unrelated_later_certificate_is_diagnosed():
    root = issue("Root", ca=True)
    leaf = issue("www", root)
    stranger = issue("Stranger", ca=True)
    parsed = [nginx(["/c/bundle.pem"], ["/k/www.key"])]
    facts = by_path(cert_facts("/c/bundle.pem", leaf, stranger), key_facts("/k/www.key", leaf.key))

    (binding,) = assemble_bindings(parsed, facts)

    assert binding["chain_path"] is None
    assert BUNDLE_BROKEN in binding["chain_diagnostic"]


def test_apache_extra_certificate_file_that_signs_the_leaf_becomes_chain_path_not_a_binding():
    root = issue("Root", ca=True)
    inter = issue("Intermediate", root, ca=True)
    leaf = issue("www", inter)
    parsed = [apache(["/c/www.crt", "/c/inter.crt"], ["/k/www.key"])]
    facts = by_path(
        cert_facts("/c/www.crt", leaf), cert_facts("/c/inter.crt", inter), key_facts("/k/www.key", leaf.key)
    )

    (binding,) = assemble_bindings(parsed, facts)

    assert (binding["cert_path"], binding["chain_path"], binding["key_path"]) == (
        "/c/www.crt",
        "/c/inter.crt",
        "/k/www.key",
    )
    assert binding["chain_diagnostic"] is None


def test_apache_chain_candidate_signing_both_leaves_is_the_chain_of_both_bindings():
    ca = issue("Shared CA", ca=True)
    rsa_leaf = issue("www", ca, key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    ec_leaf = issue("www", ca)
    parsed = [apache(["/c/rsa.crt", "/c/ec.crt"], ["/k/rsa.key", "/k/ec.key"], chain="/c/ca.pem")]
    facts = by_path(
        cert_facts("/c/rsa.crt", rsa_leaf),
        cert_facts("/c/ec.crt", ec_leaf),
        cert_facts("/c/ca.pem", ca),
        key_facts("/k/rsa.key", rsa_leaf.key),
        key_facts("/k/ec.key", ec_leaf.key),
    )

    bindings = assemble_bindings(parsed, facts)

    assert [(b["cert_path"], b["chain_path"], b["chain_diagnostic"]) for b in bindings] == [
        ("/c/rsa.crt", "/c/ca.pem", None),
        ("/c/ec.crt", "/c/ca.pem", None),
    ]


def test_apache_chain_file_that_verifies_no_leaf_is_neither_chain_nor_binding():
    ca = issue("Shared CA", ca=True)
    leaf = issue("www", ca)
    stranger = issue("Stranger", ca=True)
    parsed = [apache(["/c/www.crt"], ["/k/www.key"], chain="/c/stranger.pem")]
    facts = by_path(
        cert_facts("/c/www.crt", leaf), cert_facts("/c/stranger.pem", stranger), key_facts("/k/www.key", leaf.key)
    )

    bindings = assemble_bindings(parsed, facts)

    assert [b["cert_path"] for b in bindings] == ["/c/www.crt"]
    assert bindings[0]["chain_path"] is None
    assert CHAIN_NOT_VERIFYING in bindings[0]["chain_diagnostic"]


def test_apache_certificate_without_its_own_key_directive_uses_the_certificate_file_as_key():
    ca = issue("Shared CA", ca=True)
    first = issue("www", ca)
    second = issue("www", ca)
    parsed = [apache(["/c/first.crt", "/c/second.pem"], ["/k/first.key"])]
    facts = by_path(
        cert_facts("/c/first.crt", first),
        cert_facts("/c/second.pem", second, key_public_sha256=public_key_sha256(second.key.public_key())),
        key_facts("/k/first.key", first.key),
    )

    first_binding, second_binding = assemble_bindings(parsed, facts)

    assert first_binding["key_path"] == "/k/first.key"
    assert second_binding["key_path"] == "/c/second.pem"
    assert second_binding["key_public_sha256"] == public_key_sha256(second.key.public_key())


def test_unreadable_extra_certificate_file_is_never_a_chain_and_stays_its_own_binding():
    ca = issue("Shared CA", ca=True)
    leaf = issue("www", ca)
    parsed = [apache(["/c/www.crt", "/c/extra.crt"], ["/k/www.key", "/k/extra.key"])]
    facts = by_path(
        cert_facts("/c/www.crt", leaf), missing_facts("/c/extra.crt"), key_facts("/k/www.key", leaf.key)
    )

    bindings = assemble_bindings(parsed, facts)

    assert [(b["cert_path"], b["chain_path"], b["cert_exists"]) for b in bindings] == [
        ("/c/www.crt", None, True),
        ("/c/extra.crt", None, False),
    ]


def test_apache_bindings_report_the_configuration_file_of_each_certificate_directive():
    ca = issue("Shared CA", ca=True)
    first = issue("www", ca)
    second = issue("www", ca)
    parsed = [
        apache(
            ["/c/first.crt", "/c/second.crt"],
            ["/k/first.key", "/k/second.key"],
            cert_files=("/etc/apache2/a.conf", "/etc/apache2/conf-enabled/ec.conf"),
        )
    ]
    facts = by_path(
        cert_facts("/c/first.crt", first),
        cert_facts("/c/second.crt", second),
        key_facts("/k/first.key", first.key),
        key_facts("/k/second.key", second.key),
    )

    bindings = assemble_bindings(parsed, facts)

    assert [b["config_file"] for b in bindings] == ["/etc/apache2/a.conf", "/etc/apache2/conf-enabled/ec.conf"]


def test_nginx_never_reports_a_chain_path_even_for_a_bundle_in_a_second_certificate_file():
    root = issue("Root", ca=True)
    leaf = issue("www", root)
    parsed = [nginx(["/c/www.crt", "/c/root.crt"], ["/k/www.key", "/k/root.key"])]
    facts = by_path(
        cert_facts("/c/www.crt", leaf),
        cert_facts("/c/root.crt", root),
        key_facts("/k/www.key", leaf.key),
        key_facts("/k/root.key", root.key),
    )

    bindings = assemble_bindings(parsed, facts)

    assert [(b["cert_path"], b["chain_path"]) for b in bindings] == [("/c/www.crt", None), ("/c/root.crt", None)]


def test_diagnostics_never_contain_paths_or_pem():
    root = issue("Root", ca=True)
    leaf = issue("www", root)
    forged = issue("Root", ca=True)
    parsed = [apache(["/c/secret-dir/www.crt"], ["/k/www.key"], chain="/c/secret-dir/chain.pem")]
    facts = by_path(
        cert_facts("/c/secret-dir/www.crt", leaf),
        cert_facts("/c/secret-dir/chain.pem", forged),
        key_facts("/k/www.key", leaf.key),
    )

    (binding,) = assemble_bindings(parsed, facts)

    assert "secret-dir" not in binding["chain_diagnostic"] and "BEGIN" not in binding["chain_diagnostic"]


def test_apache_sibling_leaf_bundled_with_its_intermediate_is_not_swallowed_as_a_chain():
    root = issue("Root", ca=True)
    inter = issue("Intermediate", root, ca=True)
    rsa_leaf = issue("www", inter, key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    ec_leaf = issue("www", inter)
    parsed = [apache(["/c/rsa.crt", "/c/ec-bundle.pem"], ["/k/rsa.key", "/k/ec.key"])]
    facts = by_path(
        cert_facts("/c/rsa.crt", rsa_leaf),
        cert_facts("/c/ec-bundle.pem", ec_leaf, inter),  # the intermediate inside also signed the RSA leaf
        key_facts("/k/rsa.key", rsa_leaf.key),
        key_facts("/k/ec.key", ec_leaf.key),
    )

    bindings = assemble_bindings(parsed, facts)

    assert [(b["cert_path"], b["chain_path"]) for b in bindings] == [
        ("/c/rsa.crt", None),
        ("/c/ec-bundle.pem", None),
    ]
    assert bindings[1]["chain_diagnostic"] is None  # a verified leaf+intermediate bundle
