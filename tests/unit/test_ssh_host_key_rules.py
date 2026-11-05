"""Trusted host key rules (Slice B contract §6, rules 1–10): the pure parser, no database.

The key fixtures are fixed: their SHA-256 fingerprints below were produced with
``ssh-keygen -lf`` on the corresponding ``.pub`` lines, so a fingerprint test proves the
``SHA256:`` + unpadded base64 format the contract requires.
"""

import pytest

from app.services.ssh_host_keys import (
    ACCEPTED_KEY_TYPES,
    MAX_PASTE_BYTES,
    HostKeyValidationError,
    parse_host_keys,
)

ED25519 = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
)
ED25519_FP = "SHA256:lbmsoA0yIEcEiVDRnMWuzm+nV+3ZEEpVIURqFoeSspg"
ED25519_ALT = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU"
)
ED25519_ALT_FP = "SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4"
ECDSA256 = (
    "ecdsa-sha2-nistp256 "
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCkZ3Ha5Z8u1e4O0XudXdtC1aZjc"
    "JURwNRitr4tzqEbv+BDdyvU46KYcZ3FYekJazDGXsRrG9ghsCwyfVOm6F1I="
)
ECDSA256_FP = "SHA256:wJoy5NygV5xD8+o5777f+8GCFnl3PU47e9Fo86eVaLE"
RSA3072 = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDldI9449gAz7AbLf401ZYTWtJhPt0q9fhoUQIy/BhU1/U0"
    "cFkH4gX4QB4RLlM6jmNfiUxQIoAQtmGkXJgbtZRzSIfuV6/0UuCiID7BYFwTL+g4xFakxGTijQqPAUJxVJmTb"
    "562e41MHDBTF6hyz0AaAEKTbLzENiyL33qtOUJ17f3cDpIyK8MaXon6K/f0sABAtmW2NeU/OO9uuXMgPqCRNO"
    "yVwL3MG5yCq8VVHiKeMzdY4F4lVHa8FeHKsEdEWNHMSthuQwqpPQ9EpRP+GzHbdny7nOICcvMLx7+CYd4sCo"
    "CQVT5CbF3viscWq7xr/I/r193mZrTclSm6Q6rkt2Qw3gbJrMSIgwi66LjPwwzESH1u1ygNe6KNuNNdEOFZXuY"
    "3892n0uFKsfcFYzn5FWxxLRcJ2ARm9ehJKFeqZ8SENOH8ex61fDOhWjDq/sPSWspY2UuMgr3/m8bkLtnrxAwb"
    "zRzD5SJXQIdLgSfK/KvMh+UuRV6HCvCmMjF3TqAeXHs= fixture-rsa3072"
)
RSA3072_FP = "SHA256:tb3+Woam4pRweJHGKqrFz+TW3blN0jXY1vVOGfMWc3I"
RSA1024 = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDq9UzFE1rPcfRxEa+NmgGYgyZqHspg75RDBbvKolcbqQKWq2"
    "SddRgC27QDLK3JvpnLxq2QtJDYY94AAumS3os5WDmRxDBB+L9x8xZpsBB4SCZ2il02dkj5PafSJ7aqakCGaw"
    "WZXIoE3nhqYnmvzCqogEVbFb2Bx+t61ZwcX9i2Tw== fixture-rsa1024"
)
PRIVATE_KEY_PASTE = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "QyNTUxOQAAACD0fixture0fixture0fixture0fixture0fixture0fixture0fixtureAAAAA\n"
    "-----END OPENSSH PRIVATE KEY-----"
)

PASTE_COUNT = "Paste between 1 and 20 host keys."
PRIVATE_KEY = (
    "This looks like a private key. Paste the host's public key (for example the output of "
    "ssh-keyscan); private keys are never accepted here."
)
HOST_REQUIRED = "Enter the host this key belongs to."
MARKERS = "Certificate-authority and revoked entries are not supported."
HASHED = "Hashed host names are not supported; run ssh-keyscan without -H."
PATTERNS = "Host patterns are not supported; list each host."
UNSUPPORTED = (
    "Unsupported key type {key_type}. Accepted: ssh-ed25519, ecdsa-sha2-nistp256, "
    "ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-rsa."
)
BAD_BASE64 = "The key data is not valid base64."
TYPE_MISMATCH = "The key data does not match its type {key_type}."
RSA_SHORT = "RSA host keys shorter than 2048 bits are refused."
BAD_HOST = (
    "Use letters, digits, dots, hyphens or underscores (or an IP address); "
    "a label cannot start or end with a hyphen."
)
TOO_MANY_HOSTS = "At most 20 hosts per line."
BAD_PORT = "Host ports must be between 1 and 65535."
VERIFIED = "Confirm that you verified the fingerprints with the server before trusting them."
COMMENT_TOO_LONG = "Comment must be at most 100 characters."


def parse(entries: str, hosts: str = "", comment: str = ""):
    return parse_host_keys(entries, hosts=hosts, comment=comment)


def refused(entries: str, hosts: str = "", comment: str = "") -> HostKeyValidationError:
    with pytest.raises(HostKeyValidationError) as caught:
        parse(entries, hosts=hosts, comment=comment)
    return caught.value


def entries_errors(error: HostKeyValidationError) -> list[str]:
    return error.errors["entries"]


def line_one(message: str) -> list[str]:
    """Rule 9: every per-line refusal is listed as ``Line <n>: <message>``."""
    return [f"Line 1: {message}"]


# --- accepted formats and fingerprints -------------------------------------------------------------


def test_trust_store_accepts_the_contract_key_types():
    assert ACCEPTED_KEY_TYPES == (
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-rsa",
    )


def test_ssh_keyscan_line_parses_host_and_fingerprint():
    [key] = parse(f"web01.example.test {ED25519}")
    assert key.host == "web01.example.test"
    assert key.key_type == "ssh-ed25519"
    assert key.fingerprint_sha256 == ED25519_FP
    assert key.public_key == ED25519.split()[1]


def test_public_key_line_uses_the_hosts_field_and_lower_cases_it():
    [key] = parse(ED25519, hosts="Web01.Example.Test")
    assert key.host == "web01.example.test"
    assert key.fingerprint_sha256 == ED25519_FP


def test_fingerprints_match_ssh_keygen_for_every_accepted_family():
    [ed] = parse(ED25519, hosts="ed.example.test")
    [ecdsa] = parse(ECDSA256, hosts="ecdsa.example.test")
    [rsa] = parse(RSA3072, hosts="rsa.example.test")
    assert (ed.fingerprint_sha256, ecdsa.fingerprint_sha256, rsa.fingerprint_sha256) == (
        ED25519_FP,
        ECDSA256_FP,
        RSA3072_FP,
    )


def test_one_line_can_name_several_hosts():
    keys = parse(f"a.example.test,b.example.test {ED25519}")
    assert [key.host for key in keys] == ["a.example.test", "b.example.test"]
    assert {key.public_key for key in keys} == {ED25519.split()[1]}


def test_port_22_is_normalized_and_other_ports_are_kept():
    [normalized] = parse(f"[Web01.Example.Test]:22 {ED25519}")
    [kept] = parse(f"[Web01.Example.Test]:2222 {ED25519}")
    [ipv6] = parse(f"[2001:DB8::1]:2222 {ED25519}")
    assert normalized.host == "web01.example.test"
    assert kept.host == "[web01.example.test]:2222"
    assert ipv6.host == "[2001:db8::1]:2222"


def test_ipv6_literal_without_a_bracketed_port_is_accepted():
    [key] = parse(ED25519, hosts="2001:DB8::1")
    assert key.host == "2001:db8::1"


def test_comment_field_wins_and_a_line_comment_is_the_fallback():
    [from_line] = parse(f"web01.example.test {ED25519} lab host")
    [overridden] = parse(f"web01.example.test {ED25519} lab host", comment="from the form")
    [none] = parse(f"web01.example.test {ED25519}")
    assert from_line.comment == "lab host"
    assert overridden.comment == "from the form"
    assert none.comment is None


def test_comment_lines_and_blank_lines_are_ignored():
    keys = parse(f"# ssh-keyscan web01\n\nweb01.example.test {ED25519}\n")
    assert len(keys) == 1


# --- rule 1: count and size ------------------------------------------------------------------------


def test_empty_paste_is_refused():
    assert entries_errors(refused("")) == [PASTE_COUNT]


def test_only_blank_and_comment_lines_are_refused():
    assert entries_errors(refused("\n# nothing here\n\n")) == [PASTE_COUNT]


def test_more_than_twenty_lines_are_refused():
    lines = "\n".join(f"host{number}.example.test {ED25519}" for number in range(21))
    assert entries_errors(refused(lines)) == [PASTE_COUNT]


def test_oversized_paste_is_refused():
    huge = "x" * (MAX_PASTE_BYTES + 1)
    assert entries_errors(refused(huge)) == [PASTE_COUNT]


# --- rule 2: private keys --------------------------------------------------------------------------


def test_private_key_paste_is_refused_discarded_and_never_echoed():
    error = refused(PRIVATE_KEY_PASTE)
    assert error.discard_paste is True
    assert entries_errors(error) == [PRIVATE_KEY]
    assert PRIVATE_KEY_PASTE not in str(error)


def test_private_key_marker_is_refused_anywhere_and_in_any_case():
    error = refused(f"web01.example.test {ED25519} -----begin private key-----")
    assert error.discard_paste is True
    assert entries_errors(error) == [PRIVATE_KEY]


# --- rule 3: formats -------------------------------------------------------------------------------


def test_public_key_format_without_hosts_is_refused():
    assert entries_errors(refused(ED25519)) == line_one(HOST_REQUIRED)


def test_public_key_format_with_an_empty_hosts_list_is_refused():
    assert entries_errors(refused(ED25519, hosts=" , ")) == line_one(HOST_REQUIRED)


# --- rule 4: markers and hashed names --------------------------------------------------------------


@pytest.mark.parametrize("marker", ["@cert-authority", "@revoked"])
def test_known_hosts_markers_are_refused(marker):
    assert entries_errors(refused(f"{marker} web01.example.test {ED25519}")) == line_one(MARKERS)


def test_hashed_host_names_are_refused():
    assert entries_errors(refused(f"|1|fixturesalt=|fixturehash= {ED25519}")) == line_one(HASHED)


# --- rule 5: host tokens ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["*.example.test", "web0?.example.test", "!bad.example.test"])
def test_host_patterns_are_refused(host):
    assert entries_errors(refused(f"{host} {ED25519}")) == line_one(PATTERNS)


@pytest.mark.parametrize(
    "host", ["-bad.example.test", "bad-.example.test", "a..b", "a" * 64, "bad_host..x"]
)
def test_invalid_hosts_are_refused(host):
    assert entries_errors(refused(f"{host} {ED25519}")) == line_one(BAD_HOST)


def test_more_than_twenty_hosts_on_a_line_are_refused():
    hosts = ",".join(f"host{number}.example.test" for number in range(21))
    assert entries_errors(refused(f"{hosts} {ED25519}")) == line_one(TOO_MANY_HOSTS)


def test_port_out_of_range_is_refused():
    assert entries_errors(refused(f"[web01.example.test]:0 {ED25519}")) == line_one(BAD_PORT)
    assert entries_errors(refused(f"[web01.example.test]:65536 {ED25519}")) == line_one(BAD_PORT)


# --- rule 6: key types -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key_type", ["ssh-dss", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"]
)
def test_unsupported_key_types_are_refused(key_type):
    assert entries_errors(refused(f"web01.example.test {key_type} AAAAB3NzaC1yc2E=")) == line_one(
        UNSUPPORTED.format(key_type=key_type)
    )


def test_unsupported_key_type_in_public_key_format_is_refused():
    assert entries_errors(refused("ssh-dss AAAA", hosts="web01.example.test")) == line_one(
        UNSUPPORTED.format(key_type="ssh-dss")
    )


# --- rule 7: the key data --------------------------------------------------------------------------


def test_bad_base64_is_refused():
    assert entries_errors(refused(f"web01.example.test {ED25519.split()[0]} not%base64!")) == line_one(
        BAD_BASE64
    )


def test_truncated_base64_is_refused():
    assert entries_errors(refused(f"web01.example.test {ED25519.split()[0]} AAAAA")) == line_one(
        BAD_BASE64
    )


def test_type_mismatch_is_refused():
    ed25519_blob = ED25519.split()[1]
    assert entries_errors(refused(f"web01.example.test ssh-rsa {ed25519_blob}")) == line_one(
        TYPE_MISMATCH.format(key_type="ssh-rsa")
    )


def test_rsa_shorter_than_2048_bits_is_refused():
    assert entries_errors(refused(f"web01.example.test {RSA1024}")) == line_one(RSA_SHORT)


# --- rule 8: duplicates inside one paste ------------------------------------------------------------


def test_identical_lines_in_one_paste_collapse_silently():
    keys = parse(f"web01.example.test {ED25519}\nweb01.example.test {ED25519}")
    assert len(keys) == 1


def test_conflicting_lines_in_one_paste_are_refused():
    error = refused(f"web01.example.test {ED25519}\nweb01.example.test {ED25519_ALT}")
    assert entries_errors(error) == [
        (
            "Line 2: web01.example.test already has a different trusted ssh-ed25519 key "
            f"({ED25519_FP}). If the host key was rotated, delete the old key first."
        )
    ]


# --- rule 9: all-or-nothing -------------------------------------------------------------------------


def test_errors_are_listed_with_their_line_numbers():
    error = refused(f"web01.example.test {ED25519}\nweb02.example.test ssh-rsa {ED25519.split()[1]}")
    assert entries_errors(error) == [f"Line 2: {TYPE_MISMATCH.format(key_type='ssh-rsa')}"]


def test_several_failing_lines_are_all_reported_in_order():
    error = refused(
        f"web01.example.test ssh-dss AAAA\nweb02.example.test {ED25519}\n"
        f"web03.example.test ssh-ed25519 not%base64!"
    )
    assert entries_errors(error) == [
        f"Line 1: {UNSUPPORTED.format(key_type='ssh-dss')}",
        f"Line 3: {BAD_BASE64}",
    ]


def test_too_long_comment_is_refused():
    assert refused(f"web01.example.test {ED25519}", comment="x" * 101).errors == {
        "comment": [COMMENT_TOO_LONG]
    }


def test_verified_message_is_part_of_the_documented_rules():
    # The web transaction adds rule 10; the constant lives here so both layers share one text.
    from app.services import ssh_host_keys

    assert ssh_host_keys.VERIFIED_MESSAGE == VERIFIED


def test_a_valid_paste_returns_every_key_and_no_error():
    keys = parse(f"web01.example.test {ED25519}\nweb02.example.test {RSA3072}")
    assert [key.host for key in keys] == ["web01.example.test", "web02.example.test"]
