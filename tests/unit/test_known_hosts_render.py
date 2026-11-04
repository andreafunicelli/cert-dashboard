"""The effective known_hosts renderer (Slice B contract §7.4, §7.5; card W, decision D2).

Effective trust per job = the mounted file (read only, never written) followed by one line per
dashboard-trusted host key. The renderer produces the bytes the job stages as ``known_hosts`` (0600,
removed on exit) and is used for Ansible SSH and Git over SSH alike.
"""

import pytest

from app.services.inventory_sources import HostKey, InventoryRenderError, render_known_hosts

ED25519 = "AAAAC3NzaC1lZDI1NTE5AAAAIB7J0m1c0V3S1l0shV3Jq0cVx0Yb3jK0oQ8m3o1x0V3S"
RSA = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7V3m0c0V3S1l0shV3Jq0cVx0Yb3jK0oQ8m3o1x0V3S"
MOUNTED = b"web01.example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAImounted\n"


def key(host, key_type="ssh-ed25519", public_key=ED25519):
    return HostKey(host, key_type, public_key)


def test_no_mounted_content_and_no_rows_means_nothing_to_trust():
    assert render_known_hosts(None, []) == b""
    assert render_known_hosts(b"", []) == b""


def test_the_mounted_file_alone_is_used_unchanged():
    assert render_known_hosts(MOUNTED, []) == MOUNTED


def test_rows_alone_render_one_exact_line_each():
    assert render_known_hosts(None, [key("web01.example.test")]) == (
        f"web01.example.test ssh-ed25519 {ED25519}\n".encode()
    )


def test_the_mounted_file_comes_first_and_then_every_row():
    text = render_known_hosts(MOUNTED, [key("db01.example.test", "ssh-rsa", RSA)])
    assert text == MOUNTED + f"db01.example.test ssh-rsa {RSA}\n".encode()


def test_a_mounted_file_without_a_final_newline_does_not_run_into_the_first_row():
    text = render_known_hosts(b"web01.example.test ssh-ed25519 AAAAmounted", [key("db01.example.test")])
    assert text == (
        b"web01.example.test ssh-ed25519 AAAAmounted\n"
        + f"db01.example.test ssh-ed25519 {ED25519}\n".encode()
    )


def test_rows_are_sorted_by_host_and_key_type_regardless_of_input_order():
    rows = [
        key("web02.example.test", "ssh-rsa", RSA),
        key("web01.example.test", "ssh-rsa", RSA),
        key("web01.example.test", "ssh-ed25519"),
    ]
    first = render_known_hosts(None, rows)
    second = render_known_hosts(None, list(reversed(rows)))
    assert first == second
    assert first.decode().splitlines() == [
        f"web01.example.test ssh-ed25519 {ED25519}",
        f"web01.example.test ssh-rsa {RSA}",
        f"web02.example.test ssh-rsa {RSA}",
    ]


def test_a_port_qualified_host_token_is_rendered_as_stored():
    assert render_known_hosts(None, [key("[web01.example.test]:2222")]) == (
        f"[web01.example.test]:2222 ssh-ed25519 {ED25519}\n".encode()
    )


@pytest.mark.parametrize(
    "value",
    ["bad host", "bad\nhost", "-bad.example.test", "", "web01.example.test ssh-ed25519"],
)
def test_unsafe_hosts_are_refused(value):
    with pytest.raises(InventoryRenderError):
        render_known_hosts(None, [key(value)])


@pytest.mark.parametrize("value", ["ssh-dss", "sk-ssh-ed25519@openssh.com", "ssh-ed25519\n", "-ssh-rsa"])
def test_unsupported_or_unsafe_key_types_are_refused(value):
    with pytest.raises(InventoryRenderError):
        render_known_hosts(None, [key("web01.example.test", value)])


@pytest.mark.parametrize("value", ["", "not base64", "AAA\nBBB", "-AAAA"])
def test_unsafe_public_keys_are_refused(value):
    with pytest.raises(InventoryRenderError):
        render_known_hosts(None, [key("web01.example.test", "ssh-ed25519", value)])


def test_a_duplicated_host_and_type_is_refused():
    with pytest.raises(InventoryRenderError):
        render_known_hosts(None, [key("web01.example.test"), key("web01.example.test")])
