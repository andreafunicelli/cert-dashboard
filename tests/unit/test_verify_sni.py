"""Task 9: the SNI used to reach a binding's vhost (Contract decision 11)."""

import pytest

from app.services.bindings import verify_sni


def test_plain_vhost_name_is_the_sni():
    assert verify_sni("www.example.internal", ["www.example.internal", "example.internal"]) == "www.example.internal"


def test_wildcard_name_is_skipped_for_the_first_plain_alias():
    assert verify_sni("*.example.internal", ["*.example.internal", "www.example.internal"]) == "www.example.internal"


@pytest.mark.parametrize("placeholder", ["default", "_", ""])
def test_default_and_underscore_are_not_names(placeholder):
    assert verify_sni(placeholder, [placeholder]) is None
    assert verify_sni(placeholder, [placeholder, "app.example.internal"]) == "app.example.internal"


@pytest.mark.parametrize("literal", ["192.0.2.10", "2001:db8::1", "[2001:db8::1]"])
def test_ip_literals_are_not_names(literal):
    assert verify_sni(literal, [literal]) is None


def test_first_plain_name_wins_over_later_ones():
    assert verify_sni("default", ["*.example.internal", "b.example.internal", "a.example.internal"]) == "b.example.internal"


def test_no_plain_name_gives_none():
    assert verify_sni("*.example.internal", ["*.example.internal", "_", "10.0.0.1"]) is None


def test_names_with_unsafe_characters_are_skipped():
    assert verify_sni("bad name", ["bad name", "a/b", "ok.example.internal"]) == "ok.example.internal"
