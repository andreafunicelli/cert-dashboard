"""The ``worker.start`` read model: effective startup flags versus explicit mounted-file provenance.

The effective ``*_present`` booleans answer "did the worker hold this when it started, from the
database or from a file". They are *not* proof of a file: the web process reads the database live, so
a credential stored only in the database and deleted after startup must stop being reported as
present. These tests pin the second family, ``*_file_present``, which only a current worker report
carries — a report from an older release leaves it unknown, and unknown is never read as "mounted".
"""

from __future__ import annotations

import pytest

from app.jobs.worker import WorkerCapabilities, _capabilities_from_details


def _details(**overrides):
    """A current ``worker.start`` report: the four effective flags and the three file flags."""
    details = {
        "worker_id": "worker-1",
        "ssh_key_present": False,
        "known_hosts_present": True,
        "vault_password_present": False,
        "inventory_token_present": False,
        "ssh_key_file_present": False,
        "vault_password_file_present": False,
        "inventory_token_file_present": False,
    }
    details.update(overrides)
    return details


def test_a_current_report_carries_the_effective_and_the_file_provenance_separately():
    capabilities = _capabilities_from_details(
        _details(
            ssh_key_present=True,
            ssh_key_file_present=False,
            vault_password_present=True,
            vault_password_file_present=True,
        )
    )

    assert capabilities == WorkerCapabilities(
        "worker-1",
        True,
        True,
        True,
        False,
        ssh_key_file_present=False,
        vault_password_file_present=True,
        inventory_token_file_present=False,
    )
    # A database-held key is effective at startup but it is not a mounted file.
    assert capabilities.ssh_key_present is True and capabilities.ssh_key_file_present is False


def test_a_legacy_report_leaves_the_file_provenance_unknown():
    legacy = {
        key: value for key, value in _details(ssh_key_present=True, vault_password_present=True).items()
        if not key.endswith("_file_present")
    }

    capabilities = _capabilities_from_details(legacy)

    # The old effective booleans keep their meaning, so a reader that only asks "can this worker run
    # jobs" is unaffected; the provenance stays unknown instead of being invented from them.
    assert capabilities.ssh_key_present is True and capabilities.vault_password_present is True
    assert capabilities.ssh_key_file_present is None
    assert capabilities.vault_password_file_present is None
    assert capabilities.inventory_token_file_present is None


@pytest.mark.parametrize("value", ["true", 1, 0, {}, [], None])
def test_a_non_boolean_provenance_value_is_unknown_rather_than_a_mounted_file(value):
    capabilities = _capabilities_from_details(_details(ssh_key_file_present=value))

    assert capabilities.ssh_key_file_present is None
