import dataclasses

import pytest

from app.services.deploy import DeployTarget, FileConflict, FileWrite, plan_file_writes

NEW = "b" * 64


def _target(binding_id, cert, key, *, chain=None, new=NEW, expected="a" * 64, port=443, sni=None):
    return DeployTarget(
        binding_id=binding_id,
        cert_path=cert,
        chain_path=chain,
        key_path=key,
        expected_fingerprint=expected,
        new_fingerprint=new,
        port=port,
        sni=sni,
    )


def _as_tuples(writes):
    return [(w.path, w.kind, w.binding_ids) for w in writes]


def test_a_single_binding_without_chain_path_writes_the_full_chain_and_the_key():
    writes = plan_file_writes([_target(1, "/etc/ssl/www.crt", "/etc/ssl/www.key")])
    assert _as_tuples(writes) == [
        ("/etc/ssl/www.crt", "fullchain", (1,)),
        ("/etc/ssl/www.key", "key", (1,)),
    ]


def test_bindings_sharing_a_certificate_path_produce_one_fullchain_write_and_two_key_writes():
    writes = plan_file_writes(
        [
            _target(2, "/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/legacy.key"),
            _target(1, "/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key"),
        ]
    )
    assert _as_tuples(writes) == [
        ("/etc/nginx/ssl/legacy.key", "key", (2,)),
        ("/etc/nginx/ssl/www.crt", "fullchain", (1, 2)),
        ("/etc/nginx/ssl/www.key", "key", (1,)),
    ]


def test_a_binding_with_a_chain_path_writes_leaf_and_chain():
    writes = plan_file_writes(
        [
            _target(
                1,
                "/etc/apache2/ssl/www.crt",
                "/etc/apache2/ssl/www.key",
                chain="/etc/apache2/ssl/www.chain.pem",
            )
        ]
    )
    assert _as_tuples(writes) == [
        ("/etc/apache2/ssl/www.chain.pem", "chain", (1,)),
        ("/etc/apache2/ssl/www.crt", "leaf", (1,)),
        ("/etc/apache2/ssl/www.key", "key", (1,)),
    ]


def test_bindings_sharing_certificate_and_chain_paths_merge_into_one_write_each():
    writes = plan_file_writes(
        [
            _target(1, "/c/www.crt", "/c/a.key", chain="/c/chain.pem"),
            _target(2, "/c/www.crt", "/c/b.key", chain="/c/chain.pem"),
        ]
    )
    assert _as_tuples(writes) == [
        ("/c/a.key", "key", (1,)),
        ("/c/b.key", "key", (2,)),
        ("/c/chain.pem", "chain", (1, 2)),
        ("/c/www.crt", "leaf", (1, 2)),
    ]


def test_two_bindings_sharing_a_key_path_produce_one_key_write():
    writes = plan_file_writes(
        [_target(1, "/c/a.crt", "/c/shared.key"), _target(2, "/c/b.crt", "/c/shared.key")]
    )
    assert _as_tuples(writes) == [
        ("/c/a.crt", "fullchain", (1,)),
        ("/c/b.crt", "fullchain", (2,)),
        ("/c/shared.key", "key", (1, 2)),
    ]


def test_the_same_path_as_fullchain_and_as_leaf_is_a_conflict_naming_the_path():
    with pytest.raises(FileConflict) as excinfo:
        plan_file_writes(
            [
                _target(1, "/c/www.crt", "/c/a.key"),
                _target(2, "/c/www.crt", "/c/b.key", chain="/c/chain.pem"),
            ]
        )
    assert excinfo.value.path == "/c/www.crt"
    assert "/c/www.crt" in str(excinfo.value)
    assert isinstance(excinfo.value, ValueError)


def test_a_key_path_equal_to_a_certificate_path_is_a_conflict():
    with pytest.raises(FileConflict) as excinfo:
        plan_file_writes([_target(1, "/c/www.crt", "/c/www.key"), _target(2, "/c/other.crt", "/c/www.crt")])
    assert excinfo.value.path == "/c/www.crt"


def test_a_key_path_equal_to_the_own_certificate_path_is_a_conflict():
    with pytest.raises(FileConflict) as excinfo:
        plan_file_writes([_target(1, "/c/www.pem", "/c/www.pem")])
    assert excinfo.value.path == "/c/www.pem"


def test_a_chain_path_equal_to_the_own_certificate_path_is_a_conflict():
    with pytest.raises(FileConflict) as excinfo:
        plan_file_writes([_target(1, "/c/www.pem", "/c/www.key", chain="/c/www.pem")])
    assert excinfo.value.path == "/c/www.pem"


def test_the_same_path_with_different_new_certificates_is_a_conflict():
    with pytest.raises(FileConflict) as excinfo:
        plan_file_writes(
            [
                _target(1, "/c/www.crt", "/c/a.key", new="1" * 64),
                _target(2, "/c/www.crt", "/c/b.key", new="2" * 64),
            ]
        )
    assert excinfo.value.path == "/c/www.crt"


def test_output_is_sorted_by_path_whatever_the_input_order():
    targets = [
        _target(3, "/z/z.crt", "/z/z.key"),
        _target(1, "/a/a.crt", "/a/a.key"),
        _target(2, "/m/m.crt", "/m/m.key"),
    ]
    forward = plan_file_writes(targets)
    backward = plan_file_writes(list(reversed(targets)))
    assert forward == backward
    assert [w.path for w in forward] == sorted(w.path for w in forward)


def test_no_targets_means_no_writes():
    assert plan_file_writes([]) == ()


# --- D1: a chain write exists only for an explicit, discovery-verified chain_path -----------------


def test_d1_same_issuer_rsa_and_ecdsa_bindings_of_one_vhost_are_two_fullchain_writes_and_no_chain():
    rsa = _target(
        1, "/etc/nginx/ssl/www-rsa.crt", "/etc/nginx/ssl/www-rsa.key", port=443, sni="www.example.internal"
    )
    ecdsa = _target(
        2,
        "/etc/nginx/ssl/www-ecdsa.crt",
        "/etc/nginx/ssl/www-ecdsa.key",
        port=443,
        sni="www.example.internal",
    )
    for targets in ([rsa, ecdsa], [ecdsa, rsa]):
        writes = plan_file_writes(targets)
        assert _as_tuples(writes) == [
            ("/etc/nginx/ssl/www-ecdsa.crt", "fullchain", (2,)),
            ("/etc/nginx/ssl/www-ecdsa.key", "key", (2,)),
            ("/etc/nginx/ssl/www-rsa.crt", "fullchain", (1,)),
            ("/etc/nginx/ssl/www-rsa.key", "key", (1,)),
        ]
        assert not [w for w in writes if w.kind in ("chain", "leaf")]


def test_d1_a_chain_write_exists_only_when_a_target_declares_a_chain_path():
    plain = plan_file_writes([_target(i, f"/c/{i}.crt", f"/c/{i}.key") for i in range(1, 5)])
    assert {w.kind for w in plain} == {"fullchain", "key"}
    with_chain = plan_file_writes(
        [_target(1, "/c/1.crt", "/c/1.key", chain="/c/1.chain"), _target(2, "/c/2.crt", "/c/2.key")]
    )
    assert [w.path for w in with_chain if w.kind == "chain"] == ["/c/1.chain"]
    assert [w.path for w in with_chain if w.kind == "fullchain"] == ["/c/2.crt"]


def test_d1_paths_that_merely_look_like_chains_are_never_given_a_chain_role():
    targets = [
        _target(1, "/c/www.crt", "/c/www.key"),
        _target(2, "/c/www-chain.pem", "/c/www2.key"),
        _target(3, "/c/fullchain.pem", "/c/www3.key"),
    ]
    assert {w.kind for w in plan_file_writes(targets)} == {"fullchain", "key"}


def test_d1_a_chain_path_equal_to_another_targets_certificate_path_is_a_conflict():
    with pytest.raises(FileConflict) as excinfo:
        plan_file_writes(
            [
                _target(1, "/c/rsa.crt", "/c/rsa.key", chain="/c/ecdsa.crt"),
                _target(2, "/c/ecdsa.crt", "/c/ecdsa.key"),
            ]
        )
    assert excinfo.value.path == "/c/ecdsa.crt"


def test_deploy_target_and_file_write_are_frozen():
    target = _target(1, "/c/a.crt", "/c/a.key")
    with pytest.raises(dataclasses.FrozenInstanceError):
        target.cert_path = "/x"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        FileWrite("/c", "key", (1,)).path = "/y"  # type: ignore[misc]
