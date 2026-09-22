"""Unit tests for hashing primitives and tree construction."""

import hashlib
import struct

import pytest

from app.canonical import canonical_json_bytes
from app.tree import (
    ProofStep,
    expand_leaves,
    fold_level,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_inclusion,
)


def test_canonical_object_keys_sorted_and_compact():
    doc = {"b": 1, "a": [2, 1], "c": {"z": None, "y": True}}
    assert canonical_json_bytes(doc) == (
        b'{"a":[2,1],"b":1,"c":{"y":true,"z":null}}'
    )


def test_canonical_string_escaping():
    assert canonical_json_bytes("a/b~c") == b'"a/b~c"'
    assert canonical_json_bytes("line\nbreak") == b'"line\\nbreak"'
    assert canonical_json_bytes("quote\"x") == b'"quote\\"x"'
    assert canonical_json_bytes("\x01") == b'"\\u0001"'


def test_canonical_unicode_and_utf8():
    # Chinese characters are emitted literally (only control chars escaped).
    assert canonical_json_bytes("事实") == b'"' + "事实".encode("utf-8") + b'"'


def test_canonical_rejects_non_finite():
    import math

    with pytest.raises(ValueError):
        canonical_json_bytes(float("nan"))
    with pytest.raises(ValueError):
        canonical_json_bytes(math.inf)


def test_leaf_hash_length_prefix_encoding():
    pointer = "/a/0"
    value = "v"
    p, v = pointer.encode(), b'"v"'
    expected = hashlib.sha256(
        b"\x00"
        + struct.pack(">I", len(p)) + p
        + struct.pack(">I", len(v)) + v
    ).digest()
    assert leaf_hash(pointer, value) == expected


def test_expand_leaves_scalars_and_empty_containers():
    doc = {
        "name": "Ada",
        "age": 36,
        "active": True,
        "nick": None,
        "tags": [],
        "meta": {},
        "nested": {"x": 1, "y": {"deep": False}},
        "arr": [10, {"k": 20}],
    }
    leaves = {leaf.pointer: leaf.value for leaf in expand_leaves(doc)}
    assert leaves["/name"] == "Ada"
    assert leaves["/age"] == 36
    assert leaves["/active"] is True
    assert leaves["/nick"] is None
    assert leaves["/tags"] == []
    assert leaves["/meta"] == {}
    assert leaves["/nested/x"] == 1
    assert leaves["/nested/y/deep"] is False
    assert leaves["/arr/0"] == 10
    assert leaves["/arr/1/k"] == 20
    # Containers themselves must not appear as leaves unless empty.
    assert "/nested" not in leaves
    assert "/nested/y" not in leaves
    assert "/arr" not in leaves


def test_root_scalar_and_empty_root():
    assert {leaf.pointer for leaf in expand_leaves(42)} == {""}
    assert {leaf.pointer for leaf in expand_leaves({})} == {""}
    assert {leaf.pointer for leaf in expand_leaves([])} == {""}


def test_leaf_order_sorted_by_pointer():
    doc = {"z": 1, "a": {"y": 2, "b": 3}, "m": [9, 0]}
    pointers_ = [leaf.pointer for leaf in expand_leaves(doc)]
    assert pointers_ == sorted(pointers_)


def test_odd_level_duplicates_last_node():
    digests = [leaf_hash(f"/{i}", i) for i in range(3)]
    # Manual construction for 3 leaves: L0,L1,L2 -> H01, H22 -> root
    h01 = node_hash(digests[0], digests[1])
    h22 = node_hash(digests[2], digests[2])
    assert merkle_root(digests) == node_hash(h01, h22)


def test_single_leaf_root_is_leaf_digest():
    digest = leaf_hash("/x", 1)
    # One leaf => no pairing layer; root equals the leaf digest.
    assert merkle_root([digest]) == digest


def test_five_leaves_root_and_proofs():
    digests = [leaf_hash(f"/v{i}", i) for i in range(5)]
    # Two independent constructions must agree.
    level = digests[:]
    while len(level) > 1:
        level = fold_level(level)
    root = level[0]
    assert root == merkle_root(digests)

    for i in range(5):
        proof = inclusion_proof(digests, i)
        verify_inclusion(digests[i], proof, root)  # must not raise

    # Tampering with the leaf value fails the final root comparison.
    fake = leaf_hash("/v4", 999)
    with pytest.raises(ValueError, match="recomputed root"):
        verify_inclusion(fake, proof, root)

    # Tampering with a sibling hash fails too.
    tampered = [
        ProofStep(
            b"\xab" * 32 if j == 0 else step.sibling, step.side
        )
        for j, step in enumerate(proof)
    ]
    with pytest.raises(ValueError, match="recomputed root"):
        verify_inclusion(digests[4], tampered, root)


def test_bad_proof_side_and_lengths():
    digest = leaf_hash("/x", 1)
    root = merkle_root([digest])
    with pytest.raises(ValueError, match="side"):
        verify_inclusion(
            digest, [ProofStep(b"\x00" * 32, "up")], root
        )
    with pytest.raises(ValueError, match="sibling digest"):
        verify_inclusion(
            digest, [ProofStep(b"\x00" * 31, "left")], root
        )


def test_empty_leaf_set_rejected():
    with pytest.raises(ValueError):
        merkle_root([])
    with pytest.raises(ValueError):
        fold_level([])
