"""Unit tests for hashing primitives and tree construction."""

import hashlib
import struct

import pytest

from app.canonical import canonical_json_bytes
from app.tree import (
    ProofStep,
    compact_inclusion_proof,
    compact_rebuild_root,
    expand_leaves,
    fold_level,
    inclusion_proof,
    leaf_hash,
    level_sizes_for_leaf_count,
    merkle_root,
    node_hash,
    required_proof_positions,
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


# ---------------------------------------------------------------------------
# Compact multi-leaf proofs
# ---------------------------------------------------------------------------


def test_level_sizes():
    assert level_sizes_for_leaf_count(1) == [1]
    assert level_sizes_for_leaf_count(2) == [2, 1]
    # 5 -> 3 (with tail duplicated) -> 2 -> 1
    assert level_sizes_for_leaf_count(5) == [5, 3, 2, 1]
    # 7 -> 4 -> 2 -> 1; 8 -> 4 -> 2 -> 1
    assert level_sizes_for_leaf_count(7) == [7, 4, 2, 1]
    assert level_sizes_for_leaf_count(8) == [8, 4, 2, 1]
    with pytest.raises(ValueError):
        level_sizes_for_leaf_count(0)


def test_compact_required_positions_deduplicate_shared_siblings():
    # Adjacent leaves 0,1 in an 8-leaf tree need only the uncles upward:
    # (1,1), (2,1) — two nodes instead of 2*3 = 6 per-leaf siblings.
    assert required_proof_positions(8, [0, 1]) == {(1, 1), (2, 1)}
    # Non-adjacent leaves each need their leaf-level sibling; once both
    # half-subtrees are anchored they share the level-2 uncle.
    assert required_proof_positions(8, [0, 4]) == {
        (0, 1),
        (0, 5),
        (1, 1),
        (1, 3),
    }


def test_compact_required_positions_odd_tail_rule():
    # Leaf 4 is the odd tail at level 0 (self-pair) and the level-1 pair
    # (2,2) is also a self-pair, so the only needed sibling is high up.
    assert required_proof_positions(5, [4]) == {(2, 0)}
    # Leaf 2: needs leaf sibling 3; at level 1 it is the odd tail again;
    # level 2 needs node 1.
    assert required_proof_positions(5, [2]) == {(0, 3), (1, 0), (2, 1)}
    # n=3: leaf 0 needs sibling 1 at level 0 and node 1 at level 1;
    # leaf 2 self-pairs at level 0 and only needs node 0 at level 1.
    assert required_proof_positions(3, [0]) == {(0, 1), (1, 1)}
    assert required_proof_positions(3, [2]) == {(1, 0)}


def test_compact_required_positions_full_tree_needs_nothing():
    assert required_proof_positions(5, range(5)) == set()
    assert required_proof_positions(1, [0]) == set()


def test_compact_proofs_roundtrip_all_subsets():
    import itertools

    for n in range(1, 9):
        digests = [leaf_hash(f"/v{i}", i) for i in range(n)]
        root = merkle_root(digests)
        for size in range(1, n + 1):
            for indices in itertools.combinations(range(n), size):
                nodes = compact_inclusion_proof(digests, indices)
                # Positions unique and exactly the minimally required set.
                positions = {(node.level, node.index) for node in nodes}
                assert len(positions) == len(nodes)
                assert positions == required_proof_positions(n, indices)
                rebuilt = compact_rebuild_root(
                    n,
                    {i: digests[i] for i in indices},
                    nodes,
                )
                assert rebuilt == root


def test_compact_single_leaf_tree_empty_proof():
    digest = leaf_hash("/only", 1)
    nodes = compact_inclusion_proof([digest], [0])
    assert nodes == []
    assert compact_rebuild_root(1, {0: digest}, []) == digest


def test_compact_rebuild_rejects_out_of_range_leaf_index():
    digests = [leaf_hash(f"/v{i}", i) for i in range(4)]
    root = merkle_root(digests)
    nodes = compact_inclusion_proof(digests, [0])
    with pytest.raises(ValueError, match="out of range"):
        compact_rebuild_root(4, {4: digests[0]}, nodes)
    with pytest.raises(ValueError, match="leaf count"):
        compact_rebuild_root(0, {0: digests[0]}, [])
    assert root  # fixture sanity


def test_compact_rebuild_rejects_missing_and_surplus_nodes():
    digests = [leaf_hash(f"/v{i}", i) for i in range(4)]
    nodes = compact_inclusion_proof(digests, [0, 2])
    # Remove a required node -> missing.
    with pytest.raises(ValueError, match="missing proof node"):
        compact_rebuild_root(4, {0: digests[0], 2: digests[2]}, nodes[:-1])
    # Duplicate a node -> duplicate position.
    with pytest.raises(ValueError, match="duplicate proof node"):
        compact_rebuild_root(
            4,
            {0: digests[0], 2: digests[2]},
            list(nodes) + [nodes[0]],
        )
    # A node not needed for these disclosed leaves is a surplus node:
    # disclosing leaves 0..3 (a complete half of an 8-leaf tree) needs
    # only (2,1); node (0,1) is computable from the disclosed leaves.
    from app.tree import CompactProofNode

    digests8 = [leaf_hash(f"/w{i}", i) for i in range(8)]
    real_anchor = compact_inclusion_proof(digests8, range(4))
    surplus_nodes = list(real_anchor) + [
        CompactProofNode(level=0, index=1, digest=digests8[1])
    ]
    with pytest.raises(ValueError, match="surplus proof node"):
        compact_rebuild_root(
            8,
            {i: digests8[i] for i in range(4)},
            surplus_nodes,
        )


def test_compact_rebuild_rejects_bad_node_positions():
    from app.tree import CompactProofNode

    digests = [leaf_hash(f"/v{i}", i) for i in range(3)]
    leaf0 = {0: digests[0]}
    with pytest.raises(ValueError, match="proof level"):
        compact_rebuild_root(
            3, leaf0, [CompactProofNode(5, 0, b"\x01" * 32)]
        )
    with pytest.raises(ValueError, match="proof index"):
        compact_rebuild_root(
            3, leaf0, [CompactProofNode(0, 99, b"\x01" * 32)]
        )


def test_compact_tampered_content_mismatches_root():
    digests = [leaf_hash(f"/v{i}", i) for i in range(4)]
    root = merkle_root(digests)
    nodes = compact_inclusion_proof(digests, [0])
    # Structural rebuild succeeds, but a forged leaf value yields a
    # different root (reported as ROOT_MISMATCH by the API layer).
    forged = leaf_hash("/v0", 999)
    assert compact_rebuild_root(4, {0: forged}, nodes) != root
    # Tampered proof hash likewise produces a different root, not a crash.
    from app.tree import CompactProofNode

    bad_nodes = [
        CompactProofNode(n.level, n.index, b"\xab" * 32) for n in nodes
    ]
    assert compact_rebuild_root(4, {0: digests[0]}, bad_nodes) != root


def test_compact_inclusion_proof_rejects_bad_index():
    digests = [leaf_hash(f"/v{i}", i) for i in range(3)]
    with pytest.raises(ValueError, match="out of range"):
        compact_inclusion_proof(digests, [3])
    with pytest.raises(ValueError, match="empty leaf set"):
        compact_inclusion_proof([], [0])
