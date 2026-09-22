"""Unit tests for hashing primitives and tree construction."""

import hashlib
import struct

import pytest

from app.canonical import canonical_json_bytes
from app.tree import (
    ProofStep,
    compact_proof_nodes,
    compact_root,
    expand_leaves,
    fold_level,
    inclusion_proof,
    leaf_hash,
    level_sizes,
    merkle_root,
    node_hash,
    required_proof_nodes,
    tree_levels,
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


def test_level_sizes_shape_and_odd_floors():
    assert level_sizes(1) == [1]
    assert level_sizes(2) == [2, 1]
    assert level_sizes(3) == [3, 2, 1]
    assert level_sizes(5) == [5, 3, 2, 1]
    with pytest.raises(ValueError):
        level_sizes(0)


def _compact_fold(digests, indices):
    levels = tree_levels(digests)
    nodes = compact_proof_nodes(levels, indices)
    return levels, nodes, compact_root(
        len(digests), {i: digests[i] for i in indices}, nodes
    )


@pytest.mark.parametrize("n", range(1, 9))
def test_compact_proofs_for_every_nonempty_subset(n):
    import itertools

    digests = [leaf_hash(f"/k{i:02d}", i) for i in range(n)]
    root = merkle_root(digests)
    for width in range(1, n + 1):
        for combo in itertools.combinations(range(n), width):
            _levels, nodes, rebuilt = _compact_fold(digests, list(combo))
            assert rebuilt == root, (n, combo)


def test_compact_nodes_deduplicated_and_sorted():
    # 7 leaves; adjacent disclosed leaves 4 and 5 pair directly at level 0,
    # and every subtree above them is shared. The compact set names each tree
    # position at most once, stays level/index sorted, and is strictly
    # smaller than concatenating the two legacy per-leaf proofs.
    digests = [leaf_hash(f"/k{i}", i) for i in range(7)]
    levels = tree_levels(digests)
    nodes = compact_proof_nodes(levels, [4, 5])
    keys = [(node.level, node.index) for node in nodes]
    assert len(keys) == len(set(keys))
    assert keys == sorted(keys)

    # The legacy proofs for leaves 4 and 5 repeat the shared upper nodes and
    # leaf 4's "right sibling" is leaf 5 itself — which compact elides.
    legacy_keys = set()
    legacy_step_count = 0
    for leaf_index in (4, 5):
        pos = leaf_index
        for level, width in enumerate(level_sizes(7)[:-1]):
            odd_tail = width % 2 == 1 and pos == width - 1
            if not odd_tail:
                legacy_keys.add((level, pos ^ 1))
            legacy_step_count += 1
            pos //= 2
    assert (0, 5) in legacy_keys  # carried by leaf 4's legacy proof...
    assert not any(node.level == 0 and node.index == 5 for node in nodes)
    assert len(nodes) < legacy_step_count
    # Every compact node is also a node some legacy proof needed.
    assert set(keys) <= legacy_keys


def test_compact_odd_tail_node_is_never_required():
    # 3 leaves, disclose the last leaf: its first pairing is H(L2,L2) with a
    # duplicated tail, so no level-0 sibling node may be required.
    digests = [leaf_hash(f"/k{i}", i) for i in range(3)]
    levels = tree_levels(digests)
    nodes = compact_proof_nodes(levels, [2])
    assert [(n.level, n.index) for n in nodes] == [(1, 0)]
    _levels, _nodes, rebuilt = _compact_fold(digests, [2])
    assert rebuilt == merkle_root(digests)


def test_compact_all_leaves_requires_no_proof_nodes():
    digests = [leaf_hash(f"/k{i}", i) for i in range(6)]
    levels = tree_levels(digests)
    nodes = compact_proof_nodes(levels, list(range(6)))
    assert nodes == []
    assert compact_root(6, {i: digests[i] for i in range(6)}, []) == merkle_root(
        digests
    )


def test_compact_single_leaf_tree():
    digest = leaf_hash("/x", 1)
    levels = tree_levels([digest])
    assert compact_proof_nodes(levels, [0]) == []
    assert compact_root(1, {0: digest}, []) == digest


def test_compact_required_plan_matches_emulated_fold():
    # Independently emulate the bottom-up fold and compare the required set.
    digests = [leaf_hash(f"/k{i}", i) for i in range(8)]
    disclosed = [0, 2, 3, 6]
    plan = {
        (node.level, node.index)
        for node in required_proof_nodes(len(digests), disclosed)
    }
    expected = set()
    known = set(disclosed)
    sizes = level_sizes(8)
    for level, width in enumerate(sizes[:-1]):
        nxt = set()
        limit = width if width % 2 == 0 else width + 1
        for j in range(0, limit, 2):
            left, right = j, min(j + 1, width - 1)
            odd_tail = width % 2 == 1 and j + 1 >= width
            if left in known and right in known:
                nxt.add(j // 2)
            elif (left in known or right in known) and not odd_tail:
                expected.add((level, right if left in known else left))
                nxt.add(j // 2)
            elif left in known or right in known:
                nxt.add(j // 2)
        known = nxt
    assert plan == expected
    assert 0 in known  # the fold reaches the root


def test_compact_root_detects_missing_node():
    digests = [leaf_hash(f"/k{i}", i) for i in range(4)]
    levels = tree_levels(digests)
    nodes = compact_proof_nodes(levels, [0])
    with pytest.raises(ValueError, match="missing proof node"):
        compact_root(4, {0: digests[0]}, nodes[1:])


def test_compact_required_rejects_out_of_range_index():
    with pytest.raises(ValueError, match="out of range"):
        required_proof_nodes(3, [3])
    with pytest.raises(ValueError, match="out of range"):
        required_proof_nodes(3, [-1])
