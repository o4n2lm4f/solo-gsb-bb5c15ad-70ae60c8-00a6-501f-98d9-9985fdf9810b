"""Leaf expansion, length-prefixed leaf hashing and the Merkle tree.

Digest construction (all hashes SHA-256, 32 bytes):

Leaf preimage (domain-separated with tag byte ``0x00``)::

    0x00
    || u32be(len(pointer_utf8)) || pointer_utf8
    || u32be(len(canonical_value_utf8)) || canonical_value_utf8

Internal-node preimage (tag byte ``0x01``)::

    0x01 || left_hash(32) || right_hash(32)

The leaves are sorted by their RFC 6901 pointer string (Unicode code point
order) before the tree is built, making the root reproducible from the
document alone.  When a level being paired has an odd number of nodes, the
last node is duplicated (appended again).  A document with exactly one leaf
has that leaf digest as its root (no pairing happens); the verifier applies
the same rule, so commits and checks always agree.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Sequence, Set, Tuple

from . import pointers
from .canonical import CanonicalError, canonical_scalar_bytes

HASH_LEN = 32
LEAF_TAG = b"\x00"
NODE_TAG = b"\x01"
U32BE = struct.Struct(">I")


class TreeError(ValueError):
    """Malformed tree input (empty leaf set, bad proof, ...)."""


# ---------------------------------------------------------------------------
# Hashing primitives
# ---------------------------------------------------------------------------


def _u32be_len(data: bytes) -> bytes:
    return U32BE.pack(len(data))


def leaf_hash(pointer: str, value: Any) -> bytes:
    """Compute the length-prefixed leaf digest for one disclosed fact."""
    try:
        value_bytes = canonical_scalar_bytes(value)
    except CanonicalError:
        raise
    pointer_bytes = pointer.encode("utf-8")
    preimage = (
        LEAF_TAG
        + _u32be_len(pointer_bytes)
        + pointer_bytes
        + _u32be_len(value_bytes)
        + value_bytes
    )
    return hashlib.sha256(preimage).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != HASH_LEN or len(right) != HASH_LEN:
        raise TreeError(
            f"child digests must be {HASH_LEN} bytes, got "
            f"{len(left)} and {len(right)}"
        )
    return hashlib.sha256(NODE_TAG + left + right).digest()


# ---------------------------------------------------------------------------
# Leaf expansion
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Leaf:
    """One terminal fact: RFC 6901 pointer + the JSON value found there."""

    pointer: str
    value: Any

    @property
    def digest(self) -> bytes:
        return leaf_hash(self.pointer, self.value)


def _is_leaf_value(value: Any) -> bool:
    """A leaf is any scalar (incl. null) or an empty container."""
    if isinstance(value, dict):
        return len(value) == 0
    if isinstance(value, list):
        return len(value) == 0
    return True  # None, bool, int, float, str


def expand_leaves(doc: Any) -> List[Leaf]:
    """Depth-first expansion of *doc* into (pointer, value) leaves.

    Scalars, ``null`` and empty ``{}`` / ``[]`` are leaves.  Object members
    keep their insertion order during the walk; the final set is sorted by
    pointer string afterwards, so expansion order does not affect the root.
    """

    leaves: List[Leaf] = []

    def walk(value: Any, pointer: str) -> None:
        if _is_leaf_value(value):
            leaves.append(Leaf(pointer=pointer, value=value))
        elif isinstance(value, dict):
            for key, child in value.items():
                walk(child, pointers.build_pointer(pointer, key))
        elif isinstance(value, list):
            for idx, child in enumerate(value):
                walk(child, pointers.build_pointer(pointer, idx))
        else:  # pragma: no cover - guarded by strict JSON loading
            raise TreeError(f"unsupported value type at {pointer!r}")

    walk(doc, "")
    leaves.sort(key=lambda leaf: leaf.pointer)
    return leaves


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProofStep:
    """One level of a Merkle inclusion proof.

    ``side`` tells the verifier where the sibling sits relative to the
    running hash: ``"right"`` means ``H(running, sibling)``,
    ``"left"`` means ``H(sibling, running)``.
    """

    sibling: bytes
    side: str


def fold_level(level: Sequence[bytes]) -> List[bytes]:
    """Pair up a level left-to-right, duplicating the last odd node."""
    if not level:
        raise TreeError("cannot fold an empty level")
    nodes = list(level)
    if len(nodes) % 2 == 1:
        nodes.append(nodes[-1])
    return [node_hash(nodes[i], nodes[i + 1]) for i in range(0, len(nodes), 2)]


def merkle_root(leaf_digests: Sequence[bytes]) -> bytes:
    """Build the sorted-leaf Merkle root."""
    if not leaf_digests:
        raise TreeError("cannot build a Merkle root from an empty leaf set")
    level = list(leaf_digests)
    while len(level) > 1:
        level = fold_level(level)
    return level[0]


def inclusion_proof(leaf_digests: Sequence[bytes], index: int) -> List[ProofStep]:
    """Return the sibling path for leaf *index* in the sorted leaf set."""
    if not leaf_digests:
        raise TreeError("empty leaf set")
    if not 0 <= index < len(leaf_digests):
        raise TreeError(
            f"leaf index {index} out of range (leaf count {len(leaf_digests)})"
        )

    level = list(leaf_digests)
    pos = index
    steps: List[ProofStep] = []
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        if pos % 2 == 0:
            steps.append(ProofStep(level[pos + 1], "right"))
        else:
            steps.append(ProofStep(level[pos - 1], "left"))
        pos //= 2
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return steps


def verify_inclusion(
    leaf_digest: bytes, proof: Sequence[ProofStep], expected_root: bytes
) -> None:
    """Fold *proof* around *leaf_digest* and compare with *expected_root*.

    Raises :class:`TreeError` describing the failing step; returns on success.
    """
    if len(leaf_digest) != HASH_LEN:
        raise TreeError(
            f"leaf digest must be {HASH_LEN} bytes, got {len(leaf_digest)}"
        )
    if len(expected_root) != HASH_LEN:
        raise TreeError(
            f"root hash must be {HASH_LEN} bytes, got {len(expected_root)}"
        )

    running = leaf_digest
    for step_num, step in enumerate(proof):
        if len(step.sibling) != HASH_LEN:
            raise TreeError(
                f"proof step {step_num}: sibling digest must be "
                f"{HASH_LEN} bytes, got {len(step.sibling)}"
            )
        if step.side == "right":
            running = node_hash(running, step.sibling)
        elif step.side == "left":
            running = node_hash(step.sibling, running)
        else:
            raise TreeError(
                f"proof step {step_num}: side must be 'left' or 'right', "
                f"got {step.side!r}"
            )

    if running != expected_root:
        raise TreeError(
            "recomputed root does not match the committed root: "
            "the path, value or a sibling hash has been altered"
        )


# ---------------------------------------------------------------------------
# Compact multi-leaf proof
# ---------------------------------------------------------------------------
#
# Instead of repeating every sibling step once per disclosed leaf (the
# "standard" format), the compact format names every non-disclosed tree node
# exactly once, by its *level* (0 = leaf level) and its *index* within that
# level.  Each disclosed leaf carries only its leaf index; the verifier folds
# the whole set bottom-up:
#
#     node[level, i] =
#         disclosed-leaf digest                    (level 0)
#       | supplied proof node {level, i, hash}      (non-disclosed node)
#       | H(node[L,2i], node[L,2i+1])               (both children known)
#
# Odd levels keep the same "duplicate the last node" rule as the standard
# tree; the duplicated sibling is the node itself, so it is never needed in
# the proof set.  The set of nodes named by a compact proof is therefore
# exactly the set of nodes required for the fold: a structural validator can
# detect both missing and extraneous nodes.


@dataclass(frozen=True)
class CompactNode:
    """One proof node identified by (level, index) within the tree."""

    level: int
    index: int
    digest: bytes


def level_sizes(leaf_count: int) -> List[int]:
    """Return the node count of every level, level 0 first.

    The single-entry level (the root) is the last entry; a one-leaf tree
    yields ``[1]``.
    """
    if leaf_count <= 0:
        raise TreeError("leaf count must be at least 1")
    sizes = [leaf_count]
    while sizes[-1] > 1:
        sizes.append((sizes[-1] + 1) // 2)
    return sizes


def _pairs_at_level(width: int):
    """Yield ``(parent_index, left_index, right_index, odd_tail)`` pairs.

    When the level has an odd number of nodes the last node is paired with
    itself; ``odd_tail`` is true for that synthetic pair.
    """
    limit = width if width % 2 == 0 else width + 1
    for i in range(0, limit, 2):
        yield i // 2, i, min(i + 1, width - 1), width % 2 == 1 and i + 1 >= width


def required_proof_nodes(
    leaf_count: int, leaf_indices: Sequence[int]
) -> List[CompactNode]:
    """Plan the proof nodes needed to fold *leaf_indices* up to the root.

    This mirrors the verifier's fold structurally (without hashes).  A node
    is *known* when it is a disclosed leaf, supplied as a proof node, or
    derivable as the parent of a pair of known children.  Whenever exactly
    one child of a pair is known, the sibling must be supplied and is added
    to the required set.  Every pair contributes at most one required node,
    so a node is never required twice, even when several disclosed leaves
    would have carried it in their individual proofs.
    """
    if leaf_count <= 0:
        raise TreeError("leaf count must be at least 1")

    leaf_set: Set[int] = set()
    for idx in leaf_indices:
        if not 0 <= idx < leaf_count:
            raise TreeError(
                f"leaf index {idx} out of range (leaf count {leaf_count})"
            )
        leaf_set.add(idx)

    sizes = level_sizes(leaf_count)
    required: Dict[Tuple[int, int], CompactNode] = {}
    known_by_level: List[Set[int]] = [set(leaf_set)]

    for level, width in enumerate(sizes[:-1]):
        known = known_by_level[level]
        next_known: Set[int] = set()
        for parent, left, right, odd_tail in _pairs_at_level(width):
            left_known = left in known
            right_known = right in known
            if left_known and right_known:
                next_known.add(parent)
            elif left_known or right_known:
                missing_pos = right if left_known else left
                if not odd_tail:
                    # The sibling lives on the level currently being folded.
                    key = (level, missing_pos)
                    if key not in required:
                        required[key] = CompactNode(level, missing_pos, b"")
                next_known.add(parent)
        known_by_level.append(next_known)

    if 0 not in known_by_level[-1]:
        # Cannot happen for a non-empty leaf set: the walk reaches the root.
        raise TreeError("disclosed leaf set does not reach the tree root")
    return [required[key] for key in sorted(required)]


def compact_proof_nodes(
    levels: Sequence[Sequence[bytes]], leaf_indices: Sequence[int]
) -> List[CompactNode]:
    """Materialize the required proof nodes from an expanded tree.

    *levels* holds the concrete digests of every level (level 0 = sorted leaf
    digests); the returned nodes are deduplicated by ``(level, index)`` and
    ordered level-first, then index.
    """
    plan = required_proof_nodes(len(levels[0]), leaf_indices)
    nodes: List[CompactNode] = []
    for node in plan:
        if node.level >= len(levels) or node.index >= len(levels[node.level]):
            # pragma: no cover - the planner never names an out-of-tree node
            raise TreeError(
                f"planned proof node ({node.level},{node.index}) does not "
                "exist in the tree"
            )
        nodes.append(
            CompactNode(
                level=node.level,
                index=node.index,
                digest=levels[node.level][node.index],
            )
        )
    return nodes


def tree_levels(leaf_digests: Sequence[bytes]) -> List[List[bytes]]:
    """Expand the full tree and return the digests of every level."""
    levels: List[List[bytes]] = [list(leaf_digests)]
    while len(levels[-1]) > 1:
        levels.append(fold_level(levels[-1]))
    return levels


def compact_root(
    leaf_count: int,
    leaf_digests_by_index: Mapping[int, bytes],
    proof_nodes: Sequence[CompactNode],
) -> bytes:
    """Rebuild the Merkle root from disclosed leaves + compact proof nodes.

    Structural validation (range, uniqueness, missing/extraneous nodes) is
    expected to have run first; :class:`TreeError` is still raised if a fold
    reaches a node that was neither disclosed nor supplied.
    """
    sizes = level_sizes(leaf_count)
    # Seed each level with the proof nodes supplied for that level; level 0
    # also carries the disclosed leaf digests.
    known: List[Dict[int, bytes]] = [dict(leaf_digests_by_index)]
    for _ in sizes[1:]:
        known.append({})
    for node in proof_nodes:
        known[node.level][node.index] = node.digest

    for level, width in enumerate(sizes[:-1]):
        level_nodes = known[level]
        next_nodes: Dict[int, bytes] = known[level + 1]
        for parent, left, right, odd_tail in _pairs_at_level(width):
            if parent in next_nodes:
                continue
            if left in level_nodes and right in level_nodes:
                next_nodes[parent] = node_hash(
                    level_nodes[left], level_nodes[right]
                )
            elif odd_tail and left in level_nodes:
                next_nodes[parent] = node_hash(
                    level_nodes[left], level_nodes[left]
                )
            elif left in level_nodes or right in level_nodes:
                raise TreeError(
                    f"missing proof node at level {level}, index "
                    f"{right if left in level_nodes else left}"
                )

    root = known[-1].get(0)
    if root is None:
        raise TreeError("the compact proof does not reach a single root node")
    return root
