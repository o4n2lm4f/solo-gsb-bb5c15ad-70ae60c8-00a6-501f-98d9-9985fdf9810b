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
from typing import Any, Collection, Dict, List, Sequence, Set, Tuple

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
# Compact multi-leaf proofs
#
# A per-leaf proof repeats the same sibling node for every disclosed leaf in
# the same subtree.  The compact representation carries each sibling *once*,
# addressed by its absolute tree position ``(level, index)``:
#
# * level 0 is the sorted leaf level, index is the leaf position;
# * level L holds the nodes after L fold operations; at each level the last
#   node is duplicated when the pre-duplication node count is odd;
# * every disclosed leaf is identified by its level-0 ``index``.
#
# Reconstruction needs only the leaf count (which fixes the shape of every
# level), the disclosed leaves and the deduplicated proof nodes.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CompactProofNode:
    """One deduplicated sibling addressed by its tree position."""

    level: int
    index: int
    digest: bytes


def level_sizes_for_leaf_count(leaf_count: int) -> List[int]:
    """Number of (pre-duplication) nodes on each level for this tree shape."""
    if leaf_count < 1:
        raise TreeError("leaf count must be at least 1")
    sizes: List[int] = [leaf_count]
    n = leaf_count
    while n > 1:
        n = (n + 1) // 2
        sizes.append(n)
    return sizes


def required_proof_positions(
    leaf_count: int, leaf_indices: Collection[int]
) -> Set[Tuple[int, int]]:
    """Return the minimal set of ``(level, index)`` sibling nodes required to
    reconstruct the root from the disclosed leaves.

    Nodes shared by several disclosed leaves occur only once.  Besides
    siblings at the leaf level, a proof node at a higher level can anchor a
    whole undisclosed subtree; the two cases are computed by folding the tree
    top-down level by level.  A sibling produced by odd-layer tail
    duplication (the copy at position ``n``) is never required.
    """
    level_sizes_for_leaf_count(leaf_count)
    known: Set[int] = set(leaf_indices)
    required: Set[Tuple[int, int]] = set()
    n = leaf_count
    level = 0
    while n > 1:
        # Pair everything whose sibling is already known; every missing
        # sibling becomes a required proof node (and is treated as known from
        # then on, so proofs deeper in an undisclosed subtree are avoided).
        # Only positions of known nodes are visited, keeping this independent
        # of the (possibly attacker-supplied) leaf count.
        for pos in sorted(known):
            pair, side = divmod(pos, 2)
            sibling = 2 * pair + (0 if side == 1 else 1)
            if n % 2 == 1 and sibling == n:
                # The copy at position n duplicates the real tail node n-1.
                continue
            if sibling in known:
                continue
            required.add((level, sibling))
            known.add(sibling)

        # Every known node now belongs to a complete pair; a supplied proof
        # anchor propagates exactly like a computed parent.
        known = {pos // 2 for pos in known}
        n = (n + 1) // 2
        level += 1
    return required


def compact_inclusion_proof(
    leaf_digests: Sequence[bytes], indices: Collection[int]
) -> List[CompactProofNode]:
    """Build the deduplicated compact proof node list for *indices*, ordered
    by ``(level, index)`` (canonical tree-position order).
    """
    if not leaf_digests:
        raise TreeError("empty leaf set")
    n_total = len(leaf_digests)
    for index in indices:
        if not 0 <= index < n_total:
            raise TreeError(
                f"leaf index {index} out of range (leaf count {n_total})"
            )
    needed = required_proof_positions(n_total, indices)

    nodes: List[CompactProofNode] = []
    level = list(leaf_digests)
    level_no = 0
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        for idx in sorted(idx for (lvl, idx) in needed if lvl == level_no):
            nodes.append(
                CompactProofNode(
                    level=level_no, index=idx, digest=level[idx]
                )
            )
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        level_no += 1
    return nodes


def compact_rebuild_root(
    leaf_count: int,
    leaf_digests_by_index: Dict[int, bytes],
    proof_nodes: Sequence[CompactProofNode],
) -> bytes:
    """Rebuild the root bottom-up from disclosed leaves + compact proof.

    The tree shape (``leaf_count``) and every proof position are validated
    strictly: out-of-range indices, duplicate positions, duplicated-tail
    siblings, missing nodes and surplus nodes all raise :class:`TreeError`.
    """
    if leaf_count < 1:
        raise TreeError("leaf count must be at least 1")
    if not leaf_digests_by_index:
        raise TreeError("at least one disclosed leaf is required")
    sizes = level_sizes_for_leaf_count(leaf_count)

    # --- validate disclosed leaf indices ---------------------------------
    known: Dict[int, bytes] = {}
    for index, digest in leaf_digests_by_index.items():
        if not 0 <= index < leaf_count:
            raise TreeError(
                f"leaf index {index} out of range (leaf count {leaf_count})"
            )
        if index in known:
            raise TreeError(f"duplicate leaf index {index}")
        known[index] = digest

    # --- validate proof node positions ------------------------------------
    proof_by_pos: Dict[Tuple[int, int], bytes] = {}
    for node in proof_nodes:
        if not 0 <= node.level < len(sizes) - 1:
            raise TreeError(
                f"proof level {node.level} out of range for this tree shape"
            )
        width = sizes[node.level]
        if not 0 <= node.index < width:
            raise TreeError(
                f"proof index {node.index} out of range at level "
                f"{node.level} (width {width})"
            )
        pos = (node.level, node.index)
        if pos in proof_by_pos:
            raise TreeError(
                f"duplicate proof node at level {node.level}, index "
                f"{node.index}"
            )
        proof_by_pos[pos] = node.digest

    required = required_proof_positions(
        leaf_count, set(leaf_digests_by_index.keys())
    )
    provided = set(proof_by_pos)
    if required != provided:
        missing = sorted(required - provided)
        surplus = sorted(provided - required)
        if missing:
            level_no, idx = missing[0]
            raise TreeError(
                f"missing proof node at level {level_no}, index {idx}: "
                "a sibling hash needed to rebuild the root is absent"
            )
        level_no, idx = surplus[0]
        raise TreeError(
            f"surplus proof node at level {level_no}, index {idx}: not "
            "needed to rebuild the root from the disclosed leaves"
        )

    # --- bottom-up folding ------------------------------------------------
    n = leaf_count
    level_no = 0
    while n > 1:
        if n % 2 == 1 and (n - 1) in known:
            # Materialize the duplicated tail at position n.
            known[n] = known[n - 1]

        # Pair only positions we actually hold (disclosed leaves, supplied
        # proof hashes and parents computed on the previous iteration); a
        # required-set that matches guarantees both children of every such
        # pair are available.
        parent: Dict[int, bytes] = {}
        for pos, digest in known.items():
            pair, side = divmod(pos, 2)
            if pair in parent:
                continue  # left child already folded this pair
            left_pos, right_pos = 2 * pair, 2 * pair + 1
            if side == 0:
                left = digest
                right = (
                    known.get(right_pos)
                    if n % 2 == 1 and right_pos == n
                    else known.get(right_pos, proof_by_pos.get((level_no, right_pos)))
                )
            else:
                left = known.get(left_pos, proof_by_pos.get((level_no, left_pos)))
                right = digest
            if right is None or left is None:
                raise TreeError(
                    f"level {level_no} pair {pair} has exactly one child but "
                    "the required sibling proof node is missing"
                )
            parent[pair] = node_hash(left, right)
        known = parent
        n = (n + 1) // 2
        level_no += 1

    if len(known) != 1 or 0 not in known:
        raise TreeError("the compact proof does not anchor the root level")
    return known[0]
