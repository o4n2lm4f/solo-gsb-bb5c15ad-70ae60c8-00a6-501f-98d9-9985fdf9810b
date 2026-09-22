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
from typing import Any, Dict, List, Optional, Sequence, Tuple

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
