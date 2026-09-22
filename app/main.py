"""FastAPI application: commit-and-prove and stateless verification.

Endpoints
----------
POST /commit   submit a nested JSON document plus the RFC 6901 paths that
               may be disclosed; returns the Merkle root and, for each
               selected leaf, its canonical value and an inclusion proof.
               With proofMode="compact" the proof is a shared multi-leaf
               set of {level,index,hash} nodes plus per-leaf indices.
POST /verify   check disclosures against a previously committed root without
               ever seeing the original document; both proof formats are
               detected automatically.
GET  /healthz  liveness probe.
GET  /         service metadata.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Sequence, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import pointers
from .canonical import CanonicalError
from .errors import (
    ApiError,
    BAD_HASH_ENCODING,
    BAD_PROOF,
    DUPLICATE_PATH,
    EMPTY_REVEAL,
    INVALID_REQUEST,
    PATH_NOT_FOUND,
    PATH_NOT_LEAF,
    PAYLOAD_TOO_LARGE,
    POINTER_SYNTAX,
    ROOT_MISMATCH,
)
from .jsonio import parse_json_strict
from .openapi import install_openapi
from .tree import (
    CompactNode,
    ProofStep,
    TreeError,
    compact_proof_nodes,
    compact_root,
    expand_leaves,
    inclusion_proof,
    leaf_hash,
    level_sizes,
    merkle_root,
    required_proof_nodes,
    tree_levels,
    verify_inclusion,
)
from .validation import validate_json_value

MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(10 * 1024 * 1024)))
# Compact proofs are opt-in per request; deployments may flip the default via
# DEFAULT_PROOF_MODE=compact (per-request "proofMode" still wins).  An
# unrecognized environment value falls back to "standard".
DEFAULT_PROOF_MODE = os.environ.get("DEFAULT_PROOF_MODE", "standard").lower()
if DEFAULT_PROOF_MODE not in ("standard", "compact"):
    DEFAULT_PROOF_MODE = "standard"
# Cap the declared leaf count so a stateless verifier cannot be forced into an
# O(leafCount) structural walk by an arbitrarily large integer.
MAX_LEAF_COUNT = 1_048_576
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")

app = FastAPI(
    title="Selective JSON Disclosure",
    version="1.1.0",
    description=(
        "Commit a nested JSON document to a reproducible Merkle root and "
        "disclose individual RFC 6901 leaf facts with inclusion proofs.\n\n"
        "Two proof formats are supported: the default per-leaf "
        "`{side, sibling}` arrays and, when `proofMode` is `compact`, a "
        "shared multi-leaf proof in which every sibling tree node is named "
        "exactly once by `{level, index, hash}` and each disclosed leaf "
        "carries only its sorted leaf index. `/verify` detects the format "
        "automatically."
    ),
)


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(status_code=exc.http_status, content=exc.to_body())


install_openapi(app)


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------


async def _read_json_body(request: Request) -> Any:
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise ApiError(
            PAYLOAD_TOO_LARGE,
            f"request body of {len(raw)} bytes exceeds the "
            f"{MAX_BODY_BYTES}-byte limit",
            loc="body",
            http_status=413,
            detail={"limitBytes": MAX_BODY_BYTES, "actualBytes": len(raw)},
        )
    return parse_json_strict(raw)


def _get_field(obj: Dict[str, Any], key: str, loc: str) -> Any:
    if key not in obj:
        raise ApiError(
            INVALID_REQUEST, f"missing required field {key!r}", loc=loc
        )
    return obj[key]


def _parse_hex32(value: Any, loc: str, what: str) -> bytes:
    if not isinstance(value, str):
        raise ApiError(
            BAD_HASH_ENCODING,
            f"{what} must be a 64-character lowercase/uppercase hex string, "
            f"got {type(value).__name__}",
            loc=loc,
        )
    if not _HEX64.fullmatch(value):
        raise ApiError(
            BAD_HASH_ENCODING,
            f"{what} must be exactly 64 hex characters (32 bytes); "
            f"got {len(value)} characters",
            loc=loc,
        )
    return bytes.fromhex(value)


# ---------------------------------------------------------------------------
# POST /commit
# ---------------------------------------------------------------------------


@app.post("/commit")
async def commit(request: Request) -> Dict[str, Any]:
    body = await _read_json_body(request)
    if not isinstance(body, dict):
        raise ApiError(
            INVALID_REQUEST,
            "request body must be a JSON object",
            loc="body",
        )

    document = _get_field(body, "document", "document")
    validate_json_value(document, loc="document")
    reveal = _get_field(body, "reveal", "reveal")
    if not isinstance(reveal, list):
        raise ApiError(
            INVALID_REQUEST,
            "'reveal' must be an array of RFC 6901 pointer strings",
            loc="reveal",
        )
    if len(reveal) == 0:
        raise ApiError(
            EMPTY_REVEAL,
            "'reveal' must contain at least one RFC 6901 path",
            loc="reveal",
        )

    proof_mode = body.get("proofMode", DEFAULT_PROOF_MODE)
    if not isinstance(proof_mode, str) or proof_mode not in ("standard", "compact"):
        raise ApiError(
            INVALID_REQUEST,
            "'proofMode' must be 'standard' or 'compact' when provided, "
            f"got {proof_mode!r}",
            loc="proofMode",
        )

    # Expand every leaf of the document and index it by RFC 6901 pointer.
    leaves = expand_leaves(document)
    leaves_by_pointer = {leaf.pointer: leaf for leaf in leaves}

    selected_pointers: List[str] = []
    seen: set[str] = set()
    for i, requested in enumerate(reveal):
        loc = f"reveal[{i}]"
        if not isinstance(requested, str):
            raise ApiError(
                INVALID_REQUEST,
                f"reveal entry must be a pointer string, got "
                f"{type(requested).__name__}",
                loc=loc,
            )
        try:
            tokens = pointers.parse_pointer(requested)
        except pointers.PointerError as exc:
            raise ApiError(
                POINTER_SYNTAX, str(exc), loc=loc
            ) from exc

        if requested in leaves_by_pointer:
            if requested in seen:
                raise ApiError(
                    DUPLICATE_PATH,
                    f"path {requested!r} appears more than once in 'reveal'",
                    loc=loc,
                    detail={"path": requested},
                )
            seen.add(requested)
            selected_pointers.append(requested)
            continue

        # Not a leaf: distinguish "missing" from "container with children"
        # by actually resolving the pointer against the original document.
        try:
            resolved = pointers.resolve(document, tokens)
        except (KeyError, IndexError, TypeError) as exc:
            raise ApiError(
                PATH_NOT_FOUND,
                f"path {requested!r} does not exist in the document: {exc}",
                loc=loc,
                detail={"path": requested},
            ) from exc

        if isinstance(resolved, (dict, list)) and len(resolved) > 0:
            prefix = requested + "/"
            children = [
                leaf.pointer
                for leaf in leaves
                if leaf.pointer.startswith(prefix)
            ][:20]
            raise ApiError(
                PATH_NOT_LEAF,
                f"path {requested!r} is a non-empty "
                f"{'object' if isinstance(resolved, dict) else 'array'}, not a "
                "leaf; disclose one of its scalar/empty-container children "
                "instead",
                loc=loc,
                detail={"path": requested, "leafChildren": children},
            )
        # pragma: no cover - resolve + leaf index cover all cases
        raise ApiError(PATH_NOT_FOUND, "path is not a leaf", loc=loc)

    # Reproducible root: sorted leaf digests, odd layers duplicate the tail.
    leaf_digests = [leaf.digest for leaf in leaves]
    root = merkle_root(leaf_digests)
    pointer_to_index = {leaf.pointer: i for i, leaf in enumerate(leaves)}

    # Output selected leaves in sorted-pointer order for stable responses.
    selected_pointers.sort()
    selected_indices = [pointer_to_index[pointer] for pointer in selected_pointers]

    if proof_mode == "compact":
        # One shared node set: a sibling needed by several disclosed leaves
        # (e.g. the uncle subtree of adjacent leaves) appears exactly once.
        levels = tree_levels(leaf_digests)
        proof_nodes = compact_proof_nodes(levels, selected_indices)
        disclosed = [
            {
                "path": leaves_by_pointer[pointer].pointer,
                "index": pointer_to_index[pointer],
                "value": leaves_by_pointer[pointer].value,
            }
            for pointer in selected_pointers
        ]
        return {
            "root": root.hex(),
            "proofMode": "compact",
            "leafCount": len(leaves),
            "leaves": disclosed,
            "proofNodes": [
                {"level": node.level, "index": node.index,
                 "hash": node.digest.hex()}
                for node in proof_nodes
            ],
        }

    disclosed = []
    for pointer in selected_pointers:
        index = pointer_to_index[pointer]
        leaf = leaves_by_pointer[pointer]
        steps = inclusion_proof(leaf_digests, index)
        disclosed.append(
            {
                "path": pointer,
                "value": leaf.value,
                "proof": [
                    {"side": step.side, "sibling": step.sibling.hex()}
                    for step in steps
                ],
            }
        )

    return {"root": root.hex(), "leaves": disclosed}


# ---------------------------------------------------------------------------
# POST /verify
# ---------------------------------------------------------------------------


def _proof_steps(raw_proof: Any, loc: str) -> List[ProofStep]:
    if not isinstance(raw_proof, list):
        raise ApiError(
            BAD_PROOF,
            f"'proof' must be an array of {{side, sibling}} steps, got "
            f"{type(raw_proof).__name__}",
            loc=loc,
        )
    steps: List[ProofStep] = []
    for i, raw_step in enumerate(raw_proof):
        step_loc = f"{loc}[{i}]"
        if not isinstance(raw_step, dict):
            raise ApiError(
                BAD_PROOF, "proof step must be an object", loc=step_loc
            )
        side = _get_field(raw_step, "side", f"{step_loc}.side")
        if side not in ("left", "right"):
            raise ApiError(
                BAD_PROOF,
                f"'side' must be 'left' or 'right', got {side!r}",
                loc=f"{step_loc}.side",
            )
        sibling = _parse_hex32(
            _get_field(raw_step, "sibling", f"{step_loc}.sibling"),
            f"{step_loc}.sibling",
            "sibling hash",
        )
        steps.append(ProofStep(sibling=sibling, side=side))
    return steps


def _non_negative_int(value: Any, loc: str, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ApiError(
            INVALID_REQUEST,
            f"{what} must be a non-negative integer, got {value!r}",
            loc=loc,
        )
    return value


def _compact_proof_nodes(raw_nodes: Any) -> List[CompactNode]:
    """Structurally validate the compact ``proofNodes`` array.

    Range and uniqueness are checked against the tree shape by
    :func:`_validate_compact_structure`; here we validate types, encodings,
    duplicates and the odd-level tail rule, each with a precise ``loc``.
    """
    loc = "proofNodes"
    if not isinstance(raw_nodes, list):
        raise ApiError(
            BAD_PROOF,
            f"'proofNodes' must be an array of {{level, index, hash}} "
            f"objects, got {type(raw_nodes).__name__}",
            loc=loc,
        )
    nodes: List[CompactNode] = []
    seen: set = set()
    for i, raw_node in enumerate(raw_nodes):
        node_loc = f"{loc}[{i}]"
        if not isinstance(raw_node, dict):
            raise ApiError(
                BAD_PROOF, "proof node must be an object", loc=node_loc
            )
        level = _non_negative_int(
            _get_field(raw_node, "level", f"{node_loc}.level"),
            f"{node_loc}.level",
            "'level'",
        )
        index = _non_negative_int(
            _get_field(raw_node, "index", f"{node_loc}.index"),
            f"{node_loc}.index",
            "'index'",
        )
        digest = _parse_hex32(
            _get_field(raw_node, "hash", f"{node_loc}.hash"),
            f"{node_loc}.hash",
            "proof node hash",
        )
        key = (level, index)
        if key in seen:
            raise ApiError(
                BAD_PROOF,
                f"proof node at level {level}, index {index} is supplied "
                "more than once; nodes are unique by tree position",
                loc=node_loc,
                detail={"level": level, "index": index},
            )
        seen.add(key)
        nodes.append(CompactNode(level=level, index=index, digest=digest))
    return nodes


def _validate_compact_structure(
    leaf_count: int,
    leaf_indices: Sequence[int],
    nodes: Sequence[CompactNode],
) -> List[CompactNode]:
    """Validate a compact proof against the declared tree shape.

    Checks (each yields ``BAD_PROOF`` with a precise ``loc``):

    * leaf indices stay within ``[0, leafCount)`` and are unique;
    * proof-node levels stay below the root level and indices within level;
    * the odd-level tail is never named (it duplicates its left sibling);
    * a proof node never shadows a disclosed leaf;
    * exactly the nodes required by the fold are present — missing or
      extraneous nodes are reported by ``(level, index)``.
    """
    if leaf_count < 1:
        raise ApiError(
            BAD_PROOF,
            f"'leafCount' must be at least 1, got {leaf_count}",
            loc="leafCount",
        )
    if leaf_count > MAX_LEAF_COUNT:
        raise ApiError(
            BAD_PROOF,
            f"'leafCount' {leaf_count} exceeds the supported maximum "
            f"{MAX_LEAF_COUNT}",
            loc="leafCount",
        )

    sizes = level_sizes(leaf_count)
    last_level = len(sizes) - 1  # the root level

    # Per-leaf index checks were partly done while parsing; recheck range and
    # duplicate indices together for the precise pairwise message.
    leaf_seen: set = set()
    leaf_list = list(leaf_indices)
    for i, idx in enumerate(leaf_list):
        if not 0 <= idx < leaf_count:
            raise ApiError(
                BAD_PROOF,
                f"leaf index {idx} is out of range for leafCount "
                f"{leaf_count} (valid range 0..{leaf_count - 1})",
                loc=f"leaves[{i}].index",
                detail={"index": idx, "leafCount": leaf_count},
            )
        if idx in leaf_seen:
            raise ApiError(
                BAD_PROOF,
                f"leaf index {idx} is disclosed more than once; each leaf "
                "may appear at most once in a compact proof",
                loc=f"leaves[{i}].index",
                detail={"index": idx},
            )
        leaf_seen.add(idx)

    supplied: Dict[Tuple[int, int], CompactNode] = {}
    for i, node in enumerate(nodes):
        node_loc = f"proofNodes[{i}]"
        if node.level >= last_level:
            raise ApiError(
                BAD_PROOF,
                f"proof node level {node.level} does not exist in a tree "
                f"with leafCount {leaf_count} (valid levels "
                f"0..{max(last_level - 1, 0)}; level {last_level} is the "
                "root and cannot be supplied)",
                loc=f"{node_loc}.level",
                detail={"level": node.level, "maxLevel": last_level - 1},
            )
        width = sizes[node.level]
        if not 0 <= node.index < width:
            raise ApiError(
                BAD_PROOF,
                f"proof node index {node.index} is out of range at level "
                f"{node.level} (this level holds {width} nodes, valid range "
                f"0..{width - 1})",
                loc=f"{node_loc}.index",
                detail={
                    "level": node.level,
                    "index": node.index,
                    "levelSize": width,
                },
            )
        if width % 2 == 1 and node.index == width - 1:
            raise ApiError(
                BAD_PROOF,
                f"proof node at level {node.level}, index {node.index} is the "
                "last node of an odd-sized level: that node is paired with a "
                "copy of itself and must not be carried in the proof",
                loc=node_loc,
                detail={"level": node.level, "index": node.index},
            )
        if node.level == 0 and node.index in leaf_seen:
            raise ApiError(
                BAD_PROOF,
                f"proof node at level 0, index {node.index} duplicates a "
                "disclosed leaf: a node may not be both disclosed and "
                "supplied as a proof node",
                loc=node_loc,
                detail={"level": 0, "index": node.index},
            )
        supplied[(node.level, node.index)] = node

    # The fold planner defines the exact set of nodes that must be supplied.
    try:
        required = {
            (node.level, node.index)
            for node in required_proof_nodes(leaf_count, leaf_list)
        }
    except TreeError as exc:
        raise ApiError(BAD_PROOF, str(exc), loc="leaves") from exc

    supplied_keys = set(supplied)
    missing = required - supplied_keys
    if missing:
        level, index = sorted(missing)[0]
        raise ApiError(
            BAD_PROOF,
            f"compact proof is missing the required sibling node at level "
            f"{level}, index {index} (the fold cannot reach the root "
            "without it)",
            loc="proofNodes",
            detail={
                "missing": [
                    {"level": lv, "index": ix} for lv, ix in sorted(missing)
                ]
            },
        )
    extra = supplied_keys - required
    if extra:
        level, index = sorted(extra)[0]
        pos = next(
            i
            for i, node in enumerate(nodes)
            if (node.level, node.index) == (level, index)
        )
        raise ApiError(
            BAD_PROOF,
            f"proof node at level {level}, index {index} is not needed to "
            "fold the disclosed leaves up to the root; remove it",
            loc=f"proofNodes[{pos}]",
            detail={
                "extraneous": [
                    {"level": lv, "index": ix} for lv, ix in sorted(extra)
                ]
            },
        )

    return [supplied[key] for key in sorted(supplied)]


def _verify_compact(
    body: Dict[str, Any], expected_root: bytes
) -> List[Dict[str, Any]]:
    """Verify a compact multi-leaf disclosure request."""
    raw_count = _get_field(body, "leafCount", "leafCount")
    leaf_count = _non_negative_int(
        raw_count, "leafCount", "'leafCount'"
    )

    raw_leaves = _get_field(body, "leaves", "leaves")
    if not isinstance(raw_leaves, list):
        raise ApiError(
            INVALID_REQUEST,
            "'leaves' must be an array of {path, index, value} objects",
            loc="leaves",
        )
    if len(raw_leaves) == 0:
        raise ApiError(
            EMPTY_REVEAL,
            "'leaves' must contain at least one disclosure to verify",
            loc="leaves",
        )

    leaf_entries: List[Tuple[int, str, Any, bytes]] = []
    seen_paths: set = set()
    seen_indices: set = set()
    for i, raw_leaf in enumerate(raw_leaves):
        loc = f"leaves[{i}]"
        if not isinstance(raw_leaf, dict):
            raise ApiError(
                INVALID_REQUEST,
                "leaf entry must be an object {path, index, value}",
                loc=loc,
            )

        path = _get_field(raw_leaf, "path", f"{loc}.path")
        if not isinstance(path, str):
            raise ApiError(
                INVALID_REQUEST,
                f"'path' must be a pointer string, got {type(path).__name__}",
                loc=f"{loc}.path",
            )
        try:
            pointers.parse_pointer(path)
        except pointers.PointerError as exc:
            raise ApiError(POINTER_SYNTAX, str(exc), loc=f"{loc}.path") from exc

        if path in seen_paths:
            raise ApiError(
                DUPLICATE_PATH,
                f"path {path!r} is submitted more than once",
                loc=f"{loc}.path",
                detail={"path": path},
            )
        seen_paths.add(path)

        index = _non_negative_int(
            _get_field(raw_leaf, "index", f"{loc}.index"),
            f"{loc}.index",
            "'index'",
        )
        if index in seen_indices:
            # Structural duplicate caught early; the range check happens in
            # the tree-shape validation below once leafCount is known.
            raise ApiError(
                BAD_PROOF,
                f"leaf index {index} is disclosed more than once; each leaf "
                "may appear at most once in a compact proof",
                loc=f"{loc}.index",
                detail={"index": index},
            )
        seen_indices.add(index)

        value = _get_field(raw_leaf, "value", f"{loc}.value")
        validate_json_value(value, loc=f"{loc}.value")

        try:
            digest = leaf_hash(path, value)
        except CanonicalError as exc:
            raise ApiError(
                BAD_PROOF,
                f"disclosed value is not a leaf value (scalar or empty "
                f"container): {exc}",
                loc=f"{loc}.value",
            ) from exc
        leaf_entries.append((index, path, value, digest))

    nodes = _compact_proof_nodes(_get_field(body, "proofNodes", "proofNodes"))
    nodes = _validate_compact_structure(
        leaf_count, [entry[0] for entry in leaf_entries], nodes
    )

    try:
        rebuilt = compact_root(
            leaf_count,
            {entry[0]: entry[3] for entry in leaf_entries},
            nodes,
        )
    except TreeError as exc:
        # Structural validation already proved the set is complete; reaching
        # here means the proof shape itself is incoherent.
        raise ApiError(BAD_PROOF, str(exc), loc="proofNodes") from exc

    if rebuilt != expected_root:
        raise ApiError(
            ROOT_MISMATCH,
            "compact proof failed: the root rebuilt from the disclosed "
            "leaves and proof nodes does not match the committed root",
            loc="root",
            http_status=422,
            detail={
                "committedRoot": expected_root.hex(),
                "rebuiltRoot": rebuilt.hex(),
                "hint": (
                    "a disclosed path or value, a proof-node hash or the "
                    "committed root was tampered with"
                ),
            },
        )

    verified = [
        {"path": path, "value": value}
        for _index, path, value, _digest in leaf_entries
    ]
    verified.sort(key=lambda item: item["path"])
    return verified


@app.post("/verify")
async def verify(request: Request) -> Dict[str, Any]:
    body = await _read_json_body(request)
    if not isinstance(body, dict):
        raise ApiError(
            INVALID_REQUEST,
            "request body must be a JSON object",
            loc="body",
        )

    expected_root = _parse_hex32(
        _get_field(body, "root", "root"), "root", "root hash"
    )

    # Auto-detect the proof format: the compact shape carries a shared
    # "proofNodes" array (plus per-leaf "index" and a top-level "leafCount");
    # the legacy shape carries per-leaf "proof" arrays.
    is_compact = "proofNodes" in body or "leafCount" in body
    if is_compact:
        verified = _verify_compact(body, expected_root)
        return {
            "valid": True,
            "root": expected_root.hex(),
            "proofMode": "compact",
            "leaves": verified,
        }

    raw_leaves = _get_field(body, "leaves", "leaves")
    if not isinstance(raw_leaves, list):
        raise ApiError(
            INVALID_REQUEST,
            "'leaves' must be an array of {path, value, proof} objects",
            loc="leaves",
        )
    if len(raw_leaves) == 0:
        raise ApiError(
            EMPTY_REVEAL,
            "'leaves' must contain at least one disclosure to verify",
            loc="leaves",
        )

    verified: List[Dict[str, Any]] = []
    seen_paths: set[str] = set()
    for i, raw_leaf in enumerate(raw_leaves):
        loc = f"leaves[{i}]"
        if not isinstance(raw_leaf, dict):
            raise ApiError(
                INVALID_REQUEST,
                "leaf entry must be an object {path, value, proof}",
                loc=loc,
            )

        path = _get_field(raw_leaf, "path", f"{loc}.path")
        if not isinstance(path, str):
            raise ApiError(
                INVALID_REQUEST,
                f"'path' must be a pointer string, got {type(path).__name__}",
                loc=f"{loc}.path",
            )
        try:
            pointers.parse_pointer(path)
        except pointers.PointerError as exc:
            raise ApiError(POINTER_SYNTAX, str(exc), loc=f"{loc}.path") from exc

        if path in seen_paths:
            raise ApiError(
                DUPLICATE_PATH,
                f"path {path!r} is submitted more than once",
                loc=f"{loc}.path",
                detail={"path": path},
            )
        seen_paths.add(path)

        value = _get_field(raw_leaf, "value", f"{loc}.value")
        validate_json_value(value, loc=f"{loc}.value")

        steps = _proof_steps(
            _get_field(raw_leaf, "proof", f"{loc}.proof"), f"{loc}.proof"
        )

        # Rebuild the leaf digest from the claimed path + canonical value.
        try:
            digest = leaf_hash(path, value)
        except CanonicalError as exc:
            raise ApiError(
                BAD_PROOF,
                f"disclosed value is not a leaf value (scalar or empty "
                f"container): {exc}",
                loc=f"{loc}.value",
            ) from exc

        try:
            verify_inclusion(digest, steps, expected_root)
        except Exception as exc:
            raise ApiError(
                ROOT_MISMATCH,
                f"proof for path {path!r} failed: {exc}",
                loc=loc,
                http_status=422,
                detail={
                    "path": path,
                    "committedRoot": expected_root.hex(),
                    "hint": (
                        "the path, the value, a sibling hash or the root was "
                        "tampered with"
                    ),
                },
            ) from exc

        verified.append({"path": path, "value": value})

    verified.sort(key=lambda item: item["path"])
    return {"valid": True, "root": expected_root.hex(), "leaves": verified}


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/")
async def index() -> Dict[str, Any]:
    return {
        "service": "selective-json-disclosure",
        "version": "1.1.0",
        "endpoints": {
            "commit": "POST /commit",
            "verify": "POST /verify",
            "docs": "GET /docs",
            "health": "GET /healthz",
        },
        "hash": "sha256",
        "proofModes": ["standard", "compact"],
        "defaultProofMode": DEFAULT_PROOF_MODE,
        "maxBodyBytes": MAX_BODY_BYTES,
    }
