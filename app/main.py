"""FastAPI application: commit-and-prove and stateless verification.

Endpoints
----------
POST /commit   submit a nested JSON document plus the RFC 6901 paths that
               may be disclosed; returns the Merkle root and, for each
               selected leaf, its canonical value and inclusion proof.
POST /verify   check disclosures against a previously committed root without
               ever seeing the original document.
GET  /healthz  liveness probe.
GET  /         service metadata.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

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
from .tree import (
    HASH_LEN,
    CompactProofNode,
    ProofStep,
    TreeError,
    compact_rebuild_root,
    compact_inclusion_proof,
    expand_leaves,
    inclusion_proof,
    leaf_hash,
    level_sizes_for_leaf_count,
    merkle_root,
    required_proof_positions,
    verify_inclusion,
)
from .validation import validate_json_value

MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(10 * 1024 * 1024)))
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
PROOF_MODES = ("legacy", "compact")
DEFAULT_PROOF_MODE = os.environ.get("DEFAULT_PROOF_MODE", "legacy")
if DEFAULT_PROOF_MODE not in PROOF_MODES:
    raise RuntimeError(
        f"DEFAULT_PROOF_MODE must be one of {PROOF_MODES}, "
        f"got {DEFAULT_PROOF_MODE!r}"
    )

app = FastAPI(
    title="Selective JSON Disclosure",
    version="1.1.0",
    description=(
        "Commit a nested JSON document to a reproducible Merkle root and "
        "disclose individual RFC 6901 leaf facts with inclusion proofs.\n\n"
        "`POST /commit` accepts `proofMode: \"compact\"`, which returns one "
        "deduplicated multi-leaf proof addressed by `{level, index, hash}`; "
        "`POST /verify` recognizes both formats automatically."
    ),
)


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(status_code=exc.http_status, content=exc.to_body())


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


_COMMIT_OPENAPI = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/CommitRequest"},
                "examples": {
                    "legacy": {
                        "summary": "Per-leaf proofs (default, backwards compatible)",
                        "value": {
                            "document": {
                                "subject": {"name": "Ada", "age": 36},
                                "emails": ["a@x", "b@y"],
                            },
                            "reveal": ["/subject/age", "/emails/1"],
                        },
                    },
                    "compact": {
                        "summary": "Deduplicated compact multi-leaf proof",
                        "value": {
                            "document": {
                                "subject": {"name": "Ada", "age": 36},
                                "emails": ["a@x", "b@y"],
                            },
                            "reveal": ["/subject/age", "/emails/1"],
                            "proofMode": "compact",
                        },
                    },
                },
            }
        },
    },
    "responses": {
        "200": {
            "description": "Merkle root and the selected leaves with proofs",
            "content": {
                "application/json": {
                    "examples": {
                        "legacy": {
                            "summary": "Default (proofMode omitted or 'legacy')",
                            "value": {
                                "root": "9f0c…",
                                "leaves": [
                                    {
                                        "path": "/emails/1",
                                        "value": "b@y",
                                        "proof": [
                                            {"side": "right", "sibling": "…"}
                                        ],
                                    }
                                ],
                            },
                        },
                        "compact": {
                            "summary": "proofMode 'compact'",
                            "value": {
                                "root": "9f0c…",
                                "proofMode": "compact",
                                "leafCount": 4,
                                "leaves": [
                                    {"path": "/emails/1", "value": "b@y", "index": 3},
                                    {"path": "/subject/age", "value": 36, "index": 1},
                                ],
                                "proof": [
                                    {"level": 0, "index": 0, "hash": "…"},
                                    {"level": 0, "index": 2, "hash": "…"},
                                    {"level": 1, "index": 1, "hash": "…"},
                                ],
                            },
                        },
                    }
                }
            },
        },
        "400": {"$ref": "#/components/responses/ClientError"},
        "413": {"$ref": "#/components/responses/ClientError"},
        "422": {"$ref": "#/components/responses/RootMismatch"},
    },
}


_VERIFY_OPENAPI = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/VerifyRequest"},
                "examples": {
                    "legacy": {
                        "summary": "Per-leaf proofs (auto-detected)",
                        "value": {
                            "root": "9f0c…",
                            "leaves": [
                                {
                                    "path": "/subject/age",
                                    "value": 36,
                                    "proof": [
                                        {"side": "left", "sibling": "…"}
                                    ],
                                }
                            ],
                        },
                    },
                    "compact": {
                        "summary": "Compact multi-leaf proof (auto-detected)",
                        "value": {
                            "root": "9f0c…",
                            "leafCount": 4,
                            "leaves": [
                                {"path": "/emails/1", "value": "b@y", "index": 3},
                                {"path": "/subject/age", "value": 36, "index": 1},
                            ],
                            "proof": [
                                {"level": 0, "index": 0, "hash": "…"},
                                {"level": 0, "index": 2, "hash": "…"},
                                {"level": 1, "index": 1, "hash": "…"},
                            ],
                        },
                    },
                },
            }
        },
    },
    "responses": {
        "200": {
            "description": "Every disclosure rebuilds the committed root",
            "content": {
                "application/json": {
                    "example": {
                        "valid": True,
                        "root": "9f0c…",
                        "leaves": [
                            {"path": "/emails/1", "value": "b@y"},
                            {"path": "/subject/age", "value": 36},
                        ],
                    }
                }
            },
        },
        "400": {"$ref": "#/components/responses/ClientError"},
        "413": {"$ref": "#/components/responses/ClientError"},
        "422": {"$ref": "#/components/responses/RootMismatch"},
    },
}


_HEX64_SCHEMA = {
    "type": "string",
    "pattern": "^[0-9a-fA-F]{64}$",
    "description": "Lower-/upper-case hex encoding of a 32-byte SHA-256 digest.",
}


@app.post("/commit", openapi_extra=_COMMIT_OPENAPI)
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
    if proof_mode not in PROOF_MODES:
        raise ApiError(
            INVALID_REQUEST,
            f"'proofMode' must be one of {list(PROOF_MODES)}, got "
            f"{proof_mode!r}",
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
    selected_sorted = sorted(selected_pointers)

    if proof_mode == "compact":
        selected_indices = [pointer_to_index[p] for p in selected_sorted]
        compact_nodes = compact_inclusion_proof(leaf_digests, selected_indices)
        disclosed = [
            {
                "path": pointer,
                "value": leaves_by_pointer[pointer].value,
                "index": pointer_to_index[pointer],
            }
            for pointer in selected_sorted
        ]
        return {
            "root": root.hex(),
            "proofMode": "compact",
            "leafCount": len(leaves),
            "leaves": disclosed,
            "proof": [
                {"level": node.level, "index": node.index, "hash": node.digest.hex()}
                for node in compact_nodes
            ],
        }

    disclosed = []
    for pointer in selected_sorted:
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


def _parse_disclosed_leaf(raw_leaf: Any, loc: str) -> tuple[str, Any]:
    """Parse and validate the shared ``path`` / ``value`` of one disclosure."""
    if not isinstance(raw_leaf, dict):
        raise ApiError(
            INVALID_REQUEST,
            "leaf entry must be an object {path, value, proof} or "
            "{path, value, index}",
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

    value = _get_field(raw_leaf, "value", f"{loc}.value")
    validate_json_value(value, loc=f"{loc}.value")
    return path, value


def _leaf_digest(path: str, value: Any, loc: str) -> bytes:
    try:
        return leaf_hash(path, value)
    except CanonicalError as exc:
        raise ApiError(
            BAD_PROOF,
            f"disclosed value is not a leaf value (scalar or empty "
            f"container): {exc}",
            loc=f"{loc}.value",
        ) from exc


def _compact_proof_nodes(raw_proof: Any, sizes: List[int]) -> List[tuple]:
    """Parse the top-level compact ``proof`` array into validated positions."""
    loc = "proof"
    if not isinstance(raw_proof, list):
        raise ApiError(
            BAD_PROOF,
            f"'proof' must be an array of {{level, index, hash}} nodes, got "
            f"{type(raw_proof).__name__}",
            loc=loc,
        )

    nodes: List[tuple] = []
    seen_positions: set[tuple] = set()
    max_level = len(sizes) - 2  # level above the root carries no siblings
    for i, raw_node in enumerate(raw_proof):
        node_loc = f"{loc}[{i}]"
        if not isinstance(raw_node, dict):
            raise ApiError(
                BAD_PROOF, "proof node must be an object", loc=node_loc
            )

        level = _get_field(raw_node, "level", f"{node_loc}.level")
        if isinstance(level, bool) or not isinstance(level, int):
            raise ApiError(
                BAD_PROOF,
                f"'level' must be a non-negative integer, got "
                f"{level!r} ({type(level).__name__})",
                loc=f"{node_loc}.level",
            )
        if not 0 <= level <= max_level:
            raise ApiError(
                BAD_PROOF,
                f"'level' {level} out of range for this tree shape "
                f"(valid levels: 0..{max_level})",
                loc=f"{node_loc}.level",
            )

        index = _get_field(raw_node, "index", f"{node_loc}.index")
        if isinstance(index, bool) or not isinstance(index, int):
            raise ApiError(
                BAD_PROOF,
                f"'index' must be a non-negative integer, got "
                f"{index!r} ({type(index).__name__})",
                loc=f"{node_loc}.index",
            )
        width = sizes[level]
        if not 0 <= index < width:
            raise ApiError(
                BAD_PROOF,
                f"'index' {index} out of range at level {level} (level "
                f"width {width})",
                loc=f"{node_loc}.index",
            )

        position = (level, index)
        if position in seen_positions:
            raise ApiError(
                BAD_PROOF,
                f"duplicate proof node at level {level}, index {index}",
                loc=node_loc,
                detail={"level": level, "index": index},
            )
        seen_positions.add(position)

        digest = _parse_hex32(
            _get_field(raw_node, "hash", f"{node_loc}.hash"),
            f"{node_loc}.hash",
            "proof node hash",
        )
        nodes.append((level, index, digest))
    return nodes


def _verify_compact(body: Dict[str, Any], expected_root: bytes) -> List[Dict[str, Any]]:
    """Verify a compact multi-leaf disclosure (top-level ``leafCount``/proof)."""
    leaf_count = _get_field(body, "leafCount", "leafCount")
    if isinstance(leaf_count, bool) or not isinstance(leaf_count, int):
        raise ApiError(
            INVALID_REQUEST,
            f"'leafCount' must be a positive integer, got "
            f"{leaf_count!r} ({type(leaf_count).__name__})",
            loc="leafCount",
        )
    if leaf_count < 1:
        raise ApiError(
            BAD_PROOF,
            f"'leafCount' must be at least 1, got {leaf_count}",
            loc="leafCount",
        )
    sizes = level_sizes_for_leaf_count(leaf_count)

    raw_leaves = _get_field(body, "leaves", "leaves")
    if not isinstance(raw_leaves, list):
        raise ApiError(
            INVALID_REQUEST,
            "'leaves' must be an array of {path, value, index} objects",
            loc="leaves",
        )
    if len(raw_leaves) == 0:
        raise ApiError(
            EMPTY_REVEAL,
            "'leaves' must contain at least one disclosure to verify",
            loc="leaves",
        )
    if len(raw_leaves) > leaf_count:
        raise ApiError(
            BAD_PROOF,
            f"{len(raw_leaves)} disclosed leaves exceed leafCount "
            f"{leaf_count}",
            loc="leaves",
        )

    verified: List[Dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_indices: set[int] = set()
    digests_by_index: Dict[int, bytes] = {}
    for i, raw_leaf in enumerate(raw_leaves):
        loc = f"leaves[{i}]"
        path, value = _parse_disclosed_leaf(raw_leaf, loc)
        if path in seen_paths:
            raise ApiError(
                DUPLICATE_PATH,
                f"path {path!r} is submitted more than once",
                loc=f"{loc}.path",
                detail={"path": path},
            )
        seen_paths.add(path)

        if "proof" in raw_leaf:
            raise ApiError(
                BAD_PROOF,
                "compact disclosures carry no per-leaf 'proof'; the proof is "
                "the deduplicated top-level 'proof' array",
                loc=f"{loc}.proof",
            )

        index = _get_field(raw_leaf, "index", f"{loc}.index")
        if isinstance(index, bool) or not isinstance(index, int):
            raise ApiError(
                BAD_PROOF,
                f"'index' must be a non-negative integer, got "
                f"{index!r} ({type(index).__name__})",
                loc=f"{loc}.index",
            )
        if not 0 <= index < leaf_count:
            raise ApiError(
                BAD_PROOF,
                f"leaf index {index} out of range (leafCount {leaf_count})",
                loc=f"{loc}.index",
            )
        if index in seen_indices:
            raise ApiError(
                BAD_PROOF,
                f"duplicate leaf index {index}",
                loc=f"{loc}.index",
                detail={"index": index},
            )
        seen_indices.add(index)
        digests_by_index[index] = _leaf_digest(path, value, loc)
        verified.append({"path": path, "value": value})

    # TreeError here can only come from the defensive checks in tree.py; the
    # structural validation above already produced precise locs.
    parsed_nodes = _compact_proof_nodes(_get_field(body, "proof", "proof"), sizes)
    required = required_proof_positions(leaf_count, seen_indices)
    provided = {(level, index) for level, index, _ in parsed_nodes}
    if required != provided:
        missing = sorted(required - provided)
        surplus = sorted(provided - required)
        if missing:
            level_no, idx = missing[0]
            raise ApiError(
                BAD_PROOF,
                f"missing proof node at level {level_no}, index {idx}: a "
                "sibling hash needed to rebuild the root is absent",
                loc=f"proof[?level={level_no}&index={idx}]",
                detail={"missing": [{"level": l, "index": j} for l, j in missing]},
            )
        level_no, idx = surplus[0]
        raise ApiError(
            BAD_PROOF,
            f"surplus proof node at level {level_no}, index {idx}: not "
            "needed to rebuild the root from the disclosed leaves",
            loc=f"proof[?level={level_no}&index={idx}]",
            detail={"surplus": [{"level": l, "index": j} for l, j in surplus]},
        )

    proof_nodes = [
        CompactProofNode(level=level, index=index, digest=digest)
        for level, index, digest in parsed_nodes
    ]
    try:
        rebuilt = compact_rebuild_root(leaf_count, digests_by_index, proof_nodes)
    except TreeError as exc:
        raise ApiError(BAD_PROOF, str(exc), loc="proof") from exc

    if rebuilt != expected_root:
        raise ApiError(
            ROOT_MISMATCH,
            "compact proof failed: the root rebuilt bottom-up from the "
            "disclosed values and deduplicated proof does not match the "
            "committed root",
            loc="root",
            http_status=422,
            detail={
                "paths": sorted(seen_paths),
                "committedRoot": expected_root.hex(),
                "hint": (
                    "a disclosed path or value, a proof node hash or the "
                    "root was tampered with"
                ),
            },
        )

    verified.sort(key=lambda item: item["path"])
    return verified


@app.post("/verify", openapi_extra=_VERIFY_OPENAPI)
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

    # Automatic format detection: compact disclosures name a global
    # 'leafCount' (and carry per-leaf 'index'); legacy disclosures carry
    # per-leaf 'proof' steps and no leafCount.
    is_compact = "leafCount" in body
    if is_compact:
        verified = _verify_compact(body, expected_root)
        return {"valid": True, "root": expected_root.hex(), "leaves": verified}

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
        path, value = _parse_disclosed_leaf(raw_leaf, loc)
        if path in seen_paths:
            raise ApiError(
                DUPLICATE_PATH,
                f"path {path!r} is submitted more than once",
                loc=f"{loc}.path",
                detail={"path": path},
            )
        seen_paths.add(path)

        if "index" in raw_leaf:
            raise ApiError(
                BAD_PROOF,
                "per-leaf 'index' is only valid in compact disclosures, "
                "which also require a top-level 'leafCount' and a "
                "deduplicated top-level 'proof'",
                loc=f"{loc}.index",
            )

        steps = _proof_steps(
            _get_field(raw_leaf, "proof", f"{loc}.proof"), f"{loc}.proof"
        )
        digest = _leaf_digest(path, value, loc)

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
        "proofModes": list(PROOF_MODES),
        "defaultProofMode": DEFAULT_PROOF_MODE,
        "maxBodyBytes": MAX_BODY_BYTES,
    }


# ---------------------------------------------------------------------------
# OpenAPI components for the hand-written endpoint documentation above
# ---------------------------------------------------------------------------

_PROOF_STEP_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["side", "sibling"],
    "properties": {
        "side": {"type": "string", "enum": ["left", "right"]},
        "sibling": _HEX64_SCHEMA,
    },
}

_COMPACT_PROOF_NODE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "description": (
        "One deduplicated sibling addressed by its absolute tree position. "
        "Level 0 is the sorted leaf level; odd-width levels duplicate their "
        "last node when paired. Each (level, index) appears at most once."
    ),
    "required": ["level", "index", "hash"],
    "properties": {
        "level": {
            "type": "integer",
            "minimum": 0,
            "description": "Tree level above the leaves (0 = leaf level).",
        },
        "index": {
            "type": "integer",
            "minimum": 0,
            "description": "Node index within that level, before tail duplication.",
        },
        "hash": _HEX64_SCHEMA,
    },
}

_LEGACY_LEAF_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["path", "value", "proof"],
    "properties": {
        "path": {"type": "string", "description": "RFC 6901 JSON Pointer."},
        "value": {
            "description": "The disclosed canonical leaf value (scalar, null, {} or []).",
        },
        "proof": {
            "type": "array",
            "items": _PROOF_STEP_SCHEMA,
            "description": "Leaf-to-root siblings; empty for a one-leaf tree.",
        },
    },
}

_COMPACT_LEAF_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["path", "value", "index"],
    "properties": {
        "path": {"type": "string", "description": "RFC 6901 JSON Pointer."},
        "value": {"description": "The disclosed canonical leaf value."},
        "index": {
            "type": "integer",
            "minimum": 0,
            "description": (
                "Sorted leaf index (level-0 position). Unique within the "
                "disclosure and strictly smaller than leafCount."
            ),
        },
    },
}

_ERROR_BODY = {
    "type": "object",
    "properties": {
        "error": {
            "type": "object",
            "required": ["code", "message"],
            "properties": {
                "code": {"type": "string"},
                "message": {"type": "string"},
                "loc": {"type": "string"},
                "detail": {"type": "object"},
            },
        }
    },
}


def _custom_openapi() -> Dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema
    spec = FastAPI.openapi(app)
    spec["info"]["description"] = (
        "Commit a nested JSON document to a reproducible Merkle root and "
        "disclose individual RFC 6901 leaf facts with inclusion proofs.\n\n"
        "`POST /commit` accepts `proofMode: \"compact\"`: multi-path "
        "disclosures then return `leafCount`, each leaf's sorted `index`, "
        "and a single deduplicated `proof` array of "
        "`{level, index, hash}` siblings (each tree position at most once). "
        "`POST /verify` detects the format automatically."
    )
    spec.setdefault("components", {})
    spec["components"].setdefault("schemas", {})
    spec["components"]["schemas"].update(
        {
            "CommitRequest": {
                "type": "object",
                "additionalProperties": False,
                "required": ["document", "reveal"],
                "properties": {
                    "document": {"description": "Any JSON document."},
                    "reveal": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string"},
                        "description": "RFC 6901 pointers of the leaves to disclose.",
                    },
                    "proofMode": {
                        "type": "string",
                        "enum": list(PROOF_MODES),
                        "default": "legacy",
                        "description": (
                            "'legacy' (default) repeats a sibling path per "
                            "leaf; 'compact' returns one deduplicated "
                            "multi-leaf proof addressed by (level, index)."
                        ),
                    },
                },
            },
            "VerifyRequest": {
                "type": "object",
                "additionalProperties": False,
                "required": ["root", "leaves"],
                "properties": {
                    "root": _HEX64_SCHEMA,
                    "leaves": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "oneOf": [_LEGACY_LEAF_SCHEMA, _COMPACT_LEAF_SCHEMA]
                        },
                    },
                    "leafCount": {
                        "type": "integer",
                        "minimum": 1,
                        "description": (
                            "Presence of leafCount switches /verify to "
                            "compact mode: every leaf then carries 'index' "
                            "and the top-level 'proof' is an array of "
                            "{level, index, hash} nodes."
                        ),
                    },
                    "proof": {
                        "type": "array",
                        "items": _COMPACT_PROOF_NODE_SCHEMA,
                        "description": "Compact-mode deduplicated proof nodes.",
                    },
                },
            },
            "CompactProofNode": _COMPACT_PROOF_NODE_SCHEMA,
            "ProofStep": _PROOF_STEP_SCHEMA,
        }
    )
    spec["components"]["responses"] = {
        "ClientError": {
            "description": (
                "Structural or encoding error (INVALID_JSON, INVALID_REQUEST, "
                "POINTER_SYNTAX, PATH_NOT_FOUND, PATH_NOT_LEAF, "
                "DUPLICATE_PATH, EMPTY_REVEAL, UNSUPPORTED_VALUE, "
                "BAD_HASH_ENCODING, BAD_PROOF, PAYLOAD_TOO_LARGE)."
            ),
            "content": {"application/json": {"schema": _ERROR_BODY}},
        },
        "RootMismatch": {
            "description": (
                "The proof folded to a different root (a path, value, proof "
                "hash or the root itself was tampered with)."
            ),
            "content": {"application/json": {"schema": _ERROR_BODY}},
        },
    }
    app.openapi_schema = spec
    return spec


app.openapi = _custom_openapi  # type: ignore[assignment]
