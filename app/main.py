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
    ProofStep,
    expand_leaves,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    verify_inclusion,
)
from .validation import validate_json_value

MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(10 * 1024 * 1024)))
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")

app = FastAPI(
    title="Selective JSON Disclosure",
    version="1.0.0",
    description=(
        "Commit a nested JSON document to a reproducible Merkle root and "
        "disclose individual RFC 6901 leaf facts with inclusion proofs."
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

    disclosed = []
    # Output selected leaves in sorted-pointer order for stable responses.
    for pointer in sorted(selected_pointers):
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
        "version": "1.0.0",
        "endpoints": {
            "commit": "POST /commit",
            "verify": "POST /verify",
            "docs": "GET /docs",
            "health": "GET /healthz",
        },
        "hash": "sha256",
        "maxBodyBytes": MAX_BODY_BYTES,
    }
