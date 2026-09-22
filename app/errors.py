"""API error type carrying a stable code and a JSON-Pointer-style location."""

from __future__ import annotations

from typing import Any, Dict, Optional


class ApiError(Exception):
    """An error whose shape is part of the public API contract.

    ``code``   stable machine-readable identifier;
    ``loc``    where the problem was detected, e.g. ``reveal[2]`` or
               ``proof[1].sibling``;
    ``detail`` free-form human-readable explanation.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        loc: Optional[str] = None,
        http_status: int = 400,
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.loc = loc
        self.http_status = http_status
        self.detail = detail or {}

    def to_body(self) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "error": {
                "code": self.code,
                "message": self.message,
            }
        }
        if self.loc is not None:
            body["error"]["loc"] = self.loc
        if self.detail:
            body["error"]["detail"] = self.detail
        return body


# Stable error codes ---------------------------------------------------------

INVALID_JSON = "INVALID_JSON"
INVALID_REQUEST = "INVALID_REQUEST"
POINTER_SYNTAX = "POINTER_SYNTAX"
PATH_NOT_FOUND = "PATH_NOT_FOUND"
PATH_NOT_LEAF = "PATH_NOT_LEAF"
DUPLICATE_PATH = "DUPLICATE_PATH"
EMPTY_REVEAL = "EMPTY_REVEAL"
UNSUPPORTED_VALUE = "UNSUPPORTED_VALUE"
BAD_HASH_ENCODING = "BAD_HASH_ENCODING"
BAD_PROOF = "BAD_PROOF"
ROOT_MISMATCH = "ROOT_MISMATCH"
PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
