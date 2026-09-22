"""Strict JSON loading for request bodies.

Python's default decoder accepts duplicate object member names silently and
reports parse errors with a positional message.  Both behaviors are wrapped
here so the API can reject duplicates (they make RFC 6901 paths ambiguous)
and point at the character where parsing failed.
"""

from __future__ import annotations

import json
from typing import Any

from .errors import ApiError, INVALID_JSON


class _RejectDuplicates(json.JSONDecoder):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # Recreate object_pairs_hook per decode so duplicate tracking resets.
        self._paths_with_dupes: list[str] = []

        def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            seen: set[str] = set()
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in seen:
                    self._paths_with_dupes.append(key)
                seen.add(key)
                result[key] = value
            return result

        super().__init__(*args, object_pairs_hook=hook, **kwargs)


def parse_json_strict(raw: bytes, *, field: str = "body") -> Any:
    """Parse *raw* as JSON, raising a locatable :class:`ApiError` on failure.

    ``field`` names the offending request field for the error ``loc``
    (``"body"`` or ``"document"`` for nested document strings).
    """

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiError(
            "INVALID_JSON",
            f"request body is not valid UTF-8: {exc.reason}",
            loc=field,
        ) from exc

    decoder = _RejectDuplicates()
    try:
        value, end = decoder.raw_decode(text)
    except json.JSONDecodeError as exc:
        raise ApiError(
            "INVALID_JSON",
            f"malformed JSON at line {exc.lineno}, column {exc.colno} "
            f"(char {exc.pos}): {exc.msg}",
            loc=f"{field}@char:{exc.pos}",
        ) from exc

    tail = text[end:].strip()
    if tail:
        raise ApiError(
            "INVALID_JSON",
            "trailing data after the JSON value",
            loc=f"{field}@char:{end}",
        )
    if decoder._paths_with_dupes:
        key = decoder._paths_with_dupes[0]
        raise ApiError(
            "INVALID_JSON",
            f"duplicate object member name {key!r}: RFC 6901 paths must be "
            "unambiguous",
            loc=f"{field}.<duplicate-key>",
            detail={"duplicateKey": key},
        )
    return value
