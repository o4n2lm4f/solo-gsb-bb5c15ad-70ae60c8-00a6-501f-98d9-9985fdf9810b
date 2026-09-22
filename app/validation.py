"""Validation of externally submitted JSON-shaped Python values.

Everything that arrives over HTTP already passes through a strict JSON
decoder on the commit endpoint, but verification requests are validated
independently (the verifier never sees the original document) and callers
may still submit ``NaN``/``Infinity`` as hand-crafted floats.
"""

from __future__ import annotations

import math
from typing import Any, Set

from .errors import ApiError, UNSUPPORTED_VALUE


def validate_json_value(value: Any, loc: str = "$") -> None:
    """Raise :class:`ApiError` if *value* is not a finite, encodable JSON tree."""

    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ApiError(
                UNSUPPORTED_VALUE,
                f"non-finite number at {loc} is not a valid JSON value",
                loc=loc,
            )
        return
    if isinstance(value, str):
        for i, ch in enumerate(value):
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise ApiError(
                    UNSUPPORTED_VALUE,
                    f"lone surrogate U+{ord(ch):04X} at {loc}[{i}] cannot be "
                    "encoded as UTF-8",
                    loc=f"{loc}[{i}]",
                )
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            validate_json_value(item, f"{loc}[{i}]")
        return
    if isinstance(value, dict):
        seen: Set[str] = set()
        for key, item in value.items():
            if not isinstance(key, str):
                raise ApiError(
                    UNSUPPORTED_VALUE,
                    f"object key at {loc} must be a string, "
                    f"got {type(key).__name__}",
                    loc=loc,
                )
            if key in seen:
                raise ApiError(
                    UNSUPPORTED_VALUE,
                    f"duplicate object member name {key!r} at {loc}",
                    loc=loc,
                    detail={"duplicateKey": key},
                )
            seen.add(key)
            validate_json_value(item, f"{loc}.{key}")
        return
    raise ApiError(
        UNSUPPORTED_VALUE,
        f"unsupported type {type(value).__name__} at {loc}",
        loc=loc,
    )
