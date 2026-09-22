"""Canonical JSON encoding for leaf values.

The disclosure scheme requires a *single deterministic byte serialization*
per JSON value so that the same logical value always hashes identically.
JSON itself (RFC 8259) allows insignificant whitespace, object member
reordering and non-shortest number encodings, so a canonical form is needed.

Rules used here (a deliberately small subset-style canonical form; see the
README "规范 JSON" section):

* UTF-8 output, no insignificant whitespace;
* object members sorted by member name by Unicode code point
  (i.e. Python ``str`` ordering), recursively;
* integers rendered in shortest decimal form;
* floats rendered with ``repr`` (shortest round-trip representation);
  ``NaN`` / ``Infinity`` / ``-Infinity`` are rejected (not JSON values);
* strings minimally escaped: the mandatory escapes ``"``, ``\\`` and the
  C0 control characters, plus ``\\b`` ``\\f`` ``\\n`` ``\\r`` ``\\t``;
* literals ``true`` / ``false`` / ``null``.

Only scalar values are ever canonicalized through
:func:`canonical_scalar_bytes`; :func:`canonical_json_bytes` exists for
validating arbitrary submitted values (e.g. on the verification endpoint).
"""

from __future__ import annotations

import math
from typing import Any

_NON_FINITE = (math.nan, math.inf, -math.inf)


class CanonicalError(ValueError):
    """Raised when a value cannot be represented in canonical JSON."""


def _check_str(value: str, loc: str) -> None:
    """Reject lone UTF-16 surrogates, which cannot be encoded as UTF-8.

    Such strings can only originate from hand-crafted payloads (Python's own
    ``json`` parser never produces them), but they would otherwise explode
    deep inside the encoder with an opaque error.
    """
    for i, ch in enumerate(value):
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise CanonicalError(
                f"lone surrogate U+{ord(ch):04X} in string at {loc} "
                f"(character position {i}) cannot be encoded as UTF-8"
            )


def _encode_str(value: str) -> bytes:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out).encode("utf-8")


def _encode(value: Any, loc: str) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalError(
                f"non-finite float at {loc} is not a valid JSON number"
            )
        return repr(value).encode("ascii")
    if isinstance(value, str):
        _check_str(value, loc)
        return _encode_str(value)
    if isinstance(value, list):
        parts = [_encode(item, f"{loc}[{i}]") for i, item in enumerate(value)]
        return b"[" + b",".join(parts) + b"]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalError(
                    f"object key at {loc} must be a string, "
                    f"got {type(key).__name__}"
                )
            _check_str(key, f"{loc}.<key>")
        members = []
        for key in sorted(value.keys()):
            members.append(_encode_str(key) + b":" + _encode(value[key], loc + "." + key))
        return b"{" + b",".join(members) + b"}"
    raise CanonicalError(
        f"unsupported type {type(value).__name__} at {loc}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 JSON serialization of any JSON value."""
    return _encode(value, "$")


def canonical_scalar_bytes(value: Any) -> bytes:
    """Return canonical serialization, rejecting non-scalars.

    Empty containers are leaf *paths*, but the value placed on the wire for
    them is ``{}`` / ``[]`` (a 2-byte canonical value), so containers pass
    through here only when empty.
    """
    if isinstance(value, (dict, list)):
        if len(value) != 0:
            raise CanonicalError(
                "canonical_scalar_bytes only accepts scalars and empty "
                "containers"
            )
        return b"{}" if isinstance(value, dict) else b"[]"
    return canonical_json_bytes(value)
