"""RFC 6901 JSON Pointer helpers.

A pointer is represented as its standard textual form:

* ``""`` refers to the whole document (used only for scalar/empty root docs);
* every reference token is prefixed with ``/``;
* within a token ``~1`` means a literal ``/`` and ``~0`` a literal ``~``
  (``~1`` MUST be unescaped before ``~0``).
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


class PointerError(ValueError):
    """Raised when a pointer string violates RFC 6901 syntax."""


def parse_pointer(pointer: str) -> Tuple[str | int, ...]:
    """Parse an RFC 6901 pointer string into reference tokens.

    Array indices are returned as ``int``, object member names as ``str``.

    Note: the RFC treats ``01`` / ``-`` as valid *tokens* that simply never
    resolve against an array; that resolution failure is reported later by
    :func:`resolve`, not here.  A trailing ``~`` is the only token-level
    syntax error defined by the RFC.
    """

    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise PointerError(
            f"non-empty pointer must start with '/', got: {pointer!r}"
        )

    tokens: List[str | int] = []
    raw_tokens = pointer.split("/")[1:]
    for raw in raw_tokens:
        if "~" in raw:
            for i, ch in enumerate(raw):
                if ch == "~" and (i + 1 >= len(raw) or raw[i + 1] not in "01"):
                    raise PointerError(
                        f"invalid escape sequence in token {raw!r}: "
                        "'~' must be followed by '0' or '1'"
                    )
        token = raw.replace("~1", "/").replace("~0", "~")
        tokens.append(token)
    return tuple(tokens)


def _decode_array_index(token: str) -> int | None:
    """Return the array index for *token*, or ``None`` if it is not one."""
    if token == "0":
        return 0
    if token.isdigit() and not token.startswith("0"):
        return int(token)
    return None


def resolve(doc: Any, tokens: Tuple[str | int, ...]) -> Any:
    """Resolve parsed *tokens* against *doc*.

    ``KeyError`` / ``IndexError`` / ``TypeError`` carry a descriptive message
    and the failing token position.
    """

    current = doc
    for pos, token in enumerate(tokens):
        if isinstance(current, dict):
            if token not in current:
                raise KeyError(
                    f"object has no member {str(token)!r} at position {pos}"
                )
            current = current[token]
        elif isinstance(current, list):
            idx = _decode_array_index(str(token))
            if idx is None:
                raise IndexError(
                    f"token {token!r} is not a valid array index "
                    f"at position {pos}"
                )
            if idx < 0 or idx >= len(current):
                raise IndexError(
                    f"array index {idx} out of range (length {len(current)}) "
                    f"at position {pos}"
                )
            current = current[idx]
        else:
            raise TypeError(
                f"cannot resolve token {token!r} at position {pos}: "
                f"container is a scalar ({type(current).__name__})"
            )
    return current


def build_pointer(prefix: str, key: Any) -> str:
    """Append an object key (``str``) or array index (``int``) to *prefix*."""
    token = str(key).replace("~", "~0").replace("/", "~1")
    return prefix + "/" + token


def pointer_to_string(pointer: str) -> str:
    """Render a pointer for logs / error messages (root shown as ``<root>``)."""
    return pointer if pointer else "<root>"
