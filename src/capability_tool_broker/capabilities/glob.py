"""Resource names and resource globs.

A resource is a ``/``-separated path of 1 to 16 segments; each segment uses ``[A-Za-z0-9._@-]``,
is 1 to 64 characters long and is not ``.`` or ``..``. Globs use the same segments plus:

- ``*`` matches any run of characters inside one segment (possibly empty);
- ``?`` matches exactly one character inside one segment;
- ``**`` as a whole segment matches zero or more whole segments.

So ``invoice/*`` matches ``invoice/42`` but not ``invoice/42/lines``, and ``invoice/**`` matches
both (and ``invoice`` itself). There are no character classes and no escapes, because resources
cannot contain ``*`` or ``?``.

Matching runs in O(len(pattern) * len(value)) time without regular expressions, so an attacker who
appends a hostile glob caveat to a token cannot make the broker backtrack exponentially.
"""

from __future__ import annotations

import functools
import re

__all__ = [
    "MAX_RESOURCE_LENGTH",
    "MAX_SEGMENTS",
    "glob_match",
    "is_valid_glob",
    "is_valid_resource",
    "text_glob_match",
    "validate_glob",
    "validate_resource",
]

MAX_RESOURCE_LENGTH = 256
MAX_SEGMENTS = 16
_RESOURCE_SEGMENT = re.compile(r"[A-Za-z0-9._@-]{1,64}")
_GLOB_SEGMENT = re.compile(r"[A-Za-z0-9._@*?-]{1,64}")
_GLOBSTAR = "**"


def _segments(value: str) -> list[str] | None:
    if not value or len(value) > MAX_RESOURCE_LENGTH:
        return None
    parts = value.split("/")
    if len(parts) > MAX_SEGMENTS or any(part in {".", ".."} for part in parts):
        return None
    return parts


@functools.lru_cache(maxsize=65_536)
def is_valid_resource(value: str) -> bool:
    parts = _segments(value)
    return parts is not None and all(_RESOURCE_SEGMENT.fullmatch(part) for part in parts)


def validate_resource(value: str) -> str:
    if not is_valid_resource(value):
        raise ValueError("resource must be 1-16 '/'-separated segments of [A-Za-z0-9._@-]")
    return value


@functools.lru_cache(maxsize=65_536)
def is_valid_glob(pattern: str) -> bool:
    parts = _segments(pattern)
    if parts is None:
        return False
    for part in parts:
        if part == _GLOBSTAR:
            continue
        if not _GLOB_SEGMENT.fullmatch(part) or _GLOBSTAR in part:
            return False
    return True


def validate_glob(pattern: str) -> str:
    if not is_valid_glob(pattern):
        raise ValueError("invalid resource glob")
    return pattern


def text_glob_match(pattern: str, value: str) -> bool:
    """``*`` matches any run of characters, ``?`` one character, everything else is literal.

    The classic single-backtrack-point algorithm: when a mismatch happens after a ``*``, only
    the most recent ``*`` needs to absorb one more character, so the run time is bounded by
    ``len(pattern) * len(value)``.
    """
    p_index = v_index = 0
    star = -1
    mark = 0
    while v_index < len(value):
        if p_index < len(pattern) and pattern[p_index] == "*":
            star, mark = p_index, v_index
            p_index += 1
        elif p_index < len(pattern) and pattern[p_index] in ("?", value[v_index]):
            p_index += 1
            v_index += 1
        elif star != -1:
            mark += 1
            p_index, v_index = star + 1, mark
        else:
            return False
    while p_index < len(pattern) and pattern[p_index] == "*":
        p_index += 1
    return p_index == len(pattern)


@functools.lru_cache(maxsize=65_536)
def glob_match(pattern: str, resource: str) -> bool:
    """True if ``resource`` matches ``pattern``. Invalid patterns or resources never match."""
    if not is_valid_glob(pattern) or not is_valid_resource(resource):
        return False
    pattern_parts = pattern.split("/")
    value_parts = resource.split("/")
    p_index = v_index = 0
    star = -1
    mark = 0
    while v_index < len(value_parts):
        if p_index < len(pattern_parts) and pattern_parts[p_index] == _GLOBSTAR:
            star, mark = p_index, v_index
            p_index += 1
        elif p_index < len(pattern_parts) and text_glob_match(
            pattern_parts[p_index], value_parts[v_index]
        ):
            p_index += 1
            v_index += 1
        elif star != -1:
            mark += 1
            p_index, v_index = star + 1, mark
        else:
            return False
    while p_index < len(pattern_parts) and pattern_parts[p_index] == _GLOBSTAR:
        p_index += 1
    return p_index == len(pattern_parts)
