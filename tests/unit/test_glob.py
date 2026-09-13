"""Resource globs against an independent recursive reference matcher."""

from __future__ import annotations

import time
from functools import cache

import pytest
from hypothesis import given
from hypothesis import strategies as st

from capability_tool_broker.capabilities.glob import (
    glob_match,
    is_valid_glob,
    is_valid_resource,
    text_glob_match,
    validate_glob,
    validate_resource,
)

pytestmark = pytest.mark.unit


def oracle_text(pattern: str, value: str) -> bool:
    @cache
    def match(i: int, j: int) -> bool:
        if i == len(pattern):
            return j == len(value)
        if pattern[i] == "*":
            return match(i + 1, j) or (j < len(value) and match(i, j + 1))
        if j == len(value):
            return False
        return pattern[i] in ("?", value[j]) and match(i + 1, j + 1)

    return match(0, 0)


def oracle_glob(pattern: str, resource: str) -> bool:
    pattern_parts, value_parts = pattern.split("/"), resource.split("/")

    @cache
    def match(i: int, j: int) -> bool:
        if i == len(pattern_parts):
            return j == len(value_parts)
        if pattern_parts[i] == "**":
            return match(i + 1, j) or (j < len(value_parts) and match(i, j + 1))
        return (
            j < len(value_parts)
            and oracle_text(pattern_parts[i], value_parts[j])
            and match(i + 1, j + 1)
        )

    return match(0, 0)


value_segments = st.text(alphabet="ab", min_size=1, max_size=4)
pattern_segments = st.one_of(
    st.just("**"),
    st.text(alphabet="ab*?", min_size=1, max_size=4).filter(lambda s: "**" not in s),
)


@given(
    pattern=st.lists(pattern_segments, min_size=1, max_size=5).map("/".join),
    resource=st.lists(value_segments, min_size=1, max_size=5).map("/".join),
)
def test_glob_matching_equals_the_reference_matcher(pattern: str, resource: str) -> None:
    assert glob_match(pattern, resource) is oracle_glob(pattern, resource)


@given(pattern=st.text(alphabet="ab*?/", max_size=8), value=st.text(alphabet="ab/", max_size=8))
def test_text_matching_equals_the_reference_matcher(pattern: str, value: str) -> None:
    assert text_glob_match(pattern, value) is oracle_text(pattern, value)


@pytest.mark.parametrize(
    ("pattern", "resource", "expected"),
    [
        ("invoice/42", "invoice/42", True),
        ("invoice/*", "invoice/42", True),
        ("invoice/*", "invoice/42/lines", False),
        ("invoice/**", "invoice/42/lines", True),
        ("invoice/**", "invoice", True),
        ("invoice/4?", "invoice/42", True),
        ("invoice/4?", "invoice/4", False),
        ("mail/*@example.com", "mail/alice@example.com", True),
        ("mail/*@example.com", "mail/alice@evil.example", False),
        ("**/lines", "invoice/42/lines", True),
    ],
)
def test_examples(pattern: str, resource: str, expected: bool) -> None:
    assert glob_match(pattern, resource) is expected


@pytest.mark.parametrize(
    "pattern", ["", "a**", "a/../b", "a//b", "a b", "x" * 300, "/".join(["a"] * 17)]
)
def test_invalid_globs_never_match(pattern: str) -> None:
    assert not is_valid_glob(pattern)
    assert not glob_match(pattern, "a")
    with pytest.raises(ValueError, match="glob"):
        validate_glob(pattern)


@pytest.mark.parametrize("resource", ["", "a*", "a/./b", "a/", "a?b", "é"])
def test_invalid_resources(resource: str) -> None:
    assert not is_valid_resource(resource)
    assert not glob_match("**", resource)
    with pytest.raises(ValueError, match="resource"):
        validate_resource(resource)


def test_hostile_patterns_match_in_bounded_time() -> None:
    pattern = "/".join(["*a*a*a*a*a*a*a*a*a*b"] * 7 + ["**"] * 9)
    resource = "/".join(["a" * 64] * 16)
    started = time.perf_counter()
    for _ in range(20):
        assert glob_match(pattern, resource) is False
    assert time.perf_counter() - started < 2.0
