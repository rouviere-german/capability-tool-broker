"""The caveat DSL: canonical round trips, fail-closed parsing and evaluation semantics."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import JsonValue

from capability_tool_broker.capabilities.caveats import (
    ArgPredicate,
    CaveatSyntaxError,
    ClientIn,
    ExpiresBefore,
    HostIn,
    MaxCalls,
    Once,
    Predicate,
    RequestHashIs,
    ResourceMatches,
    TaskIs,
    ToolIn,
    VerbIn,
    evaluate,
    format_caveat,
    format_time,
    is_stateful,
    parse_caveat,
)
from capability_tool_broker.capabilities.request import CanonicalRequest, RequestContext, Verb

pytestmark = pytest.mark.unit

NOW = 1_800_000_000

names = st.from_regex(r"[a-z][a-z0-9_]{0,12}", fullmatch=True)
task_ids = st.from_regex(r"[a-z0-9][a-z0-9-]{0,20}", fullmatch=True)
hosts = st.from_regex(r"[a-z0-9]{1,8}(\.[a-z0-9]{1,8}){0,2}", fullmatch=True)
globs = (
    st.lists(
        st.one_of(st.just("**"), st.from_regex(r"[a-z0-9*?@.-]{1,6}", fullmatch=True)),
        min_size=1,
        max_size=3,
    )
    .map("/".join)
    .filter(lambda g: all(p == "**" or "**" not in p for p in g.split("/")))
)
scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**12), max_value=10**12),
    st.floats(allow_nan=False, allow_infinity=False, width=64),
    st.text(
        alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E)
        | st.sampled_from("äöüß€中文"),
        max_size=12,
    ),
)


def unique(
    strategy: st.SearchStrategy[str], max_size: int = 4
) -> st.SearchStrategy[tuple[str, ...]]:
    return st.lists(strategy, min_size=1, max_size=max_size, unique=True).map(tuple)


def arg_predicates() -> st.SearchStrategy[Predicate]:
    paths = st.lists(names, min_size=1, max_size=3).map(tuple)
    return st.one_of(
        st.builds(ArgPredicate, paths, st.sampled_from(["=", "!="]), scalars),
        st.builds(
            ArgPredicate,
            paths,
            st.sampled_from(["<", "<=", ">", ">="]),
            st.integers(min_value=-1000, max_value=1000) | st.floats(-1e6, 1e6),
        ),
        st.builds(ArgPredicate, paths, st.just("in"), st.lists(scalars, min_size=1, max_size=4)),
        st.builds(
            ArgPredicate,
            paths,
            st.just("matches"),
            st.text(alphabet="ab*?", min_size=1, max_size=8),
        ),
    )


predicates: st.SearchStrategy[Predicate] = st.one_of(
    st.builds(TaskIs, task_ids),
    st.builds(ClientIn, unique(st.from_regex(r"[a-z0-9][a-z0-9_-]{0,10}", fullmatch=True))),
    st.builds(ToolIn, unique(names)),
    st.builds(
        VerbIn,
        st.lists(st.sampled_from(list(Verb)), min_size=1, max_size=3, unique=True).map(tuple),
    ),
    st.builds(HostIn, unique(hosts)),
    st.builds(ResourceMatches, unique(globs)),
    st.builds(ExpiresBefore, st.integers(min_value=946_684_800, max_value=32_503_679_999)),
    st.builds(MaxCalls, st.integers(min_value=1, max_value=999_999_999)),
    st.builds(Once, st.from_regex(r"[0-9a-f]{32}", fullmatch=True)),
    st.builds(RequestHashIs, st.from_regex(r"[0-9a-f]{64}", fullmatch=True)),
    arg_predicates(),
)


def request(**overrides: object) -> CanonicalRequest:
    values: dict[str, object] = {
        "task_id": "task-1",
        "tool": "invoices_read",
        "verb": Verb.READ,
        "host": "invoices.internal",
        "resource": "invoice/42",
        "args": {"amount": 250, "currency": "EUR", "flag": True, "nested": {"level": 2}},
    }
    values.update(overrides)
    return CanonicalRequest.model_validate(values)


def ctx(
    req: CanonicalRequest | None = None, now: int = NOW, client: str | None = "agent-host"
) -> RequestContext:
    return RequestContext(request=req or request(), now=now, client_id=client)


@given(predicates)
def test_every_predicate_has_exactly_one_canonical_encoding(predicate: Predicate) -> None:
    text = format_caveat(predicate)
    assert parse_caveat(text) == predicate
    assert format_caveat(parse_caveat(text)) == text


@pytest.mark.parametrize(
    "condition",
    [
        "",
        "task_id",
        "task_id  = t",
        "task_id = T",
        "tool in a,a",
        "tool in ",
        "verb in read,execute",
        "resource matches a**",
        "expires < 2026-02-30T00:00:00Z",
        "expires < 1999-12-31T23:59:59Z",
        "expires < 2026-01-01 00:00:00",
        "max_calls <= 0",
        "max_calls <= 03",
        "once = ABC",
        "request_hash = 1234",
        'arg amount <= "500"',
        "arg amount in []",
        "arg amount = [1]",
        "arg amount = 1.50",
        "arg amount = NaN",
        "arg Amount = 1",
        "arg amount ~ 1",
        "arg a.b.c.d.e = 1",
        "arg amount",
        "unknown = 1",
        "tool in a\nb",
        "tool in " + ",".join(f"t{i}" for i in range(33)),
        "task_id = " + "a" * 2000,
        "task_id = \ud800",
    ],
)
def test_malformed_or_non_canonical_conditions_are_rejected(condition: str) -> None:
    with pytest.raises(CaveatSyntaxError):
        parse_caveat(condition)


def test_first_party_predicates_evaluate_against_the_request() -> None:
    context = ctx()
    assert evaluate(TaskIs("task-1"), context)
    assert not evaluate(TaskIs("task-2"), context)
    assert evaluate(ClientIn(("agent-host",)), context)
    assert not evaluate(ClientIn(("agent-host",)), ctx(client=None))
    assert evaluate(ToolIn(("x", "invoices_read")), context)
    assert not evaluate(ToolIn(("files_read",)), context)
    assert evaluate(VerbIn((Verb.READ,)), context)
    assert not evaluate(VerbIn((Verb.WRITE, Verb.DELETE)), context)
    assert evaluate(HostIn(("invoices.internal",)), context)
    assert not evaluate(HostIn(("files.internal",)), context)
    assert evaluate(ResourceMatches(("invoice/4?",)), context)
    assert not evaluate(ResourceMatches(("invoice/43", "file/*")), context)
    assert evaluate(ExpiresBefore(NOW + 1), context)
    assert not evaluate(ExpiresBefore(NOW), context)
    assert evaluate(RequestHashIs(request().request_hash()), context)
    assert not evaluate(RequestHashIs("0" * 64), context)
    assert evaluate(MaxCalls(1), context)
    assert evaluate(Once("0" * 32), context)
    assert is_stateful(MaxCalls(1))
    assert is_stateful(Once("0" * 32))
    assert not is_stateful(TaskIs("t"))


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("arg amount <= 250", True),
        ("arg amount < 250", False),
        ("arg amount >= 250.0", True),
        ("arg amount > 100", True),
        ("arg amount = 250.0", True),
        ("arg amount != 251", True),
        ('arg currency = "EUR"', True),
        ('arg currency in ["USD","EUR"]', True),
        ('arg currency in ["USD"]', False),
        ('arg currency matches "E*"', True),
        ('arg currency matches "U?D"', False),
        ("arg flag = true", True),
        ("arg flag = 1", False),
        ("arg amount = true", False),
        ("arg flag <= 1", False),
        ("arg nested.level = 2", True),
        ("arg nested = 2", False),
        ("arg missing = null", False),
        ("arg missing != 1", False),
        ("arg currency < 5", False),
        ('arg amount matches "2*"', False),
    ],
)
def test_argument_predicates(condition: str, expected: bool) -> None:
    assert evaluate(parse_caveat(condition), ctx()) is expected


def test_time_formatting_is_utc_and_second_precise() -> None:
    assert format_time(0 + 946_684_800) == "2000-01-01T00:00:00Z"
    assert parse_caveat("expires < 2026-09-13T12:00:00Z") == ExpiresBefore(1_789_300_800)


def test_numeric_comparisons_on_json_numbers() -> None:
    literal: JsonValue = 1.5
    predicate = ArgPredicate(("amount",), "<", literal)
    assert evaluate(predicate, ctx(request(args={"amount": 1})))
    assert not evaluate(predicate, ctx(request(args={"amount": 2})))
