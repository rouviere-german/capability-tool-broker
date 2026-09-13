"""The first-party caveat language: a small predicate DSL that is parsed, never evaluated as code.

Each caveat is one line ``<type> <operator> <value>`` in canonical form: formatting a parsed
condition gives back exactly the same text, so every predicate has a single encoding. Unknown
types, extra spaces and malformed values raise :class:`CaveatSyntaxError`, which the verifier
turns into a denial (fail closed). Caveats combine by conjunction: a request is authorized only if
every caveat on the token (and on its discharges) holds.

========================  ============================================  =====================
Condition                 Holds when                                    Example
========================  ============================================  =====================
``task_id = T``           the request's task id is T                    task_id = review-42
``client in A,B``         the authenticated caller is A or B            client in agent-host
``tool in A,B``           the tool is A or B                            tool in invoices_read
``verb in V,W``           the verb (from the manifest) is V or W        verb in read,write
``host in H,I``           the host (from the manifest) is H or I        host in files.internal
``resource matches G,H``  the resource matches glob G or H              resource matches a/*
``expires < TIME``        verifier time is before TIME (UTC seconds)    expires < 2026-09-13T12:00Z
``max_calls <= N``        stateful: at most N authorized calls          max_calls <= 3
``once = NONCE``          stateful: at most one authorized call         once = 9f86d0818...
``request_hash = H``      the canonical request hashes to H             request_hash = 3a7b...
``arg PATH OP JSON``      argument predicate, see below                 arg amount <= 500
========================  ============================================  =====================

Argument predicates: ``PATH`` is 1 to 4 dot-separated names (``[a-z_][a-z0-9_]{0,31}``) looked up
in nested objects. ``OP`` is one of ``= != < <= > >= in matches`` and ``JSON`` is a canonical JSON
literal: a scalar for ``=`` and ``!=``, a number for the orderings, a non-empty array of scalars
for ``in`` and a string for ``matches`` (``*`` any run, ``?`` one character). Missing arguments
and type mismatches make every argument predicate false; numbers compare numerically, booleans
are never numbers.

The stateful caveats (``max_calls``, ``once``) are always true at evaluation time; the verifier
collects them as claims that the broker commits atomically after every other check passed.
"""

from __future__ import annotations

import functools
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Literal

from pydantic import JsonValue

from capability_tool_broker.capabilities.glob import (
    glob_match,
    is_valid_glob,
    text_glob_match,
)
from capability_tool_broker.capabilities.request import (
    ARG_NAME_PATTERN,
    CLIENT_ID_PATTERN,
    TASK_ID_PATTERN,
    TOOL_PATTERN,
    RequestContext,
    Verb,
    is_valid_host,
)
from capability_tool_broker.core.canonical import CanonicalJSONError, canonical_json

__all__ = [
    "MAX_CONDITION_BYTES",
    "MAX_LIST_ITEMS",
    "ArgOp",
    "ArgPredicate",
    "CaveatSyntaxError",
    "CaveatType",
    "ClientIn",
    "ExpiresBefore",
    "HostIn",
    "MaxCalls",
    "Once",
    "Predicate",
    "RequestHashIs",
    "ResourceMatches",
    "TaskIs",
    "ToolIn",
    "VerbIn",
    "evaluate",
    "format_caveat",
    "format_time",
    "is_stateful",
    "parse_caveat",
]

MAX_CONDITION_BYTES = 1_024
MAX_LIST_ITEMS = 32
_MAX_ARG_PATH = 4
_MAX_MATCH_PATTERN = 128
_MIN_YEAR, _MAX_YEAR = 2000, 2999


class CaveatSyntaxError(ValueError):
    """A caveat condition that is not valid, canonical DSL."""


class CaveatType(StrEnum):
    TASK_ID = "task_id"
    CLIENT = "client"
    TOOL = "tool"
    VERB = "verb"
    HOST = "host"
    RESOURCE = "resource"
    EXPIRES = "expires"
    MAX_CALLS = "max_calls"
    ONCE = "once"
    REQUEST_HASH = "request_hash"
    ARG = "arg"


ArgOp = Literal["=", "!=", "<", "<=", ">", ">=", "in", "matches"]
_ARG_OPS: frozenset[str] = frozenset({"=", "!=", "<", "<=", ">", ">=", "in", "matches"})


@dataclass(frozen=True, slots=True)
class TaskIs:
    kind: ClassVar[CaveatType] = CaveatType.TASK_ID
    task_id: str


@dataclass(frozen=True, slots=True)
class ClientIn:
    kind: ClassVar[CaveatType] = CaveatType.CLIENT
    clients: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ToolIn:
    kind: ClassVar[CaveatType] = CaveatType.TOOL
    tools: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerbIn:
    kind: ClassVar[CaveatType] = CaveatType.VERB
    verbs: tuple[Verb, ...]


@dataclass(frozen=True, slots=True)
class HostIn:
    kind: ClassVar[CaveatType] = CaveatType.HOST
    hosts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ResourceMatches:
    kind: ClassVar[CaveatType] = CaveatType.RESOURCE
    globs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExpiresBefore:
    kind: ClassVar[CaveatType] = CaveatType.EXPIRES
    at: int


@dataclass(frozen=True, slots=True)
class MaxCalls:
    kind: ClassVar[CaveatType] = CaveatType.MAX_CALLS
    limit: int


@dataclass(frozen=True, slots=True)
class Once:
    kind: ClassVar[CaveatType] = CaveatType.ONCE
    nonce: str


@dataclass(frozen=True, slots=True)
class RequestHashIs:
    kind: ClassVar[CaveatType] = CaveatType.REQUEST_HASH
    digest: str


@dataclass(frozen=True, slots=True)
class ArgPredicate:
    kind: ClassVar[CaveatType] = CaveatType.ARG
    path: tuple[str, ...]
    op: ArgOp
    value: JsonValue


Predicate = (
    TaskIs
    | ClientIn
    | ToolIn
    | VerbIn
    | HostIn
    | ResourceMatches
    | ExpiresBefore
    | MaxCalls
    | Once
    | RequestHashIs
    | ArgPredicate
)

_TASK_ID = re.compile(TASK_ID_PATTERN)
_CLIENT_ID = re.compile(CLIENT_ID_PATTERN)
_TOOL = re.compile(TOOL_PATTERN)
_ARG_NAME = re.compile(ARG_NAME_PATTERN)
_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_LIMIT = re.compile(r"[1-9][0-9]{0,8}")
_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z")
_VERB_NAMES = frozenset(verb.value for verb in Verb)


# --- formatting ---------------------------------------------------------------------------------


def format_time(epoch_seconds: int) -> str:
    return datetime.fromtimestamp(epoch_seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_caveat(predicate: Predicate) -> str:  # noqa: PLR0911 - one branch per caveat type
    if isinstance(predicate, TaskIs):
        return f"task_id = {predicate.task_id}"
    if isinstance(predicate, ClientIn):
        return f"client in {','.join(predicate.clients)}"
    if isinstance(predicate, ToolIn):
        return f"tool in {','.join(predicate.tools)}"
    if isinstance(predicate, VerbIn):
        return f"verb in {','.join(verb.value for verb in predicate.verbs)}"
    if isinstance(predicate, HostIn):
        return f"host in {','.join(predicate.hosts)}"
    if isinstance(predicate, ResourceMatches):
        return f"resource matches {','.join(predicate.globs)}"
    if isinstance(predicate, ExpiresBefore):
        return f"expires < {format_time(predicate.at)}"
    if isinstance(predicate, MaxCalls):
        return f"max_calls <= {predicate.limit}"
    if isinstance(predicate, Once):
        return f"once = {predicate.nonce}"
    if isinstance(predicate, RequestHashIs):
        return f"request_hash = {predicate.digest}"
    return f"arg {'.'.join(predicate.path)} {predicate.op} {canonical_json(predicate.value)}"


# --- parsing ------------------------------------------------------------------------------------


def _expect(rest: str, operator: str) -> str:
    prefix = f"{operator} "
    if not rest.startswith(prefix):
        raise CaveatSyntaxError(f"expected operator '{operator}'")
    return rest[len(prefix) :]


def _items(value: str, check: Callable[[str], bool], what: str) -> tuple[str, ...]:
    items = value.split(",")
    if len(items) > MAX_LIST_ITEMS:
        raise CaveatSyntaxError(f"at most {MAX_LIST_ITEMS} {what} values are allowed")
    if len(set(items)) != len(items):
        raise CaveatSyntaxError(f"duplicate {what} values")
    for item in items:
        if not check(item):
            raise CaveatSyntaxError(f"invalid {what} value")
    return tuple(items)


def _parse_task(rest: str) -> Predicate:
    value = _expect(rest, "=")
    if not _TASK_ID.fullmatch(value):
        raise CaveatSyntaxError("invalid task id")
    return TaskIs(value)


def _parse_client(rest: str) -> Predicate:
    return ClientIn(_items(_expect(rest, "in"), lambda v: bool(_CLIENT_ID.fullmatch(v)), "client"))


def _parse_tool(rest: str) -> Predicate:
    return ToolIn(_items(_expect(rest, "in"), lambda v: bool(_TOOL.fullmatch(v)), "tool"))


def _parse_verb(rest: str) -> Predicate:
    names = _items(_expect(rest, "in"), lambda v: v in _VERB_NAMES, "verb")
    return VerbIn(tuple(Verb(name) for name in names))


def _parse_host(rest: str) -> Predicate:
    return HostIn(_items(_expect(rest, "in"), is_valid_host, "host"))


def _parse_resource(rest: str) -> Predicate:
    return ResourceMatches(_items(_expect(rest, "matches"), is_valid_glob, "resource glob"))


def _parse_expires(rest: str) -> Predicate:
    value = _expect(rest, "<")
    match = _TIME.fullmatch(value)
    if match is None:
        raise CaveatSyntaxError("expires needs YYYY-MM-DDTHH:MM:SSZ")
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    if not _MIN_YEAR <= year <= _MAX_YEAR:
        raise CaveatSyntaxError("expires year out of range")
    try:
        moment = datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except ValueError as exc:
        raise CaveatSyntaxError("expires is not a valid date") from exc
    return ExpiresBefore(int(moment.timestamp()))


def _parse_max_calls(rest: str) -> Predicate:
    value = _expect(rest, "<=")
    if not _LIMIT.fullmatch(value):
        raise CaveatSyntaxError("max_calls needs an integer from 1 to 999999999")
    return MaxCalls(int(value))


def _parse_once(rest: str) -> Predicate:
    value = _expect(rest, "=")
    if not _HEX32.fullmatch(value):
        raise CaveatSyntaxError("once needs 32 lowercase hex characters")
    return Once(value)


def _parse_request_hash(rest: str) -> Predicate:
    value = _expect(rest, "=")
    if not _HEX64.fullmatch(value):
        raise CaveatSyntaxError("request_hash needs 64 lowercase hex characters")
    return RequestHashIs(value)


def _is_scalar(value: JsonValue) -> bool:
    return value is None or isinstance(value, (str, bool, int, float))


def _is_number(value: JsonValue) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _reject_constant(name: str) -> JsonValue:
    raise CaveatSyntaxError(f"non-finite number {name}")


def _parse_literal(text: str) -> JsonValue:
    try:
        value: JsonValue = json.loads(text, parse_constant=_reject_constant)
        canonical = canonical_json(value)
    except (json.JSONDecodeError, CanonicalJSONError) as exc:
        raise CaveatSyntaxError("argument literal is not JSON") from exc
    if canonical != text:
        raise CaveatSyntaxError("argument literal is not canonical JSON")
    return value


def _check_literal(op: str, value: JsonValue) -> None:
    if op in {"=", "!="}:
        ok = _is_scalar(value)
    elif op in {"<", "<=", ">", ">="}:
        ok = _is_number(value)
    elif op == "in":
        ok = (
            isinstance(value, list)
            and 0 < len(value) <= MAX_LIST_ITEMS
            and all(_is_scalar(item) for item in value)
        )
    else:
        ok = isinstance(value, str) and 0 < len(value) <= _MAX_MATCH_PATTERN
    if not ok:
        raise CaveatSyntaxError(f"literal type does not fit operator '{op}'")


def _parse_arg(rest: str) -> Predicate:
    parts = rest.split(" ", 2)
    if len(parts) != 3:
        raise CaveatSyntaxError("arg needs a path, an operator and a JSON literal")
    path_text, op, literal = parts
    path = tuple(path_text.split("."))
    if len(path) > _MAX_ARG_PATH or not all(_ARG_NAME.fullmatch(name) for name in path):
        raise CaveatSyntaxError("invalid argument path")
    if op not in _ARG_OPS:
        raise CaveatSyntaxError("unknown argument operator")
    value = _parse_literal(literal)
    _check_literal(op, value)
    arg_op: ArgOp = op  # type: ignore[assignment]  # membership checked against _ARG_OPS
    return ArgPredicate(path=path, op=arg_op, value=value)


_PARSERS: dict[str, Callable[[str], Predicate]] = {
    "task_id": _parse_task,
    "client": _parse_client,
    "tool": _parse_tool,
    "verb": _parse_verb,
    "host": _parse_host,
    "resource": _parse_resource,
    "expires": _parse_expires,
    "max_calls": _parse_max_calls,
    "once": _parse_once,
    "request_hash": _parse_request_hash,
    "arg": _parse_arg,
}


def parse_caveat(condition: str) -> Predicate:
    """Parse one canonical condition; raise CaveatSyntaxError for anything else.

    Results are memoized (conditions repeat across calls with the same token family); errors are
    not cached and are raised again on every call. Predicates are immutable, so sharing is safe.
    """
    return _parse_cached(condition)


@functools.lru_cache(maxsize=8192)
def _parse_cached(condition: str) -> Predicate:
    try:
        size = len(condition.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise CaveatSyntaxError("condition is not valid UTF-8 text") from exc
    if size > MAX_CONDITION_BYTES:
        raise CaveatSyntaxError("condition too long")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in condition):
        raise CaveatSyntaxError("control characters are not allowed")
    head, separator, rest = condition.partition(" ")
    parser = _PARSERS.get(head)
    if not separator or parser is None:
        raise CaveatSyntaxError("unknown caveat type")
    predicate = parser(rest)
    if format_caveat(predicate) != condition:
        raise CaveatSyntaxError("condition is not in canonical form")
    return predicate


# --- evaluation ---------------------------------------------------------------------------------


def is_stateful(predicate: Predicate) -> bool:
    return isinstance(predicate, (MaxCalls, Once))


def _lookup(args: dict[str, JsonValue], path: tuple[str, ...]) -> tuple[bool, JsonValue]:
    current: JsonValue = args
    for name in path:
        if not isinstance(current, dict) or name not in current:
            return False, None
        current = current[name]
    return True, current


def _scalar_equal(left: JsonValue, right: JsonValue) -> bool:
    if _is_number(left) and _is_number(right):
        return left == right
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right
    return type(left) is type(right) and left == right and _is_scalar(left)


def _evaluate_arg(predicate: ArgPredicate, args: dict[str, JsonValue]) -> bool:  # noqa: PLR0911
    present, actual = _lookup(args, predicate.path)
    if not present or not _is_scalar(actual):
        return False
    expected = predicate.value
    if predicate.op == "=":
        return _scalar_equal(actual, expected)
    if predicate.op == "!=":
        return not _scalar_equal(actual, expected)
    if predicate.op == "in":
        return isinstance(expected, list) and any(_scalar_equal(actual, e) for e in expected)
    if predicate.op == "matches":
        return (
            isinstance(actual, str)
            and isinstance(expected, str)
            and text_glob_match(expected, actual)
        )
    if (
        isinstance(actual, bool)
        or isinstance(expected, bool)
        or not isinstance(actual, (int, float))
        or not isinstance(expected, (int, float))
    ):
        return False
    if predicate.op == "<":
        return actual < expected
    if predicate.op == "<=":
        return actual <= expected
    if predicate.op == ">":
        return actual > expected
    return actual >= expected


def evaluate(predicate: Predicate, ctx: RequestContext) -> bool:  # noqa: PLR0911
    """Whether ``predicate`` holds for ``ctx``. Stateful predicates are always true here."""
    request = ctx.request
    if isinstance(predicate, TaskIs):
        return request.task_id == predicate.task_id
    if isinstance(predicate, ClientIn):
        return ctx.client_id is not None and ctx.client_id in predicate.clients
    if isinstance(predicate, ToolIn):
        return request.tool in predicate.tools
    if isinstance(predicate, VerbIn):
        return request.verb in predicate.verbs
    if isinstance(predicate, HostIn):
        return request.host in predicate.hosts
    if isinstance(predicate, ResourceMatches):
        return any(glob_match(pattern, request.resource) for pattern in predicate.globs)
    if isinstance(predicate, ExpiresBefore):
        return ctx.now < predicate.at
    if isinstance(predicate, RequestHashIs):
        return request.request_hash() == predicate.digest
    if isinstance(predicate, ArgPredicate):
        return _evaluate_arg(predicate, request.args)
    return True  # MaxCalls, Once: committed by the broker's state store
