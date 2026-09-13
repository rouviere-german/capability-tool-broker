"""Offline attenuation: holders narrow a token by appending caveats, no server involved.

Attenuation is monotone by construction. Caveats are conjunctive and cannot be removed without
breaking the HMAC chain, so a child token authorizes a subset of what its parent authorizes; a
child that "asks" for a wider glob or an extra tool still carries the parent's caveats. The
property tests check this against an exhaustive oracle.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from capability_tool_broker.capabilities.caveats import (
    ExpiresBefore,
    MaxCalls,
    Predicate,
    ResourceMatches,
    ToolIn,
    VerbIn,
    format_caveat,
)
from capability_tool_broker.capabilities.request import Verb
from capability_tool_broker.capabilities.thirdparty import ApprovalCaveatId
from capability_tool_broker.macaroons.macaroon import Macaroon

__all__ = ["attenuate", "delegation_caveats", "describe_caveats"]


def attenuate(token: Macaroon, predicates: Iterable[Predicate]) -> Macaroon:
    for predicate in predicates:
        token = token.add_first_party_caveat(format_caveat(predicate))
    return token


def delegation_caveats(
    *,
    now: int,
    tools: Sequence[str] | None = None,
    resources: Sequence[str] | None = None,
    verbs: Sequence[Verb] | None = None,
    ttl_seconds: int | None = None,
    max_calls: int | None = None,
) -> list[Predicate]:
    """Caveats for handing a narrower token to a sub-agent."""
    caveats: list[Predicate] = []
    if tools:
        caveats.append(ToolIn(tuple(dict.fromkeys(tools))))
    if resources:
        caveats.append(ResourceMatches(tuple(dict.fromkeys(resources))))
    if verbs:
        caveats.append(VerbIn(tuple(dict.fromkeys(verbs))))
    if ttl_seconds is not None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        caveats.append(ExpiresBefore(now + ttl_seconds))
    if max_calls is not None:
        caveats.append(MaxCalls(max_calls))
    return caveats


def describe_caveats(token: Macaroon) -> list[str]:
    """Human-readable caveat list (third-party caveats summarized, sealed boxes omitted)."""
    lines: list[str] = []
    for caveat in token.caveats:
        if caveat.verification_id is None:
            lines.append(caveat.caveat_id.decode("utf-8", errors="backslashreplace"))
            continue
        parsed = ApprovalCaveatId.decode(caveat.caveat_id)
        if parsed is None:
            lines.append("third-party caveat (opaque)")
        else:
            lines.append(f"third-party approval by {parsed.location} when {parsed.scope}")
    return lines
