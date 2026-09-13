"""Macaroon verification: authenticate the chain and its discharges, then evaluate every caveat.

Phase 1 (authenticity, no caveat is interpreted yet):

1. Resolve the per-token root key from the identifier's key id (unknown kid: deny).
2. Recompute the HMAC chain and compare it with the token signature in constant time.
3. For each third-party caveat with a matching discharge, decrypt the caveat key from the vid under
   the running signature, recompute the discharge chain, bind it to the root signature and compare
   in constant time. Nested discharges are followed up to ``max_depth``. Every discharge must be
   used exactly once; duplicates and unused discharges are denied.

Phase 2 (authorization), in chain order, root first:

4. Parse every first-party condition (syntax error: deny, fail closed) and evaluate it against the
   request context. The first unmet caveat is reported.
5. A third-party caveat without a discharge is denied unless its authenticated scope does not
   match the request.
6. Stateful caveats (``max_calls``, ``once``) become claims keyed by a hash of the chain signature
   right after the caveat, so every copy of the same token prefix shares one counter: delegating
   a token to several sub-agents cannot multiply its call budget.

The result is an :class:`Authorization` (claims still to be committed) or a :class:`Denial`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from capability_tool_broker.capabilities.caveats import (
    CaveatSyntaxError,
    ExpiresBefore,
    MaxCalls,
    Once,
    Predicate,
    evaluate,
    format_caveat,
    is_stateful,
    parse_caveat,
)
from capability_tool_broker.capabilities.request import RequestContext
from capability_tool_broker.capabilities.thirdparty import approval_scope
from capability_tool_broker.macaroons.crypto import (
    bind_signature,
    chain_first_party,
    chain_third_party,
    constant_time_equal,
    decrypt_caveat_key,
    derive_key,
    initial_signature,
)
from capability_tool_broker.macaroons.macaroon import Caveat, Macaroon

__all__ = [
    "Authorization",
    "Denial",
    "DenyReason",
    "FailedCaveat",
    "MacaroonVerifier",
    "StateClaim",
    "VerifiedDischarge",
]


class DenyReason(StrEnum):
    # token format and authenticity
    MALFORMED = "malformed"
    UNKNOWN_KEY = "unknown_key"
    BAD_SIGNATURE = "bad_signature"
    LOCATION_NOT_ALLOWED = "location_not_allowed"
    DUPLICATE_DISCHARGE = "duplicate_discharge"
    UNUSED_DISCHARGE = "unused_discharge"
    DISCHARGE_INVALID = "discharge_invalid"
    DISCHARGE_DEPTH = "discharge_depth"
    # caveats
    CAVEAT_SYNTAX = "caveat_syntax"
    CAVEAT_UNMET = "caveat_unmet"
    UNDISCHARGED = "undischarged"
    # broker policy and state
    UNAUTHENTICATED = "unauthenticated"
    INVALID_REQUEST = "invalid_request"
    UNKNOWN_TOOL = "unknown_tool"
    MANIFEST_UNAVAILABLE = "manifest_unavailable"
    REQUIRED_CAVEAT_MISSING = "required_caveat_missing"
    APPROVAL_REQUIRED = "approval_required"
    REVOKED = "revoked"
    EXHAUSTED = "exhausted"
    REPLAYED = "replayed"
    STATE_UNAVAILABLE = "state_unavailable"
    UPSTREAM_ERROR = "upstream_error"


@dataclass(frozen=True, slots=True)
class FailedCaveat:
    condition: str
    caveat_type: str
    source: str
    index: int


@dataclass(frozen=True, slots=True)
class Denial:
    reason: DenyReason
    detail: str
    failed_caveat: FailedCaveat | None = None
    undischarged: Caveat | None = None

    @property
    def caveat_type(self) -> str:
        if self.failed_caveat is not None:
            return self.failed_caveat.caveat_type
        return "third_party" if self.undischarged is not None else "none"


@dataclass(frozen=True, slots=True)
class StateClaim:
    kind: Literal["max_calls", "once"]
    key: str
    limit: int


@dataclass(frozen=True, slots=True)
class VerifiedDischarge:
    caveat_id: bytes
    signature: bytes
    derived_caveat_key: bytes
    predicates: tuple[Predicate, ...]


@dataclass(frozen=True, slots=True)
class Authorization:
    identifier: bytes
    kid: str
    predicates: tuple[Predicate, ...]
    claims: tuple[StateClaim, ...]
    discharges: tuple[VerifiedDischarge, ...]
    expires_at: int | None

    @property
    def caveat_types(self) -> frozenset[str]:
        return frozenset(predicate.kind.value for predicate in self.predicates)


@dataclass(slots=True)
class _Walk:
    macaroon: Macaroon
    source: str
    key: bytes
    steps: list[tuple[Caveat, bytes, bytes]]
    signature: bytes


def _walk(macaroon: Macaroon, derived_key: bytes, source: str) -> _Walk:
    signature = initial_signature(derived_key, macaroon.identifier)
    steps: list[tuple[Caveat, bytes, bytes]] = []
    for caveat in macaroon.caveats:
        before = signature
        if caveat.verification_id is None:
            signature = chain_first_party(signature, caveat.caveat_id)
        else:
            signature = chain_third_party(signature, caveat.verification_id, caveat.caveat_id)
        steps.append((caveat, before, signature))
    return _Walk(macaroon, source, derived_key, steps, signature)


def _claim_key(label: bytes, chain_signature: bytes) -> str:
    return hashlib.sha256(label + chain_signature).hexdigest()


def _printable(raw: bytes) -> str:
    return raw.decode("utf-8", errors="backslashreplace")[:256]


class MacaroonVerifier:
    def __init__(
        self,
        *,
        root_key: Callable[[bytes], tuple[str, bytes] | None],
        scope_of: Callable[[bytes], Predicate | None] = approval_scope,
        allow_locations: bool = False,
        max_depth: int = 3,
        max_discharges: int = 8,
    ) -> None:
        self._root_key = root_key
        self._scope_of = scope_of
        self._allow_locations = allow_locations
        self._max_depth = max_depth
        self._max_discharges = max_discharges

    def verify(
        self, token: Macaroon, discharges: Sequence[Macaroon], ctx: RequestContext
    ) -> Authorization | Denial:
        resolved = self._root_key(token.identifier)
        if resolved is None:
            return Denial(DenyReason.UNKNOWN_KEY, "token was not minted under a known root key")
        kid, key = resolved
        authenticated = self._authenticate(token, derive_key(key), discharges)
        if isinstance(authenticated, Denial):
            return authenticated
        walks, links = authenticated
        return self._authorize(token, kid, walks, links, ctx)

    # --- phase 1 --------------------------------------------------------------------------------

    def _authenticate(  # noqa: PLR0911, PLR0912 - each return is a distinct denial
        self, token: Macaroon, derived_root_key: bytes, discharges: Sequence[Macaroon]
    ) -> tuple[list[_Walk], dict[tuple[int, int], int]] | Denial:
        if len(discharges) > self._max_discharges:
            return Denial(DenyReason.MALFORMED, "too many discharge macaroons")
        if not self._allow_locations and any(
            m.location is not None or any(c.location is not None for c in m.caveats)
            for m in (token, *discharges)
        ):
            return Denial(DenyReason.LOCATION_NOT_ALLOWED, "unauthenticated location fields")
        pool: dict[bytes, Macaroon] = {}
        for discharge in discharges:
            if discharge.identifier in pool:
                return Denial(DenyReason.DUPLICATE_DISCHARGE, "two discharges share an identifier")
            pool[discharge.identifier] = discharge

        root = _walk(token, derived_root_key, "token")
        if not constant_time_equal(root.signature, token.signature):
            return Denial(DenyReason.BAD_SIGNATURE, "token signature does not verify")

        walks = [root]
        depths = [0]
        links: dict[tuple[int, int], int] = {}
        used: set[bytes] = set()
        index = 0
        while index < len(walks):
            walk, depth = walks[index], depths[index]
            for caveat_index, (caveat, before, _after) in enumerate(walk.steps):
                if caveat.verification_id is None or caveat.caveat_id not in pool:
                    continue
                if caveat.caveat_id in used:
                    return Denial(DenyReason.DISCHARGE_INVALID, "a discharge was needed twice")
                if depth + 1 > self._max_depth:
                    return Denial(DenyReason.DISCHARGE_DEPTH, "discharges nest too deeply")
                caveat_key = decrypt_caveat_key(before, caveat.verification_id)
                if caveat_key is None:
                    return Denial(DenyReason.DISCHARGE_INVALID, "caveat key cannot be recovered")
                discharge = pool[caveat.caveat_id]
                child = _walk(discharge, caveat_key, f"discharge:{len(walks)}")
                bound = bind_signature(token.signature, child.signature)
                if not constant_time_equal(bound, discharge.signature):
                    return Denial(
                        DenyReason.DISCHARGE_INVALID,
                        "discharge signature does not verify or is not bound to this token",
                    )
                used.add(caveat.caveat_id)
                links[(index, caveat_index)] = len(walks)
                walks.append(child)
                depths.append(depth + 1)
            index += 1
        if used != pool.keys():
            return Denial(DenyReason.UNUSED_DISCHARGE, "a discharge does not match any caveat")
        return walks, links

    # --- phase 2 --------------------------------------------------------------------------------

    def _authorize(  # noqa: PLR0912 - one branch per caveat kind
        self,
        token: Macaroon,
        kid: str,
        walks: list[_Walk],
        links: dict[tuple[int, int], int],
        ctx: RequestContext,
    ) -> Authorization | Denial:
        claims: list[StateClaim] = []
        expires_at: int | None = None
        root_predicates: tuple[Predicate, ...] = ()
        verified: list[VerifiedDischarge] = []
        undischarged: Caveat | None = None
        for walk_index, walk in enumerate(walks):
            predicates: list[Predicate] = []
            for caveat_index, (caveat, _before, after) in enumerate(walk.steps):
                if caveat.verification_id is not None:
                    if undischarged is not None or (walk_index, caveat_index) in links:
                        continue
                    scope = self._scope_of(caveat.caveat_id)
                    if scope is None or is_stateful(scope) or evaluate(scope, ctx):
                        # Reported only after every first-party caveat held, so nobody is asked
                        # to approve a call the token forbids anyway.
                        undischarged = caveat
                    continue
                failed = FailedCaveat(
                    _printable(caveat.caveat_id), "unknown", walk.source, caveat_index
                )
                try:
                    predicate = parse_caveat(caveat.caveat_id.decode("utf-8"))
                except (UnicodeDecodeError, CaveatSyntaxError) as exc:
                    return Denial(DenyReason.CAVEAT_SYNTAX, str(exc), failed_caveat=failed)
                predicates.append(predicate)
                if isinstance(predicate, MaxCalls):
                    claims.append(
                        StateClaim(
                            "max_calls", _claim_key(b"ctb-max-calls-v1", after), predicate.limit
                        )
                    )
                elif isinstance(predicate, Once):
                    claims.append(StateClaim("once", _claim_key(b"ctb-once-v1", after), 1))
                elif not evaluate(predicate, ctx):
                    return Denial(
                        DenyReason.CAVEAT_UNMET,
                        "caveat not satisfied",
                        failed_caveat=FailedCaveat(
                            format_caveat(predicate),
                            predicate.kind.value,
                            walk.source,
                            caveat_index,
                        ),
                    )
                if isinstance(predicate, ExpiresBefore):
                    expires_at = (
                        predicate.at if expires_at is None else min(expires_at, predicate.at)
                    )
            if walk_index == 0:
                root_predicates = tuple(predicates)
            else:
                verified.append(
                    VerifiedDischarge(
                        caveat_id=walk.macaroon.identifier,
                        signature=walk.signature,
                        derived_caveat_key=walk.key,
                        predicates=tuple(predicates),
                    )
                )
        if undischarged is not None:
            return Denial(
                DenyReason.UNDISCHARGED,
                "a third-party caveat needs a discharge for this request",
                undischarged=undischarged,
            )
        return Authorization(
            identifier=token.identifier,
            kid=kid,
            predicates=root_predicates,
            claims=tuple(claims),
            discharges=tuple(verified),
            expires_at=expires_at,
        )
