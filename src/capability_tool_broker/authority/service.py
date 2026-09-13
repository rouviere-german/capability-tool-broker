"""Minting: one root macaroon per task, built from a policy template.

Every root token carries ``task_id``, ``client`` (the authenticated caller), ``tool``, ``verb``,
``resource`` and ``expires`` caveats, plus ``host``, ``max_calls`` and argument caveats when the
template sets them. Templates that grant ``write`` or ``delete`` also get an authority-tagged
approval caveat whose caveat key is sealed to the approver.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from capability_tool_broker.agentic.audit import AuditLog
from capability_tool_broker.authority.policy import BudgetSpec, Policy, PolicyError, substitute
from capability_tool_broker.capabilities.attenuate import attenuate, describe_caveats
from capability_tool_broker.capabilities.caveats import (
    ClientIn,
    ExpiresBefore,
    HostIn,
    MaxCalls,
    Predicate,
    ResourceMatches,
    TaskIs,
    ToolIn,
    VerbIn,
    parse_caveat,
)
from capability_tool_broker.capabilities.keys import RootKeyRing, parse_identifier
from capability_tool_broker.capabilities.request import SIDE_EFFECT_VERBS, TASK_ID_PATTERN
from capability_tool_broker.capabilities.thirdparty import (
    DEFAULT_APPROVAL_SCOPE,
    add_approval_caveat,
)
from capability_tool_broker.macaroons.macaroon import Macaroon

__all__ = ["Authority", "AuthorityError", "MintedToken", "TokenRequest"]


class AuthorityError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class TokenRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    template: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    task_id: str = Field(pattern=TASK_ID_PATTERN)
    params: dict[str, str] = Field(default_factory=dict, max_length=16)
    ttl_seconds: int | None = Field(default=None, ge=1, le=86_400)


class MintedToken(BaseModel):
    model_config = ConfigDict(frozen=True)

    token: str
    token_id: str
    task_id: str
    template: str
    expires_at: int
    caveats: list[str]
    budget: BudgetSpec


class Authority:
    def __init__(
        self,
        *,
        ring: RootKeyRing,
        policy: Policy,
        approver_public_key: X25519PublicKey,
        audit: AuditLog | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._ring = ring
        self._policy = policy
        self._approver = approver_public_key
        self._audit = audit
        self._clock = clock

    def mint(self, client_id: str, request: TokenRequest) -> MintedToken:
        client = self._policy.clients.get(client_id)
        if client is None or request.template not in client.templates:
            raise AuthorityError("forbidden", "client may not request this template")
        spec = self._policy.templates[request.template]
        try:
            params = spec.bind_params(request.params)
        except PolicyError as exc:
            raise AuthorityError("invalid_params", str(exc)) from exc

        now = int(self._clock())
        ttl = min(request.ttl_seconds or spec.ttl_seconds, spec.ttl_seconds)
        expires_at = now + min(ttl, self._policy.max_ttl_seconds)
        caveats: list[Predicate] = [
            TaskIs(request.task_id),
            ClientIn((client_id,)),
            ToolIn(spec.tools),
            VerbIn(spec.verbs),
            ResourceMatches(tuple(dict.fromkeys(substitute(r, params) for r in spec.resources))),
            ExpiresBefore(expires_at),
        ]
        if spec.hosts:
            caveats.append(HostIn(spec.hosts))
        if spec.max_calls is not None:
            caveats.append(MaxCalls(spec.max_calls))
        caveats.extend(parse_caveat(condition) for condition in spec.arg_caveats)

        identifier = self._ring.new_identifier()
        resolved = self._ring.token_key(identifier)
        if resolved is None:  # pragma: no cover - identifiers come from this ring
            raise AuthorityError("internal", "key ring cannot resolve its own identifier")
        token = attenuate(Macaroon.create(root_key=resolved[1], identifier=identifier), caveats)
        if set(spec.verbs) & SIDE_EFFECT_VERBS:
            token = add_approval_caveat(
                token,
                ring=self._ring,
                approver_public_key=self._approver,
                location=self._policy.approver_location,
                task_id=request.task_id,
                client_id=client_id,
                expires_at=expires_at,
                scope=spec.approval_scope or DEFAULT_APPROVAL_SCOPE,
            )
        parsed = parse_identifier(identifier)
        token_id = parsed[1] if parsed else ""
        described = describe_caveats(token)
        if self._audit is not None:
            self._audit.append(
                client_id,
                "authority.mint",
                {
                    "template": request.template,
                    "task_id": request.task_id,
                    "token_id": token_id,
                    "kid": self._ring.active_kid,
                    "expires_at": expires_at,
                    "caveats": list(described),
                },
            )
        return MintedToken(
            token=token.serialize(),
            token_id=token_id,
            task_id=request.task_id,
            template=request.template,
            expires_at=expires_at,
            caveats=described,
            budget=spec.budget,
        )
