"""Helpers shared by the test modules (``import support``)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import JsonValue

from capability_tool_broker.approver.service import ApprovalSubmission
from capability_tool_broker.authority.service import MintedToken, TokenRequest
from capability_tool_broker.broker.broker import BrokerOutcome, ToolCall
from capability_tool_broker.capabilities.keys import RootKeyRing
from capability_tool_broker.macaroons.macaroon import Macaroon
from capability_tool_broker.stack import ManualClock, Stack, build_stack

T0 = 1_800_000_000
CLIENT = "agent-host"
REVIEWER = "human:reviewer"
_PARAMS: dict[str, dict[str, str]] = {
    "invoice-review": {"invoice_id": "42"},
    "invoice-cleanup": {"invoice_id": "42"},
    "file-maintenance": {"name": "notes.txt"},
    "customer-notice": {"invoice_id": "42", "domain": "example.com"},
}


def make_stack(tmp_path: Path, **kwargs: Any) -> Stack:
    kwargs.setdefault("clock", ManualClock(T0))
    return build_stack(tmp_path, **kwargs)


def advance(stack: Stack, seconds: float) -> None:
    assert isinstance(stack.clock, ManualClock)
    stack.clock.advance(seconds)


def mint(
    stack: Stack,
    template: str = "invoice-review",
    *,
    task_id: str = "task-1",
    params: dict[str, str] | None = None,
    client: str = CLIENT,
    ttl_seconds: int | None = None,
) -> MintedToken:
    request = TokenRequest(
        template=template,
        task_id=task_id,
        params=_PARAMS.get(template, {}) if params is None else params,
        ttl_seconds=ttl_seconds,
    )
    return stack.authority.mint(client, request)


def call(
    stack: Stack,
    token: str,
    tool: str,
    resource: str,
    args: dict[str, JsonValue] | None = None,
    *,
    discharges: Sequence[str] = (),
    task_id: str = "task-1",
    client: str | None = CLIENT,
) -> BrokerOutcome:
    return stack.broker.call(
        token=token,
        discharges=discharges,
        call=ToolCall(task_id=task_id, tool=tool, resource=resource, args=args or {}),
        client_id=client,
    )


def approve(
    stack: Stack,
    outcome: BrokerOutcome,
    *,
    requested_by: str = CLIENT,
    approver: str = REVIEWER,
) -> str:
    assert outcome.approval is not None
    assert outcome.canonical_request is not None
    record = stack.approver.submit(
        ApprovalSubmission(caveat_id=outcome.approval.caveat_id, request=outcome.canonical_request),
        requested_by=requested_by,
    )
    decided = stack.approver.decide(record.id, approver=approver, approve=True)
    assert decided.discharge is not None
    return decided.discharge


def bind(token: str, discharge: str) -> str:
    return Macaroon.deserialize(token).bind(Macaroon.deserialize(discharge)).serialize()


def raw_token(ring: RootKeyRing, conditions: Sequence[str]) -> Macaroon:
    identifier = ring.new_identifier()
    resolved = ring.token_key(identifier)
    assert resolved is not None
    token = Macaroon.create(root_key=resolved[1], identifier=identifier)
    for condition in conditions:
        token = token.add_first_party_caveat(condition)
    return token
