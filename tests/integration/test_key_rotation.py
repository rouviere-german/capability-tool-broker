"""The key rotation runbook (docs/RUNBOOK_KEY_ROTATION.md), step by step."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from capability_tool_broker.authority.service import Authority, TokenRequest
from capability_tool_broker.broker.broker import Broker
from capability_tool_broker.broker.manifest import ManifestHolder
from capability_tool_broker.capabilities.keys import RootKeyRing, parse_identifier
from capability_tool_broker.macaroons.macaroon import Macaroon
from capability_tool_broker.stack import Stack
from support import CLIENT, advance, approve, bind, call, make_stack

pytestmark = pytest.mark.integration


def _broker(stack: Stack, ring: RootKeyRing) -> Broker:
    return Broker(
        ring=ring,
        manifest=ManifestHolder.from_manifest(stack.manifest),
        state=stack.state,
        credentials=stack.keys.credentials(),
        http=stack.http,
        clock=stack.clock,
    )


def _authority(stack: Stack, ring: RootKeyRing) -> Authority:
    return Authority(
        ring=ring,
        policy=stack.policy,
        approver_public_key=stack.keys.approver_private.public_key(),
        clock=stack.clock,
    )


def _kid(token: str) -> str:
    parsed = parse_identifier(Macaroon.deserialize(token).identifier)
    assert parsed is not None
    return parsed[0]


def test_dual_key_rotation_window(tmp_path: Path) -> None:
    stack = make_stack(tmp_path)
    try:
        request = TokenRequest(
            template="invoice-review", task_id="task-1", params={"invoice_id": "42"}
        )
        old_ring = stack.keys.ring
        old_token = stack.authority.mint(CLIENT, request).token
        assert _kid(old_token) == "k1"

        # Step 1: add k2 to every verifier (and the authority) without activating it.
        window = old_ring.with_key("k2", secrets.token_bytes(32))
        broker_window = _broker(stack, window)
        stack.broker = broker_window
        assert call(stack, old_token, "invoices_read", "invoice/42").allowed

        # Step 2: activate k2 on the authority; new tokens carry kid k2.
        authority_k2 = _authority(stack, window.activate("k2"))
        new_token = authority_k2.mint(CLIENT, request).token
        assert _kid(new_token) == "k2"
        assert call(stack, new_token, "invoices_read", "invoice/42").allowed
        stack.broker = _broker(stack, old_ring)  # a broker that skipped step 1 cannot verify k2
        assert call(stack, new_token, "invoices_read", "invoice/42").reason == "unknown_key"
        stack.broker = broker_window

        # Approval caveats minted under k2 are tagged with k2 and verify during the window.
        denied = call(stack, new_token, "invoices_update_status", "invoice/42", {"status": "paid"})
        discharge = approve(stack, denied)
        stack.authority = authority_k2
        executed = call(
            stack,
            new_token,
            "invoices_update_status",
            "invoice/42",
            {"status": "paid"},
            discharges=[bind(new_token, discharge)],
        )
        assert executed.allowed

        # Step 3: after the longest token lifetime (policy max_ttl_seconds), remove k1.
        advance(stack, stack.policy.max_ttl_seconds + 1)
        retired = window.activate("k2").without_key("k1")
        stack.broker = _broker(stack, retired)
        assert call(stack, old_token, "invoices_read", "invoice/42").reason == "unknown_key"
        fresh = _authority(stack, retired).mint(CLIENT, request).token
        assert call(stack, fresh, "invoices_read", "invoice/42").allowed
        assert RootKeyRing.parse(retired.to_spec()).kids == ("k2",)
    finally:
        stack.close()
