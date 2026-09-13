"""The verification algorithm: chains, discharges, scopes, caveat order and stateful claims."""

from __future__ import annotations

import secrets
from dataclasses import replace

import pytest

from capability_tool_broker.capabilities.caveats import MaxCalls, TaskIs
from capability_tool_broker.capabilities.keys import RootKeyRing
from capability_tool_broker.capabilities.request import CanonicalRequest, RequestContext, Verb
from capability_tool_broker.capabilities.sealed import generate_private_key
from capability_tool_broker.capabilities.thirdparty import add_approval_caveat
from capability_tool_broker.capabilities.verifier import (
    Authorization,
    Denial,
    DenyReason,
    MacaroonVerifier,
)
from capability_tool_broker.macaroons.crypto import chain_third_party
from capability_tool_broker.macaroons.macaroon import Caveat, Macaroon
from support import raw_token

pytestmark = pytest.mark.unit

RING = RootKeyRing.generate()
VERIFIER = MacaroonVerifier(root_key=RING.token_key)
NOW = 1_800_000_000


def request(**overrides: object) -> CanonicalRequest:
    values: dict[str, object] = {
        "task_id": "task-1",
        "tool": "invoices_read",
        "verb": Verb.READ,
        "host": "invoices.internal",
        "resource": "invoice/42",
    }
    values.update(overrides)
    return CanonicalRequest.model_validate(values)


def ctx(req: CanonicalRequest | None = None, now: int = NOW) -> RequestContext:
    return RequestContext(request=req or request(), now=now, client_id="agent-host")


WRITE = request(tool="invoices_update_status", verb=Verb.WRITE)


def base(*extra: str) -> Macaroon:
    return raw_token(
        RING,
        [
            "task_id = task-1",
            "tool in invoices_read,invoices_update_status",
            "resource matches invoice/42",
            *extra,
        ],
    )


def denied(result: Authorization | Denial, reason: DenyReason) -> Denial:
    assert isinstance(result, Denial), result
    assert result.reason is reason, result
    return result


def test_valid_tokens_authorize_and_report_claims_and_expiry() -> None:
    token = base(
        "max_calls <= 3", "expires < 2030-01-01T00:00:00Z", "expires < 2029-01-01T00:00:00Z"
    )
    result = VERIFIER.verify(token, (), ctx())
    assert isinstance(result, Authorization)
    assert [claim.kind for claim in result.claims] == ["max_calls"]
    assert result.expires_at == 1_861_920_000
    assert {"task_id", "tool", "resource", "max_calls", "expires"} <= result.caveat_types
    assert result.kid == RING.active_kid


def test_unknown_keys_and_bad_signatures_are_denied() -> None:
    foreign = raw_token(RootKeyRing.generate(RING.active_kid), ["task_id = task-1"])
    denied(VERIFIER.verify(foreign, (), ctx()), DenyReason.BAD_SIGNATURE)
    unknown_kid = Macaroon.create(root_key=b"k" * 32, identifier=b"ctb1:zz:" + b"0" * 32)
    denied(VERIFIER.verify(unknown_kid, (), ctx()), DenyReason.UNKNOWN_KEY)
    not_ours = Macaroon.create(root_key=b"k", identifier=b"something else")
    denied(VERIFIER.verify(not_ours, (), ctx()), DenyReason.UNKNOWN_KEY)
    token = base()
    tampered = replace(token, signature=bytes(32))
    denied(VERIFIER.verify(tampered, (), ctx()), DenyReason.BAD_SIGNATURE)


def test_the_first_failing_caveat_is_reported() -> None:
    result = denied(VERIFIER.verify(base("verb in read"), (), ctx(WRITE)), DenyReason.CAVEAT_UNMET)
    assert result.failed_caveat is not None
    assert result.failed_caveat.condition == "verb in read"
    assert result.failed_caveat.caveat_type == "verb"
    assert result.failed_caveat.source == "token"
    assert result.failed_caveat.index == 3
    assert result.caveat_type == "verb"
    expired = VERIFIER.verify(base("expires < 2020-01-01T00:00:00Z"), (), ctx())
    assert denied(expired, DenyReason.CAVEAT_UNMET).caveat_type == "expires"


@pytest.mark.parametrize(
    "condition", [b"\xff\xfe", b"unknown = 1", b"tool in ", b"task_id =  task-1"]
)
def test_malformed_conditions_fail_closed(condition: bytes) -> None:
    token = base().add_first_party_caveat(condition)
    result = denied(VERIFIER.verify(token, (), ctx()), DenyReason.CAVEAT_SYNTAX)
    assert result.failed_caveat is not None
    assert result.failed_caveat.caveat_type == "unknown"


def _discharge(key: bytes, caveat_id: bytes, *conditions: str) -> Macaroon:
    discharge = Macaroon.create(root_key=key, identifier=caveat_id)
    for condition in conditions:
        discharge = discharge.add_first_party_caveat(condition)
    return discharge


def test_third_party_caveats_need_a_valid_discharge_bound_to_the_token() -> None:
    key, caveat_id = secrets.token_bytes(32), b"generic-third-party-caveat"
    token = base().add_third_party_caveat(caveat_key=key, caveat_id=caveat_id)
    result = denied(VERIFIER.verify(token, (), ctx()), DenyReason.UNDISCHARGED)
    assert result.undischarged is not None
    assert result.caveat_type == "third_party"
    discharge = _discharge(key, caveat_id, "task_id = task-1")
    ok = VERIFIER.verify(token, (token.bind(discharge),), ctx())
    assert isinstance(ok, Authorization)
    assert ok.discharges[0].caveat_id == caveat_id
    assert ok.discharges[0].predicates == (TaskIs("task-1"),)

    other = base("verb in read")
    denied(VERIFIER.verify(token, (discharge,), ctx()), DenyReason.DISCHARGE_INVALID)
    denied(VERIFIER.verify(token, (other.bind(discharge),), ctx()), DenyReason.DISCHARGE_INVALID)
    wrong_key = _discharge(secrets.token_bytes(32), caveat_id)
    denied(VERIFIER.verify(token, (token.bind(wrong_key),), ctx()), DenyReason.DISCHARGE_INVALID)
    failing = token.bind(_discharge(key, caveat_id, "task_id = task-2"))
    unmet = denied(VERIFIER.verify(token, (failing,), ctx()), DenyReason.CAVEAT_UNMET)
    assert unmet.failed_caveat is not None
    assert unmet.failed_caveat.source == "discharge:1"
    bound = token.bind(discharge)
    denied(VERIFIER.verify(token, (bound, bound), ctx()), DenyReason.DUPLICATE_DISCHARGE)
    stray = token.bind(_discharge(key, b"unrelated"))
    denied(VERIFIER.verify(token, (bound, stray), ctx()), DenyReason.UNUSED_DISCHARGE)
    many = tuple(token.bind(_discharge(key, f"x{i}".encode())) for i in range(9))
    denied(VERIFIER.verify(token, many, ctx()), DenyReason.MALFORMED)


def test_a_caveat_key_that_cannot_be_recovered_cannot_be_discharged() -> None:
    token = base()
    caveat_id, garbage = b"cid", b"not a real verification id"
    broken = replace(
        token,
        caveats=(*token.caveats, Caveat(caveat_id, garbage)),
        signature=chain_third_party(token.signature, garbage, caveat_id),
    )
    denied(VERIFIER.verify(broken, (), ctx()), DenyReason.UNDISCHARGED)
    discharge = broken.bind(_discharge(b"any", caveat_id))
    denied(VERIFIER.verify(broken, (discharge,), ctx()), DenyReason.DISCHARGE_INVALID)


def test_nested_discharges_are_followed_up_to_the_depth_limit() -> None:
    key1, key2 = secrets.token_bytes(32), secrets.token_bytes(32)
    token = base().add_third_party_caveat(caveat_key=key1, caveat_id=b"outer")
    outer = _discharge(key1, b"outer").add_third_party_caveat(caveat_key=key2, caveat_id=b"inner")
    inner = _discharge(key2, b"inner", "resource matches invoice/*")
    bound = (token.bind(outer), token.bind(inner))
    result = VERIFIER.verify(token, bound, ctx())
    assert isinstance(result, Authorization)
    assert len(result.discharges) == 2
    shallow = MacaroonVerifier(root_key=RING.token_key, max_depth=1)
    denied(shallow.verify(token, bound, ctx()), DenyReason.DISCHARGE_DEPTH)
    twice = token.add_third_party_caveat(caveat_key=key1, caveat_id=b"outer")
    denied(
        VERIFIER.verify(twice, (twice.bind(_discharge(key1, b"outer")),), ctx()),
        DenyReason.DISCHARGE_INVALID,
    )


def test_location_fields_are_refused_unless_allowed() -> None:
    token = replace(base(), location="https://unauthenticated.example")
    denied(VERIFIER.verify(token, (), ctx()), DenyReason.LOCATION_NOT_ALLOWED)
    token = raw_token(RING, ["task_id = task-1"])
    relocated = replace(token, location="https://unauthenticated.example")
    permissive = MacaroonVerifier(root_key=RING.token_key, allow_locations=True)
    assert isinstance(permissive.verify(relocated, (), ctx()), Authorization)


def test_approval_caveats_apply_only_to_requests_in_scope() -> None:
    approver = generate_private_key().public_key()
    token = add_approval_caveat(
        base(),
        ring=RING,
        approver_public_key=approver,
        location="https://approver.internal/v1",
        task_id="task-1",
        client_id="agent-host",
        expires_at=NOW + 600,
    )
    assert isinstance(VERIFIER.verify(token, (), ctx()), Authorization)
    denied(VERIFIER.verify(token, (), ctx(WRITE)), DenyReason.UNDISCHARGED)
    narrowed = token.add_first_party_caveat("resource matches invoice/43")
    denied(VERIFIER.verify(narrowed, (), ctx(WRITE)), DenyReason.CAVEAT_UNMET)


def test_custom_scope_hooks() -> None:
    key, caveat_id = secrets.token_bytes(32), b"scoped"
    token = base().add_third_party_caveat(caveat_key=key, caveat_id=caveat_id)
    never = MacaroonVerifier(root_key=RING.token_key, scope_of=lambda cid: TaskIs("other"))
    assert isinstance(never.verify(token, (), ctx()), Authorization)
    stateful = MacaroonVerifier(root_key=RING.token_key, scope_of=lambda cid: MaxCalls(1))
    denied(stateful.verify(token, (), ctx()), DenyReason.UNDISCHARGED)


def test_stateful_claims_are_shared_by_every_copy_of_a_token_prefix() -> None:
    parent = base("max_calls <= 3")
    siblings = [
        parent,
        parent.add_first_party_caveat("verb in read"),
        parent.add_first_party_caveat("tool in invoices_read"),
    ]
    keys = []
    for token in siblings:
        result = VERIFIER.verify(token, (), ctx())
        assert isinstance(result, Authorization)
        keys.append(result.claims[0].key)
    assert len(set(keys)) == 1
    own = VERIFIER.verify(parent.add_first_party_caveat("max_calls <= 1"), (), ctx())
    assert isinstance(own, Authorization)
    assert own.claims[0].key == keys[0]
    assert own.claims[1].key != keys[0]
    once = VERIFIER.verify(base("once = " + "ab" * 16), (), ctx())
    assert isinstance(once, Authorization)
    assert once.claims[0].kind == "once"
    assert once.claims[0].limit == 1


def test_claim_expiry_comes_from_the_prefix_every_holder_shares() -> None:
    # A holder appends a short expiry after the parent's max_calls caveat. The counter is shared
    # with the parent, so its lifetime must come from the caveats before it, not from the child.
    parent = base("expires < 2030-01-01T00:00:00Z", "max_calls <= 3")
    child = parent.add_first_party_caveat("expires < 2028-01-01T00:00:00Z")
    grandchild = child.add_first_party_caveat("max_calls <= 1")
    claims = []
    for token in (parent, child, grandchild):
        result = VERIFIER.verify(token, (), ctx())
        assert isinstance(result, Authorization)
        claims.append(result.claims)
    assert claims[0][0].key == claims[1][0].key == claims[2][0].key
    assert {c[0].expires_at for c in claims} == {1_893_456_000}  # 2030-01-01
    assert claims[2][1].expires_at == 1_830_297_600  # 2028-01-01, the grandchild's own counter
    assert isinstance(result, Authorization)
    assert result.expires_at == 1_830_297_600
    no_prefix_expiry = VERIFIER.verify(
        base("max_calls <= 3", "expires < 2030-01-01T00:00:00Z"), (), ctx()
    )
    assert isinstance(no_prefix_expiry, Authorization)
    assert no_prefix_expiry.claims[0].expires_at is None


def test_discharge_nonce_expiry_ignores_expiries_a_holder_appends() -> None:
    key, caveat_id = secrets.token_bytes(32), b"approval-like"
    token = base().add_third_party_caveat(caveat_key=key, caveat_id=caveat_id)
    discharge = _discharge(key, caveat_id, "expires < 2030-01-01T00:00:00Z", "once = " + "cd" * 16)
    shortened = discharge.add_first_party_caveat("expires < 2028-01-01T00:00:00Z")
    results = [VERIFIER.verify(token, (token.bind(d),), ctx()) for d in (discharge, shortened)]
    assert all(isinstance(r, Authorization) for r in results)
    claims = [r.claims[0] for r in results if isinstance(r, Authorization)]
    assert claims[0].key == claims[1].key
    assert claims[0].expires_at == claims[1].expires_at == 1_893_456_000
