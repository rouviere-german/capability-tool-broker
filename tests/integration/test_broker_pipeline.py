"""The broker pipeline in process: decisions, approvals, state, audit, metrics and traces."""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterator, Sequence
from pathlib import Path

import httpx
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import JsonValue, ValidationError

from capability_tool_broker.agent.clients import InProcessApproverClient, InProcessBrokerClient
from capability_tool_broker.agent.host import CapabilityRuntime, RuntimeContext
from capability_tool_broker.agentic.audit import verify_file
from capability_tool_broker.agentic.budget import BudgetLedger, BudgetLimits
from capability_tool_broker.agentic.envelope import parse_envelopes
from capability_tool_broker.agentic.providers.base import LLMResponse, ToolUseBlock
from capability_tool_broker.agentic.providers.fake import FakeProvider, ScriptedPolicy
from capability_tool_broker.broker.broker import Broker, ToolCall
from capability_tool_broker.broker.manifest import ManifestHolder
from capability_tool_broker.broker.state import (
    CommitResult,
    MemoryStateStore,
    StateUnavailableError,
)
from capability_tool_broker.capabilities.attenuate import attenuate
from capability_tool_broker.capabilities.caveats import (
    Once,
    Predicate,
    RequestHashIs,
    ResourceMatches,
    TaskIs,
    ToolIn,
    VerbIn,
)
from capability_tool_broker.capabilities.request import Verb
from capability_tool_broker.capabilities.thirdparty import ApprovalCaveatId, open_approval_caveat
from capability_tool_broker.capabilities.verifier import StateClaim
from capability_tool_broker.macaroons.codec import b64u_encode
from capability_tool_broker.macaroons.macaroon import Macaroon
from capability_tool_broker.stack import Stack
from support import CLIENT, advance, approve, bind, call, make_stack, mint, raw_token

pytestmark = pytest.mark.integration

STATUS: dict[str, JsonValue] = {"status": "approved"}


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    built = make_stack(tmp_path)
    yield built
    built.close()


def test_reads_within_the_grant_execute_and_return_untrusted_data(stack: Stack) -> None:
    token = mint(stack).token
    outcome = call(stack, token, "invoices_read", "invoice/42")
    assert outcome.allowed
    assert outcome.status == 200
    assert outcome.canonical_request is not None
    assert outcome.canonical_request.verb is Verb.READ
    assert outcome.canonical_request.host == "invoices.internal"
    assert outcome.output is not None
    envelopes = parse_envelopes(outcome.output)
    assert envelopes[0].source == "tool:invoices_read"
    assert json.loads(envelopes[0].content)["id"] == "42"


def test_denials_name_the_failing_caveat_and_never_reach_a_service(stack: Stack) -> None:
    token = mint(stack).token
    cases = [
        (call(stack, token, "invoices_read", "invoice/43"), "resource matches invoice/42"),
        (
            call(stack, token, "mail_send", "mail/a@example.com", {"subject": "s", "body": "b"}),
            "tool in invoices_read,invoices_update_status",
        ),
        (call(stack, token, "invoices_read", "invoice/42", task_id="task-2"), "task_id = task-1"),
        (call(stack, token, "invoices_read", "invoice/42", client="other"), "client in agent-host"),
        (call(stack, token, "invoices_read", "invoice/42", client=None), "client in agent-host"),
    ]
    for outcome, condition in cases:
        assert not outcome.allowed
        assert outcome.reason == "caveat_unmet"
        assert outcome.failed_caveat is not None
        assert outcome.failed_caveat.condition == condition
    assert stack.router.access_log() == []


def test_the_agent_cannot_choose_verb_or_host(stack: Stack) -> None:
    with pytest.raises(ValidationError):
        ToolCall.model_validate(
            {"task_id": "t", "tool": "invoices_read", "resource": "invoice/1", "verb": "read"}
        )
    token = mint(stack).token
    denied = call(stack, token, "invoices_update_status", "invoice/42", STATUS)
    assert denied.canonical_request is not None
    assert denied.canonical_request.verb is Verb.WRITE


def test_invalid_requests_are_rejected_without_echoing_values(stack: Stack) -> None:
    token = mint(stack).token
    unknown = call(stack, token, "does_not_exist", "invoice/42")
    assert unknown.reason == "unknown_tool"
    bad_args = call(stack, token, "invoices_update_status", "invoice/42", {"status": "hacked"})
    assert bad_args.reason == "invalid_request"
    assert "status" in bad_args.detail
    assert "hacked" not in bad_args.detail
    assert call(stack, token, "invoices_read", "invoice/42/lines").reason == "invalid_request"
    assert (
        call(stack, token, "invoices_read", "invoice/42", {"extra": 1}).reason == "invalid_request"
    )
    assert call(stack, "not-a-token", "invoices_read", "invoice/42").reason == "malformed"
    assert call(stack, "A" * 25_000, "invoices_read", "invoice/42").reason == "malformed"
    many = [token] * 9
    assert call(stack, token, "invoices_read", "invoice/42", discharges=many).reason == "malformed"


def test_writes_need_an_approval_for_the_exact_request_and_run_once(stack: Stack) -> None:
    token = mint(stack).token
    denied = call(stack, token, "invoices_update_status", "invoice/42", STATUS)
    assert denied.reason == "approval_required"
    assert denied.approval is not None
    assert denied.approval.location == "https://approver.internal/v1"
    assert denied.approval.scope == "verb in write,delete"
    discharge = approve(stack, denied)
    bound = bind(token, discharge)
    executed = call(
        stack, token, "invoices_update_status", "invoice/42", STATUS, discharges=[bound]
    )
    assert executed.allowed
    assert stack.invoices.invoices["42"]["status"] == "approved"
    replay = call(stack, token, "invoices_update_status", "invoice/42", STATUS, discharges=[bound])
    assert replay.reason == "replayed"
    other = call(
        stack, token, "invoices_update_status", "invoice/42", {"status": "paid"}, discharges=[bound]
    )
    assert other.reason == "caveat_unmet"
    assert other.failed_caveat is not None
    assert other.failed_caveat.source == "discharge:1"
    unbound = call(
        stack, token, "invoices_update_status", "invoice/42", STATUS, discharges=[discharge]
    )
    assert unbound.reason == "discharge_invalid"
    assert [e.kind for e in stack.invoices.effects] == ["write"]


def _write_token_without_authority_caveat(stack: Stack) -> Macaroon:
    return raw_token(
        stack.keys.ring,
        [
            "task_id = task-1",
            "tool in invoices_update_status",
            "verb in write",
            "resource matches invoice/42",
            "expires < 2030-01-01T00:00:00Z",
        ],
    )


def test_holder_made_approval_caveats_are_not_approval_evidence(stack: Stack) -> None:
    token = _write_token_without_authority_caveat(stack)
    plain = call(stack, token.serialize(), "invoices_update_status", "invoice/42", STATUS)
    assert plain.reason == "approval_required"
    assert plain.approval is None
    assert plain.request_hash is not None
    caveat_key = secrets.token_bytes(32)
    forged_id = ApprovalCaveatId(
        location="https://approver.internal/v1",
        scope="verb in write,delete",
        kid=stack.keys.ring.active_kid,
        box=b64u_encode(secrets.token_bytes(64)),
        tag=b64u_encode(secrets.token_bytes(32)),
    ).encode()
    with_caveat = token.add_third_party_caveat(caveat_key=caveat_key, caveat_id=forged_id)
    self_discharge = attenuate(
        Macaroon.create(root_key=caveat_key, identifier=forged_id),
        [RequestHashIs(plain.request_hash), Once(secrets.token_hex(16))],
    )
    outcome = call(
        stack,
        with_caveat.serialize(),
        "invoices_update_status",
        "invoice/42",
        STATUS,
        discharges=[with_caveat.bind(self_discharge).serialize()],
    )
    assert outcome.reason == "approval_required"
    assert stack.invoices.effects == []


@pytest.mark.parametrize("missing", ["once", "request_hash"])
def test_discharges_need_both_a_request_hash_and_a_once_nonce(stack: Stack, missing: str) -> None:
    token = mint(stack).token
    denied = call(stack, token, "invoices_update_status", "invoice/42", STATUS)
    assert denied.approval is not None
    assert denied.request_hash is not None
    caveat_id = Macaroon.deserialize(token).caveats[-1].caveat_id
    opened = open_approval_caveat(caveat_id, stack.keys.approver_private)
    assert opened is not None
    caveats: list[Predicate] = [TaskIs("task-1")]
    if missing != "request_hash":
        caveats.append(RequestHashIs(denied.request_hash))
    if missing != "once":
        caveats.append(Once(secrets.token_hex(16)))
    discharge = attenuate(
        Macaroon.create(root_key=opened.caveat_key, identifier=caveat_id), caveats
    )
    outcome = call(
        stack,
        token,
        "invoices_update_status",
        "invoice/42",
        STATUS,
        discharges=[bind(token, discharge.serialize())],
    )
    assert outcome.reason == "approval_required"


def test_call_counters_are_shared_by_attenuated_copies_and_not_burned_by_denials(
    stack: Stack,
) -> None:
    token = mint(stack, "invoice-cleanup").token  # max_calls <= 5
    root = Macaroon.deserialize(token)
    copies = [
        attenuate(root, [VerbIn((Verb.READ,))]).serialize(),
        attenuate(root, [ToolIn(("invoices_read",))]).serialize(),
    ]
    for _ in range(3):
        assert call(stack, copies[0], "invoices_read", "invoice/43").reason == "caveat_unmet"
    results = [call(stack, copies[i % 2], "invoices_read", "invoice/42").allowed for i in range(6)]
    assert results == [True] * 5 + [False]
    assert call(stack, token, "invoices_read", "invoice/42").reason == "exhausted"


def test_expired_and_revoked_tokens_are_denied(stack: Stack) -> None:
    short = mint(stack, ttl_seconds=60).token
    assert call(stack, short, "invoices_read", "invoice/42").allowed
    advance(stack, 61)
    expired = call(stack, short, "invoices_read", "invoice/42")
    assert expired.failed_caveat is not None
    assert expired.failed_caveat.caveat_type == "expires"
    token = mint(stack).token
    child = attenuate(Macaroon.deserialize(token), [ResourceMatches(("invoice/42",))]).serialize()
    assert call(stack, child, "invoices_read", "invoice/42").allowed
    assert stack.broker.revoke(token)
    assert call(stack, child, "invoices_read", "invoice/42").reason == "revoked"
    assert not stack.broker.revoke("garbage")
    assert not stack.broker.revoke(Macaroon.create(root_key=b"k", identifier=b"x").serialize())


def test_manifest_required_caveats_reject_overly_broad_tokens(stack: Stack) -> None:
    broad = raw_token(stack.keys.ring, ["tool in invoices_read"]).serialize()
    outcome = call(stack, broad, "invoices_read", "invoice/42")
    assert outcome.reason == "required_caveat_missing"
    assert "expires, resource, task_id" in outcome.detail


class _BrokenState(MemoryStateStore):
    def __init__(self, failure: str) -> None:
        super().__init__()
        self.failure = failure

    def commit(
        self, claims: Sequence[StateClaim], *, expires_at: int | None, now: int
    ) -> CommitResult:
        if self.failure == "down":
            raise StateUnavailableError("down")
        return CommitResult(False, "contention")


def _broker(stack: Stack, **overrides: object) -> Broker:
    values: dict[str, object] = {
        "ring": stack.keys.ring,
        "manifest": ManifestHolder.from_manifest(stack.manifest),
        "state": MemoryStateStore(),
        "credentials": stack.keys.credentials(),
        "http": stack.http,
        "clock": stack.clock,
    }
    values.update(overrides)
    return Broker(**values)  # type: ignore[arg-type]


def test_the_broker_fails_closed(stack: Stack, tmp_path: Path) -> None:
    token = mint(stack, "invoice-audit").token
    read = ToolCall(task_id="task-1", tool="invoices_read", resource="invoice/42")

    def reason(broker: Broker) -> str:
        return broker.call(token=token, call=read, client_id=CLIENT).reason

    no_manifest = _broker(stack, manifest=ManifestHolder(tmp_path / "missing.json", {}))
    assert reason(no_manifest) == "manifest_unavailable"
    assert no_manifest.ready()["manifest_signature"] is False
    assert reason(_broker(stack, state=_BrokenState("down"))) == "state_unavailable"
    assert reason(_broker(stack, state=_BrokenState("contention"))) == "state_unavailable"
    assert reason(_broker(stack, credentials={})) == "upstream_error"

    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    offline = httpx.Client(transport=httpx.MockTransport(unreachable))
    assert reason(_broker(stack, http=offline)) == "upstream_error"
    with_base = _broker(stack, service_base_url="http://services.example/", http=offline)
    assert reason(with_base) == "upstream_error"


def test_large_outputs_are_capped(stack: Stack) -> None:
    stack.files.files["notes.txt"] = "x" * 6000
    token = mint(stack, "file-maintenance").token
    outcome = call(stack, token, "files_read", "file/notes.txt")
    assert outcome.allowed
    assert outcome.truncated
    assert outcome.output is not None
    assert len(outcome.output) < 4096 + 200


def test_decisions_are_audited_with_the_failing_caveat(stack: Stack) -> None:
    token = mint(stack).token
    call(stack, token, "invoices_read", "invoice/43")
    denied = call(stack, token, "invoices_update_status", "invoice/42", STATUS)
    discharge = approve(stack, denied)
    call(
        stack,
        token,
        "invoices_update_status",
        "invoice/42",
        STATUS,
        discharges=[bind(token, discharge)],
    )
    entries = [
        json.loads(line) for line in stack.audit.path.read_text(encoding="utf-8").splitlines()
    ]
    actions = [entry["action"] for entry in entries]
    for expected in (
        "authority.mint",
        "broker.deny",
        "approver.requested",
        "approver.discharge",
        "broker.execute",
    ):
        assert expected in actions
    first_deny = next(entry for entry in entries if entry["action"] == "broker.deny")
    assert first_deny["data"]["failed_caveat"] == "resource matches invoice/42"
    assert verify_file(stack.audit.path, expect_head=stack.audit.head).ok


def test_metrics_count_decisions_and_latencies(stack: Stack) -> None:
    token = mint(stack).token
    call(stack, token, "invoices_read", "invoice/42")
    call(stack, token, "invoices_read", "invoice/43")
    registry = stack.broker.metrics.registry
    assert (
        registry.get_sample_value(
            "capability_decisions_total", {"result": "allow", "caveat_type": "none"}
        )
        == 1
    )
    assert (
        registry.get_sample_value(
            "capability_decisions_total", {"result": "deny", "caveat_type": "resource"}
        )
        == 1
    )
    assert registry.get_sample_value("verify_latency_seconds_count") == 2
    assert registry.get_sample_value("broker_call_latency_seconds_count", {"result": "deny"}) == 1


def test_broker_spans_join_the_agent_step_trace(tmp_path: Path) -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")
    stack = make_stack(tmp_path, tracer=tracer)
    try:
        minted = mint(stack, "invoice-audit")
        planner = FakeProvider(
            ScriptedPolicy(
                [
                    LLMResponse(
                        model="fake",
                        stop_reason="tool_use",
                        tool_calls=(
                            ToolUseBlock(
                                id="c1", name="invoices_read", arguments={"resource": "invoice/42"}
                            ),
                        ),
                    ),
                    LLMResponse(model="fake", stop_reason="end_turn", text="done"),
                ]
            )
        )
        runtime = CapabilityRuntime(
            RuntimeContext(
                task_id="task-1",
                manifest=stack.manifest,
                providers=lambda name: planner,
                budget=BudgetLedger(BudgetLimits.of(steps=5, tokens=100_000, usd=1.0)),
                tracer=tracer,
                clock=stack.clock,
            ),
            token=minted.token,
            broker=InProcessBrokerClient(stack.broker, CLIENT),
            approver=InProcessApproverClient(stack.approver, CLIENT),
        )
        runtime.run("read invoice 42")
    finally:
        stack.close()
    spans = exporter.get_finished_spans()
    broker_span = next(span for span in spans if span.name == "broker.call")
    step = next(
        span
        for span in spans
        if span.name == "agent.step" and span.context.span_id == broker_span.parent.span_id  # type: ignore[union-attr]
    )
    assert broker_span.context.trace_id == step.context.trace_id
    assert dict(broker_span.attributes or {})["ctb.allowed"] is True
