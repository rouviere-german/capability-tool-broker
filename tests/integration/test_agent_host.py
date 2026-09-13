"""Agent runtimes: delegation, prompt injection, approvals, budgets and the ambient baseline."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from pathlib import Path

import httpx
import pytest
from pydantic import JsonValue

from capability_tool_broker.agent.clients import (
    InProcessApproverClient,
    InProcessAuthorityClient,
    InProcessBrokerClient,
    RemoteServiceError,
    _json_or_error,
)
from capability_tool_broker.agent.host import (
    DELEGATE_TOOL,
    AmbientRuntime,
    CapabilityRuntime,
    ProviderFactory,
    RuntimeContext,
    tools_in_token,
)
from capability_tool_broker.agentic.budget import BudgetLedger, BudgetLimits
from capability_tool_broker.agentic.errors import BudgetExceededError, ProviderError
from capability_tool_broker.agentic.providers.base import (
    LLMProvider,
    LLMResponse,
    ToolUseBlock,
    Usage,
)
from capability_tool_broker.agentic.providers.fake import FakeProvider, ScriptedPolicy
from capability_tool_broker.macaroons.macaroon import Macaroon
from capability_tool_broker.scenario import (
    DEMO_INSTRUCTION,
    demo_invoices,
    demo_providers,
    demo_token_request,
)
from capability_tool_broker.stack import Stack
from support import CLIENT, REVIEWER, make_stack, mint

pytestmark = pytest.mark.integration


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    built = make_stack(tmp_path, invoices=demo_invoices())
    yield built
    built.close()


def budget(steps: int = 50) -> BudgetLedger:
    return BudgetLedger(BudgetLimits.of(steps=steps, tokens=1_000_000, usd=10.0))


def runtime_for(
    stack: Stack,
    token: str,
    providers: ProviderFactory,
    *,
    ledger: BudgetLedger | None = None,
    max_depth: int = 2,
) -> CapabilityRuntime:
    return CapabilityRuntime(
        RuntimeContext(
            task_id="task-1" if "review-42" not in token else "review-42",
            manifest=stack.manifest,
            providers=providers,
            budget=ledger or budget(),
            audit=stack.audit,
            clock=stack.clock,
            max_depth=max_depth,
        ),
        token=token,
        broker=InProcessBrokerClient(stack.broker, CLIENT),
        approver=InProcessApproverClient(stack.approver, CLIENT),
    )


def scripted(*turns: tuple[str, Mapping[str, JsonValue]]) -> FakeProvider:
    steps: list[LLMResponse | ProviderError] = [
        LLMResponse(
            model="fake",
            stop_reason="tool_use",
            tool_calls=(ToolUseBlock(id=f"c{i}", name=name, arguments=dict(arguments)),),
        )
        for i, (name, arguments) in enumerate(turns)
    ]
    steps.append(LLMResponse(model="fake", stop_reason="end_turn", text="finished"))
    return FakeProvider(ScriptedPolicy(steps))


def test_the_injected_sub_agent_is_contained_and_the_write_waits_for_a_human(stack: Stack) -> None:
    minted = InProcessAuthorityClient(stack.authority, CLIENT).mint(demo_token_request())
    runtime = CapabilityRuntime(
        RuntimeContext(
            task_id=minted.task_id,
            manifest=stack.manifest,
            providers=demo_providers(),
            budget=budget(),
            audit=stack.audit,
            clock=stack.clock,
        ),
        token=minted.token,
        broker=InProcessBrokerClient(stack.broker, CLIENT),
        approver=InProcessApproverClient(stack.approver, CLIENT),
    )
    report = runtime.run(DEMO_INSTRUCTION)
    assert report.children[0].agent == "reader"
    denials = {
        (e.tool, e.resource): e.failed_caveat for e in runtime.events if e.outcome == "denied"
    }
    assert denials == {
        ("invoices_read", "invoice/43"): "resource matches invoice/42",
        ("invoices_update_status", "invoice/42"): "tool in invoices_read",
        ("mail_send", "mail/attacker@evil.example"): "tool in invoices_read,invoices_update_status",
    }
    assert runtime.delegations[0][2][:2] == ["tool in invoices_read", "resource matches invoice/42"]
    assert "reader" in runtime.agent_tokens
    assert len(runtime.pending) == 1
    assert stack.mailer.outbox == []
    assert stack.invoices.invoices["42"]["status"] == "open"
    assert runtime.resume() == []  # nobody decided yet
    stack.approver.decide(runtime.pending[0].approval_id, approver=REVIEWER, approve=True)
    resumed = runtime.resume()
    assert [e.outcome for e in resumed] == ["executed"]
    assert stack.invoices.invoices["42"]["status"] == "approved"
    assert runtime.pending == []


def test_a_denied_approval_is_reported_and_nothing_runs(stack: Stack) -> None:
    minted = mint(stack)
    runtime = runtime_for(
        stack,
        minted.token,
        lambda name: scripted(
            ("invoices_update_status", {"resource": "invoice/42", "status": "paid"})
        ),
    )
    runtime.run("mark invoice 42 paid")
    stack.approver.decide(runtime.pending[0].approval_id, approver=REVIEWER, approve=False)
    events = runtime.resume()
    assert [(e.outcome, e.reason) for e in events] == [("rejected", "denied by the human approver")]
    assert stack.invoices.invoices["42"]["status"] == "open"


def test_delegation_arguments_and_depth_are_checked(stack: Stack) -> None:
    token = mint(stack, "invoice-audit").token
    bad = runtime_for(
        stack,
        token,
        lambda name: scripted(
            (
                DELEGATE_TOOL,
                {"agent": "x", "task": "t", "tools": ["invoices_read"], "resources": ["a**"]},
            )
        ),
    )
    bad.run("delegate badly")
    assert [(e.outcome, e.reason) for e in bad.events] == [
        ("rejected", "invalid delegation arguments")
    ]
    flat = runtime_for(
        stack,
        token,
        lambda name: scripted(
            (
                DELEGATE_TOOL,
                {"agent": "x", "task": "t", "tools": ["invoices_read"], "resources": ["invoice/1"]},
            )
        ),
        max_depth=0,
    )
    flat.run("delegate too deep")
    assert flat.events[0].reason == "delegation depth exhausted"


def test_sub_agents_draw_from_the_task_budget(stack: Stack) -> None:
    token = mint(stack, "invoice-audit").token
    providers: dict[str, LLMProvider] = {
        "planner": scripted(
            (
                DELEGATE_TOOL,
                {
                    "agent": "reader",
                    "task": "t",
                    "tools": ["invoices_read"],
                    "resources": ["invoice/*"],
                },
            )
        ),
        "reader": scripted(
            *[("invoices_read", {"resource": f"invoice/{i}"}) for i in range(1, 10)]
        ),
    }
    ledger = budget(steps=4)
    runtime = runtime_for(stack, token, providers.__getitem__, ledger=ledger)
    with pytest.raises(BudgetExceededError):
        runtime.run("read everything")
    assert ledger.state.steps == 4


def test_the_host_rejects_unknown_tools_and_malformed_calls(stack: Stack) -> None:
    token = mint(stack, "invoice-audit").token
    runtime = runtime_for(
        stack,
        token,
        lambda name: scripted(
            ("does_not_exist", {"resource": "invoice/1"}),
            ("invoices_read", {}),
            ("invoices_read", {"resource": "invoice/1", "Bad Arg": 1}),
        ),
    )
    runtime.run("misbehave")
    assert [e.reason for e in runtime.events] == [
        "unknown tool",
        "a string 'resource' argument is required",
        "invalid_request",
    ]


def test_the_ambient_baseline_executes_injected_calls(stack: Stack) -> None:
    runtime = AmbientRuntime(
        RuntimeContext(
            task_id="review-42",
            manifest=stack.manifest,
            providers=demo_providers(),
            budget=budget(),
            clock=stack.clock,
        ),
        credentials=stack.keys.credentials(),
        http=stack.http,
    )
    runtime.run(DEMO_INSTRUCTION)
    assert len(stack.mailer.outbox) == 1
    assert stack.invoices.invoices["42"]["status"] == "approved"  # paid by injection, then approved
    assert {e.outcome for e in runtime.events} == {"executed", "delegated"}
    last_call = runtime.events[-1].call
    assert last_call is not None
    bad = runtime.execute_direct("attacker", last_call.model_copy(update={"resource": "x/y/z"}))
    assert bad.outcome == "rejected"


def test_billed_provider_failures_are_charged_before_raising(stack: Stack) -> None:
    token = mint(stack, "invoice-audit").token
    failure = ProviderError(
        "truncated", model="fake", usage=Usage(input_tokens=100, output_tokens=50)
    )
    ledger = budget()
    runtime = runtime_for(
        stack, token, lambda name: FakeProvider(ScriptedPolicy([failure])), ledger=ledger
    )
    with pytest.raises(ProviderError):
        runtime.run("fail")
    assert ledger.state.tokens == 150


def test_offered_tools_follow_the_token_caveats(stack: Stack) -> None:
    token = mint(stack).token
    assert tools_in_token(token, stack.manifest) == ("invoices_read", "invoices_update_status")
    broken = Macaroon.deserialize(token).add_first_party_caveat(b"\xff").serialize()
    assert tools_in_token(broken, stack.manifest) == ("invoices_read", "invoices_update_status")


def test_http_client_errors_are_typed() -> None:
    request = httpx.Request("GET", "http://x")
    error = httpx.Response(403, json={"error": {"code": "forbidden"}}, request=request)
    with pytest.raises(RemoteServiceError) as raised:
        _json_or_error(error)
    assert raised.value.code == "forbidden"
    with pytest.raises(RemoteServiceError) as plain:
        _json_or_error(httpx.Response(500, content=b"oops", request=request))
    assert plain.value.status == 500
