"""End-to-end check against the running compose stack, run from the agent-host container.

``start`` mints a task token over HTTP, runs the scripted scenario (delegation, injected calls,
a write that needs approval) and stores the pending approvals in a private state file. A human, or
the CI job, then runs ``capability-tool-broker approver review`` in the approver container.
``resume`` binds the discharge, executes the approved write and checks that replaying the
discharge is denied. Both phases fail (exit code 1) if any expectation does not hold.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path

from pydantic import JsonValue, TypeAdapter

from capability_tool_broker.agent.clients import (
    ApproverClient,
    AuthorityClient,
    BrokerClient,
)
from capability_tool_broker.agent.host import (
    DELEGATE_TOOL,
    CapabilityRuntime,
    PendingApproval,
    RuntimeContext,
)
from capability_tool_broker.agentic.budget import BudgetLedger, BudgetLimits
from capability_tool_broker.agentic.errors import ProviderError
from capability_tool_broker.agentic.providers.base import LLMProvider
from capability_tool_broker.broker.broker import ToolCall
from capability_tool_broker.broker.manifest import ToolManifest
from capability_tool_broker.scenario import (
    DEMO_INSTRUCTION,
    DEMO_TASK_ID,
    demo_providers,
    demo_token_request,
)

__all__ = ["E2EError", "resume_phase", "start_phase"]

_PENDING = TypeAdapter(list[dict[str, JsonValue]])


class E2EError(Exception):
    """An end-to-end expectation did not hold."""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise E2EError(message)


def _no_provider(name: str) -> LLMProvider:
    raise ProviderError(f"no model is needed to resume approved calls (asked for {name})")


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)


def start_phase(
    *,
    authority: AuthorityClient,
    broker: BrokerClient,
    approver: ApproverClient,
    manifest: ToolManifest,
    state_path: Path,
    clock: Callable[[], float] = time.time,
) -> dict[str, JsonValue]:
    minted = authority.mint(demo_token_request())
    budget = BudgetLedger(
        BudgetLimits.of(
            steps=minted.budget.steps, tokens=minted.budget.tokens, usd=minted.budget.usd
        )
    )
    runtime = CapabilityRuntime(
        RuntimeContext(
            task_id=minted.task_id,
            manifest=manifest,
            providers=demo_providers(),
            budget=budget,
            clock=clock,
        ),
        token=minted.token,
        broker=broker,
        approver=approver,
    )
    runtime.run(DEMO_INSTRUCTION)
    calls = [event for event in runtime.events if event.tool != DELEGATE_TOOL]
    executed = [event for event in calls if event.outcome == "executed"]
    denied = [event for event in calls if event.outcome == "denied"]
    _expect(len(runtime.delegations) == 1, "planner should delegate exactly once")
    _expect(
        [(e.tool, e.resource) for e in executed] == [("invoices_read", "invoice/42")],
        "only the delegated read should execute before approval",
    )
    _expect(len(denied) == 3, "all three injected calls should be denied")
    _expect(all(e.failed_caveat for e in denied), "every denial should name its failing caveat")
    _expect(len(runtime.pending) == 1, "the status change should wait for approval")
    pending = [
        {
            "approval_id": item.approval_id,
            "agent": item.agent,
            "token": item.token,
            "call": item.call.model_dump(mode="json"),
            "request_hash": item.request_hash,
        }
        for item in runtime.pending
    ]
    _write_private(
        state_path,
        json.dumps({"task_id": minted.task_id, "root_token": minted.token, "pending": pending}),
    )
    return {
        "phase": "start",
        "task_id": minted.task_id,
        "executed": len(executed),
        "denied": [f"{e.tool} {e.resource}: {e.failed_caveat}" for e in denied],
        "pending_approvals": [item.approval_id for item in runtime.pending],
    }


def resume_phase(
    *,
    broker: BrokerClient,
    approver: ApproverClient,
    manifest: ToolManifest,
    state_path: Path,
    clock: Callable[[], float] = time.time,
) -> dict[str, JsonValue]:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    runtime = CapabilityRuntime(
        RuntimeContext(
            task_id=str(state.get("task_id", DEMO_TASK_ID)),
            manifest=manifest,
            providers=_no_provider,
            budget=BudgetLedger(BudgetLimits.of(steps=1, tokens=1, usd=0)),
            clock=clock,
        ),
        token=str(state["root_token"]),
        broker=broker,
        approver=approver,
    )
    for item in _PENDING.validate_python(state["pending"]):
        runtime.pending.append(
            PendingApproval(
                approval_id=str(item["approval_id"]),
                agent=str(item["agent"]),
                token=str(item["token"]),
                call=ToolCall.model_validate(item["call"]),
                request_hash=str(item["request_hash"]),
            )
        )
    originals = list(runtime.pending)
    events = runtime.resume()
    _expect(not runtime.pending, "every approval should be decided before resuming")
    _expect(
        len(events) == len(originals) and all(e.outcome == "executed" for e in events),
        "approved calls should execute",
    )
    view = approver.fetch(originals[0].approval_id)
    _expect(view.discharge is not None, "an approved request carries a discharge")
    replay = runtime.execute_with_discharge(originals[0], view.discharge or "")
    _expect(replay.reason == "replayed", "a replayed discharge must be denied")
    state_path.unlink(missing_ok=True)
    return {
        "phase": "resume",
        "executed_after_approval": len(events),
        "replayed_discharge": replay.reason,
    }
