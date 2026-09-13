"""Offline end-to-end demo: delegation, a contained prompt injection and a CLI-approved write.

Everything runs in one process with keys generated at start-up: authority, approver, broker, the
three fake services and an agent host whose planner and sub-agent are scripted ``FakeProvider``
models. No network, no API key.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pydantic import JsonValue

from capability_tool_broker.agent.clients import (
    InProcessApproverClient,
    InProcessAuthorityClient,
    InProcessBrokerClient,
)
from capability_tool_broker.agent.host import (
    DELEGATE_TOOL,
    CapabilityRuntime,
    PendingApproval,
    RuntimeContext,
    ToolEvent,
)
from capability_tool_broker.agentic.approval import ApprovalStatus
from capability_tool_broker.agentic.audit import verify_file
from capability_tool_broker.agentic.budget import BudgetLedger, BudgetLimits
from capability_tool_broker.approver.cli import review_pending
from capability_tool_broker.scenario import (
    DEMO_INSTRUCTION,
    demo_invoices,
    demo_providers,
    demo_token_request,
)
from capability_tool_broker.stack import ManualClock, Stack, build_stack

__all__ = ["format_event", "run_demo"]

_CLIENT_ID = "agent-host"
_STALE = ("audit.jsonl", "audit.tampered.jsonl", "budget.json")


def format_event(event: ToolEvent) -> str:
    target = f"{event.tool} {event.resource or ''}".strip()
    if event.outcome == "executed":
        return f"      {event.agent}: {target} -> executed (HTTP {event.status})"
    if event.outcome == "approval_pending":
        return f"      {event.agent}: {target} -> waiting on CLI approval ({event.approval_id})"
    line = f"      {event.agent}: {target} -> DENIED ({event.reason})"
    if event.failed_caveat:
        line += f"\n          failing caveat: {event.failed_caveat}"
    return line


def _indent(text: str) -> str:
    return "\n".join(f"      {line}" for line in text.splitlines())


def run_demo(
    workdir: Path,
    *,
    interactive: bool = False,
    out: Callable[[str], None] = print,
    ask: Callable[[str], str] | None = None,
) -> dict[str, JsonValue]:
    workdir.mkdir(parents=True, exist_ok=True)
    for name in _STALE:
        (workdir / name).unlink(missing_ok=True)
    clock = ManualClock()
    stack = build_stack(workdir, clock=clock, invoices=demo_invoices())
    try:
        return _run(stack, workdir, clock, interactive=interactive, out=out, ask=ask)
    finally:
        stack.close()


def _run(  # noqa: PLR0915 - a linear narrative
    stack: Stack,
    workdir: Path,
    clock: ManualClock,
    *,
    interactive: bool,
    out: Callable[[str], None],
    ask: Callable[[str], str] | None,
) -> dict[str, JsonValue]:
    minted = InProcessAuthorityClient(stack.authority, _CLIENT_ID).mint(demo_token_request())
    out("== capability-tool-broker demo (offline: scripted FakeProvider, in-process services) ==")
    out(f"[1] authority minted the task token for {minted.task_id} ({minted.template}):")
    for line in minted.caveats:
        out(f"      {line}")

    budget = BudgetLedger(
        BudgetLimits.of(
            steps=minted.budget.steps, tokens=minted.budget.tokens, usd=minted.budget.usd
        ),
        workdir / "budget.json",
    )
    runtime = CapabilityRuntime(
        RuntimeContext(
            task_id=minted.task_id,
            manifest=stack.manifest,
            providers=demo_providers(),
            budget=budget,
            audit=stack.audit,
            clock=clock,
        ),
        token=minted.token,
        broker=InProcessBrokerClient(stack.broker, _CLIENT_ID),
        approver=InProcessApproverClient(stack.approver, _CLIENT_ID),
    )
    runtime.run(DEMO_INSTRUCTION)
    delegated: list[JsonValue] = []
    for parent, child, added in runtime.delegations:
        out(f"[2] {parent} delegated to sub-agent '{child}' offline; the child token appends:")
        for line in added:
            out(f"      {line}")
        delegated.extend(added)
    out("[3] tool calls (the reader obeys every instruction injected into invoice 42's notes):")
    for event in runtime.events:
        if event.tool != DELEGATE_TOOL:
            out(format_event(event))

    pending = list(runtime.pending)
    out(f"[4] {len(pending)} write waiting on CLI approval; the approver shows the exact request:")

    def scripted(prompt: str) -> str:
        out(f"      {prompt}y   (scripted answer; run 'demo --interactive' to decide yourself)")
        return "y"

    answer = ask if ask is not None else (input if interactive else scripted)
    decided = review_pending(
        stack.approver, approver="human:reviewer", ask=answer, show=lambda text: out(_indent(text))
    )
    resumed = runtime.resume()
    executed = [e for e in runtime.events if e.outcome == "executed"]
    denied = [e for e in runtime.events if e.outcome == "denied"]
    out("[5] the host binds the discharge to the requesting token and retries the call:")
    for event in resumed:
        out(format_event(event))
    status = stack.invoices.invoices["42"]["status"]
    out(f"      invoice 42 status is now {status!r}")

    replay_reason: str | None = None
    reuse_reason: str | None = None
    reuse_caveat: str | None = None
    approved = [record for record in decided if record.status is ApprovalStatus.APPROVED]
    if approved and pending and approved[0].discharge is not None:
        record = approved[0]
        discharge = approved[0].discharge
        original = next(item for item in pending if item.approval_id == record.id)
        replay_reason = runtime.execute_with_discharge(original, discharge).reason
        other_call = original.call.model_copy(update={"args": {"status": "paid"}})
        other = PendingApproval(
            record.id, original.agent, original.token, other_call, record.request_hash
        )
        reuse = runtime.execute_with_discharge(other, discharge)
        reuse_reason = reuse.reason
        reuse_caveat = reuse.failed_caveat.condition if reuse.failed_caveat else None
        out("[6] a discharge is single-use and bound to one canonical request:")
        out(f"      replaying the approved call          -> DENIED ({replay_reason})")
        out(f"      same discharge for status 'paid'     -> DENIED ({reuse_reason})")
        if reuse_caveat:
            out(f"          failing caveat: {reuse_caveat}")

    verified = verify_file(stack.audit.path, expect_head=stack.audit.head)
    lines = stack.audit.path.read_text(encoding="utf-8").splitlines(keepends=True)
    tampered_path = workdir / "audit.tampered.jsonl"
    tampered_path.write_text(
        "".join([lines[0].replace("authority.mint", "authority.mnt", 1), *lines[1:]]),
        encoding="utf-8",
        newline="\n",
    )
    tampered = verify_file(tampered_path)
    out(
        f"[7] audit chain: {verified.entries} entries (mint, attenuate, deny, discharge, execute), "
        f"verified={verified.ok}; edited copy detected={not tampered.ok} ({tampered.error})"
    )

    return {
        "task_id": minted.task_id,
        "root_caveats": list(minted.caveats),
        "delegated_caveats": delegated,
        "executed": [f"{e.agent}:{e.tool}:{e.resource}" for e in executed],
        "denied": [
            {
                "agent": e.agent,
                "tool": e.tool,
                "resource": e.resource,
                "reason": e.reason,
                "failed_caveat": e.failed_caveat,
            }
            for e in denied
        ],
        "approvals_requested": len(pending),
        "invoice_42_status": status,
        "replayed_discharge": replay_reason,
        "discharge_on_other_request": reuse_reason,
        "audit_ok": verified.ok,
        "audit_entries": verified.entries,
        "audit_head": verified.head,
        "tampered_copy_detected": not tampered.ok,
        "budget_steps_used": budget.state.steps,
        "messages_sent": len(stack.mailer.outbox),
    }
