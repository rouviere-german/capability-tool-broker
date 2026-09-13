"""Human review in a terminal: show the exact canonical request, ask, record the decision.

Every string that came from an agent (tool, resource, arguments) is shown with control characters
escaped, so a crafted argument cannot rewrite the terminal to hide what is being approved.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from capability_tool_broker.agentic.approval import ApprovalRecord
from capability_tool_broker.approver.service import ApproverService

__all__ = ["render_request", "review_pending"]

_TRANSLATION = {code: f"\\x{code:02x}" for code in [*range(0x20), 0x7F]}


def _safe(text: str) -> str:
    return text.translate(_TRANSLATION)


def render_request(record: ApprovalRecord) -> str:
    request = record.canonical_request()
    arguments = json.dumps(request.args, indent=2, sort_keys=True, ensure_ascii=True)
    lines = [
        f"approval request {record.id}",
        f"  requested by : {_safe(record.requested_by)}",
        f"  task         : {request.task_id}",
        f"  tool         : {request.tool} ({request.verb.value} on {request.host})",
        f"  resource     : {_safe(request.resource)}",
        "  arguments    :",
        *(f"    {_safe(line)}" for line in arguments.splitlines()),
        f"  request hash : {record.request_hash}",
    ]
    return "\n".join(lines)


def review_pending(
    service: ApproverService,
    *,
    approver: str,
    ask: Callable[[str], str] = input,
    show: Callable[[str], None] = print,
) -> list[ApprovalRecord]:
    decided: list[ApprovalRecord] = []
    for record in service.pending():
        show(render_request(record))
        answer = ask("Approve this exact request? [y/N] ").strip().lower()
        approve = answer in {"y", "yes"}
        decided.append(
            service.decide(
                record.id,
                approver=approver,
                approve=approve,
                reason="approved in CLI review" if approve else "denied in CLI review",
            )
        )
        show(f"  -> {'approved' if approve else 'denied'}")
    return decided
