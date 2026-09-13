"""Agent runtimes: one loop, two ways to execute tools.

:class:`CapabilityRuntime` is the system under test. Its planner holds only the task's capability
token; delegating to a sub-agent appends caveats offline and hands over the narrower child token.
Every tool call goes to the broker with the calling agent's own token. The host does not filter
calls: whatever a (possibly prompt-injected) model asks for is forwarded, and the broker alone
decides. Calls that need approval are submitted to the approver and resumed once a human decided.

:class:`AmbientRuntime` is the baseline the evaluation compares against: the common pattern where
the host process holds the service credentials and executes any tool the model calls, and
sub-agents inherit everything.

Both share the loop: budgets are charged per step (steps before, tokens and USD after each call),
model output is echoed back verbatim, tool output is wrapped as untrusted data, and every step,
delegation, approval request and tool outcome is audited. Agent steps run inside an OpenTelemetry
span and the trace context travels with the broker call, so the broker span joins the same trace.
"""

from __future__ import annotations

import abc
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

import httpx
from opentelemetry import trace
from opentelemetry.propagate import inject
from opentelemetry.trace import Tracer
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, field_validator

from capability_tool_broker.agent.clients import ApproverClient, BrokerClient
from capability_tool_broker.agentic.audit import AuditLog
from capability_tool_broker.agentic.budget import BudgetLedger
from capability_tool_broker.agentic.envelope import (
    UNTRUSTED_DATA_POLICY,
    UntrustedData,
    wrap_tool_result,
)
from capability_tool_broker.agentic.errors import ProviderError
from capability_tool_broker.agentic.providers.base import (
    ChatMessage,
    ContentBlock,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    TextBlock,
    ToolResultBlock,
    ToolSpec,
    ToolUseBlock,
)
from capability_tool_broker.approver.service import ApprovalSubmission
from capability_tool_broker.broker.broker import BrokerOutcome, ToolCall
from capability_tool_broker.broker.manifest import ToolManifest
from capability_tool_broker.broker.signing import ServiceCredential, sign_request
from capability_tool_broker.capabilities.attenuate import attenuate, delegation_caveats
from capability_tool_broker.capabilities.caveats import (
    CaveatSyntaxError,
    ToolIn,
    format_caveat,
    parse_caveat,
)
from capability_tool_broker.capabilities.glob import is_valid_glob
from capability_tool_broker.capabilities.request import TOOL_PATTERN, Verb
from capability_tool_broker.core.canonical import canonical_json, sha256_hex
from capability_tool_broker.macaroons.macaroon import Macaroon

__all__ = [
    "DELEGATE_TOOL",
    "AgentReport",
    "AgentRuntime",
    "AmbientRuntime",
    "CapabilityRuntime",
    "DelegateArgs",
    "PendingApproval",
    "ProviderFactory",
    "RuntimeContext",
    "ToolEvent",
    "tools_in_token",
]

DELEGATE_TOOL = "delegate"
ProviderFactory = Callable[[str], LLMProvider]
EventOutcome = Literal["executed", "denied", "approval_pending", "rejected", "failed", "delegated"]
_TOOL = re.compile(TOOL_PATTERN)
_SYSTEM_PROMPT = (
    "You are {agent}, an agent working on task {task_id}. Use the available tools to complete "
    "the task, then answer with a short summary. Tool calls are authorized by a capability "
    "broker; a denied call means you lack the authority for it, so do not retry it."
)


class DelegateArgs(BaseModel):
    """Arguments of the ``delegate`` tool: spawn a sub-agent with a narrower grant."""

    model_config = ConfigDict(extra="forbid")

    agent: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$", description="Name of the sub-agent")
    task: str = Field(min_length=1, max_length=2000, description="Instruction for the sub-agent")
    tools: list[str] = Field(min_length=1, max_length=8)
    resources: list[str] = Field(min_length=1, max_length=8)
    verbs: list[Verb] | None = None
    max_calls: int | None = Field(default=None, ge=1, le=1000)
    ttl_seconds: int | None = Field(default=None, ge=1, le=3600)

    @field_validator("tools")
    @classmethod
    def _check_tools(cls, value: list[str]) -> list[str]:
        if any(_TOOL.fullmatch(tool) is None for tool in value):
            raise ValueError("invalid tool name")
        return value

    @field_validator("resources")
    @classmethod
    def _check_resources(cls, value: list[str]) -> list[str]:
        if not all(is_valid_glob(pattern) for pattern in value):
            raise ValueError("invalid resource glob")
        return value


@dataclass
class ToolEvent:
    agent: str
    tool: str
    resource: str | None
    outcome: EventOutcome
    reason: str
    failed_caveat: str | None = None
    approval_id: str | None = None
    status: int | None = None
    call: ToolCall | None = None


@dataclass
class PendingApproval:
    approval_id: str
    agent: str
    token: str
    call: ToolCall
    request_hash: str


@dataclass
class AgentReport:
    agent: str
    final_text: str = ""
    steps: int = 0
    children: list[AgentReport] = field(default_factory=list)


@dataclass
class RuntimeContext:
    task_id: str
    manifest: ToolManifest
    providers: ProviderFactory
    budget: BudgetLedger
    audit: AuditLog | None = None
    tracer: Tracer | None = None
    clock: Callable[[], float] = time.time
    max_depth: int = 2
    max_tokens: int = 2048


@dataclass(frozen=True, slots=True)
class _Agent:
    name: str
    depth: int
    token: str | None
    tools: tuple[str, ...]


def tools_in_token(token: str, manifest: ToolManifest) -> tuple[str, ...]:
    """Manifest tools that every ``tool in`` caveat of the token allows (a prompt hint only)."""
    allowed = {tool.name for tool in manifest.tools}
    for caveat in Macaroon.deserialize(token).caveats:
        if caveat.verification_id is not None:
            continue
        try:
            predicate = parse_caveat(caveat.caveat_id.decode("utf-8"))
        except (UnicodeDecodeError, CaveatSyntaxError):
            continue
        if isinstance(predicate, ToolIn):
            allowed &= set(predicate.tools)
    return tuple(sorted(allowed))


class AgentRuntime(abc.ABC):
    def __init__(self, context: RuntimeContext) -> None:
        self.context = context
        self.task_id = context.task_id
        self._manifest = context.manifest
        self._tracer = context.tracer or trace.get_tracer("capability_tool_broker.agent")
        self.events: list[ToolEvent] = []

    # --- hooks ----------------------------------------------------------------------------------

    @abc.abstractmethod
    def _root_agent(self) -> _Agent: ...

    @abc.abstractmethod
    def _child_agent(self, parent: _Agent, args: DelegateArgs) -> _Agent: ...

    @abc.abstractmethod
    def _execute(self, agent: _Agent, tool_use_id: str, call: ToolCall) -> ToolResultBlock: ...

    # --- loop -----------------------------------------------------------------------------------

    def run(self, instruction: str, *, attachments: Sequence[UntrustedData] = ()) -> AgentReport:
        return self._run_agent(self._root_agent(), instruction, attachments)

    def _audit_append(self, actor: str, action: str, data: dict[str, JsonValue]) -> None:
        if self.context.audit is not None:
            self.context.audit.append(actor, action, data)

    def _specs(self, agent: _Agent) -> tuple[ToolSpec, ...]:
        specs = [
            ToolSpec(
                name=entry.name, description=entry.description, input_schema=entry.input_schema()
            )
            for entry in self._manifest.tools
            if entry.name in agent.tools
        ]
        if agent.depth < self.context.max_depth:
            specs.append(
                ToolSpec(
                    name=DELEGATE_TOOL,
                    description="Delegate a sub-task to a sub-agent with narrower authority.",
                    input_schema=DelegateArgs.model_json_schema(),
                )
            )
        return tuple(specs)

    def _complete(self, agent: _Agent, provider: LLMProvider, request: LLMRequest) -> LLMResponse:
        budget = self.context.budget
        try:
            response = provider.complete(request)
        except ProviderError as exc:
            if exc.usage is not None:
                budget.record_usage(model=exc.model or "unknown", usage=exc.usage)
            raise
        self._audit_append(
            agent.name,
            "agent.llm_response",
            {
                "task_id": self.task_id,
                "request_sha256": request.sha256(),
                "model": response.model,
                "stop_reason": response.stop_reason,
                "tool_calls": [call.name for call in response.tool_calls],
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
        )
        budget.record_usage(model=response.model, usage=response.usage)
        return response

    def _run_agent(
        self, agent: _Agent, instruction: str, attachments: Sequence[UntrustedData] = ()
    ) -> AgentReport:
        provider = self.context.providers(agent.name)
        system = (
            _SYSTEM_PROMPT.format(agent=agent.name, task_id=self.task_id)
            + "\n\n"
            + UNTRUSTED_DATA_POLICY
        )
        first: list[ContentBlock] = [TextBlock(text=instruction)]
        first.extend(TextBlock(text=item.render()) for item in attachments)
        messages: list[ChatMessage] = [ChatMessage(role="user", content=tuple(first))]
        specs = self._specs(agent)
        report = AgentReport(agent=agent.name)
        while True:
            self.context.budget.reserve_step()
            with self._tracer.start_as_current_span("agent.step") as span:
                span.set_attribute("ctb.agent", agent.name)
                span.set_attribute("ctb.task_id", self.task_id)
                span.set_attribute("ctb.step", report.steps)
                request = LLMRequest(
                    system=system,
                    messages=tuple(messages),
                    tools=specs,
                    max_tokens=self.context.max_tokens,
                    role="planner" if agent.depth == 0 else "subagent",
                )
                response = self._complete(agent, provider, request)
                report.steps += 1
                assistant: list[ContentBlock] = list(response.content)
                if not assistant:
                    if response.text:
                        assistant.append(TextBlock(text=response.text))
                    assistant.extend(response.tool_calls)
                if assistant:
                    messages.append(ChatMessage(role="assistant", content=tuple(assistant)))
                if not response.tool_calls:
                    report.final_text = response.text
                    self._audit_append(
                        agent.name,
                        "agent.finished",
                        {"task_id": self.task_id, "steps": report.steps},
                    )
                    return report
                results: list[ContentBlock] = [
                    self._handle(agent, call, report) for call in response.tool_calls
                ]
            messages.append(ChatMessage(role="user", content=tuple(results)))

    def _reject(self, agent: _Agent, tool_use: ToolUseBlock, reason: str) -> ToolResultBlock:
        self.events.append(ToolEvent(agent.name, tool_use.name, None, "rejected", reason))
        return ToolResultBlock(
            tool_use_id=tool_use.id, content=f"Call rejected: {reason}.", is_error=True
        )

    def _handle(
        self, agent: _Agent, tool_use: ToolUseBlock, report: AgentReport
    ) -> ToolResultBlock:
        if tool_use.name == DELEGATE_TOOL:
            return self._delegate(agent, tool_use, report)
        entry = self._manifest.get(tool_use.name)
        if entry is None:
            return self._reject(agent, tool_use, "unknown tool")
        resource = tool_use.arguments.get("resource")
        args = {key: value for key, value in tool_use.arguments.items() if key != "resource"}
        if not isinstance(resource, str):
            return self._reject(agent, tool_use, "a string 'resource' argument is required")
        try:
            call = ToolCall(task_id=self.task_id, tool=entry.name, resource=resource, args=args)
        except ValidationError:
            return self._reject(agent, tool_use, "malformed tool call")
        return self._execute(agent, tool_use.id, call)

    def _delegate(
        self, agent: _Agent, tool_use: ToolUseBlock, report: AgentReport
    ) -> ToolResultBlock:
        if agent.depth >= self.context.max_depth:
            return self._reject(agent, tool_use, "delegation depth exhausted")
        try:
            args = DelegateArgs.model_validate(tool_use.arguments)
        except ValidationError:
            return self._reject(agent, tool_use, "invalid delegation arguments")
        child = self._child_agent(agent, args)
        self.events.append(
            ToolEvent(agent.name, DELEGATE_TOOL, None, "delegated", f"sub-agent {child.name}")
        )
        child_report = self._run_agent(child, args.task)
        report.children.append(child_report)
        envelope = wrap_tool_result(DELEGATE_TOOL, child_report.final_text or "(no answer)")
        return ToolResultBlock(tool_use_id=tool_use.id, content=envelope.render())


class CapabilityRuntime(AgentRuntime):
    """Planner and sub-agents hold capability tokens; the broker decides every call."""

    def __init__(
        self,
        context: RuntimeContext,
        *,
        token: str,
        broker: BrokerClient,
        approver: ApproverClient,
        root_agent: str = "planner",
    ) -> None:
        super().__init__(context)
        self._token = token
        self._broker = broker
        self._approver = approver
        self._root_name = root_agent
        self.pending: list[PendingApproval] = []
        self.delegations: list[tuple[str, str, list[str]]] = []
        self.agent_tokens: dict[str, str] = {root_agent: token}

    def _root_agent(self) -> _Agent:
        return _Agent(self._root_name, 0, self._token, tools_in_token(self._token, self._manifest))

    def _child_agent(self, parent: _Agent, args: DelegateArgs) -> _Agent:
        if parent.token is None:  # pragma: no cover - capability agents always hold a token
            raise ValueError("capability agents need a token")
        caveats = delegation_caveats(
            now=int(self.context.clock()),
            tools=args.tools,
            resources=args.resources,
            verbs=args.verbs,
            ttl_seconds=args.ttl_seconds,
            max_calls=args.max_calls,
        )
        child_token = attenuate(Macaroon.deserialize(parent.token), caveats).serialize()
        added = [format_caveat(caveat) for caveat in caveats]
        self.agent_tokens[args.agent] = child_token
        self.delegations.append((parent.name, args.agent, added))
        self._audit_append(
            parent.name,
            "agent.attenuate",
            {"task_id": self.task_id, "child": args.agent, "added_caveats": list(added)},
        )
        offered = tuple(tool for tool in args.tools if tool in parent.tools)
        return _Agent(args.agent, parent.depth + 1, child_token, offered)

    def _call_broker(self, token: str, discharges: Sequence[str], call: ToolCall) -> BrokerOutcome:
        carrier: dict[str, str] = {}
        inject(carrier)
        return self._broker.call(
            token=token, discharges=discharges, call=call, trace_carrier=carrier
        )

    def _record(self, agent: str, call: ToolCall, outcome: BrokerOutcome) -> ToolEvent:
        event = ToolEvent(
            agent=agent,
            tool=call.tool,
            resource=call.resource,
            outcome="executed" if outcome.allowed else "denied",
            reason=outcome.reason,
            failed_caveat=outcome.failed_caveat.condition if outcome.failed_caveat else None,
            status=outcome.status,
            call=call,
        )
        self.events.append(event)
        return event

    def _execute(self, agent: _Agent, tool_use_id: str, call: ToolCall) -> ToolResultBlock:
        if agent.token is None:  # pragma: no cover - capability agents always hold a token
            raise ValueError("capability agents need a token")
        outcome = self._call_broker(agent.token, (), call)
        if outcome.allowed:
            self._record(agent.name, call, outcome)
            return ToolResultBlock(
                tool_use_id=tool_use_id,
                content=outcome.output or "",
                is_error=(outcome.status or 500) >= 400,
            )
        if (
            outcome.reason == "approval_required"
            and outcome.approval is not None
            and outcome.canonical_request is not None
        ):
            return self._request_approval(agent, tool_use_id, call, outcome)
        event = self._record(agent.name, call, outcome)
        detail = f"; failing caveat: {event.failed_caveat}" if event.failed_caveat else ""
        return ToolResultBlock(
            tool_use_id=tool_use_id,
            content=f"Call denied by the capability broker ({outcome.reason}){detail}.",
            is_error=True,
        )

    def _request_approval(
        self, agent: _Agent, tool_use_id: str, call: ToolCall, outcome: BrokerOutcome
    ) -> ToolResultBlock:
        if agent.token is None or outcome.approval is None or outcome.canonical_request is None:
            raise ValueError("approval request needs a token, a hint and a canonical request")
        view = self._approver.submit(
            ApprovalSubmission(
                caveat_id=outcome.approval.caveat_id, request=outcome.canonical_request
            )
        )
        self.pending.append(
            PendingApproval(view.id, agent.name, agent.token, call, view.request_hash)
        )
        self.events.append(
            ToolEvent(
                agent.name,
                call.tool,
                call.resource,
                "approval_pending",
                outcome.reason,
                approval_id=view.id,
            )
        )
        self._audit_append(
            agent.name,
            "agent.approval_requested",
            {"task_id": self.task_id, "approval_id": view.id, "request_hash": view.request_hash},
        )
        return ToolResultBlock(
            tool_use_id=tool_use_id,
            content=(
                f"The call to {call.tool} on {call.resource} is waiting for human approval "
                f"(request {view.id}). It has not run."
            ),
            is_error=True,
        )

    def resume(self) -> list[ToolEvent]:
        """Retry calls whose approval was decided; keep the ones still pending."""
        still_pending: list[PendingApproval] = []
        new_events: list[ToolEvent] = []
        for pending in self.pending:
            view = self._approver.fetch(pending.approval_id)
            if view.status == "pending":
                still_pending.append(pending)
                continue
            if view.status != "approved" or view.discharge is None:
                event = ToolEvent(
                    pending.agent,
                    pending.call.tool,
                    pending.call.resource,
                    "rejected",
                    "denied by the human approver",
                    approval_id=pending.approval_id,
                )
                self.events.append(event)
                new_events.append(event)
                continue
            self.execute_with_discharge(pending, view.discharge)
            new_events.append(self.events[-1])
        self.pending = still_pending
        return new_events

    def call_direct(
        self, agent: str, token: str, call: ToolCall, discharges: Sequence[str] = ()
    ) -> BrokerOutcome:
        """Send a call outside the model loop (used to replay attacks by a compromised host)."""
        outcome = self._call_broker(token, discharges, call)
        self._record(agent, call, outcome)
        return outcome

    def execute_with_discharge(self, pending: PendingApproval, discharge: str) -> BrokerOutcome:
        """Bind ``discharge`` to the requesting agent's token and send the approved call."""
        token = Macaroon.deserialize(pending.token)
        bound = token.bind(Macaroon.deserialize(discharge)).serialize()
        outcome = self._call_broker(pending.token, (bound,), pending.call)
        event = self._record(pending.agent, pending.call, outcome)
        event.approval_id = pending.approval_id
        return outcome


class AmbientRuntime(AgentRuntime):
    """Baseline: the host holds every service credential and runs whatever the model calls."""

    def __init__(
        self,
        context: RuntimeContext,
        *,
        credentials: Mapping[str, ServiceCredential],
        http: httpx.Client,
    ) -> None:
        super().__init__(context)
        self._credentials = dict(credentials)
        self._http = http

    def _all_tools(self) -> tuple[str, ...]:
        return tuple(sorted(tool.name for tool in self._manifest.tools))

    def _root_agent(self) -> _Agent:
        return _Agent("planner", 0, None, self._all_tools())

    def _child_agent(self, parent: _Agent, args: DelegateArgs) -> _Agent:
        return _Agent(args.agent, parent.depth + 1, None, self._all_tools())

    def execute_direct(self, agent: str, call: ToolCall) -> ToolEvent:
        """Run a call outside the model loop with the host's ambient credentials."""
        self._execute(_Agent(agent, 0, None, self._all_tools()), "direct", call)
        return self.events[-1]

    def _execute(self, agent: _Agent, tool_use_id: str, call: ToolCall) -> ToolResultBlock:
        entry = self._manifest.get(call.tool)
        path = entry.resolve_path(call.resource) if entry is not None else None
        if entry is None or path is None:
            self.events.append(
                ToolEvent(agent.name, call.tool, call.resource, "rejected", "bad resource")
            )
            return ToolResultBlock(tool_use_id=tool_use_id, content="Bad resource.", is_error=True)
        body = b"" if entry.method in {"GET", "DELETE"} else canonical_json(call.args).encode()
        headers = sign_request(
            self._credentials[entry.service],
            method=entry.method,
            path=path,
            body=body,
            now=int(self.context.clock()),
        )
        try:
            response = self._http.request(
                entry.method, f"http://{entry.host}{path}", content=body, headers=headers
            )
        except httpx.HTTPError:
            self.events.append(
                ToolEvent(agent.name, call.tool, call.resource, "failed", "unreachable")
            )
            return ToolResultBlock(tool_use_id=tool_use_id, content="Call failed.", is_error=True)
        text = response.content[: entry.max_output_bytes].decode("utf-8", errors="replace")
        self.events.append(
            ToolEvent(
                agent.name,
                call.tool,
                call.resource,
                "executed",
                "ok",
                status=response.status_code,
                call=call,
            )
        )
        self._audit_append(
            agent.name,
            "ambient.execute",
            {"tool": call.tool, "resource": call.resource, "output_sha256": sha256_hex(text)},
        )
        return ToolResultBlock(
            tool_use_id=tool_use_id,
            content=wrap_tool_result(entry.name, text).render(),
            is_error=response.status_code >= 400,
        )
