"""The broker pipeline: the only place a capability turns into an effect.

For each call, in order:

1. Resolve the tool in the verified manifest; build the canonical request with the manifest's verb
   and host; validate arguments and map the resource onto the upstream route.
2. Verify the token's HMAC chain and discharges (constant-time compares, key id rotation).
3. Evaluate every caveat against the request; report the first failing one.
4. Check the manifest's required caveat types and, for write and delete verbs, require approval
   evidence: a discharge of an authority-tagged approval caveat that carries ``request_hash`` for
   this exact request and a ``once`` nonce.
5. Check the revocation denylist, then atomically commit ``max_calls`` counters and ``once`` nonces.
6. Inject the service credential, sign the upstream request, call the service, cap the output and
   wrap it as untrusted data.

Steps 4 and 5 run after every stateless check, so a denied call never consumes quota or burns an
approval. Every decision is counted, timed, traced and written to the hash-chained audit log.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

import httpx
from opentelemetry import trace
from opentelemetry.propagate import extract
from opentelemetry.trace import SpanKind, Tracer
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from capability_tool_broker.agentic.audit import AuditLog
from capability_tool_broker.agentic.envelope import wrap_tool_result
from capability_tool_broker.broker.manifest import ManifestHolder, ToolEntry
from capability_tool_broker.broker.observability import BrokerMetrics, create_broker_metrics
from capability_tool_broker.broker.signing import ServiceCredential, sign_request
from capability_tool_broker.broker.state import StateStore, StateUnavailableError
from capability_tool_broker.capabilities.caveats import Once, RequestHashIs
from capability_tool_broker.capabilities.keys import RootKeyRing, parse_identifier
from capability_tool_broker.capabilities.request import (
    SIDE_EFFECT_VERBS,
    TASK_ID_PATTERN,
    TOOL_PATTERN,
    CanonicalRequest,
    RequestContext,
)
from capability_tool_broker.capabilities.thirdparty import ApprovalCaveatId, approval_tag_valid
from capability_tool_broker.capabilities.verifier import (
    Authorization,
    Denial,
    DenyReason,
    MacaroonVerifier,
)
from capability_tool_broker.core.canonical import canonical_json, sha256_hex
from capability_tool_broker.core.logging import get_logger
from capability_tool_broker.macaroons.codec import b64u_encode
from capability_tool_broker.macaroons.errors import MacaroonFormatError
from capability_tool_broker.macaroons.macaroon import Macaroon

__all__ = ["ApprovalHint", "Broker", "BrokerOutcome", "Decision", "FailedCaveatView", "ToolCall"]

_log = get_logger("capability_tool_broker.broker")
_MAX_TOKEN_TEXT = 24_000
_MAX_DISCHARGES = 8


class ToolCall(BaseModel):
    """What an agent asks for. Verb and host are not part of it: the manifest decides those."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str = Field(pattern=TASK_ID_PATTERN)
    tool: str = Field(pattern=TOOL_PATTERN)
    resource: str = Field(min_length=1, max_length=256)
    args: dict[str, JsonValue] = Field(default_factory=dict)


class FailedCaveatView(BaseModel):
    model_config = ConfigDict(frozen=True)

    condition: str
    caveat_type: str
    source: str


class ApprovalHint(BaseModel):
    """Where to obtain the discharge a call needs; everything here is already in the token."""

    model_config = ConfigDict(frozen=True)

    caveat_id: str
    location: str
    scope: str


class BrokerOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    allowed: bool
    reason: str
    detail: str = ""
    failed_caveat: FailedCaveatView | None = None
    request_hash: str | None = None
    canonical_request: CanonicalRequest | None = None
    approval: ApprovalHint | None = None
    status: int | None = None
    output: str | None = None
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of the stateless checks for one call (see :meth:`Broker.decide`)."""

    result: Authorization | Denial
    now: int
    entry: ToolEntry | None = None
    request: CanonicalRequest | None = None
    path: str | None = None
    token_id: str | None = None

    @property
    def allowed(self) -> bool:
        return isinstance(self.result, Authorization)


def _approval_hint(caveat_id: bytes) -> ApprovalHint | None:
    parsed = ApprovalCaveatId.decode(caveat_id)
    if parsed is None:
        return None
    return ApprovalHint(
        caveat_id=b64u_encode(caveat_id), location=parsed.location, scope=parsed.scope
    )


class Broker:
    def __init__(
        self,
        *,
        ring: RootKeyRing,
        manifest: ManifestHolder,
        state: StateStore,
        credentials: Mapping[str, ServiceCredential],
        http: httpx.Client,
        audit: AuditLog | None = None,
        metrics: BrokerMetrics | None = None,
        tracer: Tracer | None = None,
        clock: Callable[[], float] = time.time,
        service_base_url: str | None = None,
    ) -> None:
        self._ring = ring
        self._manifest = manifest
        self._state = state
        self._credentials = dict(credentials)
        self._http = http
        self._audit = audit
        self.metrics = metrics or create_broker_metrics()
        self._tracer = tracer or trace.get_tracer("capability_tool_broker.broker")
        self._clock = clock
        self._base_url = service_base_url.rstrip("/") if service_base_url else None
        self._verifier = MacaroonVerifier(root_key=ring.token_key)

    @property
    def ring(self) -> RootKeyRing:
        return self._ring

    def ready(self) -> dict[str, bool]:
        return {
            "root_key": bool(self._ring.kids),
            "state_store": self._state.ping(),
            "manifest_signature": self._manifest.ready(),
        }

    def revoke(self, token: str) -> bool:
        """Deny every future call with ``token`` and all of its attenuations."""
        try:
            macaroon = Macaroon.deserialize(token)
        except MacaroonFormatError:
            return False
        parsed = parse_identifier(macaroon.identifier)
        if parsed is None:
            return False
        now = int(self._clock())
        self._state.revoke(parsed[1], until=None, now=now)
        self._audit_append("broker", "token.revoked", {"token_id": parsed[1]})
        return True

    # --- the pipeline ---------------------------------------------------------------------------

    def call(
        self,
        *,
        token: str,
        discharges: Sequence[str] = (),
        call: ToolCall,
        client_id: str | None,
        trace_carrier: Mapping[str, str] | None = None,
    ) -> BrokerOutcome:
        started = time.perf_counter()
        parent = extract(dict(trace_carrier)) if trace_carrier else None
        with self._tracer.start_as_current_span(
            "broker.call", context=parent, kind=SpanKind.SERVER
        ) as span:
            span.set_attribute("ctb.tool", call.tool)
            span.set_attribute("ctb.task_id", call.task_id)
            outcome = self._run(token, discharges, call, client_id)
            span.set_attribute("ctb.allowed", outcome.allowed)
            span.set_attribute("ctb.reason", outcome.reason)
        result = "allow" if outcome.allowed else "deny"
        self.metrics.call_latency_seconds.labels(result).observe(time.perf_counter() - started)
        return outcome

    def _deny(
        self,
        denial: Denial,
        *,
        call: ToolCall,
        client_id: str | None,
        request: CanonicalRequest | None = None,
        token_id: str | None = None,
    ) -> BrokerOutcome:
        hint = _approval_hint(denial.undischarged.caveat_id) if denial.undischarged else None
        reason = denial.reason
        if reason is DenyReason.UNDISCHARGED and hint is not None:
            reason = DenyReason.APPROVAL_REQUIRED
        failed = denial.failed_caveat
        self.metrics.decisions_total.labels("deny", denial.caveat_type).inc()
        request_hash = request.request_hash() if request is not None else None
        self._audit_append(
            client_id or "anonymous",
            "broker.deny",
            {
                "tool": call.tool,
                "task_id": call.task_id,
                "reason": reason.value,
                "failed_caveat": failed.condition if failed else None,
                "caveat_type": denial.caveat_type,
                "request_hash": request_hash,
                "token_id": token_id,
            },
        )
        _log.info("capability_denied", tool=call.tool, reason=reason.value)
        return BrokerOutcome(
            allowed=False,
            reason=reason.value,
            detail=denial.detail,
            failed_caveat=(
                FailedCaveatView(
                    condition=failed.condition, caveat_type=failed.caveat_type, source=failed.source
                )
                if failed
                else None
            ),
            request_hash=request_hash,
            canonical_request=request,
            approval=hint,
        )

    def decide(
        self,
        *,
        token: str,
        discharges: Sequence[str],
        call: ToolCall,
        client_id: str | None,
    ) -> Decision:
        """Steps 1 to 4: every stateless check. Nothing is committed, executed or audited."""
        now = int(self._clock())
        manifest = self._manifest.current()
        if manifest is None:
            return Decision(Denial(DenyReason.MANIFEST_UNAVAILABLE, "no verified manifest"), now)
        entry = manifest.get(call.tool)
        if entry is None:
            return Decision(Denial(DenyReason.UNKNOWN_TOOL, "tool is not in the manifest"), now)
        request, path, problem = self._canonical(entry, call)
        if request is None or path is None:
            return Decision(Denial(DenyReason.INVALID_REQUEST, problem), now)
        if len(token) > _MAX_TOKEN_TEXT or len(discharges) > _MAX_DISCHARGES:
            denial = Denial(DenyReason.MALFORMED, "token or discharge list too large")
            return Decision(denial, now, entry=entry, request=request)
        try:
            root = Macaroon.deserialize(token)
            bound = [Macaroon.deserialize(item) for item in discharges]
        except MacaroonFormatError as exc:
            return Decision(
                Denial(DenyReason.MALFORMED, str(exc)), now, entry=entry, request=request
            )
        parsed_id = parse_identifier(root.identifier)
        token_id = parsed_id[1] if parsed_id else None
        ctx = RequestContext(request=request, now=now, client_id=client_id)
        verify_started = time.perf_counter()
        result: Authorization | Denial = self._verifier.verify(root, bound, ctx)
        self.metrics.verify_latency_seconds.observe(time.perf_counter() - verify_started)
        if isinstance(result, Authorization):
            result = self._policy_denial(entry, request, root, result) or result
        return Decision(result, now, entry=entry, request=request, path=path, token_id=token_id)

    def _run(
        self, token: str, discharges: Sequence[str], call: ToolCall, client_id: str | None
    ) -> BrokerOutcome:
        decision = self.decide(token=token, discharges=discharges, call=call, client_id=client_id)
        result = decision.result
        if isinstance(result, Denial):
            return self._deny(
                result,
                call=call,
                client_id=client_id,
                request=decision.request,
                token_id=decision.token_id,
            )
        if decision.entry is None or decision.request is None or decision.path is None:
            raise RuntimeError(
                "authorized decisions carry the resolved request"
            )  # pragma: no cover
        stateful = self._commit_state(result, decision.token_id, decision.now)
        if stateful is not None:
            return self._deny(
                stateful,
                call=call,
                client_id=client_id,
                request=decision.request,
                token_id=decision.token_id,
            )
        return self._execute(
            decision.entry,
            decision.request,
            decision.path,
            client_id=client_id,
            token_id=decision.token_id,
            now=decision.now,
        )

    def _canonical(
        self, entry: ToolEntry, call: ToolCall
    ) -> tuple[CanonicalRequest | None, str | None, str]:
        invalid = entry.invalid_args(call.args)
        if invalid:
            return None, None, f"invalid or missing arguments: {', '.join(invalid)}"
        path = entry.resolve_path(call.resource)
        if path is None:
            return None, None, f"resource does not fit {entry.resource_template}"
        try:
            request = CanonicalRequest(
                task_id=call.task_id,
                tool=entry.name,
                verb=entry.verb,
                host=entry.host,
                resource=call.resource,
                args=call.args,
            )
        except ValidationError:
            return None, None, "request is not canonical"
        return request, path, ""

    def _policy_denial(
        self,
        entry: ToolEntry,
        request: CanonicalRequest,
        root: Macaroon,
        authorization: Authorization,
    ) -> Denial | None:
        missing = sorted({c.value for c in entry.required_caveats} - authorization.caveat_types)
        if missing:
            return Denial(
                DenyReason.REQUIRED_CAVEAT_MISSING,
                f"token lacks caveat types required by the manifest: {', '.join(missing)}",
            )
        if request.verb not in SIDE_EFFECT_VERBS:
            return None
        digest = RequestHashIs(request.request_hash())
        for discharge in authorization.discharges:
            if (
                digest in discharge.predicates
                and any(isinstance(p, Once) for p in discharge.predicates)
                and approval_tag_valid(
                    self._ring, discharge.caveat_id, discharge.derived_caveat_key
                )
            ):
                return None
        approval_caveat = next(
            (
                caveat
                for caveat in root.caveats
                if caveat.verification_id is not None
                and ApprovalCaveatId.decode(caveat.caveat_id) is not None
            ),
            None,
        )
        return Denial(
            DenyReason.APPROVAL_REQUIRED,
            "write and delete calls need an approval discharge bound to this exact request",
            undischarged=approval_caveat,
        )

    def _commit_state(
        self, authorization: Authorization, token_id: str | None, now: int
    ) -> Denial | None:
        try:
            if token_id is not None and self._state.is_revoked(token_id, now=now):
                return Denial(DenyReason.REVOKED, "token has been revoked")
            result = self._state.commit(authorization.claims, now=now)
        except StateUnavailableError:
            return Denial(DenyReason.STATE_UNAVAILABLE, "state store unavailable")
        if result.ok:
            return None
        if result.reason == "exhausted":
            return Denial(DenyReason.EXHAUSTED, "max_calls limit reached")
        if result.reason == "replayed":
            return Denial(DenyReason.REPLAYED, "single-use caveat already used")
        return Denial(DenyReason.STATE_UNAVAILABLE, "state store contention")

    def _execute(
        self,
        entry: ToolEntry,
        request: CanonicalRequest,
        path: str,
        *,
        client_id: str | None,
        token_id: str | None,
        now: int,
    ) -> BrokerOutcome:
        request_hash = request.request_hash()
        credential = self._credentials.get(entry.service)
        if credential is None:
            return self._upstream_failure(request, client_id, "no credential for service")
        body = b"" if entry.method in {"GET", "DELETE"} else canonical_json(request.args).encode()
        headers = sign_request(credential, method=entry.method, path=path, body=body, now=now)
        headers["content-type"] = "application/json"
        url = (
            f"{self._base_url}/{entry.host}{path}"
            if self._base_url
            else f"http://{entry.host}{path}"
        )
        try:
            with self._http.stream(
                entry.method, url, content=body, headers=headers, timeout=10.0
            ) as response:
                captured = bytearray()
                truncated = False
                for chunk in response.iter_bytes():
                    captured.extend(chunk)
                    if len(captured) > entry.max_output_bytes:
                        truncated = True
                        del captured[entry.max_output_bytes :]
                        break
                status = response.status_code
        except httpx.HTTPError:
            return self._upstream_failure(request, client_id, "upstream service unreachable")
        text = captured.decode("utf-8", errors="replace")
        envelope = wrap_tool_result(entry.name, text).render()
        self.metrics.decisions_total.labels("allow", "none").inc()
        self._audit_append(
            client_id or "anonymous",
            "broker.execute",
            {
                "tool": entry.name,
                "task_id": request.task_id,
                "resource": request.resource,
                "request_hash": request_hash,
                "status": status,
                "output_sha256": sha256_hex(bytes(captured)),
                "truncated": truncated,
                "token_id": token_id,
            },
        )
        return BrokerOutcome(
            allowed=True,
            reason="ok",
            request_hash=request_hash,
            canonical_request=request,
            status=status,
            output=envelope,
            truncated=truncated,
        )

    def _upstream_failure(
        self, request: CanonicalRequest, client_id: str | None, detail: str
    ) -> BrokerOutcome:
        self.metrics.decisions_total.labels("error", "none").inc()
        self._audit_append(
            client_id or "anonymous",
            "broker.upstream_error",
            {"tool": request.tool, "request_hash": request.request_hash(), "detail": detail},
        )
        return BrokerOutcome(
            allowed=False,
            reason=DenyReason.UPSTREAM_ERROR.value,
            detail=detail,
            request_hash=request.request_hash(),
            canonical_request=request,
        )

    def _audit_append(self, actor: str, action: str, data: dict[str, JsonValue]) -> None:
        if self._audit is not None:
            self._audit.append(actor, action, data)
