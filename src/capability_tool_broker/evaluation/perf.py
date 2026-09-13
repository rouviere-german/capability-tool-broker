"""Latency of token verification and of broker round trips (CPU only, in-process).

- ``verify_10_caveats``: parse a serialized 10-caveat token and verify it (chain and caveats);
- ``decide_write_with_discharge``: every stateless broker check for a write with a bound approval
  discharge (manifest, canonical request, chain, discharge binding, caveats, authority tag);
- ``broker_call_in_process``: a full allowed read through the broker, including state commit,
  request signing, the fake service and an fsync'ed audit append;
- ``broker_call_no_audit``: the same without the audit log, to separate its cost;
- ``broker_call_http``: the same over the broker's FastAPI app (in-process ASGI transport) with a
  fresh EdDSA client assertion per request.
"""

from __future__ import annotations

import gc
import os
import platform
import sys
import time
from collections.abc import Callable
from pathlib import Path

from fastapi.testclient import TestClient

from capability_tool_broker.approver.service import ApprovalSubmission
from capability_tool_broker.authority.clientauth import (
    ClientAssertionVerifier,
    make_client_assertion,
)
from capability_tool_broker.authority.service import TokenRequest
from capability_tool_broker.broker.app import create_broker_app
from capability_tool_broker.broker.broker import Broker, ToolCall
from capability_tool_broker.broker.manifest import ManifestHolder
from capability_tool_broker.broker.state import MemoryStateStore
from capability_tool_broker.capabilities.request import CanonicalRequest, RequestContext, Verb
from capability_tool_broker.capabilities.verifier import Denial, MacaroonVerifier
from capability_tool_broker.core.config import Settings
from capability_tool_broker.macaroons.macaroon import Macaroon
from capability_tool_broker.stack import ManualClock, Stack, build_stack

__all__ = ["machine", "percentile", "run_perf"]

T0 = 1_800_000_000
CLIENT = "agent-host"
TEN_CAVEATS = (
    "task_id = task-1",
    "client in agent-host",
    "tool in invoices_read,invoices_update_status",
    "verb in read,write",
    "resource matches invoice/42,invoice/43",
    "host in invoices.internal",
    "expires < 2030-01-01T00:00:00Z",
    "max_calls <= 999999999",
    "resource matches invoice/**",
    "tool in invoices_read",
)


def percentile(samples: list[float], fraction: float) -> float:
    """Nearest-rank percentile."""
    ordered = sorted(samples)
    rank = max(1, min(len(ordered), round(fraction * len(ordered) + 0.5)))
    return ordered[rank - 1]


def _timed(function: Callable[[], object], runs: int, warmup: int = 20) -> dict[str, float]:
    for _ in range(warmup):
        function()
    samples: list[float] = []
    gc.disable()
    try:
        for _ in range(runs):
            started = time.perf_counter_ns()
            function()
            samples.append((time.perf_counter_ns() - started) / 1_000.0)
    finally:
        gc.enable()
    return {
        "runs": float(runs),
        "p50_us": round(percentile(samples, 0.50), 1),
        "p99_us": round(percentile(samples, 0.99), 1),
        "mean_us": round(sum(samples) / len(samples), 1),
    }


def machine() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "processor": platform.processor() or "unknown",
    }


def _ten_caveat_token(stack: Stack) -> str:
    identifier = stack.keys.ring.new_identifier()
    resolved = stack.keys.ring.token_key(identifier)
    if resolved is None:  # pragma: no cover
        raise RuntimeError("ring cannot resolve its identifier")
    token = Macaroon.create(root_key=resolved[1], identifier=identifier)
    for condition in TEN_CAVEATS:
        token = token.add_first_party_caveat(condition)
    return token.serialize()


def run_perf(
    workdir: Path,
    *,
    verify_runs: int = 5_000,
    call_runs: int = 1_000,
    http_runs: int = 300,
) -> dict[str, dict[str, float]]:
    stack = build_stack(workdir, clock=ManualClock(T0))
    try:
        token = _ten_caveat_token(stack)
        read = ToolCall(task_id="task-1", tool="invoices_read", resource="invoice/42")
        ctx = RequestContext(
            request=CanonicalRequest(
                task_id="task-1",
                tool="invoices_read",
                verb=Verb.READ,
                host="invoices.internal",
                resource="invoice/42",
            ),
            now=T0,
            client_id=CLIENT,
        )
        verifier = MacaroonVerifier(root_key=stack.keys.ring.token_key)
        verified = not isinstance(verifier.verify(Macaroon.deserialize(token), (), ctx), Denial)
        if not verified:
            raise RuntimeError("benchmark token must verify")
        results: dict[str, dict[str, float]] = {
            "verify_10_caveats": _timed(
                lambda: verifier.verify(Macaroon.deserialize(token), (), ctx), verify_runs
            )
        }

        minted = stack.authority.mint(
            CLIENT,
            TokenRequest(template="invoice-review", task_id="task-1", params={"invoice_id": "42"}),
        )
        write = ToolCall(
            task_id="task-1",
            tool="invoices_update_status",
            resource="invoice/42",
            args={"status": "approved"},
        )
        denial = stack.broker.call(token=minted.token, call=write, client_id=CLIENT)
        if denial.approval is None or denial.canonical_request is None:
            raise RuntimeError("write must need approval")
        record = stack.approver.submit(
            ApprovalSubmission(
                caveat_id=denial.approval.caveat_id, request=denial.canonical_request
            ),
            requested_by=CLIENT,
        )
        discharge = stack.approver.decide(
            record.id, approver="human:reviewer", approve=True
        ).discharge
        if discharge is None:  # pragma: no cover
            raise RuntimeError("approval must mint a discharge")
        bound = Macaroon.deserialize(minted.token).bind(Macaroon.deserialize(discharge)).serialize()
        if not stack.broker.decide(
            token=minted.token, discharges=(bound,), call=write, client_id=CLIENT
        ).allowed:
            raise RuntimeError("bound discharge must authorize the write")
        results["decide_write_with_discharge"] = _timed(
            lambda: stack.broker.decide(
                token=minted.token, discharges=(bound,), call=write, client_id=CLIENT
            ),
            verify_runs // 2,
        )

        def call_audited() -> None:
            if not stack.broker.call(token=token, call=read, client_id=CLIENT).allowed:
                raise RuntimeError("benchmark call must be allowed")

        results["broker_call_in_process"] = _timed(call_audited, call_runs)

        quiet = Broker(
            ring=stack.keys.ring,
            manifest=ManifestHolder.from_manifest(stack.manifest),
            state=MemoryStateStore(),
            credentials=stack.keys.credentials(),
            http=stack.http,
            clock=stack.clock,
        )
        results["broker_call_no_audit"] = _timed(
            lambda: quiet.call(token=token, call=read, client_id=CLIENT), call_runs
        )

        settings = Settings(
            _env_file=None,
            rate_limit_per_second=1e9,
            rate_limit_burst=1_000_000_000,
            environment="test",
        )
        verifier_jwt = ClientAssertionVerifier(
            {CLIENT: stack.keys.client_keys[CLIENT].public_key()},
            audience="broker",
            clock=stack.clock,
        )
        app = create_broker_app(
            quiet, verifier_jwt, ManifestHolder.from_manifest(stack.manifest), settings=settings
        )
        body = {"token": token, "discharges": [], "call": read.model_dump(mode="json")}
        with TestClient(app) as client:

            def http_call() -> None:
                assertion = make_client_assertion(
                    client_id=CLIENT,
                    private_key=stack.keys.client_keys[CLIENT],
                    audience="broker",
                    now=T0,
                )
                response = client.post(
                    "/v1/calls", json=body, headers={"Authorization": f"Bearer {assertion}"}
                )
                if response.status_code != 200:
                    raise RuntimeError(f"HTTP benchmark call failed: {response.status_code}")

            results["broker_call_http"] = _timed(http_call, http_runs)
        return results
    finally:
        stack.close()
