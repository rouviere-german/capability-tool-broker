"""Broker HTTP API: ``POST /v1/calls`` and ``GET /v1/manifest`` for authenticated clients.

A decision is a successful exchange, so allowed calls return 200 and denials 403, both with the
full :class:`~capability_tool_broker.broker.broker.BrokerOutcome` body (reason and failing caveat).
The W3C ``traceparent`` header is passed to the broker, whose span joins the caller's trace.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from opentelemetry.sdk.trace import TracerProvider
from pydantic import BaseModel, ConfigDict, Field, field_validator

from capability_tool_broker.authority.clientauth import (
    ClientAssertionVerifier,
    bearer_client_dependency,
    bearer_subject,
)
from capability_tool_broker.broker.broker import Broker, ToolCall
from capability_tool_broker.broker.manifest import ManifestHolder
from capability_tool_broker.core.app import create_app
from capability_tool_broker.core.config import Settings
from capability_tool_broker.core.errors import AppError

__all__ = ["CallBody", "create_broker_app"]

_MAX_TOKEN_CHARS = 24_000
_TRACE_HEADERS = ("traceparent", "tracestate")


class CallBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=_MAX_TOKEN_CHARS)
    discharges: list[str] = Field(default_factory=list, max_length=8)
    call: ToolCall

    @field_validator("discharges")
    @classmethod
    def _check_discharges(cls, value: list[str]) -> list[str]:
        if any(not item or len(item) > _MAX_TOKEN_CHARS for item in value):
            raise ValueError("discharge size out of range")
        return value


def create_broker_app(
    broker: Broker,
    verifier: ClientAssertionVerifier,
    manifest: ManifestHolder,
    *,
    settings: Settings,
    tracer_provider: TracerProvider | None = None,
) -> FastAPI:
    app = create_app(
        settings,
        readiness_checks={
            "root_key": lambda: broker.ready()["root_key"],
            "state_store": lambda: broker.ready()["state_store"],
            "manifest_signature": manifest.ready,
        },
        registry=broker.metrics.registry,
        tracer_provider=tracer_provider,
        rate_limit_subject=bearer_subject(verifier),
    )
    client = bearer_client_dependency(verifier)

    @app.post("/v1/calls")
    def call(body: CallBody, request: Request, client_id: str = Depends(client)) -> JSONResponse:
        carrier = {
            name: request.headers[name] for name in _TRACE_HEADERS if name in request.headers
        }
        outcome = broker.call(
            token=body.token,
            discharges=body.discharges,
            call=body.call,
            client_id=client_id,
            trace_carrier=carrier,
        )
        return JSONResponse(
            outcome.model_dump(mode="json"), status_code=200 if outcome.allowed else 403
        )

    @app.get("/v1/manifest")
    def manifest_document(client_id: str = Depends(client)) -> JSONResponse:
        del client_id
        current = manifest.current()
        if current is None:
            raise AppError(503, "manifest_unavailable", "No verified tool manifest is loaded.")
        return JSONResponse(current.signed().model_dump(mode="json"))

    return app
