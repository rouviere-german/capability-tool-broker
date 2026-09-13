"""Authority HTTP API: ``POST /v1/tokens`` for authenticated clients."""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import Depends, FastAPI
from opentelemetry.sdk.trace import TracerProvider
from prometheus_client import CollectorRegistry

from capability_tool_broker.authority.clientauth import (
    ClientAssertionVerifier,
    bearer_client_dependency,
)
from capability_tool_broker.authority.service import (
    Authority,
    AuthorityError,
    MintedToken,
    TokenRequest,
)
from capability_tool_broker.core.app import ReadinessCheck, create_app
from capability_tool_broker.core.config import Settings
from capability_tool_broker.core.errors import AppError

__all__ = ["create_authority_app"]


def create_authority_app(
    authority: Authority,
    verifier: ClientAssertionVerifier,
    *,
    settings: Settings,
    readiness_checks: Mapping[str, ReadinessCheck] | None = None,
    registry: CollectorRegistry | None = None,
    tracer_provider: TracerProvider | None = None,
) -> FastAPI:
    app = create_app(
        settings,
        readiness_checks=readiness_checks or {"root_key": lambda: True},
        registry=registry,
        tracer_provider=tracer_provider,
    )
    client = bearer_client_dependency(verifier)

    @app.post("/v1/tokens", response_model=MintedToken)
    def mint(body: TokenRequest, client_id: str = Depends(client)) -> MintedToken:
        try:
            return authority.mint(client_id, body)
        except AuthorityError as exc:
            status = 403 if exc.code == "forbidden" else 422
            raise AppError(status, exc.code, "Token request refused.") from exc

    return app
