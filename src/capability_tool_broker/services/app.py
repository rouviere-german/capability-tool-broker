"""HTTP front for the fake services: ``/{host}/{path}`` dispatches to the service for ``host``."""

from __future__ import annotations

from fastapi import FastAPI, Request, Response
from opentelemetry.sdk.trace import TracerProvider

from capability_tool_broker.core.app import create_app
from capability_tool_broker.core.config import Settings
from capability_tool_broker.services.base import ServiceRouter

__all__ = ["create_services_app"]


def create_services_app(
    router: ServiceRouter, *, settings: Settings, tracer_provider: TracerProvider | None = None
) -> FastAPI:
    app = create_app(
        settings,
        readiness_checks={"services": lambda: bool(router.services)},
        tracer_provider=tracer_provider,
    )

    @app.api_route("/{host}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def dispatch(host: str, path: str, request: Request) -> Response:
        body = await request.body()
        result = router.dispatch(host, request.method, f"/{path}", request.headers, body)
        return Response(
            content=result.encode(), status_code=result.status, media_type="application/json"
        )

    return app
