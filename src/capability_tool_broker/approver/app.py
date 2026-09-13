"""Approver HTTP API: clients submit approval requests and poll for the outcome.

Decisions are deliberately not exposed over HTTP: a human decides with the review CLI inside the
approver's own environment, which is the only place the approval caveat key exists.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, FastAPI, Path
from fastapi.responses import JSONResponse
from opentelemetry.sdk.trace import TracerProvider

from capability_tool_broker.agentic.errors import ApprovalError
from capability_tool_broker.approver.service import (
    ApprovalSubmission,
    ApprovalView,
    ApproverError,
    ApproverService,
)
from capability_tool_broker.authority.clientauth import (
    ClientAssertionVerifier,
    bearer_client_dependency,
    bearer_subject,
)
from capability_tool_broker.core.app import create_app
from capability_tool_broker.core.config import Settings
from capability_tool_broker.core.errors import AppError

__all__ = ["create_approver_app"]


def create_approver_app(
    service: ApproverService,
    verifier: ClientAssertionVerifier,
    *,
    settings: Settings,
    tracer_provider: TracerProvider | None = None,
) -> FastAPI:
    app = create_app(
        settings,
        readiness_checks={"approver_key": lambda: True},
        tracer_provider=tracer_provider,
        rate_limit_subject=bearer_subject(verifier),
    )
    client = bearer_client_dependency(verifier)

    @app.post("/v1/approvals", status_code=201)
    def submit(body: ApprovalSubmission, client_id: str = Depends(client)) -> JSONResponse:
        try:
            record = service.submit(body, requested_by=client_id)
        except (ApproverError, ApprovalError) as exc:
            code = exc.code if isinstance(exc, ApproverError) else "invalid_request"
            raise AppError(403, code, "Approval request refused.") from exc
        return JSONResponse(
            ApprovalView.from_record(record).model_dump(mode="json"), status_code=201
        )

    @app.get("/v1/approvals/{approval_id}", response_model=ApprovalView)
    def fetch(
        approval_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
        client_id: str = Depends(client),
    ) -> ApprovalView:
        try:
            return ApprovalView.from_record(service.fetch(approval_id, requested_by=client_id))
        except ApprovalError as exc:
            raise AppError(404, "not_found", "Unknown approval request.") from exc

    return app
