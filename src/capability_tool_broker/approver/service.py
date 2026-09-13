"""Approval requests and discharge minting.

Submitting: an agent host sends the approval caveat id from its token and the full canonical
request. The approver opens the sealed caveat id with its private key (refusing ids not sealed to
it), checks that the task id in the sealed box equals the request's task, that the caveat has not
expired and that the caveat's scope covers the request, and queues the request for a human.

Deciding: after a human approves the exact request (``capability-tool-broker approver review``),
the approver re-opens the caveat id and mints a discharge macaroon keyed with the caveat key and
carrying ``request_hash = <hash of the reviewed request>``, ``task_id``, ``expires`` (at most two
minutes, never beyond the caveat) and a fresh ``once`` nonce. The broker accepts it only for that
request, only bound to that token family and only once.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field

from capability_tool_broker.agentic.approval import ApprovalRecord, ApprovalStatus, ApprovalStore
from capability_tool_broker.agentic.audit import AuditLog
from capability_tool_broker.capabilities.attenuate import attenuate
from capability_tool_broker.capabilities.caveats import (
    CaveatSyntaxError,
    ExpiresBefore,
    Once,
    RequestHashIs,
    TaskIs,
    evaluate,
    parse_caveat,
)
from capability_tool_broker.capabilities.request import CanonicalRequest, RequestContext
from capability_tool_broker.capabilities.thirdparty import (
    OpenedApprovalCaveat,
    open_approval_caveat,
)
from capability_tool_broker.macaroons.codec import b64u_decode
from capability_tool_broker.macaroons.errors import MacaroonFormatError
from capability_tool_broker.macaroons.macaroon import Macaroon

__all__ = ["ApprovalSubmission", "ApprovalView", "ApproverError", "ApproverService"]

DEFAULT_DISCHARGE_TTL_SECONDS = 120


class ApproverError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ApprovalSubmission(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    caveat_id: str = Field(min_length=1, max_length=8_192)
    request: CanonicalRequest


class ApprovalView(BaseModel):
    """What a requester may see about its approval request."""

    model_config = ConfigDict(frozen=True)

    id: str
    status: str
    request_hash: str
    discharge: str | None = None

    @classmethod
    def from_record(cls, record: ApprovalRecord) -> ApprovalView:
        return cls(
            id=record.id,
            status=record.status.value,
            request_hash=record.request_hash,
            discharge=record.discharge,
        )


class ApproverService:
    def __init__(
        self,
        *,
        private_key: X25519PrivateKey,
        store: ApprovalStore,
        audit: AuditLog | None = None,
        clock: Callable[[], float] = time.time,
        discharge_ttl_seconds: int = DEFAULT_DISCHARGE_TTL_SECONDS,
    ) -> None:
        self._private_key = private_key
        self._store = store
        self._audit = audit
        self._clock = clock
        self._ttl = discharge_ttl_seconds

    def _open(self, caveat_id_text: str) -> tuple[bytes, OpenedApprovalCaveat]:
        try:
            caveat_id = b64u_decode(caveat_id_text)
        except MacaroonFormatError as exc:
            raise ApproverError("invalid_caveat", "caveat id is not base64url") from exc
        opened = open_approval_caveat(caveat_id, self._private_key)
        if opened is None:
            raise ApproverError("invalid_caveat", "caveat id was not issued for this approver")
        return caveat_id, opened

    def submit(self, submission: ApprovalSubmission, *, requested_by: str) -> ApprovalRecord:
        _, opened = self._open(submission.caveat_id)
        request = submission.request
        now = int(self._clock())
        if opened.box.task_id != request.task_id:
            raise ApproverError("task_mismatch", "request belongs to a different task")
        if opened.box.expires_at <= now:
            raise ApproverError("caveat_expired", "the approval caveat has expired")
        try:
            scope = parse_caveat(opened.caveat_id.scope)
        except CaveatSyntaxError as exc:  # pragma: no cover - authority validates scopes
            raise ApproverError("invalid_caveat", "approval scope is invalid") from exc
        if not evaluate(scope, RequestContext(request=request, now=now, client_id=requested_by)):
            raise ApproverError("out_of_scope", "request is outside the approval caveat's scope")
        record = self._store.submit(
            request, caveat_id=submission.caveat_id, requested_by=requested_by
        )
        self._append(
            requested_by,
            "approver.requested",
            record,
        )
        return record

    def pending(self) -> list[ApprovalRecord]:
        return self._store.pending()

    def fetch(self, request_id: str, *, requested_by: str) -> ApprovalRecord:
        return self._store.for_requester(request_id, requested_by)

    def decide(
        self, request_id: str, *, approver: str, approve: bool, reason: str | None = None
    ) -> ApprovalRecord:
        record = self._store.get(request_id)
        discharge: str | None = None
        if approve and record.status is ApprovalStatus.PENDING:
            caveat_id, opened = self._open(record.caveat_id)
            now = int(self._clock())
            if opened.box.expires_at <= now:
                raise ApproverError("caveat_expired", "the approval caveat has expired")
            expires_at = min(now + self._ttl, opened.box.expires_at)
            request = record.canonical_request()
            discharge_macaroon = attenuate(
                Macaroon.create(root_key=opened.caveat_key, identifier=caveat_id),
                [
                    RequestHashIs(record.request_hash),
                    TaskIs(request.task_id),
                    ExpiresBefore(expires_at),
                    Once(secrets.token_hex(16)),
                ],
            )
            discharge = discharge_macaroon.serialize()
        decided = self._store.decide(
            request_id, approver=approver, approve=approve, reason=reason, discharge=discharge
        )
        self._append(approver, "approver.discharge" if approve else "approver.denied", decided)
        return decided

    def _append(self, actor: str, action: str, record: ApprovalRecord) -> None:
        if self._audit is None:
            return
        request = record.canonical_request()
        self._audit.append(
            actor,
            action,
            {
                "approval_id": record.id,
                "request_hash": record.request_hash,
                "task_id": request.task_id,
                "tool": request.tool,
                "verb": request.verb.value,
                "resource": request.resource,
                "requested_by": record.requested_by,
            },
        )
