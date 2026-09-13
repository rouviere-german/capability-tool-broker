"""How an agent host reaches the authority, the broker and the approver: in-process or over HTTP.

HTTP clients authenticate every request with a fresh client-credential JWT whose audience is the
service being called, so an assertion captured at one service cannot be replayed at another.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import JsonValue

from capability_tool_broker.approver.service import (
    ApprovalSubmission,
    ApprovalView,
    ApproverService,
)
from capability_tool_broker.authority.clientauth import make_client_assertion
from capability_tool_broker.authority.service import Authority, MintedToken, TokenRequest
from capability_tool_broker.broker.broker import Broker, BrokerOutcome, ToolCall
from capability_tool_broker.broker.manifest import SignedManifest

__all__ = [
    "ApproverClient",
    "AuthorityClient",
    "BrokerClient",
    "ClientCredentials",
    "HttpApproverClient",
    "HttpAuthorityClient",
    "HttpBrokerClient",
    "InProcessApproverClient",
    "InProcessAuthorityClient",
    "InProcessBrokerClient",
    "RemoteServiceError",
]


class AuthorityClient(Protocol):
    def mint(self, request: TokenRequest) -> MintedToken: ...


class BrokerClient(Protocol):
    def call(
        self,
        *,
        token: str,
        discharges: Sequence[str],
        call: ToolCall,
        trace_carrier: Mapping[str, str],
    ) -> BrokerOutcome: ...


class ApproverClient(Protocol):
    def submit(self, submission: ApprovalSubmission) -> ApprovalView: ...

    def fetch(self, approval_id: str) -> ApprovalView: ...


# --- in-process ---------------------------------------------------------------------------------


class InProcessAuthorityClient:
    def __init__(self, authority: Authority, client_id: str) -> None:
        self._authority = authority
        self._client_id = client_id

    def mint(self, request: TokenRequest) -> MintedToken:
        return self._authority.mint(self._client_id, request)


class InProcessBrokerClient:
    def __init__(self, broker: Broker, client_id: str) -> None:
        self._broker = broker
        self._client_id = client_id

    def call(
        self,
        *,
        token: str,
        discharges: Sequence[str],
        call: ToolCall,
        trace_carrier: Mapping[str, str],
    ) -> BrokerOutcome:
        return self._broker.call(
            token=token,
            discharges=discharges,
            call=call,
            client_id=self._client_id,
            trace_carrier=trace_carrier,
        )


class InProcessApproverClient:
    def __init__(self, approver: ApproverService, client_id: str) -> None:
        self._approver = approver
        self._client_id = client_id

    def submit(self, submission: ApprovalSubmission) -> ApprovalView:
        return ApprovalView.from_record(
            self._approver.submit(submission, requested_by=self._client_id)
        )

    def fetch(self, approval_id: str) -> ApprovalView:
        return ApprovalView.from_record(
            self._approver.fetch(approval_id, requested_by=self._client_id)
        )


# --- HTTP ---------------------------------------------------------------------------------------


class RemoteServiceError(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"remote service returned HTTP {status} ({code})")
        self.status = status
        self.code = code


class ClientCredentials:
    """A client id and its Ed25519 key; produces per-request assertions."""

    def __init__(
        self,
        client_id: str,
        private_key: Ed25519PrivateKey,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.client_id = client_id
        self._private_key = private_key
        self._clock = clock

    def __repr__(self) -> str:
        return f"ClientCredentials(client_id={self.client_id!r}, private_key=<redacted>)"

    def authorization(self, audience: str) -> dict[str, str]:
        assertion = make_client_assertion(
            client_id=self.client_id,
            private_key=self._private_key,
            audience=audience,
            now=int(self._clock()),
        )
        return {"Authorization": f"Bearer {assertion}"}


def _json_or_error(response: httpx.Response, *, accept: tuple[int, ...] = (200,)) -> JsonValue:
    if response.status_code not in accept:
        code = "error"
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            code = str(body["error"].get("code", "error"))
        raise RemoteServiceError(response.status_code, code)
    payload: JsonValue = response.json()
    return payload


class HttpAuthorityClient:
    def __init__(
        self, http: httpx.Client, credentials: ClientCredentials, *, audience: str = "authority"
    ) -> None:
        self._http = http
        self._credentials = credentials
        self._audience = audience

    def mint(self, request: TokenRequest) -> MintedToken:
        response = self._http.post(
            "/v1/tokens",
            json=request.model_dump(mode="json", exclude_none=True),
            headers=self._credentials.authorization(self._audience),
        )
        return MintedToken.model_validate(_json_or_error(response))


class HttpBrokerClient:
    def __init__(
        self, http: httpx.Client, credentials: ClientCredentials, *, audience: str = "broker"
    ) -> None:
        self._http = http
        self._credentials = credentials
        self._audience = audience

    def call(
        self,
        *,
        token: str,
        discharges: Sequence[str],
        call: ToolCall,
        trace_carrier: Mapping[str, str],
    ) -> BrokerOutcome:
        headers = {**dict(trace_carrier), **self._credentials.authorization(self._audience)}
        response = self._http.post(
            "/v1/calls",
            json={
                "token": token,
                "discharges": list(discharges),
                "call": call.model_dump(mode="json"),
            },
            headers=headers,
        )
        return BrokerOutcome.model_validate(_json_or_error(response, accept=(200, 403)))

    def manifest(self) -> SignedManifest:
        response = self._http.get(
            "/v1/manifest", headers=self._credentials.authorization(self._audience)
        )
        return SignedManifest.model_validate(_json_or_error(response))


class HttpApproverClient:
    def __init__(
        self, http: httpx.Client, credentials: ClientCredentials, *, audience: str = "approver"
    ) -> None:
        self._http = http
        self._credentials = credentials
        self._audience = audience

    def submit(self, submission: ApprovalSubmission) -> ApprovalView:
        response = self._http.post(
            "/v1/approvals",
            json=submission.model_dump(mode="json"),
            headers=self._credentials.authorization(self._audience),
        )
        return ApprovalView.model_validate(_json_or_error(response, accept=(200, 201)))

    def fetch(self, approval_id: str) -> ApprovalView:
        response = self._http.get(
            f"/v1/approvals/{approval_id}",
            headers=self._credentials.authorization(self._audience),
        )
        return ApprovalView.model_validate(_json_or_error(response))
