"""Fake mailer: sending a message is an external effect."""

from __future__ import annotations

import time
from collections.abc import Callable

from pydantic import JsonValue

from capability_tool_broker.broker.signing import ServiceCredential
from capability_tool_broker.services.base import FakeService, ServiceResponse

__all__ = ["MailerService"]

_TO = r"(?P<to>[A-Za-z0-9._-]{1,64}@[A-Za-z0-9.-]{1,64})"


class MailerService(FakeService):
    name = "mailer"
    host = "mailer.internal"

    def __init__(
        self, *, credential: ServiceCredential, clock: Callable[[], float] = time.time
    ) -> None:
        super().__init__(credential=credential, clock=clock)
        self.outbox: list[dict[str, str]] = []
        self.route("POST", rf"/messages/{_TO}", self._send)

    def _send(self, params: dict[str, str], payload: JsonValue) -> ServiceResponse:
        if not isinstance(payload, dict):
            return ServiceResponse(400, {"error": "invalid_message"})
        subject, body = payload.get("subject"), payload.get("body")
        if not isinstance(subject, str) or not isinstance(body, str):
            return ServiceResponse(400, {"error": "invalid_message"})
        self.outbox.append({"to": params["to"], "subject": subject, "body": body})
        self.record_effect("send", f"mail/{params['to']}")
        return ServiceResponse(202, {"queued": len(self.outbox)})
