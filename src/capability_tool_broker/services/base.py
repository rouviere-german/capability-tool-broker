"""Shared machinery for the fake services: signature check, routing and access/effect logs."""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

import httpx
from pydantic import JsonValue

from capability_tool_broker.broker.signing import (
    RequestSignatureVerifier,
    ServiceCredential,
    SignatureCheck,
)
from capability_tool_broker.core.canonical import canonical_json

__all__ = [
    "AccessRecord",
    "Effect",
    "FakeService",
    "Handler",
    "ServiceResponse",
    "ServiceRouter",
]

_MAX_BODY_BYTES = 65_536


@dataclass(frozen=True, slots=True)
class AccessRecord:
    service: str
    method: str
    path: str
    authorized: bool
    status: int


@dataclass(frozen=True, slots=True)
class Effect:
    service: str
    kind: Literal["read", "write", "delete", "send"]
    target: str


@dataclass(frozen=True, slots=True)
class ServiceResponse:
    status: int
    body: JsonValue

    def encode(self) -> bytes:
        return canonical_json(self.body).encode("utf-8")


Handler = Callable[[dict[str, str], JsonValue], ServiceResponse]


class FakeService:
    """Routes signed requests to handlers; unsigned or replayed requests get 401."""

    name: str = "service"
    host: str = "service.internal"

    def __init__(
        self,
        *,
        credential: ServiceCredential,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._verifier = RequestSignatureVerifier(
            {credential.key_id: credential.secret}, clock=clock
        )
        self._routes: list[tuple[str, re.Pattern[str], Handler]] = []
        self._lock = threading.Lock()
        self.access_log: list[AccessRecord] = []
        self.effects: list[Effect] = []

    def route(self, method: str, pattern: str, handler: Handler) -> None:
        self._routes.append((method, re.compile(pattern), handler))

    def record_effect(self, kind: Literal["read", "write", "delete", "send"], target: str) -> None:
        with self._lock:
            self.effects.append(Effect(self.name, kind, target))

    def _log(self, method: str, path: str, authorized: bool, status: int) -> None:
        with self._lock:
            self.access_log.append(AccessRecord(self.name, method, path, authorized, status))

    def handle(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> ServiceResponse:
        lowered = {key.lower(): value for key, value in headers.items()}
        check = self._verifier.verify(method, path, lowered, body)
        if check is not SignatureCheck.OK:
            self._log(method, path, authorized=False, status=401)
            return ServiceResponse(401, {"error": "unauthenticated", "reason": check.value})
        for route_method, pattern, handler in self._routes:
            match = pattern.fullmatch(path)
            if route_method != method or match is None:
                continue
            payload: JsonValue = None
            if body:
                if len(body) > _MAX_BODY_BYTES:
                    self._log(method, path, authorized=True, status=413)
                    return ServiceResponse(413, {"error": "payload_too_large"})
                try:
                    payload = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self._log(method, path, authorized=True, status=400)
                    return ServiceResponse(400, {"error": "invalid_json"})
            response = handler(match.groupdict(), payload)
            self._log(method, path, authorized=True, status=response.status)
            return response
        self._log(method, path, authorized=True, status=404)
        return ServiceResponse(404, {"error": "not_found"})


class ServiceRouter:
    """Dispatch by host; ``transport()`` serves the services to an in-process httpx client."""

    def __init__(self, services: Iterable[FakeService]) -> None:
        self._by_host: dict[str, FakeService] = {}
        for service in services:
            if service.host in self._by_host:
                raise ValueError(f"duplicate service host {service.host}")
            self._by_host[service.host] = service

    @property
    def services(self) -> tuple[FakeService, ...]:
        return tuple(self._by_host.values())

    def get(self, host: str) -> FakeService | None:
        return self._by_host.get(host)

    def effects(self) -> list[Effect]:
        return [effect for service in self.services for effect in service.effects]

    def access_log(self) -> list[AccessRecord]:
        return [record for service in self.services for record in service.access_log]

    def dispatch(
        self, host: str, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> ServiceResponse:
        service = self._by_host.get(host)
        if service is None:
            return ServiceResponse(404, {"error": "unknown_service"})
        return service.handle(method, path, headers, body)

    def handle_httpx(self, request: httpx.Request) -> httpx.Response:
        response = self.dispatch(
            request.url.host, request.method, request.url.path, request.headers, request.read()
        )
        return httpx.Response(
            response.status,
            content=response.encode(),
            headers={"content-type": "application/json"},
        )

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle_httpx)
