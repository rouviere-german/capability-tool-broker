"""Fake file store: read, write and delete small text files."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping

from pydantic import JsonValue

from capability_tool_broker.broker.signing import ServiceCredential
from capability_tool_broker.services.base import FakeService, ServiceResponse

__all__ = ["FileStoreService"]

_NAME = r"(?P<name>[A-Za-z0-9._@-]{1,64})"
_MAX_CONTENT = 4096


class FileStoreService(FakeService):
    name = "files"
    host = "files.internal"

    def __init__(
        self,
        *,
        credential: ServiceCredential,
        clock: Callable[[], float] = time.time,
        files: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(credential=credential, clock=clock)
        self.files: dict[str, str] = dict(
            files
            if files is not None
            else {"handbook.txt": "Expense policy: approvals over 500 EUR."}
        )
        self.route("GET", rf"/files/{_NAME}", self._read)
        self.route("PUT", rf"/files/{_NAME}", self._write)
        self.route("DELETE", rf"/files/{_NAME}", self._delete)

    def _read(self, params: dict[str, str], payload: JsonValue) -> ServiceResponse:
        del payload
        content = self.files.get(params["name"])
        if content is None:
            return ServiceResponse(404, {"error": "not_found"})
        self.record_effect("read", f"file/{params['name']}")
        return ServiceResponse(200, {"name": params["name"], "content": content})

    def _write(self, params: dict[str, str], payload: JsonValue) -> ServiceResponse:
        content = payload.get("content") if isinstance(payload, dict) else None
        if not isinstance(content, str) or len(content) > _MAX_CONTENT:
            return ServiceResponse(400, {"error": "invalid_content"})
        self.files[params["name"]] = content
        self.record_effect("write", f"file/{params['name']}")
        return ServiceResponse(200, {"name": params["name"], "bytes": len(content.encode())})

    def _delete(self, params: dict[str, str], payload: JsonValue) -> ServiceResponse:
        del payload
        if self.files.pop(params["name"], None) is None:
            return ServiceResponse(404, {"error": "not_found"})
        self.record_effect("delete", f"file/{params['name']}")
        return ServiceResponse(200, {"deleted": params["name"]})
