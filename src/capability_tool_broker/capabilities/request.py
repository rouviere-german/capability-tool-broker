"""The canonical broker request: what a capability authorizes and what an approval is bound to.

The agent names a tool, a resource and arguments. The broker fills in ``verb`` and ``host`` from
the signed tool manifest, never from the agent, and hashes the result. That hash is what a human
approves and what an approval discharge carries, so an approval can never be replayed against a
different tool, resource, argument set or task.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from capability_tool_broker.capabilities.glob import validate_resource
from capability_tool_broker.core.canonical import CanonicalJSONError, canonical_json, sha256_hex

__all__ = [
    "ARG_NAME_PATTERN",
    "CLIENT_ID_PATTERN",
    "HOST_PATTERN",
    "MAX_ARGS_BYTES",
    "SIDE_EFFECT_VERBS",
    "TASK_ID_PATTERN",
    "TOOL_PATTERN",
    "CanonicalRequest",
    "RequestContext",
    "Verb",
    "is_valid_host",
]

TASK_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"
CLIENT_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,63}$"
TOOL_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
HOST_PATTERN = r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
ARG_NAME_PATTERN = r"^[a-z_][a-z0-9_]{0,31}$"
MAX_ARGS_BYTES = 8_192
_MAX_ARG_DEPTH = 4
_HOST = re.compile(HOST_PATTERN)
_ARG_NAME = re.compile(ARG_NAME_PATTERN)


class Verb(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"


SIDE_EFFECT_VERBS = frozenset({Verb.WRITE, Verb.DELETE})


def is_valid_host(value: str) -> bool:
    return len(value) <= 253 and _HOST.fullmatch(value) is not None


def _depth(value: JsonValue) -> int:
    if isinstance(value, dict):
        return 1 + max((_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(item) for item in value), default=0)
    return 0


class CanonicalRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str = Field(pattern=TASK_ID_PATTERN)
    tool: str = Field(pattern=TOOL_PATTERN)
    verb: Verb
    host: str = Field(max_length=253)
    resource: str
    args: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("host")
    @classmethod
    def _check_host(cls, value: str) -> str:
        if not is_valid_host(value):
            raise ValueError("invalid host name")
        return value

    @field_validator("resource")
    @classmethod
    def _check_resource(cls, value: str) -> str:
        return validate_resource(value)

    @field_validator("args")
    @classmethod
    def _check_args(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        for name in value:
            if not _ARG_NAME.fullmatch(name):
                raise ValueError("argument names must match ^[a-z_][a-z0-9_]{0,31}$")
        try:
            encoded = canonical_json(value)
        except CanonicalJSONError as exc:
            raise ValueError("arguments must be finite JSON") from exc
        if len(encoded.encode("utf-8")) > MAX_ARGS_BYTES:
            raise ValueError(f"arguments exceed {MAX_ARGS_BYTES} bytes")
        if _depth(value) > _MAX_ARG_DEPTH:
            raise ValueError(f"arguments nest deeper than {_MAX_ARG_DEPTH} levels")
        return value

    def canonical_dict(self) -> dict[str, JsonValue]:
        return {
            "v": 1,
            "task_id": self.task_id,
            "tool": self.tool,
            "verb": self.verb.value,
            "host": self.host,
            "resource": self.resource,
            "args": self.args,
        }

    def request_hash(self) -> str:
        """SHA-256 of the canonical JSON of :meth:`canonical_dict`."""
        return sha256_hex(canonical_json(self.canonical_dict()))


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Everything a caveat may look at: the request, the verifier's clock and the caller."""

    request: CanonicalRequest
    now: int
    client_id: str | None = None
