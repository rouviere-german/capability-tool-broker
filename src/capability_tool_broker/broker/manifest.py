"""Ed25519-signed tool manifests: what each tool does, where it goes and what a token must carry.

A manifest entry declares a tool's effect class (``read``, ``write``, ``delete``, ``external``),
its upstream host and route, the service credential it uses, its argument schema and the caveat
types every token presented for it must carry. The broker takes a request's verb and host from the
manifest, never from the agent, and maps the resource onto the upstream path through the entry's
templates, so an agent cannot reach routes the manifest does not name.

The signature covers ``b"ctb-manifest-v1\\n" || canonical_json(body)``. The broker accepts a
manifest only if it verifies under a pinned Ed25519 key; otherwise every call is denied and
``/readyz`` reports not ready.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

from capability_tool_broker.capabilities.caveats import CaveatType
from capability_tool_broker.capabilities.request import (
    ARG_NAME_PATTERN,
    TOOL_PATTERN,
    Verb,
    is_valid_host,
)
from capability_tool_broker.core.canonical import canonical_json, sha256_hex
from capability_tool_broker.macaroons.codec import b64u_decode, b64u_encode
from capability_tool_broker.macaroons.errors import MacaroonFormatError

__all__ = [
    "ArgSpec",
    "ManifestBody",
    "ManifestError",
    "ManifestHolder",
    "SignedManifest",
    "ToolEntry",
    "ToolManifest",
    "sign_manifest",
]

Effect = Literal["read", "write", "delete", "external"]
_EFFECT_VERBS: Mapping[str, Verb] = {
    "read": Verb.READ,
    "write": Verb.WRITE,
    "external": Verb.WRITE,
    "delete": Verb.DELETE,
}
_EFFECT_METHODS: Mapping[str, frozenset[str]] = {
    "read": frozenset({"GET"}),
    "write": frozenset({"PUT", "POST"}),
    "external": frozenset({"POST"}),
    "delete": frozenset({"DELETE"}),
}
_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]{0,31})\}")
_LITERAL_SEGMENT = re.compile(r"[A-Za-z0-9._@-]{1,64}")
_SIGNING_PREFIX = b"ctb-manifest-v1\n"


class ManifestError(Exception):
    """The manifest is missing, malformed, unsigned or signed by an untrusted key."""


class ArgSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    type: Literal["string", "integer", "number", "boolean"]
    required: bool = True
    max_length: int | None = Field(default=None, ge=1, le=4096)
    enum: tuple[str, ...] | None = None
    minimum: float | None = None
    maximum: float | None = None

    def accepts(self, value: JsonValue) -> bool:  # noqa: PLR0911 - one branch per type
        if self.type == "boolean":
            return isinstance(value, bool)
        if self.type == "string":
            if not isinstance(value, str):
                return False
            if self.max_length is not None and len(value) > self.max_length:
                return False
            return self.enum is None or value in self.enum
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        if self.type == "integer" and not isinstance(value, int):
            return False
        if isinstance(value, float) and not math.isfinite(value):
            return False
        if self.minimum is not None and value < self.minimum:
            return False
        return self.maximum is None or value <= self.maximum

    def json_schema(self) -> dict[str, JsonValue]:
        schema: dict[str, JsonValue] = {"type": self.type}
        if self.max_length is not None:
            schema["maxLength"] = self.max_length
        if self.enum is not None:
            schema["enum"] = list(self.enum)
        if self.minimum is not None:
            schema["minimum"] = self.minimum
        if self.maximum is not None:
            schema["maximum"] = self.maximum
        return schema


def _template_segments(template: str) -> list[str]:
    return template.split("/")


class ToolEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=TOOL_PATTERN)
    description: str = Field(min_length=1, max_length=512)
    service: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    host: str
    effect: Effect
    method: Literal["GET", "POST", "PUT", "DELETE"]
    resource_template: str = Field(max_length=256)
    path_template: str = Field(max_length=256)
    args: dict[str, ArgSpec] = Field(default_factory=dict)
    required_caveats: tuple[CaveatType, ...] = (CaveatType.TASK_ID, CaveatType.EXPIRES)
    max_output_bytes: int = Field(default=4096, ge=64, le=65_536)

    @model_validator(mode="after")
    def _check(self) -> ToolEntry:  # noqa: PLR0912 - one check per manifest rule
        if not is_valid_host(self.host):
            raise ValueError("invalid host")
        if self.method not in _EFFECT_METHODS[self.effect]:
            raise ValueError(f"method {self.method} does not fit effect {self.effect}")
        for name in self.args:
            if not re.fullmatch(ARG_NAME_PATTERN, name):
                raise ValueError("invalid argument name")
        resource_names: list[str] = []
        for segment in _template_segments(self.resource_template):
            match = _PLACEHOLDER.fullmatch(segment)
            if match is not None:
                resource_names.append(match.group(1))
            elif not _LITERAL_SEGMENT.fullmatch(segment) or segment in {".", ".."}:
                raise ValueError("invalid resource template segment")
        if len(set(resource_names)) != len(resource_names):
            raise ValueError("duplicate placeholder in resource template")
        if not self.path_template.startswith("/"):
            raise ValueError("path template must start with '/'")
        path_names: list[str] = []
        for segment in _template_segments(self.path_template[1:]):
            match = _PLACEHOLDER.fullmatch(segment)
            if match is not None:
                path_names.append(match.group(1))
            elif not _LITERAL_SEGMENT.fullmatch(segment) or segment in {".", ".."}:
                raise ValueError("invalid path template segment")
        if sorted(path_names) != sorted(resource_names):
            raise ValueError("path and resource templates must use the same placeholders once")
        return self

    @property
    def verb(self) -> Verb:
        return _EFFECT_VERBS[self.effect]

    def resolve_path(self, resource: str) -> str | None:
        """Map a resource onto the upstream path, or None if it does not fit the template."""
        template = _template_segments(self.resource_template)
        parts = resource.split("/")
        if len(parts) != len(template):
            return None
        values: dict[str, str] = {}
        for pattern, part in zip(template, parts, strict=True):
            match = _PLACEHOLDER.fullmatch(pattern)
            if match is not None:
                if not _LITERAL_SEGMENT.fullmatch(part) or part in {".", ".."}:
                    return None
                values[match.group(1)] = part
            elif pattern != part:
                return None
        return _PLACEHOLDER.sub(lambda m: values[m.group(1)], self.path_template)

    def invalid_args(self, args: Mapping[str, JsonValue]) -> list[str]:
        """Names of unknown, missing or ill-typed arguments (never their values)."""
        problems = {name for name in args if name not in self.args}
        for name, spec in self.args.items():
            if name not in args:
                if spec.required:
                    problems.add(name)
            elif not spec.accepts(args[name]):
                problems.add(name)
        return sorted(problems)

    def input_schema(self) -> dict[str, JsonValue]:
        """JSON Schema offered to a model: the resource plus the declared arguments."""
        properties: dict[str, JsonValue] = {
            "resource": {
                "type": "string",
                "description": f"Resource name shaped like {self.resource_template}",
            }
        }
        required: list[JsonValue] = ["resource"]
        for name, spec in sorted(self.args.items()):
            properties[name] = spec.json_schema()
            if spec.required:
                required.append(name)
        return {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        }


class ManifestBody(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    v: Literal[1] = 1
    issuer: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    issued_at: int = Field(ge=0)
    tools: tuple[ToolEntry, ...] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def _unique_names(self) -> ManifestBody:
        names = [tool.name for tool in self.tools]
        if len(set(names)) != len(names):
            raise ValueError("tool names must be unique")
        return self

    def signing_input(self) -> bytes:
        return _SIGNING_PREFIX + canonical_json(self.model_dump(mode="json")).encode("utf-8")


class SignedManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    body: ManifestBody
    key_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    signature: str = Field(default="", max_length=128)

    def to_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"

    @classmethod
    def load(cls, path: Path) -> SignedManifest:
        try:
            return cls.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as exc:
            raise ManifestError(f"manifest {path.name} cannot be loaded") from exc


def sign_manifest(
    body: ManifestBody, private_key: Ed25519PrivateKey, key_id: str
) -> SignedManifest:
    return SignedManifest(
        body=body, key_id=key_id, signature=b64u_encode(private_key.sign(body.signing_input()))
    )


@dataclass(frozen=True, slots=True)
class ToolManifest:
    """A manifest whose signature has been verified. Construct it with :meth:`verify`."""

    body: ManifestBody
    key_id: str
    digest: str
    signature: str

    def signed(self) -> SignedManifest:
        return SignedManifest(body=self.body, key_id=self.key_id, signature=self.signature)

    @classmethod
    def verify(
        cls, signed: SignedManifest, trusted_keys: Mapping[str, Ed25519PublicKey]
    ) -> ToolManifest:
        key = trusted_keys.get(signed.key_id)
        if key is None:
            raise ManifestError("manifest signed by an untrusted key id")
        if not signed.signature:
            raise ManifestError("manifest is unsigned")
        try:
            key.verify(b64u_decode(signed.signature), signed.body.signing_input())
        except (InvalidSignature, MacaroonFormatError) as exc:
            raise ManifestError("manifest signature does not verify") from exc
        return cls(
            body=signed.body,
            key_id=signed.key_id,
            digest=sha256_hex(signed.body.signing_input()),
            signature=signed.signature,
        )

    def get(self, name: str) -> ToolEntry | None:
        return next((tool for tool in self.body.tools if tool.name == name), None)

    @property
    def tools(self) -> tuple[ToolEntry, ...]:
        return self.body.tools


class ManifestHolder:
    """Loads and verifies a manifest file; ``current()`` is None until a valid one is loaded."""

    def __init__(self, path: Path, trusted_keys: Mapping[str, Ed25519PublicKey]) -> None:
        self._path = path
        self._trusted = dict(trusted_keys)
        self._manifest: ToolManifest | None = None
        self.error: str | None = None
        self.reload()

    @classmethod
    def from_manifest(cls, manifest: ToolManifest) -> ManifestHolder:
        holder = cls.__new__(cls)
        holder._path = Path()
        holder._trusted = {}
        holder._manifest = manifest
        holder.error = None
        return holder

    def reload(self) -> bool:
        try:
            self._manifest = ToolManifest.verify(SignedManifest.load(self._path), self._trusted)
            self.error = None
        except ManifestError as exc:
            self._manifest = None
            self.error = str(exc)
        return self._manifest is not None

    def current(self) -> ToolManifest | None:
        return self._manifest

    def ready(self) -> bool:
        return self._manifest is not None
