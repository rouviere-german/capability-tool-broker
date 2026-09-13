"""Task policy (YAML): which client may request which task template, and what a template grants.

A template names tools, verbs and resource globs with ``{param}`` placeholders, a lifetime, an
optional ``max_calls`` limit, extra argument caveats and a per-task budget. Clients supply parameter
values when they request a token; every value must match the template's regular expression *and*
be a literal resource segment (no ``*``, ``?`` or ``/``), so a parameter can never widen a glob.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from capability_tool_broker.capabilities.caveats import CaveatSyntaxError, is_stateful, parse_caveat
from capability_tool_broker.capabilities.glob import is_valid_glob
from capability_tool_broker.capabilities.request import (
    CLIENT_ID_PATTERN,
    TOOL_PATTERN,
    Verb,
    is_valid_host,
)

__all__ = [
    "BudgetSpec",
    "ClientSpec",
    "Policy",
    "PolicyError",
    "TemplateSpec",
    "substitute",
]

_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]{0,31})\}")
_LITERAL_VALUE = re.compile(r"[A-Za-z0-9._@-]{1,64}")
_TEMPLATE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


class PolicyError(ValueError):
    """The policy file is invalid."""


class BudgetSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    steps: int = Field(ge=1, le=1_000)
    tokens: int = Field(ge=1, le=10_000_000)
    usd: float = Field(ge=0, le=1_000)


def substitute(template: str, params: dict[str, str]) -> str:
    return _PLACEHOLDER.sub(lambda match: params[match.group(1)], template)


class TemplateSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    description: str = Field(min_length=1, max_length=512)
    params: dict[str, str] = Field(default_factory=dict)
    tools: tuple[str, ...] = Field(min_length=1, max_length=32)
    verbs: tuple[Verb, ...] = Field(min_length=1)
    resources: tuple[str, ...] = Field(min_length=1, max_length=32)
    hosts: tuple[str, ...] | None = None
    ttl_seconds: int = Field(ge=1, le=86_400)
    max_calls: int | None = Field(default=None, ge=1, le=1_000_000)
    arg_caveats: tuple[str, ...] = ()
    approval_scope: str | None = None
    budget: BudgetSpec

    @field_validator("tools")
    @classmethod
    def _check_tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not re.fullmatch(TOOL_PATTERN, tool) for tool in value):
            raise ValueError("invalid tool name")
        return value

    @model_validator(mode="after")
    def _check(self) -> TemplateSpec:  # noqa: PLR0912 - one check per template rule
        for name, pattern in self.params.items():
            if not re.fullmatch(r"[a-z_][a-z0-9_]{0,31}", name):
                raise ValueError("invalid parameter name")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"parameter {name} has an invalid pattern") from exc
        for resource in self.resources:
            names = set(_PLACEHOLDER.findall(resource))
            if not names <= self.params.keys():
                raise ValueError("resource placeholders must be declared parameters")
            sample = substitute(resource, dict.fromkeys(names, "x"))
            if not is_valid_glob(sample):
                raise ValueError("resource template does not produce a valid glob")
        if self.hosts is not None and not all(is_valid_host(host) for host in self.hosts):
            raise ValueError("invalid host")
        for condition in self.arg_caveats:
            try:
                if parse_caveat(condition).kind.value != "arg":
                    raise ValueError("arg_caveats may only contain arg predicates")
            except CaveatSyntaxError as exc:
                raise ValueError("invalid argument caveat") from exc
        if self.approval_scope is not None:
            try:
                scope = parse_caveat(self.approval_scope)
            except CaveatSyntaxError as exc:
                raise ValueError("invalid approval scope") from exc
            if is_stateful(scope):
                raise ValueError("approval scope must be stateless")
        return self

    def bind_params(self, values: dict[str, str]) -> dict[str, str]:
        """Validate client-supplied parameter values; raise PolicyError on any mismatch."""
        if set(values) != set(self.params):
            raise PolicyError("parameters do not match the template")
        for name, pattern in self.params.items():
            value = values[name]
            if not _LITERAL_VALUE.fullmatch(value) or value in {".", ".."}:
                raise PolicyError(f"parameter {name} is not a literal resource segment")
            if not re.fullmatch(pattern, value):
                raise PolicyError(f"parameter {name} does not match its pattern")
        return dict(values)


class ClientSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    templates: tuple[str, ...] = Field(min_length=1)


class Policy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1] = 1
    approver_location: str = Field(pattern=r"^[a-z][a-z0-9+.-]{0,15}://[A-Za-z0-9.:_/-]{1,200}$")
    max_ttl_seconds: int = Field(ge=1, le=86_400)
    clients: dict[str, ClientSpec]
    templates: dict[str, TemplateSpec]

    @model_validator(mode="after")
    def _check(self) -> Policy:
        for name in self.templates:
            if not _TEMPLATE_NAME.fullmatch(name):
                raise ValueError(f"invalid template name {name!r}")
        for client_id, client in self.clients.items():
            if not re.fullmatch(CLIENT_ID_PATTERN, client_id):
                raise ValueError(f"invalid client id {client_id!r}")
            unknown = set(client.templates) - self.templates.keys()
            if unknown:
                raise ValueError(f"client {client_id} references unknown templates")
        return self

    @classmethod
    def from_yaml(cls, text: str) -> Policy:
        try:
            return cls.model_validate(yaml.safe_load(text))
        except (yaml.YAMLError, ValidationError) as exc:
            raise PolicyError("policy file is invalid") from exc

    @classmethod
    def load(cls, path: Path) -> Policy:
        return cls.from_yaml(path.read_text(encoding="utf-8"))
