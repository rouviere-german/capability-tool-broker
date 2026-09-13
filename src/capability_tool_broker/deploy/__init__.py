"""Bundled deployment data: the default tool manifest body and task policy (YAML)."""

from __future__ import annotations

from importlib import resources

import yaml

from capability_tool_broker.authority.policy import Policy
from capability_tool_broker.broker.manifest import ManifestBody

__all__ = ["default_manifest_body", "default_policy"]


def _text(name: str) -> str:
    return resources.files(__package__).joinpath(name).read_text(encoding="utf-8")


def default_manifest_body(issued_at: int = 0) -> ManifestBody:
    data = yaml.safe_load(_text("manifest.yaml"))
    data["issued_at"] = issued_at
    return ManifestBody.model_validate(data)


def default_policy() -> Policy:
    return Policy.from_yaml(_text("policy.yaml"))
