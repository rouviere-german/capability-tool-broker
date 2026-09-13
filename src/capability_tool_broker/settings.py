"""Per-role settings. Each process reads only its own prefix.

A compose service is started with the environment of one role, and even when several roles share
an environment (local runs with one ``.env``), a role's settings class declares no field for
another role's secrets, so the process never loads them. ``tests/integration/
test_no_ambient_authority.py`` checks both the classes and the compose file.

HTTP hygiene settings (bind address, rate limits, body size, CORS, docs) stay in
:class:`capability_tool_broker.core.config.Settings` under the ``APP_`` prefix.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = [
    "AgentHostSettings",
    "ApproverSettings",
    "AuthoritySettings",
    "BrokerSettings",
    "ServicesSettings",
]


class AuthoritySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AUTHORITY_", env_file=".env", extra="ignore", frozen=True
    )

    root_keys: SecretStr
    approver_public_key: str
    client_public_keys: str
    policy_path: Path | None = None
    audit_path: Path = Path("var/authority-audit.jsonl")
    audience: str = "authority"


class BrokerSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BROKER_", env_file=".env", extra="ignore", frozen=True
    )

    root_keys: SecretStr
    manifest_path: Path = Path("var/manifest.signed.json")
    manifest_public_keys: str
    service_credentials: SecretStr
    service_base_url: str | None = None
    redis_url: SecretStr | None = None
    client_public_keys: str
    audit_path: Path = Path("var/broker-audit.jsonl")
    audience: str = "broker"


class ApproverSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APPROVER_", env_file=".env", extra="ignore", frozen=True
    )

    private_key: SecretStr
    client_public_keys: str
    store_path: Path = Path("var/approvals.json")
    audit_path: Path = Path("var/approver-audit.jsonl")
    discharge_ttl_seconds: int = Field(default=120, ge=10, le=900)
    reviewer: str = "human:reviewer"
    audience: str = "approver"


class ServicesSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SERVICES_", env_file=".env", extra="ignore", frozen=True
    )

    credentials: SecretStr
    demo_data: bool = False


class AgentHostSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENT_", env_file=".env", extra="ignore", frozen=True
    )

    client_id: str = "agent-host"
    client_private_key: SecretStr
    authority_url: str = "http://authority:8001"
    broker_url: str = "http://broker:8002"
    approver_url: str = "http://approver:8003"
    manifest_public_keys: str
    provider: Literal["fake", "anthropic"] = "fake"
    state_path: Path = Path("var/e2e-state.json")
