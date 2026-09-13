"""Build each compose role's HTTP app from its own settings (one image, four entrypoints)."""

from __future__ import annotations

from pathlib import Path

import httpx
import redis
from fastapi import FastAPI
from pydantic import SecretStr

from capability_tool_broker.agentic.approval import ApprovalStore
from capability_tool_broker.agentic.audit import AuditLog, FileCheckpointSink
from capability_tool_broker.approver.app import create_approver_app
from capability_tool_broker.approver.service import ApproverService
from capability_tool_broker.authority.app import create_authority_app
from capability_tool_broker.authority.clientauth import ClientAssertionVerifier
from capability_tool_broker.authority.policy import Policy
from capability_tool_broker.authority.service import Authority
from capability_tool_broker.broker.app import create_broker_app
from capability_tool_broker.broker.broker import Broker
from capability_tool_broker.broker.manifest import ManifestHolder
from capability_tool_broker.broker.signing import ServiceCredential
from capability_tool_broker.broker.state import MemoryStateStore, RedisStateStore, StateStore
from capability_tool_broker.capabilities.keyfiles import parse_public_key_map, parse_secret_map
from capability_tool_broker.capabilities.keys import MIN_KEY_BYTES, RootKeyRing
from capability_tool_broker.capabilities.sealed import load_private_key, load_public_key
from capability_tool_broker.core.config import Settings
from capability_tool_broker.deploy import default_policy
from capability_tool_broker.macaroons.codec import b64u_decode
from capability_tool_broker.services.base import ServiceRouter
from capability_tool_broker.services.files import FileStoreService
from capability_tool_broker.services.invoices import InvoiceService
from capability_tool_broker.services.mailer import MailerService
from capability_tool_broker.settings import (
    ApproverSettings,
    AuthoritySettings,
    BrokerSettings,
    ServicesSettings,
)

__all__ = [
    "ROLES",
    "audit_log",
    "build_app",
    "build_approver_service",
    "build_authority_app",
    "build_broker_app",
    "build_services_app",
    "service_credentials",
]

ROLES = ("authority", "broker", "approver", "services")


def service_credentials(spec: str) -> dict[str, ServiceCredential]:
    return {
        name: ServiceCredential(key_id=f"broker-{name}", secret=secret)
        for name, secret in parse_secret_map(spec).items()
    }


def audit_log(
    path: Path, checkpoint_key: SecretStr | None, checkpoint_path: Path | None
) -> AuditLog:
    """A role's audit log, with signed checkpoints when a checkpoint key is configured."""
    if checkpoint_key is None:
        if checkpoint_path is not None:
            raise ValueError("an audit checkpoint path needs an audit checkpoint key")
        return AuditLog(path)
    key = b64u_decode(checkpoint_key.get_secret_value())
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"the audit checkpoint key must be at least {MIN_KEY_BYTES} bytes")
    sink_path = checkpoint_path or path.parent / "checkpoints" / f"{path.name}.checkpoint"
    return AuditLog(path, checkpoints=FileCheckpointSink(sink_path), checkpoint_key=key)


def build_authority_app(role: AuthoritySettings, settings: Settings) -> FastAPI:
    ring = RootKeyRing.parse(role.root_keys.get_secret_value())
    policy = Policy.load(role.policy_path) if role.policy_path else default_policy()
    authority = Authority(
        ring=ring,
        policy=policy,
        approver_public_key=load_public_key(role.approver_public_key),
        audit=audit_log(role.audit_path, role.audit_checkpoint_key, role.audit_checkpoint_path),
    )
    verifier = ClientAssertionVerifier(
        parse_public_key_map(role.client_public_keys), audience=role.audience
    )
    return create_authority_app(authority, verifier, settings=settings)


def build_broker_app(role: BrokerSettings, settings: Settings) -> FastAPI:
    ring = RootKeyRing.parse(role.root_keys.get_secret_value())
    manifest = ManifestHolder(role.manifest_path, parse_public_key_map(role.manifest_public_keys))
    state: StateStore = (
        RedisStateStore(redis.Redis.from_url(role.redis_url.get_secret_value()))
        if role.redis_url is not None
        else MemoryStateStore()
    )
    broker = Broker(
        ring=ring,
        manifest=manifest,
        state=state,
        credentials=service_credentials(role.service_credentials.get_secret_value()),
        http=httpx.Client(timeout=10.0),
        audit=audit_log(role.audit_path, role.audit_checkpoint_key, role.audit_checkpoint_path),
        service_base_url=role.service_base_url,
    )
    verifier = ClientAssertionVerifier(
        parse_public_key_map(role.client_public_keys), audience=role.audience
    )
    return create_broker_app(broker, verifier, manifest, settings=settings)


def build_approver_service(role: ApproverSettings) -> ApproverService:
    return ApproverService(
        private_key=load_private_key(role.private_key.get_secret_value()),
        store=ApprovalStore(role.store_path),
        audit=audit_log(role.audit_path, role.audit_checkpoint_key, role.audit_checkpoint_path),
        discharge_ttl_seconds=role.discharge_ttl_seconds,
    )


def build_approver_app(role: ApproverSettings, settings: Settings) -> FastAPI:
    verifier = ClientAssertionVerifier(
        parse_public_key_map(role.client_public_keys), audience=role.audience
    )
    return create_approver_app(build_approver_service(role), verifier, settings=settings)


def build_services_app(role: ServicesSettings, settings: Settings) -> FastAPI:
    credentials = service_credentials(role.credentials.get_secret_value())
    from capability_tool_broker.scenario import demo_invoices  # noqa: PLC0415

    router = ServiceRouter(
        [
            InvoiceService(
                credential=credentials["invoices"],
                invoices=demo_invoices() if role.demo_data else None,
            ),
            FileStoreService(credential=credentials["files"]),
            MailerService(credential=credentials["mailer"]),
        ]
    )
    from capability_tool_broker.services.app import create_services_app  # noqa: PLC0415

    return create_services_app(router, settings=settings)


def build_app(role: str, settings: Settings) -> FastAPI:
    """Build the app for ``role`` from environment settings (raises if they are incomplete)."""
    if role == "authority":
        return build_authority_app(AuthoritySettings(), settings)
    if role == "broker":
        return build_broker_app(BrokerSettings(), settings)
    if role == "approver":
        return build_approver_app(ApproverSettings(), settings)
    if role == "services":
        return build_services_app(ServicesSettings(), settings)
    raise ValueError(f"unknown role {role!r}")
