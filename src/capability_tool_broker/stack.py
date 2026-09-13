"""In-process deployment: every component wired with keys generated at runtime.

Tests, the demo and the benchmarks use this. Each component receives only the key material its
compose service would receive: the authority gets the root key ring and the approver's *public*
key, the approver gets its private key, the broker gets the ring, the manifest public key and the
service credentials, and the fake services get their own credential. The agent host gets none of
these (see ``tests/integration/test_no_ambient_authority.py``).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from opentelemetry.trace import Tracer
from pydantic import JsonValue

from capability_tool_broker.agentic.approval import ApprovalStore
from capability_tool_broker.agentic.audit import AuditLog
from capability_tool_broker.approver.service import ApproverService
from capability_tool_broker.authority.policy import Policy
from capability_tool_broker.authority.service import Authority
from capability_tool_broker.broker.broker import Broker
from capability_tool_broker.broker.manifest import (
    ManifestBody,
    ManifestHolder,
    ToolManifest,
    sign_manifest,
)
from capability_tool_broker.broker.signing import ServiceCredential
from capability_tool_broker.broker.state import MemoryStateStore, StateStore
from capability_tool_broker.capabilities.keyfiles import (
    ed25519_private_text,
    ed25519_public_text,
    generate_ed25519,
    generate_secret,
    secret_map_text,
)
from capability_tool_broker.capabilities.keys import RootKeyRing
from capability_tool_broker.capabilities.sealed import (
    generate_private_key,
    private_key_text,
    public_key_text,
)
from capability_tool_broker.deploy import default_manifest_body, default_policy
from capability_tool_broker.services.base import ServiceRouter
from capability_tool_broker.services.files import FileStoreService
from capability_tool_broker.services.invoices import InvoiceService
from capability_tool_broker.services.mailer import MailerService

__all__ = ["Keyset", "ManualClock", "Stack", "build_stack"]

SERVICE_NAMES = ("files", "invoices", "mailer")
MANIFEST_KEY_ID = "manifest-k1"


class ManualClock:
    """A settable clock shared by every component, so tests can move time forward."""

    def __init__(self, start: float | None = None) -> None:
        self.now = float(int(time.time()) if start is None else start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class Keyset:
    ring: RootKeyRing
    approver_private: X25519PrivateKey
    manifest_private: Ed25519PrivateKey
    client_keys: dict[str, Ed25519PrivateKey]
    service_secrets: dict[str, bytes]

    def __repr__(self) -> str:
        return f"Keyset(kids={self.ring.kids}, clients={sorted(self.client_keys)})"

    @classmethod
    def generate(cls, clients: tuple[str, ...] = ("agent-host",)) -> Keyset:
        return cls(
            ring=RootKeyRing.generate("k1"),
            approver_private=generate_private_key(),
            manifest_private=generate_ed25519(),
            client_keys={client: generate_ed25519() for client in clients},
            service_secrets={name: generate_secret() for name in SERVICE_NAMES},
        )

    def credentials(self) -> dict[str, ServiceCredential]:
        return {
            name: ServiceCredential(key_id=f"broker-{name}", secret=secret)
            for name, secret in self.service_secrets.items()
        }

    def environment(self) -> dict[str, dict[str, str]]:
        """Per-role environment variables, as the compose file hands them out."""
        client_public = ",".join(
            f"{client}:{ed25519_public_text(key.public_key())}"
            for client, key in sorted(self.client_keys.items())
        )
        approver_public = public_key_text(self.approver_private.public_key())
        manifest_public = (
            f"{MANIFEST_KEY_ID}:{ed25519_public_text(self.manifest_private.public_key())}"
        )
        services = secret_map_text(self.service_secrets)
        agent_client, agent_key = next(iter(sorted(self.client_keys.items())))
        return {
            "authority": {
                "AUTHORITY_ROOT_KEYS": self.ring.to_spec(),
                "AUTHORITY_APPROVER_PUBLIC_KEY": approver_public,
                "AUTHORITY_CLIENT_PUBLIC_KEYS": client_public,
            },
            "broker": {
                "BROKER_ROOT_KEYS": self.ring.to_spec(),
                "BROKER_MANIFEST_PUBLIC_KEYS": manifest_public,
                "BROKER_SERVICE_CREDENTIALS": services,
                "BROKER_CLIENT_PUBLIC_KEYS": client_public,
            },
            "approver": {
                "APPROVER_PRIVATE_KEY": private_key_text(self.approver_private),
                "APPROVER_CLIENT_PUBLIC_KEYS": client_public,
            },
            "services": {"SERVICES_CREDENTIALS": services},
            "agent-host": {
                "AGENT_CLIENT_ID": agent_client,
                "AGENT_CLIENT_PRIVATE_KEY": ed25519_private_text(agent_key),
            },
            "manifest-signing": {
                "MANIFEST_SIGNING_KEY": ed25519_private_text(self.manifest_private),
            },
        }


@dataclass
class Stack:
    keys: Keyset
    clock: Callable[[], float]
    policy: Policy
    manifest: ToolManifest
    audit: AuditLog
    state: StateStore
    authority: Authority
    approvals: ApprovalStore
    approver: ApproverService
    router: ServiceRouter
    invoices: InvoiceService
    files: FileStoreService
    mailer: MailerService
    http: httpx.Client
    broker: Broker
    workdir: Path
    extras: dict[str, object] = field(default_factory=dict)

    def close(self) -> None:
        self.http.close()


def build_stack(
    workdir: Path,
    *,
    clock: Callable[[], float] | None = None,
    keys: Keyset | None = None,
    policy: Policy | None = None,
    manifest_body: ManifestBody | None = None,
    state: StateStore | None = None,
    invoices: Mapping[str, dict[str, JsonValue]] | None = None,
    files: Mapping[str, str] | None = None,
    tracer: Tracer | None = None,
    audit_name: str = "audit.jsonl",
) -> Stack:
    workdir.mkdir(parents=True, exist_ok=True)
    clock = clock or ManualClock()
    keys = keys or Keyset.generate()
    policy = policy or default_policy()
    body = manifest_body or default_manifest_body(issued_at=int(clock()))
    signed = sign_manifest(body, keys.manifest_private, MANIFEST_KEY_ID)
    manifest = ToolManifest.verify(signed, {MANIFEST_KEY_ID: keys.manifest_private.public_key()})
    audit = AuditLog(workdir / audit_name)
    state = state or MemoryStateStore()
    credentials = keys.credentials()

    invoice_service = InvoiceService(
        credential=credentials["invoices"], clock=clock, invoices=invoices
    )
    file_service = FileStoreService(credential=credentials["files"], clock=clock, files=files)
    mail_service = MailerService(credential=credentials["mailer"], clock=clock)
    router = ServiceRouter([invoice_service, file_service, mail_service])
    http = httpx.Client(transport=router.transport())

    approvals = ApprovalStore(clock=clock)
    return Stack(
        keys=keys,
        clock=clock,
        policy=policy,
        manifest=manifest,
        audit=audit,
        state=state,
        authority=Authority(
            ring=keys.ring,
            policy=policy,
            approver_public_key=keys.approver_private.public_key(),
            audit=audit,
            clock=clock,
        ),
        approvals=approvals,
        approver=ApproverService(
            private_key=keys.approver_private, store=approvals, audit=audit, clock=clock
        ),
        router=router,
        invoices=invoice_service,
        files=file_service,
        mailer=mail_service,
        http=http,
        broker=Broker(
            ring=keys.ring,
            manifest=ManifestHolder.from_manifest(manifest),
            state=state,
            credentials=credentials,
            http=http,
            audit=audit,
            tracer=tracer,
            clock=clock,
        ),
        workdir=workdir,
    )
