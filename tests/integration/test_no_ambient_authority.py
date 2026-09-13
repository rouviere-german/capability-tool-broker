"""No ambient authority: credentials exist only where their role needs them.

Three checks: the compose file hands every secret only to its role; the role settings classes
cannot load another role's secrets from a shared environment; and the object graph of a running
agent host (and of the approver) contains no service credential, root key or approver key.
"""

from __future__ import annotations

import types
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import SecretStr

from capability_tool_broker.agent.clients import (
    ClientCredentials,
    HttpApproverClient,
    HttpBrokerClient,
)
from capability_tool_broker.agent.host import CapabilityRuntime, RuntimeContext
from capability_tool_broker.agentic.budget import BudgetLedger, BudgetLimits
from capability_tool_broker.authority.service import Authority
from capability_tool_broker.broker.broker import Broker
from capability_tool_broker.broker.signing import ServiceCredential
from capability_tool_broker.capabilities.keys import RootKeyRing
from capability_tool_broker.macaroons.codec import b64u_encode
from capability_tool_broker.scenario import demo_providers
from capability_tool_broker.settings import (
    AgentHostSettings,
    ApproverSettings,
    AuthoritySettings,
    BrokerSettings,
    ServicesSettings,
)
from capability_tool_broker.stack import Keyset, Stack
from support import CLIENT, make_stack, mint

pytestmark = pytest.mark.integration

ROOT_KEYS = {"AUTHORITY_ROOT_KEYS", "BROKER_ROOT_KEYS"}
SERVICE_CREDENTIALS = {"BROKER_SERVICE_CREDENTIALS", "SERVICES_CREDENTIALS"}
APPROVER_KEY = {"APPROVER_PRIVATE_KEY"}
FORBIDDEN_TYPES = (RootKeyRing, ServiceCredential, X25519PrivateKey, Broker, Authority, Stack)


def _compose_environment(repo_root: Path) -> dict[str, set[str]]:
    compose = yaml.safe_load((repo_root / "docker-compose.yml").read_text(encoding="utf-8"))
    return {
        name: set((service.get("environment") or {}).keys())
        for name, service in compose["services"].items()
    }


def test_compose_hands_each_secret_only_to_its_role(repo_root: Path) -> None:
    environment = _compose_environment(repo_root)
    assert {role for role, names in environment.items() if names & SERVICE_CREDENTIALS} == {
        "broker",
        "services",
    }
    assert "BROKER_SERVICE_CREDENTIALS" in environment["broker"]
    assert {role for role, names in environment.items() if names & ROOT_KEYS} == {
        "authority",
        "broker",
    }
    assert {role for role, names in environment.items() if names & APPROVER_KEY} == {"approver"}
    for role in ("agent-host", "approver"):
        assert not environment[role] & (ROOT_KEYS | SERVICE_CREDENTIALS)
    assert all(name.startswith("AGENT_") for name in environment["agent-host"])
    assert not any(
        name.startswith("ANTHROPIC") for name in environment["broker"] | environment["approver"]
    )


def _revealed(settings: object) -> str:
    values = []
    for value in vars(settings).values():
        values.append(value.get_secret_value() if isinstance(value, SecretStr) else str(value))
    return "\n".join(values)


def test_role_settings_cannot_load_other_roles_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    environment = Keyset.generate().environment()
    for variables in environment.values():
        for name, value in variables.items():
            monkeypatch.setenv(name, value)
    monkeypatch.setenv(
        "AGENT_MANIFEST_PUBLIC_KEYS", environment["broker"]["BROKER_MANIFEST_PUBLIC_KEYS"]
    )
    secrets_by_role = {
        "root": environment["broker"]["BROKER_ROOT_KEYS"],
        "services": environment["broker"]["BROKER_SERVICE_CREDENTIALS"],
        "approver": environment["approver"]["APPROVER_PRIVATE_KEY"],
        "manifest-signing": environment["manifest-signing"]["MANIFEST_SIGNING_KEY"],
    }
    agent = _revealed(AgentHostSettings(_env_file=None))
    approver = _revealed(ApproverSettings(_env_file=None))
    authority = _revealed(AuthoritySettings(_env_file=None))
    services = _revealed(ServicesSettings(_env_file=None))
    broker = _revealed(BrokerSettings(_env_file=None))
    for secret in secrets_by_role.values():
        assert secret not in agent
    for name in ("root", "services", "manifest-signing"):
        assert secrets_by_role[name] not in approver
    for name in ("services", "approver", "manifest-signing"):
        assert secrets_by_role[name] not in authority
    for name in ("root", "approver", "manifest-signing"):
        assert secrets_by_role[name] not in services
    assert secrets_by_role["approver"] not in broker
    assert secrets_by_role["services"] in broker


def reachable(root: object, limit: int = 50_000) -> Iterator[object]:
    seen: set[int] = set()
    pending = [root]
    while pending and len(seen) < limit:
        obj = pending.pop()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        yield obj
        if isinstance(
            obj, (str, bytes, bytearray, int, float, bool, type(None), type, types.ModuleType)
        ):
            continue
        if isinstance(obj, dict):
            pending.extend(obj.keys())
            pending.extend(obj.values())
            continue
        if isinstance(obj, (list, tuple, set, frozenset)):
            pending.extend(obj)
            continue
        owner = getattr(obj, "__self__", None)
        if owner is not None and not isinstance(owner, types.ModuleType):
            pending.append(owner)
        closure = getattr(obj, "__closure__", None)
        if closure:
            pending.extend(cell.cell_contents for cell in closure)
        attributes = getattr(obj, "__dict__", None)
        if isinstance(attributes, dict):
            pending.extend(attributes.values())
        for slot in getattr(type(obj), "__slots__", ()):
            if hasattr(obj, slot):
                pending.append(getattr(obj, slot))


def _secret_fragments(stack: Stack) -> list[bytes]:
    fragments: list[bytes] = []
    for secret in stack.keys.service_secrets.values():
        fragments += [secret, b64u_encode(secret).encode()]
    for kid in stack.keys.ring.kids:
        fragments.append(stack.keys.ring.to_spec().encode())
        del kid
    approver_raw = stack.keys.approver_private.private_bytes_raw()
    fragments += [approver_raw, b64u_encode(approver_raw).encode()]
    return fragments


def _assert_clean(root: object, stack: Stack) -> int:
    fragments = _secret_fragments(stack)
    count = 0
    for obj in reachable(root):
        count += 1
        assert not isinstance(obj, FORBIDDEN_TYPES), type(obj)
        if isinstance(obj, (bytes, bytearray)):
            assert not any(fragment in obj for fragment in fragments)
        elif isinstance(obj, str):
            encoded = obj.encode("utf-8", errors="ignore")
            assert not any(fragment in encoded for fragment in fragments)
    return count


def test_a_running_agent_host_holds_only_capabilities(tmp_path: Path) -> None:
    stack = make_stack(tmp_path)
    try:
        token = mint(stack).token  # obtained from the authority; a capability, not a credential
        credentials = ClientCredentials(CLIENT, stack.keys.client_keys[CLIENT])
        runtime = CapabilityRuntime(
            RuntimeContext(
                task_id="task-1",
                manifest=stack.manifest,
                providers=demo_providers(),
                budget=BudgetLedger(BudgetLimits.of(steps=5, tokens=10, usd=0.1)),
            ),
            token=token,
            broker=HttpBrokerClient(httpx.Client(base_url="http://127.0.0.1:9"), credentials),
            approver=HttpApproverClient(httpx.Client(base_url="http://127.0.0.1:9"), credentials),
        )
        assert _assert_clean(runtime, stack) > 100
    finally:
        stack.close()


def test_the_approver_holds_no_root_keys_or_service_credentials(tmp_path: Path) -> None:
    stack = make_stack(tmp_path)
    try:
        fragments = [stack.keys.ring.to_spec().encode()]
        fragments += list(stack.keys.service_secrets.values())
        for obj in reachable(stack.approver):
            assert not isinstance(obj, (RootKeyRing, ServiceCredential, Broker, Authority)), type(
                obj
            )
            if isinstance(obj, (bytes, str)):
                raw = obj.encode() if isinstance(obj, str) else obj
                assert not any(fragment in raw for fragment in fragments)
    finally:
        stack.close()
