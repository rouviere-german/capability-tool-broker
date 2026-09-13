"""The four role apps over HTTP, the HTTP clients, the compose end-to-end phases and role wiring."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import cast

import httpx
import pytest
from fastapi.testclient import TestClient

from capability_tool_broker.agent.clients import (
    ClientCredentials,
    HttpApproverClient,
    HttpAuthorityClient,
    HttpBrokerClient,
    RemoteServiceError,
)
from capability_tool_broker.approver.app import create_approver_app
from capability_tool_broker.authority.app import create_authority_app
from capability_tool_broker.authority.clientauth import ClientAssertionVerifier
from capability_tool_broker.authority.service import TokenRequest
from capability_tool_broker.broker.app import create_broker_app
from capability_tool_broker.broker.broker import ToolCall
from capability_tool_broker.broker.manifest import ManifestHolder, ToolManifest
from capability_tool_broker.broker.signing import sign_request
from capability_tool_broker.capabilities.keyfiles import generate_ed25519
from capability_tool_broker.core.config import Settings
from capability_tool_broker.core.security import hash_api_key
from capability_tool_broker.e2e import E2EError, resume_phase, start_phase
from capability_tool_broker.roles import build_app
from capability_tool_broker.scenario import demo_invoices, demo_token_request
from capability_tool_broker.services.app import create_services_app
from capability_tool_broker.stack import MANIFEST_KEY_ID, Stack
from support import CLIENT, REVIEWER, make_stack

pytestmark = pytest.mark.integration


def session(client: TestClient) -> httpx.Client:
    """TestClient speaks the httpx.Client interface the HTTP clients use."""
    return cast(httpx.Client, client)


API_KEY = "metrics-key-" + "m" * 30
OTHER_KEY = generate_ed25519()


def settings() -> Settings:
    return Settings(
        _env_file=None,
        environment="test",
        rate_limit_per_second=10_000,
        rate_limit_burst=10_000,
        api_key_sha256=[hash_api_key(API_KEY)],
    )


class Apps:
    def __init__(self, stack: Stack, manifest: ManifestHolder | None = None) -> None:
        clients = {
            CLIENT: stack.keys.client_keys[CLIENT].public_key(),
            "other-client": OTHER_KEY.public_key(),
        }

        def verifier(audience: str) -> ClientAssertionVerifier:
            return ClientAssertionVerifier(clients, audience=audience, clock=stack.clock)

        holder = manifest or ManifestHolder.from_manifest(stack.manifest)
        self.authority = TestClient(
            create_authority_app(stack.authority, verifier("authority"), settings=settings())
        )
        self.broker = TestClient(
            create_broker_app(stack.broker, verifier("broker"), holder, settings=settings())
        )
        self.approver = TestClient(
            create_approver_app(stack.approver, verifier("approver"), settings=settings())
        )
        self.services = TestClient(create_services_app(stack.router, settings=settings()))
        self.credentials = ClientCredentials(
            CLIENT, stack.keys.client_keys[CLIENT], clock=stack.clock
        )
        self.other = ClientCredentials("other-client", OTHER_KEY, clock=stack.clock)

    def close(self) -> None:
        for client in (self.authority, self.broker, self.approver, self.services):
            client.close()


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    built = make_stack(tmp_path, invoices=demo_invoices())
    yield built
    built.close()


@pytest.fixture
def apps(stack: Stack) -> Iterator[Apps]:
    built = Apps(stack)
    yield built
    built.close()


def test_business_endpoints_require_an_assertion_for_their_own_audience(apps: Apps) -> None:
    assert apps.authority.post("/v1/tokens", json={}).status_code == 401
    wrong_audience = apps.credentials.authorization("broker")
    assert apps.authority.post("/v1/tokens", json={}, headers=wrong_audience).status_code == 401
    assert apps.broker.get("/v1/manifest").status_code == 401
    assert apps.approver.get("/v1/approvals/" + "a" * 32).status_code == 401
    assert apps.authority.get("/healthz").status_code == 200


def test_minting_over_http(apps: Apps) -> None:
    client = HttpAuthorityClient(session(apps.authority), apps.credentials)
    minted = client.mint(demo_token_request())
    assert minted.task_id == "review-42"
    with pytest.raises(RemoteServiceError) as forbidden:
        HttpAuthorityClient(session(apps.authority), apps.other).mint(demo_token_request())
    assert forbidden.value.status == 403
    assert forbidden.value.code == "forbidden"
    with pytest.raises(RemoteServiceError) as invalid:
        client.mint(
            TokenRequest(template="invoice-review", task_id="t", params={"invoice_id": "*"})
        )
    assert invalid.value.status == 422


def test_broker_decisions_manifest_readiness_and_metrics_over_http(
    apps: Apps, stack: Stack
) -> None:
    token = (
        HttpAuthorityClient(session(apps.authority), apps.credentials)
        .mint(demo_token_request())
        .token
    )
    broker = HttpBrokerClient(session(apps.broker), apps.credentials)
    allowed = broker.call(
        token=token,
        discharges=(),
        call=ToolCall(task_id="review-42", tool="invoices_read", resource="invoice/42"),
        trace_carrier={"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
    )
    assert allowed.allowed
    denied = broker.call(
        token=token,
        discharges=(),
        call=ToolCall(task_id="review-42", tool="invoices_read", resource="invoice/43"),
        trace_carrier={},
    )
    assert not denied.allowed
    assert denied.failed_caveat is not None
    raw = apps.broker.post(
        "/v1/calls",
        json={
            "token": token,
            "discharges": [],
            "call": {"task_id": "review-42", "tool": "invoices_read", "resource": "invoice/43"},
        },
        headers=apps.credentials.authorization("broker"),
    )
    assert raw.status_code == 403
    invalid = apps.broker.post(
        "/v1/calls",
        json={"token": token, "discharges": [""], "call": {}},
        headers=apps.credentials.authorization("broker"),
    )
    assert invalid.status_code == 422
    manifest = ToolManifest.verify(
        broker.manifest(), {MANIFEST_KEY_ID: stack.keys.manifest_private.public_key()}
    )
    assert manifest.digest == stack.manifest.digest
    ready = apps.broker.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["checks"] == {
        "root_key": "ok",
        "state_store": "ok",
        "manifest_signature": "ok",
    }
    assert apps.broker.get("/metrics").status_code == 401
    metrics = apps.broker.get("/metrics", headers={"X-API-Key": API_KEY}).text
    assert 'capability_decisions_total{caveat_type="resource",result="deny"}' in metrics
    assert "verify_latency_seconds_bucket" in metrics
    assert "broker_call_latency_seconds_bucket" in metrics


def test_broker_readiness_fails_without_a_verified_manifest(stack: Stack, tmp_path: Path) -> None:
    apps = Apps(stack, manifest=ManifestHolder(tmp_path / "missing.json", {}))
    try:
        ready = apps.broker.get("/readyz")
        assert ready.status_code == 503
        assert ready.json()["checks"]["manifest_signature"] == "fail"
        assert (
            apps.broker.get(
                "/v1/manifest", headers=apps.credentials.authorization("broker")
            ).status_code
            == 503
        )
    finally:
        apps.close()


def test_approvals_over_http_are_visible_only_to_their_requester(apps: Apps, stack: Stack) -> None:
    token = (
        HttpAuthorityClient(session(apps.authority), apps.credentials)
        .mint(demo_token_request())
        .token
    )
    broker = HttpBrokerClient(session(apps.broker), apps.credentials)
    write = ToolCall(
        task_id="review-42",
        tool="invoices_update_status",
        resource="invoice/42",
        args={"status": "approved"},
    )
    denied = broker.call(token=token, discharges=(), call=write, trace_carrier={})
    assert denied.approval is not None
    assert denied.canonical_request is not None
    approver = HttpApproverClient(session(apps.approver), apps.credentials)
    from capability_tool_broker.approver.service import ApprovalSubmission

    view = approver.submit(
        ApprovalSubmission(caveat_id=denied.approval.caveat_id, request=denied.canonical_request)
    )
    assert view.status == "pending"
    assert approver.fetch(view.id).discharge is None
    with pytest.raises(RemoteServiceError) as hidden:
        HttpApproverClient(session(apps.approver), apps.other).fetch(view.id)
    assert hidden.value.status == 404
    stack.approver.decide(view.id, approver=REVIEWER, approve=True)
    assert approver.fetch(view.id).discharge is not None
    with pytest.raises(RemoteServiceError) as refused:
        approver.submit(ApprovalSubmission(caveat_id="AAAA", request=denied.canonical_request))
    assert refused.value.code == "invalid_caveat"
    assert (
        apps.approver.get(
            "/v1/approvals/not-an-id", headers=apps.credentials.authorization("approver")
        ).status_code
        == 422
    )


def test_rate_limits_apply_per_authenticated_client_not_per_address(stack: Stack) -> None:
    verifier = ClientAssertionVerifier(
        {
            CLIENT: stack.keys.client_keys[CLIENT].public_key(),
            "other-client": OTHER_KEY.public_key(),
        },
        audience="broker",
        clock=stack.clock,
    )
    limited = Settings(
        _env_file=None, environment="test", rate_limit_per_second=0.001, rate_limit_burst=2
    )
    app = create_broker_app(
        stack.broker, verifier, ManifestHolder.from_manifest(stack.manifest), settings=limited
    )
    agent = ClientCredentials(CLIENT, stack.keys.client_keys[CLIENT], clock=stack.clock)
    other = ClientCredentials("other-client", OTHER_KEY, clock=stack.clock)
    with TestClient(app) as client:  # every request arrives from the same address
        codes = [
            client.get("/v1/manifest", headers=agent.authorization("broker")).status_code
            for _ in range(3)
        ]
        assert codes == [200, 200, 429]
        assert client.get("/v1/manifest", headers=other.authorization("broker")).status_code == 200
        garbage = {"Authorization": "Bearer not-a-client-assertion"}
        assert [client.get("/v1/manifest", headers=garbage).status_code for _ in range(3)] == [
            401,
            401,
            429,
        ]  # unverifiable assertions share the address bucket and cannot mint fresh ones
        assert client.get("/v1/manifest", headers=other.authorization("broker")).status_code == 200


def test_services_app_accepts_only_signed_requests(apps: Apps, stack: Stack) -> None:
    assert apps.services.get("/invoices.internal/invoices/42").status_code == 401
    headers = sign_request(
        stack.keys.credentials()["invoices"],
        method="GET",
        path="/invoices/42",
        body=b"",
        now=int(stack.clock()),
    )
    assert apps.services.get("/invoices.internal/invoices/42", headers=headers).status_code == 200


def test_compose_end_to_end_phases_over_http(apps: Apps, stack: Stack, tmp_path: Path) -> None:
    broker = HttpBrokerClient(session(apps.broker), apps.credentials)
    approver = HttpApproverClient(session(apps.approver), apps.credentials)
    authority = HttpAuthorityClient(session(apps.authority), apps.credentials)
    state = tmp_path / "state" / "e2e.json"
    started = start_phase(
        authority=authority,
        broker=broker,
        approver=approver,
        manifest=stack.manifest,
        state_path=state,
        clock=stack.clock,
    )
    assert started["executed"] == 1
    assert len(started["denied"]) == 3  # type: ignore[arg-type]
    with pytest.raises(E2EError, match="decided"):
        resume_phase(
            broker=broker,
            approver=approver,
            manifest=stack.manifest,
            state_path=state,
            clock=stack.clock,
        )
    for record in stack.approver.pending():
        stack.approver.decide(record.id, approver=REVIEWER, approve=True)
    resumed = resume_phase(
        broker=broker,
        approver=approver,
        manifest=stack.manifest,
        state_path=state,
        clock=stack.clock,
    )
    assert resumed == {
        "phase": "resume",
        "executed_after_approval": 1,
        "replayed_discharge": "replayed",
    }
    assert not state.exists()


def test_start_phase_fails_when_expectations_do_not_hold(
    apps: Apps, stack: Stack, tmp_path: Path
) -> None:
    stack.invoices.invoices["42"]["notes"] = "nothing to see"
    with pytest.raises(E2EError, match="injected"):
        start_phase(
            authority=HttpAuthorityClient(session(apps.authority), apps.credentials),
            broker=HttpBrokerClient(session(apps.broker), apps.credentials),
            approver=HttpApproverClient(session(apps.approver), apps.credentials),
            manifest=stack.manifest,
            state_path=tmp_path / "e2e.json",
            clock=stack.clock,
        )


def test_roles_build_their_apps_from_the_environment(
    stack: Stack, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = stack.keys.environment()
    manifest_path = tmp_path / "manifest.signed.json"
    manifest_path.write_text(stack.manifest.signed().to_json(), encoding="utf-8")
    for role in ("authority", "broker", "approver", "services"):
        for name, value in environment[role].items():
            monkeypatch.setenv(name, value)
    monkeypatch.setenv("BROKER_MANIFEST_PATH", str(manifest_path))
    for name in ("AUTHORITY_AUDIT_PATH", "BROKER_AUDIT_PATH", "APPROVER_AUDIT_PATH"):
        monkeypatch.setenv(name, str(tmp_path / f"{name.lower()}.jsonl"))
    monkeypatch.setenv("APPROVER_STORE_PATH", str(tmp_path / "approvals.json"))
    monkeypatch.setenv("SERVICES_DEMO_DATA", "true")
    for role in ("authority", "broker", "approver", "services"):
        with TestClient(build_app(role, settings())) as client:
            assert client.get("/readyz").status_code == 200, role
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "version: 1\napprover_location: https://approver.internal/v1\nmax_ttl_seconds: 60\n"
        "clients: {}\ntemplates: {}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AUTHORITY_POLICY_PATH", str(policy))
    with TestClient(build_app("authority", settings())) as client:
        assert client.get("/readyz").status_code == 200
    monkeypatch.setenv("BROKER_REDIS_URL", "redis://127.0.0.1:1/0")
    with TestClient(build_app("broker", settings())) as client:
        ready = client.get("/readyz")
        assert ready.status_code == 503
        assert ready.json()["checks"]["state_store"] == "fail"
    with pytest.raises(ValueError, match="unknown role"):
        build_app("agent-host", settings())
