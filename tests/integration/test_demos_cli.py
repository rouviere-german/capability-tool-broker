"""The offline demo and every CLI command."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path
from typing import Any

import fakeredis
import pytest
import redis
from fastapi import FastAPI
from opentelemetry import trace as otel_trace

from capability_tool_broker import cli
from capability_tool_broker.agentic.approval import ApprovalStatus, ApprovalStore
from capability_tool_broker.agentic.audit import AuditLog
from capability_tool_broker.approver.service import ApprovalSubmission, ApproverService
from capability_tool_broker.broker.manifest import SignedManifest, ToolManifest
from capability_tool_broker.capabilities.keyfiles import ed25519_public_text, load_ed25519_private
from capability_tool_broker.capabilities.sealed import private_key_text
from capability_tool_broker.core import tracing
from capability_tool_broker.core.app import create_app
from capability_tool_broker.core.config import Settings
from capability_tool_broker.core.security import hash_api_key
from capability_tool_broker.demo import run_demo
from capability_tool_broker.e2e import E2EError
from capability_tool_broker.stack import MANIFEST_KEY_ID
from support import CLIENT, call, make_stack, mint

pytestmark = pytest.mark.integration


def test_demo_contains_the_injection_and_runs_one_approved_write(tmp_path: Path) -> None:
    lines: list[str] = []
    summary = run_demo(tmp_path, out=lines.append)
    assert summary["messages_sent"] == 0
    assert summary["invoice_42_status"] == "approved"
    assert summary["approvals_requested"] == 1
    assert summary["replayed_discharge"] == "replayed"
    assert summary["discharge_on_other_request"] == "caveat_unmet"
    assert summary["audit_ok"] is True
    assert summary["tampered_copy_detected"] is True
    denied = summary["denied"]
    assert isinstance(denied, list)
    assert [item["failed_caveat"] for item in denied] == [  # type: ignore[index,call-overload]
        "resource matches invoice/42",
        "tool in invoices_read",
        "tool in invoices_read,invoices_update_status",
    ]
    text = "\n".join(lines)
    assert "waiting on CLI approval" in text
    assert "failing caveat: resource matches invoice/42" in text
    rerun = run_demo(tmp_path, out=lambda line: None)
    assert rerun["audit_entries"] == summary["audit_entries"]


def test_demo_honours_a_reviewer_who_declines(tmp_path: Path) -> None:
    summary = run_demo(tmp_path, out=lambda line: None, ask=lambda prompt: "n")
    assert summary["invoice_42_status"] == "open"
    assert summary["replayed_discharge"] is None


@pytest.mark.usefixtures("restore_logging")
def test_cli_demo_prints_the_narrative_and_a_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["demo", "--workdir", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "[1] authority minted the task token" in output
    summary = json.loads(output.split("summary:\n", 1)[1])
    assert summary["messages_sent"] == 0


def _env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            name, _, value = line.partition("=")
            values[name] = value
    return values


def test_cli_keygen_and_sign_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env = tmp_path / ".env"
    assert cli.main(["keygen", "--out", str(env)]) == 0
    assert cli.main(["keygen", "--out", str(env)]) == 1
    assert cli.main(["keygen", "--out", str(env), "--force"]) == 0
    values = _env_file(env)
    for name in (
        "AUTHORITY_ROOT_KEYS",
        "BROKER_SERVICE_CREDENTIALS",
        "APPROVER_PRIVATE_KEY",
        "AGENT_CLIENT_PRIVATE_KEY",
    ):
        assert values[name]
    assert values["AUTHORITY_ROOT_KEYS"] == values["BROKER_ROOT_KEYS"]
    out = tmp_path / "manifest.json"
    monkeypatch.delenv("MANIFEST_SIGNING_KEY", raising=False)
    assert cli.main(["sign-manifest", "--out", str(out)]) == 1
    monkeypatch.setenv("MANIFEST_SIGNING_KEY", values["MANIFEST_SIGNING_KEY"])
    assert cli.main(["sign-manifest", "--out", str(out)]) == 0
    public = load_ed25519_private(values["MANIFEST_SIGNING_KEY"]).public_key()
    expected_public = f"{MANIFEST_KEY_ID}:{ed25519_public_text(public)}"
    assert values["BROKER_MANIFEST_PUBLIC_KEYS"] == expected_public
    manifest = ToolManifest.verify(SignedManifest.load(out), {MANIFEST_KEY_ID: public})
    assert manifest.get("invoices_read") is not None
    body = tmp_path / "body.yaml"
    body.write_text(json.dumps(manifest.body.model_dump(mode="json")), encoding="utf-8")
    assert cli.main(["sign-manifest", "--out", str(out), "--body", str(body)]) == 0
    capsys.readouterr()


def test_cli_review_decides_pending_requests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stack = make_stack(tmp_path / "stack")
    try:
        store_path = tmp_path / "approvals.json"
        service = ApproverService(
            private_key=stack.keys.approver_private, store=ApprovalStore(store_path)
        )
        token = mint(stack).token
        denied = call(stack, token, "invoices_update_status", "invoice/42", {"status": "paid"})
        assert denied.approval is not None
        assert denied.canonical_request is not None
        record = service.submit(
            ApprovalSubmission(
                caveat_id=denied.approval.caveat_id, request=denied.canonical_request
            ),
            requested_by=CLIENT,
        )
        monkeypatch.setenv("APPROVER_PRIVATE_KEY", private_key_text(stack.keys.approver_private))
        monkeypatch.setenv("APPROVER_CLIENT_PUBLIC_KEYS", "unused")
        monkeypatch.setenv("APPROVER_STORE_PATH", str(store_path))
        monkeypatch.setenv("APPROVER_AUDIT_PATH", str(tmp_path / "approver-audit.jsonl"))
        assert cli.main(["approver", "review", "--answer", "yes"]) == 0
        assert "1 request(s) decided" in capsys.readouterr().out
        assert ApprovalStore(store_path).get(record.id).status is ApprovalStatus.APPROVED
    finally:
        stack.close()


def test_cli_revoke(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stack = make_stack(tmp_path / "stack")
    try:
        token_file = tmp_path / "token.txt"
        token_file.write_text(mint(stack).token, encoding="utf-8")
        for name in (
            "BROKER_ROOT_KEYS",
            "BROKER_MANIFEST_PUBLIC_KEYS",
            "BROKER_SERVICE_CREDENTIALS",
            "BROKER_CLIENT_PUBLIC_KEYS",
        ):
            monkeypatch.setenv(name, "unused")
        monkeypatch.delenv("BROKER_REDIS_URL", raising=False)
        assert cli.main(["revoke", "--token-file", str(token_file)]) == 1
        fake = fakeredis.FakeRedis()
        monkeypatch.setattr(redis.Redis, "from_url", lambda *args, **kwargs: fake)
        monkeypatch.setenv("BROKER_REDIS_URL", "redis://redis:6379/0")
        assert cli.main(["revoke", "--token-file", str(token_file)]) == 0
        assert list(fake.scan_iter(match="ctb:revoked:*"))
        token_file.write_text("garbage", encoding="utf-8")
        assert cli.main(["revoke", "--token-file", str(token_file)]) == 1
        from capability_tool_broker.macaroons.macaroon import Macaroon

        foreign = Macaroon.create(root_key=b"k", identifier=b"not-a-root-identifier")
        token_file.write_text(foreign.serialize(), encoding="utf-8")
        assert cli.main(["revoke", "--token-file", str(token_file)]) == 1
        capsys.readouterr()
    finally:
        stack.close()


def test_cli_e2e_phases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from capability_tool_broker import e2e
    from capability_tool_broker.agent import clients

    stack = make_stack(tmp_path / "stack")
    try:
        environment = stack.keys.environment()
        for name, value in environment["agent-host"].items():
            monkeypatch.setenv(name, value)
        monkeypatch.setenv(
            "AGENT_MANIFEST_PUBLIC_KEYS", environment["broker"]["BROKER_MANIFEST_PUBLIC_KEYS"]
        )
        monkeypatch.setenv("AGENT_STATE_PATH", str(tmp_path / "state.json"))
        monkeypatch.setattr(
            clients.HttpBrokerClient, "manifest", lambda self: stack.manifest.signed()
        )
        monkeypatch.setattr(e2e, "start_phase", lambda **kwargs: {"phase": "start"})

        def failing(**kwargs: Any) -> dict[str, Any]:
            raise E2EError("not decided")

        monkeypatch.setattr(e2e, "resume_phase", failing)
        assert cli.main(["e2e", "start"]) == 0
        assert json.loads(capsys.readouterr().out) == {"phase": "start"}
        assert cli.main(["e2e", "resume"]) == 1
        assert "not decided" in capsys.readouterr().err
    finally:
        stack.close()


def test_cli_generate_api_key(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["generate-api-key"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["api_key_sha256"] == hash_api_key(payload["api_key"])


def test_cli_audit_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("agent", "step", {})
    assert cli.main(["audit", "verify", str(path), "--expect-head", log.head]) == 0
    assert cli.main(["audit", "verify", str(path)]) == 0
    assert cli.main(["audit", "verify", str(path), "--expect-head", "0" * 64]) == 1
    capsys.readouterr()


@pytest.mark.usefixtures("restore_logging")
def test_cli_serve_builds_the_role_app_and_configures_uvicorn_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uvicorn

    from capability_tool_broker import roles

    captured: dict[str, Any] = {}
    built: list[str] = []

    def fake_run(app: object, **kwargs: Any) -> None:
        captured.update(kwargs, app=app)

    def fake_build(role: str, settings: Settings) -> FastAPI:
        built.append(role)
        return create_app(settings)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setattr(roles, "build_app", fake_build)
    monkeypatch.setattr(tracing, "_installed", [])
    monkeypatch.setattr(otel_trace, "set_tracer_provider", lambda provider: None)
    assert cli.main(["serve", "broker", "--port", "8123"]) == 0
    assert built == ["broker"]
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8123
    assert captured["server_header"] is False
    assert captured["access_log"] is False


def test_module_entry_point(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["capability_tool_broker", "generate-api-key"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("capability_tool_broker", run_name="__main__")
    assert exit_info.value.code == 0
    assert "api_key_sha256" in capsys.readouterr().out
