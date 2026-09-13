"""Roles sign audit checkpoints when a checkpoint key is configured and refuse rolled-back logs."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest
from pydantic import SecretStr

from capability_tool_broker.agentic.audit import AuditLog
from capability_tool_broker.agentic.errors import AuditIntegrityError
from capability_tool_broker.macaroons.codec import b64u_encode
from capability_tool_broker.roles import audit_log

pytestmark = pytest.mark.integration


def test_role_audit_logs_sign_checkpoints_and_refuse_a_truncated_log(tmp_path: Path) -> None:
    key = SecretStr(b64u_encode(secrets.token_bytes(32)))
    path = tmp_path / "authority-audit.jsonl"
    log = audit_log(path, key, None)
    for index in range(3):
        log.append("agent-host", "authority.mint", {"index": index})
    assert (tmp_path / "checkpoints" / "authority-audit.jsonl.checkpoint").exists()
    first_line = path.read_text(encoding="utf-8").splitlines(keepends=True)[0]
    path.write_text(first_line, encoding="utf-8", newline="\n")
    with pytest.raises(AuditIntegrityError, match="behind its last checkpoint"):
        audit_log(path, key, None)
    elsewhere = tmp_path / "anchor" / "broker.checkpoint"
    audit_log(tmp_path / "broker-audit.jsonl", key, elsewhere).append("b", "broker.authorize")
    assert elsewhere.exists()


def test_role_audit_log_configuration_is_validated(tmp_path: Path) -> None:
    assert isinstance(audit_log(tmp_path / "plain.jsonl", None, None), AuditLog)
    with pytest.raises(ValueError, match="needs an audit checkpoint key"):
        audit_log(tmp_path / "x.jsonl", None, tmp_path / "x.checkpoint")
    with pytest.raises(ValueError, match="at least 32 bytes"):
        audit_log(tmp_path / "y.jsonl", SecretStr(b64u_encode(b"short")), None)
