"""Minting from policy: caveats per template, client restrictions and parameter safety."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from capability_tool_broker.authority.policy import Policy, PolicyError
from capability_tool_broker.authority.service import AuthorityError, TokenRequest
from capability_tool_broker.capabilities.thirdparty import ApprovalCaveatId
from capability_tool_broker.deploy import default_policy
from capability_tool_broker.macaroons.macaroon import Macaroon
from capability_tool_broker.stack import Stack
from support import T0, make_stack, mint

pytestmark = pytest.mark.unit


@pytest.fixture
def stack(tmp_path: Path) -> Stack:
    return make_stack(tmp_path)


def test_minted_tokens_carry_the_template_caveats(stack: Stack) -> None:
    minted = mint(stack, "invoice-review", task_id="review-42")
    assert minted.caveats[:8] == [
        "task_id = review-42",
        "client in agent-host",
        "tool in invoices_read,invoices_update_status",
        "verb in read,write",
        "resource matches invoice/42",
        "expires < 2027-01-15T08:10:00Z",
        "host in invoices.internal",
        "max_calls <= 20",
    ]
    assert minted.expires_at == T0 + 600
    assert minted.caveats[-1].startswith("third-party approval by https://approver.internal/v1")
    token = Macaroon.deserialize(minted.token)
    assert token.identifier.decode().endswith(minted.token_id)
    assert minted.budget.steps == 20


def test_only_side_effect_templates_get_an_approval_caveat(stack: Stack) -> None:
    audit_token = Macaroon.deserialize(mint(stack, "invoice-audit").token)
    assert all(caveat.verification_id is None for caveat in audit_token.caveats)
    review_token = Macaroon.deserialize(mint(stack, "invoice-review").token)
    third_party = [c for c in review_token.caveats if c.verification_id is not None]
    assert len(third_party) == 1
    parsed = ApprovalCaveatId.decode(third_party[0].caveat_id)
    assert parsed is not None
    assert parsed.scope == "verb in write,delete"
    assert parsed.kid == "k1"


def test_clients_and_templates_are_enforced(stack: Stack) -> None:
    with pytest.raises(AuthorityError) as unknown_client:
        mint(stack, client="stranger")
    assert unknown_client.value.code == "forbidden"
    with pytest.raises(AuthorityError) as unknown_template:
        mint(stack, "does-not-exist")
    assert unknown_template.value.code == "forbidden"


@pytest.mark.parametrize("value", ["*", "4*", "?", "..", "4/2", "", "42 ", "**", "abc"])
def test_parameter_values_can_never_widen_a_resource_glob(stack: Stack, value: str) -> None:
    with pytest.raises(AuthorityError) as error:
        mint(stack, "invoice-review", params={"invoice_id": value})
    assert error.value.code == "invalid_params"


def test_parameters_must_match_the_template_exactly(stack: Stack) -> None:
    with pytest.raises(AuthorityError):
        mint(stack, "invoice-review", params={})
    with pytest.raises(AuthorityError):
        mint(stack, "invoice-review", params={"invoice_id": "42", "extra": "1"})


def test_lifetimes_are_capped_by_template_and_policy(stack: Stack) -> None:
    assert mint(stack, "invoice-review", ttl_seconds=60).expires_at == T0 + 60
    assert mint(stack, "invoice-review", ttl_seconds=86_000).expires_at == T0 + 600


def test_minting_is_audited(stack: Stack) -> None:
    minted = mint(stack, "invoice-audit", task_id="audit-1")
    entries = [
        json.loads(line) for line in stack.audit.path.read_text(encoding="utf-8").splitlines()
    ]
    assert entries[-1]["action"] == "authority.mint"
    assert entries[-1]["data"]["token_id"] == minted.token_id
    assert entries[-1]["data"]["task_id"] == "audit-1"


def test_token_requests_validate_their_shape() -> None:
    with pytest.raises(ValueError, match="pattern"):
        TokenRequest(template="Bad Name", task_id="t")


POLICY = """
version: 1
approver_location: "https://approver.internal/v1"
max_ttl_seconds: 600
clients:
  agent-host: {templates: [t]}
templates:
  t:
    description: test
    tools: [invoices_read]
    verbs: [read]
    resources: ["invoice/{id}"]
    params: {id: "[0-9]+"}
    ttl_seconds: 60
    budget: {steps: 1, tokens: 1, usd: 0}
"""


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("version: 1", "version: 2"),
        ("agent-host: {templates: [t]}", "agent-host: {templates: [missing]}"),
        ("agent-host:", "Bad Client:"),
        ('"invoice/{id}"', '"invoice/{other}"'),
        ('"invoice/{id}"', '"invoice/a**"'),
        ('{id: "[0-9]+"}', '{id: "[0-9"}'),
        ("[invoices_read]", "[Invoices]"),
        ("ttl_seconds: 60", "ttl_seconds: 60\n    arg_caveats: ['tool in x']"),
        ("ttl_seconds: 60", "ttl_seconds: 60\n    arg_caveats: ['not a caveat']"),
        ("ttl_seconds: 60", "ttl_seconds: 60\n    approval_scope: 'max_calls <= 1'"),
        ("ttl_seconds: 60", "ttl_seconds: 60\n    approval_scope: 'bogus'"),
        ("ttl_seconds: 60", "ttl_seconds: 60\n    hosts: ['NOT A HOST']"),
        ("  t:\n", "  T!:\n"),
        ("version: 1", "version: [unclosed"),
    ],
)
def test_invalid_policies_are_rejected(old: str, new: str) -> None:
    assert Policy.from_yaml(POLICY).templates["t"].ttl_seconds == 60
    assert old in POLICY
    with pytest.raises(PolicyError):
        Policy.from_yaml(POLICY.replace(old, new, 1))


def test_policies_load_from_files(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY, encoding="utf-8")
    assert Policy.load(path).clients["agent-host"].templates == ("t",)
    assert "invoice-review" in default_policy().templates
