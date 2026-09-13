"""The approver: request validation, discharge minting, separation of duties and the review CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from capability_tool_broker.agentic.approval import ApprovalRecord, ApprovalStatus, ApprovalStore
from capability_tool_broker.agentic.errors import ApprovalError
from capability_tool_broker.approver.cli import render_request, review_pending
from capability_tool_broker.approver.service import (
    ApprovalSubmission,
    ApproverError,
    ApproverService,
)
from capability_tool_broker.broker.broker import BrokerOutcome
from capability_tool_broker.capabilities.caveats import ExpiresBefore, parse_caveat
from capability_tool_broker.capabilities.request import CanonicalRequest, Verb
from capability_tool_broker.capabilities.sealed import generate_private_key
from capability_tool_broker.macaroons.macaroon import Macaroon
from capability_tool_broker.stack import Stack
from support import CLIENT, REVIEWER, T0, advance, call, make_stack, mint

pytestmark = pytest.mark.unit


@pytest.fixture
def stack(tmp_path: Path) -> Stack:
    return make_stack(tmp_path)


def write_denial(stack: Stack, status: str = "approved") -> BrokerOutcome:
    token = mint(stack).token
    outcome = call(stack, token, "invoices_update_status", "invoice/42", {"status": status})
    assert outcome.reason == "approval_required"
    return outcome


def submission(outcome: BrokerOutcome, **request_overrides: object) -> ApprovalSubmission:
    assert outcome.approval is not None
    assert outcome.canonical_request is not None
    request = outcome.canonical_request.model_copy(update=request_overrides)
    return ApprovalSubmission(caveat_id=outcome.approval.caveat_id, request=request)


def test_approval_mints_a_discharge_bound_to_the_exact_request(stack: Stack) -> None:
    outcome = write_denial(stack)
    record = stack.approver.submit(submission(outcome), requested_by=CLIENT)
    assert record.status is ApprovalStatus.PENDING
    assert stack.approver.submit(submission(outcome), requested_by=CLIENT).id == record.id
    decided = stack.approver.decide(record.id, approver=REVIEWER, approve=True)
    assert decided.discharge is not None
    discharge = Macaroon.deserialize(decided.discharge)
    conditions = [parse_caveat(c.caveat_id.decode()) for c in discharge.caveats]
    assert [type(c).__name__ for c in conditions] == [
        "RequestHashIs",
        "TaskIs",
        "ExpiresBefore",
        "Once",
    ]
    assert conditions[0] == parse_caveat(f"request_hash = {outcome.request_hash}")
    expires = conditions[2]
    assert isinstance(expires, ExpiresBefore)
    assert expires.at == T0 + 120


def test_submissions_are_validated_against_the_sealed_caveat(stack: Stack) -> None:
    outcome = write_denial(stack)
    with pytest.raises(ApproverError) as mismatch:
        stack.approver.submit(submission(outcome, task_id="task-2"), requested_by=CLIENT)
    assert mismatch.value.code == "task_mismatch"
    with pytest.raises(ApproverError) as scope:
        stack.approver.submit(submission(outcome, verb=Verb.READ), requested_by=CLIENT)
    assert scope.value.code == "out_of_scope"
    assert outcome.approval is not None
    assert outcome.canonical_request is not None
    for bad in ("!!", "AAAA"):
        with pytest.raises(ApproverError) as invalid:
            stack.approver.submit(
                ApprovalSubmission(caveat_id=bad, request=outcome.canonical_request),
                requested_by=CLIENT,
            )
        assert invalid.value.code == "invalid_caveat"
    advance(stack, 601)
    with pytest.raises(ApproverError) as expired:
        stack.approver.submit(submission(outcome), requested_by=CLIENT)
    assert expired.value.code == "caveat_expired"


def test_caveats_sealed_to_another_approver_are_refused(stack: Stack) -> None:
    outcome = write_denial(stack)
    other = ApproverService(private_key=generate_private_key(), store=ApprovalStore())
    with pytest.raises(ApproverError, match="not issued for this approver"):
        other.submit(submission(outcome), requested_by=CLIENT)


def test_separation_of_duties_and_single_decisions(stack: Stack) -> None:
    record = stack.approver.submit(submission(write_denial(stack)), requested_by=CLIENT)
    with pytest.raises(ApprovalError, match="separation of duties"):
        stack.approver.decide(record.id, approver=CLIENT, approve=True)
    denied = stack.approver.decide(record.id, approver=REVIEWER, approve=False, reason="no")
    assert denied.status is ApprovalStatus.DENIED
    assert denied.discharge is None
    with pytest.raises(ApprovalError, match="not pending"):
        stack.approver.decide(record.id, approver=REVIEWER, approve=True)
    with pytest.raises(ApprovalError, match="unknown"):
        stack.approver.decide("f" * 32, approver=REVIEWER, approve=True)


def test_requesters_see_only_their_own_requests(stack: Stack) -> None:
    record = stack.approver.submit(submission(write_denial(stack)), requested_by=CLIENT)
    assert stack.approver.fetch(record.id, requested_by=CLIENT).id == record.id
    with pytest.raises(ApprovalError):
        stack.approver.fetch(record.id, requested_by="other-client")
    with pytest.raises(ApprovalError):
        stack.approver.fetch("not-an-id", requested_by=CLIENT)


def test_expired_requests_cannot_be_decided(stack: Stack) -> None:
    store = ApprovalStore(clock=stack.clock, ttl_seconds=10)
    service = ApproverService(
        private_key=stack.keys.approver_private, store=store, clock=stack.clock
    )
    record = service.submit(submission(write_denial(stack)), requested_by=CLIENT)
    advance(stack, 11)
    assert service.pending() == []
    with pytest.raises(ApprovalError, match="expired"):
        service.decide(record.id, approver=REVIEWER, approve=False)


def test_approving_after_the_caveat_expired_is_refused(stack: Stack) -> None:
    record = stack.approver.submit(submission(write_denial(stack)), requested_by=CLIENT)
    advance(stack, 601)
    with pytest.raises(ApproverError, match="expired"):
        stack.approver.decide(record.id, approver=REVIEWER, approve=True)


def test_a_persisted_queue_is_shared_and_refuses_tampered_records(
    tmp_path: Path, stack: Stack
) -> None:
    path = tmp_path / "approvals.json"
    first = ApprovalStore(path, clock=stack.clock)
    second = ApprovalStore(path, clock=stack.clock)
    outcome = write_denial(stack)
    assert outcome.canonical_request is not None
    assert outcome.approval is not None
    record = first.submit(
        outcome.canonical_request, caveat_id=outcome.approval.caveat_id, requested_by=CLIENT
    )
    assert [r.id for r in second.pending()] == [record.id]
    second.decide(record.id, approver=REVIEWER, approve=False)
    assert first.get(record.id).status is ApprovalStatus.DENIED
    fresh = first.submit(outcome.canonical_request, caveat_id="x", requested_by=CLIENT)
    with pytest.raises(ApprovalError, match="needs a discharge"):
        first.decide(fresh.id, approver=REVIEWER, approve=True)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["records"][0]["request"]["resource"] = "invoice/43"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ApprovalError, match="failed validation"):
        first.pending()


def test_review_cli_shows_escaped_requests_and_records_decisions(stack: Stack) -> None:
    token = mint(stack, "file-maintenance").token
    content = "hello\x1b[2J\x1b[Hinvisible"
    outcome = call(stack, token, "files_write", "file/notes.txt", {"content": content})
    assert outcome.reason == "approval_required"
    stack.approver.submit(submission(outcome), requested_by=CLIENT)
    shown: list[str] = []
    decided = review_pending(
        stack.approver, approver=REVIEWER, ask=lambda _: "yes", show=shown.append
    )
    assert [record.status for record in decided] == [ApprovalStatus.APPROVED]
    rendered = "\n".join(shown)
    assert "\x1b" not in rendered
    assert "\\u001b[2J" in rendered
    assert "files_write (write on files.internal)" in rendered
    assert render_request(decided[0]).startswith("approval request")


def test_records_must_match_their_request_hash() -> None:
    request = CanonicalRequest(
        task_id="t", tool="files_read", verb=Verb.READ, host="files.internal", resource="file/a"
    )
    with pytest.raises(ValueError, match="request_hash"):
        ApprovalRecord(
            id="a" * 32,
            request_hash="0" * 64,
            request=request.canonical_dict(),
            caveat_id="x",
            requested_by=CLIENT,
            requested_at=0.0,
        )
