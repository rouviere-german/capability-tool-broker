"""Stateful semantics over time: the broker against a sequential reference model.

The soundness oracle checks stateless decisions only. This harness drives the full broker
(verifier, approval policy, state store) through random interleavings of:

- reads with the root token or any delegated descendant,
- delegation (appending a short expiry and/or a ``max_calls`` caveat to any token),
- approvals (the approver mints a discharge for the write request),
- attenuating a discharge (appending a short expiry),
- writes with any token and any discharge,
- clock advances, including jumps past the state store's expiry grace period.

The reference model never touches macaroons, the verifier or the store. It tracks each
``max_calls`` caveat by the tuple of caveats up to and including it (structural identity: every
holder of that prefix shares the counter) and each approval by its id. A call is allowed exactly
when every expiry in the presented token and discharge lies in the future, every counter on the
token is below its limit and, for writes, the approval was never used. Allowed calls increment
every counter and use the approval; denied calls change nothing. In this model counters never
reset, so a store that forgets a counter while any holder can still present it is a mismatch.
"""

from __future__ import annotations

import random
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from capability_tool_broker.agentic.approval import ApprovalStore
from capability_tool_broker.approver.service import (
    ApprovalSubmission,
    ApproverError,
    ApproverService,
)
from capability_tool_broker.broker.broker import Broker, ToolCall
from capability_tool_broker.broker.manifest import ManifestHolder
from capability_tool_broker.broker.state import MemoryStateStore, StateStore
from capability_tool_broker.capabilities.attenuate import attenuate
from capability_tool_broker.capabilities.caveats import (
    CaveatSyntaxError,
    ExpiresBefore,
    MaxCalls,
    Predicate,
    parse_caveat,
)
from capability_tool_broker.capabilities.thirdparty import add_approval_caveat
from capability_tool_broker.macaroons.codec import b64u_encode
from capability_tool_broker.macaroons.macaroon import Macaroon
from capability_tool_broker.stack import ManualClock, Stack, build_stack

__all__ = ["StatefulReport", "run_stateful"]

T0 = 1_800_000_000
CLIENT = "agent-host"
REVIEWER = "human:reviewer"
TASK = "task-1"
ROOT_TTL = 900
APPROVER_TTL = 900
READ = ToolCall(task_id=TASK, tool="invoices_read", resource="invoice/42")
WRITE = ToolCall(
    task_id=TASK, tool="invoices_update_status", resource="invoice/42", args={"status": "approved"}
)
_STATELESS = (
    f"task_id = {TASK}",
    f"client in {CLIENT}",
    "tool in invoices_read,invoices_update_status",
    "verb in read,write",
    "resource matches invoice/42",
)

Spec = tuple[str, int | str]


@dataclass
class _Token:
    macaroon: Macaroon
    specs: tuple[Spec, ...]


@dataclass
class _Discharge:
    macaroon: Macaroon
    approval: str
    expiries: tuple[int, ...]


@dataclass
class _Model:
    counters: dict[tuple[Spec, ...], int] = field(default_factory=dict)
    used: set[str] = field(default_factory=set)

    def decide(self, token: _Token, discharge: _Discharge | None, now: int) -> tuple[bool, bool]:
        """(allowed, denied only by state) for a call."""
        expiries = [int(value) for kind, value in token.specs if kind == "expires"]
        if discharge is not None:
            expiries.extend(discharge.expiries)
        if any(now >= at for at in expiries):
            return False, False
        counters = [
            (token.specs[: index + 1], int(value))
            for index, (kind, value) in enumerate(token.specs)
            if kind == "max_calls"
        ]
        if any(self.counters.get(prefix, 0) >= limit for prefix, limit in counters):
            return False, True
        if discharge is not None and discharge.approval in self.used:
            return False, True
        for prefix, _ in counters:
            self.counters[prefix] = self.counters.get(prefix, 0) + 1
        if discharge is not None:
            self.used.add(discharge.approval)
        return True, False


@dataclass
class StatefulReport:
    sequences: int
    steps: int
    calls: int
    allowed: int
    denied_by_state: int
    mismatches: int
    examples: list[str]


class _Sequence:
    def __init__(self, stack: Stack, clock: ManualClock, rng: random.Random, state: StateStore):
        self.stack = stack
        self.clock = clock
        self.rng = rng
        self.broker = Broker(
            ring=stack.keys.ring,
            manifest=ManifestHolder.from_manifest(stack.manifest),
            state=state,
            credentials=stack.keys.credentials(),
            http=stack.http,
            clock=clock,
        )
        self.approver = ApproverService(
            private_key=stack.keys.approver_private,
            store=ApprovalStore(clock=clock),
            clock=clock,
            discharge_ttl_seconds=APPROVER_TTL,
        )
        now = self.now
        limit = rng.randint(2, 6)
        ring = stack.keys.ring
        identifier = ring.new_identifier()
        resolved = ring.token_key(identifier)
        if resolved is None:  # pragma: no cover - identifiers come from this ring
            raise RuntimeError("ring cannot resolve its own identifier")
        root = Macaroon.create(root_key=resolved[1], identifier=identifier)
        for condition in _STATELESS:
            root = root.add_first_party_caveat(condition)
        root = attenuate(root, [ExpiresBefore(now + ROOT_TTL), MaxCalls(limit)])
        root = add_approval_caveat(
            root,
            ring=ring,
            approver_public_key=stack.keys.approver_private.public_key(),
            location="https://approver.internal/v1",
            task_id=TASK,
            expires_at=now + ROOT_TTL,
        )
        specs: tuple[Spec, ...] = (
            ("expires", now + ROOT_TTL),
            ("max_calls", limit),
            ("approval", 0),
        )
        self.caveat_id = root.caveats[-1].caveat_id
        self.tokens = [_Token(root, specs)]
        self.discharges: list[_Discharge] = []
        self.model = _Model()
        self.calls = self.allowed = self.denied_by_state = 0
        self.mismatches: list[str] = []

    @property
    def now(self) -> int:
        return int(self.clock())

    def step(self, index: int) -> None:
        roll = self.rng.random()
        if roll < 0.30:
            self._call(self.rng.choice(self.tokens), None, index)
        elif roll < 0.48 and self.discharges:
            self._call(self.rng.choice(self.tokens), self.rng.choice(self.discharges), index)
        elif roll < 0.62:
            self._delegate()
        elif roll < 0.72:
            self._approve()
        elif roll < 0.80 and self.discharges:
            self._attenuate_discharge()
        else:
            self.clock.advance(self.rng.choice((1, 60, 150, 302, 400)))

    def _delegate(self) -> None:
        parent = self.rng.choice(self.tokens)
        added: list[Predicate] = []
        specs = list(parent.specs)
        if self.rng.random() < 0.7:
            at = self.now + self.rng.choice((1, 30, 120, 400))
            added.append(ExpiresBefore(at))
            specs.append(("expires", at))
        if self.rng.random() < 0.4 or not added:
            limit = self.rng.randint(1, 3)
            added.append(MaxCalls(limit))
            specs.append(("max_calls", limit))
        self.tokens.append(_Token(attenuate(parent.macaroon, added), tuple(specs)))

    def _approve(self) -> None:
        decision = self.broker.decide(
            token=self.tokens[0].macaroon.serialize(), discharges=(), call=WRITE, client_id=CLIENT
        )
        if decision.request is None:  # pragma: no cover - the write request is always valid
            return
        try:
            record = self.approver.submit(
                ApprovalSubmission(caveat_id=b64u_encode(self.caveat_id), request=decision.request),
                requested_by=CLIENT,
            )
            decided = self.approver.decide(record.id, approver=REVIEWER, approve=True)
        except ApproverError:
            return  # the approval caveat has expired: nothing to discharge
        if decided.discharge is None:  # pragma: no cover - approvals always mint a discharge
            return
        discharge = Macaroon.deserialize(decided.discharge)
        expiries = tuple(
            at for caveat in discharge.caveats if (at := _expiry_of(caveat.caveat_id)) is not None
        )
        self.discharges.append(_Discharge(discharge, record.id, expiries))

    def _attenuate_discharge(self) -> None:
        parent = self.rng.choice(self.discharges)
        at = self.now + self.rng.choice((1, 30, 120))
        self.discharges.append(
            _Discharge(
                attenuate(parent.macaroon, [ExpiresBefore(at)]),
                parent.approval,
                (*parent.expiries, at),
            )
        )

    def _call(self, token: _Token, discharge: _Discharge | None, index: int) -> None:
        serialized = token.macaroon.serialize()
        bound = () if discharge is None else (token.macaroon.bind(discharge.macaroon).serialize(),)
        outcome = self.broker.call(
            token=serialized,
            discharges=bound,
            call=READ if discharge is None else WRITE,
            client_id=CLIENT,
        )
        expected, by_state = self.model.decide(token, discharge, self.now)
        self.calls += 1
        self.allowed += outcome.allowed
        self.denied_by_state += by_state
        if outcome.allowed != expected:
            kind = "read" if discharge is None else "write"
            self.mismatches.append(
                f"step {index}: {kind} with {len(token.specs)}-caveat token at t+"
                f"{self.now - T0}: broker {outcome.reason}, model allowed={expected}"
            )


def _expiry_of(condition: bytes) -> int | None:
    """The approver's expiry in its discharge (read back to seed the model, not to decide)."""
    try:
        predicate = parse_caveat(condition.decode("utf-8"))
    except (UnicodeDecodeError, CaveatSyntaxError):  # pragma: no cover - approver output parses
        return None
    return predicate.at if isinstance(predicate, ExpiresBefore) else None


def run_stateful(
    *,
    sequences: int = 200,
    steps: int = 40,
    seed: int = 7,
    workdir: Path | None = None,
    store_factory: Callable[[], StateStore] = MemoryStateStore,
) -> StatefulReport:
    rng = random.Random(seed)  # noqa: S311 - deterministic test-case generation, not cryptography
    with tempfile.TemporaryDirectory() as tmp:
        clock = ManualClock(T0)
        stack = build_stack(workdir or Path(tmp), clock=clock)
        try:
            totals = StatefulReport(sequences, 0, 0, 0, 0, 0, [])
            for _ in range(sequences):
                sequence = _Sequence(stack, clock, rng, store_factory())
                for index in range(steps):
                    sequence.step(index)
                totals.steps += steps
                totals.calls += sequence.calls
                totals.allowed += sequence.allowed
                totals.denied_by_state += sequence.denied_by_state
                totals.mismatches += len(sequence.mismatches)
                totals.examples.extend(sequence.mismatches[: max(0, 5 - len(totals.examples))])
                clock.advance(ROOT_TTL + 1)  # the next sequence starts with fresh tokens
            return totals
        finally:
            stack.close()
