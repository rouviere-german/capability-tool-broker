"""Forgery suite: every mutation of valid tokens and discharges must be rejected.

Controls first: a minted token authorizes a read, and with a bound approval discharge a write.
Then each attack category produces mutated inputs and runs them through the broker's stateless
decision (manifest, canonical request, chain, discharges, caveats, approval evidence). An attempt
counts as accepted if the broker would authorize it. Categories:

- ``byte_flips_token`` / ``byte_flips_discharge``: every byte of the binary encoding XORed with
  each mask (inputs that no longer parse count as rejected attempts);
- ``base64_mutations``: every character of the token text replaced;
- ``caveat_removal`` and ``caveat_reordering`` (signature kept);
- ``signature_splicing``: signatures moved between parent, child, sibling and other-task tokens,
  truncated and extended caveat lists, swapped identifiers;
- ``discharge_misuse``: unbound, bound to another token, other request, other task, tampered
  discharges, and a holder-added approval caveat with a forged authority tag;
- ``key_confusion``: unknown key ids and tokens from a different root key with the same kid.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path

from capability_tool_broker.approver.service import ApprovalSubmission
from capability_tool_broker.authority.service import TokenRequest
from capability_tool_broker.broker.broker import ToolCall
from capability_tool_broker.capabilities.attenuate import attenuate
from capability_tool_broker.capabilities.caveats import (
    ExpiresBefore,
    Once,
    RequestHashIs,
    ResourceMatches,
    TaskIs,
    ToolIn,
    VerbIn,
)
from capability_tool_broker.capabilities.keys import RootKeyRing
from capability_tool_broker.capabilities.request import Verb
from capability_tool_broker.capabilities.thirdparty import ApprovalCaveatId
from capability_tool_broker.macaroons.codec import b64u_encode
from capability_tool_broker.macaroons.errors import MacaroonFormatError
from capability_tool_broker.macaroons.macaroon import Macaroon
from capability_tool_broker.stack import ManualClock, Stack, build_stack

__all__ = ["ForgeryReport", "run_forgery"]

_CLIENT = "agent-host"
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


@dataclass
class ForgeryReport:
    controls_ok: bool
    attempts: dict[str, int] = field(default_factory=dict)
    accepted: dict[str, int] = field(default_factory=dict)

    @property
    def total_attempts(self) -> int:
        return sum(self.attempts.values())

    @property
    def total_accepted(self) -> int:
        return sum(self.accepted.values())


@dataclass(frozen=True, slots=True)
class _Attempt:
    token: bytes | str
    discharges: tuple[bytes | str, ...]
    call: ToolCall


def _text(value: bytes | str) -> str | None:
    if isinstance(value, str):
        return value
    try:
        return Macaroon.from_bytes(value).serialize()
    except MacaroonFormatError:
        return None


class _Suite:
    def __init__(self, stack: Stack) -> None:
        self.stack = stack
        self.report = ForgeryReport(controls_ok=False)

    def allowed(
        self, token: bytes | str, discharges: Iterable[bytes | str], call: ToolCall
    ) -> bool:
        token_text = _text(token)
        discharge_texts = [_text(item) for item in discharges]
        if token_text is None or any(text is None for text in discharge_texts):
            return False
        decision = self.stack.broker.decide(
            token=token_text,
            discharges=[text for text in discharge_texts if text is not None],
            call=call,
            client_id=_CLIENT,
        )
        return decision.allowed

    def run(self, category: str, attempts: Iterable[_Attempt]) -> None:
        count = accepted = 0
        for attempt in attempts:
            count += 1
            accepted += self.allowed(attempt.token, attempt.discharges, attempt.call)
        self.report.attempts[category] = self.report.attempts.get(category, 0) + count
        self.report.accepted[category] = self.report.accepted.get(category, 0) + accepted


def _flips(raw: bytes, masks: tuple[int, ...]) -> Iterator[bytes]:
    for index in range(len(raw)):
        for mask in masks:
            mutated = bytearray(raw)
            mutated[index] ^= mask
            yield bytes(mutated)


def run_forgery(workdir: Path, *, masks: tuple[int, ...] = (0x01, 0x80, 0xFF)) -> ForgeryReport:
    stack = build_stack(workdir, clock=ManualClock(1_800_000_000))
    try:
        return _run(stack, masks)
    finally:
        stack.close()


def _run(stack: Stack, masks: tuple[int, ...]) -> ForgeryReport:  # noqa: PLR0915 - one block per attack
    suite = _Suite(stack)
    mint = stack.authority.mint
    token_text = mint(
        _CLIENT,
        TokenRequest(template="invoice-review", task_id="task-1", params={"invoice_id": "42"}),
    ).token
    other_text = mint(
        _CLIENT,
        TokenRequest(template="invoice-review", task_id="task-2", params={"invoice_id": "42"}),
    ).token
    token = Macaroon.deserialize(token_text)
    other = Macaroon.deserialize(other_text)
    read = ToolCall(task_id="task-1", tool="invoices_read", resource="invoice/42")
    write = ToolCall(
        task_id="task-1",
        tool="invoices_update_status",
        resource="invoice/42",
        args={"status": "approved"},
    )
    write_other_args = write.model_copy(update={"args": {"status": "paid"}})
    write_task2 = write.model_copy(update={"task_id": "task-2"})

    denial = stack.broker.call(token=token_text, call=write, client_id=_CLIENT)
    if denial.approval is None or denial.canonical_request is None:
        return suite.report
    record = stack.approver.submit(
        ApprovalSubmission(caveat_id=denial.approval.caveat_id, request=denial.canonical_request),
        requested_by=_CLIENT,
    )
    discharge_text = stack.approver.decide(
        record.id, approver="human:reviewer", approve=True
    ).discharge
    if discharge_text is None:  # pragma: no cover
        return suite.report
    discharge = Macaroon.deserialize(discharge_text)
    bound = token.bind(discharge)
    child = attenuate(token, [ToolIn(("invoices_read",)), ResourceMatches(("invoice/42",))])
    suite.report.controls_ok = (
        suite.allowed(token_text, (), read)
        and suite.allowed(token_text, (bound.serialize(),), write)
        and suite.allowed(child.serialize(), (), read)
        and not suite.allowed(child.serialize(), (), write)
    )

    suite.run(
        "byte_flips_token", (_Attempt(raw, (), read) for raw in _flips(token.to_bytes(), masks))
    )
    suite.run(
        "byte_flips_discharge",
        (_Attempt(token_text, (raw,), write) for raw in _flips(bound.to_bytes(), masks)),
    )
    suite.run(
        "base64_mutations",
        (
            _Attempt(token_text[:i] + replacement + token_text[i + 1 :], (), read)
            for i, char in enumerate(token_text)
            for replacement in (
                _B64[(_B64.index(char) + 1) % 64],
                _B64[(_B64.index(char) + 17) % 64],
            )
        ),
    )

    def without(macaroon: Macaroon, index: int) -> Macaroon:
        return replace(macaroon, caveats=macaroon.caveats[:index] + macaroon.caveats[index + 1 :])

    def swapped(macaroon: Macaroon, index: int) -> Macaroon:
        caveats = list(macaroon.caveats)
        caveats[index], caveats[index + 1] = caveats[index + 1], caveats[index]
        return replace(macaroon, caveats=tuple(caveats))

    suite.run(
        "caveat_removal",
        [
            *(_Attempt(without(token, i).to_bytes(), (), read) for i in range(len(token.caveats))),
            *(_Attempt(without(child, i).to_bytes(), (), write) for i in range(len(child.caveats))),
            *(
                _Attempt(
                    without(token, i).to_bytes(),
                    (without(token, i).bind(discharge).to_bytes(),),
                    write,
                )
                for i in range(len(token.caveats))
            ),
            *(
                _Attempt(token_text, (without(discharge, i).to_bytes(),), write)
                for i in range(len(discharge.caveats))
            ),
        ],
    )
    suite.run(
        "caveat_reordering",
        [
            *(
                _Attempt(swapped(token, i).to_bytes(), (), read)
                for i in range(len(token.caveats) - 1)
            ),
            *(
                _Attempt(swapped(child, i).to_bytes(), (), write)
                for i in range(len(child.caveats) - 1)
            ),
            *(
                _Attempt(token_text, (token.bind(swapped(discharge, i)).to_bytes(),), write)
                for i in range(len(discharge.caveats) - 1)
            ),
        ],
    )

    root_count = len(token.caveats)
    sibling = attenuate(token, [VerbIn((Verb.READ,))])
    widened_child = replace(child, caveats=child.caveats[:root_count])
    splices = [
        _Attempt(replace(token, signature=child.signature).to_bytes(), (), read),
        _Attempt(replace(child, signature=token.signature).to_bytes(), (), write),
        _Attempt(widened_child.to_bytes(), (), write),
        _Attempt(replace(child, signature=sibling.signature).to_bytes(), (), write),
        _Attempt(replace(token, signature=other.signature).to_bytes(), (), read),
        _Attempt(replace(token, identifier=other.identifier).to_bytes(), (), read),
        _Attempt(replace(other, caveats=token.caveats).to_bytes(), (), read),
        _Attempt(replace(token, caveats=(*token.caveats, child.caveats[-1])).to_bytes(), (), write),
        _Attempt(replace(bound, signature=token.signature).to_bytes(), (token_text,), write),
        _Attempt(
            token_text,
            (replace(bound, signature=other.bind(discharge).signature).to_bytes(),),
            write,
        ),
    ]
    suite.run("signature_splicing", splices)

    forged_rk = secrets.token_bytes(32)
    resolved = stack.keys.ring.token_key(token.identifier)
    if resolved is None:  # pragma: no cover
        return suite.report
    unapproved = Macaroon.create(root_key=resolved[1], identifier=token.identifier)
    write_verbs = attenuate(
        unapproved,
        [
            TaskIs("task-1"),
            ToolIn(("invoices_update_status",)),
            VerbIn((Verb.WRITE,)),
            ResourceMatches(("invoice/42",)),
            ExpiresBefore(1_800_000_600),
        ],
    )
    fake_id = ApprovalCaveatId(
        location="https://approver.internal/v1",
        scope="verb in write,delete",
        kid="k1",
        box=b64u_encode(secrets.token_bytes(64)),
        tag=b64u_encode(secrets.token_bytes(32)),
    ).encode()
    holder_caveat = write_verbs.add_third_party_caveat(caveat_key=forged_rk, caveat_id=fake_id)
    self_discharge = attenuate(
        Macaroon.create(root_key=forged_rk, identifier=fake_id),
        [RequestHashIs(denial.request_hash or "0" * 64), Once(secrets.token_hex(16))],
    )
    tampered_discharge = replace(discharge, caveats=discharge.caveats[1:])
    misuse = [
        _Attempt(token_text, (discharge_text,), write),
        _Attempt(token_text, (other.bind(discharge).serialize(),), write),
        _Attempt(token_text, (bound.serialize(),), write_other_args),
        _Attempt(other_text, (other.bind(discharge).serialize(),), write_task2),
        _Attempt(token_text, (bound.serialize(), bound.serialize()), write),
        _Attempt(token_text, (token.bind(tampered_discharge).serialize(),), write),
        _Attempt(
            holder_caveat.serialize(), (holder_caveat.bind(self_discharge).serialize(),), write
        ),
        _Attempt(
            token_text, (bound.serialize(), holder_caveat.bind(self_discharge).serialize()), write
        ),
        _Attempt(token_text, (bound.serialize(),), read.model_copy(update={"task_id": "task-2"})),
    ]
    suite.run("discharge_misuse", misuse)

    foreign_ring = RootKeyRing.generate("k1")
    foreign_id = foreign_ring.new_identifier()
    foreign_key = foreign_ring.token_key(foreign_id)
    confusion: list[_Attempt] = []
    if foreign_key is not None:
        foreign = replace(
            Macaroon.create(root_key=foreign_key[1], identifier=foreign_id), caveats=()
        )
        for caveat in token.caveats:
            if caveat.verification_id is None:
                foreign = foreign.add_first_party_caveat(caveat.caveat_id)
        confusion.append(_Attempt(foreign.to_bytes(), (), read))
        unknown_kid = Macaroon.create(root_key=b"k" * 32, identifier=b"ctb1:k9:" + b"0" * 32)
        confusion.append(_Attempt(unknown_kid.to_bytes(), (), read))
        confusion.append(
            _Attempt(
                Macaroon.create(root_key=b"guess", identifier=token.identifier).to_bytes(), (), read
            )
        )
    suite.run("key_confusion", confusion)
    return suite.report
