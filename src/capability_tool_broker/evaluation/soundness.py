"""Soundness of caveat evaluation against an independent reference evaluator.

Universe: 5 tools x 20 resources x 3 verbs x 3 time steps = 900 requests. Task id and caller are
fixed, the host follows from the tool, and each request carries a deterministic ``amount``
argument so argument caveats are exercised too.

For every random caveat chain, the real system mints a macaroon, serializes it, parses it
back and verifies the parsed token once per request. The reference evaluator never touches
the DSL, the parser, the glob matcher or the verifier: it interprets the abstract caveat specs
directly, with its own recursive glob matcher. The two authorized sets must be equal. Each
chain also gets a child with 1 to 3 appended random caveats, whose authorized set must be a
subset of the parent's.

Third-party approval caveats with a verb scope are part of the generator; without a discharge the
reference rule is "denied exactly when the verb is in scope". Stateful caveats (``max_calls``) are
generated as well: they must never change a stateless authorization decision.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache

from capability_tool_broker.capabilities.keys import RootKeyRing
from capability_tool_broker.capabilities.request import CanonicalRequest, RequestContext, Verb
from capability_tool_broker.capabilities.sealed import generate_private_key
from capability_tool_broker.capabilities.thirdparty import add_approval_caveat
from capability_tool_broker.capabilities.verifier import Authorization, MacaroonVerifier
from capability_tool_broker.macaroons.macaroon import Macaroon

__all__ = [
    "RESOURCES",
    "TIMES",
    "TOOLS",
    "SoundnessReport",
    "Spec",
    "UniverseRequest",
    "oracle_allows",
    "random_chain",
    "run_soundness",
    "universe",
]

T0 = 1_800_000_000
TASK = "task-1"
CLIENT = "agent-host"
TOOLS = ("invoices_read", "invoices_update_status", "files_read", "files_write", "mail_send")
HOSTS = {
    "invoices_read": "invoices.internal",
    "invoices_update_status": "invoices.internal",
    "files_read": "files.internal",
    "files_write": "files.internal",
    "mail_send": "mailer.internal",
}
RESOURCES = (
    "invoice/1",
    "invoice/2",
    "invoice/12",
    "invoice/42",
    "invoice/43",
    "invoice/42/lines",
    "invoice/43/lines",
    "file/a.txt",
    "file/b.txt",
    "file/notes/c.txt",
    "file/notes/d.md",
    "mail/alice@example.com",
    "mail/bob@example.com",
    "mail/eve@evil.example",
    "report/2026/q1",
    "report/2026/q2",
    "report/2025/q4",
    "archive/x",
    "archive/y/z",
    "tmp",
)
VERBS = ("read", "write", "delete")
TIMES = (T0, T0 + 300, T0 + 900)
_KINDS = ("task", "client", "tool", "verb", "host", "resource", "expires", "arg", "max", "approval")
_WEIGHTS = (1, 1, 3, 3, 1, 4, 2, 2, 1, 1)
_ARG_OPS = ("=", "!=", "<", "<=", ">", ">=")


@dataclass(frozen=True, slots=True)
class Spec:
    """An abstract caveat, interpreted independently by the oracle and rendered for the SUT."""

    kind: str
    values: tuple[str, ...] = ()
    number: int = 0
    op: str = ""


@dataclass(frozen=True, slots=True)
class UniverseRequest:
    tool: str
    resource: str
    verb: str
    now: int
    amount: int


def universe() -> list[UniverseRequest]:
    requests: list[UniverseRequest] = []
    for t_index, tool in enumerate(TOOLS):
        for r_index, resource in enumerate(RESOURCES):
            for v_index, verb in enumerate(VERBS):
                amount = ((t_index * 7 + r_index * 3 + v_index) % 5) * 100
                requests.extend(UniverseRequest(tool, resource, verb, now, amount) for now in TIMES)
    return requests


# --- generator ----------------------------------------------------------------------------------


def _random_glob(rng: random.Random) -> str:
    segments = rng.choice(RESOURCES).split("/")
    out: list[str] = []
    for segment in segments:
        roll = rng.random()
        if roll < 0.15:
            out.append("*")
        elif roll < 0.25:
            out.append("**")
        elif roll < 0.35 and len(segment) > 1:
            position = rng.randrange(len(segment))
            out.append(segment[:position] + "?" + segment[position + 1 :])
        elif roll < 0.45:
            out.append(segment[: rng.randrange(1, len(segment) + 1)] + "*")
        else:
            out.append(segment)
    if rng.random() < 0.1:
        out.append("**")
    return "/".join(out)


def random_spec(rng: random.Random) -> Spec:  # noqa: PLR0911 - one branch per caveat kind
    kind = rng.choices(_KINDS, _WEIGHTS)[0]
    if kind == "task":
        return Spec(kind, (rng.choice([TASK, TASK, TASK, "task-2"]),))
    if kind == "client":
        return Spec(kind, rng.choice([(CLIENT,), ("other",), (CLIENT, "other")]))
    if kind == "tool":
        pool = [*TOOLS, "other_tool"]
        return Spec(kind, tuple(rng.sample(pool, rng.randint(1, 3))))
    if kind == "verb":
        return Spec(kind, tuple(rng.sample(VERBS, rng.randint(1, 2))))
    if kind == "host":
        pool = [*sorted(set(HOSTS.values())), "other.internal"]
        return Spec(kind, tuple(rng.sample(pool, rng.randint(1, 2))))
    if kind == "resource":
        globs = {_random_glob(rng) for _ in range(rng.randint(1, 2))}
        return Spec(kind, tuple(sorted(globs)))
    if kind == "expires":
        return Spec(kind, number=T0 + rng.choice([0, 1, 300, 301, 600, 900, 1200]))
    if kind == "arg":
        return Spec(kind, op=rng.choice(_ARG_OPS), number=rng.choice([0, 100, 200, 250, 400]))
    if kind == "max":
        return Spec(kind, number=rng.randint(1, 5))
    return Spec("approval", tuple(rng.sample(VERBS, rng.randint(1, 2))))


def random_chain(rng: random.Random, low: int = 1, high: int = 6) -> list[Spec]:
    return [random_spec(rng) for _ in range(rng.randint(low, high))]


# --- the reference evaluator (independent of the DSL, parser, glob matcher and verifier) ---------


def _oracle_segment(pattern: str, value: str) -> bool:
    @cache
    def match(i: int, j: int) -> bool:
        if i == len(pattern):
            return j == len(value)
        if pattern[i] == "*":
            return match(i + 1, j) or (j < len(value) and match(i, j + 1))
        return j < len(value) and pattern[i] in ("?", value[j]) and match(i + 1, j + 1)

    return match(0, 0)


def _oracle_glob(pattern: str, resource: str) -> bool:
    parts, values = pattern.split("/"), resource.split("/")

    @cache
    def match(i: int, j: int) -> bool:
        if i == len(parts):
            return j == len(values)
        if parts[i] == "**":
            return match(i + 1, j) or (j < len(values) and match(i, j + 1))
        return j < len(values) and _oracle_segment(parts[i], values[j]) and match(i + 1, j + 1)

    return match(0, 0)


def oracle_allows(specs: Sequence[Spec], request: UniverseRequest) -> bool:  # noqa: PLR0911
    for spec in specs:
        if spec.kind == "task" and spec.values[0] != TASK:
            return False
        if spec.kind == "client" and CLIENT not in spec.values:
            return False
        if spec.kind == "tool" and request.tool not in spec.values:
            return False
        if spec.kind == "verb" and request.verb not in spec.values:
            return False
        if spec.kind == "host" and HOSTS[request.tool] not in spec.values:
            return False
        if spec.kind == "resource" and not any(
            _oracle_glob(g, request.resource) for g in spec.values
        ):
            return False
        if spec.kind == "expires" and not request.now < spec.number:
            return False
        if spec.kind == "arg" and not _oracle_compare(request.amount, spec.op, spec.number):
            return False
        if spec.kind == "approval" and request.verb in spec.values:
            return False
    return True


def _oracle_compare(left: int, op: str, right: int) -> bool:
    table = {
        "=": left == right,
        "!=": left != right,
        "<": left < right,
        "<=": left <= right,
        ">": left > right,
        ">=": left >= right,
    }
    return table[op]


# --- the system under test ----------------------------------------------------------------------


def _condition(spec: Spec) -> str:
    if spec.kind == "task":
        return f"task_id = {spec.values[0]}"
    if spec.kind in {"client", "tool", "verb", "host"}:
        return f"{spec.kind} in {','.join(spec.values)}"
    if spec.kind == "resource":
        return f"resource matches {','.join(spec.values)}"
    if spec.kind == "expires":
        return "expires < " + datetime.fromtimestamp(spec.number, UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    if spec.kind == "arg":
        return f"arg amount {spec.op} {spec.number}"
    return f"max_calls <= {spec.number}"


@dataclass
class _System:
    ring: RootKeyRing
    verifier: MacaroonVerifier
    approver_public: object
    contexts: list[RequestContext]


def _system(requests: Sequence[UniverseRequest]) -> _System:
    ring = RootKeyRing.generate()
    contexts = [
        RequestContext(
            request=CanonicalRequest(
                task_id=TASK,
                tool=r.tool,
                verb=Verb(r.verb),
                host=HOSTS[r.tool],
                resource=r.resource,
                args={"amount": r.amount},
            ),
            now=r.now,
            client_id=CLIENT,
        )
        for r in requests
    ]
    return _System(
        ring,
        MacaroonVerifier(root_key=ring.token_key),
        generate_private_key().public_key(),
        contexts,
    )


def _extend(system: _System, token: Macaroon, specs: Sequence[Spec]) -> Macaroon:
    for spec in specs:
        if spec.kind == "approval":
            token = add_approval_caveat(
                token,
                ring=system.ring,
                approver_public_key=system.approver_public,  # type: ignore[arg-type]
                location="https://approver.internal/v1",
                task_id=TASK,
                expires_at=T0 + 10_000,
                scope=f"verb in {','.join(spec.values)}",
            )
        else:
            token = token.add_first_party_caveat(_condition(spec))
    return token


def _root(system: _System) -> Macaroon:
    identifier = system.ring.new_identifier()
    resolved = system.ring.token_key(identifier)
    if resolved is None:  # pragma: no cover
        raise RuntimeError("ring cannot resolve its identifier")
    return Macaroon.create(root_key=resolved[1], identifier=identifier)


def _authorized(system: _System, token: Macaroon) -> set[int]:
    parsed = Macaroon.deserialize(token.serialize())
    allowed: set[int] = set()
    for index, ctx in enumerate(system.contexts):
        decision = system.verifier.verify(parsed, (), ctx)
        if isinstance(decision, Authorization):
            allowed.add(index)
    return allowed


@dataclass
class SoundnessReport:
    chains: int
    requests_per_chain: int
    verifications: int
    mismatches: int
    subset_violations: int
    oracle_subset_violations: int
    chains_with_nonempty_set: int
    mean_authorized_fraction: float
    first_mismatch: str | None = None


def check_chain(
    system: _System, requests: Sequence[UniverseRequest], parent: list[Spec], extra: list[Spec]
) -> tuple[int, bool, bool, set[int]]:
    """(mismatched requests, SUT subset ok, oracle subset ok, parent authorized set)."""
    parent_token = _extend(system, _root(system), parent)
    child_token = _extend(system, parent_token, extra)
    parent_sut = _authorized(system, parent_token)
    child_sut = _authorized(system, child_token)
    parent_oracle = {i for i, r in enumerate(requests) if oracle_allows(parent, r)}
    child_oracle = {i for i in parent_oracle if oracle_allows(extra, requests[i])}
    mismatches = len(parent_sut ^ parent_oracle) + len(child_sut ^ child_oracle)
    return mismatches, child_sut <= parent_sut, child_oracle <= parent_oracle, parent_sut


def run_soundness(chains: int = 2_000, seed: int = 20260913) -> SoundnessReport:
    requests = universe()
    system = _system(requests)
    rng = random.Random(seed)  # noqa: S311  # nosec B311 - reproducible test inputs, not crypto
    mismatches = subset_violations = oracle_violations = nonempty = 0
    fraction_total = 0.0
    first: str | None = None
    for _ in range(chains):
        parent = random_chain(rng)
        extra = random_chain(rng, 1, 3)
        mismatch, sut_subset, oracle_subset, parent_set = check_chain(
            system, requests, parent, extra
        )
        mismatches += mismatch
        subset_violations += not sut_subset
        oracle_violations += not oracle_subset
        nonempty += bool(parent_set)
        fraction_total += len(parent_set) / len(requests)
        if mismatch and first is None:
            first = repr(parent) + " + " + repr(extra)
    return SoundnessReport(
        chains=chains,
        requests_per_chain=len(requests),
        verifications=chains * 2 * len(requests),
        mismatches=mismatches,
        subset_violations=subset_violations,
        oracle_subset_violations=oracle_violations,
        chains_with_nonempty_set=nonempty,
        mean_authorized_fraction=round(fraction_total / max(chains, 1), 4),
        first_mismatch=first,
    )
