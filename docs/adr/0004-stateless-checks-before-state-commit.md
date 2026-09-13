# 4. All stateless checks run before counters and nonces are committed

- Status: accepted
- Date: 2026-09-13

## Context

The specification orders the broker's checks as: verify the chain, evaluate caveats, increment
counters, require discharges for write and delete, then look up the manifest and call the service.
Taken literally, a write without an approval would consume a `max_calls` slot before being denied,
and a caveat evaluated against a verb chosen by the agent could be fooled.

`max_calls` must also behave correctly under delegation: if a planner holding "at most 3 calls"
hands copies of its token to two sub-agents, they must share the three calls, while a sub-agent
that appends its own `max_calls <= 1` gets an additional, tighter counter.

## Decision

The broker runs, in order:

1. manifest lookup: the verb and host come from the signed manifest, the resource is mapped
   through the manifest's templates, and arguments are validated;
2. HMAC chain and discharge verification;
3. evaluation of every first-party caveat, then undischarged third-party caveats (so no human is
   asked to approve a call the token forbids anyway);
4. required caveat types from the manifest and approval evidence for write and delete;
5. revocation check, then one atomic commit of every `max_calls` counter and `once` nonce;
6. credential injection, the upstream call, output capping and wrapping.

Counter keys are `sha256(label || chain signature right after the caveat)`. Every copy of a token
prefix computes the same key; a caveat appended later has a different prefix signature. The Redis
store commits with WATCH/MULTI/EXEC and bounded retries; the in-memory store under a lock.

## Consequences

- A denied call never consumes quota or burns an approval (tested in
  `tests/integration/test_broker_pipeline.py`).
- The manifest is part of the trusted computing base: a wrong verb in the manifest would bypass
  approvals, which is why the manifest is signed and `/readyz` fails without a valid signature.
- A call that fails upstream after the commit has consumed its slot; the outcome is audited as an
  upstream error.
- WATCH/MULTI avoids a Lua dependency and runs on fakeredis in tests; under heavy contention the
  broker reports `state_unavailable` after the retry budget instead of admitting the call.
