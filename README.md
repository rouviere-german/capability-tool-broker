# capability-tool-broker

Agents hold unforgeable macaroon capabilities that can only be narrowed, never ambient keys. A
broker injects the real service credentials and requires human approvals bound to the exact
request.

## Problem

Agent tools usually run with the full authority of the host process: the API keys in its
environment, the files it can open, the endpoints it can reach. One prompt injection in a document
the agent reads reaches all of it, and sub-agents inherit everything. Role-based access control on
an agent identity cannot express a grant like "this sub-step may read invoice 42 for five minutes,
at most three times", and it cannot shrink that grant for a sub-agent without a round trip to an
identity provider.

This repository implements object-capability security for agent tools:

- the **authority** mints one HMAC-chained macaroon per task from a policy template;
- agents **attenuate offline**: a planner hands a sub-agent a narrower token by appending caveats,
  and nobody can remove a caveat without the root key;
- the **broker** is the only process with service credentials. It verifies the token, evaluates
  every caveat against the concrete call, commits call counters atomically, injects the credential
  and calls the service;
- writes and deletes need a **discharge** from the **approver**, which a human issues for one exact
  canonical request, usable once.

The evaluation compares this against the common pattern where the agent host holds the keys.

## Architecture

```mermaid
flowchart LR
    subgraph agenthost["agent-host (holds only tokens + its client key)"]
        planner["planner (LLM provider)"] -- "delegate: append caveats offline" --> sub["sub-agent (child token)"]
    end
    authority["authority<br/>policy YAML, root key ring"]
    approver["approver<br/>X25519 caveat key, review CLI"]
    subgraph brokerbox["broker (only holder of service credentials)"]
        verify["1. verify HMAC chain + discharges"] --> caveats["2. evaluate caveats"]
        caveats --> policy["3. required caveats + approval evidence"]
        policy --> commit["4. revocation + atomic max_calls / once"]
        commit --> inject["5. inject credential, sign, cap + wrap output"]
    end
    redis[("Redis")]
    services["fake services<br/>invoices / files / mailer<br/>(HMAC-signed requests only)"]
    human(["human reviewer"])

    planner -- "client JWT: mint task token" --> authority
    planner & sub -- "token (+ bound discharge)" --> verify
    planner -- "approval request: caveat id + canonical request" --> approver
    human -- "approve exact request" --> approver
    approver -. "discharge: request_hash, once, expires" .-> planner
    commit <--> redis
    inject --> services
    manifest["Ed25519-signed tool manifest"] --> caveats
```

One image, four compose entrypoints (`serve authority|broker|approver|services`) plus Redis; the
agent host runs the scripted end-to-end check (`e2e start|resume`).

| Component | Holds | Code |
|---|---|---|
| Macaroon library (HMAC-SHA256 chains, V2 binary format) | nothing | `src/capability_tool_broker/macaroons/` |
| Caveat DSL, verifier, key ring, approval caveats | nothing | `src/capability_tool_broker/capabilities/` |
| Authority (client JWT authn, policy, minting) | root key ring, approver public key | `src/capability_tool_broker/authority/` |
| Approver (queue, discharges, review CLI) | X25519 caveat key | `src/capability_tool_broker/approver/` |
| Broker (pipeline, signed manifest, Redis state, metrics) | root key ring, service credentials | `src/capability_tool_broker/broker/` |
| Agent host (planner, sub-agents, ambient baseline) | its client key, tokens | `src/capability_tool_broker/agent/` |
| Fake services | their own credential | `src/capability_tool_broker/services/` |
| Evaluation harnesses | generated keys | `src/capability_tool_broker/evaluation/` |

**Caveats.** First-party caveats are one canonical line each and are parsed, never evaluated as
code: `task_id = T`, `client in A`, `tool in A,B`, `verb in read,write`, `host in H`,
`resource matches invoice/42,invoice/4*` (globs with segment-bounded `*`, `?` and `**`),
`expires < 2026-09-13T12:00:00Z`, `max_calls <= 3`, `once = <nonce>`, `request_hash = <sha256>`
and argument predicates such as `arg amount <= 500`. Unknown or non-canonical caveats deny.

**Delegation.** `delegate(tools, resources, verbs, max_calls, ttl)` appends caveats to the parent's
token. Because caveats are conjunctive, a child that asks for `invoice/*` while its parent holds
`invoice/42` still gets only `invoice/42`. `max_calls` counters are keyed by the chain signature
right after the caveat, so every copy of a token prefix shares one counter.

**Approvals.** Templates that grant write or delete get a third-party caveat scoped to
`verb in write,delete` (reads need no approval), sealed to the approver and tagged by the authority.
After a human approves the canonical request (tool, verb and host from the manifest, resource,
arguments, task), the approver mints a discharge carrying `request_hash`, `task_id`, a two-minute
`expires` and a `once` nonce; the agent binds it to its token. See
[ADR 0003](docs/adr/0003-approvals-as-authority-tagged-scoped-discharges.md).

## Quickstart

Requirements: [uv](https://docs.astral.sh/uv/) and Python 3.12. Everything below runs offline on a
CPU; no API key is needed.

```bash
uv sync --frozen
uv run python tasks.py demo        # delegation, contained injection, CLI approval, replay denied
uv run python tasks.py test        # pytest with coverage (floor 85%)
uv run python tasks.py bench       # soundness, forgery, escalation, latency with thresholds
uv run python tasks.py lint typecheck audit baseline
```

To answer the approval prompt yourself, run `uv run capability-tool-broker demo --interactive`.

What the demo prints (abridged): the task token's caveats; the sub-agent's appended caveats; the
sub-agent reading invoice 42 and then obeying three instructions injected into its notes, each
denied with the failing caveat (`resource matches invoice/42`, `tool in invoices_read`,
`tool in invoices_read,invoices_update_status`); the planner's status change waiting on CLI
approval with the full canonical request shown to the reviewer; the approved call executing once;
a replay of the discharge denied (`replayed`) and its reuse for different arguments denied by the
discharge's `request_hash` caveat; and the verified audit chain.

Compose stack (built locally, fake services and Redis; CI runs this in the `compose-integration`
job):

```bash
uv run capability-tool-broker keygen --out .env          # per-role keys; never commit .env
set -a && . ./.env && set +a
uv run capability-tool-broker sign-manifest --out deploy/local/manifest.signed.json
docker compose up --build --detach --wait
docker compose run --rm agent-host e2e start              # delegation, denials, pending approval
docker compose exec approver capability-tool-broker approver review
docker compose run --rm agent-host e2e resume             # approved write runs once, replay denied
```

## Results

All numbers below were produced by one run of

```bash
uv run python bench/bench_baseline.py --check
```

on Windows 10 (10.0.19045), Python 3.12.14, an Intel64 Family 6 Model 158 CPU with 6 logical cores,
CPU only, offline. Section run times: soundness 270.1 s, forgery 1.6 s, escalation 5.4 s,
latency 14.2 s (4 min 53 s in total). The script exited 0 with "all benchmarks within thresholds";
CI enforces the same thresholds (`bench/thresholds.json`). Output copied verbatim:

### Soundness (exhaustive oracle)

| chains | requests/chain | verifications | mismatches | child not subset | non-empty |
|---:|---:|---:|---:|---:|---:|
| 2000 | 900 | 3600000 | 0 | 0 | 1128 |

Mean fraction of the universe a parent authorizes: 0.1279

Universe: 5 tools x 20 resources x 3 verbs x 3 time steps. Each chain has 1 to 6 random caveats
(task, client, tool, verb, host, resource globs, expiry, argument predicates, `max_calls`, scoped
approval caveats); each child appends 1 to 3 more. The reference evaluator shares no code with the
DSL, parser, glob matcher or verifier. 1,128 of 2,000 parents authorize at least one request, so the
comparison is not dominated by empty sets.

### Forgery suite

| category | attempts | accepted |
|---|---:|---:|
| byte_flips_token | 2241 | 0 |
| byte_flips_discharge | 1797 | 0 |
| base64_mutations | 1992 | 0 |
| caveat_removal | 33 | 0 |
| caveat_reordering | 21 | 0 |
| signature_splicing | 10 | 0 |
| discharge_misuse | 9 | 0 |
| key_confusion | 3 | 0 |
| **total** | 6106 | 0 |

Controls (valid read, approved write, attenuated read) accepted: True

### Confused-deputy and escalation scenarios

| family | scenarios | unauthorized effects: broker | unauthorized effects: ambient keys |
|---|---:|---:|---:|
| undelegated_tool | 4 | 0 | 4 |
| widened_glob | 4 | 0 | 4 |
| expired_token | 4 | 0 | 4 |
| exhausted_max_calls | 4 | 0 | 7 |
| replayed_discharge | 4 | 0 | 9 |
| injection_read | 4 | 0 | 5 |
| injection_exfiltration | 4 | 0 | 4 |
| injection_destructive | 3 | 0 | 3 |
| verb_escalation | 2 | 0 | 2 |
| discharge_misuse | 3 | 0 | 3 |
| token_tampering | 4 | 0 | 5 |
| **total** | 40 | 0 | 50 |

Scenarios with at least one unauthorized effect: broker 0/40, ambient keys 40/40.
Utility: 30/30 benign tasks completed under least-privilege tokens (ambient keys: 30/30).

Effects are counted at the fake services, not in agent logs. The ambient baseline runs the same
scripts with the service keys in the host process; it completes the benign tasks too, so least
privilege cost no utility on this task set. The scenarios are scripted and written by the author of
the broker: they show that the enumerated attack patterns are contained, not that no other attack
exists.

### Latency

| benchmark | runs | p50 (us) | p99 (us) | mean (us) |
|---|---:|---:|---:|---:|
| verify_10_caveats | 5000 | 159.7 | 827.6 | 186.0 |
| decide_write_with_discharge | 2500 | 470.5 | 2094.6 | 551.3 |
| broker_call_in_process | 1000 | 9429.7 | 20050.8 | 9871.3 |
| broker_call_no_audit | 1000 | 581.2 | 1885.3 | 651.7 |
| broker_call_http | 300 | 2888.3 | 4869.3 | 3129.8 |

`verify_10_caveats` (parse and verify a 10-caveat token) meets the p99 < 2 ms target.
`broker_call_in_process` includes an fsync'ed audit append per call, which dominates on this
Windows machine; `broker_call_no_audit` is the same call without the audit log.
`broker_call_http` goes through the FastAPI app in-process (no network) and does not write an
audit log. Services are in-process fakes, so these are broker overheads, not end-to-end API
latencies.

## Security

Controls, each linked to its tests in [CLAIMS.md](CLAIMS.md) and the
[threat model](docs/THREAT_MODEL.md) (STRIDE, including confused deputy, token theft and discharge
replay):

- **No ambient authority.** Service credentials exist only in the broker's environment (and the
  fake services' own copy); the compose file, the per-role settings classes and the live object
  graph of the agent host and approver are checked for leaks.
- **Unforgeable, attenuation-only tokens.** HMAC-SHA256 chains compared in constant time, strict
  canonical decoding, key ids with a dual-key rotation window
  ([runbook](docs/RUNBOOK_KEY_ROTATION.md)), soundness checked against an exhaustive oracle.
- **Approvals bound to the request.** Discharges carry the canonical request hash and a single-use
  nonce, are bound to the token family, and count as evidence only for authority-tagged caveats;
  the approver key is separate from the root key.
- **Signed tool manifests.** Verb, host, route mapping, credential and required caveat types come
  from an Ed25519-signed manifest; an unsigned or modified manifest fails readiness and every call.
- **Broker-only access to services.** Services accept only HMAC-signed requests with fresh nonces.
- **Budgets.** Per-token `max_calls` (atomic, shared by delegated copies) plus per-task step, token
  and USD budgets shared by sub-agents.
- **Prompt-injection suite.** Scripted models that obey every injected instruction cannot exceed
  their token's authority; tool output is capped and wrapped as untrusted data.
- **Audit, authn, limits.** Hash-chained audit of mint, attenuate, deny (with the failing caveat),
  discharge and execute; EdDSA client-credential JWTs per service audience; token-bucket rate
  limits; body, token and output size limits; PII redaction in logs and audit records.
- **Operations.** `/readyz` checks root key, Redis and manifest signature; metrics
  `capability_decisions_total{result,caveat_type}`, `verify_latency_seconds`,
  `broker_call_latency_seconds`; the broker span joins the agent step's trace via `traceparent`.

Design decisions: [ADR 0002 macaroons over JWT and Biscuit](docs/adr/0002-macaroons-over-jwt-and-biscuit.md),
[ADR 0003 approvals as scoped, authority-tagged discharges](docs/adr/0003-approvals-as-authority-tagged-scoped-discharges.md),
[ADR 0004 stateless checks before state commits](docs/adr/0004-stateless-checks-before-state-commit.md).
Reporting vulnerabilities: [SECURITY.md](SECURITY.md).

## Non-goals

- **Process isolation of tool code.** The broker calls remote services; it does not sandbox code
  running on the agent host. A compromise of the agent host process gets its tokens (narrow,
  short-lived) but nothing else; sandboxing is the subject of a separate project.
- **Public verifiability.** Macaroons are verified with the shared root key; there is no
  public-key token format and no third-party verifier.
- **Distributed revocation and multi-replica state.** Revocation is short expiry plus a denylist
  keyed by the root token id (revoking a token revokes all its attenuations, not a single child).
  Rate-limit buckets and the JWT replay cache are per process.
- **Real identity providers and SaaS connectors.** Clients are registered by public key in
  settings; the three services are fakes that stand in for real APIs.
- **Reviewer authentication.** The review CLI records a configured reviewer name; access to the
  approver container is the control.
- **Live model runs.** Every test, the demo and the benchmarks use scripted `FakeProvider` models.
  `AnthropicProvider` (default `claude-opus-5`, adaptive thinking, strict tools, refusal fallback)
  is unit-tested against a mocked client only; no cassettes were recorded.

Deviations from the original specification, recorded honestly:

- Rate limiting uses the baseline's token-bucket middleware instead of `slowapi` (same control, no
  extra dependency).
- The macaroon library is checked against the libmacaroons README vectors and pymacaroons as a
  differential oracle. Third-party verification ids use ChaCha20-Poly1305 instead of libsodium
  secretbox, so they are not wire-compatible with libmacaroons (signatures and first-party tokens
  are).
- Broker check order: the signed manifest is consulted first (it defines verb and host), and the
  approval requirement is enforced before counters are committed, so denied calls never consume
  quota ([ADR 0004](docs/adr/0004-stateless-checks-before-state-commit.md)).
- `max_calls` uses a Redis WATCH/MULTI/EXEC transaction instead of a Lua script; tests use
  fakeredis. The real Redis 7 container is exercised only by the CI compose job, which was not run
  locally for this build.
- Added beyond the specification: the `client` caveat plus JWT authentication at the broker (token
  theft), scoped approval caveats with an authority tag, and argument predicates in the soundness
  universe.
- The three fake services run in one `services` container instead of three.
- Traces are exported to the console or not at all; there is no OTLP exporter dependency.

## Project layout

```text
src/capability_tool_broker/  macaroons, capabilities, authority, approver, broker, services,
                             agent, agentic (provider protocol, budgets, audit), core, evaluation
bench/                       bench_baseline.py and regression thresholds
docs/                        threat model, ADRs, key rotation runbook
tests/                       unit and integration tests (offline)
```

## License

MIT, see [LICENSE](LICENSE).
