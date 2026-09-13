# 2. Attenuable macaroons instead of JWT scopes or Biscuit tokens

- Status: accepted
- Date: 2026-09-13

## Context

Agents need a grant like "this sub-step may read invoice 42 for five minutes, at most three
times", and a planner must be able to hand a sub-agent a narrower version of its own grant
without calling a server and without being able to widen it. The verifier (the broker) must
explain every denial precisely, and verification must be cheap enough to run on every tool call
(the evaluation budget is verify p99 below 2 ms for a 10-caveat token on a CPU).

Options considered:

1. **JWT or OAuth access tokens with scopes** (plus RFC 8693 token exchange for delegation).
   Mature and widely understood. Narrowing requires a round trip to the issuer, every sub-agent
   delegation becomes a network call, and scopes are coarse strings that do not express
   resource globs, argument predicates or call counts without inventing a claim language anyway.
2. **Biscuit tokens** (public-key signatures, Datalog policies, offline attenuation). Holders
   attenuate offline and anyone with the public key can verify. The Datalog engine is a large
   dependency for a small caveat set, there is no maintained pure-Python implementation that is
   easy to audit in this repository, and third-party blocks model approvals less directly than
   discharge macaroons.
3. **Macaroons** (Birgisson et al., "Macaroons: Cookies with Contextual Caveats for Decentralized
   Authorization in the Cloud", NDSS 2014). HMAC chains: appending a caveat is one HMAC, removing
   one is impossible without the root key, and third-party caveats with discharge macaroons are a
   natural fit for "a human approved exactly this request".

## Decision

Use macaroons, implemented in-repo (`src/capability_tool_broker/macaroons/`, about 300 lines),
byte-compatible with libmacaroons for signatures and the V2 binary format and checked against
the published libmacaroons README vectors and pymacaroons as a differential oracle. The caveat
language is a small canonical DSL (no eval) evaluated by the broker. Root keys are per token,
derived from a key ring with key ids, so rotation works without per-token storage.

Two deliberate deviations from libmacaroons:

- the verification id of a third-party caveat is encrypted with ChaCha20-Poly1305 (from
  `cryptography`) instead of XSalsa20-Poly1305 secretbox, so vids are not interchangeable with
  libmacaroons (signatures over a given vid are);
- the broker refuses `location` fields, because libmacaroons does not authenticate them.

## Consequences

- Attenuation is offline and monotone, which the soundness benchmark checks against an exhaustive
  reference evaluator (2,000 chains, 900 requests each).
- Verification needs the root key, so the broker and the authority share the key ring. There is
  no public verifiability; a compromised broker could mint tokens. That is acceptable because the
  broker already holds the service credentials, which are worth more.
- Stateless caveats cannot express "at most N calls". `max_calls` and `once` need online state
  (Redis), committed atomically after every stateless check (see ADR 0004).
- Revocation is short expiry plus a nonce denylist keyed by the root identifier; there is no
  distributed revocation list.
- Tokens are bearer credentials. The `client` caveat and client-credential JWT authentication at
  the broker make a stolen token useless without the client's private key.
