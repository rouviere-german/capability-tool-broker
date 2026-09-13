# 3. Approvals are authority-tagged, scoped third-party discharges bound to the request hash

- Status: accepted
- Date: 2026-09-13

## Context

Writes and deletes must wait for a human who approves the *exact* call. The approval must not be
reusable for another call, another task, another token family, or twice. Reads with the same token
must not need approval. The approver process must hold nothing that lets it act on its own, and
the agent host must not be able to approve its own calls.

A plain macaroon third-party caveat is required for every request, which would make every read
wait for a human. And the classic protocol lets anyone who adds a third-party caveat choose its
caveat key: a holder can append their own "approval" caveat and discharge it themselves. That only
narrows the token (fine for macaroon semantics), but it must not count as approval evidence.

Options considered:

1. **Separate approval tokens signed by the approver** (Ed25519 over the request hash). Simple,
   but it is a second authorization channel outside the capability, and delegation would need its
   own binding rules.
2. **The template's approval gate** (a local store keyed by the call hash, consumed on use).
   Works inside one process, but the store lives next to the agent host, which is the component
   we do not trust.
3. **Discharge macaroons**, with two additions described below.

## Decision

The authority adds one third-party caveat to every token whose template grants `write` or
`delete`. Its caveat id is canonical JSON with:

- `scope`: a stateless caveat condition, by default `verb in write,delete`. The verifier requires
  a discharge only when the scope matches the request, so reads need none. The scope is covered by
  the HMAC chain and cannot be changed by holders.
- `box`: the caveat key and task id sealed to the approver's X25519 public key. Only the approver
  can open it; the authority keeps no copy and the approver queue never stores the key.
- `tag`: an HMAC under a key derived from the root key over the caveat body and the hash of the
  caveat key. The broker accepts a discharge as approval evidence only for a caveat with a valid
  tag, so self-made approval caveats never count, and an authority caveat id cannot be reused with
  a different caveat key.

After a human approves the full canonical request in the review CLI, the approver mints the
discharge with caveats `request_hash = <hash>`, `task_id`, `expires` (at most two minutes) and
`once = <nonce>`. The agent host binds it to the requesting token. For write and delete calls the
broker requires a verified, tagged discharge that carries both `request_hash` for the call and a
`once` caveat.

## Consequences

- A discharge works only for the approved request (different arguments, tool, resource or task
  change the hash), only bound to a token of the same family, and only once (the `once` key is the
  hash of the discharge chain signature, so replay through a sibling token is caught too).
- The approver cannot mint root tokens or reach services; the authority could mint discharges in
  principle (it created the caveat key) but already holds the root key, so this adds no power.
- Holders can still add their own third-party caveats; they narrow the token but are never
  evidence. The forgery suite includes a forged-tag self-discharge.
- Approval state (pending, decided) lives in the approver's file-locked queue; the discharge itself
  carries everything the broker needs.
