# Runbook: rotating the root key

Root macaroon identifiers carry a key id (`ctb1:<kid>:<nonce>`). A key ring holds one active key
(used by the authority to mint) and any number of verify-only keys. Rotation uses a dual-key window
so that no valid token is rejected. The procedure is exercised step by step in
`tests/integration/test_key_rotation.py::test_dual_key_rotation_window`.

`AUTHORITY_ROOT_KEYS` and `BROKER_ROOT_KEYS` use the format `kid:base64url[,kid:base64url...]`;
the first entry is the active key.

## Before you start

- Generate the new key: 32 random bytes, base64url without padding, for example
  `python -c "import secrets,base64;print(base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode())"`.
- Choose a new key id (`k2`, `2026-10`, ...; lowercase letters, digits, `_` and `-`).
- Note the longest token lifetime: `max_ttl_seconds` in the policy (900 seconds by default).

## Step 1: add the new key everywhere, still inactive

Set, on the broker and the authority:

```text
BROKER_ROOT_KEYS=k1:<old>,k2:<new>
AUTHORITY_ROOT_KEYS=k1:<old>,k2:<new>
```

Restart the brokers first, then the authority. Verify with `/readyz` on each broker. Tokens minted
under `k1` keep working; nothing is minted under `k2` yet.

## Step 2: activate the new key on the authority

```text
AUTHORITY_ROOT_KEYS=k2:<new>,k1:<old>
```

Restart the authority. New tokens and new approval caveats carry `k2`. Brokers verify both. Do not
do this before every broker finished step 1: a broker without `k2` denies new tokens with
`unknown_key`.

## Step 3: wait out the longest lifetime

Wait at least `max_ttl_seconds` (plus clock skew) after step 2. Every `k1` token has expired.

## Step 4: remove the old key

```text
BROKER_ROOT_KEYS=k2:<new>
AUTHORITY_ROOT_KEYS=k2:<new>
```

Restart. Any remaining `k1` token is denied with `unknown_key`. Destroy the old key material.

## Emergency rotation (suspected key compromise)

Skip the waiting period: put the new key active and remove the old key everywhere at once. Every
outstanding token becomes invalid; agents must request new tokens. Also rotate service credentials
if the broker host is suspected, and review the audit logs for `authority.mint` entries you do not
recognize.
