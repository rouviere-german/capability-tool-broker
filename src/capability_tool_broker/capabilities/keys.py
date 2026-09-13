"""Root key ring with key ids, used by the authority (to mint) and the broker (to verify).

Every root macaroon identifier is ``ctb1:<kid>:<32 hex nonce>``. The per-token root key is
``HMAC-SHA256(master[kid], "ctb-token-key-v1\\0" || identifier)``, so no per-token state is stored
and the nonce doubles as the revocation handle. A ring holds one *active* key (used to mint) and
any number of verify-only keys, which gives the dual-key rotation window described in
``docs/RUNBOOK_KEY_ROTATION.md``: add the new key everywhere, activate it on the authority, wait
out the longest token lifetime, then remove the old key.

Keys never appear in ``repr``; :meth:`RootKeyRing.fingerprint` gives a non-secret identifier.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping

from capability_tool_broker.core.canonical import sha256_hex
from capability_tool_broker.macaroons.codec import b64u_decode, b64u_encode
from capability_tool_broker.macaroons.crypto import hmac_sha256

__all__ = ["KID_PATTERN", "MIN_KEY_BYTES", "RootKeyRing", "parse_identifier"]

KID_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,15}$"
MIN_KEY_BYTES = 32
_KID = re.compile(KID_PATTERN)
_IDENTIFIER = re.compile(rb"ctb1:([a-z0-9][a-z0-9_-]{0,15}):([0-9a-f]{32})")
_TOKEN_KEY_LABEL = b"ctb-token-key-v1\x00"
_APPROVAL_TAG_LABEL = b"ctb-approval-tag-v1"


def parse_identifier(identifier: bytes) -> tuple[str, str] | None:
    """Return ``(kid, nonce)`` for a root identifier, or None if it is not one."""
    match = _IDENTIFIER.fullmatch(identifier)
    if match is None:
        return None
    return match.group(1).decode("ascii"), match.group(2).decode("ascii")


class RootKeyRing:
    def __init__(self, keys: Mapping[str, bytes], *, active_kid: str) -> None:
        if not keys:
            raise ValueError("a key ring needs at least one key")
        for kid, key in keys.items():
            if not _KID.fullmatch(kid):
                raise ValueError(f"invalid key id {kid!r}")
            if len(key) < MIN_KEY_BYTES:
                raise ValueError(f"key {kid} is shorter than {MIN_KEY_BYTES} bytes")
        if active_kid not in keys:
            raise ValueError("the active key id must be one of the keys")
        self._keys = dict(keys)
        self._active = active_kid

    def __repr__(self) -> str:
        return f"RootKeyRing(active={self._active!r}, kids={sorted(self._keys)!r})"

    # --- construction and rotation -------------------------------------------------------------

    @classmethod
    def generate(cls, kid: str = "k1") -> RootKeyRing:
        return cls({kid: secrets.token_bytes(MIN_KEY_BYTES)}, active_kid=kid)

    @classmethod
    def parse(cls, spec: str) -> RootKeyRing:
        """Parse ``kid:base64url[,kid:base64url...]``; the first entry is the active key."""
        keys: dict[str, bytes] = {}
        entries = [entry.strip() for entry in spec.split(",") if entry.strip()]
        for entry in entries:
            kid, separator, encoded = entry.partition(":")
            if not separator or kid in keys:
                raise ValueError("root keys must be 'kid:base64url' entries with unique kids")
            keys[kid] = b64u_decode(encoded)
        if not keys:
            raise ValueError("no root keys configured")
        return cls(keys, active_kid=entries[0].partition(":")[0])

    def to_spec(self) -> str:
        ordered = [self._active, *sorted(kid for kid in self._keys if kid != self._active)]
        return ",".join(f"{kid}:{b64u_encode(self._keys[kid])}" for kid in ordered)

    def with_key(self, kid: str, key: bytes, *, activate: bool = False) -> RootKeyRing:
        keys = {**self._keys, kid: key}
        return RootKeyRing(keys, active_kid=kid if activate else self._active)

    def activate(self, kid: str) -> RootKeyRing:
        return RootKeyRing(self._keys, active_kid=kid)

    def without_key(self, kid: str) -> RootKeyRing:
        if kid == self._active:
            raise ValueError("cannot remove the active key; activate another key first")
        return RootKeyRing(
            {k: v for k, v in self._keys.items() if k != kid}, active_kid=self._active
        )

    # --- queries ------------------------------------------------------------------------------

    @property
    def active_kid(self) -> str:
        return self._active

    @property
    def kids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def fingerprint(self, kid: str) -> str:
        return sha256_hex(b"ctb-key-fingerprint-v1" + self._keys[kid])[:16]

    def new_identifier(self) -> bytes:
        return f"ctb1:{self._active}:{secrets.token_hex(16)}".encode("ascii")

    def token_key(self, identifier: bytes) -> tuple[str, bytes] | None:
        """``(kid, per-token root key)`` for an identifier minted under a key in this ring."""
        parsed = parse_identifier(identifier)
        if parsed is None or parsed[0] not in self._keys:
            return None
        kid = parsed[0]
        return kid, hmac_sha256(self._keys[kid], _TOKEN_KEY_LABEL + identifier)

    def approval_tag(self, kid: str, body: bytes, derived_caveat_key: bytes) -> bytes | None:
        """Authority tag over an approval caveat body and the hash of its caveat key."""
        master = self._keys.get(kid)
        if master is None:
            return None
        tag_key = hmac_sha256(master, _APPROVAL_TAG_LABEL)
        return hmac_sha256(tag_key, body + bytes.fromhex(sha256_hex(derived_caveat_key)))
