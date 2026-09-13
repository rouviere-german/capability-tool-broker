"""Approval caveats: third-party caveats issued by the authority and discharged by the approver.

The caveat id is canonical JSON::

    {"v": 1, "purpose": "approval", "location": <approver URL>, "scope": <caveat condition>,
     "kid": <root key id>, "box": <sealed box>, "tag": <authority tag>}

- ``box`` seals ``{"v", "caveat_key", "task_id", "client_id", "expires_at"}`` to the approver's
  X25519 public key. Only the approver can open it; the caveat key is never stored by the approver
  queue. ``client_id`` is the client the authority minted the token for: the approver accepts
  approval requests for the caveat only from that client.
- ``scope`` is a stateless first-party condition (by default ``verb in write,delete``). The caveat
  must be discharged only for requests the scope matches, so reads with the same token need no
  approval. The scope is covered by the macaroon chain, so a holder cannot change it.
- ``tag`` is an HMAC under a key derived from the root key over the body and the hash of the
  caveat key. The broker accepts a discharge as *approval evidence* only for a caveat with a valid
  tag. A holder can add third-party caveats of their own (that only narrows the token) and discharge
  them with keys they chose, but without the root key they cannot produce a tag, and they cannot
  reuse an authority tag with a different caveat key because the tag binds the key's hash.
"""

from __future__ import annotations

import functools
import json
import secrets
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from capability_tool_broker.capabilities.caveats import (
    CaveatSyntaxError,
    Predicate,
    is_stateful,
    parse_caveat,
)
from capability_tool_broker.capabilities.keys import RootKeyRing
from capability_tool_broker.capabilities.request import CLIENT_ID_PATTERN, TASK_ID_PATTERN
from capability_tool_broker.capabilities.sealed import open_sealed, seal
from capability_tool_broker.core.canonical import CanonicalJSONError, canonical_json
from capability_tool_broker.macaroons.codec import b64u_decode, b64u_encode
from capability_tool_broker.macaroons.crypto import constant_time_equal, derive_key
from capability_tool_broker.macaroons.errors import MacaroonFormatError
from capability_tool_broker.macaroons.macaroon import Macaroon

__all__ = [
    "DEFAULT_APPROVAL_SCOPE",
    "ApprovalBox",
    "ApprovalCaveatId",
    "OpenedApprovalCaveat",
    "add_approval_caveat",
    "approval_scope",
    "approval_tag_valid",
    "open_approval_caveat",
]

DEFAULT_APPROVAL_SCOPE = "verb in write,delete"
_BOX_CONTEXT = b"ctb-approval-box-v1"


class ApprovalCaveatId(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    v: Literal[1] = 1
    purpose: Literal["approval"] = "approval"
    location: str = Field(pattern=r"^[a-z][a-z0-9+.-]{0,15}://[A-Za-z0-9.:_/-]{1,200}$")
    scope: str = Field(max_length=256)
    kid: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,15}$")
    box: str = Field(max_length=1024)
    tag: str = Field(default="", max_length=64)

    def body(self) -> bytes:
        return canonical_json(self.model_dump(mode="json", exclude={"tag"})).encode("utf-8")

    def encode(self) -> bytes:
        return canonical_json(self.model_dump(mode="json")).encode("utf-8")

    @classmethod
    def decode(cls, data: bytes) -> ApprovalCaveatId | None:
        """Parse a caveat id; None unless it is exactly the canonical encoding of an approval id."""
        try:
            parsed = cls.model_validate(json.loads(data.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, RecursionError):
            return None
        try:
            return parsed if parsed.encode() == data else None
        except CanonicalJSONError:  # pragma: no cover - validated fields are JSON
            return None


class ApprovalBox(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    v: Literal[1] = 1
    caveat_key: str
    task_id: str = Field(pattern=TASK_ID_PATTERN)
    client_id: str = Field(pattern=CLIENT_ID_PATTERN)
    expires_at: int


@dataclass(frozen=True, slots=True)
class OpenedApprovalCaveat:
    caveat_id: ApprovalCaveatId
    box: ApprovalBox
    caveat_key: bytes


def add_approval_caveat(
    token: Macaroon,
    *,
    ring: RootKeyRing,
    approver_public_key: X25519PublicKey,
    location: str,
    task_id: str,
    client_id: str,
    expires_at: int,
    scope: str = DEFAULT_APPROVAL_SCOPE,
) -> Macaroon:
    """Append an authority-tagged approval caveat to ``token`` (authority side)."""
    predicate = parse_caveat(scope)
    if is_stateful(predicate):
        raise ValueError("an approval scope must be a stateless condition")
    caveat_key = secrets.token_bytes(32)
    box = ApprovalBox(
        caveat_key=b64u_encode(caveat_key),
        task_id=task_id,
        client_id=client_id,
        expires_at=expires_at,
    )
    sealed = seal(
        approver_public_key,
        canonical_json(box.model_dump(mode="json")).encode("utf-8"),
        context=_BOX_CONTEXT,
    )
    unsigned = ApprovalCaveatId(
        location=location, scope=scope, kid=ring.active_kid, box=b64u_encode(sealed)
    )
    tag = ring.approval_tag(ring.active_kid, unsigned.body(), derive_key(caveat_key))
    if tag is None:  # pragma: no cover - the active kid is always in the ring
        raise ValueError("active key missing")
    caveat_id = unsigned.model_copy(update={"tag": b64u_encode(tag)})
    return token.add_third_party_caveat(caveat_key=caveat_key, caveat_id=caveat_id.encode())


def open_approval_caveat(
    caveat_id: bytes, approver_private_key: X25519PrivateKey
) -> OpenedApprovalCaveat | None:
    """Approver side: recover the caveat key and task binding, or None if not sealed to us."""
    parsed = ApprovalCaveatId.decode(caveat_id)
    if parsed is None:
        return None
    try:
        sealed = b64u_decode(parsed.box)
    except MacaroonFormatError:
        return None
    plaintext = open_sealed(approver_private_key, sealed, context=_BOX_CONTEXT)
    if plaintext is None:
        return None
    try:
        box = ApprovalBox.model_validate(json.loads(plaintext.decode("utf-8")))
        caveat_key = b64u_decode(box.caveat_key)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, MacaroonFormatError):
        return None
    if len(caveat_key) != 32:
        return None
    return OpenedApprovalCaveat(caveat_id=parsed, box=box, caveat_key=caveat_key)


@functools.lru_cache(maxsize=4_096)
def approval_scope(caveat_id: bytes) -> Predicate | None:
    """The stateless scope of an approval caveat id, or None (the caveat always applies)."""
    parsed = ApprovalCaveatId.decode(caveat_id)
    if parsed is None:
        return None
    try:
        predicate = parse_caveat(parsed.scope)
    except CaveatSyntaxError:
        return None
    return None if is_stateful(predicate) else predicate


def approval_tag_valid(ring: RootKeyRing, caveat_id: bytes, derived_caveat_key: bytes) -> bool:
    parsed = ApprovalCaveatId.decode(caveat_id)
    if parsed is None:
        return False
    try:
        presented = b64u_decode(parsed.tag)
    except MacaroonFormatError:
        return False
    expected = ring.approval_tag(parsed.kid, parsed.body(), derived_caveat_key)
    return expected is not None and constant_time_equal(expected, presented)
