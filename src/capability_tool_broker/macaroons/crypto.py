"""Cryptographic primitives of the macaroon construction.

HMAC-SHA256 chaining and binding are byte-compatible with libmacaroons and pymacaroons. The
verification id of a third-party caveat uses ChaCha20-Poly1305 (see ``macaroon.py`` for why).
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

__all__ = [
    "KEY_BYTES",
    "SIGNATURE_BYTES",
    "VID_BYTES",
    "bind_signature",
    "chain_first_party",
    "chain_third_party",
    "constant_time_equal",
    "decrypt_caveat_key",
    "derive_key",
    "encrypt_caveat_key",
    "hmac_sha256",
    "initial_signature",
]

SIGNATURE_BYTES = 32
KEY_BYTES = 32
_NONCE_BYTES = 12
_TAG_BYTES = 16
VID_BYTES = _NONCE_BYTES + KEY_BYTES + _TAG_BYTES
_KEY_GENERATOR = b"macaroons-key-generator"
_ZERO_KEY = bytes(SIGNATURE_BYTES)
_VID_AAD = b"ctb-macaroon-vid-v1"


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data, hashlib.sha256)


def derive_key(root_key: bytes) -> bytes:
    """libmacaroons key derivation: HMAC-SHA256 keyed with ``b"macaroons-key-generator"``."""
    return hmac_sha256(_KEY_GENERATOR, root_key)


def initial_signature(derived_key: bytes, identifier: bytes) -> bytes:
    return hmac_sha256(derived_key, identifier)


def chain_first_party(signature: bytes, condition: bytes) -> bytes:
    return hmac_sha256(signature, condition)


def chain_third_party(signature: bytes, verification_id: bytes, caveat_id: bytes) -> bytes:
    return hmac_sha256(
        signature, hmac_sha256(signature, verification_id) + hmac_sha256(signature, caveat_id)
    )


def bind_signature(root_signature: bytes, discharge_signature: bytes) -> bytes:
    """Bind a discharge to one root macaroon, so it cannot be presented with any other."""
    return hmac_sha256(
        _ZERO_KEY,
        hmac_sha256(_ZERO_KEY, root_signature) + hmac_sha256(_ZERO_KEY, discharge_signature),
    )


def encrypt_caveat_key(
    signature: bytes, derived_caveat_key: bytes, nonce: bytes | None = None
) -> bytes:
    """``nonce || ChaCha20-Poly1305(key=signature)(derived_caveat_key)``."""
    if len(signature) != SIGNATURE_BYTES or len(derived_caveat_key) != KEY_BYTES:
        raise ValueError("signature and caveat key must be 32 bytes")
    nonce = os.urandom(_NONCE_BYTES) if nonce is None else nonce
    if len(nonce) != _NONCE_BYTES:
        raise ValueError("nonce must be 12 bytes")
    return nonce + ChaCha20Poly1305(signature).encrypt(nonce, derived_caveat_key, _VID_AAD)


def decrypt_caveat_key(signature: bytes, verification_id: bytes) -> bytes | None:
    """Recover the derived caveat key, or None if the vid was not made under ``signature``."""
    if len(signature) != SIGNATURE_BYTES or len(verification_id) != VID_BYTES:
        return None
    nonce, sealed = verification_id[:_NONCE_BYTES], verification_id[_NONCE_BYTES:]
    try:
        return ChaCha20Poly1305(signature).decrypt(nonce, sealed, _VID_AAD)
    except InvalidTag:
        return None


def constant_time_equal(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)
