"""X25519 sealed boxes: anonymous public-key encryption to one recipient.

``seal`` generates an ephemeral X25519 key, derives a one-time ChaCha20-Poly1305 key with
HKDF-SHA256 over the shared secret (info = context || ephemeral public || recipient public) and
encrypts with a zero nonce, which is safe because every key is used exactly once. The output is
``ephemeral_public (32) || ciphertext``. This is the same shape as libsodium's ``crypto_box_seal``
built from primitives available in ``cryptography``.

The authority seals third-party caveat keys to the approver's public key, so only the approver's
private key can open them; the authority itself needs only the public key.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from capability_tool_broker.macaroons.codec import b64u_decode, b64u_encode

__all__ = [
    "generate_private_key",
    "load_private_key",
    "load_public_key",
    "open_sealed",
    "private_key_text",
    "public_key_text",
    "seal",
]

_PUBLIC_BYTES = 32
_ZERO_NONCE = bytes(12)


def generate_private_key() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def private_key_text(key: X25519PrivateKey) -> str:
    return b64u_encode(key.private_bytes_raw())


def public_key_text(key: X25519PublicKey) -> str:
    return b64u_encode(key.public_bytes_raw())


def load_private_key(text: str) -> X25519PrivateKey:
    raw = b64u_decode(text)
    if len(raw) != _PUBLIC_BYTES:
        raise ValueError("X25519 private keys are 32 bytes")
    return X25519PrivateKey.from_private_bytes(raw)


def load_public_key(text: str) -> X25519PublicKey:
    raw = b64u_decode(text)
    if len(raw) != _PUBLIC_BYTES:
        raise ValueError("X25519 public keys are 32 bytes")
    return X25519PublicKey.from_public_bytes(raw)


def _box_key(shared: bytes, ephemeral: bytes, recipient: bytes, context: bytes) -> bytes:
    kdf = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=context + ephemeral + recipient
    )
    return kdf.derive(shared)


def seal(recipient: X25519PublicKey, plaintext: bytes, *, context: bytes) -> bytes:
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes_raw()
    recipient_public = recipient.public_bytes_raw()
    key = _box_key(ephemeral.exchange(recipient), ephemeral_public, recipient_public, context)
    return ephemeral_public + ChaCha20Poly1305(key).encrypt(_ZERO_NONCE, plaintext, context)


def open_sealed(private: X25519PrivateKey, box: bytes, *, context: bytes) -> bytes | None:
    """Decrypt a sealed box, or return None if it was not sealed to this key and context."""
    if len(box) < _PUBLIC_BYTES + 16:
        return None
    ephemeral_public = box[:_PUBLIC_BYTES]
    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(ephemeral_public))
    except ValueError:  # low-order point
        return None
    recipient_public = private.public_key().public_bytes_raw()
    key = _box_key(shared, ephemeral_public, recipient_public, context)
    try:
        return ChaCha20Poly1305(key).decrypt(_ZERO_NONCE, box[_PUBLIC_BYTES:], context)
    except InvalidTag:
        return None
