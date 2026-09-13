"""Text encodings for keys and key maps used in settings (``id:base64url,id:base64url``)."""

from __future__ import annotations

import re
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from capability_tool_broker.macaroons.codec import b64u_decode, b64u_encode

__all__ = [
    "MAP_ID_PATTERN",
    "ed25519_private_text",
    "ed25519_public_text",
    "generate_ed25519",
    "generate_secret",
    "load_ed25519_private",
    "load_ed25519_public",
    "parse_public_key_map",
    "parse_secret_map",
    "secret_map_text",
]

MAP_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,63}$"
_MAP_ID = re.compile(MAP_ID_PATTERN)
_RAW_KEY_BYTES = 32
_MIN_SECRET_BYTES = 32


def generate_ed25519() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def generate_secret() -> bytes:
    return secrets.token_bytes(_MIN_SECRET_BYTES)


def ed25519_private_text(key: Ed25519PrivateKey) -> str:
    return b64u_encode(key.private_bytes_raw())


def ed25519_public_text(key: Ed25519PublicKey) -> str:
    return b64u_encode(key.public_bytes_raw())


def load_ed25519_private(text: str) -> Ed25519PrivateKey:
    raw = b64u_decode(text)
    if len(raw) != _RAW_KEY_BYTES:
        raise ValueError("Ed25519 private keys are 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_ed25519_public(text: str) -> Ed25519PublicKey:
    raw = b64u_decode(text)
    if len(raw) != _RAW_KEY_BYTES:
        raise ValueError("Ed25519 public keys are 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def _pairs(spec: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for entry in (item.strip() for item in spec.split(",")):
        if not entry:
            continue
        name, separator, value = entry.partition(":")
        if not separator or not _MAP_ID.fullmatch(name) or name in seen:
            raise ValueError("expected unique 'id:base64url' entries")
        seen.add(name)
        pairs.append((name, value))
    return pairs


def parse_public_key_map(spec: str) -> dict[str, Ed25519PublicKey]:
    return {name: load_ed25519_public(value) for name, value in _pairs(spec)}


def parse_secret_map(spec: str) -> dict[str, bytes]:
    secrets_by_id: dict[str, bytes] = {}
    for name, value in _pairs(spec):
        raw = b64u_decode(value)
        if len(raw) < _MIN_SECRET_BYTES:
            raise ValueError(f"secret {name} is shorter than {_MIN_SECRET_BYTES} bytes")
        secrets_by_id[name] = raw
    return secrets_by_id


def secret_map_text(secrets_by_id: dict[str, bytes]) -> str:
    return ",".join(f"{name}:{b64u_encode(value)}" for name, value in sorted(secrets_by_id.items()))
