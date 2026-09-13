"""Strict encodings for the wire format: unpadded base64url and minimal unsigned varints.

Both decoders accept exactly one encoding per value. Padding, non-alphabet characters, non-zero
trailing bits in base64 and overlong varints are rejected, so a mutated token can never decode to
the same bytes as the original.
"""

from __future__ import annotations

import base64
import binascii
import re

from capability_tool_broker.macaroons.errors import MacaroonFormatError

__all__ = ["b64u_decode", "b64u_encode", "decode_uvarint", "encode_uvarint"]

_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_MAX_VARINT_BYTES = 5


def b64u_encode(data: bytes) -> str:
    """Unpadded base64url text for ``data``."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    """Decode canonical unpadded base64url; raise MacaroonFormatError for anything else."""
    if not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise MacaroonFormatError("not unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - alphabet checked above
        raise MacaroonFormatError("not unpadded base64url") from exc
    if b64u_encode(raw) != text:
        raise MacaroonFormatError("non-canonical base64url (trailing bits set)")
    return raw


def encode_uvarint(value: int, out: bytearray) -> None:
    """Append the minimal little-endian base-128 encoding of ``value`` to ``out``."""
    if value < 0:
        raise ValueError("uvarint values must be non-negative")
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return


def decode_uvarint(data: bytes, offset: int) -> tuple[int, int]:
    """Return ``(value, next_offset)``; reject truncated, overlong and non-minimal varints."""
    value = 0
    for index in range(_MAX_VARINT_BYTES):
        position = offset + index
        if position >= len(data):
            raise MacaroonFormatError("truncated varint")
        byte = data[position]
        value |= (byte & 0x7F) << (7 * index)
        if byte < 0x80:
            if index > 0 and byte == 0:
                raise MacaroonFormatError("non-minimal varint")
            return value, position + 1
    raise MacaroonFormatError("varint too long")
