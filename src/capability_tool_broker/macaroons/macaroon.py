"""Macaroons (Birgisson et al., NDSS 2014) with HMAC-SHA256 chains and the libmacaroons V2 format.

Signatures follow libmacaroons and pymacaroons, and the test suite checks them against the
published libmacaroons README vectors and against pymacaroons itself:

- key derivation: ``derived = HMAC-SHA256(key="macaroons-key-generator", msg=root_key)``;
- initial signature: ``sig = HMAC(derived, identifier)``;
- first-party caveat: ``sig' = HMAC(sig, condition)``;
- third-party caveat: ``sig' = HMAC(sig, HMAC(sig, vid) || HMAC(sig, cid))``;
- discharge binding: ``HMAC(0^32, HMAC(0^32, root_sig) || HMAC(0^32, discharge_sig))``.

One deliberate difference: a third-party caveat's verification id encrypts the derived caveat key
under the running signature with ChaCha20-Poly1305 (``nonce || ciphertext``) instead of libsodium's
XSalsa20-Poly1305 secretbox, because ``cryptography`` ships no secretbox. Signatures over a given
vid match libmacaroons; the vid bytes themselves are not interchangeable.

Wire format (libmacaroons ``doc/format.txt``, version 2)::

    macaroon := 0x02 [location] identifier EOS caveat* EOS signature
    caveat   := [location] identifier [vid] EOS
    field    := type(uvarint) length(uvarint) data;  EOS := 0x00
    types    := location 1, identifier 2, vid 4, signature 6

Decoding is strict: field types must increase within a section, varints must be minimal, the
signature must be 32 bytes, no bytes may follow it, and sizes are capped. Macaroons are immutable
values; ``add_*`` and ``bind`` return new macaroons.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from capability_tool_broker.macaroons.codec import (
    b64u_decode,
    b64u_encode,
    decode_uvarint,
    encode_uvarint,
)
from capability_tool_broker.macaroons.crypto import (
    SIGNATURE_BYTES,
    bind_signature,
    chain_first_party,
    chain_third_party,
    derive_key,
    encrypt_caveat_key,
    initial_signature,
)
from capability_tool_broker.macaroons.errors import MacaroonFormatError

__all__ = ["MAX_CAVEATS", "MAX_FIELD_BYTES", "MAX_TOKEN_BYTES", "Caveat", "Macaroon"]

MAX_TOKEN_BYTES = 16_384
MAX_FIELD_BYTES = 4_096
MAX_CAVEATS = 64

_VERSION_V2 = 2
_EOS = 0
_LOCATION = 1
_IDENTIFIER = 2
_VID = 4
_SIGNATURE = 6


@dataclass(frozen=True, slots=True)
class Caveat:
    """A caveat. First-party caveats carry only ``caveat_id`` (the condition bytes)."""

    caveat_id: bytes
    verification_id: bytes | None = None
    location: str | None = None

    def __post_init__(self) -> None:
        if not self.caveat_id or len(self.caveat_id) > MAX_FIELD_BYTES:
            raise MacaroonFormatError("caveat id must be 1 to 4096 bytes")
        if self.verification_id is None:
            if self.location is not None:
                raise MacaroonFormatError("a first-party caveat cannot have a location")
        elif not self.verification_id or len(self.verification_id) > MAX_FIELD_BYTES:
            raise MacaroonFormatError("verification id must be 1 to 4096 bytes")
        if self.location is not None and len(self.location.encode("utf-8")) > MAX_FIELD_BYTES:
            raise MacaroonFormatError("location too long")

    @property
    def is_first_party(self) -> bool:
        return self.verification_id is None


@dataclass(frozen=True, slots=True)
class Macaroon:
    identifier: bytes
    signature: bytes
    caveats: tuple[Caveat, ...] = ()
    location: str | None = None

    def __post_init__(self) -> None:
        if not self.identifier or len(self.identifier) > MAX_FIELD_BYTES:
            raise MacaroonFormatError("identifier must be 1 to 4096 bytes")
        if len(self.signature) != SIGNATURE_BYTES:
            raise MacaroonFormatError("signature must be 32 bytes")
        if len(self.caveats) > MAX_CAVEATS:
            raise MacaroonFormatError(f"at most {MAX_CAVEATS} caveats are allowed")
        if self.location is not None and len(self.location.encode("utf-8")) > MAX_FIELD_BYTES:
            raise MacaroonFormatError("location too long")

    # --- construction -------------------------------------------------------------------------

    @classmethod
    def create(cls, *, root_key: bytes, identifier: bytes, location: str | None = None) -> Macaroon:
        """Mint a macaroon whose chain starts from ``root_key`` (derived as in libmacaroons)."""
        return cls(
            identifier=identifier,
            signature=initial_signature(derive_key(root_key), identifier),
            location=location,
        )

    def add_first_party_caveat(self, condition: str | bytes) -> Macaroon:
        raw = condition.encode("utf-8") if isinstance(condition, str) else condition
        caveat = Caveat(caveat_id=raw)
        return replace(
            self,
            caveats=(*self.caveats, caveat),
            signature=chain_first_party(self.signature, raw),
        )

    def add_third_party_caveat(
        self,
        *,
        caveat_key: bytes,
        caveat_id: bytes,
        location: str | None = None,
        nonce: bytes | None = None,
    ) -> Macaroon:
        """Require a discharge macaroon minted from ``caveat_key`` with identifier ``caveat_id``."""
        vid = encrypt_caveat_key(self.signature, derive_key(caveat_key), nonce)
        caveat = Caveat(caveat_id=caveat_id, verification_id=vid, location=location)
        return replace(
            self,
            caveats=(*self.caveats, caveat),
            signature=chain_third_party(self.signature, vid, caveat_id),
        )

    def bind(self, discharge: Macaroon) -> Macaroon:
        """Return ``discharge`` bound to this root macaroon (add caveats before binding)."""
        return replace(discharge, signature=bind_signature(self.signature, discharge.signature))

    # --- encoding -----------------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        out = bytearray([_VERSION_V2])
        if self.location is not None:
            _put(out, _LOCATION, self.location.encode("utf-8"))
        _put(out, _IDENTIFIER, self.identifier)
        out.append(_EOS)
        for caveat in self.caveats:
            if caveat.location is not None:
                _put(out, _LOCATION, caveat.location.encode("utf-8"))
            _put(out, _IDENTIFIER, caveat.caveat_id)
            if caveat.verification_id is not None:
                _put(out, _VID, caveat.verification_id)
            out.append(_EOS)
        out.append(_EOS)
        _put(out, _SIGNATURE, self.signature)
        return bytes(out)

    def serialize(self) -> str:
        """Unpadded base64url of the V2 binary encoding."""
        return b64u_encode(self.to_bytes())

    @classmethod
    def deserialize(cls, text: str) -> Macaroon:
        if len(text) > (MAX_TOKEN_BYTES * 4) // 3 + 4:
            raise MacaroonFormatError("token too large")
        return cls.from_bytes(b64u_decode(text))

    @classmethod
    def from_bytes(cls, data: bytes) -> Macaroon:
        if len(data) > MAX_TOKEN_BYTES:
            raise MacaroonFormatError("token too large")
        if not data or data[0] != _VERSION_V2:
            raise MacaroonFormatError("unsupported macaroon version")
        reader = _Reader(data, 1)
        location, rest = _split_location(reader.section())
        if len(rest) != 1 or rest[0][0] != _IDENTIFIER:
            raise MacaroonFormatError("invalid macaroon header")
        identifier = rest[0][1]
        caveats: list[Caveat] = []
        while section := reader.section():
            if len(caveats) == MAX_CAVEATS:
                raise MacaroonFormatError(f"at most {MAX_CAVEATS} caveats are allowed")
            caveat_location, fields = _split_location(section)
            if not fields or fields[0][0] != _IDENTIFIER:
                raise MacaroonFormatError("caveat without identifier")
            vid: bytes | None = None
            if len(fields) == 2 and fields[1][0] == _VID:
                vid = fields[1][1]
            elif len(fields) != 1:
                raise MacaroonFormatError("unexpected field in caveat")
            caveats.append(Caveat(fields[0][1], vid, caveat_location))
        field_type, signature = reader.packet()
        if field_type != _SIGNATURE:
            raise MacaroonFormatError("signature field expected")
        if not reader.at_end():
            raise MacaroonFormatError("trailing bytes after signature")
        return cls(
            identifier=identifier,
            signature=signature,
            caveats=tuple(caveats),
            location=location,
        )


def _put(out: bytearray, field_type: int, data: bytes) -> None:
    encode_uvarint(field_type, out)
    encode_uvarint(len(data), out)
    out.extend(data)


def _split_location(section: list[tuple[int, bytes]]) -> tuple[str | None, list[tuple[int, bytes]]]:
    if section and section[0][0] == _LOCATION:
        try:
            return section[0][1].decode("utf-8"), section[1:]
        except UnicodeDecodeError as exc:
            raise MacaroonFormatError("location is not UTF-8") from exc
    return None, section


class _Reader:
    def __init__(self, data: bytes, offset: int) -> None:
        self._data = data
        self._offset = offset

    def at_end(self) -> bool:
        return self._offset == len(self._data)

    def packet(self) -> tuple[int, bytes]:
        field_type, self._offset = decode_uvarint(self._data, self._offset)
        if field_type == _EOS:
            return _EOS, b""
        length, self._offset = decode_uvarint(self._data, self._offset)
        end = self._offset + length
        if length > MAX_FIELD_BYTES or end > len(self._data):
            raise MacaroonFormatError("field extends past the end of the token")
        payload = self._data[self._offset : end]
        self._offset = end
        return field_type, payload

    def section(self) -> list[tuple[int, bytes]]:
        """Fields up to the next EOS; field types must strictly increase."""
        fields: list[tuple[int, bytes]] = []
        previous = _EOS
        while True:
            if self.at_end():
                raise MacaroonFormatError("section extends past the end of the token")
            field_type, payload = self.packet()
            if field_type == _EOS:
                return fields
            if field_type <= previous or field_type not in (_LOCATION, _IDENTIFIER, _VID):
                raise MacaroonFormatError("fields out of order or of unknown type")
            fields.append((field_type, payload))
            previous = field_type
