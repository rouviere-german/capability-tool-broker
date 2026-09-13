"""The in-repo macaroon library against published vectors and pymacaroons as a reference."""

from __future__ import annotations

import binascii
import string

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pymacaroons import MACAROON_V2
from pymacaroons import Caveat as PyCaveat
from pymacaroons import Macaroon as PyMacaroon
from pymacaroons.binders import HashSignaturesBinder
from pymacaroons.utils import sign_third_party_caveat

from capability_tool_broker.macaroons import (
    MAX_CAVEATS,
    Caveat,
    Macaroon,
    MacaroonFormatError,
    b64u_decode,
    b64u_encode,
)
from capability_tool_broker.macaroons.codec import decode_uvarint, encode_uvarint
from capability_tool_broker.macaroons.crypto import (
    bind_signature,
    decrypt_caveat_key,
    derive_key,
    encrypt_caveat_key,
)

pytestmark = pytest.mark.unit

README_KEY = b"this is our super secret key; only we should know it"
README_ID = b"we used our secret key"

identifiers = st.binary(min_size=1, max_size=48)
keys = st.binary(min_size=1, max_size=48)
# pymacaroons only accepts UTF-8 conditions, so the differential tests generate text.
conditions = st.lists(
    st.text(alphabet=st.characters(codec="utf-8"), min_size=1, max_size=24).map(str.encode),
    max_size=8,
)
locations = st.text(alphabet=string.ascii_letters + string.digits + ":/._-", max_size=24)


def test_libmacaroons_readme_vectors() -> None:
    """Signatures published in the libmacaroons README (and reproduced by pymacaroons)."""
    macaroon = Macaroon.create(root_key=README_KEY, identifier=README_ID, location="http://mybank/")
    assert macaroon.signature.hex() == (
        "e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f"
    )
    expected = [
        (
            "account = 3735928559",
            "1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128",
        ),
        (
            "time < 2020-01-01T00:00",
            "b5f06c8c8ef92f6c82c6ff282cd1f8bd1849301d09a2db634ba182536a611c49",
        ),
        (
            "email = alice@example.org",
            "ddf553e46083e55b8d71ab822be3d8fcf21d6bf19c40d617bb9fb438934474b6",
        ),
    ]
    for condition, signature in expected:
        macaroon = macaroon.add_first_party_caveat(condition)
        assert macaroon.signature.hex() == signature


def test_v2_encoding_matches_pymacaroons_for_the_readme_macaroon() -> None:
    ours = Macaroon.create(
        root_key=README_KEY, identifier=README_ID, location="http://mybank/"
    ).add_first_party_caveat("account = 3735928559")
    theirs = PyMacaroon(
        location="http://mybank/", identifier=README_ID, key=README_KEY, version=MACAROON_V2
    )
    theirs.add_first_party_caveat("account = 3735928559")
    assert ours.serialize() == theirs.serialize()


@given(identifier=identifiers, key=keys, caveats=conditions, location=locations)
def test_first_party_chains_and_bytes_match_pymacaroons(
    identifier: bytes, key: bytes, caveats: list[bytes], location: str
) -> None:
    ours = Macaroon.create(root_key=key, identifier=identifier, location=location)
    theirs = PyMacaroon(location=location, identifier=identifier, key=key, version=MACAROON_V2)
    for condition in caveats:
        ours = ours.add_first_party_caveat(condition)
        theirs.add_first_party_caveat(condition)
    assert ours.signature.hex() == theirs.signature
    assert ours.serialize() == theirs.serialize()
    parsed = Macaroon.deserialize(theirs.serialize())
    assert parsed == ours


@given(
    identifier=identifiers,
    key=keys,
    before=conditions,
    caveat_id=st.binary(min_size=1, max_size=48),
    caveat_key=keys,
    nonce=st.binary(min_size=12, max_size=12),
    location=locations,
)
def test_third_party_signature_update_matches_pymacaroons_for_a_given_vid(
    identifier: bytes,
    key: bytes,
    before: list[bytes],
    caveat_id: bytes,
    caveat_key: bytes,
    nonce: bytes,
    location: str,
) -> None:
    ours = Macaroon.create(root_key=key, identifier=identifier)
    theirs = PyMacaroon(location="", identifier=identifier, key=key, version=MACAROON_V2)
    for condition in before:
        ours = ours.add_first_party_caveat(condition)
        theirs.add_first_party_caveat(condition)
    ours = ours.add_third_party_caveat(
        caveat_key=caveat_key, caveat_id=caveat_id, location=location, nonce=nonce
    )
    vid = ours.caveats[-1].verification_id
    assert vid is not None
    theirs.caveats.append(
        PyCaveat(caveat_id=caveat_id, verification_key_id=vid, location=location, version=2)
    )
    theirs.signature = sign_third_party_caveat(
        binascii.unhexlify(theirs.signature_bytes), vid, caveat_id
    )
    assert ours.signature.hex() == theirs.signature
    parsed = PyMacaroon.deserialize(ours.serialize())
    assert parsed.caveats[-1].verification_key_id == vid
    assert parsed.signature == theirs.signature


@given(root=st.binary(min_size=32, max_size=32), discharge=st.binary(min_size=32, max_size=32))
def test_discharge_binding_matches_pymacaroons(root: bytes, discharge: bytes) -> None:
    root_macaroon = PyMacaroon(identifier=b"root", key=b"k", version=MACAROON_V2)
    root_macaroon.signature = binascii.hexlify(root)
    expected = HashSignaturesBinder(root_macaroon).bind_signature(binascii.hexlify(discharge))
    assert bind_signature(root, discharge).hex() == expected.decode("ascii")


@given(
    identifier=identifiers,
    key=keys,
    steps=st.lists(
        st.tuples(st.booleans(), st.binary(min_size=1, max_size=40), st.none() | locations),
        max_size=10,
    ),
)
def test_serialization_round_trips(
    identifier: bytes, key: bytes, steps: list[tuple[bool, bytes, str | None]]
) -> None:
    macaroon = Macaroon.create(root_key=key, identifier=identifier)
    for third_party, data, location in steps:
        if third_party:
            macaroon = macaroon.add_third_party_caveat(
                caveat_key=data, caveat_id=data, location=location
            )
        else:
            macaroon = macaroon.add_first_party_caveat(data)
    assert Macaroon.from_bytes(macaroon.to_bytes()) == macaroon
    assert Macaroon.deserialize(macaroon.serialize()) == macaroon


@given(st.binary(max_size=512))
def test_arbitrary_bytes_either_parse_or_raise_a_format_error(data: bytes) -> None:
    try:
        parsed = Macaroon.from_bytes(data)
    except MacaroonFormatError:
        return
    assert parsed.to_bytes() == data  # anything accepted has exactly one encoding


def _minimal() -> bytes:
    return Macaroon.create(root_key=b"key", identifier=b"id").add_first_party_caveat("c").to_bytes()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw + b"\x00",  # trailing bytes
        lambda raw: raw[:-1],  # truncated signature
        lambda raw: b"\x01" + raw[1:],  # wrong version
        lambda raw: raw.replace(b"\x02\x02id", b"\x02\x82\x00id", 1),  # overlong varint
        lambda raw: raw.replace(b"\x02\x02id\x00", b"\x04\x02id\x02\x02id\x00", 1),  # field order
        lambda raw: raw.replace(b"\x02\x01c\x00", b"\x01\x01L\x02\x01c\x00", 1),  # 1P location
        lambda raw: b"",
    ],
)
def test_malformed_encodings_are_rejected(mutate: object) -> None:
    assert callable(mutate)
    with pytest.raises(MacaroonFormatError):
        Macaroon.from_bytes(mutate(_minimal()))


def test_size_limits_are_enforced() -> None:
    macaroon = Macaroon.create(root_key=b"k", identifier=b"i")
    for index in range(MAX_CAVEATS):
        macaroon = macaroon.add_first_party_caveat(f"c{index}")
    with pytest.raises(MacaroonFormatError):
        macaroon.add_first_party_caveat("one too many")
    with pytest.raises(MacaroonFormatError):
        Macaroon.from_bytes(b"\x02" + b"\x00" * 20_000)
    with pytest.raises(MacaroonFormatError):
        Macaroon.deserialize("A" * 30_000)
    with pytest.raises(MacaroonFormatError):
        Caveat(caveat_id=b"")


def test_base64url_decoding_is_canonical() -> None:
    raw = b"\xff\xee"
    text = b64u_encode(raw)
    assert b64u_decode(text) == raw
    for bad in (text + "=", text[:-1] + "5", "ab+c", "abcde", "a b"):
        with pytest.raises(MacaroonFormatError):
            b64u_decode(bad)


@given(st.integers(min_value=0, max_value=2**34 - 1))
def test_uvarints_round_trip_minimally(value: int) -> None:
    out = bytearray()
    encode_uvarint(value, out)
    assert decode_uvarint(bytes(out), 0) == (value, len(out))
    with pytest.raises(ValueError, match="non-negative"):
        encode_uvarint(-1, bytearray())


def test_varint_errors() -> None:
    with pytest.raises(MacaroonFormatError):
        decode_uvarint(b"\x80", 0)
    with pytest.raises(MacaroonFormatError):
        decode_uvarint(b"\xff\xff\xff\xff\xff\x01", 0)
    with pytest.raises(MacaroonFormatError):
        decode_uvarint(b"\x80\x00", 0)


def test_caveat_keys_decrypt_only_under_the_signature_they_were_sealed_with() -> None:
    signature, other = b"s" * 32, b"t" * 32
    derived = derive_key(b"caveat key")
    vid = encrypt_caveat_key(signature, derived)
    assert decrypt_caveat_key(signature, vid) == derived
    assert decrypt_caveat_key(other, vid) is None
    assert decrypt_caveat_key(signature, vid[:-1]) is None
    with pytest.raises(ValueError, match="32 bytes"):
        encrypt_caveat_key(b"short", derived)
    with pytest.raises(ValueError, match="12 bytes"):
        encrypt_caveat_key(signature, derived, nonce=b"x")


def test_binding_changes_the_signature_and_depends_on_the_root() -> None:
    root_a = Macaroon.create(root_key=b"a", identifier=b"root-a")
    root_b = Macaroon.create(root_key=b"b", identifier=b"root-b")
    discharge = Macaroon.create(root_key=b"d", identifier=b"discharge")
    assert root_a.bind(discharge).signature != discharge.signature
    assert root_a.bind(discharge).signature != root_b.bind(discharge).signature
