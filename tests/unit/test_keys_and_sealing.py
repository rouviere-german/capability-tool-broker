"""Root key rings, sealed boxes, approval caveat ids and key text encodings."""

from __future__ import annotations

import json
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from capability_tool_broker.capabilities.keyfiles import (
    ed25519_private_text,
    ed25519_public_text,
    generate_ed25519,
    generate_secret,
    load_ed25519_private,
    load_ed25519_public,
    parse_public_key_map,
    parse_secret_map,
    secret_map_text,
)
from capability_tool_broker.capabilities.keys import RootKeyRing, parse_identifier
from capability_tool_broker.capabilities.sealed import (
    generate_private_key,
    load_private_key,
    load_public_key,
    open_sealed,
    private_key_text,
    public_key_text,
    seal,
)
from capability_tool_broker.capabilities.thirdparty import (
    ApprovalCaveatId,
    add_approval_caveat,
    approval_scope,
    approval_tag_valid,
    open_approval_caveat,
)
from capability_tool_broker.macaroons.codec import b64u_encode
from capability_tool_broker.macaroons.crypto import derive_key
from capability_tool_broker.macaroons.errors import MacaroonFormatError
from capability_tool_broker.macaroons.macaroon import Macaroon

pytestmark = pytest.mark.unit


def test_key_rings_rotate_and_round_trip_through_their_spec() -> None:
    ring = RootKeyRing.generate("k1")
    rotated = ring.with_key("k2", secrets.token_bytes(32))
    assert rotated.active_kid == "k1"
    assert rotated.kids == ("k1", "k2")
    activated = rotated.activate("k2")
    assert activated.to_spec().startswith("k2:")
    parsed = RootKeyRing.parse(activated.to_spec())
    assert parsed.active_kid == "k2"
    assert parsed.fingerprint("k1") == ring.fingerprint("k1")
    retired = activated.without_key("k1")
    assert retired.kids == ("k2",)
    with pytest.raises(ValueError, match="active"):
        activated.without_key("k2")
    assert (
        RootKeyRing.parse(ring.to_spec()).with_key("k3", b"x" * 32, activate=True).active_kid
        == "k3"
    )


@pytest.mark.parametrize(
    "spec",
    [
        "",
        " , ",
        "k1",
        "k1:AAAA",
        "K1:" + b64u_encode(b"x" * 32),
        f"k1:{b64u_encode(b'x' * 32)},k1:{b64u_encode(b'y' * 32)}",
    ],
)
def test_invalid_key_ring_specs_are_rejected(spec: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - several distinct messages
        RootKeyRing.parse(spec)


def test_key_ring_constructor_checks() -> None:
    with pytest.raises(ValueError, match="at least one"):
        RootKeyRing({}, active_kid="k1")
    with pytest.raises(ValueError, match="active"):
        RootKeyRing({"k1": b"x" * 32}, active_kid="k2")


def test_rings_never_reveal_keys() -> None:
    key = secrets.token_bytes(32)
    ring = RootKeyRing({"k1": key}, active_kid="k1")
    assert key.hex() not in repr(ring)
    assert b64u_encode(key) not in repr(ring)


def test_identifiers_resolve_only_under_known_key_ids() -> None:
    ring = RootKeyRing.generate("k1")
    identifier = ring.new_identifier()
    parsed = parse_identifier(identifier)
    assert parsed is not None
    assert parsed[0] == "k1"
    resolved = ring.token_key(identifier)
    assert resolved is not None
    other = ring.token_key(ring.new_identifier())
    assert other is not None
    assert resolved[1] != other[1]  # per-token keys differ
    assert ring.token_key(b"ctb1:k9:" + b"0" * 32) is None
    assert ring.token_key(b"garbage") is None
    assert parse_identifier(b"ctb1:k1:short") is None


def test_approval_tags_bind_key_id_body_and_caveat_key() -> None:
    ring = RootKeyRing.generate("k1")
    tag = ring.approval_tag("k1", b"body", b"key")
    assert tag is not None
    assert tag != ring.approval_tag("k1", b"other body", b"key")
    assert tag != ring.approval_tag("k1", b"body", b"other key")
    assert ring.approval_tag("k2", b"body", b"key") is None


def test_sealed_boxes_open_only_for_the_recipient_and_context() -> None:
    recipient = generate_private_key()
    box = seal(recipient.public_key(), b"secret", context=b"ctx")
    assert open_sealed(recipient, box, context=b"ctx") == b"secret"
    assert open_sealed(generate_private_key(), box, context=b"ctx") is None
    assert open_sealed(recipient, box, context=b"other") is None
    assert open_sealed(recipient, box[:20], context=b"ctx") is None
    assert open_sealed(recipient, bytes(32) + box[32:], context=b"ctx") is None
    assert load_private_key(private_key_text(recipient)).public_key().public_bytes_raw() == (
        recipient.public_key().public_bytes_raw()
    )
    assert load_public_key(public_key_text(recipient.public_key())).public_bytes_raw() == (
        recipient.public_key().public_bytes_raw()
    )
    with pytest.raises(ValueError, match="32 bytes"):
        load_private_key(b64u_encode(b"x"))
    with pytest.raises(ValueError, match="32 bytes"):
        load_public_key(b64u_encode(b"x"))


def _approval_token() -> tuple[Macaroon, RootKeyRing, X25519PrivateKey]:
    ring = RootKeyRing.generate("k1")
    approver = generate_private_key()
    root = Macaroon.create(root_key=b"r" * 32, identifier=ring.new_identifier())
    token = add_approval_caveat(
        root,
        ring=ring,
        approver_public_key=approver.public_key(),
        location="https://approver.internal/v1",
        task_id="task-1",
        expires_at=1_800_000_600,
    )
    return token, ring, approver


def test_approval_caveat_ids_open_for_the_approver_and_verify_for_the_ring() -> None:
    token, ring, approver = _approval_token()
    caveat_id = token.caveats[-1].caveat_id
    opened = open_approval_caveat(caveat_id, approver)
    assert opened is not None
    assert opened.box.task_id == "task-1"
    assert approval_tag_valid(ring, caveat_id, derive_key(opened.caveat_key))
    assert not approval_tag_valid(ring, caveat_id, derive_key(b"other"))
    assert not approval_tag_valid(
        RootKeyRing.generate("k1"), caveat_id, derive_key(opened.caveat_key)
    )
    assert open_approval_caveat(caveat_id, generate_private_key()) is None
    assert approval_scope(caveat_id) is not None


def test_non_canonical_or_broken_caveat_ids_are_not_approval_caveats() -> None:
    token, ring, approver = _approval_token()
    caveat_id = token.caveats[-1].caveat_id
    parsed = ApprovalCaveatId.decode(caveat_id)
    assert parsed is not None
    spaced = json.dumps(json.loads(caveat_id), indent=1).encode()
    assert ApprovalCaveatId.decode(spaced) is None
    assert ApprovalCaveatId.decode(b"\xff") is None
    assert ApprovalCaveatId.decode(b"[]") is None
    assert approval_scope(b"not json") is None
    assert not approval_tag_valid(ring, b"not json", b"k")
    bad_tag = parsed.model_copy(update={"tag": "!!"}).encode()
    assert not approval_tag_valid(ring, bad_tag, b"k")
    bad_box = parsed.model_copy(update={"box": "!!"}).encode()
    assert open_approval_caveat(bad_box, approver) is None
    not_json_box = parsed.model_copy(
        update={
            "box": b64u_encode(seal(approver.public_key(), b"nope", context=b"ctb-approval-box-v1"))
        }
    ).encode()
    assert open_approval_caveat(not_json_box, approver) is None
    short_key_box = parsed.model_copy(
        update={
            "box": b64u_encode(
                seal(
                    approver.public_key(),
                    json.dumps(
                        {"v": 1, "caveat_key": b64u_encode(b"x"), "task_id": "t", "expires_at": 1}
                    ).encode(),
                    context=b"ctb-approval-box-v1",
                )
            )
        }
    ).encode()
    assert open_approval_caveat(short_key_box, approver) is None
    stateful = parsed.model_copy(update={"scope": "max_calls <= 1"}).encode()
    assert approval_scope(stateful) is None
    unparsable = parsed.model_copy(update={"scope": "nonsense"}).encode()
    assert approval_scope(unparsable) is None
    with pytest.raises(ValueError, match="stateless"):
        add_approval_caveat(
            token,
            ring=ring,
            approver_public_key=approver.public_key(),
            location="https://approver.internal/v1",
            task_id="task-1",
            expires_at=1,
            scope="max_calls <= 1",
        )


def test_key_text_maps() -> None:
    key = generate_ed25519()
    assert load_ed25519_public(ed25519_public_text(key.public_key())).public_bytes_raw() == (
        key.public_key().public_bytes_raw()
    )
    assert (
        load_ed25519_private(ed25519_private_text(key)).private_bytes_raw()
        == key.private_bytes_raw()
    )
    keys = parse_public_key_map(f"agent-host:{ed25519_public_text(key.public_key())}, ")
    assert list(keys) == ["agent-host"]
    secrets_map = {"invoices": generate_secret(), "files": generate_secret()}
    assert parse_secret_map(secret_map_text(secrets_map)) == secrets_map
    for bad in ("x", "Bad:AAAA", "a:AAAA,a:AAAA"):
        with pytest.raises(ValueError, match="entries"):
            parse_public_key_map(bad)
    with pytest.raises(ValueError, match="shorter"):
        parse_secret_map(f"invoices:{b64u_encode(b'short')}")
    with pytest.raises(ValueError, match="32 bytes"):
        load_ed25519_public(b64u_encode(b"x"))
    with pytest.raises(ValueError, match="32 bytes"):
        load_ed25519_private(b64u_encode(b"x"))
    with pytest.raises(MacaroonFormatError):
        parse_secret_map("invoices:!!")
