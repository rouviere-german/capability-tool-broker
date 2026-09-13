"""Client-credential JWT authentication."""

from __future__ import annotations

import jwt
import pytest

from capability_tool_broker.authority.clientauth import (
    MAX_ASSERTION_LIFETIME,
    ClientAssertionVerifier,
    ClientAuthError,
    make_client_assertion,
)
from capability_tool_broker.capabilities.keyfiles import generate_ed25519

pytestmark = pytest.mark.unit

NOW = 1_800_000_000
KEY = generate_ed25519()
OTHER = generate_ed25519()


def verifier(**kwargs: object) -> ClientAssertionVerifier:
    return ClientAssertionVerifier(
        {"agent-host": KEY.public_key()},
        audience="broker",
        clock=lambda: float(NOW),
        **kwargs,  # type: ignore[arg-type]
    )


def assertion(**overrides: object) -> str:
    claims: dict[str, object] = {
        "iss": "agent-host",
        "sub": "agent-host",
        "aud": "broker",
        "iat": NOW,
        "exp": NOW + 60,
        "jti": "0123456789abcdef0123",
    }
    claims.update(overrides)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, KEY, algorithm="EdDSA")


def test_valid_assertions_authenticate_once() -> None:
    check = verifier()
    token = make_client_assertion(
        client_id="agent-host", private_key=KEY, audience="broker", now=NOW
    )
    assert check.verify(token) == "agent-host"
    with pytest.raises(ClientAuthError, match="replayed"):
        check.verify(token)
    assert check.audience == "broker"


@pytest.mark.parametrize(
    ("token", "message"),
    [
        ("", "missing"),
        ("x" * 5000, "oversized"),
        ("not.a.jwt", "malformed"),
        (
            jwt.encode(
                {"iss": "agent-host"}, "secret-key-for-hmac-confusion-000", algorithm="HS256"
            ),
            "EdDSA",
        ),
        (assertion(iss="stranger"), "unknown client"),
        (assertion(iss=None), "unknown client"),
        (assertion(aud="authority"), "claims invalid"),
        (assertion(jti=None), "claims invalid"),
        (assertion(sub="someone-else"), "subject"),
        (assertion(iat=NOW + 60, exp=NOW + 120), "future"),
        (assertion(iat=NOW - 200, exp=NOW - 100), "expired"),
        (assertion(exp=NOW + MAX_ASSERTION_LIFETIME + 1), "lifetime"),
        (assertion(jti="short"), "jti"),
        (assertion(iat="now"), "integers"),
    ],
)
def test_invalid_assertions_are_rejected(token: str, message: str) -> None:
    with pytest.raises(ClientAuthError, match=message):
        verifier().verify(token)


def test_unsigned_and_wrongly_signed_assertions_are_rejected() -> None:
    header_none = jwt.encode(
        {
            "iss": "agent-host",
            "sub": "agent-host",
            "aud": "broker",
            "iat": NOW,
            "exp": NOW + 1,
            "jti": "a" * 20,
        },
        None,  # type: ignore[arg-type]
        algorithm="none",
    )
    with pytest.raises(ClientAuthError, match="EdDSA"):
        verifier().verify(header_none)
    forged = make_client_assertion(
        client_id="agent-host", private_key=OTHER, audience="broker", now=NOW
    )
    with pytest.raises(ClientAuthError, match="signature"):
        verifier().verify(forged)


def test_replay_cache_fails_closed_when_full() -> None:
    check = verifier(max_tracked_jtis=1)
    check.verify(assertion(jti="a" * 20))
    with pytest.raises(ClientAuthError, match="full"):
        check.verify(assertion(jti="b" * 20))
