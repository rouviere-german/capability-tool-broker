"""Client-credential JWTs: EdDSA client assertions in the style of RFC 7523 ``private_key_jwt``.

A client proves its identity with a short-lived JWT signed by its Ed25519 private key; the
verifier holds only public keys. Checks: the header algorithm must be ``EdDSA`` (``none`` and HMAC
algorithms are refused before any key is looked up, which rules out algorithm confusion), the
issuer must be a registered client and equal the subject, the audience must be this service,
lifetimes are capped at five minutes, time claims are checked against an injectable clock with a
small leeway, and every ``jti`` is accepted once.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from typing import NamedTuple

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import Request
from starlette.datastructures import Headers

from capability_tool_broker.core.errors import AppError
from capability_tool_broker.core.logging import get_logger

__all__ = [
    "MAX_ASSERTION_LIFETIME",
    "ClientAssertionVerifier",
    "ClientAuthError",
    "bearer_client_dependency",
    "bearer_subject",
    "make_client_assertion",
]

_log = get_logger("capability_tool_broker.clientauth")

MAX_ASSERTION_LIFETIME = 300
_ALGORITHM = "EdDSA"
_MAX_ASSERTION_CHARS = 4_096
_JTI = re.compile(r"[A-Za-z0-9_-]{16,128}")
_REQUIRED = ("iss", "sub", "aud", "iat", "exp", "jti")


class ClientAuthError(Exception):
    """Authentication failed. The message is safe to log; clients only ever see a 401."""


class _Checked(NamedTuple):
    issuer: str
    jti: str
    expires: int
    now: float


def make_client_assertion(
    *,
    client_id: str,
    private_key: Ed25519PrivateKey,
    audience: str,
    now: int,
    ttl_seconds: int = 60,
    jti: str | None = None,
) -> str:
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": jti or secrets.token_hex(16),
    }
    return jwt.encode(claims, private_key, algorithm=_ALGORITHM)


class ClientAssertionVerifier:
    def __init__(
        self,
        clients: Mapping[str, Ed25519PublicKey],
        *,
        audience: str,
        clock: Callable[[], float] = time.time,
        leeway_seconds: int = 5,
        max_tracked_jtis: int = 100_000,
    ) -> None:
        self._clients = dict(clients)
        self._audience = audience
        self._clock = clock
        self._leeway = leeway_seconds
        self._max_jtis = max_tracked_jtis
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    @property
    def audience(self) -> str:
        return self._audience

    def verify(self, assertion: str) -> str:
        """Return the authenticated client id or raise ClientAuthError."""
        checked = self._check(assertion)
        with self._lock:
            if len(self._seen) >= self._max_jtis:
                self._seen = {k: v for k, v in self._seen.items() if v > checked.now}
                if len(self._seen) >= self._max_jtis:
                    raise ClientAuthError("replay cache full")
            replay_key = f"{checked.issuer}:{checked.jti}"
            if replay_key in self._seen and self._seen[replay_key] > checked.now:
                raise ClientAuthError("assertion replayed")
            self._seen[replay_key] = checked.expires + self._leeway
        return checked.issuer

    def peek_subject(self, assertion: str) -> str | None:
        """The client id of a correctly signed, unexpired assertion for this audience, else None.

        The one-time ``jti`` is not consumed (the endpoint's authentication does that), which suits
        rate-limit keying: only someone holding a valid assertion for a client can charge that
        client's bucket, and forged assertions fall back to the caller's address bucket.
        """
        try:
            return self._check(assertion).issuer
        except ClientAuthError:
            return None

    def _check(self, assertion: str) -> _Checked:
        """Every check except the one-time ``jti``."""
        if not assertion or len(assertion) > _MAX_ASSERTION_CHARS:
            raise ClientAuthError("missing or oversized assertion")
        try:
            header = jwt.get_unverified_header(assertion)
            unverified = jwt.decode(assertion, options={"verify_signature": False})
        except jwt.InvalidTokenError as exc:
            raise ClientAuthError("malformed assertion") from exc
        if header.get("alg") != _ALGORITHM:
            raise ClientAuthError("assertion algorithm must be EdDSA")
        issuer = unverified.get("iss")
        if not isinstance(issuer, str):
            raise ClientAuthError("unknown client")
        key = self._clients.get(issuer)
        if key is None:
            raise ClientAuthError("unknown client")
        try:
            claims = jwt.decode(
                assertion,
                key,
                algorithms=[_ALGORITHM],
                audience=self._audience,
                issuer=issuer,
                options={
                    "require": list(_REQUIRED),
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.InvalidTokenError as exc:
            raise ClientAuthError("assertion signature or claims invalid") from exc
        if claims.get("sub") != issuer:
            raise ClientAuthError("subject must equal issuer")
        issued_at, expires = claims.get("iat"), claims.get("exp")
        if not isinstance(issued_at, int) or not isinstance(expires, int):
            raise ClientAuthError("iat and exp must be integers")
        now = self._clock()
        if issued_at > now + self._leeway:
            raise ClientAuthError("assertion issued in the future")
        if expires <= now - self._leeway:
            raise ClientAuthError("assertion expired")
        if expires - issued_at > MAX_ASSERTION_LIFETIME:
            raise ClientAuthError("assertion lifetime too long")
        jti = claims.get("jti")
        if not isinstance(jti, str) or not _JTI.fullmatch(jti):
            raise ClientAuthError("invalid jti")
        return _Checked(issuer, jti, expires, now)


def _bearer(headers: Headers) -> str:
    header = headers.get("authorization", "")
    return header[7:].strip() if header[:7].lower() == "bearer " else ""


def bearer_subject(verifier: ClientAssertionVerifier) -> Callable[[Headers], str | None]:
    """Rate-limit principal: the verified client id of the request's bearer assertion, if any."""

    def subject(headers: Headers) -> str | None:
        assertion = _bearer(headers)
        return verifier.peek_subject(assertion) if assertion else None

    return subject


def bearer_client_dependency(verifier: ClientAssertionVerifier) -> Callable[[Request], str]:
    """FastAPI dependency: authenticate ``Authorization: Bearer <client assertion>``."""

    def dependency(request: Request) -> str:
        assertion = _bearer(request.headers)
        try:
            return verifier.verify(assertion)
        except ClientAuthError as exc:
            request.app.state.metrics.auth_failures_total.inc()
            _log.info("client_auth_failed", reason=str(exc))
            raise AppError(
                401,
                "unauthorized",
                "A valid client assertion is required.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

    return dependency
