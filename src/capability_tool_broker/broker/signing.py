"""HMAC request signing between the broker and upstream services.

The broker signs every upstream request with the service's credential; the services accept only
requests whose signature verifies, whose timestamp is within the allowed skew and whose nonce has
not been seen. An agent that bypasses the broker has no credential and gets 401.

String to sign (newline-separated)::

    CTB-HMAC-SHA256-v1, METHOD, path, unix timestamp, nonce, hex SHA-256 of the body
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "HEADER_KEY_ID",
    "HEADER_NONCE",
    "HEADER_SIGNATURE",
    "HEADER_TIMESTAMP",
    "RequestSignatureVerifier",
    "ServiceCredential",
    "SignatureCheck",
    "sign_request",
    "string_to_sign",
]

HEADER_KEY_ID = "x-ctb-key-id"
HEADER_TIMESTAMP = "x-ctb-timestamp"
HEADER_NONCE = "x-ctb-nonce"
HEADER_SIGNATURE = "x-ctb-signature"
_ALGORITHM = "CTB-HMAC-SHA256-v1"
_NONCE = re.compile(r"[0-9a-f]{32}")
_SIGNATURE = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP = re.compile(r"[0-9]{1,12}")


@dataclass(frozen=True, slots=True)
class ServiceCredential:
    key_id: str
    secret: bytes

    def __repr__(self) -> str:
        return f"ServiceCredential(key_id={self.key_id!r}, secret=<redacted>)"


def string_to_sign(method: str, path: str, timestamp: int, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([_ALGORITHM, method.upper(), path, str(timestamp), nonce, body_hash]).encode(
        "utf-8"
    )


def sign_request(
    credential: ServiceCredential,
    *,
    method: str,
    path: str,
    body: bytes,
    now: int,
    nonce: str | None = None,
) -> dict[str, str]:
    nonce = secrets.token_hex(16) if nonce is None else nonce
    signature = hmac.new(
        credential.secret, string_to_sign(method, path, now, nonce, body), hashlib.sha256
    ).hexdigest()
    return {
        HEADER_KEY_ID: credential.key_id,
        HEADER_TIMESTAMP: str(now),
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: signature,
    }


class SignatureCheck(StrEnum):
    OK = "ok"
    MISSING = "missing"
    UNKNOWN_KEY = "unknown_key"
    STALE = "stale"
    REPLAYED = "replayed"
    BAD_SIGNATURE = "bad_signature"


class RequestSignatureVerifier:
    """Service side: verify signature, clock skew and nonce freshness (thread-safe)."""

    def __init__(
        self,
        credentials: Mapping[str, bytes],
        *,
        max_skew_seconds: int = 30,
        clock: Callable[[], float] = time.time,
        max_nonces: int = 100_000,
    ) -> None:
        self._credentials = dict(credentials)
        self._skew = max_skew_seconds
        self._clock = clock
        self._max_nonces = max_nonces
        self._nonces: dict[str, float] = {}
        self._lock = threading.Lock()

    def verify(  # noqa: PLR0911 - one return per failure mode
        self, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> SignatureCheck:
        key_id = headers.get(HEADER_KEY_ID)
        timestamp = headers.get(HEADER_TIMESTAMP, "")
        nonce = headers.get(HEADER_NONCE, "")
        presented = headers.get(HEADER_SIGNATURE, "")
        if (
            key_id is None
            or not _TIMESTAMP.fullmatch(timestamp)
            or not _NONCE.fullmatch(nonce)
            or not _SIGNATURE.fullmatch(presented)
        ):
            return SignatureCheck.MISSING
        secret = self._credentials.get(key_id)
        if secret is None:
            return SignatureCheck.UNKNOWN_KEY
        expected = hmac.new(
            secret, string_to_sign(method, path, int(timestamp), nonce, body), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, presented):
            return SignatureCheck.BAD_SIGNATURE
        now = self._clock()
        if abs(now - int(timestamp)) > self._skew:
            return SignatureCheck.STALE
        with self._lock:
            if len(self._nonces) >= self._max_nonces:
                self._nonces = {n: exp for n, exp in self._nonces.items() if exp > now}
                if len(self._nonces) >= self._max_nonces:
                    return SignatureCheck.REPLAYED  # fail closed when the cache is saturated
            if nonce in self._nonces and self._nonces[nonce] > now:
                return SignatureCheck.REPLAYED
            self._nonces[nonce] = now + 2 * self._skew
        return SignatureCheck.OK
