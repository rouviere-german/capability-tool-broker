"""Broker state: call counters, single-use nonces and the revocation denylist.

``commit`` is all-or-nothing: either every ``max_calls`` counter is below its limit and every
``once`` key is unused, and then all counters are incremented and all once-keys recorded in one
step, or nothing changes. The Redis store uses WATCH/MULTI/EXEC (optimistic transactions retried on
conflict), so concurrent brokers never admit more calls than a limit allows.

Lifetimes: each claim carries the earliest expiry of the chain prefix before its caveat (see
:class:`~capability_tool_broker.capabilities.verifier.StateClaim`), and a key lives until that
expiry plus :data:`EXPIRY_GRACE_SECONDS`. Every holder that can present the key's prefix is expired
by then, so forgetting the key cannot re-admit a call. A commit never shortens an existing key's
lifetime (a key without expiry stays without expiry), so state cannot be reset early even if claims
for one key ever disagreed. Claims whose prefix has no expiry persist.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

import redis

from capability_tool_broker.capabilities.verifier import StateClaim

__all__ = [
    "EXPIRY_GRACE_SECONDS",
    "CommitResult",
    "MemoryStateStore",
    "RedisStateStore",
    "StateStore",
    "StateUnavailableError",
]

EXPIRY_GRACE_SECONDS = 300


class StateUnavailableError(Exception):
    """The state backend could not be reached; the broker fails closed."""


@dataclass(frozen=True, slots=True)
class CommitResult:
    ok: bool
    reason: Literal["exhausted", "replayed", "contention"] | None = None
    key: str | None = None


class StateStore(Protocol):
    def ping(self) -> bool: ...

    def commit(self, claims: Sequence[StateClaim], *, now: int) -> CommitResult: ...

    def revoke(self, token_nonce: str, *, until: int | None, now: int) -> None: ...

    def is_revoked(self, token_nonce: str, *, now: int) -> bool: ...

    def count(self, key: str) -> int: ...


def _expiry(expires_at: int | None, now: int) -> int | None:
    return None if expires_at is None else max(expires_at, now) + EXPIRY_GRACE_SECONDS


def _later(first: int | None, second: int | None) -> int | None:
    """The later of two expiries, where None means never."""
    return None if first is None or second is None else max(first, second)


def _merge_lifetime(expiry: int | None, existing: int) -> int | None:
    """Combine a claim's key expiry with the live key's EXPIRETIME (-1: none, -2: gone)."""
    if existing == -1:
        return None
    return expiry if existing < 0 else _later(existing, expiry)


def _queue_writes(
    pipe: redis.client.Pipeline,
    counters: Sequence[tuple[str, int | None, bool]],
    onces: Sequence[tuple[str, int | None]],
) -> None:
    for key, expiry, existed in counters:
        pipe.incr(key)
        if expiry is not None:
            pipe.expireat(key, expiry)
        elif existed:
            pipe.persist(key)
    for key, expiry in onces:
        pipe.set(key, b"1", exat=expiry)


class MemoryStateStore:
    """Single-process store (tests, demo and the in-process bench)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, tuple[int, int | None]] = {}
        self._once: dict[str, int | None] = {}
        self._revoked: dict[str, int | None] = {}

    @staticmethod
    def _live(expiry: int | None, now: int) -> bool:
        return expiry is None or expiry > now

    def ping(self) -> bool:
        return True

    def commit(self, claims: Sequence[StateClaim], *, now: int) -> CommitResult:
        with self._lock:
            for claim in claims:
                if claim.kind == "max_calls":
                    if self._current(claim.key, now) + 1 > claim.limit:
                        return CommitResult(False, "exhausted", claim.key)
                elif claim.key in self._once and self._live(self._once[claim.key], now):
                    return CommitResult(False, "replayed", claim.key)
            for claim in claims:
                expiry = _expiry(claim.expires_at, now)
                if claim.kind == "max_calls":
                    value, previous = self._counters.get(claim.key, (0, None))
                    if value and self._live(previous, now):
                        self._counters[claim.key] = (value + 1, _later(previous, expiry))
                    else:
                        self._counters[claim.key] = (1, expiry)
                else:
                    self._once[claim.key] = expiry
        return CommitResult(True)

    def _current(self, key: str, now: int) -> int:
        value, expiry = self._counters.get(key, (0, None))
        return value if self._live(expiry, now) else 0

    def revoke(self, token_nonce: str, *, until: int | None, now: int) -> None:
        with self._lock:
            self._revoked[token_nonce] = _expiry(until, now)

    def is_revoked(self, token_nonce: str, *, now: int) -> bool:
        with self._lock:
            return token_nonce in self._revoked and self._live(self._revoked[token_nonce], now)

    def count(self, key: str) -> int:
        with self._lock:
            return self._counters.get(key, (0, None))[0]


class RedisStateStore:
    """Redis 7 store; atomic commits through optimistic WATCH/MULTI/EXEC transactions."""

    def __init__(self, client: redis.Redis, *, prefix: str = "ctb:", max_retries: int = 32) -> None:
        self._client = client
        self._prefix = prefix
        self._max_retries = max_retries

    def _counter_key(self, key: str) -> str:
        return f"{self._prefix}calls:{key}"

    def _once_key(self, key: str) -> str:
        return f"{self._prefix}once:{key}"

    def _revoked_key(self, nonce: str) -> str:
        return f"{self._prefix}revoked:{nonce}"

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except redis.RedisError:
            return False

    def commit(self, claims: Sequence[StateClaim], *, now: int) -> CommitResult:
        counters = [(self._counter_key(c.key), c) for c in claims if c.kind == "max_calls"]
        onces = [(self._once_key(c.key), c) for c in claims if c.kind == "once"]
        if not counters and not onces:
            return CommitResult(True)
        watched = [key for key, _ in counters] + [key for key, _ in onces]
        try:
            for _ in range(self._max_retries):
                with self._client.pipeline() as pipe:
                    try:
                        pipe.watch(*watched)  # type: ignore[no-untyped-call]
                        lifetimes: list[tuple[str, int | None, bool]] = []
                        for key, claim in counters:
                            current = pipe.get(key)
                            if int(current or 0) + 1 > claim.limit:
                                return CommitResult(False, "exhausted", claim.key)
                            expiry = _expiry(claim.expires_at, now)
                            if current is not None:
                                expiry = _merge_lifetime(expiry, int(pipe.expiretime(key)))
                            lifetimes.append((key, expiry, current is not None))
                        for key, claim in onces:
                            if pipe.exists(key):
                                return CommitResult(False, "replayed", claim.key)
                        pipe.multi()
                        _queue_writes(
                            pipe, lifetimes, [(k, _expiry(c.expires_at, now)) for k, c in onces]
                        )
                        pipe.execute()
                        return CommitResult(True)
                    except redis.WatchError:
                        continue
        except redis.RedisError as exc:
            raise StateUnavailableError("state store unavailable") from exc
        return CommitResult(False, "contention")

    def revoke(self, token_nonce: str, *, until: int | None, now: int) -> None:
        try:
            self._client.set(self._revoked_key(token_nonce), b"1", exat=_expiry(until, now))
        except redis.RedisError as exc:
            raise StateUnavailableError("state store unavailable") from exc

    def is_revoked(self, token_nonce: str, *, now: int) -> bool:
        del now  # Redis expires the entry itself
        try:
            return bool(self._client.exists(self._revoked_key(token_nonce)))
        except redis.RedisError as exc:
            raise StateUnavailableError("state store unavailable") from exc

    def count(self, key: str) -> int:
        return int(self._client.get(self._counter_key(key)) or 0)
