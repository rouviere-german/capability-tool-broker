"""Counters, single-use nonces and revocation, for the in-memory and the Redis store."""

from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Callable

import fakeredis
import pytest
import redis
from hypothesis import given
from hypothesis import strategies as st

from capability_tool_broker.broker.state import (
    EXPIRY_GRACE_SECONDS,
    CommitResult,
    MemoryStateStore,
    RedisStateStore,
    StateStore,
    StateUnavailableError,
)
from capability_tool_broker.capabilities.verifier import StateClaim

pytestmark = pytest.mark.unit

NOW = 1_800_000_000
FACTORIES: dict[str, Callable[[], StateStore]] = {
    "memory": MemoryStateStore,
    "redis": lambda: RedisStateStore(fakeredis.FakeRedis()),
}


def counter(key: str, limit: int, expires_at: int | None = None) -> StateClaim:
    return StateClaim("max_calls", key, limit, expires_at)


def once(key: str, expires_at: int | None = None) -> StateClaim:
    return StateClaim("once", key, 1, expires_at)


@pytest.fixture(params=sorted(FACTORIES))
def store(request: pytest.FixtureRequest) -> StateStore:
    return FACTORIES[str(request.param)]()


def test_counters_admit_exactly_the_limit(store: StateStore) -> None:
    results = [store.commit([counter("a", 3, NOW + 60)], now=NOW) for _ in range(5)]
    assert [r.ok for r in results] == [True, True, True, False, False]
    assert results[-1] == CommitResult(False, "exhausted", "a")
    assert store.count("a") == 3


def test_commits_are_all_or_nothing(store: StateStore) -> None:
    claims = [counter("wide", 10), counter("narrow", 1)]
    assert store.commit(claims, now=NOW).ok
    denied = store.commit(claims, now=NOW)
    assert denied.reason == "exhausted"
    assert store.count("wide") == 1  # the wide counter was not incremented by the denied call
    replay = store.commit([counter("wide", 10), once("n1")], now=NOW)
    assert replay.ok
    assert store.commit([counter("wide", 10), once("n1")], now=NOW).reason == ("replayed")
    assert store.count("wide") == 2


def test_empty_commits_succeed(store: StateStore) -> None:
    assert store.commit([], now=NOW).ok


def test_revocation(store: StateStore) -> None:
    assert not store.is_revoked("abc", now=NOW)
    store.revoke("abc", until=NOW + 60, now=NOW)
    assert store.is_revoked("abc", now=NOW)
    assert store.ping()


def test_concurrent_commits_never_exceed_the_limit(store: StateStore) -> None:
    successes: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(25):
            ok = store.commit([counter("shared", 40), counter("other", 1000)], now=NOW).ok
            with lock:
                successes.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert successes.count(True) == 40
    assert store.count("shared") == 40
    assert store.count("other") == 40


@given(
    kind=st.sampled_from(sorted(FACTORIES)),
    operations=st.lists(
        st.lists(
            st.tuples(st.sampled_from(["c1", "c2", "o1", "o2"]), st.integers(1, 3)),
            min_size=1,
            max_size=3,
            unique_by=lambda item: item[0],
        ),
        max_size=12,
    ),
)
def test_store_matches_a_sequential_model(
    kind: str, operations: list[list[tuple[str, int]]]
) -> None:
    store = FACTORIES[kind]()
    counts: Counter[str] = Counter()
    used: set[str] = set()
    for step in operations:
        claims = [once(key) if key.startswith("o") else counter(key, limit) for key, limit in step]
        expected_ok = all(
            (key not in used) if key.startswith("o") else counts[key] + 1 <= limit
            for key, limit in step
        )
        assert store.commit(claims, now=NOW).ok is expected_ok
        if expected_ok:
            for key, _ in step:
                if key.startswith("o"):
                    used.add(key)
                else:
                    counts[key] += 1
    for key in ("c1", "c2"):
        assert store.count(key) == counts[key]


def test_memory_state_lives_until_shortly_after_the_token_expires() -> None:
    store = MemoryStateStore()
    assert store.commit([counter("k", 1, NOW + 10), once("n", NOW + 10)], now=NOW).ok
    assert not store.commit([counter("k", 1, NOW + 10)], now=NOW).ok
    later = NOW + 10 + EXPIRY_GRACE_SECONDS + 1
    assert store.commit([counter("k", 1, NOW + 10), once("n", NOW + 10)], now=later).ok
    store.revoke("t", until=NOW, now=NOW)
    assert not store.is_revoked("t", now=later)


def test_redis_keys_expire_with_the_token() -> None:
    client = fakeredis.FakeRedis()
    store = RedisStateStore(client, prefix="test:")
    assert store.commit([counter("k", 2, NOW + 100), once("n", NOW + 100)], now=NOW).ok
    assert client.expiretime("test:calls:k") == NOW + 100 + EXPIRY_GRACE_SECONDS
    assert client.expiretime("test:once:n") == NOW + 100 + EXPIRY_GRACE_SECONDS


def test_memory_commits_never_shorten_a_keys_lifetime() -> None:
    store = MemoryStateStore()
    assert store.commit([counter("k", 1, NOW + 900)], now=NOW).ok
    assert store.commit([once("n", NOW + 900)], now=NOW).ok
    # Claims for the same keys that arrive with an earlier expiry must not cut the lifetime short.
    assert not store.commit([counter("k", 1, NOW + 1)], now=NOW).ok
    assert not store.commit([once("n", NOW + 1)], now=NOW).ok
    later = NOW + 1 + EXPIRY_GRACE_SECONDS + 1
    assert store.commit([counter("k", 1, NOW + 900)], now=later).reason == "exhausted"
    assert store.commit([once("n", NOW + 900)], now=later).reason == "replayed"
    assert store.commit([counter("forever", 1, None)], now=NOW).ok
    assert not store.commit([counter("forever", 1, NOW + 1)], now=NOW).ok
    assert store.commit([counter("forever", 1, None)], now=NOW + 10**6).reason == "exhausted"


def test_redis_commits_never_shorten_a_keys_lifetime() -> None:
    client = fakeredis.FakeRedis()
    store = RedisStateStore(client, prefix="test:")
    assert store.commit([counter("k", 5, NOW + 900)], now=NOW).ok
    assert store.commit([counter("k", 5, NOW + 1)], now=NOW).ok
    assert client.expiretime("test:calls:k") == NOW + 900 + EXPIRY_GRACE_SECONDS
    assert store.commit([counter("k", 5, NOW + 2000)], now=NOW).ok
    assert client.expiretime("test:calls:k") == NOW + 2000 + EXPIRY_GRACE_SECONDS
    assert store.commit([counter("p", 5, None)], now=NOW).ok
    assert store.commit([counter("p", 5, NOW + 1)], now=NOW).ok
    assert client.expiretime("test:calls:p") == -1
    assert store.commit([counter("q", 5, NOW + 1)], now=NOW).ok
    assert store.commit([counter("q", 5, None)], now=NOW).ok
    assert client.expiretime("test:calls:q") == -1
    assert store.count("q") == 2


def test_release_gives_back_counters_and_nonces_but_never_goes_negative(
    store: StateStore,
) -> None:
    claims = [counter("r", 1, NOW + 60), once("m", NOW + 60)]
    assert store.commit(claims, now=NOW).ok
    assert not store.commit(claims, now=NOW).ok
    store.release(claims, now=NOW)
    assert store.count("r") == 0
    assert store.commit(claims, now=NOW).ok
    assert store.commit([counter("r", 1, NOW + 60)], now=NOW).reason == "exhausted"
    store.release([counter("never-used", 3)], now=NOW)
    store.release([], now=NOW)
    assert store.count("never-used") == 0


def test_redis_outages_fail_closed() -> None:
    server = fakeredis.FakeServer()
    server.connected = False
    store = RedisStateStore(fakeredis.FakeRedis(server=server))
    assert not store.ping()
    with pytest.raises(StateUnavailableError):
        store.commit([counter("k", 1)], now=NOW)
    with pytest.raises(StateUnavailableError):
        store.release([counter("k", 1), once("n")], now=NOW)
    with pytest.raises(StateUnavailableError):
        store.revoke("t", until=None, now=NOW)
    with pytest.raises(StateUnavailableError):
        store.is_revoked("t", now=NOW)


def test_redis_contention_is_reported_after_bounded_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = fakeredis.FakeRedis()
    store = RedisStateStore(client, max_retries=3)
    attempts: list[int] = []

    def always_conflict(self: object, *args: object, **kwargs: object) -> None:
        attempts.append(1)
        raise redis.WatchError

    monkeypatch.setattr(redis.client.Pipeline, "execute", always_conflict)
    assert store.commit([counter("k", 5)], now=NOW) == CommitResult(False, "contention")
    assert len(attempts) == 3
    with pytest.raises(StateUnavailableError, match="contention"):
        store.release([counter("k", 5)], now=NOW)
    assert len(attempts) == 6
