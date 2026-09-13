"""The stateful harness's reproducible draws."""

from __future__ import annotations

import pytest

from capability_tool_broker.evaluation.stateful import Draws

pytestmark = pytest.mark.unit


def test_draws_are_reproducible_from_the_seed_and_stay_in_range() -> None:
    first, again, other = Draws(7), Draws(7), Draws(8)
    sequence = [first.randint(1, 6) for _ in range(200)]
    assert sequence == [again.randint(1, 6) for _ in range(200)]
    assert sequence != [other.randint(1, 6) for _ in range(200)]
    assert set(sequence) == {1, 2, 3, 4, 5, 6}
    floats = [first.random() for _ in range(200)]
    assert all(0.0 <= value < 1.0 for value in floats)
    assert {first.choice("abc") for _ in range(100)} == {"a", "b", "c"}
