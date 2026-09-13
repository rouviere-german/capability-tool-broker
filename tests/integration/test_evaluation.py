"""The evaluation harnesses at test scale (the bench runs them at full scale)."""

from __future__ import annotations

import importlib.util
import random
from pathlib import Path
from types import ModuleType

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from capability_tool_broker.evaluation.forgery import run_forgery
from capability_tool_broker.evaluation.perf import percentile, run_perf
from capability_tool_broker.evaluation.scenarios import (
    BENIGN_TASKS,
    SCENARIOS,
    run_escalation,
    run_scenario,
)
from capability_tool_broker.evaluation.soundness import (
    Spec,
    UniverseRequest,
    _system,
    check_chain,
    oracle_allows,
    random_chain,
    run_soundness,
    universe,
)

pytestmark = pytest.mark.integration

REQUESTS = universe()
SYSTEM = _system(REQUESTS)


def test_the_universe_has_the_specified_shape() -> None:
    assert len(REQUESTS) == 5 * 20 * 3 * 3
    assert len({(r.tool, r.resource, r.verb, r.now) for r in REQUESTS}) == len(REQUESTS)


@settings(max_examples=15, deadline=None)
@given(st.randoms(use_true_random=False))
def test_authorized_sets_equal_the_oracle_and_children_only_narrow(rng: random.Random) -> None:
    parent = random_chain(rng)
    extra = random_chain(rng, 1, 3)
    mismatches, sut_subset, oracle_subset, _ = check_chain(SYSTEM, REQUESTS, parent, extra)
    assert mismatches == 0
    assert sut_subset
    assert oracle_subset


def test_soundness_run_reports_no_mismatches_and_is_not_vacuous() -> None:
    report = run_soundness(chains=20, seed=3)
    assert report.mismatches == 0
    assert report.subset_violations == 0
    assert 0 < report.chains_with_nonempty_set < report.chains
    assert report.verifications == 20 * 2 * 900


def test_the_oracle_distinguishes_requests() -> None:
    request = UniverseRequest("invoices_read", "invoice/42", "read", 1_800_000_000, 100)
    assert oracle_allows([Spec("resource", ("invoice/*",))], request)
    assert not oracle_allows([Spec("resource", ("file/**",))], request)
    assert not oracle_allows([Spec("approval", ("read",))], request)
    assert oracle_allows([Spec("arg", op=">=", number=100), Spec("max", number=1)], request)
    assert not oracle_allows([Spec("expires", number=1_800_000_000)], request)


def test_forgery_suite_accepts_nothing(tmp_path: Path) -> None:
    report = run_forgery(tmp_path, masks=(0x01,))
    assert report.controls_ok
    assert report.total_accepted == 0
    assert len(report.attempts) == 8
    assert report.total_attempts > 1_000
    assert all(count > 0 for count in report.attempts.values())


def test_scenario_catalog() -> None:
    assert len(SCENARIOS) == 40
    assert len(BENIGN_TASKS) == 30
    assert len({s.name for s in (*SCENARIOS, *BENIGN_TASKS)}) == 70
    assert len({s.family for s in SCENARIOS}) == 11


def test_escalation_suite_broker_versus_ambient_keys(tmp_path: Path) -> None:
    report = run_escalation(tmp_path)
    assert report.failures == []
    assert report.capability_unauthorized_effects == 0
    assert report.ambient_scenarios_with_unauthorized == 40
    assert report.capability_benign_completed == 30
    assert report.ambient_benign_completed == 30


def test_a_single_scenario_result_explains_itself(tmp_path: Path) -> None:
    scenario = next(s for s in SCENARIOS if s.name == "replay-mail")
    capability = run_scenario(scenario, tmp_path / "cap", "capability")
    ambient = run_scenario(scenario, tmp_path / "amb", "ambient")
    assert capability.effects == {"send:mail/alice@example.com": 1}
    assert capability.completed
    assert ambient.unauthorized == 3
    assert not ambient.completed


def test_perf_harness_and_percentiles(tmp_path: Path) -> None:
    results = run_perf(tmp_path, verify_runs=40, call_runs=10, http_runs=5)
    assert set(results) == {
        "verify_10_caveats",
        "decide_write_with_discharge",
        "broker_call_in_process",
        "broker_call_no_audit",
        "broker_call_http",
    }
    assert results["verify_10_caveats"]["p50_us"] <= results["verify_10_caveats"]["p99_us"]
    assert percentile([1.0, 2.0, 3.0, 4.0], 0.5) == 2.0
    assert percentile([5.0], 0.99) == 5.0


def _bench_module(repo_root: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "bench_baseline", repo_root / "bench" / "bench_baseline.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bench_threshold_checks(repo_root: Path) -> None:
    bench = _bench_module(repo_root)
    results = {"a": {"b": 3, "ok": True}, "c": 1.5}
    thresholds = {"a.b": {"max": 2}, "a.ok": {"min": 1}, "c": {"min": 2}, "missing": {"max": 1}}
    problems = bench.check_thresholds(results, thresholds)
    assert problems == [
        "a.b = 3.0 exceeds max 2",
        "c = 1.5 is below min 2",
        "missing: metric missing from results",
    ]
