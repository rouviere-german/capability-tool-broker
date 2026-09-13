"""Evaluation benchmarks for the capability broker, with CI regression thresholds.

Usage:
  uv run python bench/bench_baseline.py            # full run, writes bench/results/latest.json
  uv run python bench/bench_baseline.py --check    # also exit 1 if bench/thresholds.json fails
  uv run python bench/bench_baseline.py --quick    # small sizes, for a fast local smoke run

Sections (all CPU-only and offline):
  soundness   2,000 random caveat chains x 900 requests vs an independent reference evaluator
  stateful    1,000 random call sequences (delegation, approvals, discharge attenuation, clock
              jumps) through the broker vs a sequential reference counter model
  forgery     byte flips, caveat removal/reordering, signature splicing, discharge misuse
  escalation  42 confused-deputy/escalation scenarios and 30 benign tasks, broker vs ambient keys
  perf        verify latency (10 caveats) and broker round trips, repeated (--perf-repeats, default
              3); reported as the median and range over the repeats because single runs are noisy

Thresholds are either exact security bounds (for example zero accepted forgeries) or loose
latency ceilings well above the locally measured values, because CI runners are noisy. Latency
thresholds apply to the median over the repeats.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from capability_tool_broker.core.logging import configure_logging
from capability_tool_broker.evaluation.forgery import ForgeryReport, run_forgery
from capability_tool_broker.evaluation.perf import machine, run_perf
from capability_tool_broker.evaluation.scenarios import EscalationReport, run_escalation
from capability_tool_broker.evaluation.soundness import SoundnessReport, run_soundness
from capability_tool_broker.evaluation.stateful import StatefulReport, run_stateful

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "bench" / "results" / "latest.json"
THRESHOLDS = ROOT / "bench" / "thresholds.json"


def flatten(prefix: str, value: object, out: dict[str, float]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            flatten(f"{prefix}.{key}" if prefix else str(key), item, out)
    elif isinstance(value, (bool, int, float)):
        out[prefix] = float(value)


def check_thresholds(
    results: dict[str, object], thresholds: dict[str, dict[str, float]]
) -> list[str]:
    flat: dict[str, float] = {}
    flatten("", results, flat)
    problems: list[str] = []
    for metric, bounds in thresholds.items():
        if metric not in flat:
            problems.append(f"{metric}: metric missing from results")
            continue
        value = flat[metric]
        if "max" in bounds and value > bounds["max"]:
            problems.append(f"{metric} = {value} exceeds max {bounds['max']}")
        if "min" in bounds and value < bounds["min"]:
            problems.append(f"{metric} = {value} is below min {bounds['min']}")
    return problems


def summarize_perf(runs: list[dict[str, dict[str, float]]]) -> dict[str, dict[str, float]]:
    """Median p50/p99/mean per benchmark over repeated runs, plus the p99 range."""
    summary: dict[str, dict[str, float]] = {}
    for name in runs[0]:
        stats = [run[name] for run in runs]
        summary[name] = {
            "runs": stats[0]["runs"],
            "repeats": float(len(stats)),
            "p50_us": round(statistics.median(s["p50_us"] for s in stats), 1),
            "p99_us": round(statistics.median(s["p99_us"] for s in stats), 1),
            "mean_us": round(statistics.median(s["mean_us"] for s in stats), 1),
            "p99_min_us": min(s["p99_us"] for s in stats),
            "p99_max_us": max(s["p99_us"] for s in stats),
        }
    return summary


def print_tables(
    soundness: SoundnessReport,
    stateful: StatefulReport,
    forgery: ForgeryReport,
    escalation: EscalationReport,
    perf: dict[str, dict[str, float]],
) -> None:
    print("\n### Soundness (reference evaluator over a 900-request universe)\n")
    print("| chains | requests/chain | verifications | mismatches | child not subset | non-empty |")
    print("|---:|---:|---:|---:|---:|---:|")
    print(
        f"| {soundness.chains} | {soundness.requests_per_chain} | {soundness.verifications} "
        f"| {soundness.mismatches} | {soundness.subset_violations} "
        f"| {soundness.chains_with_nonempty_set} |"
    )
    print(
        f"\nMean fraction of the universe a parent authorizes: {soundness.mean_authorized_fraction}"
    )

    print("\n### Stateful semantics (sequential model)\n")
    print("| sequences | steps | calls | allowed | denied by state | mismatches |")
    print("|---:|---:|---:|---:|---:|---:|")
    print(
        f"| {stateful.sequences} | {stateful.steps} | {stateful.calls} | {stateful.allowed} "
        f"| {stateful.denied_by_state} | {stateful.mismatches} |"
    )

    print("\n### Forgery suite\n")
    print("| category | attempts | accepted |")
    print("|---|---:|---:|")
    for category, count in forgery.attempts.items():
        print(f"| {category} | {count} | {forgery.accepted[category]} |")
    print(f"| **total** | {forgery.total_attempts} | {forgery.total_accepted} |")
    print(
        f"\nControls (valid read, approved write, attenuated read) accepted: {forgery.controls_ok}"
    )

    print("\n### Confused-deputy and escalation scenarios\n")
    print(
        "| family | scenarios | unauthorized effects: broker | unauthorized effects: ambient keys |"
    )
    print("|---|---:|---:|---:|")
    for family, row in escalation.per_family.items():
        print(
            f"| {family} | {row['scenarios']} | {row['capability_unauthorized']} "
            f"| {row['ambient_unauthorized']} |"
        )
    print(
        f"| **total** | {escalation.scenarios} | {escalation.capability_unauthorized_effects} "
        f"| {escalation.ambient_unauthorized_effects} |"
    )
    print(
        f"\nScenarios with at least one unauthorized effect: broker "
        f"{escalation.capability_scenarios_with_unauthorized}/{escalation.scenarios}, ambient keys "
        f"{escalation.ambient_scenarios_with_unauthorized}/{escalation.scenarios}."
    )
    print(
        f"Utility: {escalation.capability_benign_completed}/{escalation.benign_tasks} benign tasks "
        f"completed under least-privilege tokens (ambient keys: "
        f"{escalation.ambient_benign_completed}/{escalation.benign_tasks})."
    )

    print("\n### Latency (median over repeats)\n")
    print(
        "| benchmark | calls per repeat | repeats | p50 (us) | p99 (us) | p99 range (us) "
        "| mean (us) |"
    )
    print("|---|---:|---:|---:|---:|---:|---:|")
    for name, stats in perf.items():
        print(
            f"| {name} | {stats['runs']:.0f} | {stats['repeats']:.0f} | {stats['p50_us']} "
            f"| {stats['p99_us']} | {stats['p99_min_us']} to {stats['p99_max_us']} "
            f"| {stats['mean_us']} |"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="capability broker evaluation benchmarks")
    parser.add_argument("--check", action="store_true", help="enforce bench/thresholds.json")
    parser.add_argument("--quick", action="store_true", help="small sizes for a smoke run")
    parser.add_argument(
        "--perf-repeats", type=int, default=None, help="latency repeats (default 3, quick 1)"
    )
    args = parser.parse_args(argv)
    configure_logging("WARNING", json_output=True, stream=sys.stderr)
    repeats = args.perf_repeats or (1 if args.quick else 3)

    seconds: dict[str, float] = {}
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        started = time.perf_counter()
        soundness = run_soundness(chains=60 if args.quick else 2_000)
        seconds["soundness"] = round(time.perf_counter() - started, 1)
        started = time.perf_counter()
        stateful = run_stateful(sequences=40 if args.quick else 1_000, steps=40, seed=7)
        seconds["stateful"] = round(time.perf_counter() - started, 1)
        started = time.perf_counter()
        masks = (0x01,) if args.quick else (0x01, 0x80, 0xFF)
        forgery = run_forgery(workdir / "forgery", masks=masks)
        seconds["forgery"] = round(time.perf_counter() - started, 1)
        started = time.perf_counter()
        escalation = run_escalation(workdir / "escalation")
        seconds["escalation"] = round(time.perf_counter() - started, 1)
        started = time.perf_counter()
        perf_runs = [
            run_perf(
                workdir / f"perf-{repeat}",
                verify_runs=1_000 if args.quick else 5_000,
                call_runs=200 if args.quick else 1_000,
                http_runs=100 if args.quick else 300,
            )
            for repeat in range(repeats)
        ]
        perf = summarize_perf(perf_runs)
        seconds["perf"] = round(time.perf_counter() - started, 1)

    results: dict[str, object] = {
        "soundness": asdict(soundness),
        "stateful": asdict(stateful),
        "forgery": {
            "controls_ok": forgery.controls_ok,
            "attempts": forgery.attempts,
            "accepted": forgery.accepted,
            "total_attempts": forgery.total_attempts,
            "total_accepted": forgery.total_accepted,
        },
        "escalation": asdict(escalation),
        "perf": perf,
        "perf_runs": perf_runs,
        "seconds": seconds,
    }
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps({"machine": machine(), "quick": args.quick, "results": results}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"machine": machine(), "quick": args.quick, "seconds": seconds}))
    print_tables(soundness, stateful, forgery, escalation, perf)
    if args.check:
        thresholds = json.loads(THRESHOLDS.read_text(encoding="utf-8"))
        problems = check_thresholds(results, thresholds)
        for problem in problems:
            print(f"REGRESSION: {problem}")
        if problems:
            return 1
        print("\nall benchmarks within thresholds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
