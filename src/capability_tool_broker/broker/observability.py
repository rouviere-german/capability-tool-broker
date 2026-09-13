"""Broker metrics: capability decisions, verification latency and end-to-end call latency."""

from __future__ import annotations

from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, Histogram

__all__ = ["BrokerMetrics", "create_broker_metrics"]

_VERIFY_BUCKETS = (0.0001, 0.00025, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.05)
_CALL_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0)


@dataclass(frozen=True, slots=True)
class BrokerMetrics:
    registry: CollectorRegistry
    decisions_total: Counter
    verify_latency_seconds: Histogram
    call_latency_seconds: Histogram


def create_broker_metrics(registry: CollectorRegistry | None = None) -> BrokerMetrics:
    reg = registry if registry is not None else CollectorRegistry()
    return BrokerMetrics(
        registry=reg,
        decisions_total=Counter(
            "capability_decisions_total",
            "Broker authorization decisions by result and the caveat type that decided a denial.",
            ["result", "caveat_type"],
            registry=reg,
        ),
        verify_latency_seconds=Histogram(
            "verify_latency_seconds",
            "Time to authenticate a token and its discharges and evaluate every caveat.",
            registry=reg,
            buckets=_VERIFY_BUCKETS,
        ),
        call_latency_seconds=Histogram(
            "broker_call_latency_seconds",
            "End-to-end broker call latency, including the upstream service call.",
            ["result"],
            registry=reg,
            buckets=_CALL_BUCKETS,
        ),
    )
