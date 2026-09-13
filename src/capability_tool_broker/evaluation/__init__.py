"""Evaluation harnesses behind ``bench/``: soundness, forgery, escalation, utility and performance.

The logic lives in the package so the test suite runs every harness at a small scale; the bench
scripts run them at full scale and enforce regression thresholds.
"""
