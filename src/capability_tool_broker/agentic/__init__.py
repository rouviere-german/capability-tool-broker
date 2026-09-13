"""Agentic kit: providers, untrusted-data envelopes, tool registry, approval queue, budgets, audit.

The security model does not depend on the model behaving well. Tool outputs are wrapped as data,
but the enforcing controls are architectural: the broker checks every call against the calling
agent's capability token, writes and deletes need a discharge bound to the exact request, budgets
cap spend, and every decision lands in a tamper-evident audit log.
"""
