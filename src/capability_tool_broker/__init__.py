"""Capability tool broker: object-capability security for agent tools.

Sub-packages:
- ``macaroons``: the in-repo macaroon library (HMAC-SHA256 chains, V2 format);
- ``capabilities``: caveat DSL, verifier, key ring, approval caveats, attenuation;
- ``authority``, ``approver``, ``broker``, ``services``: the compose roles;
- ``agent``: planner and sub-agent runtimes (capability tokens or the ambient baseline);
- ``agentic``: provider protocol, envelopes, budgets, approval queue and audit log;
- ``core``: settings, redacting logs, tracing, metrics and the hardened FastAPI factory;
- ``evaluation``: soundness, forgery, escalation and latency harnesses behind ``bench/``.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
