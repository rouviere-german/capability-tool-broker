# Security policy

## Supported versions

Only the latest commit on `main` is supported. This is a portfolio project, not a product with
release branches.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private vulnerability
reporting ("Report a vulnerability" under the repository's Security tab). Include:

- the affected commit and component (macaroon library, verifier, broker, authority, approver);
- steps to reproduce, ideally as a failing test or a token that the broker should have rejected;
- the impact you expect.

You can expect an acknowledgement within 7 days and a fix or a written assessment within 30 days.
Credit is given in the fix commit unless you ask otherwise.

## Scope

In scope: the code in this repository, its container image, the compose file and the CI
configuration. Of particular interest: any token, discharge or request that the broker authorizes
although the evaluation suites say it should not (forgery, attenuation, replay, approval bypass),
and any way for the agent host or the approver to obtain service credentials or root keys.

Out of scope: denial of service by traffic volume, findings that need a compromised broker or
authority host (they hold the root key by design), and issues in third-party dependencies that are
already publicly tracked (please report those upstream).

## How this repository is hardened

- Threats, controls and the tests that prove them: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- Every security claim is linked to evidence in [CLAIMS.md](CLAIMS.md).
- Design decisions behind the controls: [docs/adr/](docs/adr/); key rotation:
  [docs/RUNBOOK_KEY_ROTATION.md](docs/RUNBOOK_KEY_ROTATION.md).
- CI runs ruff, mypy --strict, pytest with a coverage floor, the offline demo, the evaluation
  benchmarks with regression thresholds, bandit, semgrep (registry packs plus
  `.semgrep/rules.yml`), pip-audit, gitleaks, hadolint, a trivy image scan, a syft CycloneDX SBOM
  and a compose integration job.
- Secrets come only from the environment, one role at a time; only `.env.example` is committed.
- No pickle-family serialization; tokens, manifests, approvals and audit logs are JSON or the
  macaroon V2 binary format.
