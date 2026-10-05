# syntax=docker/dockerfile:1
#
# One multi-stage, non-root image for every role: authority, broker, approver and the fake
# services (`serve <role>`), plus the agent host's `e2e` command. Base images are pinned by digest
# (resolved 2026-09-13); Dependabot's docker ecosystem proposes digest bumps.

ARG PYTHON_IMAGE=python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

FROM ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 AS uv

FROM ${PYTHON_IMAGE} AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3.12 \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /build
# Dependencies first, so source edits do not invalidate the dependency layer.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="capability-tool-broker" \
      org.opencontainers.image.description="Capability broker for agent tools (authority, broker, approver, fake services)" \
      org.opencontainers.image.licenses="MIT"
# /var/lib/ctb holds audit logs and the approval queue, /var/lib/ctb-checkpoints the signed audit
# checkpoints and /state the agent host's `e2e` state; compose mounts named volumes there, which
# Docker initializes with this ownership. Every mount point a named volume lands on has to exist
# here: for a path missing from the image Docker creates the volume root-owned and 0755, and the
# non-root user below cannot write it.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --home-dir /nonexistent \
       --shell /usr/sbin/nologin app \
    && install -d -o 10001 -g 10001 -m 0750 /var/lib/ctb /var/lib/ctb-checkpoints /state
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOST=0.0.0.0 \
    APP_PORT=8000
WORKDIR /tmp
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-m", "capability_tool_broker.core.healthcheck"]
ENTRYPOINT ["python", "-m", "capability_tool_broker"]
CMD ["serve", "broker"]
