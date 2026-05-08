# syntax=docker/dockerfile:1.7
# pytest harness image — runs inside the compose network so the test URLs
# resolve via docker DNS (edge:8787, broker:8082, exchange:8081, etc.).
#
# Build from src/mcp/ so we can install the shim as an editable dep alongside
# the harness's pyproject.toml. We use the same uv-python base the MCP uses.

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
WORKDIR /runner

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Harness deps first for layer caching.
COPY tests/e2e/pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv && \
    uv pip install -e . -p .venv/bin/python

# MCP shim dep so tests can exercise the real ramp_fetch_impl.
COPY src/mcp/pyproject.toml src/mcp/uv.lock /mcp/
COPY src/mcp/src /mcp/src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install /mcp -p .venv/bin/python

# Test sources.
COPY tests/e2e/harness /runner/harness

ENV PATH="/runner/.venv/bin:${PATH}"
ENTRYPOINT ["pytest", "-q", "harness"]
