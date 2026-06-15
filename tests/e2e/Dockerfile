# pytest harness image — runs inside the compose network so the test URLs
# resolve via docker DNS (edge:8787, broker:8082, exchange:8081, etc.).
#
# Build context is the project root (see docker-compose.e2e.yml `runner`
# service). The harness pyproject carries a [tool.uv.sources] path entry
# pointing at `../../src/mcp` for the in-tree shim; that resolves from the
# host venv (cwd `tests/e2e/`) but escapes the build context inside the
# runner image (`/runner/../../src/mcp` → `/src/mcp`, outside `/runner`).
# The COPY + sed sequence below re-roots the path source to `/mcp` so the
# editable install resolves cleanly. Fix for agentic-content-access-2v3ui
# (predecessor diagnostic docs/diagnostics/r7frv-canonical-e2e-sweep.md §4).

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
WORKDIR /runner

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# MCP shim source — COPYed first so the [tool.uv.sources] path entry can be
# re-rooted at /mcp before the harness install resolves it.
COPY src/mcp/pyproject.toml src/mcp/uv.lock /mcp/
COPY src/mcp/src /mcp/src

# Harness pyproject + path-source re-rooting from ../../src/mcp → /mcp.
COPY tests/e2e/pyproject.toml ./
RUN sed -i 's|path = "\.\./\.\./src/mcp"|path = "/mcp"|' pyproject.toml

# Install harness deps (pulls editable ramp-mcp-shim from /mcp via the
# patched [tool.uv.sources] entry; no separate `uv pip install /mcp` needed).
RUN uv venv && \
    uv pip install -e . -p .venv/bin/python

# Test sources.
COPY tests/e2e/harness /runner/harness

ENV PATH="/runner/.venv/bin:${PATH}"
ENTRYPOINT ["pytest", "-q", "harness"]
