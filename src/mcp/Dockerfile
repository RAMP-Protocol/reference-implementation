# MCP shim container. FastMCP streamable-HTTP transport bound to 0.0.0.0:8000.
# Local runs still use stdio (override RAMP_MCP_TRANSPORT=stdio).
#
# Build from src/mcp/:
#   docker build -t ramp/mcp:dev src/mcp

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
WORKDIR /app

ENV UV_SYSTEM_PYTHON=0 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install deps (frozen against the committed lockfile).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Install the shim itself.
COPY src/ ./src/
RUN uv sync --frozen --no-dev

# Default to HTTP transport in the container; override for stdio use.
ENV RAMP_MCP_TRANSPORT=http \
    RAMP_MCP_HOST=0.0.0.0 \
    RAMP_MCP_PORT=8000 \
    PATH="/app/.venv/bin:${PATH}"

EXPOSE 8000

# Non-root UID matches distroless:nonroot (65532) for consistency across images.
RUN useradd --no-create-home --uid 65532 --shell /usr/sbin/nologin ramp
USER 65532:65532

ENTRYPOINT ["ramp-mcp"]
