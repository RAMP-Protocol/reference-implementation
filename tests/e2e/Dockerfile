# pytest harness image — runs inside the compose network so the test URLs
# resolve via docker DNS (edge:80, broker:8082, exchange:8081, the demo
# publisher domains, etc.).
#
# Build context is the project root (see docker-compose.e2e.yml `runner`
# service).

# ───── Stage 1: build the REAL production ingest binary ──────────────────
# The e2e seed ingests the demo feeds by shelling out to the production
# `cmd/ramp-ingest` binary (ParseJSONL → mapRecord → licenseterm.Validate
# → signed PushResources RPC) — NOT a Python re-implementation of mapper.go.
# The runner image has no Go toolchain, so we build the static binary here and
# COPY it into the runner. Mirrors src/exchange/Dockerfile's builder stage.
FROM golang:1.26-alpine AS ingest-builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ ./internal/
COPY src/exchange/ ./src/exchange/
ENV CGO_ENABLED=0 GOOS=linux
ARG TARGETARCH
RUN GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/ramp-ingest ./src/exchange/cmd/ramp-ingest

# ───── Stage 2: pytest harness ───────────────────────────────────────────
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
WORKDIR /runner

# git is required to resolve ramp-protocol (gen/python) + ramp-protocol-sdk
# (sdk/python), both pinned to proto git commits via [tool.uv.sources] — the
# slim base ships no git binary, so the editable shim install below would fail
# to clone them.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# The production ingest binary, copied from the Go builder stage. The seed
# (tests/e2e/harness/seed.py) shells out to this path once per demo feed.
COPY --from=ingest-builder /out/ramp-ingest /usr/local/bin/ramp-ingest

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Harness pyproject. There is no in-tree Python shim to mirror in: the MCP
# surface is the Go adapter, driven over the MCP protocol by test_mcp_endpoint.py.
# ramp-protocol-sdk resolves off-commit from git (subdirectory=sdk/python), so no
# sibling checkout is mirrored in either — git (installed above) clones it.
COPY tests/e2e/pyproject.toml ./

# Install harness deps.
RUN uv venv && \
    uv pip install -e . -p .venv/bin/python

# Test sources.
COPY tests/e2e/harness /runner/harness
# Phase-2 demo feeds (philosophy/music/sfx JSON-L) + the assertion-contract
# manifest. The seed shells out to ramp-ingest against these feeds, one
# run per feed under the owning demo-domain tenant. REPO_ROOT-relative so the
# in-container path matches the host checkout.
COPY deploy/fixtures/demo /runner/deploy/fixtures/demo
# Cross-language golden vectors the harness reads by REPO_ROOT-relative path.
# The offer-acceptance vectors (testdata/acceptance-vectors.json) are the Go
# oracle that harness/test_acceptance.py pins the ported acceptance marshal
# against. REPO_ROOT-relative (REPO_ROOT=/runner) so the lookup
# resolves in-container as well as on the host checkout.
COPY testdata /runner/testdata

ENV PATH="/runner/.venv/bin:${PATH}"
ENTRYPOINT ["pytest", "-q", "harness"]
