# pytest harness image — runs inside the compose network so the test URLs
# resolve via docker DNS (edge:80, broker:8082, exchange:8081, the demo
# publisher domains, etc.).
#
# Build context is the project root (see docker-compose.e2e.yml `runner`
# service).

# ───── Stage 1: build the REAL production ingest binary ──────────────────
# The e2e seed ingests the demo feeds by shelling out to the production
# `cmd/ramp-ingest` binary (ParseJSONL → mapRecord, canonicalizing terms
# through the SDK helper → signed PushResources RPC; the Exchange runs the
# SDK's ingest-tier term checks) — NOT a Python re-implementation of mapper.go.
# The runner image has no Go toolchain, so we build the static binary here and
# COPY it into the runner. Mirrors src/exchange/Dockerfile's builder stage.
FROM golang:1.26-alpine AS ingest-builder
WORKDIR /build
COPY go.mod go.sum ./
# The same two cache mounts the three service images carry, for the same reason
# and with the same locking split: without them every rebuild recompiles the
# whole dependency graph, and on a cold build that costs minutes. This stage is
# inside the path they were added to shorten — `make test-e2e` builds the runner
# every time, and this stage copies internal/ and src/exchange/, so any change
# under either rebuilds it.
#
# sharing=locked on the DOWNLOAD only. That step writes the module cache and
# compose builds these images concurrently, so two writers would race. The build
# step below only reads it and takes the default shared mode: locking it there
# serializes every Go image in the stack against every other, which measured
# slower than having no cache at all.
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY internal/ ./internal/
COPY src/exchange/ ./src/exchange/
ENV CGO_ENABLED=0 GOOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOARCH=${TARGETARCH:-amd64} \
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

# Install harness deps. The uv cache mount is the Python counterpart of the two
# Go ones above: without it every rebuild re-downloads every wheel, including the
# two git-sourced protocol packages. Its own id, so it is not shared with any
# other image's cache.
RUN --mount=type=cache,id=uv-e2e-runner,target=/root/.cache/uv \
    uv venv && \
    uv pip install -e . -p .venv/bin/python

# Test sources. The catalog feeds the seed ingests are part of this tree
# (harness/fixtures/catalog/), so they arrive with it — the seed resolves them
# from the harness package rather than from REPO_ROOT, which is why no separate
# COPY is needed and why the in-container layout does not have to mirror the
# host checkout.
COPY tests/e2e/harness /runner/harness
# Cross-language golden vectors the harness reads by REPO_ROOT-relative path.
# The offer-acceptance vectors (testdata/acceptance-vectors.json) are the Go
# oracle that harness/test_acceptance.py pins the ported acceptance marshal
# against. REPO_ROOT-relative (REPO_ROOT=/runner) so the lookup
# resolves in-container as well as on the host checkout.
COPY testdata /runner/testdata

ENV PATH="/runner/.venv/bin:${PATH}"
ENTRYPOINT ["pytest", "-q", "harness"]
