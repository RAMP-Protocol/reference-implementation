# Fastly Compute runner. Builds a WASM from the Hono app and serves it via
# `fastly compute serve` (Viceroy under the hood).
#
# Build from repo root:
#   docker build -f tests/e2e/fastly-edge/Dockerfile -t ramp/fastly-edge:dev .

FROM node:22-bookworm-slim AS builder
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates tar git \
    && rm -rf /var/lib/apt/lists/*

# Fastly CLI — pinned version, architecture-aware.
ARG FASTLY_CLI_VERSION=14.3.1
ARG TARGETARCH=amd64
RUN curl -fsSL "https://github.com/fastly/cli/releases/download/v${FASTLY_CLI_VERSION}/fastly_v${FASTLY_CLI_VERSION}_linux-${TARGETARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin fastly \
    && chmod +x /usr/local/bin/fastly \
    && fastly version

# Project skeleton + the upstream edge source (mounted read-only via build
# context from repo root).
COPY tests/e2e/fastly-edge/package.json tests/e2e/fastly-edge/build.mjs tests/e2e/fastly-edge/fastly.toml ./
COPY tests/e2e/fastly-edge/src ./src
# Pull the shared edge package so we can import @ramp/edge via a workspace
# link. We create a tiny local package.json under node_modules to expose it.
COPY src/edge/package.json /app/edge-src/package.json
COPY src/edge/src /app/edge-src/src
# edge-src's @ramp-protocol/sdk-l1 is a git dependency (git+https://…/protocol
# #<sha>); the npm install below clones it (git installed above) — no sibling
# checkout is mirrored in.

# Rewrite the @ramp/edge reference to point at the sibling workspace. Placing
# edge-src under /app lets esbuild resolve hono/zod from /app/node_modules.
RUN node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('package.json'));p.dependencies['@ramp/edge']='file:./edge-src';fs.writeFileSync('package.json',JSON.stringify(p,null,2));"

RUN npm install esbuild@^0.24.2 --no-save \
    && npm install --no-save

RUN node build.mjs

FROM node:22-bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/fastly /usr/local/bin/fastly
COPY --from=builder /app/bin /app/bin
COPY tests/e2e/fastly-edge/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 7676
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
