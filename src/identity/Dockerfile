# Multi-stage build for the Identity Service (the WBA registry + MCP adapter).
# Distroless runtime, no CGO — unlike the Exchange this binary links no native
# library.
#
# Build from repository root:
#   docker build -f src/identity/Dockerfile -t ghcr.io/ramp-protocol/identity:dev .

FROM golang:1.26-bookworm AS builder
WORKDIR /build

# Root go module + deps.
COPY go.mod go.sum ./
# Persist the Go module and build caches across builds.
#
# Without these every rebuild recompiles the whole dependency graph, because
# nothing in a container layer carries a compiler cache: on a cold stack build
# the go steps alone cost minutes. A cache mount lives with the builder rather
# than in the image, so it survives --no-cache and never lands in a layer.
#
# sharing=locked on the DOWNLOAD only. That step writes the module cache, and
# compose builds these services concurrently, so two writers would race. The
# build step below only reads it and takes the default shared mode: locking it
# there serializes every Go image in the stack against every other, which
# measured slower than having no cache at all.
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Source specific to the Identity build target.
COPY internal/ ./internal/
COPY src/identity/ ./src/identity/

ENV CGO_ENABLED=0 GOOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/identity ./src/identity/cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/identity /identity

# image.source is what links the published package to its repository on GitHub,
# which is in turn what allows the package to be made public. Version and
# revision are deliberately absent: neither is knowable until a build runs, so
# the publishing workflow stamps those two as --label flags instead.
LABEL org.opencontainers.image.source="https://github.com/RAMP-Protocol/reference-implementation" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="RAMP Identity" \
      org.opencontainers.image.description="RAMP Identity service: agent key registry and MCP adapter"

USER nonroot:nonroot
EXPOSE 8083
ENTRYPOINT ["/identity"]
