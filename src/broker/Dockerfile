# Multi-stage build for the Broker service.
#
# Build from repository root:
#   docker build -f src/broker/Dockerfile -t ghcr.io/ramp-protocol/broker:dev .

FROM golang:1.26-alpine AS builder
WORKDIR /build

# There is no in-tree proto/ directory to copy. The protocol is consumed as the
# published Go module github.com/RAMP-Protocol/protocol, pinned in the root
# go.mod, so `go mod download` below is what fetches it.
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

COPY internal/ ./internal/
COPY src/broker/ ./src/broker/

ENV CGO_ENABLED=0 GOOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/broker ./src/broker/cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/broker /broker

# image.source is what links the published package to its repository on GitHub,
# which is in turn what allows the package to be made public. Version and
# revision are deliberately absent: neither is knowable until a build runs, so
# the publishing workflow stamps those two as --label flags instead.
LABEL org.opencontainers.image.source="https://github.com/RAMP-Protocol/reference-implementation" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="RAMP Broker" \
      org.opencontainers.image.description="RAMP Broker service: resource discovery and exchange routing"

USER nonroot:nonroot
EXPOSE 8082
ENTRYPOINT ["/broker"]
