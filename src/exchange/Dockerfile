# Multi-stage build for the Exchange service. Distroless runtime keeps the
# final image under 20 MB with no shell, package manager, or extra users.
#
# Build from repository root:
#   docker build -f src/exchange/Dockerfile -t ramp/exchange:dev .

FROM golang:1.26-bookworm AS builder
WORKDIR /build

# TigerBeetle's Go client links a native library via CGO, so the shipped binary
# needs a C toolchain at build time and glibc at runtime. The builder is pinned
# to bookworm to match the distroless/base-debian12 runtime glibc; the Debian
# golang image ships no gcc, so install it.
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
 && rm -rf /var/lib/apt/lists/*

# proto/ was deleted in 9a1b245 — the protocol is now consumed as a
# published Go module (github.com/RAMP-Protocol/protocol). The legacy
# `COPY proto/ ./proto/` line broke the build under this stale Dockerfile.
# Root go module + deps.
COPY go.mod go.sum ./
RUN go mod download

# Source specific to the Exchange build target.
COPY internal/ ./internal/
COPY src/exchange/ ./src/exchange/

# CGO is required by the TigerBeetle client. CGO cannot cross-compile without a
# cross C toolchain, so this image builds for the native (amd64) arch only; the
# repo publishes no multi-arch image.
ENV CGO_ENABLED=1 GOOS=linux
ARG TARGETARCH
RUN GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/exchange ./src/exchange/cmd/server

FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=builder /out/exchange /exchange
USER nonroot:nonroot
EXPOSE 8081
ENTRYPOINT ["/exchange"]
