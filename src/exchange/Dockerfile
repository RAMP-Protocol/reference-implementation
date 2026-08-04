# Multi-stage build for the Exchange service. The distroless runtime carries no
# shell, no package manager and no extra users. It is the largest of the three
# service images, because the TigerBeetle client below needs glibc.
#
# Build from repository root:
#   docker build -f src/exchange/Dockerfile -t ghcr.io/ramp-protocol/exchange:dev .

FROM golang:1.26-bookworm AS builder
WORKDIR /build

# TigerBeetle's Go client links a native library via CGO, so the shipped binary
# needs a C toolchain at build time and glibc at runtime. The builder is pinned
# to bookworm to match the distroless/base-debian12 runtime glibc; the Debian
# golang image ships no gcc, so install it.
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
 && rm -rf /var/lib/apt/lists/*

# There is no in-tree proto/ directory to copy. The protocol is consumed as the
# published Go module github.com/RAMP-Protocol/protocol, pinned in the root
# go.mod, so `go mod download` below is what fetches it.
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

# image.source is what links the published package to its repository on GitHub,
# which is in turn what allows the package to be made public. Version and
# revision are deliberately absent: neither is knowable until a build runs, so
# the publishing workflow stamps those two as --label flags instead.
LABEL org.opencontainers.image.source="https://github.com/RAMP-Protocol/reference-implementation" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="RAMP Exchange" \
      org.opencontainers.image.description="RAMP Exchange service: offers, transactions and signed content URLs"

USER nonroot:nonroot
EXPOSE 8081
ENTRYPOINT ["/exchange"]
