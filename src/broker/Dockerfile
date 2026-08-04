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
RUN go mod download

COPY internal/ ./internal/
COPY src/broker/ ./src/broker/

ENV CGO_ENABLED=0 GOOS=linux
ARG TARGETARCH
RUN GOARCH=${TARGETARCH:-amd64} \
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
