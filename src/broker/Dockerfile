# Multi-stage build for the Broker service.
#
# Build from repository root:
#   docker build -f src/broker/Dockerfile -t ramp/broker:dev .

FROM golang:1.26-alpine AS builder
WORKDIR /build

# proto/ was deleted in 9a1b245 — the protocol is now consumed as a
# published Go module (github.com/RAMP-Protocol/protocol). The legacy
# `COPY proto/ ./proto/` line broke the build under this stale Dockerfile.
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
USER nonroot:nonroot
EXPOSE 8082
ENTRYPOINT ["/broker"]
