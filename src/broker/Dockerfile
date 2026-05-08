# syntax=docker/dockerfile:1.7
# Multi-stage build for the Broker service.
#
# Build from repository root:
#   docker build -f src/broker/Dockerfile -t ramp/broker:dev .

FROM golang:1.26-alpine AS builder
WORKDIR /build

COPY proto/ ./proto/
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY internal/ ./internal/
COPY src/broker/ ./src/broker/

ENV CGO_ENABLED=0 GOOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/broker ./src/broker/cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/broker /broker
USER nonroot:nonroot
EXPOSE 8082
ENTRYPOINT ["/broker"]
