# Multi-stage build for the Identity Service (the WBA registry + MCP adapter).
# Distroless runtime, no CGO — unlike the Exchange this binary links no native
# library.
#
# Build from repository root:
#   docker build -f src/identity/Dockerfile -t ramp/identity:dev .

FROM golang:1.26-bookworm AS builder
WORKDIR /build

# Root go module + deps.
COPY go.mod go.sum ./
RUN go mod download

# Source specific to the Identity build target.
COPY internal/ ./internal/
COPY src/identity/ ./src/identity/

ENV CGO_ENABLED=0 GOOS=linux
ARG TARGETARCH
RUN GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/identity ./src/identity/cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/identity /identity
USER nonroot:nonroot
EXPOSE 8083
ENTRYPOINT ["/identity"]
