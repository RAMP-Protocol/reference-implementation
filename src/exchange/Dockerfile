# syntax=docker/dockerfile:1.7
# Multi-stage build for the Exchange service. Distroless runtime keeps the
# final image under 20 MB with no shell, package manager, or extra users.
#
# Build from repository root:
#   docker build -f src/exchange/Dockerfile -t ramp/exchange:dev .

FROM golang:1.26-alpine AS builder
WORKDIR /build

# Proto code (includes its own go.mod; resolves the replace directive).
COPY proto/ ./proto/

# Root go module + deps.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Source specific to the Exchange build target.
COPY internal/ ./internal/
COPY src/exchange/ ./src/exchange/

ENV CGO_ENABLED=0 GOOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/exchange ./src/exchange/cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/exchange /exchange
USER nonroot:nonroot
EXPOSE 8081
ENTRYPOINT ["/exchange"]
