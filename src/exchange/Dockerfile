# Multi-stage build for the Exchange service. Distroless runtime keeps the
# final image under 20 MB with no shell, package manager, or extra users.
#
# Build from repository root:
#   docker build -f src/exchange/Dockerfile -t ramp/exchange:dev .

FROM golang:1.26-alpine AS builder
WORKDIR /build

# proto/ was deleted in 9a1b245 — the protocol is now consumed as a
# published Go module (github.com/RAMP-Protocol/protocol). The legacy
# `COPY proto/ ./proto/` line broke the build under this stale Dockerfile.
# Root go module + deps.
COPY go.mod go.sum ./
RUN go mod download

# Source specific to the Exchange build target.
COPY internal/ ./internal/
COPY src/exchange/ ./src/exchange/

ENV CGO_ENABLED=0 GOOS=linux
ARG TARGETARCH
RUN GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/exchange ./src/exchange/cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/exchange /exchange
USER nonroot:nonroot
EXPOSE 8081
ENTRYPOINT ["/exchange"]
