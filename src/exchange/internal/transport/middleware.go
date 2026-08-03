// Package transport wires the Exchange service layer to HTTP via Connect-Go.
// Handlers in this package are thin: validate proto envelope, hand off to
// service, translate domain errors to connect.Error.
package transport

import (
	"log/slog"
	"net/http"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
)

// RequestIDMiddleware extracts (or mints) X-Request-ID, annotates the context,
// writes the header back on the response, and attaches a request-id-scoped logger
// to the context (reqctx.IntoContext) so downstream handlers log with correlation
// without re-passing the id by hand. The shared body lives in reqctx, which also
// owns the context key: both services store the id under it, so any layer reads
// the same value with reqctx.RequestID without importing a transport package.
func RequestIDMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return reqctx.RequestIDMiddleware(logger, next)
}

// LogHTTPSigReject is the exchange's connectserver.WithOnReject observer for the
// global RFC 9421 verify gate — the shared reqctx.NewRejectLogger body keyed on
// the "exchange" audit namespace. See reqctx.NewRejectLogger for the request-id
// correlation + outcome-classification contract.
var LogHTTPSigReject = reqctx.NewRejectLogger("exchange")

// WrapPublicSurface assembles the Exchange's public HTTP middleware stack —
// the shared runhttp.WrapPublicSurface stack (request-id → URL normalization →
// opt-in proxy trust) around CatalogSignatureMiddleware → mux, the Exchange's
// one extra inner layer. ExchangeService request verification is handled by
// the connectserver handler registered in cmd/server's registerConnect (which
// wraps ExchangeService with its own request-id + RFC 9421 verify layers);
// mounting the URL-normalizing layers outside the mux fixes the @target-uri
// before BOTH that verify seam and the catalog capture see the request — layer
// order and rationale are documented on runhttp.WrapPublicSurface.
// CatalogService uses its own per-contributor signature check in
// CatalogHandler.verifyCallerSignature. Shared by cmd/server (buildWrapped) and
// the integration harness (startExchangeServer) so both exercise identical wiring.
func WrapPublicSurface(
	logger *slog.Logger,
	mux http.Handler,
	opts runhttp.PublicSurfaceOptions,
) http.Handler {
	return runhttp.WrapPublicSurface(logger, CatalogSignatureMiddleware(mux), opts)
}
