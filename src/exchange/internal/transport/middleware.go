// Package transport wires the Exchange service layer to HTTP via Connect-Go.
// Handlers in this package are thin: validate proto envelope, hand off to
// service, translate domain errors to connect.Error.
package transport

import (
	"context"
	"log/slog"
	"net/http"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// contextKey is the local key type used for request-scoped values.
type contextKey string

const requestIDKey contextKey = "request_id"

// RequestIDFromContext returns the request id propagated by the middleware.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// WithRequestID returns a context annotated with the given request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDMiddleware extracts (or mints) X-Request-ID, annotates the context,
// writes the header back on the response, and attaches a request-id-scoped logger
// to the context (reqctx.IntoContext) so downstream handlers log with correlation
// without re-passing the id by hand. The shared body lives in reqctx; this
// service passes its own WithRequestID context-key setter.
func RequestIDMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return reqctx.RequestIDMiddleware(logger, WithRequestID, next)
}

// LogHTTPSigReject is the OnError callback for the global RFC 9421 httpsig gate
// (wired in cmd/server). It logs the rejection through the request-scoped logger
// so the line carries the request_id RequestIDMiddleware stamped — these are the
// auth-rejection lines, the highest-value ones to correlate. RequestIDMiddleware
// is outermost, so r.Context() already carries the scoped logger; reqctx
// falls back to slog.Default() if a request ever bypasses the middleware. The
// httpsig interceptor only invokes OnError with a non-nil err.
func LogHTTPSigReject(r *http.Request, err error) {
	reqctx.FromContext(r.Context()).WarnContext(r.Context(), "httpsig: reject",
		"path", r.URL.Path, "err", err.Error())
}
