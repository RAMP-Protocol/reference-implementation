// Package transport wires the Exchange service layer to HTTP via Connect-Go.
// Handlers in this package are thin: validate proto envelope, hand off to
// service, translate domain errors to connect.Error.
package transport

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
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
// writes the header back on the response, and attaches a scoped logger for
// downstream use via slog.LogAttrs.
func RequestIDMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := WithRequestID(r.Context(), id)
		scoped := logger.With("request_id", id)
		scoped.DebugContext(ctx, "http request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
