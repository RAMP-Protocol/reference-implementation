// Package reqctx carries a request-scoped *slog.Logger on the context so handlers
// log with request_id correlation without re-passing the id by hand. The
// RequestIDMiddleware of each service builds a logger scoped to the request id and
// attaches it via IntoContext; handlers retrieve it with FromContext.
package reqctx

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

type loggerKey struct{}

// IntoContext returns ctx carrying logger for retrieval by FromContext.
func IntoContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// FromContext returns the request-scoped logger, or slog.Default() when none was
// attached (e.g. a request that bypassed the middleware).
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// RequestIDMiddleware extracts (or mints) X-Request-ID, writes it back on the
// response, stores the id in the context via the caller-supplied withID, attaches
// a request_id-scoped logger to the context (IntoContext), and serves next. Each
// service keeps its own context key + reader and passes the matching withID
// setter so a single shared body drives both the Broker and the Exchange.
func RequestIDMiddleware(
	logger *slog.Logger,
	withID func(context.Context, string) context.Context,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := withID(r.Context(), id)
		scoped := logger.With("request_id", id)
		ctx = IntoContext(ctx, scoped)
		scoped.DebugContext(ctx, "http request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
