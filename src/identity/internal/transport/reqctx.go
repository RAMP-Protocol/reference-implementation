package transport

import (
	"log/slog"
	"net/http"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// RequestIDMiddleware assigns or propagates an X-Request-ID per request and
// attaches a request-id-scoped logger to the context, mirroring the Exchange and
// Broker. The shared body in reqctx stores the id under reqctx's own keys;
// identity never reads it back, because correlation flows through the
// request-scoped logger reqctx attaches (which carries the id as an attribute).
//
// The context-key setter is deliberately NOT injectable: the id is a persistence
// input on the Exchange, so a service that supplied its own setter would compile
// and log correctly while leaving the shared reader empty.
func RequestIDMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return reqctx.RequestIDMiddleware(logger, next)
}
