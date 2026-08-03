package transport

import (
	"net/http"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// RevocationHandler serves GET /.well-known/ramp-key-revocations.json — the
// Broker's RAMP KeyRevocationList (ADR-003 §5: emergency keyed revocation). The
// document (and its caching / validation) is owned by RevocationSource; this
// handler is a thin transport adapter that maps a source error to a 500.
type RevocationHandler struct {
	source *RevocationSource
}

// NewRevocationHandler builds the handler. An empty path means "no operator
// revocation file": the handler serves the epoch-dated empty snapshot. The 500
// path logs through the request-scoped logger on the context (reqctx.FromContext),
// so no logger is injected here.
func NewRevocationHandler(path string) *RevocationHandler {
	return &RevocationHandler{source: NewRevocationSource(path)}
}

// ServeHTTP writes the current KeyRevocationList document.
func (h *RevocationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, err := h.source.Document()
	if err != nil {
		// The log event is namespaced like every other Broker event so it can be
		// alerted on by name; the response body stays plain prose, because it is
		// read by a caller rather than by an operator's log pipeline.
		reqctx.FromContext(r.Context()).ErrorContext(r.Context(), "broker.revocation.unavailable",
			"err", err)
		http.Error(w, "revocation list unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}
