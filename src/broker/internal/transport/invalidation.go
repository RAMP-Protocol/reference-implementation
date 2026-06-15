package transport

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// emptyInvalidationDoc is the "nothing revoked" snapshot served when no
// invalidation file is configured or present. Its as_of is the epoch so the
// consumer's monotonic guard never lets it override a real, later revocation;
// on a first fetch (no prior snapshot) it applies cleanly as an empty set.
const emptyInvalidationDoc = `{"as_of":"1970-01-01T00:00:00Z"}`

// InvalidationHandler serves GET /.well-known/ramp-invalidations.json — the
// Broker's RAMP KeyInvalidationList (ADR-003 §5: emergency keyed revocation).
// The revoked-kid set is read from the file at path on every request, so an
// operator revokes a kid by editing the file (bumping as_of) without a restart
// — the admin plane was removed (design-demo-bootstrap §9), and a re-read file
// mirrors the existing BROKER_KEYS_FILE operator-provisioning pattern.
//
// The operator owns as_of monotonicity (ADR-003 Consequences): each published
// snapshot MUST carry an as_of strictly newer than the last, or the consumer's
// rollback guard ignores it. A malformed file yields 500 (not an empty list) so
// a typo cannot silently un-revoke a key by serving a fresh empty snapshot.
type InvalidationHandler struct {
	path string
}

// NewInvalidationHandler builds the handler. An empty path means "no operator
// revocation file": the handler serves the epoch-dated empty snapshot. The 500
// path logs through the request-scoped logger on the context (reqctx.FromContext),
// so no logger is injected here.
func NewInvalidationHandler(path string) *InvalidationHandler {
	return &InvalidationHandler{path: path}
}

// ServeHTTP writes the current KeyInvalidationList document.
func (h *InvalidationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, err := h.document()
	if err != nil {
		reqctx.FromContext(r.Context()).ErrorContext(r.Context(), "invalidation list unavailable",
			"path", h.path, "err", err)
		http.Error(w, "invalidation list unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// document returns the bytes to serve: the validated file content, or the
// epoch-empty snapshot when no file is configured or the file is absent. A
// present-but-unreadable or schema-invalid file is an error (caller → 500).
func (h *InvalidationHandler) document() ([]byte, error) {
	if h.path == "" {
		return []byte(emptyInvalidationDoc), nil
	}
	data, err := os.ReadFile(h.path) //nolint:gosec // operator-controlled path
	if errors.Is(err, fs.ErrNotExist) {
		return []byte(emptyInvalidationDoc), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read invalidation file: %w", err)
	}
	if err := rampwellknown.ValidateInvalidation(data); err != nil {
		return nil, fmt.Errorf("invalidation file invalid: %w", err)
	}
	return data, nil
}
