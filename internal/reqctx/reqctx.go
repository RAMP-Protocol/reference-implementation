// Package reqctx carries a request-scoped *slog.Logger on the context so handlers
// log with request_id correlation without re-passing the id by hand. The
// RequestIDMiddleware of each service builds a logger scoped to the request id and
// attaches it via IntoContext; handlers retrieve it with FromContext.
package reqctx

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/google/uuid"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig/transportconnect"
)

// HeaderRequestID is the correlation header every service reads on the way in
// and writes on the way out. Named once so an outbound leg cannot spell it
// differently from the middleware that produced the value.
const HeaderRequestID = "X-Request-ID"

type loggerKey struct{}

type idKey struct{}

// WithID returns ctx carrying the request id for retrieval by IDFromContext.
// This is the id-as-a-value channel, distinct from the request-scoped logger:
// a logger lets a handler emit the id, whereas an outbound client needs to
// forward it, and only the latter needs the bare string.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, idKey{}, id)
}

// IDFromContext returns the request id attached by WithID, or "" when none is.
func IDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(idKey{}).(string)
	return id
}

// IDOrNew returns the request id on ctx, minting one when it carries none.
//
// This is the policy every OUTBOUND leg needs: threading the inbound id is what
// lets a tool call and the calls it causes be read as one story, and an outbound
// request that travelled with an EMPTY id leaves the peer's own log with nothing
// to join back to. Both the RAMP leg and the content leg reach for it, which is
// why it lives here rather than being spelled twice.
func IDOrNew(ctx context.Context) string {
	if id := IDFromContext(ctx); id != "" {
		return id
	}
	return uuid.NewString()
}

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

type requestIDKey struct{}

// WithRequestID returns ctx carrying the raw request id. RequestIDMiddleware
// stores the id here, so any layer that must persist or correlate on the raw id —
// not only log through the scoped logger — can read it with RequestID, without
// importing a service's transport package (which would invert the transport →
// service layering). One key serves every reader in both services.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the raw request id stored by WithRequestID, or "" when
// nothing stored one — which normally means the request never passed
// RequestIDMiddleware.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

type requestIDMintedKey struct{}

// withRequestIDMinted records how the id RequestID returns came to be. Set by
// RequestIDMiddleware, which is the only place that knows: the id alone cannot
// tell a minted UUID from a caller-supplied one, because a UUID is itself inside
// the accepted charset.
func withRequestIDMinted(ctx context.Context, minted bool) context.Context {
	return context.WithValue(ctx, requestIDMintedKey{}, minted)
}

// RequestIDMinted reports whether the id RequestID returns was minted here
// (true) or taken verbatim from the caller's X-Request-ID header (false). It
// matters because the value is persisted as the correlation key an evidence row
// is joined on: a minted id is a server-derived fact, a caller-supplied one is
// attacker-influenceable, and the two are byte-indistinguishable once stored.
//
// ok is false when no middleware ran. RequestID is then "" and the provenance of
// an absent id is undefined — NOT "caller-supplied".
func RequestIDMinted(ctx context.Context) (minted, ok bool) {
	v, ok := ctx.Value(requestIDMintedKey{}).(bool)
	return v, ok
}

// NewRejectLogger returns a connectserver.WithOnReject observer that logs a
// signature-gate rejection through the request-scoped logger, so the line
// carries the request_id RequestIDMiddleware stamped — these auth-rejection
// lines are the highest-value ones to correlate. RequestIDMiddleware is
// outermost, so r.Context() already carries the scoped logger; FromContext falls
// back to slog.Default() if a request ever bypasses the middleware. service
// names the audit message key ("<service>.httpsig.reject"); the audit outcome
// token comes from transportconnect.RejectAuditOutcome, which defers to the
// SDK's own connectserver.ClassifyReject for the four authentication outcomes —
// the gate owns that judgement and the app derives no copy of it — and names
// the one outcome the SDK's enum cannot express, a body past the read cap,
// rather than letting it default to a signature failure. Broker and Exchange
// register the same body under their own service token.
func NewRejectLogger(service string) func(*http.Request, error) {
	msg := service + ".httpsig.reject"
	return func(r *http.Request, err error) {
		FromContext(r.Context()).WarnContext(r.Context(), msg,
			"path", r.URL.Path, "outcome", transportconnect.RejectAuditOutcome(err), "err", err.Error())
	}
}

// acceptableRequestID bounds a client-supplied X-Request-ID. The value is a
// correlation token, so it may be echoed on the response, attached to every log
// line, and (on the Exchange) written into an append-once evidence row. Anything
// outside this charset and length is discarded in favour of a minted UUID rather
// than carried into those sinks: the header is attacker-authored, covered by no
// signature, and bounded only by the server's MaxHeaderBytes.
var acceptableRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// RequestIDMiddleware extracts (or mints) X-Request-ID, writes it back on the
// response, stores the id in the context under this package's key, records which
// of the two it was (withRequestIDMinted — this is the only layer that can still
// tell), attaches a request_id-scoped logger to the context (IntoContext), and
// serves next. One shared body drives both the Broker and the Exchange.
//
// The context-key setter is NOT injectable, deliberately. It once was, so each
// service could key the id its own way — but the id is now a persistence input
// (transaction_evidence.request_id reads it back through RequestID), so a service
// that passed a different setter would compile, log correctly, and silently write
// NULL into an append-once column. Storing it here is what makes "the id the
// middleware stamped" and "the id persistence reads" the same value by
// construction rather than by every future caller's agreement.
//
// A minted or sanitized id is written back onto the REQUEST headers, not only the
// response. The SDK's Connect handler installs its own request-id layer inside
// this one (connectserver wraps core.RequestIDMiddleware outermost of the
// handler), and that layer reads the request header. Without this write it sees
// no id, mints a second one, and overwrites the response header — so the caller
// would receive an id that matches neither the logs nor the persisted correlation
// column.
//
// Safe against the RFC 9421 gate that runs further in, but for a narrower reason
// than "the covered set is fixed". The SDK's reference SIGNER emits a fixed set
// (@method, @target-uri, content-digest, authorization, signature-agent, plus
// x-entitlement-token when present); its VERIFIER enforces that set as a
// MINIMUM and accepts extras, rebuilding the signature base from the signer's
// own component list off the wire. So the rewrite is safe because no RAMP client
// signs x-request-id — an assumption about clients, not a guarantee the SDK
// makes. It fails CLOSED either way: a third-party signer that did cover
// x-request-id with a non-conforming value would have its header rewritten under
// the signature and be rejected Unauthenticated, never let through. Widening this
// rewrite to headers clients DO sign would not be safe, and nothing here would
// stop it.
func RequestIDMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(helpers.RequestIDHeader)
		minted := !acceptableRequestID.MatchString(id)
		if minted {
			id = uuid.NewString()
			r.Header.Set(helpers.RequestIDHeader, id)
		}
		w.Header().Set(helpers.RequestIDHeader, id)
		ctx := withRequestIDMinted(WithRequestID(r.Context(), id), minted)
		// Also stored under this package's id-as-a-value key so an outbound client
		// can forward the id without the service having to export its private one.
		ctx = WithID(ctx, id)
		scoped := logger.With("request_id", id)
		ctx = IntoContext(ctx, scoped)
		scoped.DebugContext(ctx, "http request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
