package httpsig

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	connect "connectrpc.com/connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// ReplayTTL is the window during which a (keyID, signature) pair is
// considered replayed. Matches the 5-minute window the RAMP RFC 9421 policy
// target requires.
const ReplayTTL = 5 * time.Minute

// InterceptorOptions tunes Middleware.
type InterceptorOptions struct {
	// PathPredicate, when non-nil, returns true for paths the interceptor
	// should verify. When nil, all paths under Connect service prefixes are
	// verified (defaults to "/ramp.").
	PathPredicate func(path string) bool
	// RequestPredicate, when non-nil, takes precedence over PathPredicate
	// and decides verification on the full request (e.g. to skip when no
	// Signature-Input header is present, letting agent-direct calls
	// through while still verifying broker-relayed signed RPCs on the
	// same path).
	RequestPredicate func(r *http.Request) bool
	// Clk is the time source passed to VerifyRequest; defaults to clock.System{}
	// per ADR-008 D1.
	Clk clock.Clock
	// ReplayWindow overrides the default 5-minute replay window.
	ReplayWindow time.Duration
	// OnVerified is called on successful verification. Handlers can use this
	// to stash the verified keyID into request-scoped state for audit
	// logging. nil means no-op.
	OnVerified func(r *http.Request, v *VerifiedRequest) *http.Request
	// OnError is called before the interceptor writes the 401 response.
	// Intended for structured logging of rejections.
	OnError func(r *http.Request, err error)
}

// verifiedKey carries the VerifiedRequest in the request context so handlers
// (or downstream middleware) can read the caller's keyID without re-parsing.
type verifiedKey struct{}

// FromContext returns the VerifiedRequest the Middleware stashed, or nil.
func FromContext(ctx context.Context) *VerifiedRequest {
	v, _ := ctx.Value(verifiedKey{}).(*VerifiedRequest)
	return v
}

// NewContext returns a copy of ctx carrying v under the verified-request key.
// Tests use this to drive handler-level authz without standing up the full
// middleware + signing chain. Production code MUST NOT call this: the
// Middleware is the only legitimate populator of the verified-request slot.
func NewContext(ctx context.Context, v *VerifiedRequest) context.Context {
	return context.WithValue(ctx, verifiedKey{}, v)
}

// withVerified is the default OnVerified hook — stores v under verifiedKey.
func withVerified(r *http.Request, v *VerifiedRequest) *http.Request {
	ctx := context.WithValue(r.Context(), verifiedKey{}, v)
	return r.WithContext(ctx)
}

// Middleware wraps next with an RFC 9421 verifier + replay check. Requests
// that pass verification continue down the chain with a VerifiedRequest
// stored in context. Requests that fail are rejected with 401 and a
// Connect-flavoured JSON error body.
//
// Only requests matching PathPredicate are verified — health checks and
// well-known endpoints are intentionally left unsigned.
func Middleware(resolver KeyResolver, replay ReplayStore, opts InterceptorOptions, next http.Handler) http.Handler {
	cfg := newMiddlewareConfig(opts)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.predicate(r) {
			next.ServeHTTP(w, r)
			return
		}
		verified, err := cfg.verify(r, resolver, replay)
		if err != nil {
			if cfg.onError != nil {
				cfg.onError(r, err)
			}
			writeConnectUnauthenticated(w, err)
			return
		}
		next.ServeHTTP(w, cfg.onVerified(r, verified))
	})
}

// middlewareConfig collects Middleware's resolved options so the per-
// request handler stays small enough for the cognitive-complexity gate.
type middlewareConfig struct {
	predicate  func(r *http.Request) bool
	verifyOpts VerifyRequestOptions
	ttl        time.Duration
	onVerified func(r *http.Request, v *VerifiedRequest) *http.Request
	onError    func(r *http.Request, err error)
}

func newMiddlewareConfig(opts InterceptorOptions) middlewareConfig {
	pathPredicate := opts.PathPredicate
	if pathPredicate == nil {
		pathPredicate = defaultPathPredicate
	}
	predicate := opts.RequestPredicate
	if predicate == nil {
		predicate = func(r *http.Request) bool { return pathPredicate(r.URL.Path) }
	}
	ttl := opts.ReplayWindow
	if ttl <= 0 {
		ttl = ReplayTTL
	}
	onVerified := opts.OnVerified
	if onVerified == nil {
		onVerified = withVerified
	}
	return middlewareConfig{
		predicate:  predicate,
		verifyOpts: VerifyRequestOptions{Clk: opts.Clk},
		ttl:        ttl,
		onVerified: onVerified,
		onError:    opts.OnError,
	}
}

// verify runs RFC 9421 verification + replay check; the bool errors are
// flattened into a single error return so Middleware's hot path is a
// linear if-err chain.
func (c middlewareConfig) verify(r *http.Request, resolver KeyResolver, replay ReplayStore) (*VerifiedRequest, error) {
	verified, err := VerifyRequest(r, resolver, c.verifyOpts)
	if err != nil {
		return nil, err
	}
	seen, rerr := replay.SeenOrAdd(r.Context(), verified.KeyID, verified.Signature, c.ttl)
	if rerr != nil {
		return nil, rerr
	}
	if seen {
		return nil, ErrReplayed
	}
	return verified, nil
}

// ErrReplayed is the sentinel the Middleware writes to OnError when a
// (keyID, signature) pair is seen within the replay window.
var ErrReplayed = errors.New("httpsig: signature replayed within window")

// defaultPathPredicate matches every Connect-Go procedure path under the
// ramp.v1 namespace. Extend by passing a custom PathPredicate when Broker
// or Exchange adds non-ramp Connect services.
func defaultPathPredicate(path string) bool {
	return strings.HasPrefix(path, "/ramp.")
}

// writeConnectUnauthenticated emits a Connect-compatible error response so
// Connect clients see a proper unauthenticated code instead of a raw 401.
func writeConnectUnauthenticated(w http.ResponseWriter, err error) {
	ce := connect.NewError(connect.CodeUnauthenticated, err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"code":"unauthenticated","message":` + jsonQuote(ce.Message()) + `}`))
}

// jsonQuote returns s escaped for embedding in a JSON string literal.
func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
