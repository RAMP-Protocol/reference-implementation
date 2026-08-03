package httpsig

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

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
	// MaxSignatures bounds the signature (hop) count on a multisig request.
	// 0 (the zero value) means unbounded — only the Exchange-terminal middleware
	// sets it (= max_intermediary_hops + 1); Broker ingress must leave it 0 so
	// the relay hop is not double-bounded.
	MaxSignatures int
	// OnVerified is called on successful verification. Handlers can use this
	// to stash the verified keyID into request-scoped state for audit
	// logging. nil means no-op.
	OnVerified func(r *http.Request, v *VerifiedRequest) *http.Request
	// OnError is called before the interceptor writes the reject response.
	// Intended for structured logging of rejections.
	OnError func(r *http.Request, err error)
	// OnReject writes the HTTP error response for a rejected request. When
	// nil, Middleware writes a transport-agnostic JSON body with a 401 status
	// (429 for a hop-budget rejection). Connect-over-HTTP services inject a
	// Connect-aware writer (internal/httpsig/transportconnect.WriteError) so
	// clients see a proper Connect code; keeping the mapping out of this
	// package preserves its protocol purity (Architecture Rules 5 and 9).
	OnReject func(w http.ResponseWriter, err error)
}

// verifiedKey carries the VerifiedRequest in the request context so handlers
// (or downstream middleware) can read the caller's keyID without re-parsing.
type verifiedKey struct{}

// multisigKey carries all verified signatures for multisig requests.
type multisigKey struct{}

// FromContext returns the VerifiedRequest the Middleware stashed, or nil.
// For multisig requests, this returns the first signature for backward compat.
func FromContext(ctx context.Context) *VerifiedRequest {
	// Try multisig context first
	if sigs, ok := ctx.Value(multisigKey{}).([]VerifiedRequest); ok && len(sigs) > 0 {
		return &sigs[0]
	}
	// Fall back to single-sig context
	v, _ := ctx.Value(verifiedKey{}).(*VerifiedRequest)
	return v
}

// AllSignaturesFromContext returns all verified signatures (multisig case).
// Returns slice with single element for single-sig requests, or nil if no
// signatures are in context.
func AllSignaturesFromContext(ctx context.Context) []VerifiedRequest {
	if sigs, ok := ctx.Value(multisigKey{}).([]VerifiedRequest); ok {
		return sigs
	}
	// Fall back to single-sig context for backward compat
	if v, ok := ctx.Value(verifiedKey{}).(*VerifiedRequest); ok && v != nil {
		return []VerifiedRequest{*v}
	}
	return nil
}

// NewContext returns a copy of ctx carrying v under the verified-request key.
// Tests use this to drive handler-level authz without standing up the full
// middleware + signing chain. Production code MUST NOT call this: the
// Middleware is the only legitimate populator of the verified-request slot.
func NewContext(ctx context.Context, v *VerifiedRequest) context.Context {
	return context.WithValue(ctx, verifiedKey{}, v)
}

// NewMultisigContext returns a copy of ctx carrying all verified signatures.
// Tests use this to drive handler-level multisig authz without standing up
// the full middleware + signing chain. Production code MUST NOT call this:
// the Middleware is the only legitimate populator of the multisig slot.
func NewMultisigContext(ctx context.Context, sigs []VerifiedRequest) context.Context {
	return context.WithValue(ctx, multisigKey{}, sigs)
}

// withVerified is the default OnVerified hook — stores v under verifiedKey.
// For single-sig requests (backward compat), stores single signature.
// For multisig requests, stores all signatures under multisigKey.
func withVerified(r *http.Request, v *VerifiedRequest) *http.Request {
	// Check if we have multisig context already set
	if sigs := AllSignaturesFromContext(r.Context()); sigs != nil {
		// Already set by withMultisigVerified, don't override
		return r
	}
	// Single-sig backward compat path
	ctx := context.WithValue(r.Context(), verifiedKey{}, v)
	return r.WithContext(ctx)
}

// withMultisigVerified stores all verified signatures in context.
func withMultisigVerified(r *http.Request, sigs []VerifiedRequest) *http.Request {
	ctx := context.WithValue(r.Context(), multisigKey{}, sigs)
	return r.WithContext(ctx)
}

// Middleware wraps next with an RFC 9421 verifier + replay check. Requests
// that pass verification continue down the chain with verified signature(s)
// stored in context. Requests that fail are rejected with 401 and a
// Connect-flavoured JSON error body.
//
// Supports both single-sig and multisig requests. All signatures are stored
// in context; FromContext returns the first signature for backward compat.
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
		sigs, err := cfg.verifyMultisig(r, resolver, replay)
		if err != nil {
			if cfg.onError != nil {
				cfg.onError(r, err)
			}
			cfg.onReject(w, err)
			return
		}
		// Store all signatures in context
		r = withMultisigVerified(r, sigs)
		// Call legacy OnVerified hook with first signature for backward compat
		if len(sigs) > 0 {
			r = cfg.onVerified(r, &sigs[0])
		}
		next.ServeHTTP(w, r)
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
	onReject   func(w http.ResponseWriter, err error)
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
	onReject := opts.OnReject
	if onReject == nil {
		onReject = writePlainReject
	}
	return middlewareConfig{
		predicate:  predicate,
		verifyOpts: VerifyRequestOptions{Clk: opts.Clk, MaxSignatures: opts.MaxSignatures},
		ttl:        ttl,
		onVerified: onVerified,
		onError:    opts.OnError,
		onReject:   onReject,
	}
}

// verifyMultisig runs RFC 9421 verification + replay check for all signatures.
// Returns all verified signatures or an error if any signature fails.
func (c middlewareConfig) verifyMultisig(
	r *http.Request, resolver KeyResolver, replay ReplayStore,
) ([]VerifiedRequest, error) {
	sigs, err := VerifyMultisigRequest(r, resolver, c.verifyOpts)
	if err != nil {
		return nil, err
	}
	// Replay is checked in two phases so a rejected multisig request never burns
	// the replay key of its other signatures. Phase 1: reject if ANY
	// signature is already recorded, adding nothing. Phase 2: commit them all.
	// SeenOrAdd in phase 2 still guards a concurrent duplicate that races between
	// the phases — its first (agent) label trips here.
	for i := range sigs {
		seen, rerr := replay.Seen(r.Context(), sigs[i].KeyID, sigs[i].Signature)
		if rerr != nil {
			return nil, rerr
		}
		if seen {
			return nil, ErrReplayed
		}
	}
	for i := range sigs {
		seen, rerr := replay.SeenOrAdd(r.Context(), sigs[i].KeyID, sigs[i].Signature, c.ttl)
		if rerr != nil {
			return nil, rerr
		}
		if seen {
			return nil, ErrReplayed
		}
	}
	return sigs, nil
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

// writePlainReject is the default OnReject responder: a transport-agnostic JSON
// body with a 401 status (429 for a hop-budget rejection). HTTP status codes are
// universal, so distinguishing the hop bound here is not transport coupling;
// mapping to a Connect code/audit token is, and lives in
// internal/httpsig/transportconnect. Connect-over-HTTP services override this
// via InterceptorOptions.OnReject so their clients see a proper Connect code.
func writePlainReject(w http.ResponseWriter, err error) {
	status := http.StatusUnauthorized
	if errors.Is(err, ErrTooManyHops) {
		status = http.StatusTooManyRequests
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]string{"error": err.Error()})
	_, _ = w.Write(body)
}
