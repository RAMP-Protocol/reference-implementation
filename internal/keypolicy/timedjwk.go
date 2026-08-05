package keypolicy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// RunningWBAResolver builds an SDK WBAKeyResolver from opts and starts its
// background revocation/refresh poller on ctx, returning the running resolver.
// It captures the construction preamble every WBA-backed resolver shares; each
// caller keeps its own Resolve error policy (which delegate verdicts are
// authoritative vs. fall-through) layered on top of the returned resolver.
func RunningWBAResolver(
	ctx context.Context, opts resolvers.WBAKeyResolverOptions,
) *resolvers.WBAKeyResolver {
	resolver := resolvers.NewWBAKeyResolver(opts)
	go resolver.Run(ctx)
	return resolver
}

// TimedKey is one decoded, thumbprinted, window-validated Ed25519 JWK entry.
type TimedKey struct {
	Thumbprint string
	Public     ed25519.PublicKey
	NotBefore  time.Time
	NotAfter   time.Time
}

// InWindow reports whether now falls inside the key's [NotBefore, NotAfter)
// validity window. A zero bound is open on that side — a key published
// without a window never expires by time (retiring it takes removal from the
// key set). Callers that hold a TimedKey MUST gate use on this check;
// carrying the bounds without consulting them would publish a window and then
// honor keys outside it.
func (k TimedKey) InWindow(now time.Time) bool {
	if !k.NotBefore.IsZero() && now.Before(k.NotBefore) {
		return false
	}
	if !k.NotAfter.IsZero() && !now.Before(k.NotAfter) {
		return false
	}
	return true
}

// jwkWindow is the optional RAMP validity window (RFC 3339) plus the raw x
// parameter, layered on top of a standard JWK. not_before/not_after are RAMP
// extensions (not JWK members) and x's length must be re-checked (see below), so
// they are decoded from the same entry bytes alongside the go-jose JWK parse.
type jwkWindow struct {
	X         string `json:"x"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// DecodeTimedJWK runs the fail-closed per-entry transform every static JWKS
// loader on the request-auth trust path shares: decode the Ed25519 public key,
// derive its RFC 7638 thumbprint, and parse the [not_before, not_after)
// validity window. It returns ok=false to SKIP a malformed entry — a bad
// kty/crv, an undecodable or wrong-length x, or a present-but-unparseable window
// — so one typo cannot wedge a service at boot, and a partial window can never
// widen a key's validity. Callers differ only in the sink they write the
// returned TimedKey to.
func DecodeTimedJWK(entry json.RawMessage) (TimedKey, bool) {
	// Standard JWK members (kty/crv/x) decode off-the-shelf via go-jose
	// (library-first): the OKP/Ed25519 kty/crv guard, the base64url x decode, and
	// key-type discrimination. A non-OKP/Ed25519 key type or an undecodable x
	// fails the unmarshal or the type assertion, and the entry is SKIPPED.
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(entry); err != nil {
		return TimedKey{}, false
	}
	pub, ok := jwk.Key.(ed25519.PublicKey)
	if !ok {
		return TimedKey{}, false
	}
	var ext jwkWindow
	if err := json.Unmarshal(entry, &ext); err != nil {
		return TimedKey{}, false
	}
	// go-jose's OKP path silently zero-pads or truncates a wrong-length x to 32
	// bytes rather than rejecting it, so re-validate x against the RFC 8037
	// 32-byte contract via the shared decoder — the one check go-jose does not
	// enforce. A wrong-length entry is SKIPPED, preserving the fail-closed reject.
	if _, err := rampwellknown.DecodeEd25519X(ext.X); err != nil {
		return TimedKey{}, false
	}
	tp, err := helpers.Thumbprint(pub)
	if err != nil {
		return TimedKey{}, false
	}
	nb, na, ok := parseWindow(ext.NotBefore, ext.NotAfter)
	if !ok {
		return TimedKey{}, false
	}
	return TimedKey{Thumbprint: tp, Public: pub, NotBefore: nb, NotAfter: na}, true
}

// parseWindow parses optional RFC 3339 not_before / not_after bounds. An empty
// string is unbounded (zero time). A present-but-unparseable bound reports
// ok=false so the caller skips the malformed entry rather than treating a typo
// as unbounded — which would make an out-of-window key silently always-valid
// (fail-closed).
func parseWindow(notBefore, notAfter string) (nb, na time.Time, ok bool) {
	var err error
	if notBefore != "" {
		if nb, err = time.Parse(time.RFC3339, notBefore); err != nil {
			return time.Time{}, time.Time{}, false
		}
	}
	if notAfter != "" {
		if na, err = time.Parse(time.RFC3339, notAfter); err != nil {
			return time.Time{}, time.Time{}, false
		}
	}
	return nb, na, true
}
