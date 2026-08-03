// Package windowtest provides the shared static-key validity-window fixture and
// behavior table that both the Broker and Exchange window suites drive. The
// [not_before, not_after) gate is a single property of the static-key trust
// path; specifying it once here lets each service's window file reduce to a
// wiring assertion over its own loader instead of re-deriving the same four
// scenarios verbatim.
package windowtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// Anchor is the deterministic "now" the behavior cases are evaluated against. It
// sits between every lapsed bound and every not-yet-valid bound below, so a
// resolver reading it from an injected clock returns a stable verdict. Both
// service adapters build clock.NewDeterministic(Anchor).
var Anchor = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

// MintWindowedJWKS builds a one-entry JWKS carrying the given optional RFC 3339
// window and returns its bytes plus the key's RFC 7638 thumbprint (the keyid the
// loaders index by after the WBA split).
func MintWindowedJWKS(t *testing.T, notBefore, notAfter string) (raw []byte, thumbprint string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(pub)
	tp, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	window := ""
	if notBefore != "" {
		window += fmt.Sprintf(`,"not_before":%q`, notBefore)
	}
	if notAfter != "" {
		window += fmt.Sprintf(`,"not_after":%q`, notAfter)
	}
	doc := fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q%s}]}`, x, window)
	return []byte(doc), tp
}

// Case is one static-key validity-window scenario and its expected resolve
// verdict. WantExpired true means the resolver must return
// resolvers.ErrKeyExpired (authoritative — never a fall-through to unknown);
// false means it must resolve to the key's public bytes.
type Case struct {
	Name        string
	NotBefore   string
	NotAfter    string
	WantExpired bool
}

// BehaviorCases are the window scenarios whose verdict is identical across both
// services' loaders: each entry loads successfully, and only the window gate
// decides the resolve outcome. The fail-closed unparseable-window case is NOT
// here — it diverges by loader (one reports no keys loaded, the other an unknown
// key), so each service keeps that as its own local wiring assertion.
func BehaviorCases() []Case {
	return []Case{
		{"lapsed", "2020-01-01T00:00:00Z", "2020-01-02T00:00:00Z", true},
		{"not-yet-valid", "2999-01-01T00:00:00Z", "", true},
		{"in-window", "2020-01-01T00:00:00Z", "2999-01-01T00:00:00Z", false},
	}
}

// RunBehavior drives BehaviorCases through resolveVia — a per-service adapter
// that loads the minted JWKS bytes into that service's static resolver (clocked
// at Anchor) and returns the verdict of resolving thumbprint. Each service file
// thus reduces to one call naming its own loader.
func RunBehavior(t *testing.T, resolveVia func(t *testing.T, raw []byte, thumbprint string) error) {
	t.Helper()
	for _, tc := range BehaviorCases() {
		t.Run(tc.Name, func(t *testing.T) {
			raw, tp := MintWindowedJWKS(t, tc.NotBefore, tc.NotAfter)
			err := resolveVia(t, raw, tp)
			switch {
			case tc.WantExpired && !errors.Is(err, resolvers.ErrKeyExpired):
				t.Fatalf("%s: want ErrKeyExpired, got %v", tc.Name, err)
			case !tc.WantExpired && err != nil:
				t.Fatalf("%s: want resolve success, got %v", tc.Name, err)
			}
		})
	}
}
