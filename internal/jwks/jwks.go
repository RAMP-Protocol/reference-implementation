// Package jwks fetches and parses the buyer's Ed25519 delegation pubkey
// JWKS from an opaque HTTPS URL (ADR-002 §C, ADR-003 §1).
//
// # Wire-protocol promise — the URL is OPAQUE
//
// Per ADR-003 §1 the keys URL is treated as an opaque https:// reference.
// Verifiers (and this fetcher) enforce exactly two URL properties:
//
//   - the scheme MUST be https:// (http:// is allowed only when the URL
//     points at the loopback address — convenience for the dev/demo stack);
//   - the response body MUST parse as a JWKS (RFC 7517) carrying at least
//     one OKP/Ed25519 entry.
//
// No path inspection. No host-matches-issuer derivation. No well-known
// path assumption. The buyer chooses the URL; the resource owner trusts it
// transitively because the contract says so.
package jwks

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// fetchTimeout caps the total HTTP-fetch latency.
const fetchTimeout = 10 * time.Second

// Errors returned by Fetch + Resolve.
var (
	// ErrInvalidURL — the buyer-keys URL is not an https:// (or loopback http)
	// reference.
	ErrInvalidURL = errors.New("jwks: invalid URL")
	// ErrFetch — HTTP fetch or body read failed.
	ErrFetch = errors.New("jwks: fetch failed")
	// ErrParse — body did not decode as a JWKS.
	ErrParse = errors.New("jwks: parse failed")
	// ErrUnknownKID — the requested kid is not present in the fetched JWKS
	// (or is present but carries a mismatching `use`).
	ErrUnknownKID = errors.New("jwks: unknown kid")
	// ErrNoKeys — the fetched JWKS contains no Ed25519 OKP entries.
	ErrNoKeys = errors.New("jwks: no Ed25519 keys present")
	// ErrInvalidKey — an entry is missing required fields or has malformed
	// pubkey bytes.
	ErrInvalidKey = errors.New("jwks: invalid key entry")
)

// Use is the JWK `use` member narrowed to the two values RAMP recognizes
// (ADR-003 §5c, ye6f-21, ramp-protocol §1.1). The value discriminates which
// signing operation a key is authorized for:
//
//   - UseVerify — signs entitlement-biscuit authority blocks, agent RFC 9421
//     signatures, broker relay signatures, attestations.
//   - UseRevoke — signs revocation-list responses only. MUST be distinct
//     from the issuer's verify key so a compromised signing key does not
//     compromise the revocation path.
//
// Legacy JWKS entries written before the split carry `use=sig` (the JOSE
// default) and are treated as UseVerify for backward compatibility — the
// verify/revoke split is a RAMP convention on top of stock JOSE.
type Use string

// Use values recognized by the RAMP JWKS contract.
const (
	UseVerify Use = "verify"
	UseRevoke Use = "revoke"
)

// matchesUse returns true when the JWK's `use` field authorizes it for the
// requested operation. Empty or `sig` values are treated as UseVerify for
// backward compatibility with pre-ye6f-21 JWKS bodies.
func matchesUse(jwk JWK, want Use) bool {
	got := strings.ToLower(strings.TrimSpace(jwk.Use))
	switch got {
	case "", "sig":
		return want == UseVerify
	default:
		return Use(got) == want
	}
}

// JWK is the OKP/Ed25519 subset of RFC 7517 we care about. Other key types
// in the body are ignored.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	// IssuedAt is an optional non-RFC field some hosting platforms emit to
	// disambiguate "most recent" when multiple kids are present. Parsed best-
	// effort; absence falls back to position order in the response.
	IssuedAt string `json:"issued_at,omitempty"`
}

// Set is the parsed JWKS body limited to OKP/Ed25519 entries.
type Set struct {
	Keys []JWK
}

// ResolvedKey is the result of selecting a single kid from a fetched Set.
type ResolvedKey struct {
	Kid       string
	PublicKey ed25519.PublicKey
}

// Fetcher pulls JWKS bodies. Tests substitute a fake; production wires
// http.DefaultClient.
type Fetcher interface {
	Fetch(ctx context.Context, jwksURL string) (*Set, error)
}

// HTTPFetcher implements Fetcher over net/http.
//
// AllowInsecure relaxes the ADR-003 §1 https-only invariant so the
// fetcher accepts http:// URLs to non-loopback hosts. The flag is OFF
// by default; production callers leave it unset so cross-internet
// fetches stay https-only. Compose-internal callers (publisher-jwks
// reached via the `examplenews` network alias) opt in explicitly so the
// shared package serves both the public fetch path and the
// dev/demo-stack fetch path without a second copy.
type HTTPFetcher struct {
	Client        *http.Client
	AllowInsecure bool
}

// NewHTTPFetcher returns an HTTPFetcher with a 10s-timeout client and
// the production-safe https-only default (AllowInsecure=false).
func NewHTTPFetcher() *HTTPFetcher {
	return &HTTPFetcher{Client: &http.Client{Timeout: fetchTimeout}}
}

// Fetch validates the URL, GETs the JWKS, and parses it.
func (f *HTTPFetcher) Fetch(ctx context.Context, jwksURL string) (*Set, error) {
	if err := validateURLWithAllow(jwksURL, f.AllowInsecure); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrFetch, err)
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%w: status %d", ErrFetch, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrFetch, err)
	}
	return Parse(body)
}

// Parse decodes JWKS bytes; exposed for unit tests and callers that already
// hold the body (e.g. signed-revocation-list flows).
func Parse(body []byte) (*Set, error) {
	var raw struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	out := &Set{Keys: make([]JWK, 0, len(raw.Keys))}
	for _, k := range raw.Keys {
		if !strings.EqualFold(k.Kty, "OKP") || !strings.EqualFold(k.Crv, "Ed25519") {
			continue
		}
		out.Keys = append(out.Keys, k)
	}
	if len(out.Keys) == 0 {
		return nil, ErrNoKeys
	}
	return out, nil
}

// Resolve picks a single `use=verify` kid from the Set and decodes its
// pubkey bytes. Entries whose `use` field is `revoke` are filtered out
// because revocation-signing keys MUST NOT validate biscuit chains
// (ADR-003 §5c). Legacy entries with `use=sig` or an empty `use` are
// treated as `use=verify` for backward compatibility — see Use docs.
//
// When kid is non-empty the named entry is selected from the verify set;
// ErrUnknownKID is returned if no verify entry matches. When kid is empty
// the most-recent verify entry wins — defined as the entry with the
// latest parseable RFC3339 issued_at, falling back to last-position order
// in the JWKS body when issued_at is absent.
//
// Use ResolveRevoke when you need to verify a revocation-list signature
// instead of a biscuit signature.
func Resolve(set *Set, kid string) (ResolvedKey, error) {
	return resolveUse(set, kid, UseVerify)
}

// ResolveRevoke is the dual of Resolve for revocation-list signing keys
// (use=revoke). Entries with `use=verify`, `use=sig`, or empty `use` are
// filtered out; only explicit `use=revoke` entries are eligible.
//
// A JWKS that contains only verify entries returns ErrUnknownKID — the
// caller (a revocation-list verifier) MUST refuse to validate a list
// when no dedicated revocation key is published.
func ResolveRevoke(set *Set, kid string) (ResolvedKey, error) {
	return resolveUse(set, kid, UseRevoke)
}

func resolveUse(set *Set, kid string, want Use) (ResolvedKey, error) {
	if set == nil || len(set.Keys) == 0 {
		return ResolvedKey{}, ErrNoKeys
	}
	eligible := make([]JWK, 0, len(set.Keys))
	for _, k := range set.Keys {
		if matchesUse(k, want) {
			eligible = append(eligible, k)
		}
	}
	if len(eligible) == 0 {
		if kid != "" {
			return ResolvedKey{}, fmt.Errorf("%w: %q (no use=%s entries)", ErrUnknownKID, kid, want)
		}
		return ResolvedKey{}, fmt.Errorf("%w: no use=%s entries", ErrUnknownKID, want)
	}
	if kid != "" {
		for _, k := range eligible {
			if k.Kid == kid {
				return decodeKey(k)
			}
		}
		return ResolvedKey{}, fmt.Errorf("%w: %q (use=%s)", ErrUnknownKID, kid, want)
	}
	return decodeKey(pickMostRecent(eligible))
}

func pickMostRecent(keys []JWK) JWK {
	indexed := make([]struct {
		key JWK
		ts  time.Time
		pos int
	}, len(keys))
	for i, k := range keys {
		ts, _ := time.Parse(time.RFC3339, k.IssuedAt)
		indexed[i] = struct {
			key JWK
			ts  time.Time
			pos int
		}{k, ts, i}
	}
	sort.SliceStable(indexed, func(i, j int) bool {
		if !indexed[i].ts.Equal(indexed[j].ts) {
			return indexed[i].ts.After(indexed[j].ts)
		}
		return indexed[i].pos > indexed[j].pos
	})
	return indexed[0].key
}

func decodeKey(k JWK) (ResolvedKey, error) {
	if k.X == "" {
		return ResolvedKey{}, fmt.Errorf("%w: kid=%q missing x", ErrInvalidKey, k.Kid)
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return ResolvedKey{}, fmt.Errorf("%w: kid=%q decode x: %w", ErrInvalidKey, k.Kid, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return ResolvedKey{}, fmt.Errorf("%w: kid=%q pubkey is %d bytes (need %d)",
			ErrInvalidKey, k.Kid, len(raw), ed25519.PublicKeySize)
	}
	return ResolvedKey{Kid: k.Kid, PublicKey: ed25519.PublicKey(raw)}, nil
}

// validateURLWithAllow enforces ADR-003 §1 — opaque URL, scheme MUST
// be https (loopback http allowed for dev/demo). The allowInsecure
// escape hatch HTTPFetcher exposes to opt-in dev/demo callers extends
// the policy: when allowInsecure is true, http:// to any host is
// accepted; the loopback exception applies regardless. Production
// callers leave the flag unset so cross-internet fetches stay
// https-only per ADR-003 §1.
func validateURLWithAllow(rawURL string, allowInsecure bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: missing host in %q", ErrInvalidURL, rawURL)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) || allowInsecure {
			return nil
		}
	}
	return fmt.Errorf("%w: scheme %q not allowed (https required)", ErrInvalidURL, u.Scheme)
}

func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// FetcherFunc adapts a function into a Fetcher; used by tests.
type FetcherFunc func(ctx context.Context, url string) (*Set, error)

// Fetch calls the wrapped function.
func (f FetcherFunc) Fetch(ctx context.Context, url string) (*Set, error) { return f(ctx, url) }
