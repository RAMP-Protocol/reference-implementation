// Package buyerkeys fetches and caches buyer JWKS documents referenced by
// the authority-block `buyer_keys_url` fact (ADR-002 Gate B).
//
// The URL is protocol-opaque: ADR-002 deliberately places no structural
// constraint on the buyer's key-hosting location — it may be an enterprise
// {buyer_domain}/.well-known/ramp.json, a platform-hosted
// {platform}/buyers/{customer}/keys, a KMS/wallet provider URL, or any
// other HTTPS resource the subscriber's contract names. This package
// therefore takes a URL and treats it as a JWKS bag with no path-shape
// assumptions.
//
// Cache TTL is 5 minutes per ADR-003 §4. Callers that have never seen a
// successful fetch for a given URL receive ErrUnavailable when the current
// fetch fails; callers that saw at least one successful fetch continue to
// be served from the cached entry (the revocation-list fetcher implements
// the same fail-closed-on-stale rule; see docs/design/key-revocation.md).
package buyerkeys

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// Sentinel errors returned by Fetcher. Callers map these to
// PermissionDenied with specific audit reasons (Gate B reasons
// "buyer_key_rotated" or "buyer_jwks_unreachable").
var (
	// ErrUnavailable — the JWKS URL is unreachable and no cached entry
	// is available. Callers MUST fail closed.
	ErrUnavailable = errors.New("buyerkeys: JWKS unavailable")
	// ErrMalformed — the URL returned a document that could not be
	// parsed as a JWKS with ed25519 keys.
	ErrMalformed = errors.New("buyerkeys: JWKS malformed")
	// ErrInsecureScheme — a non-HTTPS URL was supplied in production.
	// Tests may opt into http:// via AllowInsecure.
	ErrInsecureScheme = errors.New("buyerkeys: URL must be https")
)

// DefaultCacheTTL matches the protocol-level 5-minute cache hint.
const DefaultCacheTTL = 5 * time.Minute

// Config tunes a Fetcher. The zero value yields a production-safe fetcher
// with 5m cache TTL and HTTP-disallowed.
type Config struct {
	HTTP *http.Client
	// Clk drives cache-entry freshness comparisons. Defaults to clock.System{}
	// per ADR-008 D1.
	Clk           clock.Clock
	TTL           time.Duration
	AllowInsecure bool
}

// Fetcher resolves buyer_keys_url → set of ed25519 public keys. Safe for
// concurrent use; the cache is guarded by a mutex.
type Fetcher struct {
	http  *http.Client
	clk   clock.Clock
	ttl   time.Duration
	allow bool
	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	fetchedAt time.Time
	keys      []ed25519.PublicKey
	rawKIDs   map[string]ed25519.PublicKey // kid → key for look-by-kid
}

// New constructs a Fetcher honoring cfg. HTTP defaults to a 5s-timeout
// client; Clk defaults to clock.System{}; TTL defaults to DefaultCacheTTL.
func New(cfg Config) *Fetcher {
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	clk := cfg.Clk
	if clk == nil {
		clk = clock.System{}
	}
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = DefaultCacheTTL
	}
	return &Fetcher{
		http:  client,
		clk:   clk,
		ttl:   ttl,
		allow: cfg.AllowInsecure,
		cache: make(map[string]cacheEntry),
	}
}

// Contains reports whether the raw ed25519 public key bytes (32 bytes) are
// present in the JWKS at url. Used by Gate B to assert that the
// authority-block buyer_delegation_pubkey is still in the buyer's live key
// set.
//
// Fetch errors with a valid cached entry return the cached membership
// decision. Fetch errors with no cached entry return ErrUnavailable.
func (f *Fetcher) Contains(ctx context.Context, url string, pub ed25519.PublicKey) (bool, error) {
	entry, err := f.resolve(ctx, url)
	if err != nil {
		return false, err
	}
	for _, k := range entry.keys {
		if len(k) == len(pub) && equalEd25519(k, pub) {
			return true, nil
		}
	}
	return false, nil
}

// LookupKID returns the ed25519 key registered under kid in the JWKS at
// url, or false when the kid is absent. Used by gates that need a specific
// key (e.g. revocation list signature verification downstream).
func (f *Fetcher) LookupKID(ctx context.Context, url, kid string) (ed25519.PublicKey, bool, error) {
	entry, err := f.resolve(ctx, url)
	if err != nil {
		return nil, false, err
	}
	k, ok := entry.rawKIDs[kid]
	return k, ok, nil
}

// resolve returns the current cache entry for url, refreshing if the TTL
// has elapsed. Stale entries are served when refresh fails (fail-closed on
// stale, per ADR-003 §4/§5b).
func (f *Fetcher) resolve(ctx context.Context, url string) (cacheEntry, error) {
	if err := validateScheme(url, f.allow); err != nil {
		return cacheEntry{}, err
	}
	f.mu.Lock()
	existing, hit := f.cache[url]
	fresh := hit && f.clk.Now().Sub(existing.fetchedAt) < f.ttl
	f.mu.Unlock()
	if fresh {
		return existing, nil
	}

	entry, fetchErr := f.fetch(ctx, url)
	if fetchErr != nil {
		if hit {
			return existing, nil
		}
		return cacheEntry{}, fmt.Errorf("%w: %s: %w", ErrUnavailable, url, fetchErr)
	}
	f.mu.Lock()
	f.cache[url] = entry
	f.mu.Unlock()
	return entry, nil
}

// validateScheme rejects non-HTTPS URLs in production mode.
func validateScheme(url string, allowInsecure bool) error {
	switch {
	case strings.HasPrefix(url, "https://"):
		return nil
	case allowInsecure && strings.HasPrefix(url, "http://"):
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrInsecureScheme, url)
	}
}

// fetch GETs the JWKS document and parses the ed25519 `OKP` keys out of it.
func (f *Fetcher) fetch(ctx context.Context, url string) (cacheEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return cacheEntry{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.http.Do(req)
	if err != nil {
		return cacheEntry{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return cacheEntry{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return cacheEntry{}, err
	}
	entry, err := parseJWKS(body)
	if err != nil {
		return cacheEntry{}, err
	}
	entry.fetchedAt = f.clk.Now()
	return entry, nil
}

// parseJWKS decodes a JWKS document and keeps only OKP/Ed25519 keys whose
// `use` is either "verify" (signing) or unset (back-compat). Revocation
// keys (use="revoke") are tracked separately by the revocationlist
// package and intentionally excluded here.
func parseJWKS(body []byte) (cacheEntry, error) {
	var raw struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Kid string `json:"kid"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return cacheEntry{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	entry := cacheEntry{rawKIDs: make(map[string]ed25519.PublicKey)}
	for _, k := range raw.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		if k.Use != "" && k.Use != "verify" {
			continue
		}
		pub, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return cacheEntry{}, fmt.Errorf("%w: key x=%q: %w", ErrMalformed, k.X, err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return cacheEntry{}, fmt.Errorf("%w: key x length=%d", ErrMalformed, len(pub))
		}
		edpub := ed25519.PublicKey(pub)
		entry.keys = append(entry.keys, edpub)
		if k.Kid != "" {
			entry.rawKIDs[k.Kid] = edpub
		}
	}
	return entry, nil
}

func equalEd25519(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
