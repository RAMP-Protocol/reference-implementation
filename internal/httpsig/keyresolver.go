package httpsig

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// KeyResolver looks up the Ed25519 public key registered for keyid. The
// adapter is the boundary between the RFC 9421 verifier and whatever key
// directory the caller wires (static map, Broker /.well-known, tenant DB).
// Implementations are expected to return ErrUnknownKey (or a wrapping error)
// when the keyid is not registered.
type KeyResolver interface {
	Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error)
}

// StaticResolver serves pubkeys from an in-memory map. Tests and the demo
// hardcoded-agent path use this directly.
type StaticResolver struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

// NewStaticResolver returns a StaticResolver seeded with keys.
func NewStaticResolver(keys map[string]ed25519.PublicKey) *StaticResolver {
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for k, v := range keys {
		copied[k] = v
	}
	return &StaticResolver{keys: copied}
}

// Resolve implements KeyResolver.
func (s *StaticResolver) Resolve(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pub, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: keyid=%q", ErrUnknownKey, keyID)
	}
	return pub, nil
}

// Put registers a keyid → pubkey mapping. Intended for test seeding and
// dynamic registration paths (Broker agent-register endpoint).
func (s *StaticResolver) Put(keyID string, pub ed25519.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[keyID] = pub
}

// WellKnownResolver fetches a JWKS-shaped document from a URL and caches
// resolved keys with a TTL. The wire format is a subset of RFC 7517:
//
//	{"keys":[
//	  {"kid":"agent1.v1","kty":"OKP","crv":"Ed25519","x":"<base64url>","use":"sig","alg":"EdDSA"}
//	]}
type WellKnownResolver struct {
	url         string
	http        *http.Client
	ttl         time.Duration
	clk         clock.Clock
	mu          sync.RWMutex
	cache       map[string]ed25519.PublicKey
	cacheExp    time.Time
	allowlist   func(keyID string) bool
	fetchSingle sync.Mutex
}

// WellKnownOptions tunes the resolver. Zero values are safe defaults.
type WellKnownOptions struct {
	// HTTP overrides the client used to fetch the JWKS. nil means http.DefaultClient.
	HTTP *http.Client
	// TTL is how long to cache a successful fetch. Defaults to 5 minutes.
	TTL time.Duration
	// Clk is the clock source consulted for cache freshness. Defaults to
	// clock.System{} per ADR-008 D1.
	Clk clock.Clock
	// Allow returns true when keyID is allowed to sign against this verifier.
	// nil means allow-all (demo default — explicit TODO).
	Allow func(keyID string) bool
}

// NewWellKnownResolver returns a resolver that lazily fetches the JWKS at url.
func NewWellKnownResolver(url string, opts WellKnownOptions) *WellKnownResolver {
	client := opts.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	clk := opts.Clk
	if clk == nil {
		clk = clock.System{}
	}
	// TODO(ramp-agent-registry): allowlist should be per-tenant, sourced from
	// the Broker agent registry. For the v1 demo a nil allowlist means accept
	// any registered keyid; replaced when multi-tenant registration lands.
	return &WellKnownResolver{
		url:       url,
		http:      client,
		ttl:       ttl,
		clk:       clk,
		cache:     map[string]ed25519.PublicKey{},
		allowlist: opts.Allow,
	}
}

// Resolve implements KeyResolver. Cache hit short-circuits; cache miss or TTL
// expiry triggers a single JWKS refresh (races are coalesced by fetchSingle).
func (r *WellKnownResolver) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	if r.allowlist != nil && !r.allowlist(keyID) {
		return nil, fmt.Errorf("%w: keyid %q not on allowlist", ErrUnknownKey, keyID)
	}
	if pub, ok := r.cachedKey(keyID); ok {
		return pub, nil
	}
	if err := r.refresh(ctx); err != nil {
		return nil, err
	}
	if pub, ok := r.cachedKey(keyID); ok {
		return pub, nil
	}
	return nil, fmt.Errorf("%w: keyid=%q", ErrUnknownKey, keyID)
}

func (r *WellKnownResolver) cachedKey(keyID string) (ed25519.PublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.clk.Now().After(r.cacheExp) {
		return nil, false
	}
	pub, ok := r.cache[keyID]
	return pub, ok
}

func (r *WellKnownResolver) refresh(ctx context.Context) error {
	r.fetchSingle.Lock()
	defer r.fetchSingle.Unlock()
	// Double-check: another goroutine may have refreshed while we waited.
	r.mu.RLock()
	fresh := r.clk.Now().Before(r.cacheExp)
	r.mu.RUnlock()
	if fresh {
		return nil
	}
	// r.url is operator-supplied configuration (broker /.well-known JWKS endpoint),
	// not request-derived input — gosec G107/G704 SSRF taint is a false positive.
	// #nosec G107 G704 -- trusted operator config
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return fmt.Errorf("httpsig: well-known request: %w", err)
	}
	// #nosec G107 G704 -- trusted operator config
	resp, err := r.http.Do(req)
	if err != nil {
		return fmt.Errorf("httpsig: well-known fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("httpsig: well-known status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&doc); decErr != nil {
		return fmt.Errorf("httpsig: well-known decode: %w", decErr)
	}
	fresh2 := make(map[string]ed25519.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if !strings.EqualFold(k.Kty, "OKP") || !strings.EqualFold(k.Crv, "Ed25519") {
			continue
		}
		raw, decErr := base64.RawURLEncoding.DecodeString(k.X)
		if decErr != nil {
			continue
		}
		if len(raw) != ed25519.PublicKeySize {
			continue
		}
		fresh2[k.Kid] = ed25519.PublicKey(raw)
	}
	r.mu.Lock()
	r.cache = fresh2
	r.cacheExp = r.clk.Now().Add(r.ttl)
	r.mu.Unlock()
	return nil
}
