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
// the same fail-closed-on-stale rule).
package buyerkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/keypolicy"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
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
	// ErrNoClient — the Fetcher was constructed with no injected HTTP client.
	// This is a permanent composition-root misconfiguration, never a retryable
	// upstream outage, so it surfaces UNWRAPPED (never chained into the transient
	// ErrUnavailable) and no network dial is attempted. Mirrors
	// rampwellknown.ErrNoClient; the SSRF-guarded client is built once at the
	// composition root and injected, matching agentreg/probe/rampwellknown.
	ErrNoClient = errors.New("buyerkeys: HTTP client is required")
)

// DefaultCacheTTL matches the protocol-level 5-minute cache hint.
const DefaultCacheTTL = 5 * time.Minute

// Config tunes a Fetcher. The zero value yields a production-safe fetcher
// with 5m cache TTL and HTTP-disallowed.
type Config struct {
	HTTP *http.Client
	// Clk drives cache-entry freshness comparisons. Defaults to clock.System{}
	// per ADR-008 D1.
	Clk clock.Clock
	TTL time.Duration
}

// Fetcher resolves buyer_keys_url → set of ed25519 public keys. Safe for
// concurrent use; the cache is guarded by a mutex.
type Fetcher struct {
	http  *http.Client
	clk   clock.Clock
	ttl   time.Duration
	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	fetchedAt time.Time
	keys      []ed25519.PublicKey
	rawKIDs   map[string]ed25519.PublicKey // kid → key for look-by-kid
}

// New constructs a Fetcher honoring cfg. The SSRF-guarded HTTP client is a
// REQUIRED injected dependency (cfg.HTTP): the buyer_keys_url is a
// contract-named, protocol-opaque HTTPS URL that MUST be fetched through the
// SDK's private-IP-blocking client, and the app is a pure consumer that owns no
// scheme policy — so the guarded client is built ONCE at the composition root
// (resolvers.NewGuardedClientFromEnv) and passed in, never fabricated here.
// This matches every sibling fetcher (agentreg, probe, rampwellknown). A nil
// cfg.HTTP is not silently patched: the Fetcher stores it and resolve returns
// the permanent ErrNoClient without dialing. Clk defaults to clock.System{};
// TTL defaults to DefaultCacheTTL.
func New(cfg Config) *Fetcher {
	clk := cfg.Clk
	if clk == nil {
		clk = clock.System{}
	}
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = DefaultCacheTTL
	}
	return &Fetcher{
		http:  cfg.HTTP,
		clk:   clk,
		ttl:   ttl,
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
		// Constant-time compare (subtle) over the raw public keys: returns 1 only
		// when the byte slices are equal AND the same length, so the explicit
		// length guard is subsumed. Public keys are not secret, but this removes a
		// hand-rolled early-return byte loop in favor of the vetted primitive.
		if subtle.ConstantTimeCompare(k, pub) == 1 {
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
	// Fail loud on a missing client BEFORE the cache serve and the ErrUnavailable
	// wrap below: a nil client is a permanent composition-root misconfiguration,
	// not a transient outage, and no cache entry could ever have been populated
	// without it. Returning ErrNoClient here (never chained into ErrUnavailable)
	// keeps a hard config error from masquerading as a retryable one.
	if f.http == nil {
		return cacheEntry{}, ErrNoClient
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
	// The standard-JWK decode (OKP/Ed25519 guard, base64url `x`, RFC 8037 32-byte
	// length check) is delegated to keypolicy.LoadJWKSBytes — THE shared
	// fail-closed JWKS loader (the Broker key registry loads through it too). A
	// malformed entry is SKIPPED there rather than failing the whole document, so
	// one typo in a buyer's key set cannot wedge the fetch. buyerkeys keeps its own
	// struct ONLY for the members the shared loader does not surface: `kid`
	// (look-by-kid) and `use` (the "verify"/unset signing-key filter; revocation
	// keys use="revoke" are excluded here and tracked by the revocationlist
	// package). Both views read the SAME bytes; entries are correlated by their
	// canonical base64url `x`.
	var raw struct {
		Keys []struct {
			X   string `json:"x"`
			Kid string `json:"kid"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return cacheEntry{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	type kidUse struct {
		kid string
		use string
	}
	meta := make(map[string]kidUse, len(raw.Keys))
	for _, k := range raw.Keys {
		meta[k.X] = kidUse{kid: k.Kid, use: k.Use}
	}
	entry := cacheEntry{rawKIDs: make(map[string]ed25519.PublicKey)}
	if err := keypolicy.LoadJWKSBytes(body, func(tk keypolicy.TimedKey) {
		m := meta[rampwellknown.EncodeEd25519X(tk.Public)]
		if m.use != "" && m.use != "verify" {
			return
		}
		entry.keys = append(entry.keys, tk.Public)
		if m.kid != "" {
			entry.rawKIDs[m.kid] = tk.Public
		}
	}); err != nil {
		return cacheEntry{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return entry, nil
}
