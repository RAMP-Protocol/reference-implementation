package httpsig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// WireupOptions collects the bits main.go needs to wire an httpsig middleware
// stack. Both Exchange and Broker use this helper to keep the per-service
// main.go changes small.
type WireupOptions struct {
	// KeysFile is a JWKS-style JSON file path for the StaticResolver seed.
	// Empty means start with an empty resolver.
	KeysFile string
	// Redis, when non-nil, backs the ReplayStore. A nil client falls back to
	// a MemoryReplayStore (adequate for single-instance demos and tests).
	Redis *redis.Client
	// RedisPrefix namespaces the replay keys. Default "httpsig:replay:<service>".
	RedisPrefix string
}

// Wireup constructs a (KeyResolver, ReplayStore) pair per opts.
func Wireup(opts WireupOptions) (*StaticResolver, ReplayStore, error) {
	resolver := NewStaticResolver(nil)
	if opts.KeysFile != "" {
		if err := loadKeysFile(resolver, opts.KeysFile); err != nil {
			return nil, nil, err
		}
	}
	var replay ReplayStore
	if opts.Redis != nil {
		replay = NewRedisReplayStore(opts.Redis, opts.RedisPrefix)
	} else {
		replay = NewMemoryReplayStore(clock.System{}.Now)
	}
	return resolver, replay, nil
}

// keyFileEntry is one entry of the static bootstrap JWKS. Beyond the standard
// OKP/Ed25519 JWK members it MAY carry a RAMP validity window (not_before/
// not_after, RFC 3339); an entry that carries one is loaded with the window
// enforced so a statically-listed key is held to the same not_before/not_after
// gate as a directory-published one.
type keyFileEntry struct {
	Kty       string `json:"kty"`
	Crv       string `json:"crv"`
	X         string `json:"x"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

type keyFileDoc struct {
	Keys []keyFileEntry `json:"keys"`
}

// loadKeysFile parses the static bootstrap JWKS (RAMP_KEYS_FILE) and pushes every
// Ed25519 entry into resolver, keyed by RFC 7638 thumbprint (the keyid after the
// WBA split — kid is gone). An entry carrying a not_before/not_after window is
// loaded with that window enforced; an entry without one is unbounded. Malformed
// entries (bad kty/crv, undecodable x, unparseable window) are skipped.
func loadKeysFile(resolver *StaticResolver, path string) error {
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled path
	if err != nil {
		return fmt.Errorf("httpsig: read %s: %w", path, err)
	}
	var doc keyFileDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("httpsig: decode %s: %w", path, err)
	}
	loaded := 0
	for _, e := range doc.Keys {
		pub, decErr := rampwellknown.DecodeJWKEd25519(e.Kty, e.Crv, e.X)
		if decErr != nil {
			continue
		}
		tp, tpErr := helpers.Thumbprint(pub)
		if tpErr != nil {
			continue
		}
		nb, na, ok := parseWindow(e.NotBefore, e.NotAfter)
		if !ok {
			continue // a present-but-unparseable window is a malformed entry
		}
		resolver.PutTimed(tp, pub, nb, na)
		loaded++
	}
	if loaded == 0 {
		return errors.New("httpsig: no keys loaded (empty or malformed JWKS)")
	}
	return nil
}

// parseWindow parses optional RFC 3339 not_before/not_after bounds. An empty
// string is unbounded (zero time). A present-but-unparseable bound reports
// ok=false so the caller skips the malformed entry rather than treating a typo
// as unbounded — which would make an expired key silently always-valid.
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
