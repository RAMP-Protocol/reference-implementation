package httpsig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
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

// loadKeysFile parses a JWKS-style JSON document (served at
// /.well-known/ramp.json) and pushes every Ed25519 entry into resolver.
// Malformed entries are skipped.
func loadKeysFile(resolver *StaticResolver, path string) error {
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled path
	if err != nil {
		return fmt.Errorf("httpsig: read %s: %w", path, err)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("httpsig: decode %s: %w", path, err)
	}
	if len(doc.Keys) == 0 {
		return errors.New("httpsig: no keys loaded (empty or malformed JWKS)")
	}
	for _, k := range doc.Keys {
		if k.Kid == "" || k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			continue
		}
		if len(raw) != ed25519.PublicKeySize {
			continue
		}
		resolver.Put(k.Kid, ed25519.PublicKey(raw))
	}
	return nil
}
