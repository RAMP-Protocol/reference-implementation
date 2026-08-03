package directory

import (
	"encoding/json"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// BuildWBA assembles an agent's Web Bot Auth directory — a real RFC 7517 JWK Set —
// from its keys, in the order given. Order is load-bearing: keystore.List returns
// newest-first, and a WBA consumer resolving an identity without a known thumbprint
// takes the first active key in document order, so this function must preserve it.
//
// go-jose owns the standard JWK members (kty/crv/x/use/alg, derived from each
// ed25519 public key). The RAMP validity window (not_before / not_after) has no
// field in go-jose's JSONWebKey, so it is spliced onto each key as an extension
// member; a generic verifier ignores it, and the shared ramp-wba-directory.json
// schema — which requires it — validates the result. Keys carry no kid: identity is
// the RFC 7638 thumbprint, so directory entries are deduped by the JWK `x`.
//
// An empty key set is a build error: the schema requires at least one key, and the
// caller should serve 404 for an agent with no directory rather than an empty one.
func BuildWBA(keys []keystore.Key, revocationURL string) ([]byte, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("directory: BuildWBA: a WBA directory needs at least one key")
	}

	entries := make([]json.RawMessage, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		entry, x, err := encodeJWK(k)
		if err != nil {
			return nil, fmt.Errorf("directory: BuildWBA: %w", err)
		}
		// Dedup on the `x` actually emitted into the document (go-jose's), not a
		// separately-derived value, so the key can never diverge from what dedup sees.
		if _, dup := seen[x]; dup {
			continue
		}
		seen[x] = struct{}{}
		entries = append(entries, entry)
	}

	doc := map[string]any{"keys": entries}
	if revocationURL != "" {
		doc["revocation_url"] = revocationURL
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("directory: BuildWBA: %w", err)
	}
	if err := rampwellknown.ValidateWBA(raw); err != nil {
		return nil, fmt.Errorf("directory: BuildWBA: %w", err)
	}
	return raw, nil
}

// encodeJWK marshals one key as a JWK via go-jose, then splices the RAMP validity
// window members go-jose has no field for. It also returns the emitted `x` member so
// the caller can dedup on exactly what the document carries. The window is formatted
// as RFC 3339 UTC to match the JWK not_before/not_after the schema expects and the
// value the keystore stored.
func encodeJWK(k keystore.Key) (json.RawMessage, string, error) {
	jwk := jose.JSONWebKey{Key: k.Public, Use: "sig", Algorithm: "EdDSA"}
	raw, err := jwk.MarshalJSON()
	if err != nil {
		return nil, "", fmt.Errorf("marshal jwk: %w", err)
	}
	members := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, "", fmt.Errorf("decode jwk: %w", err)
	}
	var x string
	if err := json.Unmarshal(members["x"], &x); err != nil {
		return nil, "", fmt.Errorf("decode jwk x: %w", err)
	}
	if members["not_before"], err = json.Marshal(k.Window.NotBefore.UTC().Format(time.RFC3339)); err != nil {
		return nil, "", fmt.Errorf("encode not_before: %w", err)
	}
	if members["not_after"], err = json.Marshal(k.Window.NotAfter.UTC().Format(time.RFC3339)); err != nil {
		return nil, "", fmt.Errorf("encode not_after: %w", err)
	}
	spliced, err := json.Marshal(members)
	if err != nil {
		return nil, "", fmt.Errorf("re-marshal jwk: %w", err)
	}
	return spliced, x, nil
}
