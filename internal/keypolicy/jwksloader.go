package keypolicy

import (
	"encoding/json"
	"fmt"
	"os"
)

// jwksFileDoc is the minimal JWKS envelope a static key-file loader decodes: a
// "keys" array whose members are handed to DecodeTimedJWK verbatim. Each member
// is kept as raw JSON so its standard JWK parameters (kty/crv/x) decode
// off-the-shelf via go-jose while the optional RAMP validity window
// (not_before/not_after, RFC 3339) is layered on top per entry. A file MAY carry
// richer members (use/alg, or served-directory metadata); a loader that must
// retain those keeps its own struct for that purpose and drives its trust maps
// through LoadJWKSBytes over the same bytes.
type jwksFileDoc struct {
	Keys []json.RawMessage `json:"keys"`
}

// LoadJWKSFile reads a JWKS-style JSON document at path and invokes put once per
// well-formed Ed25519 entry — each decoded, thumbprinted, and window-validated
// through DecodeTimedJWK. It is the fail-closed static-key-file loader the Broker
// and Exchange share: a malformed entry (bad kty/crv, undecodable x, or an
// unparseable window) is SKIPPED so one typo cannot wedge a service at boot.
// Returns an error only on a read or JSON-decode failure; an empty or
// all-malformed file yields zero puts and no error — the caller decides whether
// zero keys is fatal.
func LoadJWKSFile(path string, put func(TimedKey)) error {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-controlled path
	if err != nil {
		return fmt.Errorf("keypolicy: read jwks %s: %w", path, err)
	}
	return LoadJWKSBytes(raw, put)
}

// LoadJWKSBytes is LoadJWKSFile over already-read bytes: the JWKS parse plus the
// per-entry fail-closed decode loop. For callers that hold the JWKS bytes (a
// registry seeded from memory) or that also unmarshal the same bytes into a
// richer served-directory document.
func LoadJWKSBytes(raw []byte, put func(TimedKey)) error {
	var doc jwksFileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("keypolicy: decode jwks: %w", err)
	}
	for _, entry := range doc.Keys {
		if tk, ok := DecodeTimedJWK(entry); ok {
			put(tk)
		}
	}
	return nil
}
