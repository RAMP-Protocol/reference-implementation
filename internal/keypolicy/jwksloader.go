package keypolicy

import (
	"encoding/json"
	"fmt"
)

// jwksFileDoc is the minimal JWKS envelope LoadJWKSBytes decodes: a "keys"
// array whose members are handed to DecodeTimedJWK verbatim. Each member is
// kept as raw JSON so its standard JWK parameters (kty/crv/x) decode
// off-the-shelf via go-jose while the optional RAMP validity window
// (not_before/not_after, RFC 3339) is layered on top per entry. A document MAY
// carry richer members (use/alg, or served-directory metadata); a loader that
// must retain those keeps its own struct for that purpose and drives its trust
// maps through LoadJWKSBytes over the same bytes.
type jwksFileDoc struct {
	Keys []json.RawMessage `json:"keys"`
}

// LoadJWKSBytes parses a JWKS-style JSON document and invokes put once per
// well-formed Ed25519 entry — each decoded, thumbprinted, and window-validated
// through DecodeTimedJWK. It is the fail-closed JWKS decode loop shared by
// loaders of network-fetched key sets: a malformed entry (bad kty/crv,
// undecodable x, or an unparseable window) is SKIPPED so one bad entry cannot
// take the whole set down. Returns an error only on a JSON-decode failure; an
// empty or all-malformed document yields zero puts and no error — the caller
// decides whether zero keys is fatal.
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
