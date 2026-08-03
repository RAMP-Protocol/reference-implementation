// Package directory builds the two documents an agent publishes on its per-user
// subdomain: the Web Bot Auth key directory (a pure RFC 7517 JWK Set at
// /.well-known/http-message-signatures-directory) and the Signature Agent Card
// (a small JSON description at /.well-known/signature-agent-card.json).
//
// The package is deliberately pure — it depends on the key domain type
// (keystore.Key) and the shared schema guard, but on no I/O (no Vault, no
// database, no HTTP). Persistence of card metadata lives in the repo package;
// serving lives in the transport package. Keeping the builders pure is what lets
// them be unit-tested without a container.
//
// # Why the WBA directory is not the RAMP proto
//
// The directory is a standards-owned artifact: any Web Bot Auth verifier on the
// open internet reads it, and those verifiers implement RFC 7517 / the WBA draft,
// not RAMP's protobuf. So it is assembled with go-jose as a real JWK Set rather
// than marshalled from the rampv1.WBAFile proto — the identity core stays
// RAMP-agnostic (ADR-017 D1). The only RAMP-specific members are the per-key
// not_before / not_after validity bounds, which a generic verifier ignores; the
// shared ramp-wba-directory.json schema still validates the result.
package directory

import "context"

// CardPath is the request path the Signature Agent Card is served at. There is no
// registered Web Bot Auth path for the card yet (the standard is a moving IETF
// draft), so this is RAMP's chosen home; keeping it in one constant makes a future
// change a single edit. The "signature-" prefix disambiguates from Google A2A's
// /.well-known/agent-card.json, a different document with the same short name.
const CardPath = "/.well-known/signature-agent-card.json"

// Media types for the published documents. The WBA directory is a JWK Set; the
// card and the revocation list are plain JSON.
const (
	WBAMediaType        = "application/jwk-set+json"
	CardMediaType       = "application/json"
	RevocationMediaType = "application/json"
)

// Card is the Signature Agent Card: a self-asserted description of an agent. The
// field names follow ADR-017 D7 (client_name / client_uri / contacts / purpose),
// which in turn reuse OAuth Dynamic Client Registration (RFC 7591) names. Every
// field is treated as possibly-absent — the card is self-asserted and the WBA
// draft is not frozen, so the struct stays thin and tolerant.
type Card struct {
	ClientName string   `json:"client_name"`
	ClientURI  string   `json:"client_uri"`
	Contacts   []string `json:"contacts,omitempty"`
	Purpose    string   `json:"purpose,omitempty"`
}

// CardReader is the getter the serving layer depends on (interface segregation):
// it resolves one agent's card metadata by its durable subdomain identity. The
// concrete implementation lives in the repo package over Postgres. A subdomain
// with no card row yields ErrCardNotFound, which the handler maps to 404 — an
// agent may hold keys before its card metadata is written.
type CardReader interface {
	BySubdomain(ctx context.Context, subdomain string) (Card, error)
}
