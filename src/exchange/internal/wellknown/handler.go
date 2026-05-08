// Package wellknown serves the public discovery surfaces of the Exchange:
// the marketplace manifest document and the JWKS endpoint carrying the
// Ed25519 public key used to verify offer signatures.
package wellknown

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// Manifest mirrors the subset of ExchangeManifest the scrappy demo needs for
// external discovery. Only fields relevant to offer verification and RPC
// routing are populated.
type Manifest struct {
	Exchange           string   `json:"exchange"`
	Version            string   `json:"version"`
	SupportedProfiles  []string `json:"supported_profiles,omitempty"`
	ExchangeServiceURL string   `json:"exchange_service_url"`
	CatalogServiceURL  string   `json:"catalog_service_url"`
	JWKSURL            string   `json:"jwks_url"`
	BaseCurrency       string   `json:"base_currency"`
}

// Handler carries the static manifest + a reference to the signing public
// key so JWKS refreshes when the server restarts with a rotated key.
type Handler struct {
	manifest  Manifest
	publicKey ed25519.PublicKey
	keyID     string
}

// New constructs a Handler.
func New(manifest Manifest, pub ed25519.PublicKey, keyID string) *Handler {
	return &Handler{manifest: manifest, publicKey: pub, keyID: keyID}
}

// RegisterRoutes mounts the manifest and JWKS routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/ramp-marketplace.json", h.serveManifest)
	mux.HandleFunc("GET /marketplace/v1/keys", h.serveJWKS)
}

func (h *Handler) serveManifest(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.manifest)
}

// jwk is the minimum OKP JWK body for an Ed25519 public key (RFC 8037).
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg"`
	Use string `json:"use,omitempty"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func (h *Handler) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	resp := jwks{Keys: []jwk{{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(h.publicKey),
		Kid: h.keyID,
		Alg: "EdDSA",
		Use: "sig",
	}}}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	_ = json.NewEncoder(w).Encode(resp)
}
