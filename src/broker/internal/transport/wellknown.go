package transport

import (
	"encoding/base64"
	"net/http"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
)

// AgentManifest is the JSON body published at /.well-known/ramp-agent.json.
// The Exchange (or any verifier) fetches this to confirm the Broker's public
// key before accepting its detached intermediary signatures.
type AgentManifest struct {
	Ver     string     `json:"ver"`
	ID      string     `json:"id"`
	Domain  string     `json:"domain"`
	Keys    []AgentJWK `json:"keys"`
	Purpose []string   `json:"purpose,omitempty"`
}

// AgentJWK is a minimal JWKS-style entry limited to Ed25519.
type AgentJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Kid string `json:"kid"`
}

// WellKnownHandler serves GET /.well-known/ramp-agent.json.
type WellKnownHandler struct {
	signer *signing.CoSigner
	id     string
}

// NewWellKnownHandler constructs the well-known handler.
func NewWellKnownHandler(signer *signing.CoSigner, brokerID string) *WellKnownHandler {
	return &WellKnownHandler{signer: signer, id: brokerID}
}

// ServeHTTP writes the ramp-agent.json payload.
func (h *WellKnownHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	pub := h.signer.PublicKey()
	manifest := AgentManifest{
		Ver:     "0.3",
		ID:      h.id,
		Domain:  h.signer.Domain(),
		Purpose: []string{"orchestrator_signature"},
		Keys: []AgentJWK{{
			Kty: "OKP",
			Crv: "Ed25519",
			Use: "sig",
			Alg: "EdDSA",
			X:   base64.RawURLEncoding.EncodeToString(pub),
			Kid: h.id + "-ed25519",
		}},
	}
	writeJSON(w, http.StatusOK, manifest)
}
