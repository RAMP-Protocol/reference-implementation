package xclient

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampauth"
)

// RelayKey holds the Broker's outbound-relay Ed25519 keypair. After the WBA
// split the relay's RFC 9421 keyid is the RFC 7638 thumbprint of its public key
// (proof of key possession); its identity as a relay is the broker's directory
// origin, carried in the covered Signature-Agent header, and the DB
// requester_type discriminator — not a kid prefix.
type RelayKey struct {
	// KeyID is the RFC 7638 thumbprint of Private's public key — the RFC 9421
	// keyid the relay signs with.
	KeyID   string
	Private ed25519.PrivateKey
}

// relayKeyFile mirrors the JSON written by scripts/gen-broker-relay-key.sh.
// A legacy kid field is ignored: the keyid is derived from the public key.
type relayKeyFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// LoadRelayKey reads the broker-relay private key from path. The file shape is
// the same as deploy/mcp/agent-key.json: a base64url-encoded Ed25519 seed (+
// derived pubkey). The relay's keyid is the RFC 7638 thumbprint of the derived
// public key; any kid in the file is ignored.
func LoadRelayKey(path string) (*RelayKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled path
	if err != nil {
		return nil, fmt.Errorf("xclient: read broker relay key %s: %w", path, err)
	}
	var doc relayKeyFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("xclient: decode broker relay key %s: %w", path, err)
	}
	seed, err := base64.RawURLEncoding.DecodeString(doc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("xclient: decode private_key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("xclient: private_key length %d != %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	keyid, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("xclient: relay key thumbprint: %w", err)
	}
	return &RelayKey{KeyID: keyid, Private: priv}, nil
}

// NewSigningTransport wraps inner so every outbound Broker→Exchange /ramp.*
// request carries a Broker-relay RFC 9421 signature. It composes the SDK's
// signing RoundTripper (sdk/go/core.NewSigningTransport) so the signed wire
// bytes — covered components, content-digest, Signature-Input, and the
// signature — are identical to every other RAMP client the Exchange's verifier
// mirrors. The relay is an always-append caller (WithAppendSigner): a
// broker-originated call is signed as a plain sig1 and a relayed call appends a
// chain-linked sigN+1 over the agent's existing signature. A MonotonicWindow
// keeps identical back-to-back requests from colliding in the Exchange's replay
// store. directory is the broker's own directory origin, published in the
// covered Signature-Agent header (set only when the request does not already
// carry one, so a relayed agent's Signature-Agent is preserved). ttl caps the
// signature lifetime (recommended 30s); inner nil defaults to
// http.DefaultTransport; clk is the time source (pass clock.System{} in
// production wiring, nil defaults to it).
func NewSigningTransport(
	inner http.RoundTripper, key *RelayKey, directory string, ttl time.Duration, clk clock.Clock,
) (http.RoundTripper, error) {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if clk == nil {
		clk = clock.System{}
	}
	signer, err := helpers.NewEd25519Signer(key.KeyID, key.Private)
	if err != nil {
		return nil, fmt.Errorf("xclient: build relay signer: %w", err)
	}
	return core.NewSigningTransport(signer, inner,
		core.WithSignPredicate(rampauth.IsRAMPProcedure),
		core.WithSignatureAgent(directory),
		core.WithWindow(core.MonotonicWindow(clk.Now, ttl)),
		core.WithAppendSigner(),
	), nil
}
