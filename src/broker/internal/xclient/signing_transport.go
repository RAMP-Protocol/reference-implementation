package xclient

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
)

// RelayKey holds the Broker's outbound-relay Ed25519 keypair. The relay key
// is a distinct RFC 9421 caller identity, not an agent identity — its kid
// prefix is "broker." so audit logs and resolvers can separate relay hops
// from agent callers sharing the same JWKS.
type RelayKey struct {
	KID     string
	Private ed25519.PrivateKey
}

// relayKeyFile mirrors the JSON written by scripts/gen-broker-relay-key.sh.
type relayKeyFile struct {
	KID        string `json:"kid"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// LoadRelayKey reads the broker-relay private key from path. The file shape is
// the same as deploy/mcp/agent-key.json: base64url-encoded Ed25519 seed +
// derived pubkey + kid. KID must be prefixed "broker." so verifiers can
// distinguish relay signatures from agent signatures sharing the same JWKS.
func LoadRelayKey(path string) (*RelayKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled path
	if err != nil {
		return nil, fmt.Errorf("xclient: read broker relay key %s: %w", path, err)
	}
	var doc relayKeyFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("xclient: decode broker relay key %s: %w", path, err)
	}
	if doc.KID == "" {
		return nil, errors.New("xclient: broker relay key missing kid")
	}
	if !strings.HasPrefix(doc.KID, httpsig.BrokerKeyIDPrefix) {
		return nil, fmt.Errorf("xclient: broker relay kid %q must have broker.<instance>.<rotation> shape", doc.KID)
	}
	seed, err := base64.RawURLEncoding.DecodeString(doc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("xclient: decode private_key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("xclient: private_key length %d != %d", len(seed), ed25519.SeedSize)
	}
	return &RelayKey{KID: doc.KID, Private: ed25519.NewKeyFromSeed(seed)}, nil
}

// signingTransport wraps an inner RoundTripper and stamps RFC 9421 Signature
// + Signature-Input + Content-Digest on every request using the broker-relay
// private key.
type signingTransport struct {
	inner http.RoundTripper
	key   *RelayKey
	ttl   time.Duration
	clk   clock.Clock
}

// NewSigningTransport wraps inner so every request carries a Broker-relay
// RFC 9421 signature. ttl caps the signature lifetime (recommended 30s).
// inner nil defaults to http.DefaultTransport. clk is the time source used
// to stamp the signature created/expires fields; pass clock.System{} in
// production wiring.
func NewSigningTransport(inner http.RoundTripper, key *RelayKey, ttl time.Duration, clk clock.Clock) http.RoundTripper {
	if inner == nil {
		inner = http.DefaultTransport
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if clk == nil {
		clk = clock.System{}
	}
	return &signingTransport{inner: inner, key: key, ttl: ttl, clk: clk}
}

// RoundTrip buffers the outbound body (Connect-Go payloads are small), signs
// the request, and hands it to the inner transport.
func (t *signingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := readBody(req)
	if err != nil {
		return nil, err
	}

	created := t.clk.Now().Unix()
	expires := created + int64(t.ttl.Seconds())
	if err := httpsig.AppendSignatureRAMP(req, body, t.key.KID, t.key.Private, created, expires); err != nil {
		return nil, fmt.Errorf("xclient: sign outbound: %w", err)
	}

	return t.inner.RoundTrip(req)
}

// readBody drains req.Body into memory and restores a fresh reader so the
// inner transport sees the same bytes. Returns an empty slice when the
// request has no body.
func readBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	buf, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("xclient: drain body: %w", err)
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(buf))
	req.ContentLength = int64(len(buf))
	return buf, nil
}
