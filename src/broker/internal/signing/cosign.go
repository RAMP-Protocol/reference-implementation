// Package signing provides the Broker's ed25519 co-signer. The co-signer
// produces a detached signature over each outbound query, transmitted as an
// HTTP header. Per RFC 9421 hop-by-hop forwarding, the ordered set of these
// per-hop request signatures IS the forwarding chain — there is no in-message
// intermediary-hop array.
//
// Ed25519 is the only signing scheme — no HMAC, no shared secrets.
// See `project_edge_signing_strategy` memory for the rationale.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
)

// Header is the HTTP header name carrying the detached Broker signature.
const Header = "X-RAMP-Broker-Signature"

// CoSigner signs outbound Exchange calls on behalf of the Broker.
type CoSigner struct {
	domain   string
	brokerID string
	priv     ed25519.PrivateKey
	clk      clock.Clock
}

// NewCoSigner constructs a CoSigner. priv must be 64 bytes (ed25519 private key).
// clk is the time source consulted for the forwarding-signature timestamp;
// pass clock.System{} in production, a deterministic clock in tests.
func NewCoSigner(domain, brokerID string, priv ed25519.PrivateKey, clk clock.Clock) (*CoSigner, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing: private key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(priv))
	}
	if domain == "" || brokerID == "" {
		return nil, errors.New("signing: domain and broker ID are required")
	}
	if clk == nil {
		clk = clock.System{}
	}
	return &CoSigner{domain: domain, brokerID: brokerID, priv: priv, clk: clk}, nil
}

// Domain returns the broker's domain.
func (c *CoSigner) Domain() string { return c.domain }

// Now returns the signer's clock reading. The WBA publisher uses it to stamp the
// broker's own relay key with an issued-at → bounded not-after window anchored to
// the same clock the rest of the broker runs on (real time in production, a
// deterministic instant under test).
func (c *CoSigner) Now() time.Time { return c.clk.Now() }

// PublicKey returns the broker's ed25519 public key (for well-known publishing).
func (c *CoSigner) PublicKey() ed25519.PublicKey {
	return c.priv.Public().(ed25519.PublicKey)
}

// SignForward produces the Broker's detached forwarding signature over the
// outbound query. Per RFC 9421 hop-by-hop forwarding, this per-hop request
// signature is the Broker's contribution to the forwarding chain — the ordered
// set of such signatures across intermediaries IS the chain, replacing the
// removed in-message hop array. The signature travels in the
// X-RAMP-Broker-Signature header (see xclient); hop depth is counted from the
// signature stack against RequestConstraints.max_hops /
// WellKnownManifest.max_intermediary_hops. SignForward does not mutate req.
func (c *CoSigner) SignForward(req *rampv1.ResourceQuery) (string, error) {
	if req == nil {
		return "", errors.New("signing: nil ResourceQuery")
	}
	now := c.clk.Now()
	payload := fmt.Sprintf("broker:%s|id:%s|query:%s|ts:%d",
		c.domain, c.brokerID, strings.Join(req.GetUris(), ","), now.Unix())
	sig := ed25519.Sign(c.priv, []byte(payload))
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// AllowEphemeralKeyEnv opts the Broker out of the persistent-identity
// requirement, minting a throwaway key at startup instead. Development and CI
// only: the key it produces is the identity the Broker publishes in its own WBA
// directory, so a restart under this flag invalidates every cached copy of it.
const AllowEphemeralKeyEnv = "BROKER_ALLOW_EPHEMERAL_KEY"

// LoadFromEnv reads a base64-encoded ed25519 seed from BROKER_ED25519_SEED
// or, if absent, a PEM file path from BROKER_ED25519_KEY_FILE.
//
// With neither set the Broker refuses to start, mirroring the Exchange's
// signing-key contract: an unset key is a hard error so the binary fails closed
// instead of minting one that invalidates every previously-published copy of the
// Broker's identity on the next restart. Setting AllowEphemeralKeyEnv opts out
// and restores the throwaway-key behaviour for development and CI.
//
// clk is the time source consulted for the intermediary stamp; pass
// clock.System{} in production wiring.
func LoadFromEnv(domain, brokerID string, clk clock.Clock) (*CoSigner, error) {
	if seed := os.Getenv("BROKER_ED25519_SEED"); seed != "" {
		raw, err := base64.RawURLEncoding.DecodeString(seed)
		if err != nil {
			return nil, fmt.Errorf("decode BROKER_ED25519_SEED: %w", err)
		}
		if len(raw) != ed25519.SeedSize {
			return nil, fmt.Errorf("BROKER_ED25519_SEED must decode to %d bytes",
				ed25519.SeedSize)
		}
		priv := ed25519.NewKeyFromSeed(raw)
		return NewCoSigner(domain, brokerID, priv, clk)
	}
	if path := os.Getenv("BROKER_ED25519_KEY_FILE"); path != "" {
		priv, err := loadPEM(path)
		if err != nil {
			return nil, err
		}
		return NewCoSigner(domain, brokerID, priv, clk)
	}
	if !runhttp.EnvOptIn(AllowEphemeralKeyEnv) {
		return nil, fmt.Errorf(
			"no Broker identity key: set BROKER_ED25519_SEED or BROKER_ED25519_KEY_FILE "+
				"(or %s=true for development and CI, which mints a throwaway key that "+
				"changes on every restart)", AllowEphemeralKeyEnv)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	return NewCoSigner(domain, brokerID, priv, clk)
}

func loadPEM(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled path
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block in key file")
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("PEM payload must be %d bytes for ed25519 private key",
			ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(block.Bytes), nil
}
