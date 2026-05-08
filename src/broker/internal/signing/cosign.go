// Package signing provides the Broker's ed25519 co-signer. The co-signer
// marks the Broker as the current intermediary on outbound queries and
// produces a detached signature suitable for transmission as an HTTP header.
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
	"time"

	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Header is the HTTP header name carrying the detached Broker signature.
const Header = "X-RAMP-Broker-Signature"

// CoSigner signs outbound Exchange calls on behalf of the Broker.
type CoSigner struct {
	domain   string
	brokerID string
	priv     ed25519.PrivateKey
}

// NewCoSigner constructs a CoSigner. priv must be 64 bytes (ed25519 private key).
func NewCoSigner(domain, brokerID string, priv ed25519.PrivateKey) (*CoSigner, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing: private key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(priv))
	}
	if domain == "" || brokerID == "" {
		return nil, errors.New("signing: domain and broker ID are required")
	}
	return &CoSigner{domain: domain, brokerID: brokerID, priv: priv}, nil
}

// Domain returns the broker's domain.
func (c *CoSigner) Domain() string { return c.domain }

// PublicKey returns the broker's ed25519 public key (for well-known publishing).
func (c *CoSigner) PublicKey() ed25519.PublicKey {
	return c.priv.Public().(ed25519.PublicKey)
}

// StampIntermediary appends the Broker to the request's intermediary chain.
// Returns the payload signed for detached HTTP header transmission.
func (c *CoSigner) StampIntermediary(req *rampv1.ResourceQuery) (string, error) {
	if req == nil {
		return "", errors.New("signing: nil ResourceQuery")
	}
	now := time.Now().UTC()
	req.Intermediaries = append(req.Intermediaries, &rampv1.IntermediaryHop{
		Domain:      c.domain,
		Id:          c.brokerID,
		ForwardedAt: timestamppb.New(now),
	})
	payload := fmt.Sprintf("broker:%s|id:%s|query:%s|ts:%d",
		c.domain, c.brokerID, req.GetId(), now.Unix())
	sig := ed25519.Sign(c.priv, []byte(payload))
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// LoadFromEnv reads a base64-encoded ed25519 seed from BROKER_ED25519_SEED
// or, if absent, a PEM file path from BROKER_ED25519_KEY_FILE. Generates an
// ephemeral key pair when neither is set (demo-friendly).
func LoadFromEnv(domain, brokerID string) (*CoSigner, error) {
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
		return NewCoSigner(domain, brokerID, priv)
	}
	if path := os.Getenv("BROKER_ED25519_KEY_FILE"); path != "" {
		priv, err := loadPEM(path)
		if err != nil {
			return nil, err
		}
		return NewCoSigner(domain, brokerID, priv)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	return NewCoSigner(domain, brokerID, priv)
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
