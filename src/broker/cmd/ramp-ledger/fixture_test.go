package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceview"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// The fixture builds a chain whose signatures are REAL: two Ed25519 keypairs
// are generated per test and the canonical bytes are produced by the protocol
// SDK's own helpers. A fixture with hand-written signature strings would let
// every verification test pass against a verifier that returns true, which is
// the one outcome these tests exist to rule out.

const (
	fixtureOfferID     = "urn:ramp:res:stoa-press:article-4711"
	fixtureTx          = "01JZ8QW2K3M4N5P6Q7R8S9T0V1"
	fixtureTenant      = "stoa-press"
	fixtureReqID       = "https://agents.example"
	fixtureReqHost     = "agents.example"
	fixtureDomain      = "agents.example"
	fixtureIdempotency = "idem-2f6c1a9e"
	fixtureSignedURL   = "https://cdn.publisher.example/a/4711?exp=1786000000&kid=abc&sig=deadbeef"
)

type fixture struct {
	Sources     Sources
	ExchangeKey ed25519.PrivateKey
	AgentKey    ed25519.PrivateKey
	URLDigest   string
	Now         time.Time
}

// newFixture builds a complete, internally consistent chain: the Exchange
// signed the offer, the agent signed an acceptance naming that offer, the
// Broker recorded offering it, and the edge recorded delivering the URL whose
// digest the Exchange stored.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

	exchangePub, exchangePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate exchange key: %v", err)
	}
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}

	offer := &rampv1.Offer{OfferId: fixtureOfferID, Exchange: "exchange.example"}
	offerCanonical, err := helpers.CanonicalOfferBytes(offer)
	if err != nil {
		t.Fatalf("canonical offer bytes: %v", err)
	}
	offerSig := hex.EncodeToString(ed25519.Sign(exchangePriv, offerCanonical))
	offer.Signature = offerSig

	requester := &rampv1.Requester{Id: fixtureReqID, Domain: fixtureDomain}
	acceptanceCanonical, err := helpers.CanonicalAcceptanceBytes(offer, requester, fixtureIdempotency)
	if err != nil {
		t.Fatalf("canonical acceptance bytes: %v", err)
	}
	acceptanceSig := hex.EncodeToString(ed25519.Sign(agentPriv, acceptanceCanonical))

	digest := sha256.Sum256([]byte(fixtureSignedURL))
	expiry := now.Add(15 * time.Minute)

	return &fixture{
		ExchangeKey: exchangePriv,
		AgentKey:    agentPriv,
		URLDigest:   hex.EncodeToString(digest[:]),
		Now:         now,
		Sources: Sources{
			Evidence: &evidenceview.Evidence{
				TransactionID:                     fixtureTx,
				TenantID:                          fixtureTenant,
				OfferID:                           fixtureOfferID,
				OfferCanonicalBytes:               offerCanonical,
				OfferSig:                          offerSig,
				OfferSigAlgorithm:                 "EdDSA",
				ExchangeSigningPublicKey:          exchangePub,
				AgentAcceptanceSignature:          acceptanceSig,
				AgentAcceptanceCanonicalBytes:     acceptanceCanonical,
				AgentAcceptanceSignatureAlgorithm: "EdDSA",
				RequesterID:                       fixtureReqID,
				RequesterDomain:                   fixtureDomain,
				RequestIdempotencyKey:             fixtureIdempotency,
				AgentPublicKey:                    agentPub,
				CreatedAt:                         now,
			},
			Transaction: &evidenceview.TransactionState{
				// The derived per-item key: the signed request key with the
				// offer id appended, which is how the Exchange writes it.
				IdempotencyKey:  fixtureIdempotency + ":" + fixtureOfferID,
				SignedURLExpiry: &expiry,
				SignedURLHash:   digest[:],
			},
			Obligation: &evidenceview.ObligationState{
				State:     "PENDING",
				WindowEnd: now.Add(24 * time.Hour),
				CreatedAt: now,
			},
			Selection: &repo.SelectionLogEntry{
				LogID:     "sel-01JZ8Q",
				RequestID: "req-8f2a",
				AgentID:   fixtureReqHost,
				Query:     "ancient greek philosophy",
				CandidateOffers: []repo.CandidateInfo{
					{OfferID: "urn:ramp:res:other:1", ExchangeID: "exchange.example", UnitCost: "0.02", TrustLevel: "DIRECT"},
					{OfferID: fixtureOfferID, ExchangeID: "exchange.example", UnitCost: "0.05", TrustLevel: "DIRECT"},
				},
				CreatedAt: now.Add(-30 * time.Second),
			},
			Delivery: &DeliveryRecord{
				URLHash:   hex.EncodeToString(digest[:]),
				Outcome:   "cdn-origin-fetch",
				Kid:       "abc",
				Method:    "GET",
				Path:      "/a/4711",
				RequestID: "edge-req-01",
				Region:    "eu-central-1",
			},
		},
	}
}

// assertionByName finds one assertion so a test can name the check it is about
// rather than depending on the order BuildAssertions happens to use.
func assertionByName(t *testing.T, assertions []Assertion, substring string) Assertion {
	t.Helper()
	for _, a := range assertions {
		if strings.Contains(a.Name, substring) {
			return a
		}
	}
	t.Fatalf("no assertion whose name contains %q; have %v", substring, names(assertions))
	return Assertion{}
}

func names(assertions []Assertion) []string {
	out := make([]string, 0, len(assertions))
	for _, a := range assertions {
		out = append(out, a.Name)
	}
	return out
}
