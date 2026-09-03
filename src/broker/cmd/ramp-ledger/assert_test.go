package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

func TestBuildAssertions_intactChainHoldsEverywhere(t *testing.T) {
	f := newFixture(t)

	for _, a := range BuildAssertions(f.Sources) {
		if !a.OK {
			t.Errorf("assertion %q failed on an intact chain: %s", a.Name, a.Detail)
		}
	}
}

// Each case below breaks the chain in one specific way and names the ONE
// assertion that must catch it. A tampering that no assertion catches is a hole
// in the evidence, so every case also checks that the intact chain passed the
// same check — otherwise a permanently-failing assertion would look like a
// working detector.
func TestBuildAssertions_tamperingIsCaught(t *testing.T) {
	cases := []struct {
		name   string
		check  string
		tamper func(t *testing.T, f *fixture)
	}{
		{
			name:  "offer signed by a different key",
			check: "Exchange offer signature",
			tamper: func(t *testing.T, f *fixture) {
				_, other, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generate: %v", err)
				}
				f.Sources.Evidence.OfferSig = hex.EncodeToString(
					ed25519.Sign(other, f.Sources.Evidence.OfferCanonicalBytes))
			},
		},
		{
			name:  "offer bytes edited after signing",
			check: "Exchange offer signature",
			tamper: func(_ *testing.T, f *fixture) {
				bytes := f.Sources.Evidence.OfferCanonicalBytes
				edited := make([]byte, len(bytes))
				copy(edited, bytes)
				edited[0] ^= 0xFF
				f.Sources.Evidence.OfferCanonicalBytes = edited
			},
		},
		{
			name:  "acceptance signed by a different agent",
			check: "Agent acceptance signature",
			tamper: func(t *testing.T, f *fixture) {
				_, other, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generate: %v", err)
				}
				f.Sources.Evidence.AgentAcceptanceSignature = hex.EncodeToString(
					ed25519.Sign(other, f.Sources.Evidence.AgentAcceptanceCanonicalBytes))
			},
		},
		{
			// The splice: a genuine acceptance, correctly signed, but for a
			// DIFFERENT offer. Both signature checks still pass, because both
			// signatures are real. Only comparing the signed members catches it.
			name:  "genuine acceptance spliced onto another offer",
			check: "Acceptance binds this exact agreement",
			tamper: func(t *testing.T, f *fixture) {
				other := &rampv1.Offer{OfferId: "urn:ramp:res:other:9", Exchange: "exchange.example"}
				canonical, err := helpers.CanonicalOfferBytes(other)
				if err != nil {
					t.Fatalf("canonical offer: %v", err)
				}
				other.Signature = hex.EncodeToString(ed25519.Sign(f.ExchangeKey, canonical))
				acceptance, err := helpers.CanonicalAcceptanceBytes(
					other, &rampv1.Requester{Id: fixtureReqID, Domain: fixtureDomain}, fixtureIdempotency)
				if err != nil {
					t.Fatalf("canonical acceptance: %v", err)
				}
				f.Sources.Evidence.AgentAcceptanceCanonicalBytes = acceptance
				f.Sources.Evidence.AgentAcceptanceSignature = hex.EncodeToString(
					ed25519.Sign(f.AgentKey, acceptance))
			},
		},
		{
			// The fabrication the offer_sig comparison alone cannot see: one
			// genuine acceptance, written into a row for a DIFFERENT request.
			// Every signature verifies; only the idempotency-key member differs.
			name:  "one acceptance reused for a second request",
			check: "Acceptance binds this exact agreement",
			tamper: func(_ *testing.T, f *fixture) {
				f.Sources.Evidence.RequestIdempotencyKey = "idem-a-different-request"
			},
		},
		{
			name:  "row claims a requester the acceptance did not name",
			check: "Acceptance binds this exact agreement",
			tamper: func(_ *testing.T, f *fixture) {
				f.Sources.Evidence.RequesterID = "https://impostor.example"
			},
		},
		{
			name:  "transaction-log key does not derive from the signed key",
			check: "Transaction-log key derives",
			tamper: func(_ *testing.T, f *fixture) {
				f.Sources.Transaction.IdempotencyKey = fixtureIdempotency + ":urn:ramp:res:other:9"
			},
		},
		{
			name:  "Broker offered a different set of offers",
			check: "Broker independently recorded",
			tamper: func(_ *testing.T, f *fixture) {
				f.Sources.Selection.CandidateOffers = []repo.CandidateInfo{
					{OfferID: "urn:ramp:res:other:1"},
				}
			},
		},
		{
			name:  "Broker's decision belongs to a different agent",
			check: "Broker's agent and the signing agent",
			tamper: func(_ *testing.T, f *fixture) {
				f.Sources.Selection.AgentID = "someone-else.example"
			},
		},
		{
			name:  "edge served a URL the Exchange never minted",
			check: "Delivered URL is the URL the Exchange minted",
			tamper: func(_ *testing.T, f *fixture) {
				f.Sources.Delivery.URLHash = strings.Repeat("a", 64)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intact := newFixture(t)
			if a := assertionByName(t, BuildAssertions(intact.Sources), tc.check); !a.OK {
				t.Fatalf("assertion %q already fails before tampering: %s", a.Name, a.Detail)
			}

			f := newFixture(t)
			tc.tamper(t, f)

			got := assertionByName(t, BuildAssertions(f.Sources), tc.check)
			if got.OK {
				t.Errorf("assertion %q accepted a tampered chain: %s", got.Name, got.Detail)
			}
		})
	}
}

// The signed Requester.id is a directory URI; the Broker keys its audit on the
// canonical host. Plain string equality between the two would fail on a chain
// that is entirely genuine, so the normalization is the behavior under test.
func TestBrokerSawThisAgent_normalizesTheDirectoryURI(t *testing.T) {
	for _, spelling := range []string{
		"https://agents.example",
		"http://agents.example",
		"https://AGENTS.example",
		"https://agents.example/",
	} {
		t.Run(spelling, func(t *testing.T) {
			f := newFixture(t)
			f.Sources.Evidence.RequesterID = spelling
			// The acceptance must be re-signed: requester_id is one of the four
			// members it covers, so editing the row alone would fail a
			// different assertion and prove nothing about this one.
			resignAcceptance(t, f, spelling)

			if a := assertionByName(t, BuildAssertions(f.Sources), "Broker's agent"); !a.OK {
				t.Errorf("%q should normalize to the Broker's %q: %s", spelling, fixtureReqHost, a.Detail)
			}
		})
	}
}

// A signature carrying a case-varied hex spelling of the same offer_sig is
// still the same signature. The protocol accepts either case on the wire, so
// the member comparison must not reject one because the Exchange happened to
// store the other.
func TestAcceptanceBinds_hexCaseDoesNotMatter(t *testing.T) {
	f := newFixture(t)
	f.Sources.Evidence.OfferSig = strings.ToUpper(f.Sources.Evidence.OfferSig)

	if a := assertionByName(t, BuildAssertions(f.Sources), "Acceptance binds"); !a.OK {
		t.Errorf("upper-case offer_sig should still bind: %s", a.Detail)
	}
}

// A leg that could not be read is not a leg that failed. The assertion must say
// so and must not claim the chain is broken.
func TestBuildAssertions_absentLegsReportTheReasonNotAFailure(t *testing.T) {
	f := newFixture(t)
	f.Sources.Selection = nil
	f.Sources.SelectionAbsence = "not read: no Broker database URL configured"
	f.Sources.Delivery = nil
	f.Sources.DeliveryAbsence = "no delivery recorded: CloudWatch had nothing yet"

	assertions := BuildAssertions(f.Sources)
	for _, name := range []string{"Broker independently recorded", "Broker's agent", "Delivered URL"} {
		a := assertionByName(t, assertions, name)
		if a.OK {
			t.Errorf("assertion %q claims to hold with its source absent", a.Name)
		}
		// Unchecked, NOT failed. A source that was never read says nothing
		// about the chain, and reporting it as a failure would make an
		// operator without a tunnel think the evidence is broken.
		if !a.Unchecked {
			t.Errorf("assertion %q reports an unread source as a failed check", a.Name)
		}
		if !strings.Contains(a.Detail, "not read") && !strings.Contains(a.Detail, "no delivery recorded") {
			t.Errorf("assertion %q should carry the absence reason, got %q", a.Name, a.Detail)
		}
	}
	// The Exchange-side proofs need no other party, so they must still hold.
	for _, name := range []string{"Exchange offer signature", "Agent acceptance signature", "Acceptance binds"} {
		if a := assertionByName(t, assertions, name); !a.OK {
			t.Errorf("offline check %q should not depend on the other legs: %s", a.Name, a.Detail)
		}
	}
}

func TestEd25519Assertion_rejectsMalformedInputs(t *testing.T) {
	f := newFixture(t)

	t.Run("signature is not hex", func(t *testing.T) {
		s := newFixture(t).Sources
		s.Evidence.OfferSig = strings.Repeat("z", 128)
		if a := assertionByName(t, BuildAssertions(s), "Exchange offer signature"); a.OK {
			t.Error("a non-hex signature was accepted")
		}
	})

	t.Run("public key is the wrong length", func(t *testing.T) {
		s := newFixture(t).Sources
		s.Evidence.ExchangeSigningPublicKey = f.Sources.Evidence.ExchangeSigningPublicKey[:16]
		if a := assertionByName(t, BuildAssertions(s), "Exchange offer signature"); a.OK {
			t.Error("a truncated public key was accepted")
		}
	})

	t.Run("signed bytes are not a readable payload", func(t *testing.T) {
		s := newFixture(t).Sources
		s.Evidence.AgentAcceptanceCanonicalBytes = []byte("not json at all")
		s.Evidence.AgentAcceptanceSignature = hex.EncodeToString(
			ed25519.Sign(f.AgentKey, []byte("not json at all")))
		a := assertionByName(t, BuildAssertions(s), "Acceptance binds")
		if a.OK {
			t.Error("unparseable signed bytes were accepted as a binding acceptance")
		}
	})
}

// resignAcceptance rebuilds and re-signs the acceptance so the fixture stays
// internally consistent after a test edits one of the four signed members.
func resignAcceptance(t *testing.T, f *fixture, requesterID string) {
	t.Helper()
	offer := &rampv1.Offer{
		OfferId:   fixtureOfferID,
		Exchange:  "exchange.example",
		Signature: f.Sources.Evidence.OfferSig,
	}
	canonical, err := helpers.CanonicalAcceptanceBytes(
		offer, &rampv1.Requester{Id: requesterID, Domain: fixtureDomain}, fixtureIdempotency)
	if err != nil {
		t.Fatalf("canonical acceptance: %v", err)
	}
	f.Sources.Evidence.AgentAcceptanceCanonicalBytes = canonical
	f.Sources.Evidence.AgentAcceptanceSignature = hex.EncodeToString(ed25519.Sign(f.AgentKey, canonical))
}
