package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceview"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/transactionkey"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// Assertion is one checkable claim about the chain. Detail always says what was
// compared, whether the check passed or failed, so a reader can repeat it by
// hand rather than take the mark on trust.
//
// There are three outcomes, not two, and the difference between the last two is
// the point of the whole tool. OK means the check ran and held. Not OK with
// Unchecked false means the check ran and the chain failed it — evidence of
// tampering. Unchecked means the source was never read, so nothing is known
// either way; an operator with no tunnel open to the Broker must not be shown
// the same mark as an operator looking at a forged row.
type Assertion struct {
	Name      string
	OK        bool
	Unchecked bool
	Detail    string
}

// unchecked builds the verdict for a claim whose source was not available.
func unchecked(name, reason string) Assertion {
	return Assertion{Name: name, Unchecked: true, Detail: reason}
}

// BuildAssertions runs every check the three views support between them.
// Nothing here aborts: a failed assertion is a finding to render, and the
// remaining checks still carry information.
//
// The offline re-verifications come first because they are the strongest claim
// the chain makes — they need no live service, no key registry and no network.
func BuildAssertions(s Sources) []Assertion {
	e := s.Evidence
	return []Assertion{
		verifyOfferSignature(e),
		verifyAcceptanceSignature(e),
		acceptanceBindsThisAgreement(e),
		derivedKeyMatches(e, s.Transaction),
		brokerOfferedThisOffer(s),
		brokerSawThisAgent(s),
		deliveryHashMatches(s),
	}
}

// verifyOfferSignature re-runs the Exchange's own signature over the bytes the
// row stored, using the key the row stored. It re-derives nothing: the evidence
// row keeps the verbatim signed bytes precisely so this check survives a change
// to how offers are canonicalized.
func verifyOfferSignature(e *evidenceview.Evidence) Assertion {
	return ed25519Assertion(
		"Exchange offer signature re-verifies offline",
		e.ExchangeSigningPublicKey, e.OfferCanonicalBytes, e.OfferSig,
		fmt.Sprintf("%d canonical bytes against the stored Exchange key", len(e.OfferCanonicalBytes)),
	)
}

// verifyAcceptanceSignature does the same for the agent's acceptance, against
// the registry-pinned key the Exchange verified with at execute time.
func verifyAcceptanceSignature(e *evidenceview.Evidence) Assertion {
	return ed25519Assertion(
		"Agent acceptance signature re-verifies offline",
		e.AgentPublicKey, e.AgentAcceptanceCanonicalBytes, e.AgentAcceptanceSignature,
		fmt.Sprintf("%d canonical bytes against the stored agent key", len(e.AgentAcceptanceCanonicalBytes)),
	)
}

func ed25519Assertion(name string, pub, message []byte, sigHex, what string) Assertion {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return Assertion{Name: name, Detail: "signature is not valid hex: " + err.Error()}
	}
	if len(pub) != ed25519.PublicKeySize {
		return Assertion{Name: name, Detail: fmt.Sprintf("public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)}
	}
	if !ed25519.Verify(pub, message, sig) {
		return Assertion{Name: name, Detail: "ed25519.Verify rejected " + what}
	}
	return Assertion{Name: name, OK: true, Detail: "ed25519.Verify accepted " + what}
}

// acceptanceBindsThisAgreement is the check that turns two valid signatures
// into one agreement. Without it the chain proves only that the Exchange signed
// some offer and the agent signed some acceptance — not that the acceptance was
// for THIS offer, by THIS requester, under THIS request.
//
// Two distinct forgeries it refuses. An outsider splicing a genuine offer from
// one transaction onto a genuine acceptance from another is caught by offer_sig
// alone. Whoever writes the row is not: holding one genuine acceptance, they
// can write two rows for two executes against the same offer, and both pass an
// offer_sig-only check. Only comparing the idempotency key separates those, so
// all four members of the signed payload are compared and none is left
// unchecked.
func acceptanceBindsThisAgreement(e *evidenceview.Evidence) Assertion {
	const name = "Acceptance binds this exact agreement (all 4 signed members)"
	var payload rampv1.AgentAcceptancePayload
	// Unmarshalled through protojson rather than a hand-written struct so the
	// member set comes from the protocol's own message. A member added upstream
	// then shows up here as a compile-time gap, not as a silently unchecked
	// field.
	if err := protojson.Unmarshal(e.AgentAcceptanceCanonicalBytes, &payload); err != nil {
		return Assertion{Name: name, Detail: "signed bytes are not a readable acceptance payload: " + err.Error()}
	}
	mismatches := acceptanceMismatches(e, &payload)
	if len(mismatches) > 0 {
		return Assertion{Name: name, Detail: "the signed payload disagrees with the row: " + strings.Join(mismatches, "; ")}
	}
	return Assertion{
		Name: name, OK: true,
		Detail: "offer_sig, requester_id, requester_domain and idempotency_key inside the signed bytes all match the row",
	}
}

func acceptanceMismatches(e *evidenceview.Evidence, p *rampv1.AgentAcceptancePayload) []string {
	var out []string
	// Hex is compared case-insensitively: the protocol accepts either case on
	// the wire, and a dispute should read the same characters a request log
	// holds rather than a case this tool normalized.
	if !strings.EqualFold(p.GetOfferSig(), e.OfferSig) {
		out = append(out, fmt.Sprintf("offer_sig %q vs row %q", p.GetOfferSig(), e.OfferSig))
	}
	if p.GetRequesterId() != e.RequesterID {
		out = append(out, fmt.Sprintf("requester_id %q vs row %q", p.GetRequesterId(), e.RequesterID))
	}
	if p.GetRequesterDomain() != e.RequesterDomain {
		out = append(out, fmt.Sprintf("requester_domain %q vs row %q", p.GetRequesterDomain(), e.RequesterDomain))
	}
	if p.GetIdempotencyKey() != e.RequestIdempotencyKey {
		out = append(out, fmt.Sprintf("idempotency_key %q vs row %q", p.GetIdempotencyKey(), e.RequestIdempotencyKey))
	}
	return out
}

// derivedKeyMatches ties the request the agent signed to the transaction-log
// row the Exchange wrote. The Exchange derives the per-item key by appending
// the offer id to the request-level key, so the two describe the same item of
// the same request — and a row whose derived key does not rebuild from the
// signed key is describing a different request than the one that was accepted.
//
// The derivation is taken from the package the Exchange writes rows with, so a
// disagreement inside one revision is impossible. A deployed Exchange older than
// this binary can still disagree; that surfaces here as FAILED, which is why the
// derivation is documented as a compatibility contract rather than a helper.
func derivedKeyMatches(e *evidenceview.Evidence, t *evidenceview.TransactionState) Assertion {
	const name = "Transaction-log key derives from the signed request key"
	want := transactionkey.DerivedItemKey(e.RequestIdempotencyKey, e.OfferID)
	if t.IdempotencyKey != want {
		return Assertion{Name: name, Detail: fmt.Sprintf("log key %q, expected %q", t.IdempotencyKey, want)}
	}
	return Assertion{Name: name, OK: true, Detail: fmt.Sprintf("%q = signed key + \":\" + offer id", want)}
}

// brokerOfferedThisOffer is the cross-party claim the Broker leg exists to
// make: an independent party recorded having put this exact offer in front of
// this agent, before the transaction happened.
//
// The join is offer-id membership in the recorded candidate set, NOT transaction
// id equality. The Broker only serves discovery — no transaction exists at the
// time it records a decision — so there is no transaction id on its side to
// match.
func brokerOfferedThisOffer(s Sources) Assertion {
	const name = "Broker independently recorded offering this offer"
	if s.Selection == nil {
		return unchecked(name, s.SelectionAbsence)
	}
	offerID := s.Evidence.OfferID
	if !selectionOffers(s.Selection, offerID) {
		return Assertion{Name: name, Detail: fmt.Sprintf("selection %s does not list offer %s", s.Selection.LogID, offerID)}
	}
	return Assertion{
		Name: name, OK: true,
		Detail: fmt.Sprintf("selection %s recorded at %s lists offer %s among its candidates",
			s.Selection.LogID, s.Selection.CreatedAt.UTC().Format(time.RFC3339), offerID),
	}
}

// selectionOffers reports whether the Broker's recorded candidate set names
// this offer. The database already filtered on containment, so a false here
// means the row the query returned does not decode to a candidate set holding
// the offer — worth stating rather than assuming.
func selectionOffers(sel *repo.SelectionLogEntry, offerID string) bool {
	candidates, ok := sel.CandidateOffers.([]repo.CandidateInfo)
	if !ok {
		return false
	}
	for _, c := range candidates {
		if c.OfferID == offerID {
			return true
		}
	}
	return false
}

// brokerSawThisAgent checks the two sides name the same agent. The signed
// Requester.id is whatever the agent spelled its directory as; the Broker keys
// its audit on the canonical directory host. They name one agent but are not
// byte-equal, so the comparison goes through the same normalization the
// Exchange's own agent identity does.
func brokerSawThisAgent(s Sources) Assertion {
	const name = "Broker's agent and the signing agent are the same identity"
	if s.Selection == nil {
		return unchecked(name, s.SelectionAbsence)
	}
	signed := s.Evidence.RequesterID
	canonical, err := agentid.FromDirectory(signed)
	if err != nil {
		return Assertion{Name: name, Detail: fmt.Sprintf(
			"signed requester id %q does not name a directory host: %v", signed, err)}
	}
	if canonical != s.Selection.AgentID {
		return Assertion{Name: name, Detail: fmt.Sprintf(
			"signed %q normalizes to %q, Broker recorded %q", signed, canonical, s.Selection.AgentID)}
	}
	return Assertion{Name: name, OK: true, Detail: fmt.Sprintf(
		"signed %q normalizes to the Broker's %q", signed, canonical)}
}

// deliveryHashMatches is the delivery join: the digest the Exchange stored when
// it minted the URL against the digest the edge worker computed over the URL it
// was actually presented.
//
// It is hash equality and nothing more. The evidence contract deliberately
// withholds the signed URL itself — it stays a live bearer capability until it
// expires — so a signed-URL SIGNATURE match is not something this chain can
// ever show. Both sides hold the same SHA-256 over the URL's verbatim bytes,
// which is what makes the two comparable at all.
func deliveryHashMatches(s Sources) Assertion {
	const name = "Delivered URL is the URL the Exchange minted"
	if s.Delivery == nil {
		return unchecked(name, s.DeliveryAbsence)
	}
	stored := hexOf(s.Transaction.SignedURLHash)
	if stored == "" {
		return unchecked(name, "the Exchange stored no URL digest for this transaction")
	}
	if !strings.EqualFold(stored, s.Delivery.URLHash) {
		return Assertion{Name: name, Detail: fmt.Sprintf("Exchange stored %s, edge logged %s", stored, s.Delivery.URLHash)}
	}
	return Assertion{Name: name, OK: true, Detail: "sha256 " + stored + " on both sides"}
}

func hexOf(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}
