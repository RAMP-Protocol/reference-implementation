//go:build integration

package transport_test

import (
	"net/http"
	"testing"

	connect "connectrpc.com/connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// GetAccountStatus reuses the Register test harness wholesale
// (newRegisterHarness / newAgent / newBrokerCaller): both RPCs share the same
// signed-request path, the same self-signup, and the same account surfaces, so
// the status tests observe exactly the account state Register produced through
// the same public router.

// TestExchangeGetAccountStatus_RegisteredActive drives Register then
// GetAccountStatus through the real Connect-Go router: a registered agent under
// a tenant whose activate_new_agents_by_default defaults TRUE reports its stored
// billing_ref and active=true. The status read observes the account Register
// created — no raw SQL (Testing Doctrine §9).
func TestExchangeGetAccountStatus_RegisteredActive(t *testing.T) {
	h := newRegisterHarness(t)
	a := h.newAgent(t, "status-agent.example")

	reg, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(testutil.RegistrationStruct(t, map[string]any{"legal_entity": "Acme AI Ltd"}))))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	ref := reg.Msg.GetBillingRef()

	resp, err := a.client.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest()))
	if err != nil {
		t.Fatalf("GetAccountStatus: %v", err)
	}
	if got := resp.Msg.GetBillingRef(); got != ref {
		t.Fatalf("billing_ref = %q, want %q (the ref Register stored)", got, ref)
	}
	if !resp.Msg.GetActive() {
		t.Fatal("active = false, want true (tenant activate_new_agents_by_default defaults TRUE)")
	}
}

// TestExchangeGetAccountStatus_RegisteredInactive proves an account that exists
// but is switched off reports active=false, NOT NotFound. The SoR in-memory
// adapter exposes no public deactivate surface (only OnRegister / IsActive), so
// the account is made inactive at the source by flipping the tenant activation
// default OFF before Register — the same arrange surface
// TestExchangeRegister_TenantActivationDefaultOff uses. This still exercises the
// load-bearing distinction (a present billing_ref + active=false must not
// collapse to NotFound) without inventing a deactivate path the production code
// does not have.
func TestExchangeGetAccountStatus_RegisteredInactive(t *testing.T) {
	h := newRegisterHarness(t)
	// Flip the single default tenant's activation policy off so the agent starts
	// inactive.
	setTenantActivationDefault(t, h.arrange(), false)

	a := h.newAgent(t, "inactive-agent.example")
	reg, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	ref := reg.Msg.GetBillingRef()

	resp, err := a.client.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest()))
	if err != nil {
		t.Fatalf("GetAccountStatus on an inactive account: %v (want success with active=false, not an error)", err)
	}
	if got := resp.Msg.GetBillingRef(); got != ref {
		t.Fatalf("billing_ref = %q, want %q (account exists)", got, ref)
	}
	if resp.Msg.GetActive() {
		t.Fatal("active = true, want false (registered under activation default OFF)")
	}
}

// TestExchangeGetAccountStatus_NeverRegistered proves an identity that has a
// signed presence but no account is NotFound (not an empty success). The agent
// self-signs up on its first signed call (lazy registration), so its
// ramp.agents row exists with an empty billing_ref — exactly the "known
// identity, no account" state — and GetAccountStatus maps it to CodeNotFound.
func TestExchangeGetAccountStatus_NeverRegistered(t *testing.T) {
	h := newRegisterHarness(t)
	a := h.newAgent(t, "unregistered-agent.example")

	_, err := a.client.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest()))
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Fatalf("code = %v, want NotFound (err=%v)", got, err)
	}
}

// TestExchangeGetAccountStatus_Negatives drives the auth/permission failure
// modes through the same public surface (Testing Doctrine §10), mirroring
// Register's negatives: an unsigned request is rejected by the httpsig gate
// before the handler runs, and a broker caller carries no agent identity of its
// own so it has no account to read.
func TestExchangeGetAccountStatus_Negatives(t *testing.T) {
	t.Run("unsigned request is Unauthenticated", func(t *testing.T) {
		h := newRegisterHarness(t)
		unsigned := rampconnect.NewExchangeServiceClient(
			&http.Client{Transport: h.baseTransport}, h.server, connect.WithGRPC(),
		)
		_, err := unsigned.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest()))
		if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
			t.Fatalf("code = %v, want Unauthenticated (err=%v)", got, err)
		}
	})

	t.Run("broker caller is PermissionDenied", func(t *testing.T) {
		h := newRegisterHarness(t)
		client := h.newBrokerCaller(t, "broker-status.example")
		_, err := client.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest()))
		if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
			t.Fatalf("code = %v, want PermissionDenied (err=%v)", got, err)
		}
	})
}

// TestExchangeGetAccountStatus_TermsDigestIsWhatWasAccepted drives the one
// property the digest field exists for: the response reports the acceptance this
// account recorded, never the terms the Exchange happens to publish today.
//
// The two answers are the same on every Exchange that has never revised its
// terms, which is why the case needs a second Exchange over the same database.
// The agent registers against one publishing digest A and its acceptance is
// recorded; the operator then revises, and a second Exchange over the same
// accounts publishes digest B. The status read must still say A.
//
// That divergence is the whole point of the field. Comparing this value against a
// freshly fetched manifest digest is how an agent discovers the terms moved under
// an account it already holds, and a repeat Register will not tell it — a repeat
// is answered from the stored record and runs no gate at all.
//
// This is also the assertion that fails if the handler ever answers from its
// configuration instead of the stored column. Every other digest case in this
// package would pass just as happily against that mistake, because the two values
// agree until the operator revises.
func TestExchangeGetAccountStatus_TermsDigestIsWhatWasAccepted(t *testing.T) {
	h := newHarnessPublishing(t, mustSchema(t), testutil.TermsDigest)
	a := h.newAgent(t, "accepted-digest.example")

	if _, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
		testutil.RegistrationStruct(t, conformingRegistration()), testutil.TermsDigest,
	))); err != nil {
		t.Fatalf("Register: %v", err)
	}

	revised := h.republishingTerms(t, testutil.RevisedTermsDigest)
	resp, err := revised.clientOn(a).GetAccountStatus(
		revised.ctx, connect.NewRequest(newAccountStatusRequest()),
	)
	if err != nil {
		t.Fatalf("GetAccountStatus against the revised Exchange: %v", err)
	}
	if got := resp.Msg.GetTermsDigest(); got != testutil.TermsDigest {
		t.Errorf("terms_digest = %q, want %q — the response must report what this account "+
			"ACCEPTED, not what the Exchange publishes now (%q)",
			got, testutil.TermsDigest, testutil.RevisedTermsDigest)
	}
}

// TestExchangeGetAccountStatus_NoDigestPublishedReportsNoAcceptance is the other
// half: an Exchange that publishes no terms accepts nothing, so it records
// nothing, so the field is absent.
//
// Absence has exactly one meaning in the contract — no acceptance is recorded —
// and an Exchange must not withhold a digest it holds, because absence is already
// spoken for. This case proves the empty answer is a real "nothing recorded"
// rather than the handler declining to look.
func TestExchangeGetAccountStatus_NoDigestPublishedReportsNoAcceptance(t *testing.T) {
	h := newRegisterHarness(t)
	a := h.newAgent(t, "no-digest.example")

	if _, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
		testutil.RegistrationStruct(t, conformingRegistration()), testutil.TermsDigest,
	))); err != nil {
		t.Fatalf("Register: %v", err)
	}

	resp, err := a.client.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest()))
	if err != nil {
		t.Fatalf("GetAccountStatus: %v", err)
	}
	if got := resp.Msg.GetTermsDigest(); got != "" {
		t.Errorf("terms_digest = %q, want absent — this Exchange publishes none, so the "+
			"presented value was neither checked nor recorded", got)
	}
}
