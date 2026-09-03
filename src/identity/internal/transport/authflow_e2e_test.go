//go:build integration

package transport_test

import (
	"net/http"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauthserver"
)

// The fast-tier happy paths of the sign-up flow. They drive the shared harness in
// authflow_fixture_test.go, which is also what the negatives and the real-Zitadel
// tier run on, so all three tiers assert the same flow through the same surface.

// TestAuthFlow_HappyPathProvisions drives the full fast-tier flow (real Postgres +
// Vault, fake upstream) and asserts the central acceptance outcome — keys + card +
// well-known served on the minted subdomain — through the service's own read
// surfaces. This puts the primary acceptance assertion on the always-run
// integration gate, not only the Zitadel tier.
func TestAuthFlow_HappyPathProvisions(t *testing.T) {
	f := newAuthFixture(t)
	clientID, verifier := f.driveToConsent(t)

	// The consent screen names the identity it is about to grant access to, which
	// is the minted subdomain.
	f.assertConsentNames(t, f.subdomain)

	code := f.grantCode(t)
	if tok := f.exchangeToken(t, code, verifier, clientID); tok.status != http.StatusOK {
		t.Fatalf("token exchange = %d, want 200", tok.status)
	}
	f.assertProvisioned(t)
}

// TestAuthFlow_ReturningDeveloperReusesTheSameIdentity verifies sign-up is
// idempotent across two full flows: a developer who signs in a second time is
// resolved to the account already provisioned for them, and still has to approve
// the client before a code is issued.
//
// The second callback's 302 is what carries the idempotency claim, which is worth
// spelling out because it does not read like one. Sign-up resolves a returning
// developer two ways: a direct lookup by (issuer, subject), and — if that lookup
// is skipped — the unique violation the insert then hits, whose handler goes back
// to the same lookup. Either one landing the browser on /consent is the evidence
// that the second sign-in reused the first account instead of minting a second.
//
// Disabling both arms was checked and does make this fail, with a 500 at the
// callback; disabling either one alone does not, because the other covers it. So
// this asserts the outcome rather than one mechanism, which is the right thing
// for it to hold and the reason the failure message names the outcome.
//
// Landing on /consent only shows that SOME account was resolved, so the subdomain
// the screen names is asserted too. That needs the counting slug generator — under
// the fixed one every account carries the same label — and it needs a second,
// unrelated developer signing up in between, so the first developer's account is
// no longer the only one a resolver could hand back.
func TestAuthFlow_ReturningDeveloperReusesTheSameIdentity(t *testing.T) {
	up, drive := fakeUpstreamWith()
	f := buildAuthFixture(t, up, drive, authServerOpts{slugs: &countingSlug{}})
	clientID, verifier := f.driveToConsent(t)
	f.assertConsentNames(t, f.subdomain)
	code := f.grantCode(t)
	if tok := f.exchangeToken(t, code, verifier, clientID); tok.status != http.StatusOK {
		t.Fatalf("first exchange = %d, want 200", tok.status)
	}

	// A second developer signs up on the same server and takes the next subdomain.
	// driveToConsent registers a client of its own for that flow; the first
	// developer's client is the one picked up again below.
	up.claims.Subject = otherUpstreamSubject
	f.driveToConsent(t)
	f.assertConsentNames(t, countedSlug(2)+"."+baseZone)
	f.grantCode(t)

	// Second sign-in for the FIRST developer: the fake upstream asserts their
	// subject again, so the callback must land on the consent screen rather than
	// issue a code without approval.
	up.claims.Subject = stubUpstreamSubject
	_, challenge := pkcePair(t)
	cb := f.authorizeThenCallback(t, clientID, flowClientURI, challenge)
	if cb.status != http.StatusFound || cb.location != oauthserver.ConsentPath {
		t.Fatalf("returning developer callback = %d -> %q, want 302 -> /consent — a 500 here "+
			"means sign-in could not resolve the account this identity already has",
			cb.status, cb.location)
	}
	// And that screen must name the subdomain minted for them the first time: a
	// third label means a second account was minted for one identity, and the
	// second developer's label means sign-in resolved the wrong account.
	f.assertConsentNames(t, f.subdomain)
	// Approving consent yields the code back to the client.
	f.grantCode(t)
}
