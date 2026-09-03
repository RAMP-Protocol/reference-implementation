//go:build integration

package transport_test

import (
	"net/http"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
)

// TestReportUsage_SignerKeyMustMatchCallerDirectory_ImpersonationRejected pins the
// service-layer identity↔key binding in ExchangeService.lookupCaller: a verified
// signature authorizes as the Signature-Agent DIRECTORY only when that directory
// actually publishes the key that produced the signature. RFC 9421 keyids are
// RFC 7638 thumbprints (proof of key possession), and a resolver will verify a
// signature against ANY key it knows; without this binding a holder of any
// resolver-known key could set Signature-Agent to another registered directory and
// be authorized as it.
//
// This binding is reachable ONLY through resolveCaller, whose sole caller is
// ReportUsage: DiscoverResources performs no key-directory authorization, and
// ExecuteTransaction proves agent identity through the BODY offer-acceptance
// (authorizeExecute), not lookupCaller. ReportUsage is therefore the surface that
// exercises this code path end-to-end.
//
// Scenario: victim.example is a legitimately registered agent pinned to keyA;
// attacker.example is a legitimately registered agent pinned to keyB (so keyB is
// resolver-known and the transport signature verifies). The attacker signs a
// ReportUsage with keyB but stamps Signature-Agent: victim.example. The httpsig
// middleware verifies the signature against keyB (keyed by keyB's thumbprint keyid)
// and hands the service SignatureAgent=victim.example with the proven key keyB.
// lookupCaller resolves victim's PINNED key (keyA), finds keyA != keyB, attempts a
// bounded re-pin of victim's directory (which does not re-publish keyB — here the
// directory is not re-fetchable, so the pin stands), and refuses with
// Unauthenticated — before any obligation is loaded. The code is Unauthenticated
// (an authentication failure) not PermissionDenied, matching the catalog-push gate
// and not leaking whether victim.example is a registered identity.
//
// Round-trip honesty: the write leg drives ExchangeService/ReportUsage through the
// Connect-Go router + RFC 9421 verification + service authz. The no-side-effect
// assertion reads the obligation state back through the same obligation surface
// (assertObligationState) — never raw sqlc/SQL/DB (Testing Doctrine §9).
func TestReportUsage_SignerKeyMustMatchCallerDirectory_ImpersonationRejected(t *testing.T) {
	h := newTestHarness(t) // tenant A + agent-test
	// A real, PENDING obligation belonging to agent-test — the side-effect surface
	// the rejected impersonation must leave untouched.
	txID, billingID := executeTransactionFor(t, h, 100)

	// victim.example: a registered agent pinned to keyA (the impersonation target).
	h.addCallerWithKey(t, "victim.example", "AGENT")
	// attacker.example: a registered agent pinned to keyB, so keyB is resolver-known
	// and the transport signature the attacker produces will verify.
	_, _, attackerPriv := h.addCallerWithKey(t, "attacker.example", "AGENT")

	// The attack: sign with attacker's keyB but claim Signature-Agent: victim.example.
	impersonatingClient := rampconnect.NewExchangeServiceClient(
		&http.Client{Transport: newSigningTransport(h.baseTransport, "victim.example", attackerPriv)},
		h.server.URL, connect.WithGRPC(),
	)

	_, err := impersonatingClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-impersonate", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100})))
	// keyA (victim's pinned key) != keyB (the proven signer) and the bounded re-pin
	// does not change that → the identity↔key binding refuses with Unauthenticated
	// before any obligation load.
	assertConnectError(t, err, connect.CodeUnauthenticated, "not published by caller directory")
	// The rejected impersonation left NO trace: the obligation stays PENDING.
	assertObligationState(t, h, txID, "PENDING", "")
}
