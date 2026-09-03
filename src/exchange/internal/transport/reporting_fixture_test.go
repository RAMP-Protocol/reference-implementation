//go:build integration

package transport_test

// Shared bring-up for the reporting suites: the gate tests, the overdue tests
// and the recovery tests all need the same fixture, and each used to build its
// own copy of it.

import (
	"crypto/ed25519"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// newReportingHarness builds the fixture every reporting suite needs: a harness
// on a deterministic clock anchored at the wall clock, the billing recorder, and
// the audit-log buffer.
//
// It returns all four pieces and each suite discards what it does not use. The
// three suites previously kept a private constructor apiece, differing only in
// which values they kept and the order they returned them — which is the shape
// Testing Doctrine point 7 exists to prevent, and which invites the next test to
// copy whichever variant is nearer.
func newReportingHarness(t *testing.T) (
	*testHarness, *recordingAdapter, *safeBuffer, *clock.DeterministicClock,
) {
	t.Helper()
	det := clock.NewDeterministic(time.Now().UTC())
	h, rec, buf := newRecordingHarnessCapturingLogs(t, det)
	return h, rec, buf, det
}

// executeCaller is one registered agent's execute identity: the client whose
// transport signs as that agent, the requester its body carries, and the key its
// offer acceptance is signed with. The three travel together because an execute
// needs all of them to name the same agent, and splitting them across arguments
// is how a test ends up proving a property for the harness default while
// believing it drove a second agent.
type executeCaller struct {
	client    rampconnect.ExchangeServiceClient
	requester *rampv1.Requester
	priv      ed25519.PrivateKey
}

// addExecuteCaller registers a second agent and returns everything an execute
// for it needs. The harness default is agent-test, so any test whose subject is
// a per-agent property needs an identity that is registered, resolver-known, and
// able to sign its own acceptance.
func (h *testHarness) addExecuteCaller(t *testing.T, agentID string) executeCaller {
	t.Helper()
	client, _, priv := h.addCallerWithKey(t, agentID, "AGENT")
	// A registered agent still needs a billing account before it can execute a
	// paid offer, or the item comes back denied with ACCOUNT_NOT_REGISTERED and
	// the test reads as a gate refusal. Register is the production path an agent
	// takes to mint its ref and open its ledger account.
	registerCaller(t, h.ctx, client)
	return executeCaller{
		client:    client,
		requester: newRequester(agentID, agentID+".example"),
		priv:      priv,
	}
}

// executeSingleItemAs is executeSingleItem for a caller other than the harness
// default. The gate reads its agent from requester.id, and the acceptance is
// verified against that agent's registered key, so both come from the caller.
func executeSingleItemAs(
	t *testing.T, h *testHarness, c executeCaller, txID string, offer *rampv1.Offer,
) (*connect.Response[rampv1.TransactionResponse], error) {
	t.Helper()
	return c.client.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: txID,
		Requester:      c.requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, c.priv, offer, c.requester, txID)},
		},
	}))
}
