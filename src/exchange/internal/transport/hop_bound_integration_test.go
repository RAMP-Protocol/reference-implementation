//go:build integration

package transport_test

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// newHopBoundHarness brings up the standard transport integration harness with
// the global httpsig gate's MaxSignatures ceiling set to maxSignatures, and the
// service logger wired to a JSON handler over the returned safeBuffer so the
// test can assert the audit-log outcome of a gate rejection. Bring-up delegates
// to newTestHarnessWith (Testing Doctrine #7).
func newHopBoundHarness(t *testing.T, maxSignatures int) (*testHarness, *safeBuffer) {
	t.Helper()
	buf := &safeBuffer{}
	h := newTestHarnessWith(t, harnessOptions{
		logger:        slog.New(slog.NewJSONHandler(buf, nil)),
		maxSignatures: maxSignatures,
	})
	return h, buf
}

// TestExecuteTransaction_HopBudgetRejected drives the Exchange hop-bound policy
// (ADR-013 D5 / RAMP-56) through the real startExchangeServer middleware — the
// SAME shared wiring production uses (transport.WrapPublicSurface). It mirrors
// the production ceiling formula MaxSignatures = max_intermediary_hops + 1 with
// max_intermediary_hops = 1, i.e. a budget of 2 signatures.
//
// A 3-signature forwarding chain (agent + 2 intermediaries) is one over the
// budget and MUST be rejected at the gate — before any signature is
// cryptographically verified — with HTTP 429 + a resource_exhausted body and
// the audit outcome REJECTED_HOP_BUDGET. A 2-signature chain at exactly the
// budget is the control: it clears the gate and the transaction succeeds.
//
// The over-budget assertion inspects the raw HTTP response rather than the
// Connect gRPC client: the client remaps a bare HTTP 429 to
// connect.CodeUnavailable, which would mask the gate's resource_exhausted
// semantics. The raw 429 + body + audit log is the faithful production contract
// (mirrors internal/httpsig/chain_test.go).
//
// This is the integration coverage HIGH-01 found missing: deleting the
// MaxSignatures wiring from the shared constructor makes the over-budget
// assertion below fail.
func TestExecuteTransaction_HopBudgetRejected(t *testing.T) {
	// Production formula: max_intermediary_hops = 1 → MaxSignatures = 1 + 1 = 2.
	const maxSignatures = 2
	h, logs := newHopBoundHarness(t, maxSignatures)
	ctx := h.ctx
	h.enableBrokerRelay(t, h.tenantID)

	seedCatalog(t, h)
	offer := discoverFirst(t, h)[0]

	// Control: a 2-signature chain (agent + 1 broker) is exactly at the budget;
	// it clears the hop gate and the transaction succeeds.
	withinBudget := h.newChainClient(t, "broker.example")
	if _, err := withinBudget.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-within-budget",
		OfferId:        stringPtr(offer.GetOfferId()),
		OfferSignature: stringPtr(offer.GetSignature()),
		Requester:      &rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	})); err != nil {
		t.Fatalf("2-signature chain at budget should clear the hop gate: %v", err)
	}
	if got := logs.String(); strings.Contains(got, "REJECTED_HOP_BUDGET") {
		t.Fatalf("within-budget chain must not trip the hop gate; log: %s", got)
	}

	// Over-budget: a 3-signature chain (agent + 2 intermediaries) exceeds the
	// budget of 2 and is rejected at the gate before crypto verification.
	resp := h.signedChainPOST(t, "/ramp.v1.ExchangeService/ExecuteTransaction", "relay.one", "relay.two")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 Too Many Requests", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "resource_exhausted") {
		t.Fatalf("body = %q, want resource_exhausted", string(body))
	}

	got := logs.String()
	if !strings.Contains(got, "httpsig: reject") || !strings.Contains(got, `"outcome":"REJECTED_HOP_BUDGET"`) {
		t.Fatalf("audit log missing hop-budget rejection; log: %s", got)
	}
}
