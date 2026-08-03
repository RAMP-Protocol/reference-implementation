//go:build integration

package transport_test

import (
	"net/http"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Request-id propagation across the Broker→Exchange hop.
//
// The Exchange writes the X-Request-ID it sees into transaction_evidence, an
// append-once row, and its header documents that column as the key correlating an
// evidence row outward against the edge delivery log and the reconciliation
// sweep. The relay is the leg that makes the claim true or false: in the deployed
// agent → MCP → Broker → Exchange topology the Exchange only ever sees the id the
// Broker sends it. Without forwarding it mints its own, and the stored key
// appears in no broker log, no MCP log, and no agent record — a join that
// resolves to nothing, on a row that can never be corrected.
//
// Round-trip honesty: these are PROTOCOL round-trips over real HTTP. The request
// enters through the broker's public relay route under the production
// RequestIDMiddleware, and the assertion reads the header an httptest Exchange
// actually received — not a mocked client, not the broker's own context.

// TestExchangeRelay_ForwardsCallerRequestIDUpstream drives a conforming
// caller-supplied id and requires the Exchange to see that exact value, so a
// dispute can be traced from the agent's own record through to the evidence row.
func TestExchangeRelay_ForwardsCallerRequestIDUpstream(t *testing.T) {
	env := newRelayTestEnv(t)
	const wantID = "corr-relay-execute-1"

	req := env.signedRelayRequest(t, env.txBody(t))
	req.Header.Set(helpers.RequestIDHeader, wantID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relay status = %d, want 200", resp.StatusCode)
	}

	// The broker echoes the id it accepted...
	if got := resp.Header.Get(helpers.RequestIDHeader); got != wantID {
		t.Errorf("broker response X-Request-ID = %q, want the caller's %q", got, wantID)
	}
	// ...and sends that same id upstream, rather than letting the Exchange mint a
	// second one the caller never saw.
	if got := env.captured.getRequestID(); got != wantID {
		t.Errorf("Exchange saw X-Request-ID %q, want the caller's %q", got, wantID)
	}
}

// TestExchangeRelay_ForwardsMintedRequestIDUpstream covers the caller that sends
// no id at all — the common case, since the header is optional.
//
// The broker mints one, and the assertion is that the SAME minted value reaches
// the Exchange and is echoed to the caller. A test that only checked "some id
// arrived" would pass with three independently minted ids, which is precisely the
// failure mode: three logs that cannot be joined.
func TestExchangeRelay_ForwardsMintedRequestIDUpstream(t *testing.T) {
	env := newRelayTestEnv(t)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, env.txBody(t)))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relay status = %d, want 200", resp.StatusCode)
	}

	minted := resp.Header.Get(helpers.RequestIDHeader)
	if minted == "" {
		t.Fatal("broker returned no X-Request-ID; nothing was minted to correlate on")
	}
	if got := env.captured.getRequestID(); got != minted {
		t.Errorf("Exchange saw X-Request-ID %q, want the id the broker minted and returned %q", got, minted)
	}
}
