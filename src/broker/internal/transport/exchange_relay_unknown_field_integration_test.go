//go:build integration

package transport_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestExchangeRelay_UnknownRequesterFieldIgnored guards the forward-compatibility
// of the hand-rolled relay execute route (POST /broker/v1/exchange/execute). That
// handler decodes the TransactionRequest with protojson, whose default rejects
// unknown fields — so a caller still sending a field the protocol has REMOVED must
// be tolerated and ignored, exactly as every Connect codec path already is, not
// 400'd. The motivating case is the reserved Requester.billing_ref: once field 5 is
// gone, a body still carrying it decodes as an unknown field. This pins the
// DiscardUnknown tolerance by injecting a stray billing_ref key into a valid,
// signed relay body and asserting the request still succeeds and forwards.
//
// It also stands in for the Exchange-side AC-6 anti-spoofing test retired with the
// field: once field 5 is reserved, "a wire billing_ref selects the account" is
// unrepresentable (structurally stronger than the test), so what remains worth
// guarding is that the stray key is ignored — which this does, at the one route
// that would otherwise reject it.
func TestExchangeRelay_UnknownRequesterFieldIgnored(t *testing.T) {
	env := newRelayTestEnv(t)

	// A valid, per-item-signed 1-item body, then inject a stray billing_ref key
	// into its requester object. The per-item AgentAcceptance covers only the flat
	// identity projection (never billing_ref), so the injection leaves it valid;
	// the outer agent sig1 is signed over these modified bytes by signedRelayRequest.
	body := env.txBody(t)
	modified := injectRequesterKey(t, body, "billing_ref", "billing-victim")

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, modified))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relay rejected a body carrying an unknown requester field — it must be ignored, "+
			"not 400'd: %d %s", resp.StatusCode, bodyBytes)
	}
	if env.mockExch.executeCalls != 1 {
		t.Errorf("Exchange.ExecuteTransaction called %d times, want 1 (the relay must forward)",
			env.mockExch.executeCalls)
	}

	var txResp rampv1.TransactionResponse
	if err := protojson.Unmarshal(bodyBytes, &txResp); err != nil {
		t.Fatalf("parse TransactionResponse: %v", err)
	}
	if len(txResp.GetItems()) != 1 || txResp.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Errorf("relay did not deliver the item despite the ignored field: %s", bodyBytes)
	}
}

// injectRequesterKey adds key=value to the requester object of a protojson
// TransactionRequest body and returns the re-marshaled bytes.
func injectRequesterKey(t *testing.T, body []byte, key, value string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal relay body: %v", err)
	}
	requester, ok := m["requester"].(map[string]any)
	if !ok {
		t.Fatalf("relay body has no requester object: %s", body)
	}
	requester[key] = value
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal modified relay body: %v", err)
	}
	return out
}
