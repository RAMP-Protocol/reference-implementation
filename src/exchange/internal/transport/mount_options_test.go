package transport_test

import (
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// TestExchangeMountOptions_NilAudienceIsRefused drives the guard that keeps the
// ExchangeService mount from coming up without a recipient check. A nil
// interceptor is worse than a broken one: it mounts cleanly and checks nothing,
// so the surface would serve every RPC with the check silently absent. The
// refusal is a boot-time fault threaded up to run(), so the process exits rather
// than serving.
//
// This is the Exchange half. The Broker's is driven through its composition root
// instead — buildBrokerMux is handed a nil interceptor there and the refusal it
// returns is this same one, reaching it through BrokerMountOptions. A second
// direct test of that function would assert what the mux test already proves.
func TestExchangeMountOptions_NilAudienceIsRefused(t *testing.T) {
	t.Parallel()
	opts, err := transport.ExchangeMountOptions(nil, nil, 0, nil)
	if err == nil {
		t.Fatal("nil recipient interceptor returned nil error; want a refusal")
	}
	if opts != nil {
		t.Errorf("options = %v, want nil beside the refusal", opts)
	}
	if !strings.Contains(err.Error(), "the recipient interceptor is required") {
		t.Fatalf("error %q is not the missing-interceptor refusal", err)
	}
}
