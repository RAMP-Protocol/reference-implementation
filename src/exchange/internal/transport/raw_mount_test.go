package transport_test

import (
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// TestRawValidatedMountOptions_NilAudienceIsRefused drives the guard that keeps
// a raw mount from coming up without a recipient check. A nil interceptor is
// worse than a broken one: it mounts cleanly and checks nothing, so the catalog
// surface would serve pushes with the check silently absent. The refusal is a
// boot-time fault every caller threads up to run(), so the process exits rather
// than serving.
func TestRawValidatedMountOptions_NilAudienceIsRefused(t *testing.T) {
	t.Parallel()
	opts, err := transport.RawValidatedMountOptions(nil)
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
