package transport_test

import (
	"context"
	"errors"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// TestPushResources_MissingSignatureMiddleware_MapsToInternal is the
// Kind-table guard. The catalog signature gate used to hand-pick connect
// codes inline (connect.NewError(connect.CodeInternal, ...) / CodeUnauthenticated); the fix
// routes those failures through the domain Kind vocabulary (exchange.Newf /
// exchange.Wrap) + exchange.ToConnect so the gate shares the single
// Kind→connect.Code mapping table with every other handler path. This test
// pins that the refactor does NOT change the emitted code for the
// middleware-missing wiring fault: it must still surface as CodeInternal.
//
// Surface: this drives the gate through the EXPORTED CatalogHandler.PushResources
// (the outermost public surface that owns the check) and asserts the
// connect.Code back through that same surface. The middleware-missing branch
// returns before the service or registry is touched, so a nil svc/registry is
// safe here — this is the one gate branch with no prior coverage. The
// CodeUnauthenticated branches (unsigned request, unknown caller with no
// self-signup) are guarded end-to-end through the full RPC + RFC 9421 stack by
// TestPushResources_UnsignedRequestRejected and
// TestPushResources_UnknownCallerManifestMissing in push_resources_e2e_test.go;
// those assert CodeUnauthenticated and MUST stay green across this refactor.
func TestPushResources_MissingSignatureMiddleware_MapsToInternal(t *testing.T) {
	t.Parallel()

	// No CatalogSignatureMiddleware ran, so the context lacks the raw
	// request/body the gate requires — the "signature middleware missing"
	// wiring fault. nil svc/registry are never reached on this branch.
	h := transport.NewCatalogHandler(nil, nil)

	_, err := h.PushResources(context.Background(), connect.NewRequest(&rampv1.PushResourcesRequest{
		CallerId: "caller.example",
	}))
	if err == nil {
		t.Fatal("expected error when signature middleware did not run, got nil")
	}

	var connErr *connect.Error
	if !errors.As(err, &connErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if got := connErr.Code(); got != connect.CodeInternal {
		t.Fatalf("code = %s, want %s (missing-middleware fault must map to Internal via the Kind table)",
			got, connect.CodeInternal)
	}
}
