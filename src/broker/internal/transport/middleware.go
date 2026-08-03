package transport

import (
	"log/slog"
	"net/http"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
)

// maxAgentBodyBytes caps the request body every agent-facing POST will buffer
// before processing. The broker's agent endpoints carry small protobuf-JSON
// payloads (a DiscoveryRequest / TransactionRequest is well under a kilobyte), so a
// 64 KiB ceiling never truncates a legitimate request. The cap is a DoS guard:
// without it an (intentionally pre-auth) endpoint like the ExecuteTransaction
// relay would buffer an arbitrarily large attacker body into memory before any
// signature check could reject it. Read with io.LimitReader at every agent POST.
const maxAgentBodyBytes int64 = 64 * 1024

// WrapPublicSurface assembles the Broker's outermost HTTP middleware — the
// shared runhttp.WrapPublicSurface stack (request-id → URL normalization →
// opt-in proxy trust) around the Broker's mux, which needs no extra inner
// layer. The stack fixes the @target-uri before every verifying surface inside
// the mux (the BrokerService connectserver seam and the relay boundary's
// requestTargetURL) sees the request; layer order and rationale are documented
// on runhttp.WrapPublicSurface. Shared by cmd/server and the integration
// harness so both exercise identical wiring.
func WrapPublicSurface(
	logger *slog.Logger,
	mux http.Handler,
	opts runhttp.PublicSurfaceOptions,
) http.Handler {
	return runhttp.WrapPublicSurface(logger, mux, opts)
}

// LogHTTPSigReject is the broker's connectserver.WithOnReject observer — the
// shared reqctx.NewRejectLogger body keyed on the "broker" audit namespace. See
// reqctx.NewRejectLogger for the request-id correlation + outcome-classification
// contract.
var LogHTTPSigReject = reqctx.NewRejectLogger("broker")
