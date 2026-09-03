package transport

import (
	sdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience"
)

// ExchangeMountOptions returns the ServerOption set the ExchangeService mount
// runs with. Production and the integration harness both call it, so the mount
// under test is the mount that ships.
//
// This exists for the reason RawValidatedMountOptions exists one file over. That
// one was extracted after the harness and production came apart on it: the
// harness had installed a bare protovalidate interceptor where production
// installs the SDK's, which validates responses as well. The ExchangeService
// mount was left as two hand-maintained lists, and a test that reads what the
// mount serves was then reading the harness's list rather than this one — remove
// an option from production alone and that test still passed.
//
// audience is required rather than optional, on the same reasoning
// RawValidatedMountOptions gives: a nil interceptor mounts cleanly and checks
// nothing. It is checked here rather than left to the caller, because a
// typed-nil pointer handed to WithInterceptors arrives as a non-nil
// connect.Interceptor and fails at request time instead of at boot.
func ExchangeMountOptions(
	resolver helpers.KeyResolver,
	replayStore core.ReplayStore,
	maxSignatures int,
	audience *rampaudience.Interceptor,
) ([]connectserver.ServerOption, error) {
	if err := rampaudience.Require(audience, "exchange mount options"); err != nil {
		return nil, err
	}
	return []connectserver.ServerOption{
		connectserver.WithKeyResolver(resolver),
		connectserver.WithReplayStore(replayStore),
		connectserver.WithMaxSignatures(maxSignatures),
		connectserver.WithValidation(sdkconnect.ValidationStrict),
		connectserver.WithEmitUnpopulated(),
		// Refuse a request addressed to a different Exchange. It runs as an
		// interceptor, so it is asked once for every RPC on this mount and
		// answers before the handler — and therefore before any database work,
		// which is the ordering the check needs: the identifiers a message
		// carries elsewhere are opaque and Exchange-scoped, so verifying one
		// would mean the very lookup this check is meant to precede.
		connectserver.WithInterceptors(audience),
		// Audit-log every gate rejection with its outcome: the four the SDK's
		// own classifier names (replay / broken_chain / hop_budget / signature)
		// plus body_too_large, which its enum has no value for and which the
		// app names rather than letting default to a signature failure. The
		// same observer runs on the catalog mount, which calls it from the
		// middleware that captures the body, since that mount has no verify
		// seam to hook.
		connectserver.WithOnReject(LogHTTPSigReject),
		// Bound what one request can make this mount read. The SDK models two
		// quantities under this one option, because a caller can exhaust the
		// server through either: the raw HTTP body the verify face buffers
		// before it can check a signature, refused as a 413 with a
		// resource_exhausted body — before authentication, so an unsigned
		// caller reaches only this bound — and the decompressed Connect message
		// the handler decodes, refused as CodeResourceExhausted. Both are
		// pinned at MaxRPCReadBytes here; left unset, the SDK's own larger
		// default would apply. The Register RPC adds a tighter, semantic bound
		// on registration_data on top.
		connectserver.WithMaxRequestBytes(MaxRPCReadBytes),
	}, nil
}
