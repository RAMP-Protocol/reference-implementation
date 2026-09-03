package transport

import (
	"net/http"

	sdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience"
)

// BrokerMountOptions returns the ServerOption set the BrokerService mount runs
// with. Production and the integration harness both call it, so the mount those
// tests drive is the mount that ships.
//
// Written out twice instead, the two lists came apart: the harness never wired
// the recipient check that production mounts, while its own comment said it
// wired the production set "no more, no less". Nothing failed, because no
// agent-facing BrokerService request names a recipient today — which is exactly
// why the gap could sit there, and exactly why the day an RPC gains one is the
// wrong day to discover it.
//
// audience is required rather than optional, matching the Exchange's mount
// options and the refusal buildBrokerMux already made: a nil interceptor mounts
// cleanly and checks nothing.
func BrokerMountOptions(
	resolver helpers.KeyResolver,
	replayStore core.ReplayStore,
	audience *rampaudience.Interceptor,
) ([]connectserver.ServerOption, error) {
	if err := rampaudience.Require(audience, "broker mount options"); err != nil {
		return nil, err
	}
	// MaxSignatures is deliberately unset (0 = unbounded): the hop bound is an
	// Exchange-terminal policy, and bounding it at the Broker too would
	// double-count the relay hop the Broker is about to add.
	return []connectserver.ServerOption{
		connectserver.WithKeyResolver(resolver),
		connectserver.WithReplayStore(replayStore),
		connectserver.WithValidation(sdkconnect.ValidationStrict),
		// Zero-valued response fields stay on the wire (platform JSON contract).
		connectserver.WithEmitUnpopulated(),
		// The same recipient check the Exchange mounts, from the one shared
		// definition. Nothing this interceptor sees names a recipient today: the
		// only agent-facing BrokerService RPC is discovery, and DiscoveryRequest
		// carries no recipient field, so there is nothing to compare rather than
		// a comparison that passes. It is mounted so an agent-facing RPC that
		// gains a recipient later is guarded the day it does rather than the day
		// somebody remembers.
		connectserver.WithInterceptors(audience),
		// A /ramp. request must clear the seam iff it PRESENTS a signature: an
		// unsigned Resolve reaches the handler, which finds no verified context
		// and returns the typed Unauthenticated fault (ADR-019 error detail) —
		// the no-caller negative path the contract tests drive.
		connectserver.WithVerifyGate(func(r *http.Request) bool {
			return r.Header.Get("Signature-Input") != ""
		}),
		// Audit-log every gate rejection with its outcome: the four the SDK's
		// own classifier names (replay / broken_chain / hop_budget / signature)
		// plus body_too_large, which its enum has no value for. That fifth one
		// is reachable here even though this set names no request cap, because
		// an unset cap leaves the SDK's own default in force rather than no
		// bound at all, and a body past it is refused before verification.
		//
		// Reachable for a SIGNED request only, on this service. The observer
		// runs from inside the verify seam, and the gate above admits an
		// unsigned request to the handler without entering it, so an unsigned
		// body past the cap is refused by the same bound and audited by
		// nothing. Closing that would take a body-cap wrapper outside the seam,
		// the shape the Exchange's catalog mount uses; the runbook records the
		// gap rather than the code pretending it is not there.
		connectserver.WithOnReject(LogHTTPSigReject),
	}, nil
}
