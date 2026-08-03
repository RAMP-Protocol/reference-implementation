package transport

import (
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
)

// brokerDetail builds the ErrorDetail envelope every broker fault shares: the
// non-authoritative developer Message, the stable Domain, and any structured
// field metadata a broker.Error recorded via WithField/WithMeta. It is the
// SINGLE source of the metadata-ride, so the broker's two emit sinks — the
// Connect resolveFaultError and the raw-relay writeBrokerError — cannot drift
// (jscpd). The envelope body itself is the shared SDK build half
// (connectserver.NewErrorDetail) — the canonical ADR-019 §1 shape: the offending
// field identity travels machine-readably, never only in the message string.
// Broker faults are the generic transport class, so no reason oneof is set —
// Domain + Message + optional Metadata only. The Connect sink attaches this via
// the shared SDK connectserver.AttachDetail; the raw-relay sink
// marshals it itself (it writes raw bytes, not a connect.Error).
func brokerDetail(err error) *rampv1.ErrorDetail {
	var meta map[string]string
	var be *broker.Error
	if errors.As(err, &be) {
		meta = be.Metadata
	}
	return connectserver.NewErrorDetail(brokerServiceDomain, err.Error(), meta)
}
