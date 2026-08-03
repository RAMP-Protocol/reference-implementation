package transport

import (
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/resolve"
)

// moneyStringToFixedPoint parses a canonical wire money string and scales it to
// 1e8 fixed-point int64 via the resolve core's shared scaling convention
// (resolve.DecimalToFixedPoint — the same unit the resolve budget gate accounts
// in). The empty (unset) string maps to (0, nil) — an absent budget/cost
// contributes nothing, matching the gate's "no limit / no cost" semantics. A
// present-but-malformed value returns the ParseMoney error; the canonical wire
// pattern is enforced upstream by protovalidate, so callers on the resolve path
// treat that error as "no value" (0) by discarding it, while the regression test
// (which feeds only canonical strings) never observes it.
func moneyStringToFixedPoint(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	d, err := helpers.ParseMoney(s)
	if err != nil {
		return 0, err
	}
	return resolve.DecimalToFixedPoint(d), nil
}
