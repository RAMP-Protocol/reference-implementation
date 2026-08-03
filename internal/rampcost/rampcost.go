// Package rampcost aggregates per-item RAMP transaction costs into the
// batch-level total_cost scalar.
//
// A multi-source (multi-exchange) or mixed-currency batch must never collapse
// charges into a single mis-labeled scalar: summing amounts across differing
// ISO-4217 currencies is meaningless, and latching one source's subtotal as the
// whole-batch aggregate under-counts the rest. The authoritative cost is always
// the per-item items[].cost; the batch scalar is a convenience that is emitted
// ONLY when the whole batch shares one currency, and is absent (nil) otherwise.
//
// Both the Exchange (its own items[] batch) and the Broker (the fan-out merge
// across exchanges) render total_cost through this one primitive so the two
// surfaces cannot drift. Money is exact decimal end to end
// (helpers.ParseMoney/FormatMoney), never float.
package rampcost

import (
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/shopspring/decimal"
)

// BatchTotal renders the batch-level total_cost from the authoritative per-item
// costs of a result set. It sums the costed items per ISO-4217 currency and
// returns a single *rampv1.Cost when every costed item shares one currency
// (Amount = the exact decimal sum), or nil when the items span multiple
// currencies or none carry a cost — in which case callers rely on the per-item
// items[].cost. Items with a nil Cost or empty Currency are skipped. A
// non-decimal cost Amount yields an error (the caller surfaces it as internal /
// omits the scalar) rather than a silent miscount.
func BatchTotal(items []*rampv1.TransactionResultItem) (*rampv1.Cost, error) {
	sums := map[string]decimal.Decimal{}
	order := make([]string, 0)
	for _, it := range items {
		cost := it.GetCost()
		if cost == nil || cost.GetCurrency() == "" {
			continue
		}
		amount, err := helpers.ParseMoney(cost.GetAmount())
		if err != nil {
			return nil, fmt.Errorf("parse item cost amount %q: %w", cost.GetAmount(), err)
		}
		cur := cost.GetCurrency()
		if _, seen := sums[cur]; !seen {
			order = append(order, cur)
		}
		sums[cur] = sums[cur].Add(amount)
	}
	// Zero costed items (every item denied / free) or a mixed-currency batch: no
	// single scalar is meaningful, so the aggregate is absent and items[].cost is
	// the sole authoritative cost.
	if len(order) != 1 {
		return nil, nil
	}
	cur := order[0]
	amountStr, err := helpers.FormatMoney(sums[cur])
	if err != nil {
		return nil, fmt.Errorf("format batch total_cost: %w", err)
	}
	return &rampv1.Cost{Amount: amountStr, Currency: cur}, nil
}
