package resolve

import "github.com/shopspring/decimal"

// fixedPointScale is the number of decimal places the Broker budget gate
// accounts money at. Money is scaled to FIXED-POINT int64 at 1e8 (8dp) so the
// Redis INCRBY budget counter stays an atomic integer while still representing
// fractions of a cent EXACTLY (user DECISION 1+3). This REPLACES the old 2dp
// int64(amount*100) cents model, which truncated any sub-cent amount to 0 and
// silently let the period cap never deplete (the bug budget_fixedpoint_test.go
// pins). decimal.Shift(8) moves the point 8 places; IntPart() then yields the
// fixed-point integer, truncating any precision beyond 8dp (the wire pattern
// permits more, but the platform's money precision is 8dp).
const fixedPointScale int32 = 8

// DecimalToFixedPoint scales an exact decimal to 1e8 fixed-point int64.
// Truncates beyond 8dp; never uses float. Exported so the transport adapter's
// money-string parser (moneyStringToFixedPoint) shares the single scaling
// convention the resolve budget gate uses.
func DecimalToFixedPoint(d decimal.Decimal) int64 {
	return d.Shift(fixedPointScale).IntPart()
}
