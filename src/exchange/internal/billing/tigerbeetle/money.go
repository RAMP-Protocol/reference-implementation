package tigerbeetle

import (
	"fmt"
	"math/big"
)

// ScaleFactor returns 10^scale as a big.Int: the multiplier that converts a
// currency amount into integer minor units at a ledger's (immutable) asset
// scale. Kept here, next to MinorUnits, so the production adapter and the test
// fixtures derive the factor from one place.
func ScaleFactor(scale uint8) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)
}

// MinorUnits converts an exact rational amount to an integer number of minor
// units at the given asset scale. A value with finer precision than the scale
// can represent is rejected with ErrAmountNotRepresentable rather than silently
// rounded, so every amount the ledger stores is exact. A nil value is an error.
//
// This is the single money-conversion source of truth: the TigerBeetle adapter's
// toMinor and the integration-test fixtures (tbtest) both call it, so a change to
// the exactness rule cannot diverge between what production posts and what a test
// asserts.
func MinorUnits(v *big.Rat, scale uint8) (*big.Int, error) {
	if v == nil {
		return nil, fmt.Errorf("tigerbeetle: nil amount")
	}
	scaled := new(big.Rat).Mul(v, new(big.Rat).SetInt(ScaleFactor(scale)))
	if !scaled.IsInt() {
		return nil, fmt.Errorf("%w: %s (scale %d)",
			ErrAmountNotRepresentable, v.FloatString(int(scale)+2), scale)
	}
	return new(big.Int).Set(scaled.Num()), nil
}
