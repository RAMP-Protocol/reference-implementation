package repo

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5/pgtype"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/money"
)

// creditMaxIntegerDigits is the integer-digit capacity of NUMERIC(20,8):
// 20 total digits minus money.AssetScale (8) fraction digits. The guard
// enforces it so an oversized value surfaces as ErrDefaultCreditInvalid rather
// than a raw Postgres numeric-overflow error.
const creditMaxIntegerDigits = 12

// ErrDefaultCreditInvalid is returned when a default-agent-credit value cannot
// be stored: negative, finer than the ledger asset scale of 8, or too large
// for the column. Wraps carry the specific cause in their message; callers
// branch with errors.Is.
var ErrDefaultCreditInvalid = errors.New("repo: default agent credit invalid")

// pow10Rat returns 10^n as a big.Rat for positive n.
func pow10Rat(n int) *big.Rat {
	return new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil))
}

// guardDefaultAgentCredit validates a credit amount and converts it to the
// pgtype.Numeric the NUMERIC(20,8) column expects. It rejects nil and negative
// values, values that are not an integer count of minor units at the ledger
// asset scale (Postgres would round those, not reject them — the exactness
// rule is money.MinorUnits, the same conversion the billing adapter posts
// with), and values too large for the column's 12 integer digits. The encode
// goes through the shared numericFromDecimal rather than hand-building a
// pgtype.Numeric.
func guardDefaultAgentCredit(credit *big.Rat) (pgtype.Numeric, error) {
	if credit == nil {
		return pgtype.Numeric{}, fmt.Errorf("%w: nil amount", ErrDefaultCreditInvalid)
	}
	if credit.Sign() < 0 {
		return pgtype.Numeric{}, fmt.Errorf("%w: negative amount %s", ErrDefaultCreditInvalid, credit.RatString())
	}
	if _, err := money.MinorUnits(credit); err != nil {
		return pgtype.Numeric{}, fmt.Errorf(
			"%w: %s is finer than asset scale %d", ErrDefaultCreditInvalid, credit.RatString(), money.AssetScale)
	}
	if credit.Cmp(pow10Rat(creditMaxIntegerDigits)) >= 0 {
		return pgtype.Numeric{}, fmt.Errorf(
			"%w: %s exceeds %d integer digits", ErrDefaultCreditInvalid, credit.RatString(), creditMaxIntegerDigits)
	}
	return numericFromDecimal(money.DecimalString(credit))
}

// ratFromNumeric decodes a finite pgtype.Numeric into a big.Rat. The
// default_agent_credit column is NOT NULL and never NaN/infinite, so any
// non-finite value is a store inconsistency surfaced as an error.
func ratFromNumeric(n pgtype.Numeric) (*big.Rat, error) {
	if !n.Valid || n.NaN || n.InfinityModifier != pgtype.Finite {
		return nil, errors.New("repo: numeric is not a finite value")
	}
	r := new(big.Rat).SetInt(n.Int)
	switch {
	case n.Exp > 0:
		r.Mul(r, pow10Rat(int(n.Exp)))
	case n.Exp < 0:
		r.Quo(r, pow10Rat(int(-n.Exp)))
	}
	return r, nil
}
