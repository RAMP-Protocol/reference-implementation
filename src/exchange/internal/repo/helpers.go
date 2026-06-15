package repo

import (
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5/pgtype"
)

func pgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// numericFromFloat encodes a float64 (e.g. a tolerance fraction) as the
// pgtype.Numeric the NUMERIC(5,4) tolerance column expects. Routes via the
// canonical decimal string so the round-trip matches pgx's internal Scan
// path used by numericFromDecimal.
func numericFromFloat(f float64) (pgtype.Numeric, error) {
	var n pgtype.Numeric
	if err := n.Scan(strconv.FormatFloat(f, 'f', -1, 64)); err != nil {
		return pgtype.Numeric{}, fmt.Errorf("scan numeric from float %g: %w", f, err)
	}
	return n, nil
}

// floatFromNumeric decodes a pgtype.Numeric to float64 for in-process
// arithmetic. The validator uses this once per call to materialize
// quantity_tolerance into the fixed-point computation; the precision loss
// is bounded by the NUMERIC(5,4) column definition (≤ 0.0001 absolute).
// Returns 0 (not an error) for NULL values so callers can treat "missing
// tolerance" as "use the default" without an extra branch.
func floatFromNumeric(n pgtype.Numeric) (float64, error) {
	if !n.Valid {
		return 0, nil
	}
	s, err := decimalFromNumeric(n)
	if err != nil {
		return 0, err
	}
	if s == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("parse float from numeric %q: %w", s, err)
	}
	return f, nil
}
