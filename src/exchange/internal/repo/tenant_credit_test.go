package repo

import (
	"errors"
	"math/big"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

func TestGuardDefaultAgentCredit_Accepts(t *testing.T) {
	for _, tc := range []struct {
		in        string
		wantMinor string // expected integer minor units at scale 8
	}{
		{"0", "0"},
		{"100", "10000000000"},
		{"0.00000001", "1"}, // one minor unit, the finest representable value
		{"12.5", "1250000000"},
		{"999999999999.99999999", "99999999999999999999"}, // NUMERIC(20,8) maximum
	} {
		n, err := guardDefaultAgentCredit(testutil.MustRat(t, tc.in))
		if err != nil {
			t.Fatalf("guard(%s): unexpected error %v", tc.in, err)
		}
		if !n.Valid || n.Exp != -8 || n.Int.String() != tc.wantMinor {
			t.Fatalf("guard(%s) = {Int:%v Exp:%d Valid:%v}, want minor %s at exp -8",
				tc.in, n.Int, n.Exp, n.Valid, tc.wantMinor)
		}
	}
}

func TestGuardDefaultAgentCredit_Rejects(t *testing.T) {
	for name, in := range map[string]*big.Rat{
		"nil amount":             nil,
		"negative":               testutil.MustRat(t, "-0.01"),
		"finer than scale 8":     testutil.MustRat(t, "0.000000001"),
		"non-terminating":        testutil.MustRat(t, "1/3"),
		"exceeds integer digits": testutil.MustRat(t, "1000000000000"), // 10^12: one past NUMERIC(20,8) capacity
	} {
		if _, err := guardDefaultAgentCredit(in); !errors.Is(err, ErrDefaultCreditInvalid) {
			t.Fatalf("%s: got %v, want ErrDefaultCreditInvalid", name, err)
		}
	}
}

func TestRatFromNumeric_RoundTrip(t *testing.T) {
	for _, s := range []string{"0", "100", "0.00000001", "12.5"} {
		want := testutil.MustRat(t, s)
		n, err := guardDefaultAgentCredit(want)
		if err != nil {
			t.Fatalf("guard(%s): %v", s, err)
		}
		got, err := ratFromNumeric(n)
		if err != nil {
			t.Fatalf("ratFromNumeric(%s): %v", s, err)
		}
		if got.Cmp(want) != 0 {
			t.Fatalf("round trip %s: got %s", s, got.RatString())
		}
	}
}

func TestRatFromNumeric_RejectsNonFinite(t *testing.T) {
	for name, n := range map[string]pgtype.Numeric{
		"invalid": {},
		"NaN":     {NaN: true, Valid: true},
	} {
		if _, err := ratFromNumeric(n); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
}
