package money

import (
	"errors"
	"math/big"
	"testing"
)

func TestScaleFactor(t *testing.T) {
	if got := ScaleFactor(); got.Int64() != 100_000_000 {
		t.Errorf("ScaleFactor() = %s, want 100000000", got)
	}
}

func TestMinorUnits(t *testing.T) {
	tests := []struct {
		name    string
		amount  string
		want    int64
		wantErr error // sentinel to errors.Is against; nil = expect success
	}{
		{"exact whole", "1.00", 100_000_000, nil},
		{"exact fraction", "0.05", 5_000_000, nil},
		{"one minor unit", "0.00000001", 1, nil},
		{"zero", "0", 0, nil},
		{"negative is sign-agnostic", "-1.00", -100_000_000, nil},
		{"sub-scale remainder rejected", "0.000000005", 0, ErrAmountNotRepresentable},
		{"non-terminating rejected", "1/3", 0, ErrAmountNotRepresentable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := new(big.Rat).SetString(tc.amount)
			if !ok {
				t.Fatalf("bad test amount %q", tc.amount)
			}
			got, err := MinorUnits(v)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("MinorUnits(%q) err = %v, want %v", tc.amount, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MinorUnits(%q) unexpected err: %v", tc.amount, err)
			}
			if got.Int64() != tc.want {
				t.Errorf("MinorUnits(%q) = %s, want %d", tc.amount, got, tc.want)
			}
		})
	}
}

func TestMinorUnitsNilAmount(t *testing.T) {
	if _, err := MinorUnits(nil); err == nil {
		t.Fatal("MinorUnits(nil) = nil error, want non-nil")
	}
}
