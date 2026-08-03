package tigerbeetle

import (
	"errors"
	"math/big"
	"testing"
)

func TestScaleFactor(t *testing.T) {
	tests := []struct {
		scale uint8
		want  int64
	}{
		{0, 1},
		{2, 100},
		{8, 100_000_000},
	}
	for _, tc := range tests {
		if got := ScaleFactor(tc.scale); got.Int64() != tc.want {
			t.Errorf("ScaleFactor(%d) = %s, want %d", tc.scale, got, tc.want)
		}
	}
}

func TestMinorUnits(t *testing.T) {
	tests := []struct {
		name    string
		amount  string
		scale   uint8
		want    int64
		wantErr error // sentinel to errors.Is against; nil = expect success
	}{
		{"exact whole at scale 8", "1.00", 8, 100_000_000, nil},
		{"exact fraction at scale 8", "0.05", 8, 5_000_000, nil},
		{"exact at scale 2", "1.23", 2, 123, nil},
		{"zero", "0", 8, 0, nil},
		{"negative is sign-agnostic", "-1.00", 2, -100, nil},
		{"sub-unit remainder rejected", "0.005", 2, 0, ErrAmountNotRepresentable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := new(big.Rat).SetString(tc.amount)
			if !ok {
				t.Fatalf("bad test amount %q", tc.amount)
			}
			got, err := MinorUnits(v, tc.scale)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("MinorUnits(%q, %d) err = %v, want %v", tc.amount, tc.scale, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MinorUnits(%q, %d) unexpected err: %v", tc.amount, tc.scale, err)
			}
			if got.Int64() != tc.want {
				t.Errorf("MinorUnits(%q, %d) = %s, want %d", tc.amount, tc.scale, got, tc.want)
			}
		})
	}
}

func TestMinorUnitsNilAmount(t *testing.T) {
	if _, err := MinorUnits(nil, 8); err == nil {
		t.Fatal("MinorUnits(nil) = nil error, want non-nil")
	}
}
