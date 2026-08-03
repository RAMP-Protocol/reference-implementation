package service

import "testing"

func TestResolveFeeRateBps(t *testing.T) {
	t.Parallel()
	ptr := func(v int) *int { return &v }
	tests := []struct {
		name          string
		tenantDefault int
		override      *int
		want          int
	}{
		{"no override falls back to tenant default", 250, nil, 250},
		{"override supersedes default", 250, ptr(1000), 1000},
		{"override of zero is honoured over a non-zero default", 250, ptr(0), 0},
		{"override below default still wins", 1000, ptr(100), 100},
		{"zero default and no override", 0, nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ResolveFeeRateBps(tt.tenantDefault, tt.override); got != tt.want {
				t.Errorf("ResolveFeeRateBps(%d, %v) = %d, want %d", tt.tenantDefault, tt.override, got, tt.want)
			}
		})
	}
}
