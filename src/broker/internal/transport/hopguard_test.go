package transport

import "testing"

func TestEnforceHopBudget(t *testing.T) {
	t.Parallel()
	hops := func(n int32) *int32 { return &n }
	tests := []struct {
		name    string
		maxHops *int32
		wantErr bool
	}{
		{"no cap permits the relay", nil, false},
		{"cap above the broker hop", hops(2), false},
		{"cap equal to the broker hop", hops(1), false},
		{"cap of zero forbids any intermediary", hops(0), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := enforceHopBudget(tc.maxHops)
			if tc.wantErr && err == nil {
				t.Fatal("expected hop-budget rejection, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected the relay to be permitted, got %v", err)
			}
		})
	}
}
