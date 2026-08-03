package main

import "testing"

// The wiring (Vault, Postgres, the Revoker) is exercised end-to-end in the transport
// package; here only the pure argument parsing needs its own coverage — the negative
// invocations that must fail before any backend is touched.
func TestParseRevokeArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantSub string
		wantTP  string
		wantErr bool
	}{
		{"valid", []string{"revoke", "agent-1.rampmcp.org", "TPTPTP"}, "agent-1.rampmcp.org", "TPTPTP", false},
		{"no args", nil, "", "", true},
		{"unknown command", []string{"rotate", "a", "b"}, "", "", true},
		{"missing thumbprint", []string{"revoke", "agent-1.rampmcp.org"}, "", "", true},
		{"extra argument", []string{"revoke", "a", "b", "c"}, "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub, tp, err := parseRevokeArgs(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseRevokeArgs(%v) err = %v, wantErr %v", tc.args, err, tc.wantErr)
			}
			if sub != tc.wantSub || tp != tc.wantTP {
				t.Errorf("parseRevokeArgs(%v) = (%q, %q), want (%q, %q)", tc.args, sub, tp, tc.wantSub, tc.wantTP)
			}
		})
	}
}
