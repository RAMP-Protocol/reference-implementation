package rampwellknown_test

import (
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

func TestHostAnchored(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		anchor    string
		candidate string
		want      bool
	}{
		{"exact bare host", "wba.example", "https://wba.example/revocations", true},
		{"subdomain of directory", "example.com", "https://keys.example.com/rev", true},
		{"deep subdomain", "example.com", "https://a.b.example.com/rev", true},
		{"different host", "wba.example", "https://evil.test/rev", false},
		{"suffix but not subdomain", "example.com", "https://evilexample.com/rev", false},
		{"label-boundary spoof", "a.com", "https://evil-a.com/rev", false},
		{"case-insensitive", "Example.COM", "https://EXAMPLE.com/rev", true},
		{"same host and port", "svc.local:8443", "http://svc.local:8443/rev", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := rampwellknown.HostAnchored(tc.anchor, tc.candidate)
			if err != nil {
				t.Fatalf("HostAnchored(%q, %q): unexpected err %v", tc.anchor, tc.candidate, err)
			}
			if got != tc.want {
				t.Errorf("HostAnchored(%q, %q) = %v, want %v", tc.anchor, tc.candidate, got, tc.want)
			}
		})
	}
}

// IsBareHost guards the callers that concatenate a caller-supplied domain into a
// URL, so the cases that matter most are the ones where something extra rides
// along: a fragment (everything after it is dropped, so the suffix the caller
// expected to be appended vanishes), a path, a query, and userinfo (which moves
// the effective host entirely).
func TestIsBareHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ref  string
		want bool
	}{
		{"bare domain", "exchange.example", true},
		{"host and port", "exchange.example:8081", true},
		{"trailing root dot", "exchange.example.", true},
		{"scheme", "https://exchange.example", false},
		{"path", "exchange.example/internal/admin", false},
		{"query", "exchange.example?token=x", false},
		{"fragment swallows the appended suffix", "exchange.example#", false},
		{"path and query behind a fragment", "exchange.example/internal/admin?token=x#", false},
		{"userinfo names a different host", "exchange.example@internal.invalid", false},
		{"trailing slash", "exchange.example/", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := rampwellknown.IsBareHost(tc.ref)
			if err != nil {
				t.Fatalf("IsBareHost(%q): unexpected err %v", tc.ref, err)
			}
			if got != tc.want {
				t.Errorf("IsBareHost(%q) = %v, want %v", tc.ref, got, tc.want)
			}
		})
	}
}

func TestIsBareHost_UnparseableIsError(t *testing.T) {
	t.Parallel()
	if _, err := rampwellknown.IsBareHost(""); err == nil {
		t.Fatal("empty ref must return an error")
	}
}

func TestHostAnchored_UnparseableIsError(t *testing.T) {
	t.Parallel()
	if _, err := rampwellknown.HostAnchored("", "https://wba.example/rev"); err == nil {
		t.Fatal("empty anchor must return an error")
	}
	if _, err := rampwellknown.HostAnchored("wba.example", ""); err == nil {
		t.Fatal("empty candidate must return an error")
	}
}
