package transport_test

import (
	"net/netip"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// TestParseAllowlist exercises every branch of the admin IP-allowlist parser: CIDR
// masking, bare-IP host routes (v4 /32, v6 /128), whitespace skipping, the empty
// input (which yields no prefixes — the fail-closed default the middleware turns
// into deny-all), and the two error branches, each of which must name the
// offending token. Pure parser → Testing-Doctrine pt2 unit test (no DB, runs fast).
func TestParseAllowlist(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name string
		raw  string
		want []string
	}{
		{"cidr masked", "10.1.2.3/8", []string{"10.0.0.0/8"}},
		{"bare ipv4 to /32", "127.0.0.1", []string{"127.0.0.1/32"}},
		{"bare ipv6 to /128", "::1", []string{"::1/128"}},
		{"whitespace skipped", " , 10.0.0.0/8 ,\t", []string{"10.0.0.0/8"}},
		{"empty is fail-closed empty", "", nil},
		{"mixed", "127.0.0.1, 10.0.0.0/8", []string{"127.0.0.1/32", "10.0.0.0/8"}},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			got, err := transport.ParseAllowlist(tc.raw)
			if err != nil {
				t.Fatalf("ParseAllowlist(%q) unexpected error: %v", tc.raw, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParseAllowlist(%q) = %v, want %v", tc.raw, prefixStrings(got), tc.want)
			}
			for i, p := range got {
				if p.String() != tc.want[i] {
					t.Errorf("prefix[%d] = %q, want %q", i, p.String(), tc.want[i])
				}
			}
		})
	}

	bad := []struct {
		name  string
		raw   string
		token string
	}{
		{"bad cidr names the token", "10.0.0.0/33", "10.0.0.0/33"},
		{"bad ip names the token", "not-an-ip", "not-an-ip"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := transport.ParseAllowlist(tc.raw)
			if err == nil {
				t.Fatalf("ParseAllowlist(%q) = nil error, want error naming %q", tc.raw, tc.token)
			}
			if !strings.Contains(err.Error(), tc.token) {
				t.Errorf("error %q does not name the offending token %q", err, tc.token)
			}
		})
	}
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}
