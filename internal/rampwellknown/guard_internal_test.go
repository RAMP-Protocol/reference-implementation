package rampwellknown

import (
	"net"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},       // loopback
		{"::1", false},             // loopback v6
		{"10.0.0.1", false},        // private
		{"172.16.5.4", false},      // private
		{"192.168.1.1", false},     // private
		{"169.254.169.254", false}, // cloud metadata (link-local)
		{"169.254.1.1", false},     // link-local
		{"fe80::1", false},         // link-local v6
		{"fc00::1", false},         // ULA (private v6)
		{"0.0.0.0", false},         // unspecified
		{"::", false},              // unspecified v6
		{"224.0.0.1", false},       // multicast
		{"ff02::1", false},         // multicast v6
		{"100.64.0.1", false},      // CGNAT shared space (RFC 6598)
		{"100.127.255.255", false}, // CGNAT upper bound
		{"100.128.0.1", true},      // just above CGNAT — public
		// NAT64 well-known prefix (RFC 6052): the embedded IPv4 is classified.
		{"64:ff9b::a9fe:a9fe", false}, // -> 169.254.169.254 (metadata)
		{"64:ff9b::7f00:1", false},    // -> 127.0.0.1 (loopback)
		{"64:ff9b::a00:1", false},     // -> 10.0.0.1 (private)
		{"64:ff9b::808:808", true},    // -> 8.8.8.8 (public)
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("unparseable test IP %q", tc.ip)
			}
			if got := isPublicIP(ip); got != tc.want {
				t.Fatalf("isPublicIP(%s)=%v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// TestGuardOptionsFromEnv pins the single env-driven insecure-mode decision:
// only the exact value "1" relaxes the guard.
func TestGuardOptionsFromEnv(t *testing.T) {
	t.Setenv(EnvInsecureAllowPrivate, "1")
	if !GuardOptionsFromEnv().Insecure {
		t.Error(`"1" must enable insecure mode`)
	}
	for _, v := range []string{"0", "true", "", "yes"} {
		t.Setenv(EnvInsecureAllowPrivate, v)
		if GuardOptionsFromEnv().Insecure {
			t.Errorf("value %q must NOT enable insecure mode", v)
		}
	}
}
