package rampwellknown

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// EnvInsecureAllowPrivate is the environment flag that relaxes the SSRF guard
// for local / docker-compose stacks. It MUST be unset (or any value other than
// "1") in production. The flag name lives here, next to the guard it controls,
// so every service wires the decision identically.
const EnvInsecureAllowPrivate = "RAMP_FETCH_INSECURE_ALLOW_PRIVATE"

// ErrBlockedTarget is returned when the SSRF guard refuses a fetch target — a
// disallowed URL scheme or a destination IP that is not a public address.
var ErrBlockedTarget = errors.New("rampwellknown: fetch target blocked")

// GuardOptions configures the SSRF guard applied to outbound manifest and
// invalidation-list fetches. The zero value is production-safe: only the https
// scheme is permitted and connections to loopback, link-local (including the
// cloud metadata address 169.254.169.254), private, unspecified, and multicast
// destinations are refused.
//
// The manifest's invalidation_url and a registration's manifest_url are
// attacker-influenceable (manifest content / caller input), so the guard treats
// every fetch target as untrusted and validates the *connected* IP at dial time
// — a DNS-rebinding host that resolves to a public address at check time but a
// private one at connect time is still refused.
type GuardOptions struct {
	// Insecure relaxes the guard for local / docker-compose stacks: it permits
	// the http scheme and connections to private/loopback/link-local ranges so
	// docker-internal hostnames (broker:8082, exchange:8081, publisher:80)
	// resolve. MUST be false in production. Wired from the
	// RAMP_FETCH_INSECURE_ALLOW_PRIVATE environment flag at the production root.
	Insecure bool
}

const guardDialTimeout = 10 * time.Second

// NewGuardedClient builds an *http.Client that enforces opts. The destination
// IP is validated at dial time via net.Dialer.Control, so a rebinding host that
// passes a name-resolution check but connects to a private IP is still refused.
// Per-request deadlines are still supplied by the fetch layer's context; the
// client carries no overall timeout of its own.
func NewGuardedClient(opts GuardOptions) *http.Client {
	base := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   guardDialTimeout,
			KeepAlive: 30 * time.Second,
			Control:   guardControl(opts.Insecure),
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   guardDialTimeout,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{Transport: schemeGuard{base: base, insecure: opts.Insecure}}
}

// GuardOptionsFromEnv derives GuardOptions from the environment: Insecure is
// true only when EnvInsecureAllowPrivate == "1". This is the single place the
// production-safe default is decided, so a service can never wire the guard
// from a stale or divergent flag name.
func GuardOptionsFromEnv() GuardOptions {
	return GuardOptions{Insecure: os.Getenv(EnvInsecureAllowPrivate) == "1"}
}

// NewGuardedClientFromEnv builds a guarded *http.Client configured from the
// environment (see GuardOptionsFromEnv). Services constructing the outbound
// .well-known fetch client use this so the SSRF default lives once.
func NewGuardedClientFromEnv() *http.Client {
	return NewGuardedClient(GuardOptionsFromEnv())
}

// schemeGuard rejects a request whose URL scheme is not permitted before it
// reaches the dialer: https is always allowed, http only in insecure mode. It
// re-runs on every redirect hop, so a 3xx scheme downgrade is also caught.
type schemeGuard struct {
	base     http.RoundTripper
	insecure bool
}

func (g schemeGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Scheme {
	case "https":
	case "http":
		if !g.insecure {
			return nil, fmt.Errorf("%w: http scheme requires insecure mode: %s",
				ErrBlockedTarget, req.URL.Redacted())
		}
	default:
		return nil, fmt.Errorf("%w: scheme %q not permitted: %s",
			ErrBlockedTarget, req.URL.Scheme, req.URL.Redacted())
	}
	return g.base.RoundTrip(req)
}

// guardControl returns a net.Dialer.Control hook that refuses to connect to a
// non-public destination unless insecure is set. Runs after name resolution
// with the concrete dialed address, defeating DNS rebinding.
func guardControl(insecure bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		if insecure {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%w: bad dial address %q: %w", ErrBlockedTarget, address, err)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("%w: unresolved dial address %q", ErrBlockedTarget, host)
		}
		if !isPublicIP(ip) {
			return fmt.Errorf("%w: destination %s is not a public address", ErrBlockedTarget, ip)
		}
		return nil
	}
}

// cgnatPrefix is RFC 6598 shared (CGNAT) address space, 100.64.0.0/10. Go's
// net.IP.IsPrivate covers RFC 1918 + IPv6 ULA only and omits CGNAT, yet
// 100.64.0.0/10 routes to reachable internal services in some deployments (EKS
// secondary ranges, GKE, Tailscale), so it is rejected explicitly.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// nat64WellKnownPrefix is the RFC 6052 well-known prefix 64:ff9b::/96. An
// address inside it embeds an IPv4 address in its low 32 bits; a NAT64 gateway
// translates a connection to it into a connection to that embedded IPv4. Left
// unchecked, 64:ff9b::a9fe:a9fe (a global-unicast IPv6 by Go's classifier)
// reaches 169.254.169.254 — the metadata endpoint the guard exists to protect.
var nat64WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")

// isPublicIP reports whether ip is a globally-routable unicast destination,
// refusing every range that a NAT64 / CGNAT / private / link-local path could
// route back to an internal target. See isPublicAddr for the per-range rules.
func isPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return isPublicAddr(addr.Unmap())
}

// isPublicAddr rejects loopback, link-local unicast/multicast (covers
// 169.254.169.254 and IPv6 fe80::/10), any multicast, the unspecified address,
// the private ranges (RFC 1918 + IPv6 ULA), and RFC 6598 CGNAT. For a NAT64
// well-known-prefix address it recurses onto the embedded IPv4, so a 64:ff9b::
// wrapper cannot smuggle a private/metadata target past the guard. Go's
// IsGlobalUnicast alone is insufficient — it returns true for all of the above
// — so each range is checked explicitly.
func isPublicAddr(addr netip.Addr) bool {
	if nat64WellKnownPrefix.Contains(addr) {
		b := addr.As16()
		return isPublicAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() || addr.IsPrivate() ||
		cgnatPrefix.Contains(addr) {
		return false
	}
	return addr.IsGlobalUnicast()
}
