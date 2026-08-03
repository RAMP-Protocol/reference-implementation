package transport

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// ParseAllowlist parses a comma-separated list of IPs and CIDRs into prefixes. A
// bare IP (no "/") becomes a host route (/32 or /128). Empty/whitespace items are
// skipped; an unparseable entry is an error naming the offending token.
func ParseAllowlist(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("admin allowlist CIDR %q: %w", item, err)
			}
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("admin allowlist IP %q: %w", item, err)
		}
		out = append(out, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
	}
	return out, nil
}

// IPAllowlistMiddleware rejects (403) any request whose source IP is not covered
// by one of allowed. The source is taken from RemoteAddr via clientIPFromRequest —
// X-Forwarded-For is deliberately NOT consulted, so this is sound only for a
// directly-bound internal listener (the handoff: a fronting proxy makes
// RemoteAddr the proxy and the allowlist vacuous). An empty allowlist denies
// everything (fail-closed): the admin plane must be explicitly opened. Wrap this
// INSIDE RequestIDMiddleware so a rejection still logs a correlated request_id.
func IPAllowlistMiddleware(allowed []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ipAllowed(allowed, r) {
			reqctx.FromContext(r.Context()).WarnContext(r.Context(),
				"exchange.admin.ip_reject", "client_ip", clientIPFromRequest(r))
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ipAllowed(allowed []netip.Prefix, r *http.Request) bool {
	addr, err := netip.ParseAddr(clientIPFromRequest(r))
	if err != nil {
		return false
	}
	addr = addr.Unmap() // normalize IPv4-in-IPv6 so a v4 prefix can contain it
	for _, p := range allowed {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
