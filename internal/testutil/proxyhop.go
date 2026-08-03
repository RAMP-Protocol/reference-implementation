//go:build integration

package testutil

import (
	"net/http"
	"strings"
	"testing"
)

// HTTPSVariant rewrites an httptest server's http:// base URL to https:// so a
// client signs the public-scheme URL a TLS-terminating proxy would present,
// while the actual dial still targets the plain-HTTP listener.
func HTTPSVariant(t *testing.T, serverURL string) string {
	t.Helper()
	if !strings.HasPrefix(serverURL, "http://") {
		t.Fatalf("server URL %q is not http", serverURL)
	}
	return "https://" + strings.TrimPrefix(serverURL, "http://")
}

// DowngradeToProxiedWire rewrites a request signed over its https URL into the
// wire shape a TLS-terminating proxy (Caddy, an ALB) forwards: X-Forwarded-Proto
// carries the original scheme and the dialed URL.Scheme drops to plain http. The
// signature, already minted over the https @target-uri, is left untouched — this
// is the byte-for-byte shape the service receives behind the proxy. Mutates req
// in place; use TLSTerminatingProxyTransport for a Connect client instead.
func DowngradeToProxiedWire(req *http.Request) {
	req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)
	req.URL.Scheme = "http"
}

// TLSTerminatingProxyTransport applies DowngradeToProxiedWire as a RoundTripper.
// It sits UNDER a signing transport, so the signature is minted over the https
// URL first and the wire request is then downgraded to the plain-HTTP listener —
// the RoundTripper form for Connect clients. For a hand-built raw *http.Request,
// call DowngradeToProxiedWire directly.
type TLSTerminatingProxyTransport struct{ Base http.RoundTripper }

func (p TLSTerminatingProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	DowngradeToProxiedWire(r2)
	return p.Base.RoundTrip(r2)
}
