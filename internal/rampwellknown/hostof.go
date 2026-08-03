package rampwellknown

import (
	"fmt"
	"net/url"
)

// HostOf extracts the host (including any port) from a bare domain, a
// host:port, or a full-URL reference, using the same normalization as
// ManifestURL so host comparisons across the codebase are apples-to-apples.
// An empty or unparseable reference is an error.
//
// The dial-time SSRF guard is SDK-owned. Host anchoring is the separate, second
// half of that defence — it is what refuses delivery to an unrelated PUBLIC host,
// which an address-based guard cannot see — and lives alongside this function in
// hostanchor.go.
func HostOf(ref string) (string, error) {
	normalized, err := ManifestURL(ref, "", "")
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidHost, err)
	}
	return parsed.Host, nil
}
