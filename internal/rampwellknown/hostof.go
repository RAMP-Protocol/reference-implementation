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
// NEVER anchor with this. Host anchoring — the second half of the SSRF defence,
// which refuses a call to an unrelated PUBLIC host that an address-based guard
// has no objection to — is helpers.HostAnchored in the pinned protocol module,
// and it normalizes through its own parser. This is a SEPARATE and more
// permissive normalization that happens to agree on ordinary hosts and does not
// agree everywhere: a reference whose authority parses empty ("//agent.example",
// "/foo") is ("", nil) here and an error there. An anchoring check fed two empty
// hosts passes for any candidate, which is why the one caller of this function
// refuses that case by hand (see internal/agentid).
//
// The module ships its own helpers.HostOf, and replacing this one with it is
// open work rather than something ruled out. Compared across bare domains,
// host:port pairs, full URLs, a trailing dot, mixed case and a trailing path,
// the two answer the same host; the only difference found is the empty-authority
// case above, where this one answers ("", nil) and the module returns an error —
// and the one caller refuses that case either way, so at that caller the swap
// changes nothing. What it needs before it can be made is the check this
// paragraph does not stand in for: that no other input reaches a different
// answer through ManifestURL's normalization than through the module's parser.
//
// Until then, treat this as what it is: a local normalizer with one caller and
// one job — deriving the stored identity of an agent directory.
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
