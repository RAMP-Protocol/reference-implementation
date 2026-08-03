package rampwellknown

import (
	"fmt"
	"strings"
)

// IsBareHost reports whether ref is EXACTLY a host — nothing a URL could carry
// besides the authority. It answers false for a ref that has a scheme, userinfo,
// a path, a query, or a fragment, because HostOf had to strip something to reach
// the host.
//
// It exists for the callers that hand a caller-supplied domain to code which
// builds a URL by concatenation. There, narrowing a rich ref to its host is the
// wrong repair: the value was never a domain, and accepting it silently means the
// caller chose the path the service fetches, not just the host it fetches from.
// Comparing against the normalized host is what makes the rejection structural,
// rather than a blocklist of the separators anyone thought to name.
//
// The error is HostOf's, for a ref that is not parseable as a host at all.
func IsBareHost(ref string) (bool, error) {
	host, err := HostOf(ref)
	if err != nil {
		return false, err
	}
	return host == ref, nil
}

// HostAnchored reports whether candidate's host is anchored to anchor's host —
// i.e. equal to it or a subdomain of it (case-insensitive). Both refs may be
// bare domains, host:port pairs, or full URLs; either failing to parse is
// returned as an error (callers treat that as "not anchored"). Anchoring a
// resource URL (e.g. a WBA directory's revocation_url) to the directory host
// before fetching it blocks cross-host polling and the SSRF amplification a
// hostile directory could otherwise drive by pointing revocation_url at an
// arbitrary target.
func HostAnchored(anchor, candidate string) (bool, error) {
	anchorHost, err := HostOf(anchor)
	if err != nil {
		return false, fmt.Errorf("anchor host: %w", err)
	}
	candidateHost, err := HostOf(candidate)
	if err != nil {
		return false, fmt.Errorf("candidate host: %w", err)
	}
	return sameOrSubdomain(anchorHost, candidateHost), nil
}

// sameOrSubdomain reports whether candidate equals anchor or is a subdomain of
// it. Comparison is case-insensitive and tolerant of a trailing root dot. A
// subdomain match requires a full dot-delimited label boundary so "evil-a.com"
// is NOT treated as a subdomain of "a.com".
func sameOrSubdomain(anchor, candidate string) bool {
	a := strings.ToLower(strings.TrimSuffix(anchor, "."))
	c := strings.ToLower(strings.TrimSuffix(candidate, "."))
	if a == "" {
		return false
	}
	return c == a || strings.HasSuffix(c, "."+a)
}
