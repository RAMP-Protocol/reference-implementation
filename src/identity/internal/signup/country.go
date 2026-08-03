package signup

import "strings"

// alpha2Set is the ISO 3166-1 alpha-2 lookup, built once from the reference data.
var alpha2Set = buildAlpha2Set()

func buildAlpha2Set() map[string]struct{} {
	codes := strings.Fields(iso3166Alpha2)
	set := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		set[code] = struct{}{}
	}
	return set
}

// ValidCountry reports whether s is exactly an officially assigned ISO 3166-1
// alpha-2 code (uppercase, two letters, actually assigned). It is strict: callers
// normalize (trim + uppercase) before checking, so this predicate stays a clean
// set-membership with no casing rules baked in.
func ValidCountry(s string) bool {
	_, ok := alpha2Set[s]
	return ok
}
