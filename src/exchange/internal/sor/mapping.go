package sor

// mapRegistration is the single source of the known-key set. Keys that name a
// typed licensing-deal field (or the email) are written to that field; every
// other key is copied verbatim into extra. extra is always non-nil.
//
// A key added to the registration_data contract is a one-line addition
// to knownFields here (with, at most, a later additive migration to promote a
// hot extra key to its own column) — the reason storage can be built ahead of
// the field set being fixed.
func mapRegistration(data map[string]string) (profile LicensingProfile, email string, extra map[string]string) {
	fields := knownFields(&profile, &email)
	extra = make(map[string]string)
	for k, v := range data {
		if assign, ok := fields[k]; ok {
			assign(v)
			continue
		}
		extra[k] = v
	}
	return profile, email, extra
}

// knownFields maps each recognized registration key to a setter that writes its
// value into the typed destination. A table (not a switch ladder) keeps the set
// declarative and the mapping function's complexity flat.
func knownFields(p *LicensingProfile, email *string) map[string]func(string) {
	return map[string]func(string){
		"legal_entity":             func(v string) { p.LegalEntity = v },
		"jurisdiction_country":     func(v string) { p.JurisdictionCountry = v },
		"jurisdiction_subdivision": func(v string) { p.JurisdictionSubdivision = v },
		"address_line1":            func(v string) { p.AddressLine1 = v },
		"address_line2":            func(v string) { p.AddressLine2 = v },
		"address_city":             func(v string) { p.AddressCity = v },
		"address_region":           func(v string) { p.AddressRegion = v },
		"address_postal_code":      func(v string) { p.AddressPostalCode = v },
		"address_country":          func(v string) { p.AddressCountry = v },
		"email":                    func(v string) { *email = v },
	}
}
