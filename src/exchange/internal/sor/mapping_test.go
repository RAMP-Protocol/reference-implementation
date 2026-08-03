package sor

import "testing"

// mapRegistration is the single source of the known-key set, so these unit
// tests pin every known key to its typed destination, prove unknown keys land
// in extra, and prove the two partitions never overlap.

func TestMapRegistration_KnownKeysToTypedFields(t *testing.T) {
	t.Parallel()
	data := map[string]string{
		"legal_entity":             "ACME Inc",
		"jurisdiction_country":     "US",
		"jurisdiction_subdivision": "CA",
		"address_line1":            "1 Main St",
		"address_line2":            "Suite 2",
		"address_city":             "Springfield",
		"address_region":           "IL",
		"address_postal_code":      "62704",
		"address_country":          "US",
		"email":                    "ops@acme.example",
	}

	profile, email, extra := mapRegistration(data)

	want := LicensingProfile{
		LegalEntity:             "ACME Inc",
		JurisdictionCountry:     "US",
		JurisdictionSubdivision: "CA",
		AddressLine1:            "1 Main St",
		AddressLine2:            "Suite 2",
		AddressCity:             "Springfield",
		AddressRegion:           "IL",
		AddressPostalCode:       "62704",
		AddressCountry:          "US",
	}
	if profile != want {
		t.Errorf("profile = %+v, want %+v", profile, want)
	}
	if email != "ops@acme.example" {
		t.Errorf("email = %q, want %q", email, "ops@acme.example")
	}
	if len(extra) != 0 {
		t.Errorf("extra = %v, want empty (every key was known)", extra)
	}
}

func TestMapRegistration_UnknownKeysToExtra(t *testing.T) {
	t.Parallel()
	data := map[string]string{
		"vat_id":       "GB123",
		"contact_name": "Jane",
	}

	profile, email, extra := mapRegistration(data)

	if profile != (LicensingProfile{}) {
		t.Errorf("profile = %+v, want zero (no known keys)", profile)
	}
	if email != "" {
		t.Errorf("email = %q, want empty", email)
	}
	if extra["vat_id"] != "GB123" || extra["contact_name"] != "Jane" {
		t.Errorf("extra = %v, want the two unknown keys verbatim", extra)
	}
	if len(extra) != 2 {
		t.Errorf("extra has %d keys, want 2", len(extra))
	}
}

// TestMapRegistration_Precedence proves the known/unknown partition: a known key
// is written to its typed field and NEVER duplicated into extra, and only the
// genuinely unknown keys land in extra.
func TestMapRegistration_Precedence(t *testing.T) {
	t.Parallel()
	data := map[string]string{
		"legal_entity": "ACME Inc", // known
		"email":        "ops@acme.example",
		"vat_id":       "GB123", // unknown
	}

	profile, email, extra := mapRegistration(data)

	if profile.LegalEntity != "ACME Inc" {
		t.Errorf("legal_entity = %q, want mapped to the typed field", profile.LegalEntity)
	}
	if email != "ops@acme.example" {
		t.Errorf("email = %q, want mapped out of extra", email)
	}
	if _, leaked := extra["legal_entity"]; leaked {
		t.Error("legal_entity leaked into extra; known keys must not be duplicated there")
	}
	if _, leaked := extra["email"]; leaked {
		t.Error("email leaked into extra; known keys must not be duplicated there")
	}
	if extra["vat_id"] != "GB123" || len(extra) != 1 {
		t.Errorf("extra = %v, want only the unknown vat_id", extra)
	}
}

func TestMapRegistration_EmptyData(t *testing.T) {
	t.Parallel()
	profile, email, extra := mapRegistration(nil)

	if profile != (LicensingProfile{}) {
		t.Errorf("profile = %+v, want zero", profile)
	}
	if email != "" {
		t.Errorf("email = %q, want empty", email)
	}
	if extra == nil {
		t.Fatal("extra is nil, want a non-nil empty map")
	}
	if len(extra) != 0 {
		t.Errorf("extra = %v, want empty", extra)
	}
}
