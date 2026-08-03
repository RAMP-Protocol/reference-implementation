package signup_test

import (
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/signup"
)

func TestValidateForm_AcceptsAndNormalizes(t *testing.T) {
	clean, verr := signup.ValidateForm(signup.FormInput{
		LegalEntity:         "  Acme GmbH ",
		Address:             " 1 Main St, Berlin ",
		JurisdictionCountry: " de ",
	})
	if verr != nil {
		t.Fatalf("ValidateForm rejected a valid form: %v", verr)
	}
	if clean.LegalEntity != "Acme GmbH" || clean.Address != "1 Main St, Berlin" {
		t.Errorf("trimming = %+v, want surrounding whitespace removed", clean)
	}
	if clean.JurisdictionCountry != "DE" {
		t.Errorf("jurisdiction = %q, want normalized upper-case DE", clean.JurisdictionCountry)
	}
}

func TestValidateForm_ReportsEveryMissingFieldAtOnce(t *testing.T) {
	_, verr := signup.ValidateForm(signup.FormInput{})
	if verr == nil {
		t.Fatal("ValidateForm accepted an empty form")
	}
	for _, field := range []string{signup.FieldLegalEntity, signup.FieldAddress, signup.FieldJurisdiction} {
		if _, ok := verr.Fields[field]; !ok {
			t.Errorf("missing error for %q; got %v", field, verr.Fields)
		}
	}
}

func TestValidateForm_RejectsBadCountryCodes(t *testing.T) {
	for _, bad := range []string{"ZZ", "XX", "USA", "U", "1", "D3", "gb1"} {
		in := signup.FormInput{LegalEntity: "Acme", Address: "1 Main St", JurisdictionCountry: bad}
		_, verr := signup.ValidateForm(in)
		if verr == nil {
			t.Errorf("ValidateForm accepted invalid country %q", bad)
			continue
		}
		if _, ok := verr.Fields[signup.FieldJurisdiction]; !ok {
			t.Errorf("country %q: no jurisdiction error; got %v", bad, verr.Fields)
		}
	}
}

func TestValidateForm_OnlyJurisdictionWrong(t *testing.T) {
	_, verr := signup.ValidateForm(signup.FormInput{
		LegalEntity: "Acme", Address: "1 Main St", JurisdictionCountry: "ZZ",
	})
	if verr == nil {
		t.Fatal("expected rejection for ZZ")
	}
	if len(verr.Fields) != 1 {
		t.Errorf("expected exactly the jurisdiction error, got %v", verr.Fields)
	}
}

func TestValidCountry(t *testing.T) {
	for _, ok := range []string{"US", "DE", "GB", "UA", "FR", "JP"} {
		if !signup.ValidCountry(ok) {
			t.Errorf("ValidCountry(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"ZZ", "XX", "us", "USA", "", "U"} {
		if signup.ValidCountry(bad) {
			t.Errorf("ValidCountry(%q) = true, want false", bad)
		}
	}
}
