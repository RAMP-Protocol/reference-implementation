package signup

import "strings"

// Form field names, used both as the ValidationError keys and as the HTML form
// input names, so a per-field error binds to the input that produced it.
const (
	FieldLegalEntity  = "legal_entity"
	FieldAddress      = "address"
	FieldJurisdiction = "jurisdiction_country"
)

// ValidateForm normalizes and checks the three mandatory fields, returning the
// cleaned input to store and, when anything is wrong, a *ValidationError naming
// every offending field at once. Normalization is surrounding-whitespace trimming
// for all three plus uppercasing the country, so "de " is accepted as "DE" while a
// blank field or an unassigned/misshaped code (ZZ, USA, 1) is rejected. A nil error
// means the returned FormInput is safe to persist verbatim.
func ValidateForm(in FormInput) (FormInput, *ValidationError) {
	clean := FormInput{
		LegalEntity:         strings.TrimSpace(in.LegalEntity),
		Address:             strings.TrimSpace(in.Address),
		JurisdictionCountry: strings.ToUpper(strings.TrimSpace(in.JurisdictionCountry)),
	}
	fields := map[string]string{}
	if clean.LegalEntity == "" {
		fields[FieldLegalEntity] = "Legal entity is required."
	}
	if clean.Address == "" {
		fields[FieldAddress] = "Address is required."
	}
	switch {
	case clean.JurisdictionCountry == "":
		fields[FieldJurisdiction] = "Jurisdiction is required."
	case !ValidCountry(clean.JurisdictionCountry):
		fields[FieldJurisdiction] = "Jurisdiction must be a valid ISO 3166-1 alpha-2 country code."
	}
	if len(fields) > 0 {
		return FormInput{}, &ValidationError{Fields: fields}
	}
	return clean, nil
}
