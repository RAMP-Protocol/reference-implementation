package licenseterm

import (
	"regexp"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/functiontokens"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/geographytokens"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/usertypes"
)

// VocabProvider abstracts the restriction-token vocabulary registry so that
// Validate can flag unknown tokens without owning the registry. Tokens are
// matched exactly — callers normalize aliases to canonical form first.
//
// The canonical registry is the (ramp.v1.vocab_enum) options on the
// RestrictionKind enum values, single-sourced into the generated
// functiontokens / geographytokens / usertypes packages. InMemoryVocab adapts
// those generated IsRegistered checks to the per-axis VocabProvider interface.
type VocabProvider interface {
	// Known reports whether token is a registered canonical value on the given
	// restriction axis.
	Known(axis rampv1.RestrictionKind, token string) bool
}

// isoAlpha2 matches a well-formed ISO 3166-1 alpha-2 country code (two
// uppercase letters). Per the geography axis contract, ISO codes are valid
// structurally and are NOT enumerated in the registry; only the non-ISO
// specials (*, EU, EEA) are listed in geographytokens.
var isoAlpha2 = regexp.MustCompile(`^[A-Z]{2}$`)

// geographyRegistered reports whether geo is a registered geography token: a
// non-ISO special (geographytokens.IsRegistered: *, EU, EEA) OR a well-formed
// ISO 3166-1 alpha-2 code validated structurally.
func geographyRegistered(geo string) bool {
	return geographytokens.IsRegistered(geo) || isoAlpha2.MatchString(geo)
}

// InMemoryVocab is a VocabProvider backed entirely by the generated per-axis
// registries (functiontokens / geographytokens / usertypes IsRegistered),
// single-sourced from the (ramp.v1.vocab_enum) proto options. It holds no token
// data of its own — there is exactly one source. The OTHER axis carries no
// registry and is always unknown.
type InMemoryVocab struct{}

// NewInMemoryVocab returns an InMemoryVocab. It is stateless: membership is
// delegated to the generated registries.
func NewInMemoryVocab() *InMemoryVocab {
	return &InMemoryVocab{}
}

// Known reports whether token is registered on axis, delegating to the
// generated per-axis registries. GEOGRAPHY additionally accepts any well-formed
// ISO 3166-1 alpha-2 code (validated structurally, not enumerated).
func (v *InMemoryVocab) Known(axis rampv1.RestrictionKind, token string) bool {
	switch axis {
	case rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION:
		return functiontokens.IsRegistered(token)
	case rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY:
		return geographyRegistered(token)
	case rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE:
		return usertypes.IsRegistered(token)
	default: // OTHER and any unknown axis carry no registry.
		return false
	}
}
