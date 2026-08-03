package licenseterm_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/licenseterm"
)

// InMemoryVocab must satisfy the VocabProvider interface.
var _ licenseterm.VocabProvider = (*licenseterm.InMemoryVocab)(nil)

func TestInMemoryVocabKnown(t *testing.T) {
	v := licenseterm.NewInMemoryVocab()

	cases := []struct {
		name  string
		axis  rampv1.RestrictionKind
		token string
		want  bool
	}{
		{"function canonical ai-train", rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, "ai-train", true},
		{"function canonical ai-input", rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, "ai-input", true},
		{"function unknown", rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, "ai-foo", false},
		{"geography ISO alpha-2 US (structural)", rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY, "US", true},
		{"geography ISO alpha-2 ZZ (structural, any two uppercase letters)", rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY, "ZZ", true},
		{"geography special wildcard", rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY, "*", true},
		{"geography special EEA", rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY, "EEA", true},
		{"geography malformed lowercase", rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY, "us", false},
		{"geography malformed 3-letter", rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY, "USA", false},
		{"user-type canonical", rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE, "commercial_entity", true},
		{"user-type unknown", rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE, "robots", false},
		{"OTHER axis is never known", rampv1.RestrictionKind_RESTRICTION_KIND_OTHER, "ai-train", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := v.Known(tc.axis, tc.token); got != tc.want {
				t.Fatalf("Known(%v, %q) = %v, want %v", tc.axis, tc.token, got, tc.want)
			}
		})
	}
}
