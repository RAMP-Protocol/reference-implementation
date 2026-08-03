package signup_test

import (
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/signup"
)

func TestRandomSlugGen_ProducesDNSValidLabels(t *testing.T) {
	var gen signup.RandomSlugGen
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		slug, err := gen.New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if !strings.HasPrefix(slug, "agent-") {
			t.Fatalf("slug %q missing agent- prefix", slug)
		}
		// The label must be a valid subdomain on its own and as a full FQDN — that
		// is the exact grammar the keystore and card store key on.
		if !keystore.ValidSubdomain(slug) || !keystore.ValidSubdomain(slug+".rampmcp.org") {
			t.Fatalf("slug %q is not a DNS-valid label", slug)
		}
		if seen[slug] {
			t.Fatalf("slug %q collided within 200 draws — entropy too low", slug)
		}
		seen[slug] = true
	}
}
