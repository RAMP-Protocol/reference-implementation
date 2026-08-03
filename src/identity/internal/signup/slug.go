package signup

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// SlugGen mints candidate subdomain labels. It is an interface so a test can inject
// a deterministic sequence and exercise the collision-retry path.
type SlugGen interface {
	New() (string, error)
}

// RandomSlugGen mints "agent-" + 8 lowercase base32 characters from crypto/rand: a
// DNS-valid label (leads with a letter, lowercase alphanumerics only) carrying ~40
// bits of entropy, so it is unpredictable, leaks no identity, and effectively never
// collides. The database UNIQUE on subdomain remains the authoritative backstop.
type RandomSlugGen struct{}

// slugEncoding is standard base32 (RFC 4648, no padding) lowercased; its alphabet
// (a-z, 2-7) is entirely DNS-label-safe. Five random bytes encode to exactly eight
// characters with no padding.
var slugEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// New implements SlugGen.
func (RandomSlugGen) New() (string, error) {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("signup: slug entropy: %w", err)
	}
	return "agent-" + strings.ToLower(slugEncoding.EncodeToString(b[:])), nil
}
