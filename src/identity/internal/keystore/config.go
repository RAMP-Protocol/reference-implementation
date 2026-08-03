package keystore

import (
	"errors"
	"fmt"
	"path"
	"regexp"

	"github.com/hashicorp/vault/api"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// Default Vault coordinates. The mount is Vault's own default KV v2 mount; the
// prefix namespaces agent keys inside it so the Identity Service can share a
// mount with unrelated secrets without colliding.
const (
	DefaultMount  = "secret"
	DefaultPrefix = "agents"
)

// Config wires a VaultStore.
//
// Client arrives ALREADY AUTHENTICATED. Choosing how the service proves its
// identity to Vault — a token today, AppRole or Kubernetes or AWS IAM auth
// later — is the composition root's job, not custody's. Were the store to build
// its own client from the environment, every future hardening of that credential
// would mean editing the one component this package promises is backend-agnostic.
type Config struct {
	Client *api.Client
	// Mount is the KV v2 mount path; empty means DefaultMount.
	Mount string
	// Prefix namespaces agent keys within the mount; empty means DefaultPrefix.
	Prefix string
	// Clk stamps CreatedAt. Validity windows are supplied by the caller, so this is
	// the only wall-clock reading the store does.
	Clk clock.Clock
}

// subdomainRE matches a DNS name in the shape an agent's WBA directory takes
// (`agent-123.rampmcp.org`): lowercase labels of alphanumerics and hyphens, a
// hyphen never leading or trailing, labels joined by dots. Anything else — an
// empty string, an absolute path, a `..` traversal, a percent escape — is
// rejected before it can become part of a storage path.
var subdomainRE = regexp.MustCompile(
	`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`,
)

// thumbprintRE matches an RFC 7638 thumbprint: the base64url-no-pad encoding of
// a SHA-256 digest, which is always 43 characters and never contains a path
// separator.
var thumbprintRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// maxSubdomainLen is the DNS limit on a fully-qualified name.
const maxSubdomainLen = 253

// validate fills in defaults and rejects a Config that cannot work.
func (c *Config) validate() error {
	if c.Client == nil {
		return errors.New("keystore: Config.Client is required (authenticated *api.Client)")
	}
	if c.Clk == nil {
		return errors.New("keystore: Config.Clk is required")
	}
	if c.Mount == "" {
		c.Mount = DefaultMount
	}
	if c.Prefix == "" {
		c.Prefix = DefaultPrefix
	}
	return nil
}

// validateSubdomain guards every entry point that names an agent.
func validateSubdomain(subdomain string) error {
	if len(subdomain) > maxSubdomainLen || !subdomainRE.MatchString(subdomain) {
		return fmt.Errorf("%w: %q", ErrInvalidSubdomain, subdomain)
	}
	return nil
}

// ValidSubdomain reports whether subdomain is syntactically a name this store
// would accept, using the same grammar every store entry point enforces. It lets
// a caller reject a malformed host before spending a backend round-trip on it —
// the single source of the grammar, so the two cannot drift.
func ValidSubdomain(subdomain string) bool {
	return validateSubdomain(subdomain) == nil
}

// validateRef guards every entry point that names one key.
func validateRef(ref Ref) error {
	if err := validateSubdomain(ref.Subdomain); err != nil {
		return err
	}
	if !thumbprintRE.MatchString(ref.Thumbprint) {
		return fmt.Errorf("%w: %q", ErrInvalidThumbprint, ref.Thumbprint)
	}
	return nil
}

// secretPath is the KV v2 secret path for one key, relative to the mount. The
// api.KVv2 helper prepends the mount and the `data/` segment itself.
func (s *VaultStore) secretPath(ref Ref) string {
	return path.Join(s.prefix, ref.Subdomain, ref.Thumbprint)
}

// dataReadPath is the absolute Vault path a raw GET reads for one key. Writes go
// through the api.KVv2 helper, which prepends the mount and the `data/` segment
// itself; reads do not, because the helper cannot tell a missing secret from a
// missing mount (see rawRead), so the segments are spelled out here.
func (s *VaultStore) dataReadPath(ref Ref) string {
	return path.Join(s.mount, "data", s.secretPath(ref))
}

// agentPath is the KV v2 path holding one agent's keys, relative to the mount.
func (s *VaultStore) agentPath(subdomain string) string {
	return path.Join(s.prefix, subdomain)
}

// metadataListPath is the absolute Vault path a LIST reads to enumerate an
// agent's keys. Unlike reads and writes, listing has no api.KVv2 helper, so the
// `metadata/` segment is spelled out here.
func (s *VaultStore) metadataListPath(subdomain string) string {
	return path.Join(s.mount, "metadata", s.agentPath(subdomain))
}
